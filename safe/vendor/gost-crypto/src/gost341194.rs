//! GOST R 34.11-94 hash function (RFC 5831).
//!
//! Implements the [`digest::Update`] and [`digest::FixedOutput`] traits
//! for compatibility with the `RustCrypto` ecosystem.

use crate::gost28147::{Lut, build_lut, encrypt_with_lut};
use crate::sbox::{Sbox, SBOX_CRYPTOPRO};
use digest::{HashMarker, Output, OutputSizeUser, Reset, Update};
use digest::typenum::U32;

// C3 constant from RFC 5831.
const C3: [u8; 32] = [
    0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff,
    0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
    0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
];

// Word-sized XOR over two 32-byte arrays.
#[inline]
fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let av = u64::from_ne_bytes([a[8*i],a[8*i+1],a[8*i+2],a[8*i+3],a[8*i+4],a[8*i+5],a[8*i+6],a[8*i+7]]);
        let bv = u64::from_ne_bytes([b[8*i],b[8*i+1],b[8*i+2],b[8*i+3],b[8*i+4],b[8*i+5],b[8*i+6],b[8*i+7]]);
        out[8*i..8*i+8].copy_from_slice(&(av ^ bv).to_ne_bytes());
    }
    out
}

// A(x): out[0..8] = x[16..24] ^ x[24..32];  out[8..32] = x[0..24]
#[inline]
fn perm_a(x: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 { out[i] = x[16 + i] ^ x[24 + i]; }
    out[8..32].copy_from_slice(&x[0..24]);
    out
}

// P(x): p[i + 4*j] = x[8*i + j]  for i in 0..4, j in 0..8
#[inline]
fn perm_p(x: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4usize {
        for j in 0..8usize {
            out[i + 4 * j] = x[8 * i + j];
        }
    }
    out
}

// Chi (ψ): mixing step — in-place.
// out[0..2] = y[30..32]^y[28..30]^y[26..28]^y[24..26]^y[0..2]^y[6..8]
// out[2..32] = y[0..30]
#[inline]
fn chi_in_place(y: &mut [u8; 32]) {
    let b0 = y[30] ^ y[28] ^ y[26] ^ y[24] ^ y[0] ^ y[6];
    let b1 = y[31] ^ y[29] ^ y[27] ^ y[25] ^ y[1] ^ y[7];
    y.copy_within(0..30, 2);
    y[0] = b0;
    y[1] = b1;
}

#[inline]
fn chi(y: &[u8; 32]) -> [u8; 32] {
    let mut out = *y;
    chi_in_place(&mut out);
    out
}

#[inline]
fn chi_n(y: &[u8; 32], n: usize) -> [u8; 32] {
    let mut x = *y;
    for _ in 0..n { chi_in_place(&mut x); }
    x
}

// Add two 256-bit big-endian values modulo 2^256. Byte 0 is most significant.
#[expect(clippy::cast_possible_truncation, reason = "intentional: keeps low 8 bits of sum")]
fn add256_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    out
}

// Derive one round key from the running U and V state vectors.
#[inline]
fn derive_key(u: &[u8; 32], v: &[u8; 32]) -> [u8; 32] {
    let w = xor32(u, v);
    let mut k = perm_p(&w);
    k.reverse();
    k
}

// Advance the U/V state vectors by one key-schedule step.
// `c` is the round constant (C2 = 0, C3, C4 = 0 per RFC 5831).
#[inline]
fn advance_uv(u: &mut [u8; 32], v: &mut [u8; 32], c: &[u8; 32]) {
    *u = xor32(&perm_a(u), c);
    *v = perm_a(&perm_a(v));
}

// Reverse `chunk`, encrypt with GOST 28147-89 using cached LUT, reverse the result.
#[inline]
fn encrypt_chunk(lut: &Lut, key: &[u8; 32], chunk: [u8; 8]) -> [u8; 8] {
    let mut subkeys = [0u32; 8];
    for (i, c) in key.chunks_exact(4).enumerate() {
        subkeys[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    let mut rev = chunk;
    rev.reverse();
    let mut out = encrypt_with_lut(&subkeys, lut, rev);
    out.reverse();
    out
}

// GOST R 34.11-94 step function.
// Both `h` and `m` must be 32-byte big-endian blocks (reversed from raw data,
// as produced by the digest's `process_block` method).
#[expect(clippy::many_single_char_names, reason = "standard GOST variable names from RFC 5831")]
fn step(h: &[u8; 32], m: &[u8; 32], lut: &Lut) -> [u8; 32] {
    let zeros = [0u8; 32];
    let mut u = *h;
    let mut v = *m;

    let k1 = derive_key(&u, &v);
    advance_uv(&mut u, &mut v, &zeros);      // C2 = 0
    let k2 = derive_key(&u, &v);
    advance_uv(&mut u, &mut v, &C3);
    let k3 = derive_key(&u, &v);
    advance_uv(&mut u, &mut v, &zeros);      // C4 = 0
    let k4 = derive_key(&u, &v);

    let mut s = [0u8; 32];
    s[24..32].copy_from_slice(&encrypt_chunk(lut, &k1, h[24..32].try_into().unwrap()));
    s[16..24].copy_from_slice(&encrypt_chunk(lut, &k2, h[16..24].try_into().unwrap()));
    s[8..16].copy_from_slice( &encrypt_chunk(lut, &k3, h[8..16].try_into().unwrap()));
    s[0..8].copy_from_slice(  &encrypt_chunk(lut, &k4, h[0..8].try_into().unwrap()));

    chi_n(&xor32(h, &chi(&xor32(m, &chi_n(&s, 12)))), 61)
}

/// GOST R 34.11-94 hash function.
///
/// Use [`Gost341194::new_with_cryptopro`] for `КриптоПро` CSP compatibility.
pub struct Gost341194 {
    lut: Lut,
    /// Current hash state (32 bytes).
    h: [u8; 32],
    /// Running checksum accumulator (big-endian 256-bit).
    checksum: [u8; 32],
    /// Total number of bits processed so far (from complete blocks only).
    bit_len: u64,
    /// Partial data buffer (up to 31 bytes).
    buf: [u8; 32],
    buf_len: usize,
}

impl Gost341194 {
    /// Create a new hasher with the **`CryptoPro`** S-box.
    ///
    /// This is compatible with `КриптоПро` CSP and is the most common variant.
    #[must_use]
    pub fn new_with_cryptopro() -> Self {
        Self::new_with_sbox(&SBOX_CRYPTOPRO)
    }

    /// Create a new hasher with a custom S-box.
    #[must_use]
    pub fn new_with_sbox(sbox: &Sbox) -> Self {
        Self {
            lut: build_lut(sbox),
            h: [0u8; 32],
            checksum: [0u8; 32],
            bit_len: 0,
            buf: [0u8; 32],
            buf_len: 0,
        }
    }

    // Process one complete 32-byte block.
    fn process_block(&mut self, block: &[u8; 32]) {
        // gogost reference implementation convention.
        let mut rev = *block;
        rev.reverse();
        self.checksum = add256_be(&self.checksum, &rev);
        self.h = step(&self.h, &rev, &self.lut);
        self.bit_len = self.bit_len.wrapping_add(256);
    }

    /// Compute the final hash. Consumes self.
    #[must_use]
    pub fn finalize_bytes(self) -> [u8; 32] {
        let mut h = self.h;
        let mut checksum = self.checksum;
        let mut bit_len = self.bit_len;

        if self.buf_len > 0 {
            bit_len = bit_len.wrapping_add((self.buf_len as u64) * 8);
            // Zero-pad on the RIGHT, then reverse (matching Go's blockReverse).
            // block = [b0..bN-1, 0..0] → reversed = [0..0, bN-1..b0]
            let mut block = [0u8; 32];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            block.reverse();
            checksum = add256_be(&checksum, &block);
            h = step(&h, &block, &self.lut);
        }

        // Length block: bit_len as u64 big-endian in bytes [24..32], rest zero.
        let mut len_block = [0u8; 32];
        len_block[24..32].copy_from_slice(&bit_len.to_be_bytes());
        h = step(&h, &len_block, &self.lut);

        // Checksum block: checksum is already in big-endian format.
        h = step(&h, &checksum, &self.lut);

        h.reverse();
        h
    }
}

impl HashMarker for Gost341194 {}

impl OutputSizeUser for Gost341194 {
    type OutputSize = U32;
}

impl Update for Gost341194 {
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        if self.buf_len > 0 {
            let take = (32 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset += take;
            if self.buf_len == 32 {
                let block: [u8; 32] = self.buf;
                self.process_block(&block);
                self.buf_len = 0;
            }
        }

        while offset + 32 <= data.len() {
            // SAFETY: data[offset..offset+32] is exactly 32 bytes.
            let block: [u8; 32] = data[offset..offset + 32].try_into().unwrap();
            self.process_block(&block);
            offset += 32;
        }

        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }
}

impl digest::FixedOutput for Gost341194 {
    fn finalize_into(self, out: &mut Output<Self>) {
        out.copy_from_slice(&self.finalize_bytes());
    }
}

impl Reset for Gost341194 {
    fn reset(&mut self) {
        self.h        = [0u8; 32];
        self.checksum = [0u8; 32];
        self.bit_len  = 0;
        self.buf      = [0u8; 32];
        self.buf_len  = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Update;

    fn hash_hex(sbox: &Sbox, data: &[u8]) -> [u8; 32] {
        let mut h = Gost341194::new_with_sbox(sbox);
        Update::update(&mut h, data);
        h.finalize_bytes()
    }

    mod finalize_bytes {
        use super::*;

        // Regression vectors — derived from this implementation.
        // Cross-verify against gogost or RFC 5831 §7 before publishing.

        #[test]
        fn empty_input_test_sbox() {
            let got = hash_hex(&crate::sbox::SBOX_TEST, b"");
            assert_eq!(got, [
                0xce, 0x85, 0xb9, 0x9c, 0xc4, 0x67, 0x52, 0xff,
                0xfe, 0xe3, 0x5c, 0xab, 0x9a, 0x7b, 0x02, 0x78,
                0xab, 0xb4, 0xc2, 0xd2, 0x05, 0x5c, 0xff, 0x68,
                0x5a, 0xf4, 0x91, 0x2c, 0x49, 0x49, 0x0f, 0x8d,
            ]);
        }

        #[test]
        fn abc_test_sbox() {
            let got = hash_hex(&crate::sbox::SBOX_TEST, b"abc");
            assert_eq!(got, [
                0xf3, 0x13, 0x43, 0x48, 0xc4, 0x4f, 0xb1, 0xb2,
                0xa2, 0x77, 0x72, 0x9e, 0x22, 0x85, 0xeb, 0xb5,
                0xcb, 0x5e, 0x0f, 0x29, 0xc9, 0x75, 0xbc, 0x75,
                0x3b, 0x70, 0x49, 0x7c, 0x06, 0xa4, 0xd5, 0x1d,
            ]);
        }
    }
}
