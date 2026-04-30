//! GOST 28147-89 block cipher (RFC 5830).
//!
//! 64-bit block, 256-bit key. Implements [`cipher::BlockEncrypt`],
//! [`cipher::BlockDecrypt`] and [`cipher::KeyInit`] for `RustCrypto` compatibility.
//!
//! Use with external mode crates: `cbc`, `cfb-mode`, `ofb`, `cmac`, etc.
//!
//! [`KeyInit::new`] uses the **`CryptoPro`** S-box. For other S-boxes use
//! [`Gost28147::with_sbox`].

use cipher::{BlockCipher, KeyInit, KeySizeUser, consts::{U8, U32}};
use crate::sbox::{Sbox, SBOX_CRYPTOPRO};

/// Precomputed substitution+rotation table.
/// `LUT[i][b]` = contribution of byte `b` at byte position `i` after S-box + `rotate_left(11)`.
pub(crate) type Lut = [[u32; 256]; 4];

/// Build a [`Lut`] from an S-box.
///
/// Each byte position `i` covers S-box rows `2*i` (low nibble) and `2*i+1` (high nibble).
/// The full `apply_sbox(x).rotate_left(11)` is then `LUT[0][b0]^LUT[1][b1]^LUT[2][b2]^LUT[3][b3]`.
pub(crate) fn build_lut(sbox: &Sbox) -> Lut {
    let mut t = [[0u32; 256]; 4];
    for i in 0..4usize {
        for b in 0..256usize {
            let lo = u32::from(sbox[2 * i][b & 0xF]);
            let hi = u32::from(sbox[2 * i + 1][(b >> 4) & 0xF]);
            // SAFETY: i ∈ 0..4, so 8*i ∈ {0,8,16,24} — fits in u32.
            #[expect(clippy::cast_possible_truncation, reason = "i ∈ 0..4, shift ≤ 24")]
            let shift = (8 * i) as u32;
            t[i][b] = (lo | (hi << 4)).wrapping_shl(shift).rotate_left(11);
        }
    }
    t
}

/// Encrypt one 8-byte block using precomputed `lut` and `subkeys`, without creating a struct.
#[inline]
pub(crate) fn encrypt_with_lut(subkeys: &[u32; 8], lut: &Lut, block: [u8; 8]) -> [u8; 8] {
    xcrypt_lut(subkeys, lut, &SEQ_ENCRYPT, block)
}

#[inline]
fn xcrypt_lut(subkeys: &[u32; 8], lut: &Lut, seq: &[usize; 32], block: [u8; 8]) -> [u8; 8] {
    let mut n1 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    let mut n2 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
    for &ki in seq {
        let x = n1.wrapping_add(subkeys[ki]);
        let t = lut[0][(x & 0xFF) as usize]
            ^ lut[1][((x >> 8)  & 0xFF) as usize]
            ^ lut[2][((x >> 16) & 0xFF) as usize]
            ^ lut[3][((x >> 24) & 0xFF) as usize];
        let new_n1 = t ^ n2;
        n2 = n1;
        n1 = new_n1;
    }
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&n2.to_le_bytes());
    out[4..8].copy_from_slice(&n1.to_le_bytes());
    out
}

/// Encryption key schedule: K0–K7 ×3, then K7–K0.
const SEQ_ENCRYPT: [usize; 32] = [
    0,1,2,3,4,5,6,7,
    0,1,2,3,4,5,6,7,
    0,1,2,3,4,5,6,7,
    7,6,5,4,3,2,1,0,
];

/// Decryption key schedule: K0–K7, then K7–K0 ×3.
const SEQ_DECRYPT: [usize; 32] = [
    0,1,2,3,4,5,6,7,
    7,6,5,4,3,2,1,0,
    7,6,5,4,3,2,1,0,
    7,6,5,4,3,2,1,0,
];

/// GOST 28147-89 block cipher.
///
/// Implements [`cipher::KeyInit`] (`CryptoPro` S-box), [`cipher::BlockEncrypt`],
/// and [`cipher::BlockDecrypt`].
#[derive(Clone)]
pub struct Gost28147 {
    subkeys: [u32; 8],
    lut: Lut,
}

impl Gost28147 {
    /// Construct with an explicit S-box.
    ///
    /// Use this when you need a parameter set other than `CryptoPro`
    /// (e.g. [`crate::SBOX_TEST`] for RFC 5831 test vectors).
    #[must_use]
    pub fn with_sbox(key: &[u8; 32], sbox: &Sbox) -> Self {
        let mut subkeys = [0u32; 8];
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            subkeys[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        Self { subkeys, lut: build_lut(sbox) }
    }

    /// Low-level: no trait overhead.
    #[inline]
    #[must_use]
    pub fn encrypt_block_raw(&self, block: [u8; 8]) -> [u8; 8] {
        xcrypt_lut(&self.subkeys, &self.lut, &SEQ_ENCRYPT, block)
    }

    /// Low-level: no trait overhead.
    #[inline]
    #[must_use]
    pub fn decrypt_block_raw(&self, block: [u8; 8]) -> [u8; 8] {
        xcrypt_lut(&self.subkeys, &self.lut, &SEQ_DECRYPT, block)
    }
}

impl KeySizeUser for Gost28147 {
    type KeySize = U32;
}

impl BlockCipher for Gost28147 {}

/// Uses **`CryptoPro`** S-box. For other S-boxes use [`Gost28147::with_sbox`].
impl KeyInit for Gost28147 {
    fn new(key: &cipher::Key<Self>) -> Self {
        // SAFETY: Key<Gost28147> = GenericArray<u8, U32>, always exactly 32 bytes.
        let bytes: &[u8; 32] = key.as_slice().try_into().unwrap();
        Self::with_sbox(bytes, &SBOX_CRYPTOPRO)
    }
}

cipher::impl_simple_block_encdec!(
    <> Gost28147, U8, state, block,
    encrypt: {
        let pt: [u8; 8] = block.get_in().as_slice().try_into().unwrap();
        let ct = state.encrypt_block_raw(pt);
        block.get_out().copy_from_slice(&ct);
    }
    decrypt: {
        let ct: [u8; 8] = block.get_in().as_slice().try_into().unwrap();
        let pt = state.decrypt_block_raw(ct);
        block.get_out().copy_from_slice(&pt);
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    use crate::sbox::SBOX_CRYPTOPRO;

    fn test_cipher() -> Gost28147 {
        let key: [u8; 32] = [
            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
            0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
            0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
        ];
        Gost28147::with_sbox(&key, &SBOX_CRYPTOPRO)
    }

    mod encrypt_block_raw {
        use super::*;

        #[test]
        fn ciphertext_differs_from_plaintext() {
            let pt = [0x01u8,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF];
            let ct = test_cipher().encrypt_block_raw(pt);
            assert_ne!(pt, ct);
        }

        #[test]
        fn decrypt_recovers_original() {
            let c = test_cipher();
            let pt = [0x01u8,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF];
            let ct = c.encrypt_block_raw(pt);
            assert_eq!(c.decrypt_block_raw(ct), pt);
        }
    }

    mod trait_roundtrip {
        use super::*;

        #[test]
        fn encrypt_then_decrypt_returns_original() {
            let key = [0x42u8; 32];
            let c = Gost28147::new(&key.into());
            let pt_orig: [u8; 8] = [1,2,3,4,5,6,7,8];
            let mut buf = cipher::Block::<Gost28147>::clone_from_slice(&pt_orig);
            c.encrypt_block(&mut buf);
            assert_ne!(buf.as_slice(), &pt_orig);
            c.decrypt_block(&mut buf);
            assert_eq!(buf.as_slice(), &pt_orig);
        }
    }

    mod zero_inputs {
        use super::*;

        #[test]
        fn zero_key_zero_block_does_not_panic() {
            let c = Gost28147::new(&[0u8; 32].into());
            let _ = c.encrypt_block_raw([0u8; 8]);
        }
    }
}
