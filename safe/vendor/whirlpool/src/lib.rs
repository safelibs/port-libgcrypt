//! An implementation of the [Whirlpool][1] cryptographic hash algorithm.
//!
//! This is the algorithm recommended by NESSIE (New European Schemes for
//! Signatures, Integrity and Encryption; an European research project).
//!
//! The constants used by Whirlpool were changed twice (2001 and 2003) - this
//! crate only implements the most recent standard. The two older Whirlpool
//! implementations (sometimes called Whirlpool-0 (pre 2001) and Whirlpool-T
//! (pre 2003)) were not used much anyway (both have never been recommended
//! by NESSIE).
//!
//! For details see [http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html](https://web.archive.org/web/20171129084214/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html).
//!
//! # Usage
//!
//! ```rust
//! use whirlpool::{Whirlpool, Digest};
//! use hex_literal::hex;
//!
//! // create a hasher object, to use it do not forget to import `Digest` trait
//! let mut hasher = Whirlpool::new();
//! // write input message
//! hasher.update(b"Hello Whirlpool");
//! // read hash digest (it will consume hasher)
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     8eaccdc136903c458ea0b1376be2a5fc9dc5b8ce8892a3b4f43366e2610c206c
//!     a373816495e63db0fff2ff25f75aa7162f332c9f518c3036456502a8414d300a
//! ")[..]);
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/Whirlpool_(hash_function)
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

#[cfg(not(all(feature = "asm", any(target_arch = "x86", target_arch = "x86_64"))))]
mod compress;

#[cfg(all(feature = "asm", any(target_arch = "x86", target_arch = "x86_64")))]
use whirlpool_asm as compress;

use compress::compress;

use core::fmt;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U64},
    HashMarker, Output,
};

/// Core Whirlpool hasher state.
#[derive(Clone)]
pub struct WhirlpoolCore {
    bit_len: [u64; 4],
    state: [u64; 8],
}

impl HashMarker for WhirlpoolCore {}

impl BlockSizeUser for WhirlpoolCore {
    type BlockSize = U64;
}

impl BufferKindUser for WhirlpoolCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for WhirlpoolCore {
    type OutputSize = U64;
}

impl UpdateCore for WhirlpoolCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        let block_bits = 8 * BLOCK_SIZE as u64;
        self.update_len(block_bits * (blocks.len() as u64));
        compress(&mut self.state, convert(blocks));
    }
}

impl FixedOutputCore for WhirlpoolCore {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        self.update_len(8 * pos as u64);

        let mut buf = [0u8; 4 * 8];
        for (chunk, v) in buf.chunks_exact_mut(8).zip(self.bit_len.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }

        let mut state = self.state;
        buffer.digest_pad(0x80, &buf, |block| {
            compress(&mut state, convert(core::slice::from_ref(block)));
        });

        for (chunk, v) in out.chunks_exact_mut(8).zip(state.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl WhirlpoolCore {
    fn update_len(&mut self, len: u64) {
        let mut carry = 0;
        adc(&mut self.bit_len[3], len, &mut carry);
        adc(&mut self.bit_len[2], 0, &mut carry);
        adc(&mut self.bit_len[1], 0, &mut carry);
        adc(&mut self.bit_len[0], 0, &mut carry);
    }
}

// derivable impl does not inline
#[allow(clippy::derivable_impls)]
impl Default for WhirlpoolCore {
    #[inline]
    fn default() -> Self {
        Self {
            bit_len: Default::default(),
            state: [0u64; 8],
        }
    }
}

impl Reset for WhirlpoolCore {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for WhirlpoolCore {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Whirlpool")
    }
}

impl fmt::Debug for WhirlpoolCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WhirlpoolCore { ... }")
    }
}

/// Whirlpool hasher state.
pub type Whirlpool = CoreWrapper<WhirlpoolCore>;

/// Whirlpool state for libgcrypt's `GCRY_MD_FLAG_BUGEMU1` buffering bug.
///
/// This mode is not a Whirlpool variant. It preserves a historical libgcrypt
/// compatibility bug where certain chunk boundaries are not reflected in the
/// encoded message length.
#[derive(Clone)]
pub struct LibgcryptBugemu1 {
    state: [u64; 8],
    buffer: [u8; BLOCK_SIZE],
    count: usize,
    length: [u8; 32],
}

impl LibgcryptBugemu1 {
    /// Create a new bug-emulation state.
    pub fn new() -> Self {
        Self {
            state: [0u64; 8],
            buffer: [0u8; BLOCK_SIZE],
            count: 0,
            length: [0u8; 32],
        }
    }

    /// Add one caller-provided chunk.
    pub fn update(&mut self, data: &[u8]) {
        bugemu_add(self, Some(data));
    }

    /// Finalize and return the bug-emulation digest without consuming state.
    pub fn finalize(&self) -> [u8; 64] {
        let mut ctx = self.clone();
        bugemu_add(&mut ctx, None);

        ctx.buffer[ctx.count] = 0x80;
        ctx.count += 1;

        if ctx.count > 32 {
            while ctx.count < BLOCK_SIZE {
                ctx.buffer[ctx.count] = 0;
                ctx.count += 1;
            }
            bugemu_add(&mut ctx, None);
        }
        while ctx.count < 32 {
            ctx.buffer[ctx.count] = 0;
            ctx.count += 1;
        }

        let count = ctx.count;
        ctx.buffer[count..count + 32].copy_from_slice(&ctx.length);
        ctx.count += 32;
        bugemu_add(&mut ctx, None);

        let mut out = [0u8; 64];
        for (chunk, word) in out.chunks_exact_mut(8).zip(ctx.state.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

impl Default for LibgcryptBugemu1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute Whirlpool using libgcrypt's `GCRY_MD_FLAG_BUGEMU1` buffering bug.
pub fn libgcrypt_bugemu1_digest(chunks: &[&[u8]]) -> [u8; 64] {
    let mut ctx = LibgcryptBugemu1::new();
    for chunk in chunks {
        ctx.update(chunk);
    }
    ctx.finalize()
}


#[inline(always)]
fn adc(a: &mut u64, b: u64, carry: &mut u64) {
    let ret = (*a as u128) + (b as u128) + (*carry as u128);
    *a = ret as u64;
    *carry = (ret >> 64) as u64;
}

const BLOCK_SIZE: usize = <WhirlpoolCore as BlockSizeUser>::BlockSize::USIZE;

#[inline(always)]
fn convert(blocks: &[Block<WhirlpoolCore>]) -> &[[u8; BLOCK_SIZE]] {
    // SAFETY: GenericArray<u8, U64> and [u8; 64] have
    // exactly the same memory layout
    let p = blocks.as_ptr() as *const [u8; BLOCK_SIZE];
    unsafe { core::slice::from_raw_parts(p, blocks.len()) }
}

fn bugemu_flush_full(ctx: &mut LibgcryptBugemu1) {
    if ctx.count == BLOCK_SIZE {
        compress(&mut ctx.state, core::slice::from_ref(&ctx.buffer));
        ctx.count = 0;
    }
}

fn bugemu_add(ctx: &mut LibgcryptBugemu1, input: Option<&[u8]>) {
    bugemu_flush_full(ctx);
    let Some(mut input) = input else {
        return;
    };
    let original_len = input.len() as u64;

    if ctx.count != 0 {
        let take = core::cmp::min(BLOCK_SIZE - ctx.count, input.len());
        ctx.buffer[ctx.count..ctx.count + take].copy_from_slice(&input[..take]);
        ctx.count += take;
        input = &input[take..];
        bugemu_flush_full(ctx);
        if input.is_empty() {
            return;
        }
    }

    while input.len() >= BLOCK_SIZE {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(&input[..BLOCK_SIZE]);
        compress(&mut ctx.state, core::slice::from_ref(&block));
        ctx.count = 0;
        input = &input[BLOCK_SIZE..];
    }

    if !input.is_empty() {
        ctx.buffer[..input.len()].copy_from_slice(input);
        ctx.count = input.len();
    }

    bugemu_update_length(&mut ctx.length, original_len);
}

fn bugemu_update_length(length: &mut [u8; 32], byte_len: u64) {
    let mut bit_len = byte_len << 3;
    let mut carry = 0u16;
    for i in 1..=32 {
        if bit_len == 0 && carry == 0 {
            break;
        }
        let index = 32 - i;
        let sum = length[index] as u16 + (bit_len & 0xff) as u16 + carry;
        length[index] = sum as u8;
        bit_len >>= 8;
        carry = sum >> 8;
    }
}
