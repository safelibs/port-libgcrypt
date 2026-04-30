//! Pure-Rust GOST cryptography, compatible with the `RustCrypto` ecosystem.
//!
//! ## Algorithms
//!
//! | Algorithm | Type | Feature |
//! |-----------|------|---------|
//! | GOST 28147-89 | Block cipher (64-bit block, 256-bit key) | always |
//! | GOST R 34.11-94 | Hash (256-bit, `CryptoPro` / Test param sets) | always |
//! | CMAC / OMAC | MAC over GOST 28147-89 | `mac` |
//! | GOST R 34.11-2012 (Streebog) | Hash 256 / 512-bit | `streebog` |
//!
//! ## Block cipher modes
//!
//! [`Gost28147`] implements [`cipher::BlockCipherEncrypt`] + [`cipher::BlockCipherDecrypt`]
//! + [`cipher::KeyInit`], so standard `RustCrypto` mode crates work out of the box:
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! gost-crypto = "0.2"
//! cbc         = "0.1"
//! cfb-mode    = "0.8"
//! ofb         = "0.6"
//! ```
//!
//! ```ignore
//! use gost_crypto::Gost28147;
//! use cbc::Encryptor;
//! use cipher::{KeyIvInit, BlockEncryptMut, block_padding::Pkcs7};
//!
//! let enc = Encryptor::<Gost28147>::new(&key.into(), &iv.into());
//! let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);
//! ```
//!
//! ## CMAC (feature `mac`)
//!
//! ```toml
//! gost-crypto = { version = "0.2", features = ["mac"] }
//! ```
//!
//! ```ignore
//! use gost_crypto::mac::Gost28147Mac;
//! use digest::Mac;
//! let mut mac = Gost28147Mac::new(&key.into());
//! mac.update(b"message");
//! let tag = mac.finalize().into_bytes();
//! ```
//!
//! ## Streebog (feature `streebog`)
//!
//! ```toml
//! gost-crypto = { version = "0.2", features = ["streebog"] }
//! ```
//!
//! ```ignore
//! use gost_crypto::streebog::{Streebog256, Streebog512};
//! use digest::Digest;
//! let hash = Streebog256::digest(b"hello");
//! ```
//!
//! # Example
//! ```rust
//! use gost_crypto::{Gost341194, SBOX_CRYPTOPRO};
//! use digest::Update;
//!
//! let mut h = Gost341194::new_with_sbox(&SBOX_CRYPTOPRO);
//! Update::update(&mut h, b"hello");
//! let result = h.finalize_bytes();
//! assert_eq!(result.len(), 32);
//! ```

#![no_std]

pub(crate) mod gost28147;
pub(crate) mod gost341194;
pub(crate) mod sbox;

pub use gost28147::Gost28147;
pub use gost341194::Gost341194;
pub use sbox::{Sbox, SBOX_CRYPTOPRO, SBOX_TEST};

/// CMAC/OMAC MAC over GOST 28147-89.
///
/// Enabled with feature `mac`.
#[cfg(feature = "mac")]
pub mod mac {
    /// CMAC authenticator keyed with GOST 28147-89.
    pub type Gost28147Mac = cmac::Cmac<super::Gost28147>;
}

/// GOST R 34.11-2012 (Streebog) hash, 256-bit and 512-bit variants.
///
/// Enabled with feature `streebog`. Re-exports the `streebog` crate.
#[cfg(feature = "streebog")]
pub use streebog;

/// GOST R 34.12-2015 Kuznyechik (Grasshopper) block cipher, 128-bit block, 256-bit key.
///
/// Enabled with feature `kuznyechik`. Re-exports the `kuznyechik` crate.
/// Implements `cipher::BlockCipherEncrypt + BlockCipherDecrypt + KeyInit`.
#[cfg(feature = "kuznyechik")]
pub use ::kuznyechik;

/// HMAC over Streebog-256 and Streebog-512 (RFC 7836 §A.1).
///
/// Enabled with feature `hmac-streebog`.
#[cfg(feature = "hmac-streebog")]
pub mod hmac_streebog {
    /// HMAC keyed with Streebog-256.
    pub type HmacStreebog256 = hmac::Hmac<::streebog::Streebog256>;
    /// HMAC keyed with Streebog-512.
    pub type HmacStreebog512 = hmac::Hmac<::streebog::Streebog512>;
}
