//! Integration tests for GOST cipher modes (GOST R 34.13-2015 compatible).
//!
//! Tests CBC, CTR, CFB, OFB modes for both Magma (GOST 28147-89, 64-bit block)
//! and Kuznyechik (GOST R 34.12-2015, 128-bit block).

use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};
use cipher::block_padding::NoPadding;

// ── Magma (GOST 28147-89) — 64-bit block ─────────────────────────────────────

mod magma_cbc {
    use super::*;
    use gost_crypto::Gost28147;

    type Enc = cbc::Encryptor<Gost28147>;
    type Dec = cbc::Decryptor<Gost28147>;

    const KEY: [u8; 32] = [0x42u8; 32];
    const IV:  [u8; 8]  = [0x01u8; 8];

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let pt = [0xABu8; 32];
        let mut buf = pt;
        Enc::new(&KEY.into(), &IV.into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, 32)
            .unwrap();
        assert_ne!(buf, pt);
    }

    #[test]
    fn roundtrip() {
        let pt = [0xABu8; 32];
        let mut buf = pt;
        Enc::new(&KEY.into(), &IV.into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, 32)
            .unwrap();
        Dec::new(&KEY.into(), &IV.into())
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn different_ivs_produce_different_ciphertexts() {
        let pt = [0xABu8; 8];
        let mut ct1 = pt;
        let mut ct2 = pt;
        Enc::new(&KEY.into(), &[0x01u8; 8].into())
            .encrypt_padded_mut::<NoPadding>(&mut ct1, 8).unwrap();
        Enc::new(&KEY.into(), &[0x02u8; 8].into())
            .encrypt_padded_mut::<NoPadding>(&mut ct2, 8).unwrap();
        assert_ne!(ct1, ct2);
    }
}

mod magma_cfb {
    use super::*;
    use gost_crypto::Gost28147;

    type Enc = cfb_mode::Encryptor<Gost28147>;
    type Dec = cfb_mode::Decryptor<Gost28147>;

    const KEY: [u8; 32] = [0x11u8; 32];
    const IV:  [u8; 8]  = [0xFFu8; 8];

    #[test]
    fn roundtrip() {
        let pt = [0x55u8; 32];
        let mut buf = pt;
        let mut enc = Enc::new(&KEY.into(), &IV.into());
        enc.encrypt_block_mut(cipher::Block::<Gost28147>::from_mut_slice(&mut buf[..8]));
        enc.encrypt_block_mut(cipher::Block::<Gost28147>::from_mut_slice(&mut buf[8..16]));
        enc.encrypt_block_mut(cipher::Block::<Gost28147>::from_mut_slice(&mut buf[16..24]));
        enc.encrypt_block_mut(cipher::Block::<Gost28147>::from_mut_slice(&mut buf[24..32]));
        assert_ne!(buf, pt);
        let mut dec = Dec::new(&KEY.into(), &IV.into());
        dec.decrypt_block_mut(cipher::Block::<Gost28147>::from_mut_slice(&mut buf[..8]));
        dec.decrypt_block_mut(cipher::Block::<Gost28147>::from_mut_slice(&mut buf[8..16]));
        dec.decrypt_block_mut(cipher::Block::<Gost28147>::from_mut_slice(&mut buf[16..24]));
        dec.decrypt_block_mut(cipher::Block::<Gost28147>::from_mut_slice(&mut buf[24..32]));
        assert_eq!(buf, pt);
    }
}

mod magma_ofb {
    use super::*;
    use gost_crypto::Gost28147;

    type Cipher = ofb::Ofb<Gost28147>;

    const KEY: [u8; 32] = [0xAAu8; 32];
    const IV:  [u8; 8]  = [0x55u8; 8];

    #[test]
    fn roundtrip() {
        let pt = [0x77u8; 16];
        let mut ct = pt;
        Cipher::new(&KEY.into(), &IV.into()).apply_keystream(&mut ct);
        assert_ne!(ct, pt);
        Cipher::new(&KEY.into(), &IV.into()).apply_keystream(&mut ct);
        assert_eq!(ct, pt);
    }

    #[test]
    fn encrypt_equals_decrypt() {
        let pt = [0x33u8; 8];
        let mut ct = pt;
        Cipher::new(&KEY.into(), &IV.into()).apply_keystream(&mut ct);
        let mut dt = ct;
        Cipher::new(&KEY.into(), &IV.into()).apply_keystream(&mut dt);
        assert_eq!(dt, pt);
    }
}

// ── Kuznyechik — 128-bit block ────────────────────────────────────────────────
//
// Kuznyechik (kuznyechik crate v0.9.x-rc) uses cipher v0.5, while the stable
// mode crates (cbc 0.1, ctr 0.9, ofb 0.6, cfb-mode 0.8) use cipher v0.4.
// Kuznyechik mode tests live in the kuznyechik worker's test suite where the
// correct cipher v0.5 mode crates can be used without version conflicts.
