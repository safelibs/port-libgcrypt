//! RFC 7801 §A known-answer tests for Kuznyechik.

#[cfg(feature = "kuznyechik")]
mod kat {
    use gost_crypto::kuznyechik::Kuznyechik;
    use gost_crypto::kuznyechik::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use hex_literal::hex;

    fn make_cipher() -> Kuznyechik {
        let key = hex!("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF");
        Kuznyechik::new(&key.into())
    }

    #[test]
    fn rfc7801_encrypt_block() {
        let c = make_cipher();
        let mut block = hex!("1122334455667700FFEEDDCCBBAA9988");
        c.encrypt_block((&mut block).into());
        assert_eq!(block, hex!("7F679D90BEBC24305A468D42B9D4EDCD"));
    }

    #[test]
    fn rfc7801_decrypt_block() {
        let c = make_cipher();
        let mut block = hex!("7F679D90BEBC24305A468D42B9D4EDCD");
        c.decrypt_block((&mut block).into());
        assert_eq!(block, hex!("1122334455667700FFEEDDCCBBAA9988"));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let c = make_cipher();
        let pt_orig = hex!("DEADBEEFCAFEBABE0123456789ABCDEF");
        let mut block = pt_orig;
        c.encrypt_block((&mut block).into());
        assert_ne!(block, pt_orig);
        c.decrypt_block((&mut block).into());
        assert_eq!(block, pt_orig);
    }

    #[test]
    fn zero_key_zero_block_no_panic() {
        let c = Kuznyechik::new(&[0u8; 32].into());
        let mut block = [0u8; 16];
        c.encrypt_block((&mut block).into());
    }
}
