//! RFC 7836 §A.1 known-answer tests for HMAC-Streebog.

#[cfg(feature = "hmac-streebog")]
mod kat {
    use gost_crypto::hmac_streebog::{HmacStreebog256, HmacStreebog512};
    use digest::Mac;
    use hex_literal::hex;

    const KEY: &[u8] = &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const DATA: &[u8] = &hex!("0126bdb87800af214341456563780100");

    #[test]
    fn hmac_streebog256_rfc7836() {
        let mut mac = HmacStreebog256::new_from_slice(KEY).unwrap();
        mac.update(DATA);
        let result = mac.finalize().into_bytes();
        assert_eq!(result.as_slice(), &hex!(
            "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"
        ));
    }

    #[test]
    fn hmac_streebog512_rfc7836() {
        let mut mac = HmacStreebog512::new_from_slice(KEY).unwrap();
        mac.update(DATA);
        let result = mac.finalize().into_bytes();
        assert_eq!(result.as_slice(), &hex!(
            "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77\
             3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"
        ));
    }

    #[test]
    fn hmac256_incremental_update_matches_single() {
        let mut mac1 = HmacStreebog256::new_from_slice(KEY).unwrap();
        mac1.update(DATA);

        // Split data in half
        let mut mac2 = HmacStreebog256::new_from_slice(KEY).unwrap();
        mac2.update(&DATA[..DATA.len()/2]);
        mac2.update(&DATA[DATA.len()/2..]);

        assert_eq!(
            mac1.finalize().into_bytes(),
            mac2.finalize().into_bytes()
        );
    }

    #[test]
    fn hmac512_incremental_update_matches_single() {
        let mut mac1 = HmacStreebog512::new_from_slice(KEY).unwrap();
        mac1.update(DATA);

        let mut mac2 = HmacStreebog512::new_from_slice(KEY).unwrap();
        mac2.update(&DATA[..8]);
        mac2.update(&DATA[8..]);

        assert_eq!(
            mac1.finalize().into_bytes(),
            mac2.finalize().into_bytes()
        );
    }
}
