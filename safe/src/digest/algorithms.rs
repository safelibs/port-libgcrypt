use std::ffi::c_int;

use super::gcry_md_hd_t;

pub(crate) const GCRY_MD_NONE: c_int = 0;
pub(crate) const GCRY_MD_MD5: c_int = 1;
pub(crate) const GCRY_MD_SHA1: c_int = 2;
pub(crate) const GCRY_MD_RMD160: c_int = 3;
pub(crate) const GCRY_MD_MD2: c_int = 5;
pub(crate) const GCRY_MD_TIGER: c_int = 6;
pub(crate) const GCRY_MD_HAVAL: c_int = 7;
pub(crate) const GCRY_MD_SHA256: c_int = 8;
pub(crate) const GCRY_MD_SHA384: c_int = 9;
pub(crate) const GCRY_MD_SHA512: c_int = 10;
pub(crate) const GCRY_MD_SHA224: c_int = 11;
pub(crate) const GCRY_MD_MD4: c_int = 301;
pub(crate) const GCRY_MD_CRC32: c_int = 302;
pub(crate) const GCRY_MD_CRC32_RFC1510: c_int = 303;
pub(crate) const GCRY_MD_CRC24_RFC2440: c_int = 304;
pub(crate) const GCRY_MD_WHIRLPOOL: c_int = 305;
pub(crate) const GCRY_MD_TIGER1: c_int = 306;
pub(crate) const GCRY_MD_TIGER2: c_int = 307;
pub(crate) const GCRY_MD_GOSTR3411_94: c_int = 308;
pub(crate) const GCRY_MD_STRIBOG256: c_int = 309;
pub(crate) const GCRY_MD_STRIBOG512: c_int = 310;
pub(crate) const GCRY_MD_GOSTR3411_CP: c_int = 311;
pub(crate) const GCRY_MD_SHA3_224: c_int = 312;
pub(crate) const GCRY_MD_SHA3_256: c_int = 313;
pub(crate) const GCRY_MD_SHA3_384: c_int = 314;
pub(crate) const GCRY_MD_SHA3_512: c_int = 315;
pub(crate) const GCRY_MD_SHAKE128: c_int = 316;
pub(crate) const GCRY_MD_SHAKE256: c_int = 317;
pub(crate) const GCRY_MD_BLAKE2B_512: c_int = 318;
pub(crate) const GCRY_MD_BLAKE2B_384: c_int = 319;
pub(crate) const GCRY_MD_BLAKE2B_256: c_int = 320;
pub(crate) const GCRY_MD_BLAKE2B_160: c_int = 321;
pub(crate) const GCRY_MD_BLAKE2S_256: c_int = 322;
pub(crate) const GCRY_MD_BLAKE2S_224: c_int = 323;
pub(crate) const GCRY_MD_BLAKE2S_160: c_int = 324;
pub(crate) const GCRY_MD_BLAKE2S_128: c_int = 325;
pub(crate) const GCRY_MD_SM3: c_int = 326;
pub(crate) const GCRY_MD_SHA512_256: c_int = 327;
pub(crate) const GCRY_MD_SHA512_224: c_int = 328;

const SHA1_ASNOID: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const SHA224_ASNOID: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
    0x05, 0x00, 0x04, 0x1c,
];
const SHA256_ASNOID: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];
const SHA384_ASNOID: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0x05, 0x00, 0x04, 0x30,
];
const SHA512_ASNOID: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    0x05, 0x00, 0x04, 0x40,
];
const SHA512_224_ASNOID: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
    0x05, 0x00, 0x04, 0x1c,
];
const SHA512_256_ASNOID: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
    0x05, 0x00, 0x04, 0x20,
];
const SHA3_224_ASNOID: &[u8] = &[
    0x30, 0x2b, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
    0x04, 0x1c,
];
const SHA3_256_ASNOID: &[u8] = &[
    0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
    0x04, 0x20,
];
const SHA3_384_ASNOID: &[u8] = &[
    0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
    0x04, 0x30,
];
const SHA3_512_ASNOID: &[u8] = &[
    0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
    0x04, 0x40,
];
const SM3_ASNOID: &[u8] = &[
    0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11, 0x05,
    0x00, 0x04, 0x20,
];

#[derive(Clone, Copy, Debug)]
pub(crate) struct DigestInfo {
    pub(crate) available: bool,
    pub(crate) output_len: usize,
    pub(crate) block_len: usize,
    pub(crate) xof: bool,
    pub(crate) oid_der: Option<&'static [u8]>,
    pub(crate) oid_text: Option<&'static str>,
}

fn digest_info_impl(algo: c_int) -> Option<DigestInfo> {
    let info = match algo {
        GCRY_MD_MD5 => DigestInfo {
            available: true,
            output_len: 16,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: None,
        },
        GCRY_MD_SHA1 => DigestInfo {
            available: true,
            output_len: 20,
            block_len: 64,
            xof: false,
            oid_der: Some(SHA1_ASNOID),
            oid_text: Some("1.3.14.3.2.26"),
        },
        GCRY_MD_RMD160 => DigestInfo {
            available: false,
            output_len: 20,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: Some("1.3.36.3.2.1"),
        },
        GCRY_MD_MD2 => DigestInfo {
            available: false,
            output_len: 16,
            block_len: 16,
            xof: false,
            oid_der: None,
            oid_text: Some("1.2.840.113549.2.2"),
        },
        GCRY_MD_TIGER | GCRY_MD_TIGER1 | GCRY_MD_TIGER2 => DigestInfo {
            available: false,
            output_len: 24,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: match algo {
                GCRY_MD_TIGER1 => Some("1.3.6.1.4.1.11591.12.2"),
                _ => None,
            },
        },
        GCRY_MD_HAVAL => DigestInfo {
            available: false,
            output_len: 20,
            block_len: 128,
            xof: false,
            oid_der: None,
            oid_text: None,
        },
        GCRY_MD_SHA224 => DigestInfo {
            available: true,
            output_len: 28,
            block_len: 64,
            xof: false,
            oid_der: Some(SHA224_ASNOID),
            oid_text: Some("2.16.840.1.101.3.4.2.4"),
        },
        GCRY_MD_SHA256 => DigestInfo {
            available: true,
            output_len: 32,
            block_len: 64,
            xof: false,
            oid_der: Some(SHA256_ASNOID),
            oid_text: Some("2.16.840.1.101.3.4.2.1"),
        },
        GCRY_MD_SHA384 => DigestInfo {
            available: true,
            output_len: 48,
            block_len: 128,
            xof: false,
            oid_der: Some(SHA384_ASNOID),
            oid_text: Some("2.16.840.1.101.3.4.2.2"),
        },
        GCRY_MD_SHA512 => DigestInfo {
            available: true,
            output_len: 64,
            block_len: 128,
            xof: false,
            oid_der: Some(SHA512_ASNOID),
            oid_text: Some("2.16.840.1.101.3.4.2.3"),
        },
        GCRY_MD_MD4 => DigestInfo {
            available: false,
            output_len: 16,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: Some("1.2.840.113549.2.4"),
        },
        GCRY_MD_CRC32 => DigestInfo {
            available: false,
            output_len: 4,
            block_len: 1,
            xof: false,
            oid_der: None,
            oid_text: None,
        },
        GCRY_MD_CRC32_RFC1510 => DigestInfo {
            available: false,
            output_len: 4,
            block_len: 1,
            xof: false,
            oid_der: None,
            oid_text: None,
        },
        GCRY_MD_CRC24_RFC2440 => DigestInfo {
            available: false,
            output_len: 3,
            block_len: 1,
            xof: false,
            oid_der: None,
            oid_text: None,
        },
        GCRY_MD_WHIRLPOOL => DigestInfo {
            available: false,
            output_len: 64,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: Some("1.0.10118.3.0.55"),
        },
        GCRY_MD_GOSTR3411_94 => DigestInfo {
            available: false,
            output_len: 32,
            block_len: 32,
            xof: false,
            oid_der: None,
            oid_text: None,
        },
        GCRY_MD_GOSTR3411_CP => DigestInfo {
            available: true,
            output_len: 32,
            block_len: 32,
            xof: false,
            oid_der: None,
            oid_text: Some("1.2.643.2.2.9"),
        },
        GCRY_MD_STRIBOG256 => DigestInfo {
            available: true,
            output_len: 32,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: Some("1.2.643.7.1.1.2.2"),
        },
        GCRY_MD_STRIBOG512 => DigestInfo {
            available: true,
            output_len: 64,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: Some("1.2.643.7.1.1.2.3"),
        },
        GCRY_MD_SHA3_224 => DigestInfo {
            available: true,
            output_len: 28,
            block_len: 144,
            xof: false,
            oid_der: Some(SHA3_224_ASNOID),
            oid_text: Some("2.16.840.1.101.3.4.2.7"),
        },
        GCRY_MD_SHA3_256 => DigestInfo {
            available: true,
            output_len: 32,
            block_len: 136,
            xof: false,
            oid_der: Some(SHA3_256_ASNOID),
            oid_text: Some("2.16.840.1.101.3.4.2.8"),
        },
        GCRY_MD_SHA3_384 => DigestInfo {
            available: true,
            output_len: 48,
            block_len: 104,
            xof: false,
            oid_der: Some(SHA3_384_ASNOID),
            oid_text: Some("2.16.840.1.101.3.4.2.9"),
        },
        GCRY_MD_SHA3_512 => DigestInfo {
            available: true,
            output_len: 64,
            block_len: 72,
            xof: false,
            oid_der: Some(SHA3_512_ASNOID),
            oid_text: Some("2.16.840.1.101.3.4.2.10"),
        },
        GCRY_MD_SHAKE128 => DigestInfo {
            available: true,
            output_len: 0,
            block_len: 168,
            xof: true,
            oid_der: None,
            oid_text: Some("2.16.840.1.101.3.4.2.11"),
        },
        GCRY_MD_SHAKE256 => DigestInfo {
            available: true,
            output_len: 0,
            block_len: 136,
            xof: true,
            oid_der: None,
            oid_text: Some("2.16.840.1.101.3.4.2.12"),
        },
        GCRY_MD_BLAKE2B_512 => DigestInfo {
            available: false,
            output_len: 64,
            block_len: 128,
            xof: false,
            oid_der: None,
            oid_text: Some("1.3.6.1.4.1.1722.12.2.1.16"),
        },
        GCRY_MD_BLAKE2B_384 => DigestInfo {
            available: false,
            output_len: 48,
            block_len: 128,
            xof: false,
            oid_der: None,
            oid_text: Some("1.3.6.1.4.1.1722.12.2.1.12"),
        },
        GCRY_MD_BLAKE2B_256 => DigestInfo {
            available: false,
            output_len: 32,
            block_len: 128,
            xof: false,
            oid_der: None,
            oid_text: Some("1.3.6.1.4.1.1722.12.2.1.8"),
        },
        GCRY_MD_BLAKE2B_160 => DigestInfo {
            available: false,
            output_len: 20,
            block_len: 128,
            xof: false,
            oid_der: None,
            oid_text: Some("1.3.6.1.4.1.1722.12.2.1.5"),
        },
        GCRY_MD_BLAKE2S_256 => DigestInfo {
            available: false,
            output_len: 32,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: Some("1.3.6.1.4.1.1722.12.2.2.8"),
        },
        GCRY_MD_BLAKE2S_224 => DigestInfo {
            available: false,
            output_len: 28,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: Some("1.3.6.1.4.1.1722.12.2.2.7"),
        },
        GCRY_MD_BLAKE2S_160 => DigestInfo {
            available: false,
            output_len: 20,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: Some("1.3.6.1.4.1.1722.12.2.2.5"),
        },
        GCRY_MD_BLAKE2S_128 => DigestInfo {
            available: false,
            output_len: 16,
            block_len: 64,
            xof: false,
            oid_der: None,
            oid_text: Some("1.3.6.1.4.1.1722.12.2.2.4"),
        },
        GCRY_MD_SM3 => DigestInfo {
            available: true,
            output_len: 32,
            block_len: 64,
            xof: false,
            oid_der: Some(SM3_ASNOID),
            oid_text: Some("1.2.156.10197.1.401"),
        },
        GCRY_MD_SHA512_256 => DigestInfo {
            available: true,
            output_len: 32,
            block_len: 128,
            xof: false,
            oid_der: Some(SHA512_256_ASNOID),
            oid_text: Some("2.16.840.1.101.3.4.2.6"),
        },
        GCRY_MD_SHA512_224 => DigestInfo {
            available: true,
            output_len: 28,
            block_len: 128,
            xof: false,
            oid_der: Some(SHA512_224_ASNOID),
            oid_text: Some("2.16.840.1.101.3.4.2.5"),
        },
        _ => return None,
    };

    Some(info)
}

pub(crate) fn info(algo: c_int) -> Option<DigestInfo> {
    digest_info_impl(algo)
}

pub(crate) fn digest_output_len(algo: c_int) -> usize {
    info(algo).map_or(0, |item| item.output_len)
}

pub(crate) fn digest_block_len(algo: c_int) -> usize {
    info(algo).map_or(0, |item| item.block_len)
}

pub(crate) fn digest_is_available(algo: c_int) -> bool {
    info(algo).is_some_and(|item| item.available)
}

pub(crate) fn supports_hmac(algo: c_int) -> bool {
    info(algo).is_some_and(|item| item.available && !item.xof)
}

pub(crate) fn is_xof(algo: c_int) -> bool {
    info(algo).is_some_and(|item| item.available && item.xof)
}

pub(crate) fn oid_der(algo: c_int) -> Option<&'static [u8]> {
    info(algo).and_then(|item| item.oid_der)
}

fn canonical_name(algo: c_int) -> Option<&'static str> {
    match algo {
        GCRY_MD_MD5 => Some("MD5"),
        GCRY_MD_SHA1 => Some("SHA1"),
        GCRY_MD_RMD160 => Some("RIPEMD160"),
        GCRY_MD_MD2 => Some("MD2"),
        GCRY_MD_TIGER => Some("TIGER192"),
        GCRY_MD_HAVAL => Some("HAVAL"),
        GCRY_MD_SHA256 => Some("SHA256"),
        GCRY_MD_SHA384 => Some("SHA384"),
        GCRY_MD_SHA512 => Some("SHA512"),
        GCRY_MD_SHA224 => Some("SHA224"),
        GCRY_MD_MD4 => Some("MD4"),
        GCRY_MD_CRC32 => Some("CRC32"),
        GCRY_MD_CRC32_RFC1510 => Some("CRC32RFC1510"),
        GCRY_MD_CRC24_RFC2440 => Some("CRC24RFC2440"),
        GCRY_MD_WHIRLPOOL => Some("WHIRLPOOL"),
        GCRY_MD_TIGER1 => Some("TIGER"),
        GCRY_MD_TIGER2 => Some("TIGER2"),
        GCRY_MD_GOSTR3411_94 => Some("GOSTR3411_94"),
        GCRY_MD_STRIBOG256 => Some("STRIBOG256"),
        GCRY_MD_STRIBOG512 => Some("STRIBOG512"),
        GCRY_MD_GOSTR3411_CP => Some("GOSTR3411_CP"),
        GCRY_MD_SHA3_224 => Some("SHA3_224"),
        GCRY_MD_SHA3_256 => Some("SHA3_256"),
        GCRY_MD_SHA3_384 => Some("SHA3_384"),
        GCRY_MD_SHA3_512 => Some("SHA3_512"),
        GCRY_MD_SHAKE128 => Some("SHAKE128"),
        GCRY_MD_SHAKE256 => Some("SHAKE256"),
        GCRY_MD_BLAKE2B_512 => Some("BLAKE2B_512"),
        GCRY_MD_BLAKE2B_384 => Some("BLAKE2B_384"),
        GCRY_MD_BLAKE2B_256 => Some("BLAKE2B_256"),
        GCRY_MD_BLAKE2B_160 => Some("BLAKE2B_160"),
        GCRY_MD_BLAKE2S_256 => Some("BLAKE2S_256"),
        GCRY_MD_BLAKE2S_224 => Some("BLAKE2S_224"),
        GCRY_MD_BLAKE2S_160 => Some("BLAKE2S_160"),
        GCRY_MD_BLAKE2S_128 => Some("BLAKE2S_128"),
        GCRY_MD_SM3 => Some("SM3"),
        GCRY_MD_SHA512_256 => Some("SHA512_256"),
        GCRY_MD_SHA512_224 => Some("SHA512_224"),
        _ => None,
    }
}

pub(crate) fn canonical_name_bytes(algo: c_int) -> Option<&'static [u8]> {
    canonical_name(algo).map(|name| match name {
        "MD5" => b"MD5\0".as_slice(),
        "SHA1" => b"SHA1\0".as_slice(),
        "RIPEMD160" => b"RIPEMD160\0".as_slice(),
        "MD2" => b"MD2\0".as_slice(),
        "TIGER192" => b"TIGER192\0".as_slice(),
        "HAVAL" => b"HAVAL\0".as_slice(),
        "SHA256" => b"SHA256\0".as_slice(),
        "SHA384" => b"SHA384\0".as_slice(),
        "SHA512" => b"SHA512\0".as_slice(),
        "SHA224" => b"SHA224\0".as_slice(),
        "MD4" => b"MD4\0".as_slice(),
        "CRC32" => b"CRC32\0".as_slice(),
        "CRC32RFC1510" => b"CRC32RFC1510\0".as_slice(),
        "CRC24RFC2440" => b"CRC24RFC2440\0".as_slice(),
        "WHIRLPOOL" => b"WHIRLPOOL\0".as_slice(),
        "TIGER" => b"TIGER\0".as_slice(),
        "TIGER2" => b"TIGER2\0".as_slice(),
        "GOSTR3411_94" => b"GOSTR3411_94\0".as_slice(),
        "STRIBOG256" => b"STRIBOG256\0".as_slice(),
        "STRIBOG512" => b"STRIBOG512\0".as_slice(),
        "GOSTR3411_CP" => b"GOSTR3411_CP\0".as_slice(),
        "SHA3_224" => b"SHA3_224\0".as_slice(),
        "SHA3_256" => b"SHA3_256\0".as_slice(),
        "SHA3_384" => b"SHA3_384\0".as_slice(),
        "SHA3_512" => b"SHA3_512\0".as_slice(),
        "SHAKE128" => b"SHAKE128\0".as_slice(),
        "SHAKE256" => b"SHAKE256\0".as_slice(),
        "BLAKE2B_512" => b"BLAKE2B_512\0".as_slice(),
        "BLAKE2B_384" => b"BLAKE2B_384\0".as_slice(),
        "BLAKE2B_256" => b"BLAKE2B_256\0".as_slice(),
        "BLAKE2B_160" => b"BLAKE2B_160\0".as_slice(),
        "BLAKE2S_256" => b"BLAKE2S_256\0".as_slice(),
        "BLAKE2S_224" => b"BLAKE2S_224\0".as_slice(),
        "BLAKE2S_160" => b"BLAKE2S_160\0".as_slice(),
        "BLAKE2S_128" => b"BLAKE2S_128\0".as_slice(),
        "SM3" => b"SM3\0".as_slice(),
        "SHA512_256" => b"SHA512_256\0".as_slice(),
        "SHA512_224" => b"SHA512_224\0".as_slice(),
        _ => unreachable!(),
    })
}

fn normalize_name(name: &str) -> String {
    name.chars()
        .filter_map(|ch| {
            if ch.is_ascii_alphanumeric() {
                Some(ch.to_ascii_uppercase())
            } else if ch == '-' || ch == '_' {
                Some('_')
            } else {
                None
            }
        })
        .collect()
}

fn match_aliases(algo: c_int, normalized: &str) -> bool {
    let aliases: &[&str] = match algo {
        GCRY_MD_MD5 => &["MD5"],
        GCRY_MD_SHA1 => &["SHA1", "SHA", "SHA_1"],
        GCRY_MD_RMD160 => &["RIPEMD160", "RMD160"],
        GCRY_MD_MD2 => &["MD2"],
        GCRY_MD_TIGER => &["TIGER192", "TIGER_192"],
        GCRY_MD_HAVAL => &["HAVAL"],
        GCRY_MD_SHA256 => &["SHA256", "SHA_256"],
        GCRY_MD_SHA384 => &["SHA384", "SHA_384"],
        GCRY_MD_SHA512 => &["SHA512", "SHA_512"],
        GCRY_MD_SHA224 => &["SHA224", "SHA_224"],
        GCRY_MD_MD4 => &["MD4"],
        GCRY_MD_CRC32 => &["CRC32"],
        GCRY_MD_CRC32_RFC1510 => &["CRC32RFC1510", "CRC32_RFC1510"],
        GCRY_MD_CRC24_RFC2440 => &["CRC24RFC2440", "CRC24_RFC2440"],
        GCRY_MD_WHIRLPOOL => &["WHIRLPOOL"],
        GCRY_MD_TIGER1 => &["TIGER", "TIGER1"],
        GCRY_MD_TIGER2 => &["TIGER2"],
        GCRY_MD_GOSTR3411_94 => &["GOSTR3411_94", "GOST94"],
        GCRY_MD_STRIBOG256 => &["STRIBOG256"],
        GCRY_MD_STRIBOG512 => &["STRIBOG512"],
        GCRY_MD_GOSTR3411_CP => &["GOSTR3411_CP"],
        GCRY_MD_SHA3_224 => &["SHA3_224"],
        GCRY_MD_SHA3_256 => &["SHA3_256"],
        GCRY_MD_SHA3_384 => &["SHA3_384"],
        GCRY_MD_SHA3_512 => &["SHA3_512"],
        GCRY_MD_SHAKE128 => &["SHAKE128", "SHAKE_128"],
        GCRY_MD_SHAKE256 => &["SHAKE256", "SHAKE_256"],
        GCRY_MD_BLAKE2B_512 => &["BLAKE2B_512"],
        GCRY_MD_BLAKE2B_384 => &["BLAKE2B_384"],
        GCRY_MD_BLAKE2B_256 => &["BLAKE2B_256"],
        GCRY_MD_BLAKE2B_160 => &["BLAKE2B_160"],
        GCRY_MD_BLAKE2S_256 => &["BLAKE2S_256"],
        GCRY_MD_BLAKE2S_224 => &["BLAKE2S_224"],
        GCRY_MD_BLAKE2S_160 => &["BLAKE2S_160"],
        GCRY_MD_BLAKE2S_128 => &["BLAKE2S_128"],
        GCRY_MD_SM3 => &["SM3"],
        GCRY_MD_SHA512_256 => &["SHA512_256", "SHA_512_256"],
        GCRY_MD_SHA512_224 => &["SHA512_224", "SHA_512_224"],
        _ => &[],
    };

    aliases.iter().any(|alias| *alias == normalized)
}

pub(crate) fn map_name(name: &str) -> c_int {
    if name.is_empty() {
        return 0;
    }

    let raw = name.trim();
    let oid = raw
        .strip_prefix("oid.")
        .or_else(|| raw.strip_prefix("OID."))
        .unwrap_or(raw);
    if oid.bytes().next().is_some_and(|byte| byte.is_ascii_digit()) {
        for algo in 1..400 {
            if info(algo).and_then(|item| item.oid_text) == Some(oid) {
                return algo;
            }
        }
        return 0;
    }

    let normalized = normalize_name(raw);
    for algo in 1..400 {
        if match_aliases(algo, &normalized) {
            return algo;
        }
    }
    0
}

pub(crate) fn resolve_read_algo(hd: gcry_md_hd_t, requested: c_int) -> Option<c_int> {
    if requested != 0 {
        Some(requested)
    } else {
        let algo = super::gcry_md_get_algo(hd);
        (algo != 0).then_some(algo)
    }
}
