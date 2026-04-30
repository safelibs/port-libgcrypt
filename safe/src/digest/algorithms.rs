use std::ffi::{CStr, c_char, c_int};

use digest::{Digest, ExtendableOutput, Update, VariableOutput, XofReader};
use hmac::Mac;

pub(crate) const GCRY_MD_MD5: c_int = 1;
pub(crate) const GCRY_MD_SHA1: c_int = 2;
pub(crate) const GCRY_MD_RMD160: c_int = 3;
pub(crate) const GCRY_MD_TIGER: c_int = 6;
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
pub(crate) const GCRY_MD_SHA512_256: c_int = 327;
pub(crate) const GCRY_MD_SHA512_224: c_int = 328;
pub(crate) const GCRY_MD_GOSTR3411_94: c_int = 308;
pub(crate) const GCRY_MD_GOSTR3411_CP: c_int = 311;
pub(crate) const GCRY_MD_STRIBOG256: c_int = 309;
pub(crate) const GCRY_MD_STRIBOG512: c_int = 310;
pub(crate) const GCRY_MD_SM3: c_int = 326;

#[derive(Clone)]
pub(crate) enum HashState {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Rmd160(ripemd::Ripemd160),
    Tiger(tiger::Tiger),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha512_256(sha2::Sha512_256),
    Sha512_224(sha2::Sha512_224),
    Md4(md4::Md4),
    Crc32(Crc32State),
    Crc32Rfc1510(Crc32State),
    Crc24Rfc2440(Crc24State),
    Whirlpool(whirlpool::Whirlpool),
    Tiger1(tiger::Tiger),
    Tiger2(tiger::Tiger2),
    Sha3_224(sha3::Sha3_224),
    Sha3_256(sha3::Sha3_256),
    Sha3_384(sha3::Sha3_384),
    Sha3_512(sha3::Sha3_512),
    Shake128(sha3::Shake128),
    Shake256(sha3::Shake256),
    Blake2b(blake2::Blake2bVar, usize),
    Blake2s(blake2::Blake2sVar, usize),
    Sm3(sm3::Sm3),
    Gost94(gost94::Gost94Test),
    Gost94Cp(gost94::Gost94CryptoPro),
    Streebog256(streebog::Streebog256),
    Streebog512(streebog::Streebog512),
}

#[derive(Clone)]
pub(crate) struct Crc32State {
    crc: u32,
    final_xor: u32,
}

impl Crc32State {
    fn new(crc: u32, final_xor: u32) -> Self {
        Self { crc, final_xor }
    }

    fn update(&mut self, data: &[u8]) {
        for byte in data {
            self.crc ^= u32::from(*byte);
            for _ in 0..8 {
                if self.crc & 1 != 0 {
                    self.crc = (self.crc >> 1) ^ 0xedb8_8320;
                } else {
                    self.crc >>= 1;
                }
            }
        }
    }

    fn finalize_vec(&self) -> Vec<u8> {
        (self.crc ^ self.final_xor).to_be_bytes().to_vec()
    }
}

#[derive(Clone)]
pub(crate) struct Crc24State {
    crc: u32,
}

impl Crc24State {
    fn new() -> Self {
        Self { crc: 0xb704ce }
    }

    fn update(&mut self, data: &[u8]) {
        for byte in data {
            self.crc ^= u32::from(*byte) << 16;
            for _ in 0..8 {
                self.crc <<= 1;
                if self.crc & 0x0100_0000 != 0 {
                    self.crc ^= 0x0186_4cfb;
                }
            }
            self.crc &= 0x00ff_ffff;
        }
    }

    fn finalize_vec(&self) -> Vec<u8> {
        vec![
            ((self.crc >> 16) & 0xff) as u8,
            ((self.crc >> 8) & 0xff) as u8,
            (self.crc & 0xff) as u8,
        ]
    }
}

impl HashState {
    pub(crate) fn new(algo: c_int) -> Option<Self> {
        Some(match algo {
            GCRY_MD_MD5 => Self::Md5(md5::Md5::new()),
            GCRY_MD_SHA1 => Self::Sha1(sha1::Sha1::new()),
            GCRY_MD_RMD160 => Self::Rmd160(ripemd::Ripemd160::new()),
            GCRY_MD_TIGER => Self::Tiger(tiger::Tiger::new()),
            GCRY_MD_SHA224 => Self::Sha224(sha2::Sha224::new()),
            GCRY_MD_SHA256 => Self::Sha256(sha2::Sha256::new()),
            GCRY_MD_SHA384 => Self::Sha384(sha2::Sha384::new()),
            GCRY_MD_SHA512 => Self::Sha512(sha2::Sha512::new()),
            GCRY_MD_SHA512_256 => Self::Sha512_256(sha2::Sha512_256::new()),
            GCRY_MD_SHA512_224 => Self::Sha512_224(sha2::Sha512_224::new()),
            GCRY_MD_MD4 => Self::Md4(md4::Md4::new()),
            GCRY_MD_CRC32 => Self::Crc32(Crc32State::new(0xffff_ffff, 0xffff_ffff)),
            GCRY_MD_CRC32_RFC1510 => Self::Crc32Rfc1510(Crc32State::new(0, 0)),
            GCRY_MD_CRC24_RFC2440 => Self::Crc24Rfc2440(Crc24State::new()),
            GCRY_MD_WHIRLPOOL => Self::Whirlpool(whirlpool::Whirlpool::new()),
            GCRY_MD_TIGER1 => Self::Tiger1(tiger::Tiger::new()),
            GCRY_MD_TIGER2 => Self::Tiger2(tiger::Tiger2::new()),
            GCRY_MD_SHA3_224 => Self::Sha3_224(sha3::Sha3_224::new()),
            GCRY_MD_SHA3_256 => Self::Sha3_256(sha3::Sha3_256::new()),
            GCRY_MD_SHA3_384 => Self::Sha3_384(sha3::Sha3_384::new()),
            GCRY_MD_SHA3_512 => Self::Sha3_512(sha3::Sha3_512::new()),
            GCRY_MD_SHAKE128 => Self::Shake128(sha3::Shake128::default()),
            GCRY_MD_SHAKE256 => Self::Shake256(sha3::Shake256::default()),
            GCRY_MD_BLAKE2B_512 => Self::Blake2b(blake2::Blake2bVar::new(64).ok()?, 64),
            GCRY_MD_BLAKE2B_384 => Self::Blake2b(blake2::Blake2bVar::new(48).ok()?, 48),
            GCRY_MD_BLAKE2B_256 => Self::Blake2b(blake2::Blake2bVar::new(32).ok()?, 32),
            GCRY_MD_BLAKE2B_160 => Self::Blake2b(blake2::Blake2bVar::new(20).ok()?, 20),
            GCRY_MD_BLAKE2S_256 => Self::Blake2s(blake2::Blake2sVar::new(32).ok()?, 32),
            GCRY_MD_BLAKE2S_224 => Self::Blake2s(blake2::Blake2sVar::new(28).ok()?, 28),
            GCRY_MD_BLAKE2S_160 => Self::Blake2s(blake2::Blake2sVar::new(20).ok()?, 20),
            GCRY_MD_BLAKE2S_128 => Self::Blake2s(blake2::Blake2sVar::new(16).ok()?, 16),
            GCRY_MD_SM3 => Self::Sm3(sm3::Sm3::new()),
            GCRY_MD_GOSTR3411_94 => Self::Gost94(gost94::Gost94Test::new()),
            GCRY_MD_GOSTR3411_CP => Self::Gost94Cp(gost94::Gost94CryptoPro::new()),
            GCRY_MD_STRIBOG256 => Self::Streebog256(streebog::Streebog256::new()),
            GCRY_MD_STRIBOG512 => Self::Streebog512(streebog::Streebog512::new()),
            _ => return None,
        })
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Self::Md5(h) => Digest::update(h, data),
            Self::Sha1(h) => Digest::update(h, data),
            Self::Rmd160(h) => Digest::update(h, data),
            Self::Tiger(h) => Digest::update(h, data),
            Self::Sha224(h) => Digest::update(h, data),
            Self::Sha256(h) => Digest::update(h, data),
            Self::Sha384(h) => Digest::update(h, data),
            Self::Sha512(h) => Digest::update(h, data),
            Self::Sha512_256(h) => Digest::update(h, data),
            Self::Sha512_224(h) => Digest::update(h, data),
            Self::Md4(h) => Digest::update(h, data),
            Self::Crc32(h) | Self::Crc32Rfc1510(h) => h.update(data),
            Self::Crc24Rfc2440(h) => h.update(data),
            Self::Whirlpool(h) => Digest::update(h, data),
            Self::Tiger1(h) => Digest::update(h, data),
            Self::Tiger2(h) => Digest::update(h, data),
            Self::Sha3_224(h) => Digest::update(h, data),
            Self::Sha3_256(h) => Digest::update(h, data),
            Self::Sha3_384(h) => Digest::update(h, data),
            Self::Sha3_512(h) => Digest::update(h, data),
            Self::Shake128(h) => Update::update(h, data),
            Self::Shake256(h) => Update::update(h, data),
            Self::Blake2b(h, _) => Update::update(h, data),
            Self::Blake2s(h, _) => Update::update(h, data),
            Self::Sm3(h) => Digest::update(h, data),
            Self::Gost94(h) => Digest::update(h, data),
            Self::Gost94Cp(h) => Digest::update(h, data),
            Self::Streebog256(h) => Digest::update(h, data),
            Self::Streebog512(h) => Digest::update(h, data),
        }
    }

    pub(crate) fn finalize_vec(&self) -> Vec<u8> {
        match self {
            Self::Md5(h) => h.clone().finalize().to_vec(),
            Self::Sha1(h) => h.clone().finalize().to_vec(),
            Self::Rmd160(h) => h.clone().finalize().to_vec(),
            Self::Tiger(h) => {
                let mut out = h.clone().finalize().to_vec();
                for word in out.chunks_exact_mut(8) {
                    word.reverse();
                }
                out
            }
            Self::Sha224(h) => h.clone().finalize().to_vec(),
            Self::Sha256(h) => h.clone().finalize().to_vec(),
            Self::Sha384(h) => h.clone().finalize().to_vec(),
            Self::Sha512(h) => h.clone().finalize().to_vec(),
            Self::Sha512_256(h) => h.clone().finalize().to_vec(),
            Self::Sha512_224(h) => h.clone().finalize().to_vec(),
            Self::Md4(h) => h.clone().finalize().to_vec(),
            Self::Crc32(h) | Self::Crc32Rfc1510(h) => h.finalize_vec(),
            Self::Crc24Rfc2440(h) => h.finalize_vec(),
            Self::Whirlpool(h) => h.clone().finalize().to_vec(),
            Self::Tiger1(h) => h.clone().finalize().to_vec(),
            Self::Tiger2(h) => h.clone().finalize().to_vec(),
            Self::Sha3_224(h) => h.clone().finalize().to_vec(),
            Self::Sha3_256(h) => h.clone().finalize().to_vec(),
            Self::Sha3_384(h) => h.clone().finalize().to_vec(),
            Self::Sha3_512(h) => h.clone().finalize().to_vec(),
            Self::Shake128(_) | Self::Shake256(_) => self.xof_vec(0).unwrap_or_default(),
            Self::Blake2b(h, len) => {
                let mut out = vec![0u8; *len];
                h.clone()
                    .finalize_variable(&mut out)
                    .expect("valid BLAKE2b output length");
                out
            }
            Self::Blake2s(h, len) => {
                let mut out = vec![0u8; *len];
                h.clone()
                    .finalize_variable(&mut out)
                    .expect("valid BLAKE2s output length");
                out
            }
            Self::Sm3(h) => h.clone().finalize().to_vec(),
            Self::Gost94(h) => h.clone().finalize().to_vec(),
            Self::Gost94Cp(h) => h.clone().finalize().to_vec(),
            Self::Streebog256(h) => h.clone().finalize().to_vec(),
            Self::Streebog512(h) => h.clone().finalize().to_vec(),
        }
    }

    pub(crate) fn xof_vec(&self, length: usize) -> Option<Vec<u8>> {
        match self {
            Self::Shake128(h) => {
                let mut out = vec![0u8; length];
                let mut reader = h.clone().finalize_xof();
                reader.read(&mut out);
                Some(out)
            }
            Self::Shake256(h) => {
                let mut out = vec![0u8; length];
                let mut reader = h.clone().finalize_xof();
                reader.read(&mut out);
                Some(out)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AlgorithmInfo {
    pub(crate) id: c_int,
    pub(crate) name: &'static [u8],
    pub(crate) digest_len: usize,
}

const ALGORITHMS: &[AlgorithmInfo] = &[
    AlgorithmInfo {
        id: GCRY_MD_MD5,
        name: b"MD5\0",
        digest_len: 16,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA1,
        name: b"SHA1\0",
        digest_len: 20,
    },
    AlgorithmInfo {
        id: GCRY_MD_RMD160,
        name: b"RIPEMD160\0",
        digest_len: 20,
    },
    AlgorithmInfo {
        id: GCRY_MD_TIGER,
        name: b"TIGER192\0",
        digest_len: 24,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA224,
        name: b"SHA224\0",
        digest_len: 28,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA256,
        name: b"SHA256\0",
        digest_len: 32,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA384,
        name: b"SHA384\0",
        digest_len: 48,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA512,
        name: b"SHA512\0",
        digest_len: 64,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA512_256,
        name: b"SHA512_256\0",
        digest_len: 32,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA512_224,
        name: b"SHA512_224\0",
        digest_len: 28,
    },
    AlgorithmInfo {
        id: GCRY_MD_MD4,
        name: b"MD4\0",
        digest_len: 16,
    },
    AlgorithmInfo {
        id: GCRY_MD_CRC32,
        name: b"CRC32\0",
        digest_len: 4,
    },
    AlgorithmInfo {
        id: GCRY_MD_CRC32_RFC1510,
        name: b"CRC32RFC1510\0",
        digest_len: 4,
    },
    AlgorithmInfo {
        id: GCRY_MD_CRC24_RFC2440,
        name: b"CRC24RFC2440\0",
        digest_len: 3,
    },
    AlgorithmInfo {
        id: GCRY_MD_WHIRLPOOL,
        name: b"WHIRLPOOL\0",
        digest_len: 64,
    },
    AlgorithmInfo {
        id: GCRY_MD_TIGER1,
        name: b"TIGER\0",
        digest_len: 24,
    },
    AlgorithmInfo {
        id: GCRY_MD_TIGER2,
        name: b"TIGER2\0",
        digest_len: 24,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA3_224,
        name: b"SHA3-224\0",
        digest_len: 28,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA3_256,
        name: b"SHA3-256\0",
        digest_len: 32,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA3_384,
        name: b"SHA3-384\0",
        digest_len: 48,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHA3_512,
        name: b"SHA3-512\0",
        digest_len: 64,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHAKE128,
        name: b"SHAKE128\0",
        digest_len: 0,
    },
    AlgorithmInfo {
        id: GCRY_MD_SHAKE256,
        name: b"SHAKE256\0",
        digest_len: 0,
    },
    AlgorithmInfo {
        id: GCRY_MD_BLAKE2B_512,
        name: b"BLAKE2B_512\0",
        digest_len: 64,
    },
    AlgorithmInfo {
        id: GCRY_MD_BLAKE2B_384,
        name: b"BLAKE2B_384\0",
        digest_len: 48,
    },
    AlgorithmInfo {
        id: GCRY_MD_BLAKE2B_256,
        name: b"BLAKE2B_256\0",
        digest_len: 32,
    },
    AlgorithmInfo {
        id: GCRY_MD_BLAKE2B_160,
        name: b"BLAKE2B_160\0",
        digest_len: 20,
    },
    AlgorithmInfo {
        id: GCRY_MD_BLAKE2S_256,
        name: b"BLAKE2S_256\0",
        digest_len: 32,
    },
    AlgorithmInfo {
        id: GCRY_MD_BLAKE2S_224,
        name: b"BLAKE2S_224\0",
        digest_len: 28,
    },
    AlgorithmInfo {
        id: GCRY_MD_BLAKE2S_160,
        name: b"BLAKE2S_160\0",
        digest_len: 20,
    },
    AlgorithmInfo {
        id: GCRY_MD_BLAKE2S_128,
        name: b"BLAKE2S_128\0",
        digest_len: 16,
    },
    AlgorithmInfo {
        id: GCRY_MD_SM3,
        name: b"SM3\0",
        digest_len: 32,
    },
    AlgorithmInfo {
        id: GCRY_MD_GOSTR3411_94,
        name: b"GOSTR3411_94\0",
        digest_len: 32,
    },
    AlgorithmInfo {
        id: GCRY_MD_GOSTR3411_CP,
        name: b"GOSTR3411_CP\0",
        digest_len: 32,
    },
    AlgorithmInfo {
        id: GCRY_MD_STRIBOG256,
        name: b"STRIBOG256\0",
        digest_len: 32,
    },
    AlgorithmInfo {
        id: GCRY_MD_STRIBOG512,
        name: b"STRIBOG512\0",
        digest_len: 64,
    },
];

const UNKNOWN_NAME: &[u8] = b"?\0";
const SHA256_ASNOID: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const RMD160_ASNOID: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14,
];
const MD4_ASNOID: &[u8] = &[
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x04, 0x05, 0x00,
    0x04, 0x10,
];
const TIGER1_ASNOID: &[u8] = &[
    0x30, 0x29, 0x30, 0x0d, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0c, 0x02, 0x05,
    0x00, 0x04, 0x18,
];

pub(crate) fn lookup(algo: c_int) -> Option<&'static AlgorithmInfo> {
    ALGORITHMS.iter().find(|entry| entry.id == algo)
}

pub(crate) fn digest_len(algo: c_int) -> usize {
    lookup(algo).map(|entry| entry.digest_len).unwrap_or(0)
}

pub(crate) fn algo_name(algo: c_int) -> *const c_char {
    lookup(algo)
        .map(|entry| entry.name.as_ptr().cast())
        .unwrap_or_else(|| UNKNOWN_NAME.as_ptr().cast())
}

pub(crate) fn map_name(name: *const c_char) -> c_int {
    if name.is_null() {
        return 0;
    }

    let text = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    let normalized = text
        .chars()
        .filter(|ch| *ch != '-' && *ch != '_' && !ch.is_ascii_whitespace())
        .flat_map(char::to_lowercase)
        .collect::<String>();

    match normalized.as_str() {
        "md5" => GCRY_MD_MD5,
        "sha1" => GCRY_MD_SHA1,
        "rmd160" | "ripemd160" => GCRY_MD_RMD160,
        "tiger192" => GCRY_MD_TIGER,
        "tiger" | "tiger1" => GCRY_MD_TIGER1,
        "tiger2" => GCRY_MD_TIGER2,
        "sha224" => GCRY_MD_SHA224,
        "sha256" => GCRY_MD_SHA256,
        "sha384" => GCRY_MD_SHA384,
        "sha512" => GCRY_MD_SHA512,
        "sha512256" => GCRY_MD_SHA512_256,
        "sha512224" => GCRY_MD_SHA512_224,
        "md4" => GCRY_MD_MD4,
        "crc32" => GCRY_MD_CRC32,
        "crc32rfc1510" => GCRY_MD_CRC32_RFC1510,
        "crc24rfc2440" => GCRY_MD_CRC24_RFC2440,
        "whirlpool" => GCRY_MD_WHIRLPOOL,
        "sha3224" => GCRY_MD_SHA3_224,
        "sha3256" => GCRY_MD_SHA3_256,
        "sha3384" => GCRY_MD_SHA3_384,
        "sha3512" => GCRY_MD_SHA3_512,
        "shake128" => GCRY_MD_SHAKE128,
        "shake256" => GCRY_MD_SHAKE256,
        "blake2b512" => GCRY_MD_BLAKE2B_512,
        "blake2b384" => GCRY_MD_BLAKE2B_384,
        "blake2b256" => GCRY_MD_BLAKE2B_256,
        "blake2b160" => GCRY_MD_BLAKE2B_160,
        "blake2s256" => GCRY_MD_BLAKE2S_256,
        "blake2s224" => GCRY_MD_BLAKE2S_224,
        "blake2s160" => GCRY_MD_BLAKE2S_160,
        "blake2s128" => GCRY_MD_BLAKE2S_128,
        "sm3" => GCRY_MD_SM3,
        "gostr341194" | "gost94" => GCRY_MD_GOSTR3411_94,
        "gostr3411cp" | "gost94cp" => GCRY_MD_GOSTR3411_CP,
        "stribog256" => GCRY_MD_STRIBOG256,
        "stribog512" => GCRY_MD_STRIBOG512,
        _ => 0,
    }
}

pub(crate) fn asnoid(algo: c_int) -> Option<&'static [u8]> {
    match algo {
        GCRY_MD_RMD160 => Some(RMD160_ASNOID),
        GCRY_MD_MD4 => Some(MD4_ASNOID),
        GCRY_MD_TIGER1 => Some(TIGER1_ASNOID),
        GCRY_MD_SHA256 => Some(SHA256_ASNOID),
        _ => None,
    }
}

pub(crate) fn is_xof(algo: c_int) -> bool {
    matches!(algo, GCRY_MD_SHAKE128 | GCRY_MD_SHAKE256)
}

pub(crate) fn is_blake2(algo: c_int) -> bool {
    matches!(
        algo,
        GCRY_MD_BLAKE2B_512
            | GCRY_MD_BLAKE2B_384
            | GCRY_MD_BLAKE2B_256
            | GCRY_MD_BLAKE2B_160
            | GCRY_MD_BLAKE2S_256
            | GCRY_MD_BLAKE2S_224
            | GCRY_MD_BLAKE2S_160
            | GCRY_MD_BLAKE2S_128
    )
}

pub(crate) fn blake2_key_valid(algo: c_int, key: &[u8]) -> bool {
    match algo {
        GCRY_MD_BLAKE2B_512 | GCRY_MD_BLAKE2B_384 | GCRY_MD_BLAKE2B_256 | GCRY_MD_BLAKE2B_160 => {
            key.len() <= 64
        }
        GCRY_MD_BLAKE2S_256 | GCRY_MD_BLAKE2S_224 | GCRY_MD_BLAKE2S_160 | GCRY_MD_BLAKE2S_128 => {
            key.len() <= 32
        }
        _ => false,
    }
}

pub(crate) fn digest_once(algo: c_int, data: &[u8]) -> Option<Vec<u8>> {
    let mut state = HashState::new(algo)?;
    state.update(data);
    Some(state.finalize_vec())
}

macro_rules! hmac_one {
    ($ty:ty, $key:expr, $data:expr) => {{
        let mut mac =
            <hmac::SimpleHmac<$ty> as hmac::digest::KeyInit>::new_from_slice($key).ok()?;
        Mac::update(&mut mac, $data);
        Some(mac.finalize().into_bytes().to_vec())
    }};
}

macro_rules! blake2_keyed_one {
    ($ty:ty, $key:expr, $data:expr) => {{
        let mut mac = <$ty as Mac>::new_from_slice($key).ok()?;
        Mac::update(&mut mac, $data);
        Some(mac.finalize().into_bytes().to_vec())
    }};
}

pub(crate) fn blake2_keyed_once(algo: c_int, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if !blake2_key_valid(algo, key) {
        return None;
    }
    match algo {
        GCRY_MD_BLAKE2B_512 => blake2_keyed_one!(blake2::Blake2bMac512, key, data),
        GCRY_MD_BLAKE2B_384 => {
            blake2_keyed_one!(blake2::Blake2bMac<digest::consts::U48>, key, data)
        }
        GCRY_MD_BLAKE2B_256 => {
            blake2_keyed_one!(blake2::Blake2bMac<digest::consts::U32>, key, data)
        }
        GCRY_MD_BLAKE2B_160 => {
            blake2_keyed_one!(blake2::Blake2bMac<digest::consts::U20>, key, data)
        }
        GCRY_MD_BLAKE2S_256 => blake2_keyed_one!(blake2::Blake2sMac256, key, data),
        GCRY_MD_BLAKE2S_224 => {
            blake2_keyed_one!(blake2::Blake2sMac<digest::consts::U28>, key, data)
        }
        GCRY_MD_BLAKE2S_160 => {
            blake2_keyed_one!(blake2::Blake2sMac<digest::consts::U20>, key, data)
        }
        GCRY_MD_BLAKE2S_128 => {
            blake2_keyed_one!(blake2::Blake2sMac<digest::consts::U16>, key, data)
        }
        _ => None,
    }
}

fn hmac_with_local_digest(
    algo: c_int,
    block_len: usize,
    key: &[u8],
    data: &[u8],
) -> Option<Vec<u8>> {
    let mut key_block = if key.len() > block_len {
        digest_once(algo, key)?
    } else {
        key.to_vec()
    };
    key_block.resize(block_len, 0);

    let mut ipad = vec![0x36; block_len];
    let mut opad = vec![0x5c; block_len];
    for (idx, key_byte) in key_block.iter().enumerate() {
        ipad[idx] ^= key_byte;
        opad[idx] ^= key_byte;
    }

    ipad.extend_from_slice(data);
    let inner = digest_once(algo, &ipad)?;
    opad.extend_from_slice(&inner);
    digest_once(algo, &opad)
}

pub(crate) fn hmac_once(algo: c_int, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    match algo {
        GCRY_MD_MD5 => hmac_one!(md5::Md5, key, data),
        GCRY_MD_SHA1 => hmac_one!(sha1::Sha1, key, data),
        GCRY_MD_RMD160 => hmac_one!(ripemd::Ripemd160, key, data),
        GCRY_MD_TIGER => hmac_with_local_digest(algo, 64, key, data),
        GCRY_MD_TIGER1 => hmac_one!(tiger::Tiger, key, data),
        GCRY_MD_TIGER2 => hmac_one!(tiger::Tiger2, key, data),
        GCRY_MD_SHA224 => hmac_one!(sha2::Sha224, key, data),
        GCRY_MD_SHA256 => hmac_one!(sha2::Sha256, key, data),
        GCRY_MD_SHA384 => hmac_one!(sha2::Sha384, key, data),
        GCRY_MD_SHA512 => hmac_one!(sha2::Sha512, key, data),
        GCRY_MD_SHA512_256 => hmac_one!(sha2::Sha512_256, key, data),
        GCRY_MD_SHA512_224 => hmac_one!(sha2::Sha512_224, key, data),
        GCRY_MD_MD4 => hmac_one!(md4::Md4, key, data),
        GCRY_MD_WHIRLPOOL => hmac_one!(whirlpool::Whirlpool, key, data),
        GCRY_MD_SHA3_224 => hmac_one!(sha3::Sha3_224, key, data),
        GCRY_MD_SHA3_256 => hmac_one!(sha3::Sha3_256, key, data),
        GCRY_MD_SHA3_384 => hmac_one!(sha3::Sha3_384, key, data),
        GCRY_MD_SHA3_512 => hmac_one!(sha3::Sha3_512, key, data),
        GCRY_MD_BLAKE2B_512 => hmac_one!(blake2::Blake2b512, key, data),
        GCRY_MD_BLAKE2B_384 => hmac_one!(blake2::Blake2b<digest::consts::U48>, key, data),
        GCRY_MD_BLAKE2B_256 => hmac_one!(blake2::Blake2b<digest::consts::U32>, key, data),
        GCRY_MD_BLAKE2B_160 => hmac_one!(blake2::Blake2b<digest::consts::U20>, key, data),
        GCRY_MD_BLAKE2S_256 => hmac_one!(blake2::Blake2s256, key, data),
        GCRY_MD_BLAKE2S_224 => hmac_one!(blake2::Blake2s<digest::consts::U28>, key, data),
        GCRY_MD_BLAKE2S_160 => hmac_one!(blake2::Blake2s<digest::consts::U20>, key, data),
        GCRY_MD_BLAKE2S_128 => hmac_one!(blake2::Blake2s<digest::consts::U16>, key, data),
        GCRY_MD_SM3 => hmac_one!(sm3::Sm3, key, data),
        GCRY_MD_GOSTR3411_94 => hmac_one!(gost94::Gost94Test, key, data),
        GCRY_MD_GOSTR3411_CP => hmac_one!(gost94::Gost94CryptoPro, key, data),
        GCRY_MD_STRIBOG256 => hmac_one!(streebog::Streebog256, key, data),
        GCRY_MD_STRIBOG512 => hmac_one!(streebog::Streebog512, key, data),
        _ => None,
    }
}

pub(crate) fn pbkdf2_hmac(
    algo: c_int,
    pass: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> bool {
    macro_rules! pbkdf2_simple_hmac {
        ($ty:ty) => {{
            if pbkdf2::pbkdf2::<hmac::SimpleHmac<$ty>>(pass, salt, iterations, out).is_err() {
                return false;
            }
        }};
    }

    match algo {
        GCRY_MD_MD5 => pbkdf2::pbkdf2_hmac::<md5::Md5>(pass, salt, iterations, out),
        GCRY_MD_SHA1 => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pass, salt, iterations, out),
        GCRY_MD_RMD160 => pbkdf2::pbkdf2_hmac::<ripemd::Ripemd160>(pass, salt, iterations, out),
        GCRY_MD_TIGER | GCRY_MD_TIGER1 => pbkdf2_simple_hmac!(tiger::Tiger),
        GCRY_MD_TIGER2 => pbkdf2_simple_hmac!(tiger::Tiger2),
        GCRY_MD_SHA224 => pbkdf2::pbkdf2_hmac::<sha2::Sha224>(pass, salt, iterations, out),
        GCRY_MD_SHA256 => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pass, salt, iterations, out),
        GCRY_MD_SHA384 => pbkdf2::pbkdf2_hmac::<sha2::Sha384>(pass, salt, iterations, out),
        GCRY_MD_SHA512 => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pass, salt, iterations, out),
        GCRY_MD_SHA512_256 => pbkdf2::pbkdf2_hmac::<sha2::Sha512_256>(pass, salt, iterations, out),
        GCRY_MD_SHA512_224 => pbkdf2::pbkdf2_hmac::<sha2::Sha512_224>(pass, salt, iterations, out),
        GCRY_MD_MD4 => pbkdf2_simple_hmac!(md4::Md4),
        GCRY_MD_WHIRLPOOL => pbkdf2_simple_hmac!(whirlpool::Whirlpool),
        GCRY_MD_SHA3_224 => pbkdf2_simple_hmac!(sha3::Sha3_224),
        GCRY_MD_SHA3_256 => pbkdf2_simple_hmac!(sha3::Sha3_256),
        GCRY_MD_SHA3_384 => pbkdf2_simple_hmac!(sha3::Sha3_384),
        GCRY_MD_SHA3_512 => pbkdf2_simple_hmac!(sha3::Sha3_512),
        GCRY_MD_BLAKE2B_512 => pbkdf2_simple_hmac!(blake2::Blake2b512),
        GCRY_MD_BLAKE2B_384 => {
            pbkdf2_simple_hmac!(blake2::Blake2b<digest::consts::U48>)
        }
        GCRY_MD_BLAKE2B_256 => {
            pbkdf2_simple_hmac!(blake2::Blake2b<digest::consts::U32>)
        }
        GCRY_MD_BLAKE2B_160 => {
            pbkdf2_simple_hmac!(blake2::Blake2b<digest::consts::U20>)
        }
        GCRY_MD_BLAKE2S_256 => pbkdf2_simple_hmac!(blake2::Blake2s256),
        GCRY_MD_BLAKE2S_224 => {
            pbkdf2_simple_hmac!(blake2::Blake2s<digest::consts::U28>)
        }
        GCRY_MD_BLAKE2S_160 => {
            pbkdf2_simple_hmac!(blake2::Blake2s<digest::consts::U20>)
        }
        GCRY_MD_BLAKE2S_128 => {
            pbkdf2_simple_hmac!(blake2::Blake2s<digest::consts::U16>)
        }
        GCRY_MD_GOSTR3411_94 => {
            pbkdf2::pbkdf2_hmac::<gost94::Gost94Test>(pass, salt, iterations, out)
        }
        GCRY_MD_GOSTR3411_CP => {
            pbkdf2::pbkdf2_hmac::<gost94::Gost94CryptoPro>(pass, salt, iterations, out)
        }
        GCRY_MD_SM3 => pbkdf2_simple_hmac!(sm3::Sm3),
        GCRY_MD_STRIBOG256 => {
            pbkdf2::pbkdf2_hmac::<streebog::Streebog256>(pass, salt, iterations, out)
        }
        GCRY_MD_STRIBOG512 => {
            pbkdf2::pbkdf2_hmac::<streebog::Streebog512>(pass, salt, iterations, out)
        }
        _ => return false,
    }
    true
}
