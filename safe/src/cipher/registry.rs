use std::ffi::{c_char, c_int, c_uint, c_void, CStr};

use super::{aead, block, stream};

use crate::error;

pub(crate) const GCRY_CIPHER_IDEA: c_int = 1;
pub(crate) const GCRY_CIPHER_3DES: c_int = 2;
pub(crate) const GCRY_CIPHER_CAST5: c_int = 3;
pub(crate) const GCRY_CIPHER_BLOWFISH: c_int = 4;
pub(crate) const GCRY_CIPHER_AES: c_int = 7;
pub(crate) const GCRY_CIPHER_AES192: c_int = 8;
pub(crate) const GCRY_CIPHER_AES256: c_int = 9;
pub(crate) const GCRY_CIPHER_TWOFISH: c_int = 10;
pub(crate) const GCRY_CIPHER_ARCFOUR: c_int = 301;
pub(crate) const GCRY_CIPHER_DES: c_int = 302;
pub(crate) const GCRY_CIPHER_TWOFISH128: c_int = 303;
pub(crate) const GCRY_CIPHER_SERPENT128: c_int = 304;
pub(crate) const GCRY_CIPHER_SERPENT192: c_int = 305;
pub(crate) const GCRY_CIPHER_SERPENT256: c_int = 306;
pub(crate) const GCRY_CIPHER_RFC2268_40: c_int = 307;
pub(crate) const GCRY_CIPHER_RFC2268_128: c_int = 308;
pub(crate) const GCRY_CIPHER_SEED: c_int = 309;
pub(crate) const GCRY_CIPHER_CAMELLIA128: c_int = 310;
pub(crate) const GCRY_CIPHER_CAMELLIA192: c_int = 311;
pub(crate) const GCRY_CIPHER_CAMELLIA256: c_int = 312;
pub(crate) const GCRY_CIPHER_SALSA20: c_int = 313;
pub(crate) const GCRY_CIPHER_SALSA20R12: c_int = 314;
pub(crate) const GCRY_CIPHER_GOST28147: c_int = 315;
pub(crate) const GCRY_CIPHER_CHACHA20: c_int = 316;
pub(crate) const GCRY_CIPHER_GOST28147_MESH: c_int = 317;
pub(crate) const GCRY_CIPHER_SM4: c_int = 318;

pub(crate) const GCRY_CIPHER_MODE_NONE: c_int = 0;
pub(crate) const GCRY_CIPHER_MODE_ECB: c_int = 1;
pub(crate) const GCRY_CIPHER_MODE_CFB: c_int = 2;
pub(crate) const GCRY_CIPHER_MODE_CBC: c_int = 3;
pub(crate) const GCRY_CIPHER_MODE_STREAM: c_int = 4;
pub(crate) const GCRY_CIPHER_MODE_OFB: c_int = 5;
pub(crate) const GCRY_CIPHER_MODE_CTR: c_int = 6;
pub(crate) const GCRY_CIPHER_MODE_AESWRAP: c_int = 7;
pub(crate) const GCRY_CIPHER_MODE_CCM: c_int = 8;
pub(crate) const GCRY_CIPHER_MODE_GCM: c_int = 9;
pub(crate) const GCRY_CIPHER_MODE_POLY1305: c_int = 10;
pub(crate) const GCRY_CIPHER_MODE_OCB: c_int = 11;
pub(crate) const GCRY_CIPHER_MODE_CFB8: c_int = 12;
pub(crate) const GCRY_CIPHER_MODE_XTS: c_int = 13;
pub(crate) const GCRY_CIPHER_MODE_EAX: c_int = 14;
pub(crate) const GCRY_CIPHER_MODE_SIV: c_int = 15;
pub(crate) const GCRY_CIPHER_MODE_GCM_SIV: c_int = 16;

pub(crate) const GCRY_CIPHER_ENABLE_SYNC: c_uint = 2;
pub(crate) const GCRY_CIPHER_CBC_CTS: c_uint = 4;
pub(crate) const GCRY_CIPHER_CBC_MAC: c_uint = 8;
pub(crate) const GCRY_CIPHER_EXTENDED: c_uint = 16;

pub(crate) const GCRYCTL_CFB_SYNC: c_int = 3;
pub(crate) const GCRYCTL_RESET: c_int = 4;
pub(crate) const GCRYCTL_FINALIZE: c_int = 5;
pub(crate) const GCRYCTL_GET_KEYLEN: c_int = 6;
pub(crate) const GCRYCTL_GET_BLKLEN: c_int = 7;
pub(crate) const GCRYCTL_TEST_ALGO: c_int = 8;
pub(crate) const GCRYCTL_SET_CBC_CTS: c_int = 41;
pub(crate) const GCRYCTL_SET_CBC_MAC: c_int = 42;
pub(crate) const GCRYCTL_SET_CCM_LENGTHS: c_int = 69;
pub(crate) const GCRYCTL_SET_TAGLEN: c_int = 75;
pub(crate) const GCRYCTL_GET_TAGLEN: c_int = 76;
pub(crate) const GCRYCTL_SET_ALLOW_WEAK_KEY: c_int = 79;
pub(crate) const GCRYCTL_SET_DECRYPTION_TAG: c_int = 80;

#[derive(Clone, Copy)]
struct CipherQueryInfo {
    id: c_int,
    name: &'static [u8],
    match_names: &'static [&'static str],
    block_len: usize,
    key_len: usize,
}

const IDEA_NAMES: &[&str] = &["idea"];
const DES3_NAMES: &[&str] = &["3des"];
const CAST5_NAMES: &[&str] = &["cast5"];
const BLOWFISH_NAMES: &[&str] = &["blowfish"];
const AES_NAMES: &[&str] = &["aes", "rijndael", "aes128", "rijndael128"];
const AES192_NAMES: &[&str] = &["aes192", "rijndael192"];
const AES256_NAMES: &[&str] = &["aes256", "rijndael256"];
const TWOFISH_NAMES: &[&str] = &["twofish"];
const ARCFOUR_NAMES: &[&str] = &["arcfour"];
const DES_NAMES: &[&str] = &["des"];
const TWOFISH128_NAMES: &[&str] = &["twofish128"];
const SERPENT128_NAMES: &[&str] = &["serpent128", "serpent"];
const SERPENT192_NAMES: &[&str] = &["serpent192"];
const SERPENT256_NAMES: &[&str] = &["serpent256"];
const RFC2268_40_NAMES: &[&str] = &["rfc226840"];
const RFC2268_128_NAMES: &[&str] = &["rfc2268128"];
const SEED_NAMES: &[&str] = &["seed"];
const CAMELLIA128_NAMES: &[&str] = &["camellia128"];
const CAMELLIA192_NAMES: &[&str] = &["camellia192"];
const CAMELLIA256_NAMES: &[&str] = &["camellia256"];
const SALSA20_NAMES: &[&str] = &["salsa20"];
const SALSA20R12_NAMES: &[&str] = &["salsa20r12"];
const GOST28147_NAMES: &[&str] = &["gost28147"];
const CHACHA20_NAMES: &[&str] = &["chacha20"];
const GOST28147_MESH_NAMES: &[&str] = &["gost28147mesh"];
const SM4_NAMES: &[&str] = &["sm4"];

const QUERY_ALGORITHMS: &[CipherQueryInfo] = &[
    CipherQueryInfo {
        id: GCRY_CIPHER_IDEA,
        name: b"IDEA\0",
        match_names: IDEA_NAMES,
        block_len: 8,
        key_len: 16,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_3DES,
        name: b"3DES\0",
        match_names: DES3_NAMES,
        block_len: 8,
        key_len: 24,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_CAST5,
        name: b"CAST5\0",
        match_names: CAST5_NAMES,
        block_len: 8,
        key_len: 16,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_BLOWFISH,
        name: b"BLOWFISH\0",
        match_names: BLOWFISH_NAMES,
        block_len: 8,
        key_len: 16,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_AES,
        name: b"AES\0",
        match_names: AES_NAMES,
        block_len: 16,
        key_len: 16,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_AES192,
        name: b"AES192\0",
        match_names: AES192_NAMES,
        block_len: 16,
        key_len: 24,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_AES256,
        name: b"AES256\0",
        match_names: AES256_NAMES,
        block_len: 16,
        key_len: 32,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_TWOFISH,
        name: b"TWOFISH\0",
        match_names: TWOFISH_NAMES,
        block_len: 16,
        key_len: 32,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_ARCFOUR,
        name: b"ARCFOUR\0",
        match_names: ARCFOUR_NAMES,
        block_len: 1,
        key_len: 16,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_DES,
        name: b"DES\0",
        match_names: DES_NAMES,
        block_len: 8,
        key_len: 8,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_TWOFISH128,
        name: b"TWOFISH128\0",
        match_names: TWOFISH128_NAMES,
        block_len: 16,
        key_len: 16,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_SERPENT128,
        name: b"SERPENT128\0",
        match_names: SERPENT128_NAMES,
        block_len: 16,
        key_len: 16,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_SERPENT192,
        name: b"SERPENT192\0",
        match_names: SERPENT192_NAMES,
        block_len: 16,
        key_len: 24,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_SERPENT256,
        name: b"SERPENT256\0",
        match_names: SERPENT256_NAMES,
        block_len: 16,
        key_len: 32,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_RFC2268_40,
        name: b"RFC2268_40\0",
        match_names: RFC2268_40_NAMES,
        block_len: 8,
        key_len: 5,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_RFC2268_128,
        name: b"RFC2268_128\0",
        match_names: RFC2268_128_NAMES,
        block_len: 8,
        key_len: 16,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_SEED,
        name: b"SEED\0",
        match_names: SEED_NAMES,
        block_len: 16,
        key_len: 16,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_CAMELLIA128,
        name: b"CAMELLIA128\0",
        match_names: CAMELLIA128_NAMES,
        block_len: 16,
        key_len: 16,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_CAMELLIA192,
        name: b"CAMELLIA192\0",
        match_names: CAMELLIA192_NAMES,
        block_len: 16,
        key_len: 24,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_CAMELLIA256,
        name: b"CAMELLIA256\0",
        match_names: CAMELLIA256_NAMES,
        block_len: 16,
        key_len: 32,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_SALSA20,
        name: b"SALSA20\0",
        match_names: SALSA20_NAMES,
        block_len: 1,
        key_len: 32,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_SALSA20R12,
        name: b"SALSA20R12\0",
        match_names: SALSA20R12_NAMES,
        block_len: 1,
        key_len: 32,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_GOST28147,
        name: b"GOST28147\0",
        match_names: GOST28147_NAMES,
        block_len: 8,
        key_len: 32,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_CHACHA20,
        name: b"CHACHA20\0",
        match_names: CHACHA20_NAMES,
        block_len: 1,
        key_len: 32,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_GOST28147_MESH,
        name: b"GOST28147_MESH\0",
        match_names: GOST28147_MESH_NAMES,
        block_len: 8,
        key_len: 32,
    },
    CipherQueryInfo {
        id: GCRY_CIPHER_SM4,
        name: b"SM4\0",
        match_names: SM4_NAMES,
        block_len: 16,
        key_len: 16,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CipherAlgorithm {
    Idea,
    TripleDes,
    Cast5,
    Blowfish,
    Aes128,
    Aes192,
    Aes256,
    Twofish,
    Arcfour,
    Des,
    Twofish128,
    Serpent128,
    Serpent192,
    Serpent256,
    Rc2_40,
    Rc2_128,
    Seed,
    Camellia128,
    Camellia192,
    Camellia256,
    Salsa20,
    Salsa20R12,
    Gost28147,
    Chacha20,
    Gost28147Mesh,
    Sm4,
}

impl CipherAlgorithm {
    pub(crate) fn id(self) -> c_int {
        match self {
            Self::Idea => GCRY_CIPHER_IDEA,
            Self::TripleDes => GCRY_CIPHER_3DES,
            Self::Cast5 => GCRY_CIPHER_CAST5,
            Self::Blowfish => GCRY_CIPHER_BLOWFISH,
            Self::Aes128 => GCRY_CIPHER_AES,
            Self::Aes192 => GCRY_CIPHER_AES192,
            Self::Aes256 => GCRY_CIPHER_AES256,
            Self::Twofish => GCRY_CIPHER_TWOFISH,
            Self::Arcfour => GCRY_CIPHER_ARCFOUR,
            Self::Des => GCRY_CIPHER_DES,
            Self::Twofish128 => GCRY_CIPHER_TWOFISH128,
            Self::Serpent128 => GCRY_CIPHER_SERPENT128,
            Self::Serpent192 => GCRY_CIPHER_SERPENT192,
            Self::Serpent256 => GCRY_CIPHER_SERPENT256,
            Self::Rc2_40 => GCRY_CIPHER_RFC2268_40,
            Self::Rc2_128 => GCRY_CIPHER_RFC2268_128,
            Self::Seed => GCRY_CIPHER_SEED,
            Self::Camellia128 => GCRY_CIPHER_CAMELLIA128,
            Self::Camellia192 => GCRY_CIPHER_CAMELLIA192,
            Self::Camellia256 => GCRY_CIPHER_CAMELLIA256,
            Self::Salsa20 => GCRY_CIPHER_SALSA20,
            Self::Salsa20R12 => GCRY_CIPHER_SALSA20R12,
            Self::Gost28147 => GCRY_CIPHER_GOST28147,
            Self::Chacha20 => GCRY_CIPHER_CHACHA20,
            Self::Gost28147Mesh => GCRY_CIPHER_GOST28147_MESH,
            Self::Sm4 => GCRY_CIPHER_SM4,
        }
    }

    pub(crate) fn block_len(self) -> usize {
        query_algorithm_from_id(self.id())
            .map(|info| info.block_len)
            .unwrap_or(0)
    }

    pub(crate) fn is_aes(self) -> bool {
        matches!(self, Self::Aes128 | Self::Aes192 | Self::Aes256)
    }

    pub(crate) fn is_stream_cipher(self) -> bool {
        matches!(
            self,
            Self::Arcfour | Self::Salsa20 | Self::Salsa20R12 | Self::Chacha20
        )
    }

    pub(crate) fn is_block_cipher(self) -> bool {
        !self.is_stream_cipher()
    }

    pub(crate) fn is_block16(self) -> bool {
        self.block_len() == 16 && self.is_block_cipher()
    }

    pub(crate) fn is_block8(self) -> bool {
        self.block_len() == 8 && self.is_block_cipher()
    }

    pub(crate) fn local_runtime_supported(self) -> bool {
        !matches!(self, Self::Seed | Self::Gost28147 | Self::Gost28147Mesh)
    }
}

pub(crate) fn algorithm_is_locally_supported(algo: CipherAlgorithm) -> bool {
    algo.local_runtime_supported()
}

fn unknown_name() -> *const c_char {
    b"?\0".as_ptr().cast()
}

fn query_algorithm_from_id(algo: c_int) -> Option<&'static CipherQueryInfo> {
    QUERY_ALGORITHMS.iter().find(|info| info.id == algo)
}

fn query_algorithm_from_name(name: &str) -> Option<&'static CipherQueryInfo> {
    let normalized = normalize_name(name);
    QUERY_ALGORITHMS
        .iter()
        .find(|info| info.match_names.iter().any(|candidate| *candidate == normalized))
}

pub(crate) fn algorithm_from_id(algo: c_int) -> Option<CipherAlgorithm> {
    match algo {
        GCRY_CIPHER_IDEA => Some(CipherAlgorithm::Idea),
        GCRY_CIPHER_3DES => Some(CipherAlgorithm::TripleDes),
        GCRY_CIPHER_CAST5 => Some(CipherAlgorithm::Cast5),
        GCRY_CIPHER_BLOWFISH => Some(CipherAlgorithm::Blowfish),
        GCRY_CIPHER_AES => Some(CipherAlgorithm::Aes128),
        GCRY_CIPHER_AES192 => Some(CipherAlgorithm::Aes192),
        GCRY_CIPHER_AES256 => Some(CipherAlgorithm::Aes256),
        GCRY_CIPHER_TWOFISH => Some(CipherAlgorithm::Twofish),
        GCRY_CIPHER_ARCFOUR => Some(CipherAlgorithm::Arcfour),
        GCRY_CIPHER_DES => Some(CipherAlgorithm::Des),
        GCRY_CIPHER_TWOFISH128 => Some(CipherAlgorithm::Twofish128),
        GCRY_CIPHER_SERPENT128 => Some(CipherAlgorithm::Serpent128),
        GCRY_CIPHER_SERPENT192 => Some(CipherAlgorithm::Serpent192),
        GCRY_CIPHER_SERPENT256 => Some(CipherAlgorithm::Serpent256),
        GCRY_CIPHER_RFC2268_40 => Some(CipherAlgorithm::Rc2_40),
        GCRY_CIPHER_RFC2268_128 => Some(CipherAlgorithm::Rc2_128),
        GCRY_CIPHER_SEED => Some(CipherAlgorithm::Seed),
        GCRY_CIPHER_CAMELLIA128 => Some(CipherAlgorithm::Camellia128),
        GCRY_CIPHER_CAMELLIA192 => Some(CipherAlgorithm::Camellia192),
        GCRY_CIPHER_CAMELLIA256 => Some(CipherAlgorithm::Camellia256),
        GCRY_CIPHER_SALSA20 => Some(CipherAlgorithm::Salsa20),
        GCRY_CIPHER_SALSA20R12 => Some(CipherAlgorithm::Salsa20R12),
        GCRY_CIPHER_GOST28147 => Some(CipherAlgorithm::Gost28147),
        GCRY_CIPHER_CHACHA20 => Some(CipherAlgorithm::Chacha20),
        GCRY_CIPHER_GOST28147_MESH => Some(CipherAlgorithm::Gost28147Mesh),
        GCRY_CIPHER_SM4 => Some(CipherAlgorithm::Sm4),
        _ => None,
    }
}

pub(crate) fn mode_supported(mode: c_int) -> bool {
    stream::is_stream_mode(mode)
        || mode == GCRY_CIPHER_MODE_POLY1305
        || block::is_block_mode(mode)
        || aead::is_aead_mode(mode)
}

pub(crate) fn mode_supported_for_algorithm(mode: c_int, algo: CipherAlgorithm) -> bool {
    if !algo.local_runtime_supported() {
        return false;
    }

    match mode {
        GCRY_CIPHER_MODE_STREAM => algo.is_stream_cipher(),
        GCRY_CIPHER_MODE_POLY1305 => algo == CipherAlgorithm::Chacha20,
        GCRY_CIPHER_MODE_NONE
        | GCRY_CIPHER_MODE_ECB
        | GCRY_CIPHER_MODE_CFB
        | GCRY_CIPHER_MODE_CBC
        | GCRY_CIPHER_MODE_OFB
        | GCRY_CIPHER_MODE_CTR
        | GCRY_CIPHER_MODE_CFB8
        | GCRY_CIPHER_MODE_EAX => algo.is_block_cipher(),
        GCRY_CIPHER_MODE_CCM
        | GCRY_CIPHER_MODE_GCM
        | GCRY_CIPHER_MODE_OCB
        | GCRY_CIPHER_MODE_XTS => algo.is_block16(),
        GCRY_CIPHER_MODE_AESWRAP => algo.is_aes(),
        GCRY_CIPHER_MODE_SIV | GCRY_CIPHER_MODE_GCM_SIV => algo.is_block16(),
        _ => false,
    }
}

pub(crate) fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

pub(crate) fn mode_from_oid_str(oid: &CStr) -> c_int {
    match oid.to_bytes() {
        // AES / Rijndael
        b"2.16.840.1.101.3.4.1.1" => GCRY_CIPHER_MODE_ECB,
        b"2.16.840.1.101.3.4.1.2" => GCRY_CIPHER_MODE_CBC,
        b"2.16.840.1.101.3.4.1.3" => GCRY_CIPHER_MODE_OFB,
        b"2.16.840.1.101.3.4.1.4" => GCRY_CIPHER_MODE_CFB,
        b"2.16.840.1.101.3.4.1.6" => GCRY_CIPHER_MODE_GCM,
        b"2.16.840.1.101.3.4.1.7" => GCRY_CIPHER_MODE_CCM,
        b"2.16.840.1.101.3.4.1.21" => GCRY_CIPHER_MODE_ECB,
        b"2.16.840.1.101.3.4.1.22" => GCRY_CIPHER_MODE_CBC,
        b"2.16.840.1.101.3.4.1.23" => GCRY_CIPHER_MODE_OFB,
        b"2.16.840.1.101.3.4.1.24" => GCRY_CIPHER_MODE_CFB,
        b"2.16.840.1.101.3.4.1.26" => GCRY_CIPHER_MODE_GCM,
        b"2.16.840.1.101.3.4.1.27" => GCRY_CIPHER_MODE_CCM,
        b"2.16.840.1.101.3.4.1.41" => GCRY_CIPHER_MODE_ECB,
        b"2.16.840.1.101.3.4.1.42" => GCRY_CIPHER_MODE_CBC,
        b"2.16.840.1.101.3.4.1.43" => GCRY_CIPHER_MODE_OFB,
        b"2.16.840.1.101.3.4.1.44" => GCRY_CIPHER_MODE_CFB,
        b"2.16.840.1.101.3.4.1.46" => GCRY_CIPHER_MODE_GCM,
        b"2.16.840.1.101.3.4.1.47" => GCRY_CIPHER_MODE_CCM,
        // Camellia
        b"1.2.392.200011.61.1.1.1.2" => GCRY_CIPHER_MODE_CBC,
        b"0.3.4401.5.3.1.9.1" => GCRY_CIPHER_MODE_ECB,
        b"0.3.4401.5.3.1.9.3" => GCRY_CIPHER_MODE_OFB,
        b"0.3.4401.5.3.1.9.4" => GCRY_CIPHER_MODE_CFB,
        b"1.2.392.200011.61.1.1.1.3" => GCRY_CIPHER_MODE_CBC,
        b"0.3.4401.5.3.1.9.21" => GCRY_CIPHER_MODE_ECB,
        b"0.3.4401.5.3.1.9.23" => GCRY_CIPHER_MODE_OFB,
        b"0.3.4401.5.3.1.9.24" => GCRY_CIPHER_MODE_CFB,
        b"1.2.392.200011.61.1.1.1.4" => GCRY_CIPHER_MODE_CBC,
        b"0.3.4401.5.3.1.9.41" => GCRY_CIPHER_MODE_ECB,
        b"0.3.4401.5.3.1.9.43" => GCRY_CIPHER_MODE_OFB,
        b"0.3.4401.5.3.1.9.44" => GCRY_CIPHER_MODE_CFB,
        // Serpent
        b"1.3.6.1.4.1.11591.13.2.1" => GCRY_CIPHER_MODE_ECB,
        b"1.3.6.1.4.1.11591.13.2.2" => GCRY_CIPHER_MODE_CBC,
        b"1.3.6.1.4.1.11591.13.2.3" => GCRY_CIPHER_MODE_OFB,
        b"1.3.6.1.4.1.11591.13.2.4" => GCRY_CIPHER_MODE_CFB,
        b"1.3.6.1.4.1.11591.13.2.21" => GCRY_CIPHER_MODE_ECB,
        b"1.3.6.1.4.1.11591.13.2.22" => GCRY_CIPHER_MODE_CBC,
        b"1.3.6.1.4.1.11591.13.2.23" => GCRY_CIPHER_MODE_OFB,
        b"1.3.6.1.4.1.11591.13.2.24" => GCRY_CIPHER_MODE_CFB,
        b"1.3.6.1.4.1.11591.13.2.41" => GCRY_CIPHER_MODE_ECB,
        b"1.3.6.1.4.1.11591.13.2.42" => GCRY_CIPHER_MODE_CBC,
        b"1.3.6.1.4.1.11591.13.2.43" => GCRY_CIPHER_MODE_OFB,
        b"1.3.6.1.4.1.11591.13.2.44" => GCRY_CIPHER_MODE_CFB,
        // 3DES
        b"1.2.840.113549.3.7" => GCRY_CIPHER_MODE_CBC,
        b"1.3.36.3.1.3.2.1" => GCRY_CIPHER_MODE_CBC,
        b"1.2.840.113549.1.12.1.3" => GCRY_CIPHER_MODE_CBC,
        // SEED
        b"1.2.410.200004.1.3" => GCRY_CIPHER_MODE_ECB,
        b"1.2.410.200004.1.4" => GCRY_CIPHER_MODE_CBC,
        b"1.2.410.200004.1.5" => GCRY_CIPHER_MODE_CFB,
        b"1.2.410.200004.1.6" => GCRY_CIPHER_MODE_OFB,
        // RFC2268 / RC2
        b"1.2.840.113549.1.12.1.6" => GCRY_CIPHER_MODE_CBC,
        b"1.2.840.113549.1.12.1.5" => GCRY_CIPHER_MODE_CBC,
        // SM4
        b"1.2.156.10197.1.104.1" => GCRY_CIPHER_MODE_ECB,
        b"1.2.156.10197.1.104.2" => GCRY_CIPHER_MODE_CBC,
        b"1.2.156.10197.1.104.3" => GCRY_CIPHER_MODE_OFB,
        b"1.2.156.10197.1.104.4" => GCRY_CIPHER_MODE_CFB,
        b"1.2.156.10197.1.104.7" => GCRY_CIPHER_MODE_CTR,
        // GOST28147 with CryptoPro key meshing
        b"1.2.643.2.2.21" => GCRY_CIPHER_MODE_CFB,
        b"1.2.643.2.2.31.1" => GCRY_CIPHER_MODE_CFB,
        b"1.2.643.2.2.31.2" => GCRY_CIPHER_MODE_CFB,
        b"1.2.643.2.2.31.3" => GCRY_CIPHER_MODE_CFB,
        b"1.2.643.2.2.31.4" => GCRY_CIPHER_MODE_CFB,
        _ => 0,
    }
}

pub(crate) fn algo_info(algo: c_int, what: c_int, buffer: *mut c_void, nbytes: *mut usize) -> u32 {
    match what {
        GCRYCTL_GET_KEYLEN => {
            if !buffer.is_null() || nbytes.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }

            let Some(info) = query_algorithm_from_id(algo) else {
                return error::gcry_error_from_code(error::GPG_ERR_CIPHER_ALGO);
            };

            unsafe {
                *nbytes = info.key_len;
            }
            0
        }
        GCRYCTL_GET_BLKLEN => {
            if !buffer.is_null() || nbytes.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }

            let Some(info) = query_algorithm_from_id(algo) else {
                return error::gcry_error_from_code(error::GPG_ERR_CIPHER_ALGO);
            };

            unsafe {
                *nbytes = info.block_len;
            }
            0
        }
        GCRYCTL_TEST_ALGO => {
            if !buffer.is_null() || !nbytes.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            if algorithm_from_id(algo)
                .filter(|algo| algorithm_is_locally_supported(*algo))
                .is_some()
            {
                0
            } else {
                error::gcry_error_from_code(error::GPG_ERR_CIPHER_ALGO)
            }
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

pub(crate) fn algo_name(algorithm: c_int) -> *const c_char {
    query_algorithm_from_id(algorithm)
        .map(|info| info.name.as_ptr().cast())
        .unwrap_or_else(unknown_name)
}

pub(crate) fn map_name(name: *const c_char) -> c_int {
    if name.is_null() {
        return 0;
    }

    let name = unsafe { CStr::from_ptr(name) };
    query_algorithm_from_name(&name.to_string_lossy())
        .map(|info| info.id)
        .unwrap_or(0)
}

pub(crate) fn get_algo_keylen(algo: c_int) -> usize {
    query_algorithm_from_id(algo)
        .map(|info| info.key_len)
        .unwrap_or(0)
}

pub(crate) fn get_algo_blklen(algo: c_int) -> usize {
    query_algorithm_from_id(algo)
        .map(|info| info.block_len)
        .unwrap_or(0)
}
