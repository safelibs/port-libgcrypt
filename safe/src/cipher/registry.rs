use std::ffi::{CStr, c_char, c_int, c_void};

use crate::error;
use crate::global;

const GCRYCTL_GET_KEYLEN: c_int = 6;
const GCRYCTL_GET_BLKLEN: c_int = 7;
const GCRYCTL_TEST_ALGO: c_int = 8;
const UNKNOWN_NAME: &[u8] = b"?\0";

const MODE_ECB: c_int = 1;
const MODE_CFB: c_int = 2;
const MODE_CBC: c_int = 3;
const MODE_OFB: c_int = 5;
const MODE_CTR: c_int = 6;
const MODE_CCM: c_int = 8;
const MODE_GCM: c_int = 9;

#[allow(dead_code)]
pub(crate) const IMPLEMENTED_ALGORITHMS: &[c_int] = &[
    0, 1, 2, 3, 4, 7, 8, 9, 10, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313,
    314, 315, 316, 317, 318,
];

#[allow(dead_code)]
pub(crate) const IMPLEMENTED_MODES: &[c_int] =
    &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

struct CipherSpec {
    algo: c_int,
    name: &'static [u8],
    aliases: &'static [&'static [u8]],
    oids: &'static [(&'static [u8], c_int)],
    block_len: usize,
    key_len: usize,
    fips: bool,
}

const NO_ALIASES: &[&[u8]] = &[];
const NO_OIDS: &[(&[u8], c_int)] = &[];

const AES_ALIASES: &[&[u8]] = &[b"RIJNDAEL", b"AES128", b"AES-128"];
const AES192_ALIASES: &[&[u8]] = &[b"RIJNDAEL192", b"AES-192"];
const AES256_ALIASES: &[&[u8]] = &[b"RIJNDAEL256", b"AES-256"];
const SERPENT128_ALIASES: &[&[u8]] = &[b"SERPENT", b"SERPENT-128"];
const SERPENT192_ALIASES: &[&[u8]] = &[b"SERPENT-192"];
const SERPENT256_ALIASES: &[&[u8]] = &[b"SERPENT-256"];

const AES_OIDS: &[(&[u8], c_int)] = &[
    (b"2.16.840.1.101.3.4.1.1", MODE_ECB),
    (b"2.16.840.1.101.3.4.1.2", MODE_CBC),
    (b"2.16.840.1.101.3.4.1.3", MODE_OFB),
    (b"2.16.840.1.101.3.4.1.4", MODE_CFB),
    (b"2.16.840.1.101.3.4.1.6", MODE_GCM),
    (b"2.16.840.1.101.3.4.1.7", MODE_CCM),
];
const AES192_OIDS: &[(&[u8], c_int)] = &[
    (b"2.16.840.1.101.3.4.1.21", MODE_ECB),
    (b"2.16.840.1.101.3.4.1.22", MODE_CBC),
    (b"2.16.840.1.101.3.4.1.23", MODE_OFB),
    (b"2.16.840.1.101.3.4.1.24", MODE_CFB),
    (b"2.16.840.1.101.3.4.1.26", MODE_GCM),
    (b"2.16.840.1.101.3.4.1.27", MODE_CCM),
];
const AES256_OIDS: &[(&[u8], c_int)] = &[
    (b"2.16.840.1.101.3.4.1.41", MODE_ECB),
    (b"2.16.840.1.101.3.4.1.42", MODE_CBC),
    (b"2.16.840.1.101.3.4.1.43", MODE_OFB),
    (b"2.16.840.1.101.3.4.1.44", MODE_CFB),
    (b"2.16.840.1.101.3.4.1.46", MODE_GCM),
    (b"2.16.840.1.101.3.4.1.47", MODE_CCM),
];
const TDES_OIDS: &[(&[u8], c_int)] = &[
    (b"1.2.840.113549.3.7", MODE_CBC),
    (b"1.3.36.3.1.3.2.1", MODE_CBC),
    (b"1.2.840.113549.1.12.1.3", MODE_CBC),
];
const RFC2268_40_OIDS: &[(&[u8], c_int)] = &[(b"1.2.840.113549.1.12.1.6", MODE_CBC)];
const RFC2268_128_OIDS: &[(&[u8], c_int)] = &[(b"1.2.840.113549.1.12.1.5", MODE_CBC)];
const SEED_OIDS: &[(&[u8], c_int)] = &[
    (b"1.2.410.200004.1.3", MODE_ECB),
    (b"1.2.410.200004.1.4", MODE_CBC),
    (b"1.2.410.200004.1.5", MODE_CFB),
    (b"1.2.410.200004.1.6", MODE_OFB),
];
const CAMELLIA128_OIDS: &[(&[u8], c_int)] = &[
    (b"1.2.392.200011.61.1.1.1.2", MODE_CBC),
    (b"0.3.4401.5.3.1.9.1", MODE_ECB),
    (b"0.3.4401.5.3.1.9.3", MODE_OFB),
    (b"0.3.4401.5.3.1.9.4", MODE_CFB),
];
const CAMELLIA192_OIDS: &[(&[u8], c_int)] = &[
    (b"1.2.392.200011.61.1.1.1.3", MODE_CBC),
    (b"0.3.4401.5.3.1.9.21", MODE_ECB),
    (b"0.3.4401.5.3.1.9.23", MODE_OFB),
    (b"0.3.4401.5.3.1.9.24", MODE_CFB),
];
const CAMELLIA256_OIDS: &[(&[u8], c_int)] = &[
    (b"1.2.392.200011.61.1.1.1.4", MODE_CBC),
    (b"0.3.4401.5.3.1.9.41", MODE_ECB),
    (b"0.3.4401.5.3.1.9.43", MODE_OFB),
    (b"0.3.4401.5.3.1.9.44", MODE_CFB),
];
const SERPENT128_OIDS: &[(&[u8], c_int)] = &[
    (b"1.3.6.1.4.1.11591.13.2.1", MODE_ECB),
    (b"1.3.6.1.4.1.11591.13.2.2", MODE_CBC),
    (b"1.3.6.1.4.1.11591.13.2.3", MODE_OFB),
    (b"1.3.6.1.4.1.11591.13.2.4", MODE_CFB),
];
const SERPENT192_OIDS: &[(&[u8], c_int)] = &[
    (b"1.3.6.1.4.1.11591.13.2.21", MODE_ECB),
    (b"1.3.6.1.4.1.11591.13.2.22", MODE_CBC),
    (b"1.3.6.1.4.1.11591.13.2.23", MODE_OFB),
    (b"1.3.6.1.4.1.11591.13.2.24", MODE_CFB),
];
const SERPENT256_OIDS: &[(&[u8], c_int)] = &[
    (b"1.3.6.1.4.1.11591.13.2.41", MODE_ECB),
    (b"1.3.6.1.4.1.11591.13.2.42", MODE_CBC),
    (b"1.3.6.1.4.1.11591.13.2.43", MODE_OFB),
    (b"1.3.6.1.4.1.11591.13.2.44", MODE_CFB),
];
const GOST_MESH_OIDS: &[(&[u8], c_int)] = &[
    (b"1.2.643.2.2.21", MODE_CFB),
    (b"1.2.643.2.2.31.1", MODE_CFB),
    (b"1.2.643.2.2.31.2", MODE_CFB),
    (b"1.2.643.2.2.31.3", MODE_CFB),
    (b"1.2.643.2.2.31.4", MODE_CFB),
];
const SM4_OIDS: &[(&[u8], c_int)] = &[
    (b"1.2.156.10197.1.104.1", MODE_ECB),
    (b"1.2.156.10197.1.104.2", MODE_CBC),
    (b"1.2.156.10197.1.104.3", MODE_OFB),
    (b"1.2.156.10197.1.104.4", MODE_CFB),
    (b"1.2.156.10197.1.104.7", MODE_CTR),
];

const CIPHER_SPECS: &[CipherSpec] = &[
    CipherSpec {
        algo: 1,
        name: b"IDEA\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 8,
        key_len: 16,
        fips: false,
    },
    CipherSpec {
        algo: 2,
        name: b"3DES\0",
        aliases: NO_ALIASES,
        oids: TDES_OIDS,
        block_len: 8,
        key_len: 24,
        fips: false,
    },
    CipherSpec {
        algo: 3,
        name: b"CAST5\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 8,
        key_len: 16,
        fips: false,
    },
    CipherSpec {
        algo: 4,
        name: b"BLOWFISH\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 8,
        key_len: 16,
        fips: false,
    },
    CipherSpec {
        algo: 7,
        name: b"AES\0",
        aliases: AES_ALIASES,
        oids: AES_OIDS,
        block_len: 16,
        key_len: 16,
        fips: true,
    },
    CipherSpec {
        algo: 8,
        name: b"AES192\0",
        aliases: AES192_ALIASES,
        oids: AES192_OIDS,
        block_len: 16,
        key_len: 24,
        fips: true,
    },
    CipherSpec {
        algo: 9,
        name: b"AES256\0",
        aliases: AES256_ALIASES,
        oids: AES256_OIDS,
        block_len: 16,
        key_len: 32,
        fips: true,
    },
    CipherSpec {
        algo: 10,
        name: b"TWOFISH\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 16,
        key_len: 32,
        fips: false,
    },
    CipherSpec {
        algo: 301,
        name: b"ARCFOUR\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 1,
        key_len: 16,
        fips: false,
    },
    CipherSpec {
        algo: 302,
        name: b"DES\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 8,
        key_len: 8,
        fips: false,
    },
    CipherSpec {
        algo: 303,
        name: b"TWOFISH128\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 16,
        key_len: 16,
        fips: false,
    },
    CipherSpec {
        algo: 304,
        name: b"SERPENT128\0",
        aliases: SERPENT128_ALIASES,
        oids: SERPENT128_OIDS,
        block_len: 16,
        key_len: 16,
        fips: false,
    },
    CipherSpec {
        algo: 305,
        name: b"SERPENT192\0",
        aliases: SERPENT192_ALIASES,
        oids: SERPENT192_OIDS,
        block_len: 16,
        key_len: 24,
        fips: false,
    },
    CipherSpec {
        algo: 306,
        name: b"SERPENT256\0",
        aliases: SERPENT256_ALIASES,
        oids: SERPENT256_OIDS,
        block_len: 16,
        key_len: 32,
        fips: false,
    },
    CipherSpec {
        algo: 307,
        name: b"RFC2268_40\0",
        aliases: NO_ALIASES,
        oids: RFC2268_40_OIDS,
        block_len: 8,
        key_len: 5,
        fips: false,
    },
    CipherSpec {
        algo: 308,
        name: b"RFC2268_128\0",
        aliases: NO_ALIASES,
        oids: RFC2268_128_OIDS,
        block_len: 8,
        key_len: 16,
        fips: false,
    },
    CipherSpec {
        algo: 309,
        name: b"SEED\0",
        aliases: NO_ALIASES,
        oids: SEED_OIDS,
        block_len: 16,
        key_len: 16,
        fips: false,
    },
    CipherSpec {
        algo: 310,
        name: b"CAMELLIA128\0",
        aliases: NO_ALIASES,
        oids: CAMELLIA128_OIDS,
        block_len: 16,
        key_len: 16,
        fips: false,
    },
    CipherSpec {
        algo: 311,
        name: b"CAMELLIA192\0",
        aliases: NO_ALIASES,
        oids: CAMELLIA192_OIDS,
        block_len: 16,
        key_len: 24,
        fips: false,
    },
    CipherSpec {
        algo: 312,
        name: b"CAMELLIA256\0",
        aliases: NO_ALIASES,
        oids: CAMELLIA256_OIDS,
        block_len: 16,
        key_len: 32,
        fips: false,
    },
    CipherSpec {
        algo: 313,
        name: b"SALSA20\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 1,
        key_len: 32,
        fips: false,
    },
    CipherSpec {
        algo: 314,
        name: b"SALSA20R12\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 1,
        key_len: 32,
        fips: false,
    },
    CipherSpec {
        algo: 315,
        name: b"GOST28147\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 8,
        key_len: 32,
        fips: false,
    },
    CipherSpec {
        algo: 316,
        name: b"CHACHA20\0",
        aliases: NO_ALIASES,
        oids: NO_OIDS,
        block_len: 1,
        key_len: 32,
        fips: false,
    },
    CipherSpec {
        algo: 317,
        name: b"GOST28147_MESH\0",
        aliases: NO_ALIASES,
        oids: GOST_MESH_OIDS,
        block_len: 8,
        key_len: 32,
        fips: false,
    },
    CipherSpec {
        algo: 318,
        name: b"SM4\0",
        aliases: NO_ALIASES,
        oids: SM4_OIDS,
        block_len: 16,
        key_len: 16,
        fips: false,
    },
];

fn err(code: u32) -> u32 {
    error::gcry_error_from_code(code)
}

fn spec_from_algo(algo: c_int) -> Option<&'static CipherSpec> {
    CIPHER_SPECS.iter().find(|spec| spec.algo == algo)
}

fn spec_from_name(name: &[u8]) -> Option<&'static CipherSpec> {
    CIPHER_SPECS.iter().find(|spec| {
        spec.name[..spec.name.len() - 1].eq_ignore_ascii_case(name)
            || spec
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name))
    })
}

fn normalize_oid(mut oid: &[u8]) -> &[u8] {
    if oid.len() > 4 && (&oid[..4]).eq_ignore_ascii_case(b"oid.") {
        oid = &oid[4..];
    }
    oid
}

fn spec_from_oid(oid: &[u8]) -> Option<(&'static CipherSpec, c_int)> {
    let oid = normalize_oid(oid);
    CIPHER_SPECS.iter().find_map(|spec| {
        spec.oids
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(oid))
            .map(|(_, mode)| (spec, *mode))
    })
}

fn algorithm_available(spec: &CipherSpec) -> bool {
    let state = global::lock_runtime_state();
    !state.fips_mode || spec.fips
}

pub(crate) fn algorithm_available_for_open(algo: c_int) -> bool {
    let Some(spec) = spec_from_algo(algo) else {
        return false;
    };
    let mut state = global::lock_runtime_state();
    global::global_init_locked(&mut state);
    !state.fips_mode || spec.fips
}

pub(crate) fn algo_info(algo: c_int, what: c_int, buffer: *mut c_void, nbytes: *mut usize) -> u32 {
    let Some(spec) = spec_from_algo(algo) else {
        return err(error::GPG_ERR_CIPHER_ALGO);
    };

    match what {
        GCRYCTL_GET_KEYLEN => {
            if !buffer.is_null() || nbytes.is_null() {
                return err(error::GPG_ERR_CIPHER_ALGO);
            }
            unsafe {
                *nbytes = spec.key_len;
            }
            0
        }
        GCRYCTL_GET_BLKLEN => {
            if !buffer.is_null() || nbytes.is_null() {
                return err(error::GPG_ERR_CIPHER_ALGO);
            }
            unsafe {
                *nbytes = spec.block_len;
            }
            0
        }
        GCRYCTL_TEST_ALGO => {
            if !buffer.is_null() || !nbytes.is_null() {
                return err(error::GPG_ERR_INV_ARG);
            }
            if algorithm_available(spec) {
                0
            } else {
                err(error::GPG_ERR_CIPHER_ALGO)
            }
        }
        _ => err(error::GPG_ERR_INV_OP),
    }
}

pub(crate) fn algo_name(algorithm: c_int) -> *const c_char {
    spec_from_algo(algorithm)
        .map(|spec| spec.name.as_ptr().cast())
        .unwrap_or_else(|| UNKNOWN_NAME.as_ptr().cast())
}

pub(crate) fn map_name(name: *const c_char) -> c_int {
    if name.is_null() {
        return 0;
    }

    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    if let Some((spec, _)) = spec_from_oid(bytes) {
        return spec.algo;
    }

    spec_from_name(bytes).map(|spec| spec.algo).unwrap_or(0)
}

pub(crate) fn mode_from_oid(string: *const c_char) -> c_int {
    if string.is_null() {
        return 0;
    }

    let bytes = unsafe { CStr::from_ptr(string) }.to_bytes();
    spec_from_oid(bytes).map(|(_, mode)| mode).unwrap_or(0)
}

pub(crate) fn get_algo_keylen(algo: c_int) -> usize {
    let mut nbytes = 0;
    if algo_info(algo, GCRYCTL_GET_KEYLEN, std::ptr::null_mut(), &mut nbytes) == 0 {
        nbytes
    } else {
        0
    }
}

pub(crate) fn get_algo_blklen(algo: c_int) -> usize {
    let mut nbytes = 0;
    if algo_info(algo, GCRYCTL_GET_BLKLEN, std::ptr::null_mut(), &mut nbytes) == 0 {
        nbytes
    } else {
        0
    }
}
