use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::mem::{size_of, zeroed};
use std::ptr::{copy_nonoverlapping, drop_in_place, null_mut, write};

use crate::alloc;
use crate::digest;
use crate::error;

const GCRYCTL_RESET: c_int = 4;
const GCRYCTL_GET_KEYLEN: c_int = 6;
const GCRYCTL_TEST_ALGO: c_int = 8;

const GCRY_MAC_FLAG_SECURE: c_uint = 1;

const GPG_ERR_CHECKSUM: u32 = 10;
const GPG_ERR_INV_LENGTH: u32 = 139;
const GPG_ERR_MAC_ALGO: u32 = 197;

const GCRY_MAC_NONE: c_int = 0;
const GCRY_MAC_GOST28147_IMIT: c_int = 1;
const GCRY_MAC_HMAC_SHA256: c_int = 101;
const GCRY_MAC_HMAC_SHA224: c_int = 102;
const GCRY_MAC_HMAC_SHA512: c_int = 103;
const GCRY_MAC_HMAC_SHA384: c_int = 104;
const GCRY_MAC_HMAC_SHA1: c_int = 105;
const GCRY_MAC_HMAC_MD5: c_int = 106;
const GCRY_MAC_HMAC_MD4: c_int = 107;
const GCRY_MAC_HMAC_RMD160: c_int = 108;
const GCRY_MAC_HMAC_TIGER1: c_int = 109;
const GCRY_MAC_HMAC_WHIRLPOOL: c_int = 110;
const GCRY_MAC_HMAC_GOSTR3411_94: c_int = 111;
const GCRY_MAC_HMAC_STRIBOG256: c_int = 112;
const GCRY_MAC_HMAC_STRIBOG512: c_int = 113;
const GCRY_MAC_HMAC_MD2: c_int = 114;
const GCRY_MAC_HMAC_SHA3_224: c_int = 115;
const GCRY_MAC_HMAC_SHA3_256: c_int = 116;
const GCRY_MAC_HMAC_SHA3_384: c_int = 117;
const GCRY_MAC_HMAC_SHA3_512: c_int = 118;
const GCRY_MAC_HMAC_GOSTR3411_CP: c_int = 119;
const GCRY_MAC_HMAC_BLAKE2B_512: c_int = 120;
const GCRY_MAC_HMAC_BLAKE2B_384: c_int = 121;
const GCRY_MAC_HMAC_BLAKE2B_256: c_int = 122;
const GCRY_MAC_HMAC_BLAKE2B_160: c_int = 123;
const GCRY_MAC_HMAC_BLAKE2S_256: c_int = 124;
const GCRY_MAC_HMAC_BLAKE2S_224: c_int = 125;
const GCRY_MAC_HMAC_BLAKE2S_160: c_int = 126;
const GCRY_MAC_HMAC_BLAKE2S_128: c_int = 127;
const GCRY_MAC_HMAC_SM3: c_int = 128;
const GCRY_MAC_HMAC_SHA512_256: c_int = 129;
const GCRY_MAC_HMAC_SHA512_224: c_int = 130;
const GCRY_MAC_CMAC_AES: c_int = 201;
const GCRY_MAC_CMAC_3DES: c_int = 202;
const GCRY_MAC_CMAC_CAMELLIA: c_int = 203;
const GCRY_MAC_CMAC_CAST5: c_int = 204;
const GCRY_MAC_CMAC_BLOWFISH: c_int = 205;
const GCRY_MAC_CMAC_TWOFISH: c_int = 206;
const GCRY_MAC_CMAC_SERPENT: c_int = 207;
const GCRY_MAC_CMAC_SEED: c_int = 208;
const GCRY_MAC_CMAC_RFC2268: c_int = 209;
const GCRY_MAC_CMAC_IDEA: c_int = 210;
const GCRY_MAC_CMAC_GOST28147: c_int = 211;
const GCRY_MAC_CMAC_SM4: c_int = 212;
const GCRY_MAC_GMAC_AES: c_int = 401;
const GCRY_MAC_GMAC_CAMELLIA: c_int = 402;
const GCRY_MAC_GMAC_TWOFISH: c_int = 403;
const GCRY_MAC_GMAC_SERPENT: c_int = 404;
const GCRY_MAC_GMAC_SEED: c_int = 405;
const GCRY_MAC_POLY1305: c_int = 501;
const GCRY_MAC_POLY1305_AES: c_int = 502;
const GCRY_MAC_POLY1305_CAMELLIA: c_int = 503;
const GCRY_MAC_POLY1305_TWOFISH: c_int = 504;
const GCRY_MAC_POLY1305_SERPENT: c_int = 505;
const GCRY_MAC_POLY1305_SEED: c_int = 506;

const GCRY_MD_FLAG_SECURE: c_uint = 1;
const GCRY_MD_FLAG_HMAC: c_uint = 2;

pub type gcry_mac_hd_t = *mut gcry_mac_handle;

#[repr(C)]
pub struct gcry_mac_handle {
    algo: c_int,
    md: digest::gcry_md_hd_t,
}

fn map_mac_algo_to_md(algo: c_int) -> c_int {
    match algo {
        GCRY_MAC_HMAC_MD2 => digest::algorithms::GCRY_MD_MD2,
        GCRY_MAC_HMAC_MD4 => digest::algorithms::GCRY_MD_MD4,
        GCRY_MAC_HMAC_MD5 => digest::algorithms::GCRY_MD_MD5,
        GCRY_MAC_HMAC_SHA1 => digest::algorithms::GCRY_MD_SHA1,
        GCRY_MAC_HMAC_SHA224 => digest::algorithms::GCRY_MD_SHA224,
        GCRY_MAC_HMAC_SHA256 => digest::algorithms::GCRY_MD_SHA256,
        GCRY_MAC_HMAC_SHA384 => digest::algorithms::GCRY_MD_SHA384,
        GCRY_MAC_HMAC_SHA512 => digest::algorithms::GCRY_MD_SHA512,
        GCRY_MAC_HMAC_SHA512_256 => digest::algorithms::GCRY_MD_SHA512_256,
        GCRY_MAC_HMAC_SHA512_224 => digest::algorithms::GCRY_MD_SHA512_224,
        GCRY_MAC_HMAC_SHA3_224 => digest::algorithms::GCRY_MD_SHA3_224,
        GCRY_MAC_HMAC_SHA3_256 => digest::algorithms::GCRY_MD_SHA3_256,
        GCRY_MAC_HMAC_SHA3_384 => digest::algorithms::GCRY_MD_SHA3_384,
        GCRY_MAC_HMAC_SHA3_512 => digest::algorithms::GCRY_MD_SHA3_512,
        GCRY_MAC_HMAC_RMD160 => digest::algorithms::GCRY_MD_RMD160,
        GCRY_MAC_HMAC_TIGER1 => digest::algorithms::GCRY_MD_TIGER1,
        GCRY_MAC_HMAC_WHIRLPOOL => digest::algorithms::GCRY_MD_WHIRLPOOL,
        GCRY_MAC_HMAC_GOSTR3411_94 => digest::algorithms::GCRY_MD_GOSTR3411_94,
        GCRY_MAC_HMAC_GOSTR3411_CP => digest::algorithms::GCRY_MD_GOSTR3411_CP,
        GCRY_MAC_HMAC_STRIBOG256 => digest::algorithms::GCRY_MD_STRIBOG256,
        GCRY_MAC_HMAC_STRIBOG512 => digest::algorithms::GCRY_MD_STRIBOG512,
        GCRY_MAC_HMAC_BLAKE2B_512 => digest::algorithms::GCRY_MD_BLAKE2B_512,
        GCRY_MAC_HMAC_BLAKE2B_384 => digest::algorithms::GCRY_MD_BLAKE2B_384,
        GCRY_MAC_HMAC_BLAKE2B_256 => digest::algorithms::GCRY_MD_BLAKE2B_256,
        GCRY_MAC_HMAC_BLAKE2B_160 => digest::algorithms::GCRY_MD_BLAKE2B_160,
        GCRY_MAC_HMAC_BLAKE2S_256 => digest::algorithms::GCRY_MD_BLAKE2S_256,
        GCRY_MAC_HMAC_BLAKE2S_224 => digest::algorithms::GCRY_MD_BLAKE2S_224,
        GCRY_MAC_HMAC_BLAKE2S_160 => digest::algorithms::GCRY_MD_BLAKE2S_160,
        GCRY_MAC_HMAC_BLAKE2S_128 => digest::algorithms::GCRY_MD_BLAKE2S_128,
        GCRY_MAC_HMAC_SM3 => digest::algorithms::GCRY_MD_SM3,
        _ => digest::algorithms::GCRY_MD_NONE,
    }
}

fn mac_is_available(algo: c_int) -> bool {
    let md_algo = map_mac_algo_to_md(algo);
    md_algo != digest::algorithms::GCRY_MD_NONE && digest::algorithms::supports_hmac(md_algo)
}

fn canonical_name(algo: c_int) -> Option<&'static str> {
    match algo {
        GCRY_MAC_NONE => Some("NONE"),
        GCRY_MAC_GOST28147_IMIT => Some("GOST28147_IMIT"),
        GCRY_MAC_HMAC_SHA256 => Some("HMAC_SHA256"),
        GCRY_MAC_HMAC_SHA224 => Some("HMAC_SHA224"),
        GCRY_MAC_HMAC_SHA512 => Some("HMAC_SHA512"),
        GCRY_MAC_HMAC_SHA384 => Some("HMAC_SHA384"),
        GCRY_MAC_HMAC_SHA1 => Some("HMAC_SHA1"),
        GCRY_MAC_HMAC_MD5 => Some("HMAC_MD5"),
        GCRY_MAC_HMAC_MD4 => Some("HMAC_MD4"),
        GCRY_MAC_HMAC_RMD160 => Some("HMAC_RMD160"),
        GCRY_MAC_HMAC_TIGER1 => Some("HMAC_TIGER1"),
        GCRY_MAC_HMAC_WHIRLPOOL => Some("HMAC_WHIRLPOOL"),
        GCRY_MAC_HMAC_GOSTR3411_94 => Some("HMAC_GOSTR3411_94"),
        GCRY_MAC_HMAC_STRIBOG256 => Some("HMAC_STRIBOG256"),
        GCRY_MAC_HMAC_STRIBOG512 => Some("HMAC_STRIBOG512"),
        GCRY_MAC_HMAC_MD2 => Some("HMAC_MD2"),
        GCRY_MAC_HMAC_SHA3_224 => Some("HMAC_SHA3_224"),
        GCRY_MAC_HMAC_SHA3_256 => Some("HMAC_SHA3_256"),
        GCRY_MAC_HMAC_SHA3_384 => Some("HMAC_SHA3_384"),
        GCRY_MAC_HMAC_SHA3_512 => Some("HMAC_SHA3_512"),
        GCRY_MAC_HMAC_GOSTR3411_CP => Some("HMAC_GOSTR3411_CP"),
        GCRY_MAC_HMAC_BLAKE2B_512 => Some("HMAC_BLAKE2B_512"),
        GCRY_MAC_HMAC_BLAKE2B_384 => Some("HMAC_BLAKE2B_384"),
        GCRY_MAC_HMAC_BLAKE2B_256 => Some("HMAC_BLAKE2B_256"),
        GCRY_MAC_HMAC_BLAKE2B_160 => Some("HMAC_BLAKE2B_160"),
        GCRY_MAC_HMAC_BLAKE2S_256 => Some("HMAC_BLAKE2S_256"),
        GCRY_MAC_HMAC_BLAKE2S_224 => Some("HMAC_BLAKE2S_224"),
        GCRY_MAC_HMAC_BLAKE2S_160 => Some("HMAC_BLAKE2S_160"),
        GCRY_MAC_HMAC_BLAKE2S_128 => Some("HMAC_BLAKE2S_128"),
        GCRY_MAC_HMAC_SM3 => Some("HMAC_SM3"),
        GCRY_MAC_HMAC_SHA512_256 => Some("HMAC_SHA512_256"),
        GCRY_MAC_HMAC_SHA512_224 => Some("HMAC_SHA512_224"),
        GCRY_MAC_CMAC_AES => Some("CMAC_AES"),
        GCRY_MAC_CMAC_3DES => Some("CMAC_3DES"),
        GCRY_MAC_CMAC_CAMELLIA => Some("CMAC_CAMELLIA"),
        GCRY_MAC_CMAC_CAST5 => Some("CMAC_CAST5"),
        GCRY_MAC_CMAC_BLOWFISH => Some("CMAC_BLOWFISH"),
        GCRY_MAC_CMAC_TWOFISH => Some("CMAC_TWOFISH"),
        GCRY_MAC_CMAC_SERPENT => Some("CMAC_SERPENT"),
        GCRY_MAC_CMAC_SEED => Some("CMAC_SEED"),
        GCRY_MAC_CMAC_RFC2268 => Some("CMAC_RFC2268"),
        GCRY_MAC_CMAC_IDEA => Some("CMAC_IDEA"),
        GCRY_MAC_CMAC_GOST28147 => Some("CMAC_GOST28147"),
        GCRY_MAC_CMAC_SM4 => Some("CMAC_SM4"),
        GCRY_MAC_GMAC_AES => Some("GMAC_AES"),
        GCRY_MAC_GMAC_CAMELLIA => Some("GMAC_CAMELLIA"),
        GCRY_MAC_GMAC_TWOFISH => Some("GMAC_TWOFISH"),
        GCRY_MAC_GMAC_SERPENT => Some("GMAC_SERPENT"),
        GCRY_MAC_GMAC_SEED => Some("GMAC_SEED"),
        GCRY_MAC_POLY1305 => Some("POLY1305"),
        GCRY_MAC_POLY1305_AES => Some("POLY1305_AES"),
        GCRY_MAC_POLY1305_CAMELLIA => Some("POLY1305_CAMELLIA"),
        GCRY_MAC_POLY1305_TWOFISH => Some("POLY1305_TWOFISH"),
        GCRY_MAC_POLY1305_SERPENT => Some("POLY1305_SERPENT"),
        GCRY_MAC_POLY1305_SEED => Some("POLY1305_SEED"),
        _ => None,
    }
}

fn canonical_name_bytes(algo: c_int) -> Option<&'static [u8]> {
    canonical_name(algo).map(|name| match name {
        "NONE" => b"NONE\0".as_slice(),
        "GOST28147_IMIT" => b"GOST28147_IMIT\0".as_slice(),
        "HMAC_SHA256" => b"HMAC_SHA256\0".as_slice(),
        "HMAC_SHA224" => b"HMAC_SHA224\0".as_slice(),
        "HMAC_SHA512" => b"HMAC_SHA512\0".as_slice(),
        "HMAC_SHA384" => b"HMAC_SHA384\0".as_slice(),
        "HMAC_SHA1" => b"HMAC_SHA1\0".as_slice(),
        "HMAC_MD5" => b"HMAC_MD5\0".as_slice(),
        "HMAC_MD4" => b"HMAC_MD4\0".as_slice(),
        "HMAC_RMD160" => b"HMAC_RMD160\0".as_slice(),
        "HMAC_TIGER1" => b"HMAC_TIGER1\0".as_slice(),
        "HMAC_WHIRLPOOL" => b"HMAC_WHIRLPOOL\0".as_slice(),
        "HMAC_GOSTR3411_94" => b"HMAC_GOSTR3411_94\0".as_slice(),
        "HMAC_STRIBOG256" => b"HMAC_STRIBOG256\0".as_slice(),
        "HMAC_STRIBOG512" => b"HMAC_STRIBOG512\0".as_slice(),
        "HMAC_MD2" => b"HMAC_MD2\0".as_slice(),
        "HMAC_SHA3_224" => b"HMAC_SHA3_224\0".as_slice(),
        "HMAC_SHA3_256" => b"HMAC_SHA3_256\0".as_slice(),
        "HMAC_SHA3_384" => b"HMAC_SHA3_384\0".as_slice(),
        "HMAC_SHA3_512" => b"HMAC_SHA3_512\0".as_slice(),
        "HMAC_GOSTR3411_CP" => b"HMAC_GOSTR3411_CP\0".as_slice(),
        "HMAC_BLAKE2B_512" => b"HMAC_BLAKE2B_512\0".as_slice(),
        "HMAC_BLAKE2B_384" => b"HMAC_BLAKE2B_384\0".as_slice(),
        "HMAC_BLAKE2B_256" => b"HMAC_BLAKE2B_256\0".as_slice(),
        "HMAC_BLAKE2B_160" => b"HMAC_BLAKE2B_160\0".as_slice(),
        "HMAC_BLAKE2S_256" => b"HMAC_BLAKE2S_256\0".as_slice(),
        "HMAC_BLAKE2S_224" => b"HMAC_BLAKE2S_224\0".as_slice(),
        "HMAC_BLAKE2S_160" => b"HMAC_BLAKE2S_160\0".as_slice(),
        "HMAC_BLAKE2S_128" => b"HMAC_BLAKE2S_128\0".as_slice(),
        "HMAC_SM3" => b"HMAC_SM3\0".as_slice(),
        "HMAC_SHA512_256" => b"HMAC_SHA512_256\0".as_slice(),
        "HMAC_SHA512_224" => b"HMAC_SHA512_224\0".as_slice(),
        "CMAC_AES" => b"CMAC_AES\0".as_slice(),
        "CMAC_3DES" => b"CMAC_3DES\0".as_slice(),
        "CMAC_CAMELLIA" => b"CMAC_CAMELLIA\0".as_slice(),
        "CMAC_CAST5" => b"CMAC_CAST5\0".as_slice(),
        "CMAC_BLOWFISH" => b"CMAC_BLOWFISH\0".as_slice(),
        "CMAC_TWOFISH" => b"CMAC_TWOFISH\0".as_slice(),
        "CMAC_SERPENT" => b"CMAC_SERPENT\0".as_slice(),
        "CMAC_SEED" => b"CMAC_SEED\0".as_slice(),
        "CMAC_RFC2268" => b"CMAC_RFC2268\0".as_slice(),
        "CMAC_IDEA" => b"CMAC_IDEA\0".as_slice(),
        "CMAC_GOST28147" => b"CMAC_GOST28147\0".as_slice(),
        "CMAC_SM4" => b"CMAC_SM4\0".as_slice(),
        "GMAC_AES" => b"GMAC_AES\0".as_slice(),
        "GMAC_CAMELLIA" => b"GMAC_CAMELLIA\0".as_slice(),
        "GMAC_TWOFISH" => b"GMAC_TWOFISH\0".as_slice(),
        "GMAC_SERPENT" => b"GMAC_SERPENT\0".as_slice(),
        "GMAC_SEED" => b"GMAC_SEED\0".as_slice(),
        "POLY1305" => b"POLY1305\0".as_slice(),
        "POLY1305_AES" => b"POLY1305_AES\0".as_slice(),
        "POLY1305_CAMELLIA" => b"POLY1305_CAMELLIA\0".as_slice(),
        "POLY1305_TWOFISH" => b"POLY1305_TWOFISH\0".as_slice(),
        "POLY1305_SERPENT" => b"POLY1305_SERPENT\0".as_slice(),
        "POLY1305_SEED" => b"POLY1305_SEED\0".as_slice(),
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

fn matches_name(normalized: &str, canonical: &str) -> bool {
    let canonical_normalized = normalize_name(canonical);
    if normalized == canonical_normalized {
        return true;
    }
    normalized == canonical_normalized.replace('_', "")
}

fn map_name(name: &str) -> c_int {
    let normalized = normalize_name(name.trim());
    if normalized.is_empty() {
        return 0;
    }

    for algo in [
        GCRY_MAC_NONE,
        GCRY_MAC_GOST28147_IMIT,
        GCRY_MAC_HMAC_SHA256,
        GCRY_MAC_HMAC_SHA224,
        GCRY_MAC_HMAC_SHA512,
        GCRY_MAC_HMAC_SHA384,
        GCRY_MAC_HMAC_SHA1,
        GCRY_MAC_HMAC_MD5,
        GCRY_MAC_HMAC_MD4,
        GCRY_MAC_HMAC_RMD160,
        GCRY_MAC_HMAC_TIGER1,
        GCRY_MAC_HMAC_WHIRLPOOL,
        GCRY_MAC_HMAC_GOSTR3411_94,
        GCRY_MAC_HMAC_STRIBOG256,
        GCRY_MAC_HMAC_STRIBOG512,
        GCRY_MAC_HMAC_MD2,
        GCRY_MAC_HMAC_SHA3_224,
        GCRY_MAC_HMAC_SHA3_256,
        GCRY_MAC_HMAC_SHA3_384,
        GCRY_MAC_HMAC_SHA3_512,
        GCRY_MAC_HMAC_GOSTR3411_CP,
        GCRY_MAC_HMAC_BLAKE2B_512,
        GCRY_MAC_HMAC_BLAKE2B_384,
        GCRY_MAC_HMAC_BLAKE2B_256,
        GCRY_MAC_HMAC_BLAKE2B_160,
        GCRY_MAC_HMAC_BLAKE2S_256,
        GCRY_MAC_HMAC_BLAKE2S_224,
        GCRY_MAC_HMAC_BLAKE2S_160,
        GCRY_MAC_HMAC_BLAKE2S_128,
        GCRY_MAC_HMAC_SM3,
        GCRY_MAC_HMAC_SHA512_256,
        GCRY_MAC_HMAC_SHA512_224,
        GCRY_MAC_CMAC_AES,
        GCRY_MAC_CMAC_3DES,
        GCRY_MAC_CMAC_CAMELLIA,
        GCRY_MAC_CMAC_CAST5,
        GCRY_MAC_CMAC_BLOWFISH,
        GCRY_MAC_CMAC_TWOFISH,
        GCRY_MAC_CMAC_SERPENT,
        GCRY_MAC_CMAC_SEED,
        GCRY_MAC_CMAC_RFC2268,
        GCRY_MAC_CMAC_IDEA,
        GCRY_MAC_CMAC_GOST28147,
        GCRY_MAC_CMAC_SM4,
        GCRY_MAC_GMAC_AES,
        GCRY_MAC_GMAC_CAMELLIA,
        GCRY_MAC_GMAC_TWOFISH,
        GCRY_MAC_GMAC_SERPENT,
        GCRY_MAC_GMAC_SEED,
        GCRY_MAC_POLY1305,
        GCRY_MAC_POLY1305_AES,
        GCRY_MAC_POLY1305_CAMELLIA,
        GCRY_MAC_POLY1305_TWOFISH,
        GCRY_MAC_POLY1305_SERPENT,
        GCRY_MAC_POLY1305_SEED,
    ] {
        if let Some(canonical) = canonical_name(algo) {
            if matches_name(&normalized, canonical) {
                return algo;
            }
        }
    }

    0
}

fn allocate_handle(algo: c_int, md: digest::gcry_md_hd_t, secure: bool) -> Option<gcry_mac_hd_t> {
    let raw = if secure {
        alloc::gcry_calloc_secure(1, size_of::<gcry_mac_handle>())
    } else {
        alloc::gcry_calloc(1, size_of::<gcry_mac_handle>())
    }
    .cast::<gcry_mac_handle>();
    if raw.is_null() {
        return None;
    }

    unsafe {
        write(raw, gcry_mac_handle { algo, md });
    }
    Some(raw)
}

fn const_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (lhs, rhs) in left.iter().zip(right) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

#[no_mangle]
pub extern "C" fn gcry_mac_open(
    handle: *mut gcry_mac_hd_t,
    algo: c_int,
    flags: c_uint,
    _ctx: *mut c_void,
) -> u32 {
    if handle.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    unsafe {
        *handle = null_mut();
    }

    if flags & !GCRY_MAC_FLAG_SECURE != 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if !mac_is_available(algo) {
        return error::gcry_error_from_code(GPG_ERR_MAC_ALGO);
    }

    let md_algo = map_mac_algo_to_md(algo);
    let secure = flags & GCRY_MAC_FLAG_SECURE != 0;
    let md_flags = GCRY_MD_FLAG_HMAC | if secure { GCRY_MD_FLAG_SECURE } else { 0 };

    let mut md = unsafe { zeroed() };
    let rc = digest::gcry_md_open(&mut md, md_algo, md_flags);
    if rc != 0 {
        return rc;
    }

    let Some(raw) = allocate_handle(algo, md, secure) else {
        digest::gcry_md_close(md);
        return error::gcry_error_from_errno(crate::get_errno());
    };

    unsafe {
        *handle = raw;
    }
    0
}

#[no_mangle]
pub extern "C" fn gcry_mac_close(handle: gcry_mac_hd_t) {
    if handle.is_null() {
        return;
    }

    unsafe {
        digest::gcry_md_close((*handle).md);
        drop_in_place(handle);
    }
    alloc::gcry_free(handle.cast());
}

#[no_mangle]
pub extern "C" fn gcry_mac_ctl(
    handle: gcry_mac_hd_t,
    cmd: c_int,
    _buffer: *mut c_void,
    _buflen: usize,
) -> u32 {
    if handle.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    match cmd {
        GCRYCTL_RESET => {
            unsafe {
                digest::gcry_md_reset((*handle).md);
            }
            0
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[no_mangle]
pub extern "C" fn gcry_mac_algo_info(
    algo: c_int,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    match what {
        GCRYCTL_GET_KEYLEN => {
            if !buffer.is_null() || nbytes.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }

            let value = gcry_mac_get_algo_keylen(algo);
            if value == 0 {
                return error::gcry_error_from_code(GPG_ERR_MAC_ALGO);
            }

            unsafe {
                *nbytes = value as usize;
            }
            0
        }
        GCRYCTL_TEST_ALGO => {
            if !buffer.is_null() || !nbytes.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            if mac_is_available(algo) {
                0
            } else {
                error::gcry_error_from_code(GPG_ERR_MAC_ALGO)
            }
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[no_mangle]
pub extern "C" fn gcry_mac_setkey(handle: gcry_mac_hd_t, key: *const c_void, keylen: usize) -> u32 {
    if handle.is_null() || (keylen > 0 && key.is_null()) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    unsafe { digest::gcry_md_setkey((*handle).md, key, keylen) }
}

#[no_mangle]
pub extern "C" fn gcry_mac_setiv(handle: gcry_mac_hd_t, iv: *const c_void, ivlen: usize) -> u32 {
    if handle.is_null() || (ivlen > 0 && iv.is_null()) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    error::gcry_error_from_code(error::GPG_ERR_INV_ARG)
}

#[no_mangle]
pub extern "C" fn gcry_mac_write(
    handle: gcry_mac_hd_t,
    buffer: *const c_void,
    length: usize,
) -> u32 {
    if handle.is_null() || (length > 0 && buffer.is_null()) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    unsafe {
        digest::gcry_md_write((*handle).md, buffer, length);
    }
    0
}

#[no_mangle]
pub extern "C" fn gcry_mac_read(
    handle: gcry_mac_hd_t,
    buffer: *mut c_void,
    buflen: *mut usize,
) -> u32 {
    if handle.is_null() || buffer.is_null() || buflen.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let requested = unsafe { *buflen };
    if requested == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let algo = unsafe { (*handle).algo };
    let md_algo = map_mac_algo_to_md(algo);
    let maclen = gcry_mac_get_algo_maclen(algo) as usize;
    let digest = unsafe { digest::gcry_md_read((*handle).md, md_algo) };
    if digest.is_null() || maclen == 0 {
        return error::gcry_error_from_code(GPG_ERR_MAC_ALGO);
    }

    let copy_len = requested.min(maclen);
    unsafe {
        copy_nonoverlapping(digest, buffer.cast::<u8>(), copy_len);
        if requested > maclen {
            *buflen = maclen;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn gcry_mac_verify(
    handle: gcry_mac_hd_t,
    buffer: *const c_void,
    buflen: usize,
) -> u32 {
    if handle.is_null() || buffer.is_null() || buflen == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let algo = unsafe { (*handle).algo };
    let md_algo = map_mac_algo_to_md(algo);
    let maclen = gcry_mac_get_algo_maclen(algo) as usize;
    if buflen > maclen {
        return error::gcry_error_from_code(GPG_ERR_INV_LENGTH);
    }

    let digest = unsafe { digest::gcry_md_read((*handle).md, md_algo) };
    if digest.is_null() {
        return error::gcry_error_from_code(GPG_ERR_MAC_ALGO);
    }

    let expected = unsafe { std::slice::from_raw_parts(digest.cast_const(), buflen) };
    let actual = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), buflen) };
    if const_time_eq(expected, actual) {
        0
    } else {
        error::gcry_error_from_code(GPG_ERR_CHECKSUM)
    }
}

#[no_mangle]
pub extern "C" fn gcry_mac_get_algo(handle: gcry_mac_hd_t) -> c_int {
    if handle.is_null() {
        0
    } else {
        unsafe { (*handle).algo }
    }
}

#[no_mangle]
pub extern "C" fn gcry_mac_get_algo_maclen(algo: c_int) -> c_uint {
    let md_algo = map_mac_algo_to_md(algo);
    if md_algo == digest::algorithms::GCRY_MD_NONE {
        0
    } else {
        digest::gcry_md_get_algo_dlen(md_algo)
    }
}

#[no_mangle]
pub extern "C" fn gcry_mac_get_algo_keylen(algo: c_int) -> c_uint {
    let md_algo = map_mac_algo_to_md(algo);
    if md_algo == digest::algorithms::GCRY_MD_NONE {
        0
    } else {
        digest::digest_block_len(md_algo) as c_uint
    }
}

#[no_mangle]
pub extern "C" fn gcry_mac_algo_name(algo: c_int) -> *const c_char {
    canonical_name_bytes(algo)
        .map_or(b"?\0".as_ptr().cast(), |name| name.as_ptr().cast())
}

#[no_mangle]
pub extern "C" fn gcry_mac_map_name(name: *const c_char) -> c_int {
    if name.is_null() {
        return 0;
    }

    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    map_name(&name)
}
