use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::ptr::copy_nonoverlapping;

use blowfish::Blowfish;
use camellia::Camellia128;
use cast5::Cast5;
use cipher04::generic_array::GenericArray;
use cipher04::{BlockEncrypt as BlockEncrypt04, KeyInit as KeyInit04};
use cipher05::{Block as Block05, BlockCipherEncrypt, KeyInit as KeyInit05};
use des::TdesEde3;
use gost_crypto::{Gost28147, SBOX_TEST};
use idea::Idea;
use kisaseed::SEED;
use rc2::Rc2;
use serpent::Serpent;
use sm4::Sm4;
use twofish::Twofish;

use crate::digest::algorithms;
use crate::error;

pub type gcry_mac_hd_t = *mut gcry_mac_handle;

const GCRYCTL_RESET: c_int = 4;
const GCRYCTL_GET_KEYLEN: c_int = 6;
const GCRYCTL_TEST_ALGO: c_int = 8;
const GCRYCTL_SET_SBOX: c_int = 73;
const GPG_ERR_MAC_ALGO: u32 = 197;
const GPG_ERR_VALUE_NOT_FOUND: u32 = 28;

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

#[derive(Clone, Copy)]
enum MacKind {
    Gost28147Imit,
    Hmac(c_int),
    Cmac(c_int),
    Gmac(c_int),
    Poly1305Plain,
    Poly1305Cipher(c_int),
}

#[repr(C)]
pub struct gcry_mac_handle {
    algo: c_int,
    kind: MacKind,
    key: Vec<u8>,
    iv: Vec<u8>,
    data: Vec<u8>,
    result: Vec<u8>,
    key_set: bool,
    iv_set: bool,
    gost_sbox: &'static [[u8; 16]; 8],
}

fn digest_for_mac(algo: c_int) -> Option<c_int> {
    Some(match algo {
        GCRY_MAC_HMAC_SHA256 => algorithms::GCRY_MD_SHA256,
        GCRY_MAC_HMAC_SHA224 => algorithms::GCRY_MD_SHA224,
        GCRY_MAC_HMAC_SHA512 => algorithms::GCRY_MD_SHA512,
        GCRY_MAC_HMAC_SHA384 => algorithms::GCRY_MD_SHA384,
        GCRY_MAC_HMAC_SHA1 => algorithms::GCRY_MD_SHA1,
        GCRY_MAC_HMAC_MD5 => algorithms::GCRY_MD_MD5,
        GCRY_MAC_HMAC_MD4 => algorithms::GCRY_MD_MD4,
        GCRY_MAC_HMAC_RMD160 => algorithms::GCRY_MD_RMD160,
        GCRY_MAC_HMAC_TIGER1 => algorithms::GCRY_MD_TIGER1,
        GCRY_MAC_HMAC_WHIRLPOOL => algorithms::GCRY_MD_WHIRLPOOL,
        GCRY_MAC_HMAC_GOSTR3411_94 => algorithms::GCRY_MD_GOSTR3411_94,
        GCRY_MAC_HMAC_STRIBOG256 => algorithms::GCRY_MD_STRIBOG256,
        GCRY_MAC_HMAC_STRIBOG512 => algorithms::GCRY_MD_STRIBOG512,
        GCRY_MAC_HMAC_SHA3_224 => algorithms::GCRY_MD_SHA3_224,
        GCRY_MAC_HMAC_SHA3_256 => algorithms::GCRY_MD_SHA3_256,
        GCRY_MAC_HMAC_SHA3_384 => algorithms::GCRY_MD_SHA3_384,
        GCRY_MAC_HMAC_SHA3_512 => algorithms::GCRY_MD_SHA3_512,
        GCRY_MAC_HMAC_GOSTR3411_CP => algorithms::GCRY_MD_GOSTR3411_CP,
        GCRY_MAC_HMAC_BLAKE2B_512 => algorithms::GCRY_MD_BLAKE2B_512,
        GCRY_MAC_HMAC_BLAKE2B_384 => algorithms::GCRY_MD_BLAKE2B_384,
        GCRY_MAC_HMAC_BLAKE2B_256 => algorithms::GCRY_MD_BLAKE2B_256,
        GCRY_MAC_HMAC_BLAKE2B_160 => algorithms::GCRY_MD_BLAKE2B_160,
        GCRY_MAC_HMAC_BLAKE2S_256 => algorithms::GCRY_MD_BLAKE2S_256,
        GCRY_MAC_HMAC_BLAKE2S_224 => algorithms::GCRY_MD_BLAKE2S_224,
        GCRY_MAC_HMAC_BLAKE2S_160 => algorithms::GCRY_MD_BLAKE2S_160,
        GCRY_MAC_HMAC_BLAKE2S_128 => algorithms::GCRY_MD_BLAKE2S_128,
        GCRY_MAC_HMAC_SM3 => algorithms::GCRY_MD_SM3,
        GCRY_MAC_HMAC_SHA512_256 => algorithms::GCRY_MD_SHA512_256,
        GCRY_MAC_HMAC_SHA512_224 => algorithms::GCRY_MD_SHA512_224,
        _ => return None,
    })
}

fn kind_for_mac(algo: c_int) -> Option<MacKind> {
    if let Some(digest) = digest_for_mac(algo) {
        return Some(MacKind::Hmac(digest));
    }
    match algo {
        GCRY_MAC_GOST28147_IMIT => Some(MacKind::Gost28147Imit),
        GCRY_MAC_CMAC_AES
        | GCRY_MAC_CMAC_3DES
        | GCRY_MAC_CMAC_CAMELLIA
        | GCRY_MAC_CMAC_CAST5
        | GCRY_MAC_CMAC_BLOWFISH
        | GCRY_MAC_CMAC_TWOFISH
        | GCRY_MAC_CMAC_SERPENT
        | GCRY_MAC_CMAC_SEED
        | GCRY_MAC_CMAC_RFC2268
        | GCRY_MAC_CMAC_IDEA
        | GCRY_MAC_CMAC_GOST28147
        | GCRY_MAC_CMAC_SM4 => Some(MacKind::Cmac(algo)),
        GCRY_MAC_GMAC_AES
        | GCRY_MAC_GMAC_CAMELLIA
        | GCRY_MAC_GMAC_TWOFISH
        | GCRY_MAC_GMAC_SERPENT
        | GCRY_MAC_GMAC_SEED => Some(MacKind::Gmac(algo)),
        GCRY_MAC_POLY1305 => Some(MacKind::Poly1305Plain),
        GCRY_MAC_POLY1305_AES
        | GCRY_MAC_POLY1305_CAMELLIA
        | GCRY_MAC_POLY1305_TWOFISH
        | GCRY_MAC_POLY1305_SERPENT
        | GCRY_MAC_POLY1305_SEED => Some(MacKind::Poly1305Cipher(algo)),
        _ => None,
    }
}

fn known_mac(algo: c_int) -> bool {
    digest_for_mac(algo).is_some()
        || matches!(
            algo,
            GCRY_MAC_GOST28147_IMIT
                | GCRY_MAC_CMAC_AES
                | GCRY_MAC_CMAC_3DES
                | GCRY_MAC_CMAC_CAMELLIA
                | GCRY_MAC_CMAC_CAST5
                | GCRY_MAC_CMAC_BLOWFISH
                | GCRY_MAC_CMAC_TWOFISH
                | GCRY_MAC_CMAC_SERPENT
                | GCRY_MAC_CMAC_SEED
                | GCRY_MAC_CMAC_RFC2268
                | GCRY_MAC_CMAC_IDEA
                | GCRY_MAC_CMAC_GOST28147
                | GCRY_MAC_CMAC_SM4
                | GCRY_MAC_GMAC_AES
                | GCRY_MAC_GMAC_CAMELLIA
                | GCRY_MAC_GMAC_TWOFISH
                | GCRY_MAC_GMAC_SERPENT
                | GCRY_MAC_GMAC_SEED
                | GCRY_MAC_POLY1305
                | GCRY_MAC_POLY1305_AES
                | GCRY_MAC_POLY1305_CAMELLIA
                | GCRY_MAC_POLY1305_TWOFISH
                | GCRY_MAC_POLY1305_SERPENT
                | GCRY_MAC_POLY1305_SEED
        )
}

fn mac_name(algo: c_int) -> &'static [u8] {
    match algo {
        GCRY_MAC_GOST28147_IMIT => b"GOST28147_IMIT\0",
        GCRY_MAC_HMAC_SHA256 => b"HMAC_SHA256\0",
        GCRY_MAC_HMAC_SHA224 => b"HMAC_SHA224\0",
        GCRY_MAC_HMAC_SHA512 => b"HMAC_SHA512\0",
        GCRY_MAC_HMAC_SHA384 => b"HMAC_SHA384\0",
        GCRY_MAC_HMAC_SHA1 => b"HMAC_SHA1\0",
        GCRY_MAC_HMAC_MD5 => b"HMAC_MD5\0",
        GCRY_MAC_HMAC_MD4 => b"HMAC_MD4\0",
        GCRY_MAC_HMAC_RMD160 => b"HMAC_RMD160\0",
        GCRY_MAC_HMAC_TIGER1 => b"HMAC_TIGER1\0",
        GCRY_MAC_HMAC_WHIRLPOOL => b"HMAC_WHIRLPOOL\0",
        GCRY_MAC_HMAC_GOSTR3411_94 => b"HMAC_GOSTR3411_94\0",
        GCRY_MAC_HMAC_STRIBOG256 => b"HMAC_STRIBOG256\0",
        GCRY_MAC_HMAC_STRIBOG512 => b"HMAC_STRIBOG512\0",
        GCRY_MAC_HMAC_SHA3_224 => b"HMAC_SHA3_224\0",
        GCRY_MAC_HMAC_SHA3_256 => b"HMAC_SHA3_256\0",
        GCRY_MAC_HMAC_SHA3_384 => b"HMAC_SHA3_384\0",
        GCRY_MAC_HMAC_SHA3_512 => b"HMAC_SHA3_512\0",
        GCRY_MAC_HMAC_GOSTR3411_CP => b"HMAC_GOSTR3411_CP\0",
        GCRY_MAC_HMAC_BLAKE2B_512 => b"HMAC_BLAKE2B_512\0",
        GCRY_MAC_HMAC_BLAKE2B_384 => b"HMAC_BLAKE2B_384\0",
        GCRY_MAC_HMAC_BLAKE2B_256 => b"HMAC_BLAKE2B_256\0",
        GCRY_MAC_HMAC_BLAKE2B_160 => b"HMAC_BLAKE2B_160\0",
        GCRY_MAC_HMAC_BLAKE2S_256 => b"HMAC_BLAKE2S_256\0",
        GCRY_MAC_HMAC_BLAKE2S_224 => b"HMAC_BLAKE2S_224\0",
        GCRY_MAC_HMAC_BLAKE2S_160 => b"HMAC_BLAKE2S_160\0",
        GCRY_MAC_HMAC_BLAKE2S_128 => b"HMAC_BLAKE2S_128\0",
        GCRY_MAC_HMAC_SM3 => b"HMAC_SM3\0",
        GCRY_MAC_HMAC_SHA512_256 => b"HMAC_SHA512_256\0",
        GCRY_MAC_HMAC_SHA512_224 => b"HMAC_SHA512_224\0",
        GCRY_MAC_CMAC_AES => b"CMAC_AES\0",
        GCRY_MAC_CMAC_3DES => b"CMAC_3DES\0",
        GCRY_MAC_CMAC_CAMELLIA => b"CMAC_CAMELLIA\0",
        GCRY_MAC_CMAC_CAST5 => b"CMAC_CAST5\0",
        GCRY_MAC_CMAC_BLOWFISH => b"CMAC_BLOWFISH\0",
        GCRY_MAC_CMAC_TWOFISH => b"CMAC_TWOFISH\0",
        GCRY_MAC_CMAC_SERPENT => b"CMAC_SERPENT\0",
        GCRY_MAC_CMAC_SEED => b"CMAC_SEED\0",
        GCRY_MAC_CMAC_RFC2268 => b"CMAC_RFC2268\0",
        GCRY_MAC_CMAC_IDEA => b"CMAC_IDEA\0",
        GCRY_MAC_CMAC_GOST28147 => b"CMAC_GOST28147\0",
        GCRY_MAC_CMAC_SM4 => b"CMAC_SM4\0",
        GCRY_MAC_GMAC_AES => b"GMAC_AES\0",
        GCRY_MAC_GMAC_CAMELLIA => b"GMAC_CAMELLIA\0",
        GCRY_MAC_GMAC_TWOFISH => b"GMAC_TWOFISH\0",
        GCRY_MAC_GMAC_SERPENT => b"GMAC_SERPENT\0",
        GCRY_MAC_GMAC_SEED => b"GMAC_SEED\0",
        GCRY_MAC_POLY1305 => b"POLY1305\0",
        GCRY_MAC_POLY1305_AES => b"POLY1305_AES\0",
        GCRY_MAC_POLY1305_CAMELLIA => b"POLY1305_CAMELLIA\0",
        GCRY_MAC_POLY1305_TWOFISH => b"POLY1305_TWOFISH\0",
        GCRY_MAC_POLY1305_SERPENT => b"POLY1305_SERPENT\0",
        GCRY_MAC_POLY1305_SEED => b"POLY1305_SEED\0",
        _ => b"?\0",
    }
}

fn compute(handle: &mut gcry_mac_handle) -> Result<&[u8], u32> {
    if handle.result.is_empty() {
        handle.result = match handle.kind {
            MacKind::Gost28147Imit => {
                if !handle.key_set {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_INV_STATE));
                }
                gost28147_imit_compute(
                    &handle.key,
                    handle.iv.as_slice(),
                    &handle.data,
                    handle.gost_sbox,
                )
                .ok_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_KEYLEN))?
            }
            MacKind::Hmac(digest_algo) => {
                algorithms::hmac_once(digest_algo, &handle.key, &handle.data)
                    .ok_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_ARG))?
            }
            MacKind::Cmac(algo) => cmac_compute(algo, &handle.key, &handle.data)
                .ok_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_ARG))?,
            MacKind::Gmac(algo) => gmac_compute(algo, &handle.key, &handle.iv, &handle.data)
                .ok_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_STATE))?,
            MacKind::Poly1305Plain => {
                if !handle.key_set {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_INV_STATE));
                }
                let key = (&handle.key[..])
                    .try_into()
                    .map_err(|_| error::gcry_error_from_code(error::GPG_ERR_INV_KEYLEN))?;
                poly1305_mac(key, &handle.data).to_vec()
            }
            MacKind::Poly1305Cipher(algo) => {
                if !handle.key_set || !handle.iv_set {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_INV_STATE));
                }
                let one_time_key = poly1305_cipher_key(algo, &handle.key, &handle.iv)
                    .ok_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_KEYLEN))?;
                poly1305_mac(&one_time_key, &handle.data).to_vec()
            }
        };
    }
    Ok(&handle.result)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_open(
    handle: *mut gcry_mac_hd_t,
    algo: c_int,
    flags: c_uint,
    _ctx: *mut c_void,
) -> u32 {
    if handle.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if flags & !1 != 0 {
        unsafe { *handle = std::ptr::null_mut() };
        return error::gcry_error_from_code(error::GPG_ERR_INV_FLAG);
    }
    let Some(kind) = kind_for_mac(algo) else {
        unsafe { *handle = std::ptr::null_mut() };
        let code = if known_mac(algo) {
            error::GPG_ERR_NOT_SUPPORTED
        } else {
            error::GPG_ERR_INV_ARG
        };
        return error::gcry_error_from_code(code);
    };
    let mac = Box::new(gcry_mac_handle {
        algo,
        kind,
        key: Vec::new(),
        iv: Vec::new(),
        data: Vec::new(),
        result: Vec::new(),
        key_set: false,
        iv_set: false,
        gost_sbox: &GOST28147_CRYPTOPRO_A_SBOX,
    });
    unsafe { *handle = Box::into_raw(mac) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_close(handle: gcry_mac_hd_t) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_ctl(
    handle: gcry_mac_hd_t,
    cmd: c_int,
    buffer: *mut c_void,
    _buflen: usize,
) -> u32 {
    if handle.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    match cmd {
        GCRYCTL_RESET => {
            let handle = unsafe { &mut *handle };
            if matches!(
                handle.kind,
                MacKind::Poly1305Plain | MacKind::Poly1305Cipher(_)
            ) && (!handle.key_set || !handle.iv_set)
            {
                return error::gcry_error_from_code(error::GPG_ERR_INV_STATE);
            }
            if matches!(handle.kind, MacKind::Gost28147Imit | MacKind::Gmac(_)) {
                handle.iv.clear();
                handle.iv_set = false;
            }
            handle.data.clear();
            handle.result.clear();
            0
        }
        GCRYCTL_SET_SBOX => {
            let handle = unsafe { &mut *handle };
            if !matches!(handle.kind, MacKind::Gost28147Imit) {
                return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
            }
            if buffer.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            let oid = unsafe { CStr::from_ptr(buffer.cast::<c_char>()) };
            let Some(sbox) = gost28147_sbox_from_oid(oid.to_bytes()) else {
                return error::gcry_error_from_code(GPG_ERR_VALUE_NOT_FOUND);
            };
            handle.gost_sbox = sbox;
            handle.result.clear();
            0
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[unsafe(no_mangle)]
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
            let keylen = gcry_mac_get_algo_keylen(algo) as usize;
            if keylen == 0 {
                return error::gcry_error_from_code(GPG_ERR_MAC_ALGO);
            }
            unsafe { *nbytes = keylen };
            0
        }
        GCRYCTL_TEST_ALGO => {
            if !buffer.is_null() || !nbytes.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            if kind_for_mac(algo).is_some() {
                0
            } else if known_mac(algo) {
                error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED)
            } else {
                error::gcry_error_from_code(error::GPG_ERR_INV_ARG)
            }
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_setkey(handle: gcry_mac_hd_t, key: *const c_void, keylen: usize) -> u32 {
    if handle.is_null() || (key.is_null() && keylen != 0) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let handle = unsafe { &mut *handle };
    let key_bytes = if keylen == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(key.cast::<u8>(), keylen) }
    };
    if !valid_key_for_kind(handle.kind, key_bytes) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_KEYLEN);
    }
    handle.key.clear();
    handle.key.extend_from_slice(key_bytes);
    handle.key_set = true;
    match handle.kind {
        MacKind::Poly1305Plain => {
            handle.iv.clear();
            handle.iv_set = true;
        }
        MacKind::Poly1305Cipher(_) => {
            handle.iv.clear();
            handle.iv_set = false;
        }
        MacKind::Gost28147Imit | MacKind::Hmac(_) | MacKind::Cmac(_) | MacKind::Gmac(_) => {}
    }
    handle.data.clear();
    handle.result.clear();
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_setiv(handle: gcry_mac_hd_t, iv: *const c_void, ivlen: usize) -> u32 {
    if handle.is_null() || (iv.is_null() && ivlen != 0) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let handle = unsafe { &mut *handle };
    match handle.kind {
        MacKind::Hmac(_) | MacKind::Cmac(_) | MacKind::Poly1305Plain => {
            error::gcry_error_from_code(error::GPG_ERR_INV_ARG)
        }
        MacKind::Gost28147Imit => {
            if ivlen != 8 {
                return error::gcry_error_from_code(error::GPG_ERR_INV_LENGTH);
            }
            handle.iv.clear();
            handle
                .iv
                .extend_from_slice(unsafe { std::slice::from_raw_parts(iv.cast::<u8>(), ivlen) });
            handle.iv_set = true;
            handle.data.clear();
            handle.result.clear();
            0
        }
        MacKind::Gmac(_) => {
            if ivlen == 0 {
                return error::gcry_error_from_code(error::GPG_ERR_INV_LENGTH);
            }
            handle.iv.clear();
            handle
                .iv
                .extend_from_slice(unsafe { std::slice::from_raw_parts(iv.cast::<u8>(), ivlen) });
            handle.iv_set = true;
            handle.data.clear();
            handle.result.clear();
            0
        }
        MacKind::Poly1305Cipher(_) => {
            if ivlen != 16 {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            if !handle.key_set {
                return 0;
            }
            handle.iv.clear();
            handle
                .iv
                .extend_from_slice(unsafe { std::slice::from_raw_parts(iv.cast::<u8>(), ivlen) });
            handle.iv_set = true;
            handle.data.clear();
            handle.result.clear();
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_write(
    handle: gcry_mac_hd_t,
    buffer: *const c_void,
    length: usize,
) -> u32 {
    if handle.is_null() || (buffer.is_null() && length != 0) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let handle = unsafe { &mut *handle };
    if matches!(
        handle.kind,
        MacKind::Poly1305Plain | MacKind::Poly1305Cipher(_)
    ) {
        if !handle.key_set || !handle.iv_set || !handle.result.is_empty() {
            return error::gcry_error_from_code(error::GPG_ERR_INV_STATE);
        }
    }
    if matches!(handle.kind, MacKind::Gmac(_)) && (!handle.key_set || !handle.result.is_empty()) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_STATE);
    }
    if length != 0 {
        handle
            .data
            .extend_from_slice(unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) });
    }
    handle.result.clear();
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_read(
    handle: gcry_mac_hd_t,
    buffer: *mut c_void,
    buflen: *mut usize,
) -> u32 {
    if handle.is_null() || buffer.is_null() || buflen.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let handle = unsafe { &mut *handle };
    let mut requested = unsafe { *buflen };
    if requested == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if matches!(handle.kind, MacKind::Gmac(_)) {
        if requested > 16 {
            requested = 16;
            unsafe { *buflen = requested };
        } else if !valid_gmac_tag_len(requested) {
            return error::gcry_error_from_code(error::GPG_ERR_INV_LENGTH);
        }
    }
    let mac = match compute(handle) {
        Ok(mac) => mac,
        Err(err) => return err,
    };
    let to_copy = requested.min(mac.len());
    unsafe { *buflen = to_copy };
    if to_copy != 0 {
        unsafe { copy_nonoverlapping(mac.as_ptr(), buffer.cast::<u8>(), to_copy) };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_verify(
    handle: gcry_mac_hd_t,
    buffer: *const c_void,
    buflen: usize,
) -> u32 {
    if handle.is_null() || buffer.is_null() || buflen == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let handle = unsafe { &mut *handle };
    let is_gmac = matches!(handle.kind, MacKind::Gmac(_));
    let mac = match compute(handle) {
        Ok(mac) => mac,
        Err(err) => return err,
    };
    if is_gmac && !valid_gmac_tag_len(buflen) {
        return error::gcry_error_from_code(error::GPG_ERR_CHECKSUM);
    }
    if buflen > mac.len() {
        let code = match handle.kind {
            MacKind::Cmac(_) => error::GPG_ERR_INV_ARG,
            MacKind::Gost28147Imit
            | MacKind::Hmac(_)
            | MacKind::Gmac(_)
            | MacKind::Poly1305Plain
            | MacKind::Poly1305Cipher(_) => error::GPG_ERR_INV_LENGTH,
        };
        return error::gcry_error_from_code(code);
    }
    let input = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), buflen) };
    if buflen <= mac.len() && input == &mac[..buflen] {
        0
    } else {
        error::gcry_error_from_code(error::GPG_ERR_CHECKSUM)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_get_algo(handle: gcry_mac_hd_t) -> c_int {
    if handle.is_null() {
        0
    } else {
        unsafe { (*handle).algo }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_get_algo_maclen(algo: c_int) -> c_uint {
    match kind_for_mac(algo) {
        Some(MacKind::Gost28147Imit) => 4,
        Some(MacKind::Hmac(digest)) => algorithms::digest_len(digest) as c_uint,
        Some(MacKind::Cmac(cmac_algo)) => cmac_block_len(cmac_algo) as c_uint,
        Some(MacKind::Gmac(_)) => 16,
        Some(MacKind::Poly1305Plain | MacKind::Poly1305Cipher(_)) => 16,
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_get_algo_keylen(algo: c_int) -> c_uint {
    match kind_for_mac(algo) {
        Some(MacKind::Gost28147Imit) => 32,
        Some(MacKind::Hmac(_)) => hmac_keylen(algo) as c_uint,
        Some(MacKind::Cmac(cmac_algo)) => cmac_key_len(cmac_algo) as c_uint,
        Some(MacKind::Gmac(gmac_algo)) => gmac_key_len(gmac_algo) as c_uint,
        Some(MacKind::Poly1305Plain | MacKind::Poly1305Cipher(_)) => 32,
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_algo_name(algo: c_int) -> *const c_char {
    mac_name(algo).as_ptr().cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_map_name(name: *const c_char) -> c_int {
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
        "hmacsha256" => GCRY_MAC_HMAC_SHA256,
        "hmacsha224" => GCRY_MAC_HMAC_SHA224,
        "hmacsha512" => GCRY_MAC_HMAC_SHA512,
        "hmacsha384" => GCRY_MAC_HMAC_SHA384,
        "hmacsha1" => GCRY_MAC_HMAC_SHA1,
        "hmacmd5" => GCRY_MAC_HMAC_MD5,
        "hmacmd4" => GCRY_MAC_HMAC_MD4,
        "hmacrmd160" | "hmacripemd160" => GCRY_MAC_HMAC_RMD160,
        "hmactiger" | "hmactiger1" => GCRY_MAC_HMAC_TIGER1,
        "hmacwhirlpool" => GCRY_MAC_HMAC_WHIRLPOOL,
        "hmacgostr341194" | "hmacgost94" => GCRY_MAC_HMAC_GOSTR3411_94,
        "hmacstribog256" => GCRY_MAC_HMAC_STRIBOG256,
        "hmacstribog512" => GCRY_MAC_HMAC_STRIBOG512,
        "hmacsha3224" => GCRY_MAC_HMAC_SHA3_224,
        "hmacsha3256" => GCRY_MAC_HMAC_SHA3_256,
        "hmacsha3384" => GCRY_MAC_HMAC_SHA3_384,
        "hmacsha3512" => GCRY_MAC_HMAC_SHA3_512,
        "hmacgostr3411cp" | "hmacgost94cp" => GCRY_MAC_HMAC_GOSTR3411_CP,
        "hmacblake2b512" => GCRY_MAC_HMAC_BLAKE2B_512,
        "hmacblake2b384" => GCRY_MAC_HMAC_BLAKE2B_384,
        "hmacblake2b256" => GCRY_MAC_HMAC_BLAKE2B_256,
        "hmacblake2b160" => GCRY_MAC_HMAC_BLAKE2B_160,
        "hmacblake2s256" => GCRY_MAC_HMAC_BLAKE2S_256,
        "hmacblake2s224" => GCRY_MAC_HMAC_BLAKE2S_224,
        "hmacblake2s160" => GCRY_MAC_HMAC_BLAKE2S_160,
        "hmacblake2s128" => GCRY_MAC_HMAC_BLAKE2S_128,
        "hmacsm3" => GCRY_MAC_HMAC_SM3,
        "hmacsha512256" => GCRY_MAC_HMAC_SHA512_256,
        "hmacsha512224" => GCRY_MAC_HMAC_SHA512_224,
        "gost28147imit" => GCRY_MAC_GOST28147_IMIT,
        "cmacaes" => GCRY_MAC_CMAC_AES,
        "cmac3des" => GCRY_MAC_CMAC_3DES,
        "cmaccamellia" => GCRY_MAC_CMAC_CAMELLIA,
        "cmaccast5" => GCRY_MAC_CMAC_CAST5,
        "cmacblowfish" => GCRY_MAC_CMAC_BLOWFISH,
        "cmactwofish" => GCRY_MAC_CMAC_TWOFISH,
        "cmacserpent" => GCRY_MAC_CMAC_SERPENT,
        "cmacseed" => GCRY_MAC_CMAC_SEED,
        "cmacrfc2268" => GCRY_MAC_CMAC_RFC2268,
        "cmacidea" => GCRY_MAC_CMAC_IDEA,
        "cmacgost28147" => GCRY_MAC_CMAC_GOST28147,
        "cmacsm4" => GCRY_MAC_CMAC_SM4,
        "gmacaes" => GCRY_MAC_GMAC_AES,
        "gmaccamellia" => GCRY_MAC_GMAC_CAMELLIA,
        "gmactwofish" => GCRY_MAC_GMAC_TWOFISH,
        "gmacserpent" => GCRY_MAC_GMAC_SERPENT,
        "gmacseed" => GCRY_MAC_GMAC_SEED,
        "poly1305" => GCRY_MAC_POLY1305,
        "poly1305aes" => GCRY_MAC_POLY1305_AES,
        "poly1305camellia" => GCRY_MAC_POLY1305_CAMELLIA,
        "poly1305twofish" => GCRY_MAC_POLY1305_TWOFISH,
        "poly1305serpent" => GCRY_MAC_POLY1305_SERPENT,
        "poly1305seed" => GCRY_MAC_POLY1305_SEED,
        _ => 0,
    }
}

fn hmac_keylen(algo: c_int) -> usize {
    match algo {
        GCRY_MAC_HMAC_SHA384 | GCRY_MAC_HMAC_SHA512 => 128,
        GCRY_MAC_HMAC_GOSTR3411_94 => 32,
        _ => 64,
    }
}

fn mac_keylen_metadata(algo: c_int) -> usize {
    match algo {
        GCRY_MAC_GOST28147_IMIT => 32,
        GCRY_MAC_CMAC_AES => 16,
        GCRY_MAC_CMAC_3DES => 24,
        GCRY_MAC_CMAC_TWOFISH | GCRY_MAC_CMAC_GOST28147 => 32,
        GCRY_MAC_CMAC_CAMELLIA
        | GCRY_MAC_CMAC_CAST5
        | GCRY_MAC_CMAC_BLOWFISH
        | GCRY_MAC_CMAC_SERPENT
        | GCRY_MAC_CMAC_SEED
        | GCRY_MAC_CMAC_RFC2268
        | GCRY_MAC_CMAC_IDEA
        | GCRY_MAC_CMAC_SM4 => 16,
        GCRY_MAC_GMAC_AES | GCRY_MAC_GMAC_CAMELLIA | GCRY_MAC_GMAC_SERPENT | GCRY_MAC_GMAC_SEED => {
            16
        }
        GCRY_MAC_GMAC_TWOFISH => 32,
        GCRY_MAC_POLY1305 | GCRY_MAC_POLY1305_AES => 32,
        GCRY_MAC_POLY1305_CAMELLIA
        | GCRY_MAC_POLY1305_TWOFISH
        | GCRY_MAC_POLY1305_SERPENT
        | GCRY_MAC_POLY1305_SEED => 32,
        _ => 0,
    }
}

fn cmac_key_len(algo: c_int) -> usize {
    mac_keylen_metadata(algo)
}

fn cmac_block_len(algo: c_int) -> usize {
    match algo {
        GCRY_MAC_CMAC_3DES
        | GCRY_MAC_CMAC_CAST5
        | GCRY_MAC_CMAC_BLOWFISH
        | GCRY_MAC_CMAC_RFC2268
        | GCRY_MAC_CMAC_IDEA
        | GCRY_MAC_CMAC_GOST28147 => 8,
        GCRY_MAC_CMAC_AES
        | GCRY_MAC_CMAC_CAMELLIA
        | GCRY_MAC_CMAC_TWOFISH
        | GCRY_MAC_CMAC_SERPENT
        | GCRY_MAC_CMAC_SEED
        | GCRY_MAC_CMAC_SM4 => 16,
        _ => 0,
    }
}

fn valid_key_for_kind(kind: MacKind, key: &[u8]) -> bool {
    match kind {
        MacKind::Gost28147Imit => key.len() == 32,
        MacKind::Hmac(_) => true,
        MacKind::Cmac(algo) => {
            if algo == GCRY_MAC_CMAC_AES {
                matches!(key.len(), 16 | 24 | 32)
            } else {
                key.len() == cmac_key_len(algo)
            }
        }
        MacKind::Poly1305Plain => key.len() == 32,
        MacKind::Poly1305Cipher(algo) => {
            if key.len() <= 16 {
                return false;
            }
            let block = [0u8; 16];
            let cipher_key_len = key.len() - 16;
            mac_encrypt_block(algo, &key[..cipher_key_len], &block).is_some()
        }
        MacKind::Gmac(algo) => valid_gmac_key(algo, key),
    }
}

fn double_cmac_subkey(input: &[u8]) -> Option<Vec<u8>> {
    let rb = match input.len() {
        8 => 0x1b,
        16 => 0x87,
        _ => return None,
    };
    let carry = input[0] & 0x80 != 0;
    let mut out = vec![0u8; input.len()];
    let mut shifted = 0u8;
    for i in (0..input.len()).rev() {
        out[i] = (input[i] << 1) | shifted;
        shifted = input[i] >> 7;
    }
    if carry {
        let last = out.len() - 1;
        out[last] ^= rb;
    }
    Some(out)
}

fn xor_block(left: &[u8], right: &[u8]) -> Option<Vec<u8>> {
    if left.len() != right.len() {
        return None;
    }
    Some(left.iter().zip(right).map(|(a, b)| a ^ b).collect())
}

fn cmac_compute(algo: c_int, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let block_len = cmac_block_len(algo);
    if block_len == 0 {
        return None;
    }
    if algo == GCRY_MAC_CMAC_AES {
        if !matches!(key.len(), 16 | 24 | 32) {
            return None;
        }
    } else if key.len() != cmac_key_len(algo) {
        return None;
    }

    let l = mac_encrypt_block(algo, key, &vec![0u8; block_len])?;
    let k1 = double_cmac_subkey(&l)?;
    let k2 = double_cmac_subkey(&k1)?;
    let complete = !data.is_empty() && data.len() % block_len == 0;
    let full_blocks_before_last = if complete {
        data.len() / block_len - 1
    } else {
        data.len() / block_len
    };

    let mut state = vec![0u8; block_len];
    for block in data[..full_blocks_before_last * block_len].chunks_exact(block_len) {
        state = mac_encrypt_block(algo, key, &xor_block(&state, block)?)?;
    }

    let mut last = vec![0u8; block_len];
    if complete {
        last.copy_from_slice(&data[data.len() - block_len..]);
        last = xor_block(&last, &k1)?;
    } else {
        let rem = &data[full_blocks_before_last * block_len..];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] = 0x80;
        last = xor_block(&last, &k2)?;
    }
    mac_encrypt_block(algo, key, &xor_block(&state, &last)?)
}

fn mac_encrypt_block(algo: c_int, key: &[u8], block: &[u8]) -> Option<Vec<u8>> {
    match algo {
        GCRY_MAC_CMAC_AES | GCRY_MAC_GMAC_AES | GCRY_MAC_POLY1305_AES => {
            let input: &[u8; 16] = block.try_into().ok()?;
            Some(aes_encrypt_block(key, input)?.to_vec())
        }
        GCRY_MAC_CMAC_3DES => encrypt_block05::<TdesEde3>(key, block),
        GCRY_MAC_CMAC_CAMELLIA | GCRY_MAC_GMAC_CAMELLIA | GCRY_MAC_POLY1305_CAMELLIA => {
            encrypt_block05::<Camellia128>(key, block)
        }
        GCRY_MAC_CMAC_CAST5 => encrypt_block05::<Cast5>(key, block),
        GCRY_MAC_CMAC_BLOWFISH => encrypt_block05::<Blowfish>(key, block),
        GCRY_MAC_CMAC_TWOFISH | GCRY_MAC_GMAC_TWOFISH | GCRY_MAC_POLY1305_TWOFISH => {
            encrypt_block05::<Twofish>(key, block)
        }
        GCRY_MAC_CMAC_SERPENT | GCRY_MAC_GMAC_SERPENT | GCRY_MAC_POLY1305_SERPENT => {
            encrypt_block05::<Serpent>(key, block)
        }
        GCRY_MAC_CMAC_SEED | GCRY_MAC_GMAC_SEED | GCRY_MAC_POLY1305_SEED => {
            encrypt_block04::<SEED>(key, block)
        }
        GCRY_MAC_CMAC_RFC2268 => encrypt_block05::<Rc2>(key, block),
        GCRY_MAC_CMAC_IDEA => encrypt_block05::<Idea>(key, block),
        GCRY_MAC_CMAC_GOST28147 => encrypt_gost28147_test_sbox(key, block),
        GCRY_MAC_CMAC_SM4 => encrypt_block05::<Sm4>(key, block),
        _ => None,
    }
}

fn gmac_key_len(algo: c_int) -> usize {
    mac_keylen_metadata(algo)
}

fn valid_gmac_key(algo: c_int, key: &[u8]) -> bool {
    match algo {
        GCRY_MAC_GMAC_AES => matches!(key.len(), 16 | 24 | 32),
        GCRY_MAC_GMAC_CAMELLIA => key.len() == 16,
        GCRY_MAC_GMAC_TWOFISH => matches!(key.len(), 16 | 32),
        GCRY_MAC_GMAC_SERPENT | GCRY_MAC_GMAC_SEED => key.len() == 16,
        _ => false,
    }
}

fn valid_gmac_tag_len(taglen: usize) -> bool {
    matches!(taglen, 16 | 15 | 14 | 13 | 12 | 8 | 4)
}

fn gmac_compute(algo: c_int, key: &[u8], iv: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if !valid_gmac_key(algo, key) {
        return None;
    }
    let h_block = mac_encrypt_block(algo, key, &[0u8; 16])?;
    let h = u128::from_be_bytes(h_block.try_into().ok()?);
    let j0 = if iv.is_empty() {
        gmac_initial_counter(h, &[0u8; 16])
    } else {
        gmac_initial_counter(h, iv)
    };
    let s = ghash_with_lengths(h, aad, 0);
    let tag_mask = mac_encrypt_block(algo, key, &j0.to_be_bytes())?;
    let mask = u128::from_be_bytes(tag_mask.try_into().ok()?);
    Some((s ^ mask).to_be_bytes().to_vec())
}

fn gmac_initial_counter(h: u128, iv: &[u8]) -> u128 {
    if iv.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        u128::from_be_bytes(j0)
    } else {
        let mut y = ghash_blocks(h, 0, iv);
        let mut lengths = [0u8; 16];
        lengths[8..].copy_from_slice(&(iv.len() as u64 * 8).to_be_bytes());
        y = ghash_block(h, y, &lengths);
        y
    }
}

pub(crate) fn ghash_with_lengths(h: u128, aad: &[u8], ciphertext_bits: u64) -> u128 {
    let mut y = ghash_blocks(h, 0, aad);
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
    lengths[8..].copy_from_slice(&ciphertext_bits.to_be_bytes());
    y = ghash_block(h, y, &lengths);
    y
}

pub(crate) fn ghash_blocks(h: u128, mut y: u128, data: &[u8]) -> u128 {
    let mut chunks = data.chunks_exact(16);
    for chunk in &mut chunks {
        y = ghash_block(h, y, chunk);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut block = [0u8; 16];
        block[..rem.len()].copy_from_slice(rem);
        y = ghash_block(h, y, &block);
    }
    y
}

pub(crate) fn ghash_block(h: u128, y: u128, block: &[u8]) -> u128 {
    let mut padded = [0u8; 16];
    padded.copy_from_slice(block);
    gf128_mul(y ^ u128::from_be_bytes(padded), h)
}

pub(crate) fn gf128_mul(x: u128, mut y: u128) -> u128 {
    const R: u128 = 0xe1000000000000000000000000000000;
    let mut z = 0u128;
    for bit in 0..128 {
        if x & (1u128 << (127 - bit)) != 0 {
            z ^= y;
        }
        if y & 1 == 0 {
            y >>= 1;
        } else {
            y = (y >> 1) ^ R;
        }
    }
    z
}

fn encrypt_block05<C>(key: &[u8], block: &[u8]) -> Option<Vec<u8>>
where
    C: KeyInit05 + BlockCipherEncrypt,
{
    let cipher = C::new_from_slice(key).ok()?;
    let mut block = Block05::<C>::try_from(block).ok()?.clone();
    cipher.encrypt_block(&mut block);
    Some(block.as_slice().to_vec())
}

fn encrypt_block04<C>(key: &[u8], block: &[u8]) -> Option<Vec<u8>>
where
    C: KeyInit04 + BlockEncrypt04,
{
    let cipher = C::new_from_slice(key).ok()?;
    let mut block = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut block);
    Some(block.to_vec())
}

fn encrypt_gost28147_test_sbox(key: &[u8], block: &[u8]) -> Option<Vec<u8>> {
    let key: &[u8; 32] = key.try_into().ok()?;
    let cipher = Gost28147::with_sbox(key, &SBOX_TEST);
    let mut block = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut block);
    Some(block.to_vec())
}

const GOST28147_TEST_3411_SBOX: [[u8; 16]; 8] = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
];

const GOST28147_CRYPTOPRO_3411_SBOX: [[u8; 16]; 8] = [
    [10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15],
    [5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8],
    [7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13],
    [4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3],
    [7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5],
    [7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3],
    [13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11],
    [1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12],
];

const GOST28147_TEST_89_SBOX: [[u8; 16]; 8] = [
    [4, 2, 15, 5, 9, 1, 0, 8, 14, 3, 11, 12, 13, 7, 10, 6],
    [12, 9, 15, 14, 8, 1, 3, 10, 2, 7, 4, 13, 6, 0, 11, 5],
    [13, 8, 14, 12, 7, 3, 9, 10, 1, 5, 2, 4, 6, 15, 0, 11],
    [14, 9, 11, 2, 5, 15, 7, 1, 0, 13, 12, 6, 10, 4, 3, 8],
    [3, 14, 5, 9, 6, 8, 0, 13, 10, 11, 7, 12, 2, 1, 15, 4],
    [8, 15, 6, 11, 1, 9, 12, 5, 13, 3, 7, 10, 0, 14, 2, 4],
    [9, 11, 12, 0, 3, 6, 7, 5, 4, 8, 14, 15, 1, 10, 2, 13],
    [12, 6, 5, 2, 11, 0, 9, 13, 3, 14, 7, 10, 15, 4, 1, 8],
];

const GOST28147_CRYPTOPRO_A_SBOX: [[u8; 16]; 8] = [
    [9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5],
    [3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1],
    [14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9],
    [14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6],
    [11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6],
    [3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6],
    [1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14],
    [11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4],
];

const GOST28147_CRYPTOPRO_B_SBOX: [[u8; 16]; 8] = [
    [8, 4, 11, 1, 3, 5, 0, 9, 2, 14, 10, 12, 13, 6, 7, 15],
    [0, 1, 2, 10, 4, 13, 5, 12, 9, 7, 3, 15, 11, 8, 6, 14],
    [14, 12, 0, 10, 9, 2, 13, 11, 7, 5, 8, 15, 3, 6, 1, 4],
    [7, 5, 0, 13, 11, 6, 1, 2, 3, 10, 12, 15, 4, 14, 9, 8],
    [2, 7, 12, 15, 9, 5, 10, 11, 1, 4, 0, 13, 6, 8, 14, 3],
    [8, 3, 2, 6, 4, 13, 14, 11, 12, 1, 7, 15, 10, 0, 9, 5],
    [5, 2, 10, 11, 9, 1, 12, 3, 7, 4, 13, 0, 6, 15, 8, 14],
    [0, 4, 11, 14, 8, 3, 7, 1, 10, 2, 9, 6, 15, 13, 5, 12],
];

const GOST28147_CRYPTOPRO_C_SBOX: [[u8; 16]; 8] = [
    [1, 11, 12, 2, 9, 13, 0, 15, 4, 5, 8, 14, 10, 7, 6, 3],
    [0, 1, 7, 13, 11, 4, 5, 2, 8, 14, 15, 12, 9, 10, 6, 3],
    [8, 2, 5, 0, 4, 9, 15, 10, 3, 7, 12, 13, 6, 14, 1, 11],
    [3, 6, 0, 1, 5, 13, 10, 8, 11, 2, 9, 7, 14, 15, 12, 4],
    [8, 13, 11, 0, 4, 5, 1, 2, 9, 3, 12, 14, 6, 15, 10, 7],
    [12, 9, 11, 1, 8, 14, 2, 4, 7, 3, 6, 5, 10, 0, 15, 13],
    [10, 9, 6, 8, 13, 14, 2, 0, 15, 3, 5, 11, 4, 1, 12, 7],
    [7, 4, 0, 5, 10, 2, 15, 14, 12, 6, 1, 11, 13, 9, 3, 8],
];

const GOST28147_CRYPTOPRO_D_SBOX: [[u8; 16]; 8] = [
    [15, 12, 2, 10, 6, 4, 5, 0, 7, 9, 14, 13, 1, 11, 8, 3],
    [11, 6, 3, 4, 12, 15, 14, 2, 7, 13, 8, 0, 5, 10, 9, 1],
    [1, 12, 11, 0, 15, 14, 6, 5, 10, 13, 4, 8, 9, 3, 7, 2],
    [1, 5, 14, 12, 10, 7, 0, 13, 6, 2, 11, 4, 9, 3, 15, 8],
    [0, 12, 8, 9, 13, 2, 10, 11, 7, 3, 6, 5, 4, 14, 15, 1],
    [8, 0, 15, 3, 2, 5, 14, 11, 1, 10, 4, 7, 12, 9, 13, 6],
    [3, 0, 6, 15, 1, 14, 9, 2, 13, 8, 12, 4, 11, 10, 5, 7],
    [1, 10, 6, 8, 15, 11, 0, 4, 12, 3, 5, 9, 7, 13, 2, 14],
];

const GOST28147_TC26_Z_SBOX: [[u8; 16]; 8] = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

pub(crate) fn gost28147_default_cipher_sbox() -> &'static [[u8; 16]; 8] {
    &GOST28147_TEST_3411_SBOX
}

pub(crate) fn gost28147_sbox_info_from_oid(oid: &[u8]) -> Option<(&'static [[u8; 16]; 8], bool)> {
    match oid {
        b"1.2.643.2.2.30.0" => Some((&GOST28147_TEST_3411_SBOX, false)),
        b"1.2.643.2.2.30.1" => Some((&GOST28147_CRYPTOPRO_3411_SBOX, false)),
        b"1.2.643.2.2.31.0" => Some((&GOST28147_TEST_89_SBOX, false)),
        b"1.2.643.2.2.31.1" => Some((&GOST28147_CRYPTOPRO_A_SBOX, true)),
        b"1.2.643.2.2.31.2" => Some((&GOST28147_CRYPTOPRO_B_SBOX, true)),
        b"1.2.643.2.2.31.3" => Some((&GOST28147_CRYPTOPRO_C_SBOX, true)),
        b"1.2.643.2.2.31.4" => Some((&GOST28147_CRYPTOPRO_D_SBOX, true)),
        b"1.2.643.7.1.2.5.1.1" => Some((&GOST28147_TC26_Z_SBOX, true)),
        _ => None,
    }
}

pub(crate) fn gost28147_sbox_from_oid(oid: &[u8]) -> Option<&'static [[u8; 16]; 8]> {
    gost28147_sbox_info_from_oid(oid).map(|(sbox, _)| sbox)
}

fn gost28147_imit_compute(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    sbox: &'static [[u8; 16]; 8],
) -> Option<Vec<u8>> {
    if key.len() != 32 || !(iv.is_empty() || iv.len() == 8) {
        return None;
    }

    let mut subkeys = [0u32; 8];
    for (slot, chunk) in subkeys.iter_mut().zip(key.chunks_exact(4)) {
        *slot = u32::from_le_bytes(chunk.try_into().ok()?);
    }

    let mut n1 = 0u32;
    let mut n2 = 0u32;
    if !iv.is_empty() {
        n1 = u32::from_le_bytes(iv[..4].try_into().ok()?);
        n2 = u32::from_le_bytes(iv[4..8].try_into().ok()?);
    }

    let mut count = 0usize;
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        gost28147_imit_block(sbox, &subkeys, &mut n1, &mut n2, chunk.try_into().ok()?);
        count += 1;
    }

    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut block = [0u8; 8];
        block[..rem.len()].copy_from_slice(rem);
        gost28147_imit_block(sbox, &subkeys, &mut n1, &mut n2, &block);
        count += 1;
    }

    if count == 1 {
        gost28147_imit_block(sbox, &subkeys, &mut n1, &mut n2, &[0u8; 8]);
    }

    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&n1.to_le_bytes());
    out.extend_from_slice(&n2.to_le_bytes());
    Some(out)
}

fn gost28147_imit_block(
    sbox: &[[u8; 16]; 8],
    key: &[u32; 8],
    o1: &mut u32,
    o2: &mut u32,
    block: &[u8; 8],
) {
    let mut n1 = u32::from_le_bytes(block[..4].try_into().expect("valid GOST block"));
    let mut n2 = u32::from_le_bytes(block[4..].try_into().expect("valid GOST block"));
    n1 ^= *o1;
    n2 ^= *o2;

    for _ in 0..2 {
        n2 ^= gost28147_imit_val(sbox, key[0], n1);
        n1 ^= gost28147_imit_val(sbox, key[1], n2);
        n2 ^= gost28147_imit_val(sbox, key[2], n1);
        n1 ^= gost28147_imit_val(sbox, key[3], n2);
        n2 ^= gost28147_imit_val(sbox, key[4], n1);
        n1 ^= gost28147_imit_val(sbox, key[5], n2);
        n2 ^= gost28147_imit_val(sbox, key[6], n1);
        n1 ^= gost28147_imit_val(sbox, key[7], n2);
    }

    *o1 = n1;
    *o2 = n2;
}

fn gost28147_imit_val(sbox: &[[u8; 16]; 8], subkey: u32, input: u32) -> u32 {
    let x = input.wrapping_add(subkey);
    let mut y = 0u32;
    for i in 0..4 {
        let byte = ((x >> (8 * i)) & 0xff) as usize;
        let sbox_byte = sbox[2 * i][byte & 0x0f] | (sbox[2 * i + 1][byte >> 4] << 4);
        y |= u32::from(sbox_byte) << (8 * i);
    }
    y.rotate_left(11)
}

fn poly1305_cipher_key(algo: c_int, key: &[u8], iv: &[u8]) -> Option<[u8; 32]> {
    if iv.len() != 16 || key.len() <= 16 {
        return None;
    }
    let cipher_key_len = key.len() - 16;
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&key[cipher_key_len..]);
    out[16..].copy_from_slice(&mac_encrypt_block(algo, &key[..cipher_key_len], iv)?);
    Some(out)
}

fn load32_le(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("valid 32-bit lane"),
    )
}

fn poly1305_process_block(h: &mut [u64; 5], r: &[u64; 5], block: &[u8; 16], hibit: u64) {
    const MASK: u64 = (1 << 26) - 1;
    let t0 = load32_le(block, 0) as u64;
    let t1 = load32_le(block, 4) as u64;
    let t2 = load32_le(block, 8) as u64;
    let t3 = load32_le(block, 12) as u64;

    h[0] += t0 & MASK;
    h[1] += ((t0 >> 26) | (t1 << 6)) & MASK;
    h[2] += ((t1 >> 20) | (t2 << 12)) & MASK;
    h[3] += ((t2 >> 14) | (t3 << 18)) & MASK;
    h[4] += (t3 >> 8) | hibit;

    let s1 = r[1] * 5;
    let s2 = r[2] * 5;
    let s3 = r[3] * 5;
    let s4 = r[4] * 5;

    let d0 = h[0] as u128 * r[0] as u128
        + h[1] as u128 * s4 as u128
        + h[2] as u128 * s3 as u128
        + h[3] as u128 * s2 as u128
        + h[4] as u128 * s1 as u128;
    let mut d1 = h[0] as u128 * r[1] as u128
        + h[1] as u128 * r[0] as u128
        + h[2] as u128 * s4 as u128
        + h[3] as u128 * s3 as u128
        + h[4] as u128 * s2 as u128;
    let mut d2 = h[0] as u128 * r[2] as u128
        + h[1] as u128 * r[1] as u128
        + h[2] as u128 * r[0] as u128
        + h[3] as u128 * s4 as u128
        + h[4] as u128 * s3 as u128;
    let mut d3 = h[0] as u128 * r[3] as u128
        + h[1] as u128 * r[2] as u128
        + h[2] as u128 * r[1] as u128
        + h[3] as u128 * r[0] as u128
        + h[4] as u128 * s4 as u128;
    let mut d4 = h[0] as u128 * r[4] as u128
        + h[1] as u128 * r[3] as u128
        + h[2] as u128 * r[2] as u128
        + h[3] as u128 * r[1] as u128
        + h[4] as u128 * r[0] as u128;

    let mut c = (d0 >> 26) as u64;
    h[0] = (d0 as u64) & MASK;
    d1 += c as u128;
    c = (d1 >> 26) as u64;
    h[1] = (d1 as u64) & MASK;
    d2 += c as u128;
    c = (d2 >> 26) as u64;
    h[2] = (d2 as u64) & MASK;
    d3 += c as u128;
    c = (d3 >> 26) as u64;
    h[3] = (d3 as u64) & MASK;
    d4 += c as u128;
    c = (d4 >> 26) as u64;
    h[4] = (d4 as u64) & MASK;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= MASK;
    h[1] += c;
}

fn poly1305_lower_byte(h: &[u64; 5], byte_index: usize) -> u8 {
    let bit = byte_index * 8;
    let limb = bit / 26;
    let shift = bit % 26;
    let mut value = h[limb] >> shift;
    if shift > 18 && limb + 1 < h.len() {
        value |= h[limb + 1] << (26 - shift);
    }
    (value & 0xff) as u8
}

pub(crate) fn poly1305_mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    const MASK: u64 = (1 << 26) - 1;
    let t0 = load32_le(key, 0) as u64;
    let t1 = load32_le(key, 4) as u64;
    let t2 = load32_le(key, 8) as u64;
    let t3 = load32_le(key, 12) as u64;
    let r = [
        t0 & MASK,
        ((t0 >> 26) | (t1 << 6)) & 0x3ffff03,
        ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff,
        ((t2 >> 14) | (t3 << 18)) & 0x3f03fff,
        (t3 >> 8) & 0x00fffff,
    ];
    let mut h = [0u64; 5];
    let mut chunks = data.chunks_exact(16);
    for chunk in &mut chunks {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        poly1305_process_block(&mut h, &r, &block, 1 << 24);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut block = [0u8; 16];
        block[..rem.len()].copy_from_slice(rem);
        block[rem.len()] = 1;
        poly1305_process_block(&mut h, &r, &block, 0);
    }

    let mut c = h[1] >> 26;
    h[1] &= MASK;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= MASK;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= MASK;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= MASK;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= MASK;
    h[1] += c;

    let mut g = [0u64; 5];
    g[0] = h[0] + 5;
    c = g[0] >> 26;
    g[0] &= MASK;
    g[1] = h[1] + c;
    c = g[1] >> 26;
    g[1] &= MASK;
    g[2] = h[2] + c;
    c = g[2] >> 26;
    g[2] &= MASK;
    g[3] = h[3] + c;
    c = g[3] >> 26;
    g[3] &= MASK;
    let g4 = h[4] as i64 + c as i64 - (1i64 << 26);
    if g4 >= 0 {
        g[4] = g4 as u64;
        h = g;
    }

    let mut tag = [0u8; 16];
    let mut carry = 0u16;
    for i in 0..16 {
        let sum = poly1305_lower_byte(&h, i) as u16 + key[16 + i] as u16 + carry;
        tag[i] = sum as u8;
        carry = sum >> 8;
    }
    tag
}

pub(crate) struct AesKey {
    nr: usize,
    words: [u32; 60],
}

impl AesKey {
    pub(crate) fn new(key: &[u8]) -> Option<Self> {
        let nk = match key.len() {
            16 => 4,
            24 => 6,
            32 => 8,
            _ => return None,
        };
        let nr = nk + 6;
        Some(Self {
            nr,
            words: aes_expand_key(key, nk, nr),
        })
    }

    pub(crate) fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut state = *input;
        aes_add_round_key(&mut state, &self.words, 0);
        for round in 1..self.nr {
            aes_sub_bytes(&mut state);
            aes_shift_rows(&mut state);
            aes_mix_columns(&mut state);
            aes_add_round_key(&mut state, &self.words, round);
        }
        aes_sub_bytes(&mut state);
        aes_shift_rows(&mut state);
        aes_add_round_key(&mut state, &self.words, self.nr);
        state
    }

    pub(crate) fn decrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut state = *input;
        aes_add_round_key(&mut state, &self.words, self.nr);
        for round in (1..self.nr).rev() {
            aes_inv_shift_rows(&mut state);
            aes_inv_sub_bytes(&mut state);
            aes_add_round_key(&mut state, &self.words, round);
            aes_inv_mix_columns(&mut state);
        }
        aes_inv_shift_rows(&mut state);
        aes_inv_sub_bytes(&mut state);
        aes_add_round_key(&mut state, &self.words, 0);
        state
    }
}

pub(crate) fn aes_encrypt_block(key: &[u8], input: &[u8; 16]) -> Option<[u8; 16]> {
    Some(AesKey::new(key)?.encrypt_block(input))
}

pub(crate) fn aes_decrypt_block(key: &[u8], input: &[u8; 16]) -> Option<[u8; 16]> {
    Some(AesKey::new(key)?.decrypt_block(input))
}

fn aes_expand_key(key: &[u8], nk: usize, nr: usize) -> [u32; 60] {
    let total_words = 4 * (nr + 1);
    let mut words = [0u32; 60];
    for i in 0..nk {
        words[i] = u32::from_be_bytes(key[i * 4..i * 4 + 4].try_into().expect("AES key word"));
    }
    for i in nk..total_words {
        let mut temp = words[i - 1];
        if i % nk == 0 {
            temp = aes_sub_word(temp.rotate_left(8)) ^ ((AES_RCON[i / nk] as u32) << 24);
        } else if nk > 6 && i % nk == 4 {
            temp = aes_sub_word(temp);
        }
        words[i] = words[i - nk] ^ temp;
    }
    words
}

fn aes_sub_word(word: u32) -> u32 {
    let mut block = [0u8; 16];
    block[..4].copy_from_slice(&word.to_be_bytes());
    aes_sbox_bytes(&mut block);
    u32::from_be_bytes(block[..4].try_into().expect("AES key word"))
}

fn aes_add_round_key(state: &mut [u8; 16], words: &[u32], round: usize) {
    for column in 0..4 {
        let word = words[round * 4 + column].to_be_bytes();
        for row in 0..4 {
            state[column * 4 + row] ^= word[row];
        }
    }
}

fn aes_sub_bytes(state: &mut [u8; 16]) {
    aes_sbox_bytes(state);
}

fn aes_inv_sub_bytes(state: &mut [u8; 16]) {
    aes_inv_sbox_bytes(state);
}

fn aes_shift_rows(state: &mut [u8; 16]) {
    let old = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[column * 4 + row] = old[((column + row) % 4) * 4 + row];
        }
    }
}

fn aes_inv_shift_rows(state: &mut [u8; 16]) {
    let old = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[column * 4 + row] = old[((column + 4 - row) % 4) * 4 + row];
        }
    }
}

fn aes_xtime(value: u8) -> u8 {
    (value << 1) ^ (0x1b & 0u8.wrapping_sub(value >> 7))
}

fn aes_mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let offset = column * 4;
        let a0 = state[offset];
        let a1 = state[offset + 1];
        let a2 = state[offset + 2];
        let a3 = state[offset + 3];
        let t = a0 ^ a1 ^ a2 ^ a3;
        let u = a0;
        state[offset] ^= t ^ aes_xtime(a0 ^ a1);
        state[offset + 1] ^= t ^ aes_xtime(a1 ^ a2);
        state[offset + 2] ^= t ^ aes_xtime(a2 ^ a3);
        state[offset + 3] ^= t ^ aes_xtime(a3 ^ u);
    }
}

fn aes_inv_mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let o = column * 4;
        let a0 = state[o];
        let a1 = state[o + 1];
        let a2 = state[o + 2];
        let a3 = state[o + 3];
        state[o] = aes_gf_mul(a0, 14) ^ aes_gf_mul(a1, 11) ^ aes_gf_mul(a2, 13) ^ aes_gf_mul(a3, 9);
        state[o + 1] =
            aes_gf_mul(a0, 9) ^ aes_gf_mul(a1, 14) ^ aes_gf_mul(a2, 11) ^ aes_gf_mul(a3, 13);
        state[o + 2] =
            aes_gf_mul(a0, 13) ^ aes_gf_mul(a1, 9) ^ aes_gf_mul(a2, 14) ^ aes_gf_mul(a3, 11);
        state[o + 3] =
            aes_gf_mul(a0, 11) ^ aes_gf_mul(a1, 13) ^ aes_gf_mul(a2, 9) ^ aes_gf_mul(a3, 14);
    }
}

// Evaluate the AES S-box as bit-sliced field arithmetic over all 16 state
// bytes, avoiding secret-indexed lookup tables in the software AES path.
fn aes_sbox_bytes(bytes: &mut [u8; 16]) {
    let bits = aes_bitslice(bytes);
    aes_unbitslice(aes_sbox_bits(bits), bytes);
}

fn aes_inv_sbox_bytes(bytes: &mut [u8; 16]) {
    let bits = aes_bitslice(bytes);
    aes_unbitslice(aes_inv_sbox_bits(bits), bytes);
}

fn aes_bitslice(bytes: &[u8; 16]) -> [u16; 8] {
    let mut bits = [0u16; 8];
    for (lane, byte) in bytes.iter().copied().enumerate() {
        for bit in 0..8 {
            bits[bit] |= (((byte >> bit) & 1) as u16) << lane;
        }
    }
    bits
}

fn aes_unbitslice(bits: [u16; 8], bytes: &mut [u8; 16]) {
    for (lane, byte) in bytes.iter_mut().enumerate() {
        let mut value = 0u8;
        for bit in 0..8 {
            value |= (((bits[bit] >> lane) & 1) as u8) << bit;
        }
        *byte = value;
    }
}

fn aes_sbox_bits(bits: [u16; 8]) -> [u16; 8] {
    let inv = aes_gf_inv_bits(bits);
    let mut out = [0u16; 8];
    for bit in 0..8 {
        out[bit] = inv[bit]
            ^ inv[(bit + 7) & 7]
            ^ inv[(bit + 6) & 7]
            ^ inv[(bit + 5) & 7]
            ^ inv[(bit + 4) & 7];
        if (0x63 >> bit) & 1 != 0 {
            out[bit] ^= u16::MAX;
        }
    }
    out
}

fn aes_inv_sbox_bits(bits: [u16; 8]) -> [u16; 8] {
    let mut affine = [0u16; 8];
    for bit in 0..8 {
        affine[bit] = bits[(bit + 7) & 7] ^ bits[(bit + 5) & 7] ^ bits[(bit + 2) & 7];
        if (0x05 >> bit) & 1 != 0 {
            affine[bit] ^= u16::MAX;
        }
    }
    aes_gf_inv_bits(affine)
}

fn aes_gf_inv_bits(bits: [u16; 8]) -> [u16; 8] {
    let mut result = [0u16; 8];
    result[0] = u16::MAX;
    let mut base = bits;
    let mut exp = 254u16;
    for _ in 0..8 {
        let product = aes_gf_mul_bits(result, base);
        if exp & 1 != 0 {
            result = product;
        }
        base = aes_gf_mul_bits(base, base);
        exp >>= 1;
    }
    result
}

fn aes_gf_mul_bits(a: [u16; 8], b: [u16; 8]) -> [u16; 8] {
    let mut product = [0u16; 15];
    for i in 0..8 {
        for j in 0..8 {
            product[i + j] ^= a[i] & b[j];
        }
    }
    for degree in (8..15).rev() {
        let carry = product[degree];
        product[degree - 4] ^= carry;
        product[degree - 5] ^= carry;
        product[degree - 7] ^= carry;
        product[degree - 8] ^= carry;
    }
    product[..8].try_into().expect("AES field product")
}

fn aes_gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        product ^= a & 0u8.wrapping_sub(b & 1);
        a = (a << 1) ^ (0x1b & 0u8.wrapping_sub(a >> 7));
        b >>= 1;
    }
    product
}

const AES_RCON: [u8; 15] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
];
