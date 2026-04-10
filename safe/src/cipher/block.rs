use std::ffi::c_void;

use super::gcry_cipher_hd_t;
use super::modes;
use super::registry::{
    GCRY_CIPHER_MODE_AESWRAP, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_MODE_CFB8,
    GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_MODE_NONE, GCRY_CIPHER_MODE_OFB,
    GCRY_CIPHER_MODE_XTS,
};

pub(crate) fn encrypt(
    handle: gcry_cipher_hd_t,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> u32 {
    modes::crypt(handle, out, outsize, input, inlen, true)
}

pub(crate) fn decrypt(
    handle: gcry_cipher_hd_t,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> u32 {
    modes::crypt(handle, out, outsize, input, inlen, false)
}

pub(crate) fn setkey(handle: gcry_cipher_hd_t, key: *const c_void, keylen: usize) -> u32 {
    modes::setkey(handle, key, keylen)
}

pub(crate) fn setiv(handle: gcry_cipher_hd_t, iv: *const c_void, ivlen: usize) -> u32 {
    modes::setiv(handle, iv, ivlen)
}

pub(crate) fn setctr(handle: gcry_cipher_hd_t, ctr: *const c_void, ctrlen: usize) -> u32 {
    modes::setctr(handle, ctr, ctrlen)
}

pub(crate) fn is_block_mode(mode: i32) -> bool {
    matches!(
        mode,
        GCRY_CIPHER_MODE_NONE
            | GCRY_CIPHER_MODE_ECB
            | GCRY_CIPHER_MODE_CFB
            | GCRY_CIPHER_MODE_CBC
            | GCRY_CIPHER_MODE_OFB
            | GCRY_CIPHER_MODE_CTR
            | GCRY_CIPHER_MODE_AESWRAP
            | GCRY_CIPHER_MODE_CFB8
            | GCRY_CIPHER_MODE_XTS
    )
}
