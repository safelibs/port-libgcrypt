use std::ffi::c_void;

use super::gcry_cipher_hd_t;
use crate::upstream;

pub(crate) fn encrypt(
    handle: gcry_cipher_hd_t,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> u32 {
    unsafe { (upstream::lib().cipher_encrypt)(handle.cast(), out, outsize, input, inlen) }
}

pub(crate) fn decrypt(
    handle: gcry_cipher_hd_t,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> u32 {
    unsafe { (upstream::lib().cipher_decrypt)(handle.cast(), out, outsize, input, inlen) }
}

pub(crate) fn setkey(handle: gcry_cipher_hd_t, key: *const c_void, keylen: usize) -> u32 {
    unsafe { (upstream::lib().cipher_setkey)(handle.cast(), key, keylen) }
}

pub(crate) fn setiv(handle: gcry_cipher_hd_t, iv: *const c_void, ivlen: usize) -> u32 {
    unsafe { (upstream::lib().cipher_setiv)(handle.cast(), iv, ivlen) }
}

pub(crate) fn setctr(handle: gcry_cipher_hd_t, ctr: *const c_void, ctrlen: usize) -> u32 {
    unsafe { (upstream::lib().cipher_setctr)(handle.cast(), ctr, ctrlen) }
}

pub(crate) fn is_block_mode(mode: i32) -> bool {
    matches!(mode, 1 | 2 | 3 | 5 | 6 | 7 | 12 | 13)
}
