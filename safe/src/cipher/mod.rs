mod aead;
mod block;
mod modes;
mod registry;
mod stream;

use std::ffi::{c_char, c_int, c_uint, c_void};

pub type gcry_cipher_hd_t = *mut gcry_cipher_handle;

#[repr(C)]
pub struct gcry_cipher_handle {
    _private: [u8; 0],
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_open(
    handle: *mut gcry_cipher_hd_t,
    algo: c_int,
    mode: c_int,
    flags: c_uint,
) -> u32 {
    modes::open(handle, algo, mode, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_close(handle: gcry_cipher_hd_t) {
    modes::close(handle)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_ctl(
    handle: gcry_cipher_hd_t,
    cmd: c_int,
    buffer: *mut c_void,
    buflen: usize,
) -> u32 {
    modes::ctl(handle, cmd, buffer, buflen)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_info(
    handle: gcry_cipher_hd_t,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    modes::info(handle, what, buffer, nbytes)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_algo_info(
    algo: c_int,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    registry::algo_info(algo, what, buffer, nbytes)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_algo_name(algorithm: c_int) -> *const c_char {
    registry::algo_name(algorithm)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_map_name(name: *const c_char) -> c_int {
    registry::map_name(name)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_mode_from_oid(string: *const c_char) -> c_int {
    modes::mode_from_oid(string)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_encrypt(
    handle: gcry_cipher_hd_t,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> u32 {
    block::encrypt(handle, out, outsize, input, inlen)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_decrypt(
    handle: gcry_cipher_hd_t,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> u32 {
    block::decrypt(handle, out, outsize, input, inlen)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_setkey(
    handle: gcry_cipher_hd_t,
    key: *const c_void,
    keylen: usize,
) -> u32 {
    block::setkey(handle, key, keylen)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_setiv(
    handle: gcry_cipher_hd_t,
    iv: *const c_void,
    ivlen: usize,
) -> u32 {
    block::setiv(handle, iv, ivlen)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_setctr(
    handle: gcry_cipher_hd_t,
    ctr: *const c_void,
    ctrlen: usize,
) -> u32 {
    block::setctr(handle, ctr, ctrlen)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_authenticate(
    handle: gcry_cipher_hd_t,
    abuf: *const c_void,
    abuflen: usize,
) -> u32 {
    aead::authenticate(handle, abuf, abuflen)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_gettag(
    handle: gcry_cipher_hd_t,
    outtag: *mut c_void,
    taglen: usize,
) -> u32 {
    aead::gettag(handle, outtag, taglen)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_checktag(
    handle: gcry_cipher_hd_t,
    intag: *const c_void,
    taglen: usize,
) -> u32 {
    aead::checktag(handle, intag, taglen)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_get_algo_keylen(algo: c_int) -> usize {
    registry::get_algo_keylen(algo)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_cipher_get_algo_blklen(algo: c_int) -> usize {
    registry::get_algo_blklen(algo)
}
