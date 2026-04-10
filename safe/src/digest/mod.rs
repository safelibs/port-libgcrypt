mod algorithms;

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::ptr::copy_nonoverlapping;

use crate::error;
use crate::upstream::{self, gcry_buffer_t};

pub type gcry_md_hd_t = *mut gcry_md_handle;

#[repr(C)]
pub struct gcry_md_handle {
    pub ctx: *mut c_void,
    pub bufpos: c_int,
    pub bufsize: c_int,
    pub buf: [u8; 1],
}

#[no_mangle]
pub extern "C" fn gcry_md_open(h: *mut gcry_md_hd_t, algo: c_int, flags: c_uint) -> u32 {
    unsafe { (upstream::lib().md_open)(h.cast(), algo, flags) }
}

#[no_mangle]
pub extern "C" fn gcry_md_close(hd: gcry_md_hd_t) {
    unsafe { (upstream::lib().md_close)(hd.cast()) }
}

#[no_mangle]
pub extern "C" fn gcry_md_enable(hd: gcry_md_hd_t, algo: c_int) -> u32 {
    unsafe { (upstream::lib().md_enable)(hd.cast(), algo) }
}

#[no_mangle]
pub extern "C" fn gcry_md_copy(dest: *mut gcry_md_hd_t, src: gcry_md_hd_t) -> u32 {
    unsafe { (upstream::lib().md_copy)(dest.cast(), src.cast()) }
}

#[no_mangle]
pub extern "C" fn gcry_md_reset(hd: gcry_md_hd_t) {
    unsafe { (upstream::lib().md_reset)(hd.cast()) }
}

#[no_mangle]
pub extern "C" fn gcry_md_ctl(
    hd: gcry_md_hd_t,
    cmd: c_int,
    buffer: *mut c_void,
    buflen: usize,
) -> u32 {
    unsafe { (upstream::lib().md_ctl)(hd.cast(), cmd, buffer, buflen) }
}

#[no_mangle]
pub extern "C" fn gcry_md_write(hd: gcry_md_hd_t, buffer: *const c_void, length: usize) {
    unsafe { (upstream::lib().md_write)(hd.cast(), buffer, length) }
}

#[no_mangle]
pub extern "C" fn gcry_md_read(hd: gcry_md_hd_t, algo: c_int) -> *mut u8 {
    unsafe { (upstream::lib().md_read)(hd.cast(), algo) }
}

#[no_mangle]
pub extern "C" fn gcry_md_extract(
    hd: gcry_md_hd_t,
    algo: c_int,
    buffer: *mut c_void,
    length: usize,
) -> u32 {
    unsafe { (upstream::lib().md_extract)(hd.cast(), algo, buffer, length) }
}

#[no_mangle]
pub extern "C" fn gcry_md_hash_buffer(
    algo: c_int,
    digest: *mut c_void,
    buffer: *const c_void,
    length: usize,
) {
    unsafe { (upstream::lib().md_hash_buffer)(algo, digest, buffer, length) }
}

#[no_mangle]
pub extern "C" fn gcry_md_hash_buffers(
    algo: c_int,
    flags: c_uint,
    digest: *mut c_void,
    iov: *const gcry_buffer_t,
    iovcnt: c_int,
) -> u32 {
    unsafe { (upstream::lib().md_hash_buffers)(algo, flags, digest, iov, iovcnt) }
}

#[no_mangle]
pub extern "C" fn gcry_md_get_algo(hd: gcry_md_hd_t) -> c_int {
    unsafe { (upstream::lib().md_get_algo)(hd.cast()) }
}

#[no_mangle]
pub extern "C" fn gcry_md_get_algo_dlen(algo: c_int) -> c_uint {
    unsafe { (upstream::lib().md_get_algo_dlen)(algo) }
}

#[no_mangle]
pub extern "C" fn gcry_md_is_enabled(hd: gcry_md_hd_t, algo: c_int) -> c_int {
    unsafe { (upstream::lib().md_is_enabled)(hd.cast(), algo) }
}

#[no_mangle]
pub extern "C" fn gcry_md_is_secure(hd: gcry_md_hd_t) -> c_int {
    unsafe { (upstream::lib().md_is_secure)(hd.cast()) }
}

#[no_mangle]
pub extern "C" fn gcry_md_info(
    hd: gcry_md_hd_t,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    unsafe { (upstream::lib().md_info)(hd.cast(), what, buffer, nbytes) }
}

#[no_mangle]
pub extern "C" fn gcry_md_algo_info(
    algo: c_int,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    unsafe { (upstream::lib().md_algo_info)(algo, what, buffer, nbytes) }
}

#[no_mangle]
pub extern "C" fn gcry_md_algo_name(algo: c_int) -> *const c_char {
    unsafe { (upstream::lib().md_algo_name)(algo) }
}

#[no_mangle]
pub extern "C" fn gcry_md_map_name(name: *const c_char) -> c_int {
    unsafe { (upstream::lib().md_map_name)(name) }
}

#[no_mangle]
pub extern "C" fn gcry_md_setkey(hd: gcry_md_hd_t, key: *const c_void, keylen: usize) -> u32 {
    unsafe { (upstream::lib().md_setkey)(hd.cast(), key, keylen) }
}

#[no_mangle]
pub extern "C" fn gcry_md_debug(hd: gcry_md_hd_t, suffix: *const c_char) {
    unsafe { (upstream::lib().md_debug)(hd.cast(), suffix) }
}

#[export_name = "safe_gcry_md_get"]
pub extern "C" fn safe_gcry_md_get(
    hd: gcry_md_hd_t,
    algo: c_int,
    buffer: *mut u8,
    buflen: c_int,
) -> u32 {
    if hd.is_null() || buffer.is_null() || buflen < 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    if crate::global::lock_runtime_state().fips_mode {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    }

    let Some(algo) = algorithms::resolve_read_algo(hd, algo) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };

    if algorithms::is_xof(algo) {
        return unsafe {
            (upstream::lib().md_extract)(hd.cast(), algo, buffer.cast(), buflen as usize)
        };
    }

    let digest_len = gcry_md_get_algo_dlen(algo) as usize;
    if digest_len == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if (buflen as usize) < digest_len {
        return error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT);
    }

    let digest = gcry_md_read(hd, algo);
    if digest.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    unsafe {
        copy_nonoverlapping(digest, buffer, digest_len);
    }
    0
}
