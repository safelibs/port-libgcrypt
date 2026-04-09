use std::ffi::{c_char, c_int, c_uint, c_void};

use crate::upstream;

pub type gcry_mac_hd_t = *mut gcry_mac_handle;

#[repr(C)]
pub struct gcry_mac_handle {
    _private: [u8; 0],
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_open(
    handle: *mut gcry_mac_hd_t,
    algo: c_int,
    flags: c_uint,
    ctx: *mut c_void,
) -> u32 {
    unsafe { (upstream::lib().mac_open)(handle.cast(), algo, flags, ctx) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_close(handle: gcry_mac_hd_t) {
    unsafe { (upstream::lib().mac_close)(handle.cast()) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_ctl(
    handle: gcry_mac_hd_t,
    cmd: c_int,
    buffer: *mut c_void,
    buflen: usize,
) -> u32 {
    unsafe { (upstream::lib().mac_ctl)(handle.cast(), cmd, buffer, buflen) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_algo_info(
    algo: c_int,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    unsafe { (upstream::lib().mac_algo_info)(algo, what, buffer, nbytes) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_setkey(handle: gcry_mac_hd_t, key: *const c_void, keylen: usize) -> u32 {
    unsafe { (upstream::lib().mac_setkey)(handle.cast(), key, keylen) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_setiv(handle: gcry_mac_hd_t, iv: *const c_void, ivlen: usize) -> u32 {
    unsafe { (upstream::lib().mac_setiv)(handle.cast(), iv, ivlen) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_write(
    handle: gcry_mac_hd_t,
    buffer: *const c_void,
    length: usize,
) -> u32 {
    unsafe { (upstream::lib().mac_write)(handle.cast(), buffer, length) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_read(
    handle: gcry_mac_hd_t,
    buffer: *mut c_void,
    buflen: *mut usize,
) -> u32 {
    unsafe { (upstream::lib().mac_read)(handle.cast(), buffer, buflen) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_verify(
    handle: gcry_mac_hd_t,
    buffer: *const c_void,
    buflen: usize,
) -> u32 {
    unsafe { (upstream::lib().mac_verify)(handle.cast(), buffer, buflen) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_get_algo(handle: gcry_mac_hd_t) -> c_int {
    unsafe { (upstream::lib().mac_get_algo)(handle.cast()) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_get_algo_maclen(algo: c_int) -> c_uint {
    unsafe { (upstream::lib().mac_get_algo_maclen)(algo) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_get_algo_keylen(algo: c_int) -> c_uint {
    unsafe { (upstream::lib().mac_get_algo_keylen)(algo) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_algo_name(algo: c_int) -> *const c_char {
    unsafe { (upstream::lib().mac_algo_name)(algo) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mac_map_name(name: *const c_char) -> c_int {
    unsafe { (upstream::lib().mac_map_name)(name) }
}
