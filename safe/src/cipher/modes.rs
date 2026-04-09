use std::ffi::{c_int, c_uint, c_void};

use super::aead;
use super::block;
use super::gcry_cipher_hd_t;
use super::stream;
use crate::upstream;

pub(crate) fn open(
    handle: *mut gcry_cipher_hd_t,
    algo: c_int,
    mode: c_int,
    flags: c_uint,
) -> u32 {
    debug_assert!(
        aead::is_aead_mode(mode) || block::is_block_mode(mode) || stream::is_stream_mode(mode)
    );
    unsafe { (upstream::lib().cipher_open)(handle.cast(), algo, mode, flags) }
}

pub(crate) fn close(handle: gcry_cipher_hd_t) {
    unsafe { (upstream::lib().cipher_close)(handle.cast()) }
}

pub(crate) fn ctl(handle: gcry_cipher_hd_t, cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
    unsafe { (upstream::lib().cipher_ctl)(handle.cast(), cmd, buffer, buflen) }
}

pub(crate) fn info(
    handle: gcry_cipher_hd_t,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    unsafe { (upstream::lib().cipher_info)(handle.cast(), what, buffer, nbytes) }
}

pub(crate) fn mode_from_oid(string: *const i8) -> c_int {
    unsafe { (upstream::lib().cipher_mode_from_oid)(string) }
}
