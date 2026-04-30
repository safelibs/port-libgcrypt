use std::ffi::{c_int, c_uint, c_void};

use super::aead;
use super::block;
use super::gcry_cipher_hd_t;
use super::local::CipherContext;
use super::registry;
use super::stream;
use crate::error;

pub(crate) fn open(handle: *mut gcry_cipher_hd_t, algo: c_int, mode: c_int, flags: c_uint) -> u32 {
    debug_assert!(
        aead::is_aead_mode(mode) || block::is_block_mode(mode) || stream::is_stream_mode(mode)
    );
    if handle.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    unsafe {
        *handle = std::ptr::null_mut();
    }

    let ctx = match CipherContext::open(algo, mode, flags) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    let local = match super::make_handle(ctx) {
        Ok(local) => local,
        Err(rc) => return rc,
    };
    unsafe {
        *handle = local;
    }
    0
}

pub(crate) fn close(handle: gcry_cipher_hd_t) {
    super::drop_handle(handle);
}

pub(crate) fn ctl(handle: gcry_cipher_hd_t, cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
    let ctx = match super::ctx(handle) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    ctx.ctl(cmd, buffer, buflen)
}

pub(crate) fn info(
    handle: gcry_cipher_hd_t,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    let ctx = match super::ctx(handle) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    ctx.info(what, buffer, nbytes)
}

pub(crate) fn mode_from_oid(string: *const i8) -> c_int {
    registry::mode_from_oid(string)
}
