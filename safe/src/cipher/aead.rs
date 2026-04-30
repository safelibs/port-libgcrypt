use std::ffi::c_void;

use super::gcry_cipher_hd_t;
use crate::error;

pub(crate) fn authenticate(handle: gcry_cipher_hd_t, abuf: *const c_void, abuflen: usize) -> u32 {
    let ctx = match super::ctx(handle) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    if !ctx.supports_authenticate() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_CIPHER_MODE);
    }
    let data = if abuf.is_null() {
        if abuflen != 0 {
            return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
        }
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(abuf.cast::<u8>(), abuflen) }
    };
    ctx.authenticate(data)
}

pub(crate) fn gettag(handle: gcry_cipher_hd_t, outtag: *mut c_void, taglen: usize) -> u32 {
    if outtag.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let out = unsafe { std::slice::from_raw_parts_mut(outtag.cast::<u8>(), taglen) };
    let ctx = match super::ctx(handle) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    ctx.gettag(out)
}

pub(crate) fn checktag(handle: gcry_cipher_hd_t, intag: *const c_void, taglen: usize) -> u32 {
    if intag.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let tag = unsafe { std::slice::from_raw_parts(intag.cast::<u8>(), taglen) };
    let ctx = match super::ctx(handle) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    ctx.checktag(tag)
}

pub(crate) fn is_aead_mode(mode: i32) -> bool {
    matches!(mode, 8 | 9 | 10 | 11 | 14 | 15 | 16)
}
