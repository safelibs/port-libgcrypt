use std::ffi::c_void;

use super::gcry_cipher_hd_t;
use crate::error;

const GPG_ERR_MISSING_KEY: u32 = 181;

fn input_bytes(
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> Result<Vec<u8>, u32> {
    if out.is_null() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
    }
    if input.is_null() {
        Ok(unsafe { std::slice::from_raw_parts(out.cast::<u8>(), outsize) }.to_vec())
    } else {
        Ok(unsafe { std::slice::from_raw_parts(input.cast::<u8>(), inlen) }.to_vec())
    }
}

fn write_output(out: *mut c_void, outsize: usize, data: &[u8]) -> u32 {
    if out.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if outsize < data.len() {
        return error::gcry_error_from_code(error::GPG_ERR_BUFFER_TOO_SHORT);
    }
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), out.cast::<u8>(), data.len());
    }
    0
}

pub(crate) fn encrypt(
    handle: gcry_cipher_hd_t,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> u32 {
    let ctx = match super::ctx(handle) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    if !ctx.has_key() {
        return error::gcry_error_from_code(GPG_ERR_MISSING_KEY);
    }
    let input = match input_bytes(out, outsize, input, inlen) {
        Ok(input) => input,
        Err(rc) => return rc,
    };
    match ctx.encrypt(&input) {
        Ok(result) => write_output(out, outsize, &result),
        Err(rc) => rc,
    }
}

pub(crate) fn decrypt(
    handle: gcry_cipher_hd_t,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> u32 {
    let ctx = match super::ctx(handle) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    if !ctx.has_key() {
        return error::gcry_error_from_code(GPG_ERR_MISSING_KEY);
    }
    let input = match input_bytes(out, outsize, input, inlen) {
        Ok(input) => input,
        Err(rc) => return rc,
    };
    match ctx.decrypt(&input) {
        Ok(result) => write_output(out, outsize, &result),
        Err(rc) => rc,
    }
}

pub(crate) fn setkey(handle: gcry_cipher_hd_t, key: *const c_void, keylen: usize) -> u32 {
    if key.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let key = unsafe { std::slice::from_raw_parts(key.cast::<u8>(), keylen) };
    let ctx = match super::ctx(handle) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    ctx.setkey(key)
}

pub(crate) fn setiv(handle: gcry_cipher_hd_t, iv: *const c_void, ivlen: usize) -> u32 {
    let iv = if iv.is_null() {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(iv.cast::<u8>(), ivlen) }
    };
    let ctx = match super::ctx(handle) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    ctx.setiv(iv)
}

pub(crate) fn setctr(handle: gcry_cipher_hd_t, ctr: *const c_void, ctrlen: usize) -> u32 {
    let ctr = if ctr.is_null() {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(ctr.cast::<u8>(), ctrlen) }
    };
    let ctx = match super::ctx(handle) {
        Ok(ctx) => ctx,
        Err(rc) => return rc,
    };
    ctx.setctr(ctr)
}

pub(crate) fn is_block_mode(mode: i32) -> bool {
    matches!(mode, 1 | 2 | 3 | 5 | 6 | 7 | 12 | 13)
}
