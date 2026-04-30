mod aead;
mod block;
mod local;
mod modes;
mod registry;
mod stream;

use std::ffi::{c_char, c_int, c_uint, c_void};

use crate::alloc;
use crate::context;
use crate::error;

pub type gcry_cipher_hd_t = *mut gcry_cipher_handle;

#[repr(C)]
pub struct gcry_cipher_handle {
    secure: bool,
    ctx: local::CipherContext,
}

impl gcry_cipher_handle {
    pub(crate) fn new(ctx: local::CipherContext) -> Self {
        Self {
            secure: ctx.is_secure(),
            ctx,
        }
    }
}

pub(crate) fn ctx(handle: gcry_cipher_hd_t) -> Result<&'static mut local::CipherContext, u32> {
    if handle.is_null() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
    }
    Ok(unsafe { &mut (*handle).ctx })
}

pub(crate) fn make_handle(ctx: local::CipherContext) -> Result<gcry_cipher_hd_t, u32> {
    let handle = gcry_cipher_handle::new(ctx);
    if handle.secure {
        let raw = alloc::gcry_calloc_secure(1, std::mem::size_of::<gcry_cipher_handle>())
            .cast::<gcry_cipher_handle>();
        if raw.is_null() {
            return Err(error::gcry_error_from_errno(crate::ENOMEM_VALUE));
        }
        unsafe {
            raw.write(handle);
        }
        context::set_object_secure(raw.cast(), true);
        Ok(raw)
    } else {
        Ok(Box::into_raw(Box::new(handle)))
    }
}

pub(crate) fn drop_handle(handle: gcry_cipher_hd_t) {
    if handle.is_null() {
        return;
    }

    unsafe {
        if (*handle).secure {
            context::remove_object(handle.cast());
            std::ptr::drop_in_place(handle);
            alloc::gcry_free(handle.cast());
        } else {
            drop(Box::from_raw(handle));
        }
    }
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
