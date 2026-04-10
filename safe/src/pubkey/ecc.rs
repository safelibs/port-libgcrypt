use std::ffi::{c_char, c_int, c_uint, c_void};
use std::ptr::null_mut;

use crate::error;
use crate::sexp;

use super::encoding;

pub(crate) const NAME: &[u8] = b"ecc\0";

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    matches!(algo, 18 | 301 | 302 | 303)
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}

#[no_mangle]
pub extern "C" fn gcry_pk_get_curve(
    key: *mut sexp::gcry_sexp,
    iterator: c_int,
    nbits: *mut c_uint,
) -> *const c_char {
    if key.is_null() {
        return unsafe { (encoding::api().pk_get_curve)(null_mut(), iterator, nbits) };
    }

    let upstream_key = match encoding::sexp_to_upstream(key) {
        Ok(value) => value,
        Err(_) => return std::ptr::null(),
    };
    let result = unsafe { (encoding::api().pk_get_curve)(upstream_key, iterator, nbits) };
    unsafe {
        encoding::release_upstream_sexp(upstream_key);
    }
    result
}

#[no_mangle]
pub extern "C" fn gcry_pk_get_param(algo: c_int, name: *const c_char) -> *mut sexp::gcry_sexp {
    let upstream = unsafe { (encoding::api().pk_get_param)(algo, name) };
    if upstream.is_null() {
        return null_mut();
    }

    let local = encoding::sexp_from_upstream(upstream);
    unsafe {
        encoding::release_upstream_sexp(upstream);
    }
    local.unwrap_or(null_mut())
}

#[no_mangle]
pub extern "C" fn gcry_pubkey_get_sexp(
    result: *mut *mut sexp::gcry_sexp,
    mode: c_int,
    ctx: *mut c_void,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    unsafe {
        *result = null_mut();
    }

    let mut upstream = null_mut();
    let rc = unsafe { (encoding::api().pubkey_get_sexp)(&mut upstream, mode, ctx) };
    if rc != 0 {
        return rc;
    }

    let local = match encoding::sexp_from_upstream(upstream) {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                encoding::release_upstream_sexp(upstream);
            }
            return err;
        }
    };
    unsafe {
        encoding::release_upstream_sexp(upstream);
        *result = local;
    }
    0
}

#[no_mangle]
pub extern "C" fn gcry_ecc_get_algo_keylen(curveid: c_int) -> c_uint {
    unsafe { (encoding::api().ecc_get_algo_keylen)(curveid) }
}

#[no_mangle]
pub extern "C" fn gcry_ecc_mul_point(
    curveid: c_int,
    result: *mut u8,
    scalar: *const u8,
    point: *const u8,
) -> u32 {
    unsafe { (encoding::api().ecc_mul_point)(curveid, result, scalar, point) }
}
