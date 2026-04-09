mod dsa;
pub(crate) mod encoding;
mod ecc;
mod elgamal;
mod keygrip;
mod rsa;

use std::ffi::{c_char, c_int, c_void};
use std::ptr::null_mut;

use crate::digest::gcry_md_hd_t;
use crate::error;
use crate::sexp;

pub(crate) const KEYGRIP_LEN: usize = 20;

fn fallback_algo_name(algo: c_int) -> *const c_char {
    rsa::fallback_name(algo)
        .or_else(|| dsa::fallback_name(algo))
        .or_else(|| elgamal::fallback_name(algo))
        .or_else(|| ecc::fallback_name(algo))
        .unwrap_or(std::ptr::null())
}

fn clear_result_slot(result: *mut *mut sexp::gcry_sexp) {
    if !result.is_null() {
        unsafe {
            *result = null_mut();
        }
    }
}

fn convert_result(result: *mut *mut sexp::gcry_sexp, upstream: *mut c_void) -> u32 {
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

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_encrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);

    let upstream_data = match encoding::sexp_to_upstream(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let upstream_key = match encoding::sexp_to_upstream(pkey) {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                encoding::release_upstream_sexp(upstream_data);
            }
            return err;
        }
    };

    let mut upstream_result = null_mut();
    let rc = unsafe { (encoding::api().pk_encrypt)(&mut upstream_result, upstream_data, upstream_key) };
    unsafe {
        encoding::release_upstream_sexp(upstream_data);
        encoding::release_upstream_sexp(upstream_key);
    }
    if rc != 0 {
        return rc;
    }
    convert_result(result, upstream_result)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_decrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);

    let upstream_data = match encoding::sexp_to_upstream(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let upstream_key = match encoding::sexp_to_upstream(skey) {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                encoding::release_upstream_sexp(upstream_data);
            }
            return err;
        }
    };

    let mut upstream_result = null_mut();
    let rc = unsafe { (encoding::api().pk_decrypt)(&mut upstream_result, upstream_data, upstream_key) };
    unsafe {
        encoding::release_upstream_sexp(upstream_data);
        encoding::release_upstream_sexp(upstream_key);
    }
    if rc != 0 {
        return rc;
    }
    convert_result(result, upstream_result)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_sign(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);

    let upstream_data = match encoding::sexp_to_upstream(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let upstream_key = match encoding::sexp_to_upstream(skey) {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                encoding::release_upstream_sexp(upstream_data);
            }
            return err;
        }
    };

    let mut upstream_result = null_mut();
    let rc = unsafe { (encoding::api().pk_sign)(&mut upstream_result, upstream_data, upstream_key) };
    unsafe {
        encoding::release_upstream_sexp(upstream_data);
        encoding::release_upstream_sexp(upstream_key);
    }
    if rc != 0 {
        return rc;
    }
    convert_result(result, upstream_result)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_verify(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    let upstream_sig = match encoding::sexp_to_upstream(sigval) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let upstream_data = match encoding::sexp_to_upstream(data) {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                encoding::release_upstream_sexp(upstream_sig);
            }
            return err;
        }
    };
    let upstream_key = match encoding::sexp_to_upstream(pkey) {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                encoding::release_upstream_sexp(upstream_sig);
                encoding::release_upstream_sexp(upstream_data);
            }
            return err;
        }
    };

    let rc = unsafe { (encoding::api().pk_verify)(upstream_sig, upstream_data, upstream_key) };
    unsafe {
        encoding::release_upstream_sexp(upstream_sig);
        encoding::release_upstream_sexp(upstream_data);
        encoding::release_upstream_sexp(upstream_key);
    }
    rc
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_testkey(key: *mut sexp::gcry_sexp) -> u32 {
    let upstream_key = match encoding::sexp_to_upstream(key) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let rc = unsafe { (encoding::api().pk_testkey)(upstream_key) };
    unsafe {
        encoding::release_upstream_sexp(upstream_key);
    }
    rc
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_genkey(
    result: *mut *mut sexp::gcry_sexp,
    parms: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);

    let upstream_parms = match encoding::sexp_to_upstream(parms) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let mut upstream_result = null_mut();
    let rc = unsafe { (encoding::api().pk_genkey)(&mut upstream_result, upstream_parms) };
    unsafe {
        encoding::release_upstream_sexp(upstream_parms);
    }
    if rc != 0 {
        return rc;
    }
    convert_result(result, upstream_result)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_ctl(cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
    unsafe { (encoding::api().pk_ctl)(cmd, buffer, buflen) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_algo_info(
    algo: c_int,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    unsafe { (encoding::api().pk_algo_info)(algo, what, buffer, nbytes) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_algo_name(algo: c_int) -> *const c_char {
    let upstream = unsafe { (encoding::api().pk_algo_name)(algo) };
    if upstream.is_null() {
        fallback_algo_name(algo)
    } else {
        upstream
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_map_name(name: *const c_char) -> c_int {
    unsafe { (encoding::api().pk_map_name)(name) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_get_nbits(key: *mut sexp::gcry_sexp) -> u32 {
    let upstream_key = match encoding::sexp_to_upstream(key) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let nbits = unsafe { (encoding::api().pk_get_nbits)(upstream_key) };
    unsafe {
        encoding::release_upstream_sexp(upstream_key);
    }
    nbits
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_hash_sign(
    result: *mut *mut sexp::gcry_sexp,
    data_tmpl: *const c_char,
    skey: *mut sexp::gcry_sexp,
    hd: gcry_md_hd_t,
    ctx: *mut c_void,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);

    let upstream_key = match encoding::sexp_to_upstream(skey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let mut upstream_result = null_mut();
    let rc =
        unsafe { (encoding::api().pk_hash_sign)(&mut upstream_result, data_tmpl, upstream_key, hd.cast(), ctx) };
    unsafe {
        encoding::release_upstream_sexp(upstream_key);
    }
    if rc != 0 {
        return rc;
    }
    convert_result(result, upstream_result)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_hash_verify(
    sigval: *mut sexp::gcry_sexp,
    data_tmpl: *const c_char,
    pkey: *mut sexp::gcry_sexp,
    hd: gcry_md_hd_t,
    ctx: *mut c_void,
) -> u32 {
    let upstream_sig = match encoding::sexp_to_upstream(sigval) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let upstream_key = match encoding::sexp_to_upstream(pkey) {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                encoding::release_upstream_sexp(upstream_sig);
            }
            return err;
        }
    };

    let rc = unsafe {
        (encoding::api().pk_hash_verify)(upstream_sig, data_tmpl, upstream_key, hd.cast(), ctx)
    };
    unsafe {
        encoding::release_upstream_sexp(upstream_sig);
        encoding::release_upstream_sexp(upstream_key);
    }
    rc
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_random_override_new(
    r_ctx: *mut *mut c_void,
    p: *const u8,
    len: usize,
) -> u32 {
    if r_ctx.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    unsafe {
        *r_ctx = null_mut();
    }
    unsafe { (encoding::api().pk_random_override_new)(r_ctx, p, len) }
}

#[unsafe(export_name = "safe_gcry_pk_register")]
pub extern "C" fn gcry_pk_register() -> u32 {
    error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED)
}
