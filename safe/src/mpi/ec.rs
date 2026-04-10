use std::ffi::{c_char, c_int, c_uint, c_void};
use std::ptr::null_mut;

use crate::error;
use crate::pubkey::encoding;
use crate::sexp;

use super::gcry_mpi;

const ECDSA_TOKEN: &[u8] = b"ecdsa\0";
const MPI_PARAM_P: &[u8] = b"p\0";
const MPI_PARAM_A: &[u8] = b"a\0";

fn zero_target(target: *mut gcry_mpi) {
    if !target.is_null() {
        super::gcry_mpi_set_ui(target, 0);
    }
}

fn new_upstream_mpi() -> *mut c_void {
    unsafe { (encoding::api().mpi_new)(0) }
}

fn legacy_ecdsa_param_error(keyparam: *mut sexp::gcry_sexp, curvename: *const c_char) -> bool {
    if keyparam.is_null() || !curvename.is_null() {
        return false;
    }

    let ecdsa = sexp::gcry_sexp_find_token(keyparam, ECDSA_TOKEN.as_ptr().cast(), 0);
    if ecdsa.is_null() {
        return false;
    }

    let has_p = !sexp::gcry_sexp_find_token(ecdsa, MPI_PARAM_P.as_ptr().cast(), 0).is_null();
    let has_a = !sexp::gcry_sexp_find_token(ecdsa, MPI_PARAM_A.as_ptr().cast(), 0).is_null();
    sexp::gcry_sexp_release(ecdsa);
    !(has_p && has_a)
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_new(nbits: c_uint) -> *mut c_void {
    unsafe { (encoding::api().point_new)(nbits) }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_release(point: *mut c_void) {
    if !point.is_null() {
        unsafe {
            (encoding::api().point_release)(point);
        }
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_copy(point: *mut c_void) -> *mut c_void {
    if point.is_null() {
        null_mut()
    } else {
        unsafe { (encoding::api().point_copy)(point) }
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_get(
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
    point: *mut c_void,
) {
    if point.is_null() {
        zero_target(x);
        zero_target(y);
        zero_target(z);
        return;
    }

    let up_x = new_upstream_mpi();
    let up_y = new_upstream_mpi();
    let up_z = new_upstream_mpi();
    if up_x.is_null() || up_y.is_null() || up_z.is_null() {
        unsafe {
            encoding::release_upstream_mpi(up_x);
            encoding::release_upstream_mpi(up_y);
            encoding::release_upstream_mpi(up_z);
        }
        return;
    }

    unsafe {
        (encoding::api().point_get)(up_x, up_y, up_z, point);
        let _ = encoding::assign_local_from_upstream_mpi(x, up_x);
        let _ = encoding::assign_local_from_upstream_mpi(y, up_y);
        let _ = encoding::assign_local_from_upstream_mpi(z, up_z);
        encoding::release_upstream_mpi(up_x);
        encoding::release_upstream_mpi(up_y);
        encoding::release_upstream_mpi(up_z);
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_snatch_get(
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
    point: *mut c_void,
) {
    if point.is_null() {
        zero_target(x);
        zero_target(y);
        zero_target(z);
        return;
    }

    let up_x = new_upstream_mpi();
    let up_y = new_upstream_mpi();
    let up_z = new_upstream_mpi();
    if up_x.is_null() || up_y.is_null() || up_z.is_null() {
        unsafe {
            encoding::release_upstream_mpi(up_x);
            encoding::release_upstream_mpi(up_y);
            encoding::release_upstream_mpi(up_z);
        }
        return;
    }

    unsafe {
        (encoding::api().point_snatch_get)(up_x, up_y, up_z, point);
        let _ = encoding::assign_local_from_upstream_mpi(x, up_x);
        let _ = encoding::assign_local_from_upstream_mpi(y, up_y);
        let _ = encoding::assign_local_from_upstream_mpi(z, up_z);
        encoding::release_upstream_mpi(up_x);
        encoding::release_upstream_mpi(up_y);
        encoding::release_upstream_mpi(up_z);
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_set(
    point: *mut c_void,
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
) -> *mut c_void {
    let up_x = match encoding::local_to_upstream_mpi(x) {
        Ok(value) => value,
        Err(_) => return null_mut(),
    };
    let up_y = match encoding::local_to_upstream_mpi(y) {
        Ok(value) => value,
        Err(_) => {
            unsafe {
                encoding::release_upstream_mpi(up_x);
            }
            return null_mut();
        }
    };
    let up_z = match encoding::local_to_upstream_mpi(z) {
        Ok(value) => value,
        Err(_) => {
            unsafe {
                encoding::release_upstream_mpi(up_x);
                encoding::release_upstream_mpi(up_y);
            }
            return null_mut();
        }
    };

    let result = unsafe { (encoding::api().point_set)(point, up_x, up_y, up_z) };
    unsafe {
        encoding::release_upstream_mpi(up_x);
        encoding::release_upstream_mpi(up_y);
        encoding::release_upstream_mpi(up_z);
    }
    result
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_snatch_set(
    point: *mut c_void,
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
) -> *mut c_void {
    let up_x = match encoding::local_to_upstream_mpi(x) {
        Ok(value) => value,
        Err(_) => return null_mut(),
    };
    let up_y = match encoding::local_to_upstream_mpi(y) {
        Ok(value) => value,
        Err(_) => {
            unsafe {
                encoding::release_upstream_mpi(up_x);
            }
            return null_mut();
        }
    };
    let up_z = match encoding::local_to_upstream_mpi(z) {
        Ok(value) => value,
        Err(_) => {
            unsafe {
                encoding::release_upstream_mpi(up_x);
                encoding::release_upstream_mpi(up_y);
            }
            return null_mut();
        }
    };

    let result = unsafe { (encoding::api().point_snatch_set)(point, up_x, up_y, up_z) };
    if result.is_null() {
        unsafe {
            encoding::release_upstream_mpi(up_x);
            encoding::release_upstream_mpi(up_y);
            encoding::release_upstream_mpi(up_z);
        }
    }
    result
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_new(
    r_ctx: *mut *mut c_void,
    keyparam: *mut sexp::gcry_sexp,
    curvename: *const c_char,
) -> u32 {
    if r_ctx.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    unsafe {
        *r_ctx = null_mut();
    }

    if legacy_ecdsa_param_error(keyparam, curvename) {
        return error::gcry_error_from_errno(crate::EINVAL_VALUE);
    }

    let upstream_key = match encoding::sexp_to_upstream(keyparam) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let mut upstream_ctx = null_mut();
    let rc = unsafe { (encoding::api().ec_new)(&mut upstream_ctx, upstream_key, curvename) };
    unsafe {
        encoding::release_upstream_sexp(upstream_key);
    }
    if rc == 0 {
        unsafe {
            *r_ctx = upstream_ctx;
        }
    }
    rc
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_get_mpi(
    name: *const c_char,
    ctx: *mut c_void,
    _copy: c_int,
) -> *mut gcry_mpi {
    if name.is_null() || ctx.is_null() {
        return null_mut();
    }

    let upstream = unsafe { (encoding::api().ec_get_mpi)(name, ctx, 1) };
    if upstream.is_null() {
        return null_mut();
    }

    let local = encoding::upstream_to_local_mpi(upstream).unwrap_or(null_mut());
    unsafe {
        encoding::release_upstream_mpi(upstream);
    }
    local
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_get_point(
    name: *const c_char,
    ctx: *mut c_void,
    _copy: c_int,
) -> *mut c_void {
    if name.is_null() || ctx.is_null() {
        null_mut()
    } else {
        unsafe { (encoding::api().ec_get_point)(name, ctx, 1) }
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_set_mpi(
    name: *const c_char,
    newvalue: *mut gcry_mpi,
    ctx: *mut c_void,
) -> u32 {
    if name.is_null() || ctx.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let upstream = match encoding::local_to_upstream_mpi(newvalue) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let rc = unsafe { (encoding::api().ec_set_mpi)(name, upstream, ctx) };
    unsafe {
        encoding::release_upstream_mpi(upstream);
    }
    rc
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_set_point(
    name: *const c_char,
    newvalue: *mut c_void,
    ctx: *mut c_void,
) -> u32 {
    if name.is_null() || ctx.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    unsafe { (encoding::api().ec_set_point)(name, newvalue, ctx) }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_decode_point(
    result: *mut c_void,
    value: *mut gcry_mpi,
    ctx: *mut c_void,
) -> u32 {
    if result.is_null() || ctx.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let upstream_value = match encoding::local_to_upstream_mpi(value) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let rc = unsafe { (encoding::api().ec_decode_point)(result, upstream_value, ctx) };
    unsafe {
        encoding::release_upstream_mpi(upstream_value);
    }
    rc
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_get_affine(
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    point: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    if point.is_null() || ctx.is_null() {
        return -1;
    }

    let up_x = if x.is_null() {
        null_mut()
    } else {
        new_upstream_mpi()
    };
    let up_y = if y.is_null() {
        null_mut()
    } else {
        new_upstream_mpi()
    };
    let rc = unsafe { (encoding::api().ec_get_affine)(up_x, up_y, point, ctx) };
    if rc == 0 {
        if !up_x.is_null() {
            let _ = encoding::assign_local_from_upstream_mpi(x, up_x);
        }
        if !up_y.is_null() {
            let _ = encoding::assign_local_from_upstream_mpi(y, up_y);
        }
    }
    unsafe {
        encoding::release_upstream_mpi(up_x);
        encoding::release_upstream_mpi(up_y);
    }
    rc
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_dup(w: *mut c_void, u: *mut c_void, ctx: *mut c_void) {
    if !w.is_null() && !u.is_null() && !ctx.is_null() {
        unsafe {
            (encoding::api().ec_dup)(w, u, ctx);
        }
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_add(
    w: *mut c_void,
    u: *mut c_void,
    v: *mut c_void,
    ctx: *mut c_void,
) {
    if !w.is_null() && !u.is_null() && !v.is_null() && !ctx.is_null() {
        unsafe {
            (encoding::api().ec_add)(w, u, v, ctx);
        }
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_sub(
    w: *mut c_void,
    u: *mut c_void,
    v: *mut c_void,
    ctx: *mut c_void,
) {
    if !w.is_null() && !u.is_null() && !v.is_null() && !ctx.is_null() {
        unsafe {
            (encoding::api().ec_sub)(w, u, v, ctx);
        }
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_mul(
    w: *mut c_void,
    n: *mut gcry_mpi,
    u: *mut c_void,
    ctx: *mut c_void,
) {
    if w.is_null() || u.is_null() || ctx.is_null() {
        return;
    }

    let upstream_n = match encoding::local_to_upstream_mpi(n) {
        Ok(value) => value,
        Err(_) => return,
    };
    unsafe {
        (encoding::api().ec_mul)(w, upstream_n, u, ctx);
        encoding::release_upstream_mpi(upstream_n);
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_curve_point(w: *mut c_void, ctx: *mut c_void) -> c_int {
    if w.is_null() || ctx.is_null() {
        0
    } else {
        unsafe { (encoding::api().ec_curve_point)(w, ctx) }
    }
}
