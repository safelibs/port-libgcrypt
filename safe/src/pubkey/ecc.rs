use std::ffi::{c_char, c_int, c_uint, c_void};
use std::ptr::null_mut;
use std::sync::OnceLock;

use crate::alloc;
use crate::context;
use crate::error;
use crate::sexp;
use crate::upstream::{load_symbol, open_upstream_handle};

use super::encoding;

pub(crate) const NAME: &[u8] = b"ecc\0";
const ALIASES: &[&[u8]] = &[b"ecc\0", b"ecdsa\0", b"ecdh\0", b"eddsa\0"];

type GcryError = u32;
type CheckVersionFn = unsafe extern "C" fn(*const c_char) -> *const c_char;
type PkResultFn =
    unsafe extern "C" fn(*mut *mut c_void, *mut c_void, *mut c_void) -> GcryError;
type PkVerifyFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> GcryError;
type PkTestKeyFn = unsafe extern "C" fn(*mut c_void) -> GcryError;
type PkGenKeyFn = unsafe extern "C" fn(*mut *mut c_void, *mut c_void) -> GcryError;
type PkGetNbitsFn = unsafe extern "C" fn(*mut c_void) -> c_uint;
type PkGetKeygripFn = unsafe extern "C" fn(*mut c_void, *mut u8) -> *mut u8;
type PkGetCurveFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_uint) -> *const c_char;
type PkGetParamFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void;
type PubkeyGetSexpFn = unsafe extern "C" fn(*mut *mut c_void, c_int, *mut c_void) -> GcryError;
type EccGetAlgoKeylenFn = unsafe extern "C" fn(c_int) -> c_uint;
type EccMulPointFn = unsafe extern "C" fn(c_int, *mut u8, *const u8, *const u8) -> GcryError;

struct EccBridgeApi {
    _handle: usize,
    pk_encrypt: PkResultFn,
    pk_decrypt: PkResultFn,
    pk_sign: PkResultFn,
    pk_verify: PkVerifyFn,
    pk_testkey: PkTestKeyFn,
    pk_genkey: PkGenKeyFn,
    pk_get_nbits: PkGetNbitsFn,
    pk_get_keygrip: PkGetKeygripFn,
    pk_get_curve: PkGetCurveFn,
    pk_get_param: PkGetParamFn,
    pubkey_get_sexp: PubkeyGetSexpFn,
    ecc_get_algo_keylen: EccGetAlgoKeylenFn,
    ecc_mul_point: EccMulPointFn,
}

unsafe impl Send for EccBridgeApi {}
unsafe impl Sync for EccBridgeApi {}

fn init() -> EccBridgeApi {
    let handle = unsafe { open_upstream_handle() };
    let check_version: CheckVersionFn = unsafe { load_symbol(handle, "gcry_check_version") };
    let version = unsafe { check_version(std::ptr::null()) };
    if version.is_null() {
        panic!("upstream libgcrypt initialization via gcry_check_version failed");
    }

    EccBridgeApi {
        _handle: handle as usize,
        pk_encrypt: unsafe { load_symbol(handle, "gcry_pk_encrypt") },
        pk_decrypt: unsafe { load_symbol(handle, "gcry_pk_decrypt") },
        pk_sign: unsafe { load_symbol(handle, "gcry_pk_sign") },
        pk_verify: unsafe { load_symbol(handle, "gcry_pk_verify") },
        pk_testkey: unsafe { load_symbol(handle, "gcry_pk_testkey") },
        pk_genkey: unsafe { load_symbol(handle, "gcry_pk_genkey") },
        pk_get_nbits: unsafe { load_symbol(handle, "gcry_pk_get_nbits") },
        pk_get_keygrip: unsafe { load_symbol(handle, "gcry_pk_get_keygrip") },
        pk_get_curve: unsafe { load_symbol(handle, "gcry_pk_get_curve") },
        pk_get_param: unsafe { load_symbol(handle, "gcry_pk_get_param") },
        pubkey_get_sexp: unsafe { load_symbol(handle, "gcry_pubkey_get_sexp") },
        ecc_get_algo_keylen: unsafe { load_symbol(handle, "gcry_ecc_get_algo_keylen") },
        ecc_mul_point: unsafe { load_symbol(handle, "gcry_ecc_mul_point") },
    }
}

fn api() -> &'static EccBridgeApi {
    static API: OnceLock<EccBridgeApi> = OnceLock::new();
    API.get_or_init(init)
}

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    matches!(algo, 18 | 301 | 302 | 303)
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}

pub(crate) fn has_key_token(key: *mut sexp::gcry_sexp) -> bool {
    !super::find_first_token(key, ALIASES).is_null()
}

fn bridge_result(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    key: *mut sexp::gcry_sexp,
    op: PkResultFn,
) -> u32 {
    let upstream_data = match encoding::sexp_to_upstream(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let upstream_key = match encoding::sexp_to_upstream(key) {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                encoding::release_upstream_sexp(upstream_data);
            }
            return err;
        }
    };

    let mut upstream_result = null_mut();
    let rc = unsafe { op(&mut upstream_result, upstream_data, upstream_key) };
    unsafe {
        encoding::release_upstream_sexp(upstream_data);
        encoding::release_upstream_sexp(upstream_key);
    }
    if rc != 0 {
        unsafe {
            encoding::release_upstream_sexp(upstream_result);
        }
        return rc;
    }

    let local = match encoding::sexp_from_upstream(upstream_result) {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                encoding::release_upstream_sexp(upstream_result);
            }
            return err;
        }
    };
    unsafe {
        encoding::release_upstream_sexp(upstream_result);
        *result = local;
    }
    0
}

pub(crate) fn bridge_encrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    bridge_result(result, data, pkey, api().pk_encrypt)
}

pub(crate) fn bridge_decrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    bridge_result(result, data, skey, api().pk_decrypt)
}

pub(crate) fn bridge_sign(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    bridge_result(result, data, skey, api().pk_sign)
}

pub(crate) fn bridge_verify(
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

    let rc = unsafe { (api().pk_verify)(upstream_sig, upstream_data, upstream_key) };
    unsafe {
        encoding::release_upstream_sexp(upstream_sig);
        encoding::release_upstream_sexp(upstream_data);
        encoding::release_upstream_sexp(upstream_key);
    }
    rc
}

pub(crate) fn bridge_testkey(key: *mut sexp::gcry_sexp) -> u32 {
    let upstream_key = match encoding::sexp_to_upstream(key) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let rc = unsafe { (api().pk_testkey)(upstream_key) };
    unsafe {
        encoding::release_upstream_sexp(upstream_key);
    }
    rc
}

pub(crate) fn bridge_genkey(
    result: *mut *mut sexp::gcry_sexp,
    parms: *mut sexp::gcry_sexp,
) -> u32 {
    let upstream_parms = match encoding::sexp_to_upstream(parms) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let mut upstream_result = null_mut();
    let rc = unsafe { (api().pk_genkey)(&mut upstream_result, upstream_parms) };
    unsafe {
        encoding::release_upstream_sexp(upstream_parms);
    }
    if rc != 0 {
        unsafe {
            encoding::release_upstream_sexp(upstream_result);
        }
        return rc;
    }

    let local = match encoding::sexp_from_upstream(upstream_result) {
        Ok(value) => value,
        Err(err) => {
            unsafe {
                encoding::release_upstream_sexp(upstream_result);
            }
            return err;
        }
    };
    unsafe {
        encoding::release_upstream_sexp(upstream_result);
        *result = local;
    }
    0
}

pub(crate) fn bridge_get_nbits(key: *mut sexp::gcry_sexp) -> c_uint {
    let upstream_key = match encoding::sexp_to_upstream(key) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let nbits = unsafe { (api().pk_get_nbits)(upstream_key) };
    unsafe {
        encoding::release_upstream_sexp(upstream_key);
    }
    nbits
}

pub(crate) fn bridge_keygrip(key: *mut sexp::gcry_sexp, array: *mut u8) -> *mut u8 {
    let upstream_key = match encoding::sexp_to_upstream(key) {
        Ok(value) => value,
        Err(_) => return null_mut(),
    };

    let out = if array.is_null() {
        alloc::gcry_malloc(super::KEYGRIP_LEN).cast::<u8>()
    } else {
        array
    };
    if out.is_null() {
        unsafe {
            encoding::release_upstream_sexp(upstream_key);
        }
        return null_mut();
    }

    let result = unsafe { (api().pk_get_keygrip)(upstream_key, out) };
    unsafe {
        encoding::release_upstream_sexp(upstream_key);
    }
    if result.is_null() && array.is_null() {
        alloc::gcry_free(out.cast());
    }

    if result.is_null() { null_mut() } else { out }
}

#[no_mangle]
pub extern "C" fn gcry_pk_get_curve(
    key: *mut sexp::gcry_sexp,
    iterator: c_int,
    nbits: *mut c_uint,
) -> *const c_char {
    if key.is_null() {
        return unsafe { (api().pk_get_curve)(null_mut(), iterator, nbits) };
    }

    let upstream_key = match encoding::sexp_to_upstream(key) {
        Ok(value) => value,
        Err(_) => return std::ptr::null(),
    };
    let result = unsafe { (api().pk_get_curve)(upstream_key, iterator, nbits) };
    unsafe {
        encoding::release_upstream_sexp(upstream_key);
    }
    result
}

#[no_mangle]
pub extern "C" fn gcry_pk_get_param(algo: c_int, name: *const c_char) -> *mut sexp::gcry_sexp {
    let upstream = unsafe { (api().pk_get_param)(algo, name) };
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

    if context::is_random_override_context(ctx) {
        return error::gcry_error_from_code(super::GPG_ERR_WRONG_CRYPT_CTX);
    }

    let mut upstream = null_mut();
    let rc = unsafe { (api().pubkey_get_sexp)(&mut upstream, mode, ctx) };
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
    unsafe { (api().ecc_get_algo_keylen)(curveid) }
}

#[no_mangle]
pub extern "C" fn gcry_ecc_mul_point(
    curveid: c_int,
    result: *mut u8,
    scalar: *const u8,
    point: *const u8,
) -> u32 {
    unsafe { (api().ecc_mul_point)(curveid, result, scalar, point) }
}
