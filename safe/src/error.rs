#![allow(dead_code)]

use std::ffi::{c_char, c_int};

pub(crate) const GPG_ERR_SOURCE_SHIFT: u32 = 24;
pub(crate) const GPG_ERR_CODE_MASK: u32 = 0xffff;
pub(crate) const GPG_ERR_SOURCE_MASK: u32 = 0x7f;

pub(crate) const GPG_ERR_GENERAL: u32 = 1;
pub(crate) const GPG_ERR_NO_PRIME: u32 = 21;
pub(crate) const GPG_ERR_NOT_FOUND: u32 = 27;
pub(crate) const GPG_ERR_SYNTAX: u32 = 29;
pub(crate) const GPG_ERR_INV_ARG: u32 = 45;
pub(crate) const GPG_ERR_NOT_SUPPORTED: u32 = 60;
pub(crate) const GPG_ERR_INV_OP: u32 = 61;
pub(crate) const GPG_ERR_INV_OBJ: u32 = 65;
pub(crate) const GPG_ERR_TOO_SHORT: u32 = 66;
pub(crate) const GPG_ERR_TOO_LARGE: u32 = 67;
pub(crate) const GPG_ERR_NO_OBJ: u32 = 68;
pub(crate) const GPG_ERR_NOT_IMPLEMENTED: u32 = 69;
pub(crate) const GPG_ERR_INV_FLAG: u32 = 72;
pub(crate) const GPG_ERR_INV_NAME: u32 = 88;
pub(crate) const GPG_ERR_BAD_DATA: u32 = 89;
pub(crate) const GPG_ERR_MISSING_VALUE: u32 = 128;
pub(crate) const GPG_ERR_BUFFER_TOO_SHORT: u32 = 200;
pub(crate) const GPG_ERR_SEXP_INV_LEN_SPEC: u32 = 201;
pub(crate) const GPG_ERR_SEXP_STRING_TOO_LONG: u32 = 202;
pub(crate) const GPG_ERR_SEXP_UNMATCHED_PAREN: u32 = 203;
pub(crate) const GPG_ERR_SEXP_NOT_CANONICAL: u32 = 204;
pub(crate) const GPG_ERR_SEXP_BAD_CHARACTER: u32 = 205;
pub(crate) const GPG_ERR_SEXP_BAD_QUOTATION: u32 = 206;
pub(crate) const GPG_ERR_SEXP_ZERO_PREFIX: u32 = 207;
pub(crate) const GPG_ERR_SEXP_NESTED_DH: u32 = 208;
pub(crate) const GPG_ERR_SEXP_UNMATCHED_DH: u32 = 209;
pub(crate) const GPG_ERR_SEXP_UNEXPECTED_PUNC: u32 = 210;
pub(crate) const GPG_ERR_SEXP_BAD_HEX_CHAR: u32 = 211;
pub(crate) const GPG_ERR_SEXP_ODD_HEX_NUMBERS: u32 = 212;
pub(crate) const GPG_ERR_SEXP_BAD_OCT_CHAR: u32 = 213;
pub(crate) const GPG_ERR_USER_1: u32 = 1024;
pub(crate) const GPG_ERR_ERANGE: u32 = (1 << 15) | 117;

#[link(name = "gpg-error")]
extern "C" {
    fn gpg_strerror(err: u32) -> *const c_char;
    fn gpg_strsource(err: u32) -> *const c_char;
    fn gpg_err_code_from_errno(err: c_int) -> u32;
    fn gpg_err_code_to_errno(code: u32) -> c_int;
    fn gpg_error_check_version(req_version: *const c_char) -> *const c_char;
}

pub(crate) fn make_error(source: u32, code: u32) -> u32 {
    if code == 0 {
        0
    } else {
        ((source & GPG_ERR_SOURCE_MASK) << GPG_ERR_SOURCE_SHIFT) | (code & GPG_ERR_CODE_MASK)
    }
}

pub(crate) fn gcry_error_from_code(code: u32) -> u32 {
    code & GPG_ERR_CODE_MASK
}

pub(crate) fn gcry_error_from_source(source: u32, code: u32) -> u32 {
    make_error(source, code)
}

pub(crate) fn gpg_err_code_from_os_error(err: c_int) -> u32 {
    unsafe { gpg_err_code_from_errno(err) }
}

pub(crate) fn gpgrt_version_string() -> String {
    let ptr = unsafe { gpg_error_check_version(std::ptr::null()) };
    if ptr.is_null() {
        return "unknown".to_string();
    }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn encode_version_number(version: &str) -> u32 {
    let mut pieces = version.split('.');
    let major = pieces
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = pieces
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
    let micro = pieces
        .next()
        .map(|part| {
            part.chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>()
        })
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
    (major << 16) | (minor << 8) | micro
}

#[export_name = "safe_gcry_err_code_from_errno"]
pub extern "C" fn gcry_err_code_from_errno(err: c_int) -> u32 {
    gpg_err_code_from_os_error(err)
}

#[export_name = "safe_gcry_err_code_to_errno"]
pub extern "C" fn gcry_err_code_to_errno(code: u32) -> c_int {
    unsafe { gpg_err_code_to_errno(code) }
}

#[export_name = "safe_gcry_err_make_from_errno"]
pub extern "C" fn gcry_err_make_from_errno(source: u32, err: c_int) -> u32 {
    gcry_error_from_source(source, gpg_err_code_from_os_error(err))
}

#[export_name = "safe_gcry_error_from_errno"]
pub extern "C" fn gcry_error_from_errno(err: c_int) -> u32 {
    gcry_error_from_code(gpg_err_code_from_os_error(err))
}

#[export_name = "safe_gcry_strerror"]
pub extern "C" fn gcry_strerror(err: u32) -> *const c_char {
    unsafe { gpg_strerror(err) }
}

#[export_name = "safe_gcry_strsource"]
pub extern "C" fn gcry_strsource(err: u32) -> *const c_char {
    unsafe { gpg_strsource(err) }
}
