use std::ffi::{c_char, c_int};

pub(crate) const GPG_ERR_SOURCE_SHIFT: u32 = 24;
pub(crate) const GPG_ERR_CODE_MASK: u32 = 0xffff;
pub(crate) const GPG_ERR_SOURCE_MASK: u32 = 0x7f;

pub(crate) const GPG_ERR_GENERAL: u32 = 1;
pub(crate) const GPG_ERR_INV_ARG: u32 = 45;
pub(crate) const GPG_ERR_NOT_SUPPORTED: u32 = 60;
pub(crate) const GPG_ERR_INV_OP: u32 = 61;
pub(crate) const GPG_ERR_NOT_IMPLEMENTED: u32 = 69;
pub(crate) const GPG_ERR_INV_NAME: u32 = 88;

#[link(name = "gpg-error")]
unsafe extern "C" {
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

#[unsafe(export_name = "safe_gcry_err_code_from_errno")]
pub extern "C" fn gcry_err_code_from_errno(err: c_int) -> u32 {
    gpg_err_code_from_os_error(err)
}

#[unsafe(export_name = "safe_gcry_err_code_to_errno")]
pub extern "C" fn gcry_err_code_to_errno(code: u32) -> c_int {
    unsafe { gpg_err_code_to_errno(code) }
}

#[unsafe(export_name = "safe_gcry_err_make_from_errno")]
pub extern "C" fn gcry_err_make_from_errno(source: u32, err: c_int) -> u32 {
    gcry_error_from_source(source, gpg_err_code_from_os_error(err))
}

#[unsafe(export_name = "safe_gcry_error_from_errno")]
pub extern "C" fn gcry_error_from_errno(err: c_int) -> u32 {
    gcry_error_from_code(gpg_err_code_from_os_error(err))
}

#[unsafe(export_name = "safe_gcry_strerror")]
pub extern "C" fn gcry_strerror(err: u32) -> *const c_char {
    unsafe { gpg_strerror(err) }
}

#[unsafe(export_name = "safe_gcry_strsource")]
pub extern "C" fn gcry_strsource(err: u32) -> *const c_char {
    unsafe { gpg_strsource(err) }
}
