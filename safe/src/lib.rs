#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use std::ffi::{c_char, c_int, c_uint, c_void};

mod alloc;
mod cipher;
mod config;
mod context;
mod digest;
mod drbg;
mod error;
mod global;
mod hwfeatures;
mod kdf;
mod log;
mod mac;
mod mpi;
mod os_rng;
mod pubkey;
mod random;
mod secmem;
mod sexp;
mod upstream;

pub(crate) type gcry_handler_progress_t =
    Option<unsafe extern "C" fn(*mut c_void, *const c_char, c_int, c_int, c_int)>;
pub(crate) type gcry_handler_alloc_t = Option<unsafe extern "C" fn(usize) -> *mut c_void>;
pub(crate) type gcry_handler_secure_check_t = Option<unsafe extern "C" fn(*const c_void) -> c_int>;
pub(crate) type gcry_handler_realloc_t =
    Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>;
pub(crate) type gcry_handler_free_t = Option<unsafe extern "C" fn(*mut c_void)>;
pub(crate) type gcry_handler_no_mem_t =
    Option<unsafe extern "C" fn(*mut c_void, usize, c_uint) -> c_int>;
pub(crate) type gcry_handler_error_t =
    Option<unsafe extern "C" fn(*mut c_void, c_int, *const c_char)>;
pub(crate) type gcry_gettext_handler_t =
    Option<unsafe extern "C" fn(*const c_char) -> *const c_char>;
pub(crate) type FILE = c_void;

pub(crate) const PACKAGE_VERSION: &str = "1.10.3";
pub(crate) const PACKAGE_VERSION_BYTES: &[u8] = b"1.10.3\0";
pub(crate) const GCRYPT_VERSION_NUMBER: u32 = 0x010a03;

pub(crate) const EINVAL_VALUE: c_int = 22;
pub(crate) const ENOMEM_VALUE: c_int = 12;

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

pub(crate) fn set_errno(value: c_int) {
    unsafe {
        *__errno_location() = value;
    }
}

pub(crate) fn get_errno() -> c_int {
    unsafe { *__errno_location() }
}

pub use alloc::*;
pub use config::*;
pub use error::*;
pub use global::*;
pub use log::*;

#[unsafe(no_mangle)]
pub extern "C" fn safe_gcry_stub_zero() -> usize {
    0
}
