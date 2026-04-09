use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr::null_mut;

use crate::alloc;
use crate::error;
use crate::global;
use crate::log;
use crate::{FILE, GCRYPT_VERSION_NUMBER, PACKAGE_VERSION, set_errno};

unsafe extern "C" {
    fn fwrite(ptr: *const c_void, size: usize, nmemb: usize, stream: *mut FILE) -> usize;
}

fn cpu_arch_name() -> &'static str {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        "x86"
    }
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        "arm"
    }
    #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
    {
        "ppc"
    }
    #[cfg(target_arch = "s390x")]
    {
        "s390x"
    }
    #[cfg(not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "s390x"
    )))]
    {
        "generic"
    }
}

fn rng_type_name(rng_type: c_int) -> &'static str {
    match rng_type {
        global::GCRY_RNG_TYPE_FIPS => "fips",
        global::GCRY_RNG_TYPE_SYSTEM => "system",
        _ => "standard",
    }
}

fn version_line() -> String {
    let gpgrt_version = error::gpgrt_version_string();
    let gpgrt_hex = error::encode_version_number(&gpgrt_version);
    format!("version:{PACKAGE_VERSION}:{GCRYPT_VERSION_NUMBER:x}:{gpgrt_version}:{gpgrt_hex:x}:")
}

fn cpu_arch_line() -> String {
    format!("cpu-arch:{}:", cpu_arch_name())
}

fn rng_type_line() -> String {
    let rng_type = global::current_rng_type();
    format!("rng-type:{}:{}:0:0:", rng_type_name(rng_type), rng_type)
}

fn config_text(what: Option<&CStr>) -> Option<String> {
    match what.map(|item| item.to_bytes()) {
        None => Some(format!(
            "{}\n{}\n{}\n",
            version_line(),
            cpu_arch_line(),
            rng_type_line()
        )),
        Some(b"version") => Some(version_line()),
        Some(b"cpu-arch") => Some(cpu_arch_line()),
        Some(b"rng-type") => Some(rng_type_line()),
        _ => None,
    }
}

pub(crate) fn print_config_to_stream(stream: *mut FILE) {
    if let Some(text) = config_text(None) {
        if stream.is_null() {
            log::emit_message(log::GCRY_LOG_INFO, &text);
            return;
        }

        unsafe {
            let _ = fwrite(text.as_ptr().cast(), 1, text.len(), stream);
        }
    }
}

#[unsafe(export_name = "safe_gcry_get_config")]
pub extern "C" fn gcry_get_config(mode: c_int, what: *const c_char) -> *mut c_char {
    if mode != 0 {
        set_errno(crate::EINVAL_VALUE);
        return null_mut();
    }

    let what = if what.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(what) })
    };

    let Some(text) = config_text(what) else {
        set_errno(0);
        return null_mut();
    };

    let text = match CString::new(text) {
        Ok(value) => value,
        Err(_) => {
            set_errno(error::gcry_err_code_to_errno(error::GPG_ERR_INV_ARG));
            return null_mut();
        }
    };

    let ptr = alloc::copy_bytes(text.as_bytes_with_nul(), false, false);
    if ptr.is_null() {
        return null_mut();
    }

    ptr
}
