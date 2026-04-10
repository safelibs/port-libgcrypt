use std::ptr::null_mut;

use crate::alloc;
use crate::sexp;

use super::{KEYGRIP_LEN, encoding};

#[no_mangle]
pub extern "C" fn gcry_pk_get_keygrip(key: *mut sexp::gcry_sexp, array: *mut u8) -> *mut u8 {
    let upstream_key = match encoding::sexp_to_upstream(key) {
        Ok(value) => value,
        Err(_) => return null_mut(),
    };

    let out = if array.is_null() {
        alloc::gcry_malloc(KEYGRIP_LEN).cast::<u8>()
    } else {
        array
    };
    if out.is_null() {
        unsafe {
            encoding::release_upstream_sexp(upstream_key);
        }
        return null_mut();
    }

    let result = unsafe { (encoding::api().pk_get_keygrip)(upstream_key, out) };
    unsafe {
        encoding::release_upstream_sexp(upstream_key);
    }

    if result.is_null() && array.is_null() {
        alloc::gcry_free(out.cast());
    }

    if result.is_null() { null_mut() } else { out }
}
