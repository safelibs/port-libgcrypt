use std::ptr::null_mut;

use crate::alloc;
use crate::sexp;

use super::{Family, KEYGRIP_LEN, dsa, ecc, elgamal, family_from_key, rsa};

#[no_mangle]
pub extern "C" fn gcry_pk_get_keygrip(key: *mut sexp::gcry_sexp, array: *mut u8) -> *mut u8 {
    match family_from_key(key) {
        Some(Family::Ecc) => ecc::bridge_keygrip(key, array),
        Some(Family::Rsa) => copy_grip(rsa::keygrip(key), array),
        Some(Family::Dsa) => copy_grip(dsa::keygrip(key), array),
        Some(Family::Elgamal) => copy_grip(elgamal::keygrip(key), array),
        None => null_mut(),
    }
}

fn copy_grip(grip: Option<[u8; KEYGRIP_LEN]>, array: *mut u8) -> *mut u8 {
    let Some(grip) = grip else {
        return null_mut();
    };

    let out = if array.is_null() {
        alloc::gcry_malloc(KEYGRIP_LEN).cast::<u8>()
    } else {
        array
    };
    if out.is_null() {
        return null_mut();
    }

    unsafe {
        std::ptr::copy_nonoverlapping(grip.as_ptr(), out, KEYGRIP_LEN);
    }
    out
}
