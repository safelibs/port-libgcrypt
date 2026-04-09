use std::ffi::{c_int, c_uint, c_void};
use std::ptr::null_mut;

use crate::alloc;

use super::{context, copy_opaque_value, gcry_mpi, OpaqueValue};

fn replace_with_opaque(a: *mut gcry_mpi, ptr: *mut c_void, nbits: c_uint) -> *mut gcry_mpi {
    let raw = if a.is_null() {
        super::gcry_mpi::from_numeric(super::Mpz::new(0), false)
    } else {
        a
    };
    unsafe {
        if let Some(value) = gcry_mpi::as_mut(raw) {
            value.kind = super::MpiKind::Opaque(OpaqueValue { ptr, nbits });
            value.clear_special_flags();
            value.sync_secure_registration();
        }
    }
    raw
}

#[unsafe(export_name = "gcry_mpi_set_opaque")]
pub extern "C" fn gcry_mpi_set_opaque(a: *mut gcry_mpi, p: *mut c_void, nbits: c_uint) -> *mut gcry_mpi {
    replace_with_opaque(a, p, nbits)
}

#[unsafe(export_name = "gcry_mpi_set_opaque_copy")]
pub extern "C" fn gcry_mpi_set_opaque_copy(
    a: *mut gcry_mpi,
    p: *const c_void,
    nbits: c_uint,
) -> *mut gcry_mpi {
    let nbytes = nbits.div_ceil(8) as usize;
    let copied = if p.is_null() || nbytes == 0 {
        null_mut()
    } else {
        let ptr = alloc::gcry_malloc(nbytes);
        if ptr.is_null() {
            return null_mut();
        }
        unsafe {
            std::ptr::copy_nonoverlapping(p.cast::<u8>(), ptr.cast::<u8>(), nbytes);
        }
        ptr
    };
    replace_with_opaque(a, copied, nbits)
}

#[unsafe(export_name = "gcry_mpi_get_opaque")]
pub extern "C" fn gcry_mpi_get_opaque(a: *mut gcry_mpi, nbits: *mut c_uint) -> *mut c_void {
    let Some(value) = (unsafe { gcry_mpi::as_ref(a) }) else {
        return null_mut();
    };
    let Some(opaque) = value.opaque() else {
        return null_mut();
    };
    if !nbits.is_null() {
        unsafe {
            *nbits = opaque.nbits;
        }
    }
    opaque.ptr
}
