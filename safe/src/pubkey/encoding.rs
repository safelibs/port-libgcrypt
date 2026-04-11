use std::ffi::c_int;
use std::ptr::null_mut;

use crate::mpi::gcry_mpi;
use crate::sexp::{self, gcry_sexp};

use super::find_token;

pub(crate) fn data_value_mpi(data: *mut gcry_sexp, format: c_int) -> *mut gcry_mpi {
    if data.is_null() {
        return null_mut();
    }

    let value = find_token(data, b"value\0");
    if !value.is_null() {
        let mpi = sexp::gcry_sexp_nth_mpi(value.raw(), 1, format);
        if !mpi.is_null() {
            return mpi;
        }
    }

    sexp::gcry_sexp_nth_mpi(data, 0, format)
}

pub(crate) fn token_data(sexp_ptr: *mut gcry_sexp, name: &[u8]) -> Option<Vec<u8>> {
    let token = find_token(sexp_ptr, name);
    if token.is_null() {
        return None;
    }
    super::nth_data_bytes(token.raw(), 1)
}
