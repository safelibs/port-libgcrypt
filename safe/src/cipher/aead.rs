use std::ffi::c_void;

use super::gcry_cipher_hd_t;
use super::modes;
use super::registry::{
    GCRY_CIPHER_MODE_CCM, GCRY_CIPHER_MODE_EAX, GCRY_CIPHER_MODE_GCM, GCRY_CIPHER_MODE_GCM_SIV,
    GCRY_CIPHER_MODE_OCB, GCRY_CIPHER_MODE_SIV,
};

pub(crate) fn authenticate(handle: gcry_cipher_hd_t, abuf: *const c_void, abuflen: usize) -> u32 {
    modes::authenticate(handle, abuf, abuflen)
}

pub(crate) fn gettag(handle: gcry_cipher_hd_t, outtag: *mut c_void, taglen: usize) -> u32 {
    modes::gettag(handle, outtag, taglen)
}

pub(crate) fn checktag(handle: gcry_cipher_hd_t, intag: *const c_void, taglen: usize) -> u32 {
    modes::checktag(handle, intag, taglen)
}

pub(crate) fn is_aead_mode(mode: i32) -> bool {
    matches!(
        mode,
        GCRY_CIPHER_MODE_CCM
            | GCRY_CIPHER_MODE_GCM
            | GCRY_CIPHER_MODE_OCB
            | GCRY_CIPHER_MODE_EAX
            | GCRY_CIPHER_MODE_SIV
            | GCRY_CIPHER_MODE_GCM_SIV
    )
}
