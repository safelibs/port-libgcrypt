use std::ffi::c_void;

use super::gcry_cipher_hd_t;
use crate::upstream;

pub(crate) fn authenticate(handle: gcry_cipher_hd_t, abuf: *const c_void, abuflen: usize) -> u32 {
    unsafe { (upstream::lib().cipher_authenticate)(handle.cast(), abuf, abuflen) }
}

pub(crate) fn gettag(handle: gcry_cipher_hd_t, outtag: *mut c_void, taglen: usize) -> u32 {
    unsafe { (upstream::lib().cipher_gettag)(handle.cast(), outtag, taglen) }
}

pub(crate) fn checktag(handle: gcry_cipher_hd_t, intag: *const c_void, taglen: usize) -> u32 {
    unsafe { (upstream::lib().cipher_checktag)(handle.cast(), intag, taglen) }
}

pub(crate) fn is_aead_mode(mode: i32) -> bool {
    matches!(mode, 8 | 9 | 10 | 11 | 14 | 15 | 16)
}
