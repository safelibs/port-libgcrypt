#![allow(dead_code)]

use std::ffi::c_void;

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct gcry_buffer_t {
    pub(crate) size: usize,
    pub(crate) off: usize,
    pub(crate) len: usize,
    pub(crate) data: *mut c_void,
}
