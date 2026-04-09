use std::ffi::{c_char, c_int, c_void};

use crate::upstream;

#[allow(dead_code)]
pub(crate) const IMPLEMENTED_ALGORITHMS: &[c_int] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312,
    313, 314, 315, 316, 317, 318,
];

#[allow(dead_code)]
pub(crate) const IMPLEMENTED_MODES: &[c_int] =
    &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

pub(crate) fn algo_info(algo: c_int, what: c_int, buffer: *mut c_void, nbytes: *mut usize) -> u32 {
    unsafe { (upstream::lib().cipher_algo_info)(algo, what, buffer, nbytes) }
}

pub(crate) fn algo_name(algorithm: c_int) -> *const c_char {
    unsafe { (upstream::lib().cipher_algo_name)(algorithm) }
}

pub(crate) fn map_name(name: *const c_char) -> c_int {
    unsafe { (upstream::lib().cipher_map_name)(name) }
}

pub(crate) fn get_algo_keylen(algo: c_int) -> usize {
    unsafe { (upstream::lib().cipher_get_algo_keylen)(algo) }
}

pub(crate) fn get_algo_blklen(algo: c_int) -> usize {
    unsafe { (upstream::lib().cipher_get_algo_blklen)(algo) }
}
