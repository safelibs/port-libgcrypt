use std::ffi::{c_char, c_int};

pub(crate) const NAME: &[u8] = b"rsa\0";

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    matches!(algo, 1 | 2 | 3)
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}
