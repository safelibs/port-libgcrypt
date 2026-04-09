use std::ffi::c_int;

use super::gcry_md_hd_t;

pub(crate) const GCRY_MD_SHAKE128: c_int = 316;
pub(crate) const GCRY_MD_SHAKE256: c_int = 317;

pub(crate) fn resolve_read_algo(hd: gcry_md_hd_t, requested: c_int) -> Option<c_int> {
    if requested != 0 {
        Some(requested)
    } else {
        let algo = super::gcry_md_get_algo(hd);
        (algo != 0).then_some(algo)
    }
}

pub(crate) fn is_xof(algo: c_int) -> bool {
    matches!(algo, GCRY_MD_SHAKE128 | GCRY_MD_SHAKE256)
}
