use std::ffi::{c_char, c_int, c_uint, c_void};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use crate::alloc;
use crate::error;
use crate::mpi::{GCRYMPI_FMT_STD, gcry_mpi};
use crate::sexp::{self, gcry_sexp};
use crate::upstream::{load_symbol, open_upstream_handle};

const GCRYSEXP_FMT_CANON: c_int = 1;
const GCRYSEXP_FMT_ADVANCED: c_int = 3;
const GCRYMPI_FLAG_OPAQUE: c_int = 2;

type GcryError = u32;

type CheckVersionFn = unsafe extern "C" fn(*const c_char) -> *const c_char;
type CtxReleaseFn = unsafe extern "C" fn(*mut c_void);

type SexpSscanFn =
    unsafe extern "C" fn(*mut *mut c_void, *mut usize, *const c_char, usize) -> GcryError;
type SexpSprintFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, usize) -> usize;
type SexpReleaseFn = unsafe extern "C" fn(*mut c_void);

type MpiNewFn = unsafe extern "C" fn(c_uint) -> *mut c_void;
type MpiReleaseFn = unsafe extern "C" fn(*mut c_void);
type MpiScanFn =
    unsafe extern "C" fn(*mut *mut c_void, c_int, *const c_void, usize, *mut usize) -> GcryError;
type MpiPrintFn =
    unsafe extern "C" fn(c_int, *mut u8, usize, *mut usize, *const c_void) -> GcryError;
type MpiGetFlagFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type MpiGetOpaqueFn = unsafe extern "C" fn(*mut c_void, *mut c_uint) -> *mut c_void;
type MpiSetOpaqueCopyFn = unsafe extern "C" fn(*mut c_void, *const c_void, c_uint) -> *mut c_void;

type PointNewFn = unsafe extern "C" fn(c_uint) -> *mut c_void;
type PointReleaseFn = unsafe extern "C" fn(*mut c_void);
type PointCopyFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type PointGetFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
type PointSetFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> *mut c_void;

type EcNewFn = unsafe extern "C" fn(*mut *mut c_void, *mut c_void, *const c_char) -> GcryError;
type EcGetMpiFn = unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> *mut c_void;
type EcGetPointFn = unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> *mut c_void;
type EcSetMpiFn = unsafe extern "C" fn(*const c_char, *mut c_void, *mut c_void) -> GcryError;
type EcSetPointFn = unsafe extern "C" fn(*const c_char, *mut c_void, *mut c_void) -> GcryError;
type EcDecodePointFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> GcryError;
type EcGetAffineFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> c_int;
type EcDupFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
type EcPointVoidFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
type EcMulFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
type EcCurvePointFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;

pub(crate) struct PubkeyApi {
    _handle: usize,
    pub(crate) ctx_release: CtxReleaseFn,
    pub(crate) sexp_sscan: SexpSscanFn,
    pub(crate) sexp_sprint: SexpSprintFn,
    pub(crate) sexp_release: SexpReleaseFn,
    pub(crate) mpi_new: MpiNewFn,
    pub(crate) mpi_release: MpiReleaseFn,
    pub(crate) mpi_scan: MpiScanFn,
    pub(crate) mpi_print: MpiPrintFn,
    pub(crate) mpi_get_flag: MpiGetFlagFn,
    pub(crate) mpi_get_opaque: MpiGetOpaqueFn,
    pub(crate) mpi_set_opaque_copy: MpiSetOpaqueCopyFn,
    pub(crate) point_new: PointNewFn,
    pub(crate) point_release: PointReleaseFn,
    pub(crate) point_copy: PointCopyFn,
    pub(crate) point_get: PointGetFn,
    pub(crate) point_snatch_get: PointGetFn,
    pub(crate) point_set: PointSetFn,
    pub(crate) point_snatch_set: PointSetFn,
    pub(crate) ec_new: EcNewFn,
    pub(crate) ec_get_mpi: EcGetMpiFn,
    pub(crate) ec_get_point: EcGetPointFn,
    pub(crate) ec_set_mpi: EcSetMpiFn,
    pub(crate) ec_set_point: EcSetPointFn,
    pub(crate) ec_decode_point: EcDecodePointFn,
    pub(crate) ec_get_affine: EcGetAffineFn,
    pub(crate) ec_dup: EcDupFn,
    pub(crate) ec_add: EcPointVoidFn,
    pub(crate) ec_sub: EcPointVoidFn,
    pub(crate) ec_mul: EcMulFn,
    pub(crate) ec_curve_point: EcCurvePointFn,
}

unsafe impl Send for PubkeyApi {}
unsafe impl Sync for PubkeyApi {}

fn init() -> PubkeyApi {
    let handle = unsafe { open_upstream_handle() };
    let check_version: CheckVersionFn = unsafe { load_symbol(handle, "gcry_check_version") };
    let version = unsafe { check_version(null()) };
    if version.is_null() {
        panic!("upstream libgcrypt initialization via gcry_check_version failed");
    }

    PubkeyApi {
        _handle: handle as usize,
        ctx_release: unsafe { load_symbol(handle, "gcry_ctx_release") },
        sexp_sscan: unsafe { load_symbol(handle, "gcry_sexp_sscan") },
        sexp_sprint: unsafe { load_symbol(handle, "gcry_sexp_sprint") },
        sexp_release: unsafe { load_symbol(handle, "gcry_sexp_release") },
        mpi_new: unsafe { load_symbol(handle, "gcry_mpi_new") },
        mpi_release: unsafe { load_symbol(handle, "gcry_mpi_release") },
        mpi_scan: unsafe { load_symbol(handle, "gcry_mpi_scan") },
        mpi_print: unsafe { load_symbol(handle, "gcry_mpi_print") },
        mpi_get_flag: unsafe { load_symbol(handle, "gcry_mpi_get_flag") },
        mpi_get_opaque: unsafe { load_symbol(handle, "gcry_mpi_get_opaque") },
        mpi_set_opaque_copy: unsafe { load_symbol(handle, "gcry_mpi_set_opaque_copy") },
        point_new: unsafe { load_symbol(handle, "gcry_mpi_point_new") },
        point_release: unsafe { load_symbol(handle, "gcry_mpi_point_release") },
        point_copy: unsafe { load_symbol(handle, "gcry_mpi_point_copy") },
        point_get: unsafe { load_symbol(handle, "gcry_mpi_point_get") },
        point_snatch_get: unsafe { load_symbol(handle, "gcry_mpi_point_snatch_get") },
        point_set: unsafe { load_symbol(handle, "gcry_mpi_point_set") },
        point_snatch_set: unsafe { load_symbol(handle, "gcry_mpi_point_snatch_set") },
        ec_new: unsafe { load_symbol(handle, "gcry_mpi_ec_new") },
        ec_get_mpi: unsafe { load_symbol(handle, "gcry_mpi_ec_get_mpi") },
        ec_get_point: unsafe { load_symbol(handle, "gcry_mpi_ec_get_point") },
        ec_set_mpi: unsafe { load_symbol(handle, "gcry_mpi_ec_set_mpi") },
        ec_set_point: unsafe { load_symbol(handle, "gcry_mpi_ec_set_point") },
        ec_decode_point: unsafe { load_symbol(handle, "gcry_mpi_ec_decode_point") },
        ec_get_affine: unsafe { load_symbol(handle, "gcry_mpi_ec_get_affine") },
        ec_dup: unsafe { load_symbol(handle, "gcry_mpi_ec_dup") },
        ec_add: unsafe { load_symbol(handle, "gcry_mpi_ec_add") },
        ec_sub: unsafe { load_symbol(handle, "gcry_mpi_ec_sub") },
        ec_mul: unsafe { load_symbol(handle, "gcry_mpi_ec_mul") },
        ec_curve_point: unsafe { load_symbol(handle, "gcry_mpi_ec_curve_point") },
    }
}

pub(crate) fn api() -> &'static PubkeyApi {
    static API: OnceLock<PubkeyApi> = OnceLock::new();
    API.get_or_init(init)
}

fn oom_error() -> u32 {
    error::gcry_error_from_errno(crate::ENOMEM_VALUE)
}

pub(crate) unsafe fn release_upstream_sexp(sexp: *mut c_void) {
    if !sexp.is_null() {
        unsafe {
            (api().sexp_release)(sexp);
        }
    }
}

pub(crate) unsafe fn release_upstream_mpi(mpi: *mut c_void) {
    if !mpi.is_null() {
        unsafe {
            (api().mpi_release)(mpi);
        }
    }
}

pub(crate) fn sexp_to_upstream(local: *mut gcry_sexp) -> Result<*mut c_void, u32> {
    if local.is_null() {
        return Ok(null_mut());
    }

    let needed = sexp::gcry_sexp_sprint(local, GCRYSEXP_FMT_ADVANCED, null_mut(), 0);
    if needed == 0 {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
    }

    let mut rendered = vec![0u8; needed];
    let written = sexp::gcry_sexp_sprint(
        local,
        GCRYSEXP_FMT_ADVANCED,
        rendered.as_mut_ptr().cast(),
        rendered.len(),
    );
    let datalen = if written == 0 { needed - 1 } else { written };

    let mut upstream = null_mut();
    let rc =
        unsafe { (api().sexp_sscan)(&mut upstream, null_mut(), rendered.as_ptr().cast(), datalen) };
    if rc != 0 {
        return Err(rc);
    }
    Ok(upstream)
}

pub(crate) fn sexp_from_upstream(upstream: *mut c_void) -> Result<*mut gcry_sexp, u32> {
    if upstream.is_null() {
        return Ok(null_mut());
    }

    let needed = unsafe { (api().sexp_sprint)(upstream, GCRYSEXP_FMT_CANON, null_mut(), 0) };
    if needed == 0 {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
    }

    let mut rendered = vec![0u8; needed];
    let written = unsafe {
        (api().sexp_sprint)(
            upstream,
            GCRYSEXP_FMT_CANON,
            rendered.as_mut_ptr().cast(),
            rendered.len(),
        )
    };
    let datalen = if written == 0 { needed - 1 } else { written };

    let mut local = null_mut();
    let rc = sexp::gcry_sexp_sscan(&mut local, null_mut(), rendered.as_ptr().cast(), datalen);
    if rc != 0 {
        return Err(rc);
    }
    Ok(local)
}

pub(crate) fn local_to_upstream_mpi(local: *mut gcry_mpi) -> Result<*mut c_void, u32> {
    if local.is_null() {
        return Ok(null_mut());
    }

    let is_opaque = unsafe { gcry_mpi::as_ref(local) }.is_some_and(gcry_mpi::is_opaque);
    if is_opaque {
        let mut nbits = 0u32;
        let data = crate::mpi::opaque::gcry_mpi_get_opaque(local, &mut nbits);
        let upstream = unsafe { (api().mpi_set_opaque_copy)(null_mut(), data, nbits) };
        if upstream.is_null() && (nbits != 0 || !data.is_null()) {
            return Err(oom_error());
        }
        if upstream.is_null() {
            let zero = unsafe { (api().mpi_new)(0) };
            if zero.is_null() {
                return Err(oom_error());
            }
            return Ok(zero);
        }
        return Ok(upstream);
    }

    let mut data = null_mut();
    let mut datalen = 0usize;
    let rc = crate::mpi::scan::gcry_mpi_aprint(GCRYMPI_FMT_STD, &mut data, &mut datalen, local);
    if rc != 0 {
        return Err(rc);
    }

    let result = if datalen == 0 {
        let zero = unsafe { (api().mpi_new)(0) };
        if zero.is_null() {
            Err(oom_error())
        } else {
            Ok(zero)
        }
    } else {
        let mut upstream = null_mut();
        let rc = unsafe {
            (api().mpi_scan)(
                &mut upstream,
                GCRYMPI_FMT_STD,
                data.cast(),
                datalen,
                null_mut(),
            )
        };
        if rc != 0 { Err(rc) } else { Ok(upstream) }
    };

    alloc::gcry_free(data.cast());
    result
}

pub(crate) fn upstream_to_local_mpi(upstream: *mut c_void) -> Result<*mut gcry_mpi, u32> {
    if upstream.is_null() {
        return Ok(null_mut());
    }

    let is_opaque = unsafe { (api().mpi_get_flag)(upstream, GCRYMPI_FLAG_OPAQUE) != 0 };
    if is_opaque {
        let mut nbits = 0u32;
        let opaque = unsafe { (api().mpi_get_opaque)(upstream, &mut nbits) };
        let local = crate::mpi::opaque::gcry_mpi_set_opaque_copy(null_mut(), opaque, nbits);
        if local.is_null() && (nbits != 0 || !opaque.is_null()) {
            return Err(oom_error());
        }
        return Ok(local);
    }

    let mut needed = 0usize;
    let rc = unsafe { (api().mpi_print)(GCRYMPI_FMT_STD, null_mut(), 0, &mut needed, upstream) };
    if rc != 0 {
        return Err(rc);
    }

    let mut rendered = vec![0u8; needed.max(1)];
    let rc = unsafe {
        (api().mpi_print)(
            GCRYMPI_FMT_STD,
            rendered.as_mut_ptr(),
            rendered.len(),
            &mut needed,
            upstream,
        )
    };
    if rc != 0 {
        return Err(rc);
    }

    let mut local = null_mut();
    let rc = crate::mpi::scan::gcry_mpi_scan(
        &mut local,
        GCRYMPI_FMT_STD,
        rendered.as_ptr().cast(),
        needed,
        null_mut(),
    );
    if rc != 0 {
        return Err(rc);
    }
    Ok(local)
}

pub(crate) fn assign_local_from_upstream_mpi(target: *mut gcry_mpi, upstream: *mut c_void) -> u32 {
    if target.is_null() {
        return 0;
    }

    let local = match upstream_to_local_mpi(upstream) {
        Ok(value) => value,
        Err(err) => return err,
    };
    if local.is_null() {
        crate::mpi::gcry_mpi_set_ui(target, 0);
        return 0;
    }

    crate::mpi::gcry_mpi_set(target, local);
    crate::mpi::gcry_mpi_release(local);
    0
}
