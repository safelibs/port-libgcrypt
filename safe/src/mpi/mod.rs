use std::cmp::Ordering;
use std::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::mem::{MaybeUninit, size_of};
use std::ptr::{copy_nonoverlapping, null, null_mut};

use crate::alloc;
use crate::context;
use crate::error;
use crate::log;
use crate::random;

pub(crate) mod arith;
pub(crate) mod consts;
pub(crate) mod opaque;
pub(crate) mod prime;
pub(crate) mod scan;

pub(crate) const GCRYMPI_FMT_STD: c_int = 1;
pub(crate) const GCRYMPI_FMT_PGP: c_int = 2;
pub(crate) const GCRYMPI_FMT_SSH: c_int = 3;
pub(crate) const GCRYMPI_FMT_HEX: c_int = 4;
pub(crate) const GCRYMPI_FMT_USG: c_int = 5;
pub(crate) const GCRYMPI_FMT_OPAQUE: c_int = 8;

pub(crate) const GCRYMPI_FLAG_SECURE: c_uint = 1;
pub(crate) const GCRYMPI_FLAG_OPAQUE: c_uint = 2;
pub(crate) const GCRYMPI_FLAG_IMMUTABLE: c_uint = 4;
pub(crate) const GCRYMPI_FLAG_CONST: c_uint = 8;
pub(crate) const GCRYMPI_FLAG_USER_MASK: c_uint = 0x0f00;

pub(crate) const GCRY_PRIME_FLAG_SECRET: c_uint = 1 << 0;
pub(crate) const GCRY_PRIME_FLAG_SPECIAL_FACTOR: c_uint = 1 << 1;

pub(crate) const MAX_EXTERN_MPI_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_EXTERN_PGP_BITS: usize = 16_384;

type mp_bitcnt_t = usize;
type mp_size_t = c_long;
type mp_limb_t = c_ulong;

#[derive(Debug)]
#[repr(C)]
pub(crate) struct __mpz_struct {
    _mp_alloc: c_int,
    _mp_size: c_int,
    _mp_d: *mut mp_limb_t,
}

type mpz_ptr = *mut __mpz_struct;
type mpz_srcptr = *const __mpz_struct;

#[link(name = "gmp")]
unsafe extern "C" {
    fn __gmpz_abs(rop: mpz_ptr, op: mpz_srcptr);
    fn __gmpz_add(rop: mpz_ptr, op1: mpz_srcptr, op2: mpz_srcptr);
    fn __gmpz_add_ui(rop: mpz_ptr, op1: mpz_srcptr, op2: c_ulong);
    fn __gmpz_clear(x: mpz_ptr);
    fn __gmpz_clrbit(rop: mpz_ptr, bit_index: mp_bitcnt_t);
    fn __gmpz_cmp(op1: mpz_srcptr, op2: mpz_srcptr) -> c_int;
    fn __gmpz_cmp_ui(op1: mpz_srcptr, op2: c_ulong) -> c_int;
    fn __gmpz_export(
        rop: *mut c_void,
        countp: *mut usize,
        order: c_int,
        size: usize,
        endian: c_int,
        nails: usize,
        op: mpz_srcptr,
    ) -> *mut c_void;
    fn __gmpz_fdiv_q_2exp(rop: mpz_ptr, op1: mpz_srcptr, op2: mp_bitcnt_t);
    fn __gmpz_fdiv_qr(q: mpz_ptr, r: mpz_ptr, n: mpz_srcptr, d: mpz_srcptr);
    fn __gmpz_fdiv_r(rop: mpz_ptr, op1: mpz_srcptr, op2: mpz_srcptr);
    fn __gmpz_fdiv_r_2exp(rop: mpz_ptr, op1: mpz_srcptr, op2: mp_bitcnt_t);
    fn __gmpz_gcd(rop: mpz_ptr, op1: mpz_srcptr, op2: mpz_srcptr);
    fn __gmpz_import(
        rop: mpz_ptr,
        count: usize,
        order: c_int,
        size: usize,
        endian: c_int,
        nails: usize,
        op: *const c_void,
    );
    fn __gmpz_init(x: mpz_ptr);
    fn __gmpz_init2(x: mpz_ptr, n: mp_bitcnt_t);
    fn __gmpz_invert(rop: mpz_ptr, op1: mpz_srcptr, op2: mpz_srcptr) -> c_int;
    fn __gmpz_mod(rop: mpz_ptr, op1: mpz_srcptr, op2: mpz_srcptr);
    fn __gmpz_mul(rop: mpz_ptr, op1: mpz_srcptr, op2: mpz_srcptr);
    fn __gmpz_mul_2exp(rop: mpz_ptr, op1: mpz_srcptr, op2: mp_bitcnt_t);
    fn __gmpz_mul_ui(rop: mpz_ptr, op1: mpz_srcptr, op2: c_ulong);
    fn __gmpz_neg(rop: mpz_ptr, op1: mpz_srcptr);
    fn __gmpz_nextprime(rop: mpz_ptr, op1: mpz_srcptr);
    fn __gmpz_powm(rop: mpz_ptr, base: mpz_srcptr, exp: mpz_srcptr, modu: mpz_srcptr);
    fn __gmpz_powm_sec(rop: mpz_ptr, base: mpz_srcptr, exp: mpz_srcptr, modu: mpz_srcptr);
    fn __gmpz_probab_prime_p(n: mpz_srcptr, reps: c_int) -> c_int;
    fn __gmpz_set(rop: mpz_ptr, op: mpz_srcptr);
    fn __gmpz_set_ui(rop: mpz_ptr, op: c_ulong);
    fn __gmpz_setbit(rop: mpz_ptr, bit_index: mp_bitcnt_t);
    fn __gmpz_sizeinbase(op: mpz_srcptr, base: c_int) -> usize;
    fn __gmpz_sub(rop: mpz_ptr, op1: mpz_srcptr, op2: mpz_srcptr);
    fn __gmpz_sub_ui(rop: mpz_ptr, op1: mpz_srcptr, op2: c_ulong);
    fn __gmpz_swap(op1: mpz_ptr, op2: mpz_ptr);
    fn __gmpz_tdiv_q_2exp(rop: mpz_ptr, op1: mpz_srcptr, op2: mp_bitcnt_t);
    fn __gmpz_tdiv_qr(q: mpz_ptr, r: mpz_ptr, n: mpz_srcptr, d: mpz_srcptr);
    fn __gmpz_tstbit(op: mpz_srcptr, bit_index: mp_bitcnt_t) -> c_int;
}

#[derive(Debug)]
pub(crate) struct Mpz {
    raw: __mpz_struct,
}

impl Mpz {
    pub(crate) fn new(bits: usize) -> Self {
        let mut raw = MaybeUninit::<__mpz_struct>::uninit();
        unsafe {
            if bits == 0 {
                __gmpz_init(raw.as_mut_ptr());
            } else {
                __gmpz_init2(raw.as_mut_ptr(), bits);
            }
            Self {
                raw: raw.assume_init(),
            }
        }
    }

    pub(crate) fn from_ui(value: c_ulong) -> Self {
        let mut result = Self::new(size_of::<c_ulong>() * 8);
        unsafe {
            __gmpz_set_ui(result.as_mut_ptr(), value);
        }
        result
    }

    pub(crate) fn clone_from(src: mpz_srcptr) -> Self {
        let mut result = Self::new(0);
        unsafe {
            __gmpz_set(result.as_mut_ptr(), src);
        }
        result
    }

    pub(crate) fn as_ptr(&self) -> mpz_srcptr {
        &self.raw
    }

    pub(crate) fn as_mut_ptr(&mut self) -> mpz_ptr {
        &mut self.raw
    }
}

impl Drop for Mpz {
    fn drop(&mut self) {
        unsafe {
            __gmpz_clear(self.as_mut_ptr());
        }
    }
}

#[derive(Debug)]
pub(crate) struct OpaqueValue {
    pub(crate) ptr: *mut c_void,
    pub(crate) nbits: c_uint,
}

impl OpaqueValue {
    pub(crate) fn len(&self) -> usize {
        self.nbits.div_ceil(8) as usize
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        if self.ptr.is_null() || self.len() == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr.cast::<u8>(), self.len()) }
        }
    }
}

impl Drop for OpaqueValue {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            alloc::gcry_free(self.ptr);
            self.ptr = null_mut();
        }
    }
}

#[derive(Debug)]
pub(crate) enum MpiKind {
    Numeric(Mpz),
    Opaque(OpaqueValue),
}

#[derive(Debug)]
pub struct gcry_mpi {
    pub(crate) kind: MpiKind,
    pub(crate) secure: bool,
    immutable: bool,
    const_flag: bool,
    user_flags: c_uint,
    secret_sensitive: bool,
}

impl Drop for gcry_mpi {
    fn drop(&mut self) {
        context::remove_object((self as *mut Self).cast());
    }
}

impl gcry_mpi {
    fn new_numeric(bits: usize, secure: bool) -> *mut gcry_mpi {
        let raw = Box::into_raw(Box::new(Self {
            kind: MpiKind::Numeric(Mpz::new(bits)),
            secure,
            immutable: false,
            const_flag: false,
            user_flags: 0,
            secret_sensitive: secure,
        }));
        context::set_object_secure(raw.cast(), secure);
        raw
    }

    pub(crate) fn from_numeric(value: Mpz, secure: bool) -> *mut gcry_mpi {
        let raw = Box::into_raw(Box::new(Self {
            kind: MpiKind::Numeric(value),
            secure,
            immutable: false,
            const_flag: false,
            user_flags: 0,
            secret_sensitive: secure,
        }));
        context::set_object_secure(raw.cast(), secure);
        raw
    }

    pub(crate) unsafe fn as_ref<'a>(ptr: *const gcry_mpi) -> Option<&'a gcry_mpi> {
        unsafe { ptr.as_ref() }
    }

    pub(crate) unsafe fn as_mut<'a>(ptr: *mut gcry_mpi) -> Option<&'a mut gcry_mpi> {
        unsafe { ptr.as_mut() }
    }

    pub(crate) fn sync_secure_registration(&self) {
        context::set_object_secure((self as *const Self).cast(), self.secure);
    }

    pub(crate) fn set_secure_flag(&mut self, secure: bool) {
        self.secure = secure;
        if secure {
            self.secret_sensitive = true;
        }
        self.sync_secure_registration();
    }

    pub(crate) fn is_opaque(&self) -> bool {
        matches!(self.kind, MpiKind::Opaque(_))
    }

    pub(crate) fn opaque(&self) -> Option<&OpaqueValue> {
        match &self.kind {
            MpiKind::Opaque(value) => Some(value),
            MpiKind::Numeric(_) => None,
        }
    }

    pub(crate) fn numeric(&self) -> Option<&Mpz> {
        match &self.kind {
            MpiKind::Numeric(value) => Some(value),
            MpiKind::Opaque(_) => None,
        }
    }

    pub(crate) fn numeric_mut(&mut self) -> &mut Mpz {
        if self.is_opaque() {
            self.kind = MpiKind::Numeric(Mpz::new(0));
        }
        match &mut self.kind {
            MpiKind::Numeric(value) => value,
            MpiKind::Opaque(_) => unreachable!(),
        }
    }

    pub(crate) fn clear_special_flags(&mut self) {
        self.immutable = false;
        self.const_flag = false;
    }

    pub(crate) fn deep_copy(&self) -> *mut gcry_mpi {
        let kind = match &self.kind {
            MpiKind::Numeric(value) => MpiKind::Numeric(Mpz::clone_from(value.as_ptr())),
            MpiKind::Opaque(value) => MpiKind::Opaque(copy_opaque_value(value, self.secure)),
        };
        let raw = Box::into_raw(Box::new(Self {
            kind,
            secure: self.secure,
            immutable: false,
            const_flag: false,
            user_flags: self.user_flags,
            secret_sensitive: self.secret_sensitive,
        }));
        context::set_object_secure(raw.cast(), self.secure);
        raw
    }

    pub(crate) fn overwrite_from(&mut self, other: &gcry_mpi) {
        self.kind = match &other.kind {
            MpiKind::Numeric(value) => MpiKind::Numeric(Mpz::clone_from(value.as_ptr())),
            MpiKind::Opaque(value) => MpiKind::Opaque(copy_opaque_value(value, self.secure)),
        };
        self.clear_special_flags();
        self.user_flags = other.user_flags;
        self.secret_sensitive = self.secret_sensitive || other.secret_sensitive;
    }
}

pub(crate) fn copy_opaque_value(value: &OpaqueValue, secure: bool) -> OpaqueValue {
    let len = value.len();
    let ptr = if len == 0 {
        null_mut()
    } else {
        let raw = if secure {
            alloc::gcry_malloc_secure(len)
        } else {
            alloc::gcry_malloc(len)
        };
        if raw.is_null() {
            return OpaqueValue {
                ptr: null_mut(),
                nbits: value.nbits,
            };
        }
        unsafe {
            copy_nonoverlapping(value.ptr.cast::<u8>(), raw.cast::<u8>(), len);
        }
        raw
    };
    OpaqueValue {
        ptr,
        nbits: value.nbits,
    }
}

pub(crate) fn alloc_output_bytes(bytes: &[u8], secure: bool) -> *mut c_void {
    if bytes.is_empty() {
        return null_mut();
    }

    let ptr = if secure {
        alloc::gcry_malloc_secure(bytes.len())
    } else {
        alloc::gcry_malloc(bytes.len())
    };
    if ptr.is_null() {
        return null_mut();
    }
    unsafe {
        copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
    }
    ptr
}

pub(crate) fn abs_to_bytes(value: &gcry_mpi) -> Vec<u8> {
    match &value.kind {
        MpiKind::Opaque(opaque) => opaque.as_slice().to_vec(),
        MpiKind::Numeric(number) => numeric_abs_to_bytes(number.as_ptr()),
    }
}

pub(crate) fn numeric_abs_to_bytes(value: mpz_srcptr) -> Vec<u8> {
    let mut tmp = Mpz::new(0);
    unsafe {
        __gmpz_abs(tmp.as_mut_ptr(), value);
    }
    export_unsigned(tmp.as_ptr())
}

pub(crate) fn export_unsigned(value: mpz_srcptr) -> Vec<u8> {
    if unsafe { mpz_sgn(value) } == 0 {
        return Vec::new();
    }

    let nbits = unsafe { __gmpz_sizeinbase(value, 2) };
    let nbytes = nbits.div_ceil(8);
    let mut out = vec![0u8; nbytes];
    let mut written = 0usize;
    unsafe {
        __gmpz_export(
            out.as_mut_ptr().cast(),
            &mut written,
            1,
            1,
            1,
            0,
            value,
        );
    }
    out.truncate(written);
    out
}

pub(crate) unsafe fn mpz_sgn(value: mpz_srcptr) -> c_int {
    if value.is_null() {
        0
    } else {
        unsafe { (*value)._mp_size.signum() }
    }
}

pub(crate) fn import_unsigned_bytes(bytes: &[u8]) -> Mpz {
    let mut result = Mpz::new(bytes.len() * 8);
    if !bytes.is_empty() {
        unsafe {
            __gmpz_import(
                result.as_mut_ptr(),
                bytes.len(),
                1,
                1,
                1,
                0,
                bytes.as_ptr().cast(),
            );
        }
    }
    result
}

pub(crate) fn cmp_opaque(left: &OpaqueValue, right: &OpaqueValue) -> c_int {
    match left.nbits.cmp(&right.nbits) {
        Ordering::Less => return -1,
        Ordering::Greater => return 1,
        Ordering::Equal => {}
    }

    for (a, b) in left.as_slice().iter().zip(right.as_slice().iter()) {
        match a.cmp(b) {
            Ordering::Less => return -1,
            Ordering::Greater => return 1,
            Ordering::Equal => {}
        }
    }
    0
}

pub(crate) fn compare(left: &gcry_mpi, right: &gcry_mpi) -> c_int {
    match (&left.kind, &right.kind) {
        (MpiKind::Opaque(l), MpiKind::Opaque(r)) => cmp_opaque(l, r),
        (MpiKind::Opaque(_), MpiKind::Numeric(_)) => -1,
        (MpiKind::Numeric(_), MpiKind::Opaque(_)) => 1,
        (MpiKind::Numeric(l), MpiKind::Numeric(r)) => unsafe { __gmpz_cmp(l.as_ptr(), r.as_ptr()) },
    }
}

pub(crate) fn make_result_numeric(dest: *mut gcry_mpi, secure_hint: bool) -> *mut gcry_mpi {
    if dest.is_null() {
        gcry_mpi::new_numeric(0, secure_hint)
    } else {
        let dest_ref = unsafe { &mut *dest };
        dest_ref.kind = MpiKind::Numeric(Mpz::new(0));
        if secure_hint {
            dest_ref.set_secure_flag(true);
        }
        dest_ref.clear_special_flags();
        dest
    }
}

pub(crate) fn maybe_secret_powm(exponent: &gcry_mpi, modu: &gcry_mpi) -> bool {
    exponent.secret_sensitive || exponent.secure || modu.secret_sensitive || modu.secure
}

pub(crate) fn cmp_zero(value: &gcry_mpi) -> Ordering {
    match &value.kind {
        MpiKind::Opaque(opaque) => {
            if opaque.nbits == 0 || opaque.as_slice().iter().all(|byte| *byte == 0) {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        MpiKind::Numeric(number) => match unsafe { mpz_sgn(number.as_ptr()) }.cmp(&0) {
            Ordering::Less => Ordering::Less,
            Ordering::Equal => Ordering::Equal,
            Ordering::Greater => Ordering::Greater,
        },
    }
}

pub(crate) fn set_numeric_from_u64(dest: *mut gcry_mpi, value: c_ulong, secure_hint: bool) -> *mut gcry_mpi {
    let dest = make_result_numeric(dest, secure_hint);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), value);
        }
    }
    dest
}

pub(crate) fn set_errno_oom() -> u32 {
    error::gcry_error_from_errno(crate::ENOMEM_VALUE)
}

pub(crate) fn mpi_printable_hex(value: &gcry_mpi) -> String {
    let bytes = scan::mpi_to_hex_bytes(value);
    String::from_utf8_lossy(&bytes).into_owned()
}

#[unsafe(export_name = "gcry_mpi_new")]
pub extern "C" fn gcry_mpi_new(nbits: c_uint) -> *mut gcry_mpi {
    gcry_mpi::new_numeric(nbits as usize, false)
}

#[unsafe(export_name = "gcry_mpi_snew")]
pub extern "C" fn gcry_mpi_snew(nbits: c_uint) -> *mut gcry_mpi {
    gcry_mpi::new_numeric(nbits as usize, true)
}

#[unsafe(export_name = "gcry_mpi_release")]
pub extern "C" fn gcry_mpi_release(a: *mut gcry_mpi) {
    if a.is_null() {
        return;
    }

    let is_const = unsafe { (*a).const_flag };
    if is_const {
        return;
    }

    unsafe {
        drop(Box::from_raw(a));
    }
}

#[unsafe(export_name = "gcry_mpi_copy")]
pub extern "C" fn gcry_mpi_copy(a: *const gcry_mpi) -> *mut gcry_mpi {
    unsafe { gcry_mpi::as_ref(a).map_or(null_mut(), gcry_mpi::deep_copy) }
}

#[unsafe(export_name = "gcry_mpi_snatch")]
pub extern "C" fn gcry_mpi_snatch(w: *mut gcry_mpi, u: *mut gcry_mpi) {
    if w.is_null() || u.is_null() || w == u {
        return;
    }

    unsafe {
        if let (Some(dest), Some(src)) = (gcry_mpi::as_mut(w), gcry_mpi::as_ref(u)) {
            dest.overwrite_from(src);
        }
    }
    gcry_mpi_release(u);
}

#[unsafe(export_name = "gcry_mpi_set")]
pub extern "C" fn gcry_mpi_set(w: *mut gcry_mpi, u: *const gcry_mpi) -> *mut gcry_mpi {
    let Some(src) = (unsafe { gcry_mpi::as_ref(u) }) else {
        return null_mut();
    };
    if w.is_null() {
        return src.deep_copy();
    }
    if std::ptr::eq(w as *const gcry_mpi, u) {
        return w;
    }
    unsafe {
        if let Some(dest) = gcry_mpi::as_mut(w) {
            dest.overwrite_from(src);
            return w;
        }
    }
    null_mut()
}

#[unsafe(export_name = "gcry_mpi_set_ui")]
pub extern "C" fn gcry_mpi_set_ui(w: *mut gcry_mpi, u: c_ulong) -> *mut gcry_mpi {
    set_numeric_from_u64(w, u, unsafe { gcry_mpi::as_ref(w).is_some_and(|mpi| mpi.secure) })
}

#[unsafe(export_name = "gcry_mpi_get_ui")]
pub extern "C" fn gcry_mpi_get_ui(w: *mut c_uint, u: *mut gcry_mpi) -> u32 {
    let Some(value) = (unsafe { gcry_mpi::as_ref(u) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };

    if value.is_opaque() {
        return error::gcry_error_from_code(error::GPG_ERR_ERANGE);
    }

    let number = value.numeric().expect("numeric checked");
    let sign = unsafe { mpz_sgn(number.as_ptr()) };
    if sign < 0 || unsafe { __gmpz_cmp_ui(number.as_ptr(), c_uint::MAX as c_ulong) } > 0 {
        return error::gcry_error_from_code(error::GPG_ERR_ERANGE);
    }
    if !w.is_null() {
        unsafe {
            *w = export_unsigned(number.as_ptr())
                .iter()
                .fold(0u32, |acc, byte| (acc << 8) | (*byte as u32));
        }
    }
    0
}

#[unsafe(export_name = "gcry_mpi_swap")]
pub extern "C" fn gcry_mpi_swap(a: *mut gcry_mpi, b: *mut gcry_mpi) {
    if a.is_null() || b.is_null() || a == b {
        return;
    }
    unsafe {
        std::mem::swap(&mut *a, &mut *b);
        (*a).sync_secure_registration();
        (*b).sync_secure_registration();
    }
}

#[unsafe(export_name = "gcry_mpi_is_neg")]
pub extern "C" fn gcry_mpi_is_neg(a: *mut gcry_mpi) -> c_int {
    unsafe {
        gcry_mpi::as_ref(a).map_or(0, |mpi| match &mpi.kind {
            MpiKind::Opaque(_) => 0,
            MpiKind::Numeric(value) => (mpz_sgn(value.as_ptr()) < 0) as c_int,
        })
    }
}

#[unsafe(export_name = "gcry_mpi_neg")]
pub extern "C" fn gcry_mpi_neg(w: *mut gcry_mpi, u: *mut gcry_mpi) {
    let snapshot = gcry_mpi_copy(u);
    let Some(src) = (unsafe { gcry_mpi::as_ref(snapshot) }) else {
        return;
    };
    let secure_hint = src.secure;
    let dest = make_result_numeric(w, secure_hint);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            match &src.kind {
                MpiKind::Opaque(_) => {
                    __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0);
                }
                MpiKind::Numeric(value) => {
                    __gmpz_neg(dest_ref.numeric_mut().as_mut_ptr(), value.as_ptr());
                }
            }
        }
    }
    gcry_mpi_release(snapshot);
}

#[unsafe(export_name = "gcry_mpi_abs")]
pub extern "C" fn gcry_mpi_abs(w: *mut gcry_mpi) {
    let snapshot = gcry_mpi_copy(w);
    let Some(src) = (unsafe { gcry_mpi::as_ref(snapshot) }) else {
        return;
    };
    unsafe {
        if let Some(dest) = gcry_mpi::as_mut(w) {
            match &src.kind {
                MpiKind::Numeric(value) => __gmpz_abs(dest.numeric_mut().as_mut_ptr(), value.as_ptr()),
                MpiKind::Opaque(_) => __gmpz_set_ui(dest.numeric_mut().as_mut_ptr(), 0),
            }
        }
    }
    gcry_mpi_release(snapshot);
}

#[unsafe(export_name = "gcry_mpi_cmp")]
pub extern "C" fn gcry_mpi_cmp(u: *const gcry_mpi, v: *const gcry_mpi) -> c_int {
    match (unsafe { gcry_mpi::as_ref(u) }, unsafe { gcry_mpi::as_ref(v) }) {
        (Some(left), Some(right)) => compare(left, right),
        (Some(_), None) => 1,
        (None, Some(_)) => -1,
        (None, None) => 0,
    }
}

#[unsafe(export_name = "gcry_mpi_cmp_ui")]
pub extern "C" fn gcry_mpi_cmp_ui(u: *const gcry_mpi, v: c_ulong) -> c_int {
    let Some(left) = (unsafe { gcry_mpi::as_ref(u) }) else {
        return -1;
    };
    match &left.kind {
        MpiKind::Opaque(_) => -1,
        MpiKind::Numeric(value) => unsafe { __gmpz_cmp_ui(value.as_ptr(), v) },
    }
}

#[unsafe(export_name = "gcry_mpi_get_nbits")]
pub extern "C" fn gcry_mpi_get_nbits(a: *mut gcry_mpi) -> c_uint {
    let Some(value) = (unsafe { gcry_mpi::as_ref(a) }) else {
        return 0;
    };
    match &value.kind {
        MpiKind::Opaque(opaque) => opaque.nbits,
        MpiKind::Numeric(number) => {
            if unsafe { mpz_sgn(number.as_ptr()) } == 0 {
                0
            } else {
                let mut tmp = Mpz::clone_from(number.as_ptr());
                unsafe {
                    __gmpz_abs(tmp.as_mut_ptr(), tmp.as_ptr());
                    __gmpz_sizeinbase(tmp.as_ptr(), 2) as c_uint
                }
            }
        }
    }
}

#[unsafe(export_name = "gcry_mpi_test_bit")]
pub extern "C" fn gcry_mpi_test_bit(a: *mut gcry_mpi, n: c_uint) -> c_int {
    let Some(value) = (unsafe { gcry_mpi::as_ref(a) }) else {
        return 0;
    };
    match &value.kind {
        MpiKind::Opaque(opaque) => {
            let bit = n as usize;
            let total = opaque.nbits as usize;
            if bit >= total {
                return 0;
            }
            let byte_index = opaque.len().saturating_sub(1 + bit / 8);
            let mask = 1u8 << (bit % 8);
            opaque.as_slice().get(byte_index).map_or(0, |byte| ((byte & mask) != 0) as c_int)
        }
        MpiKind::Numeric(number) => {
            let mut tmp = Mpz::clone_from(number.as_ptr());
            unsafe {
                __gmpz_abs(tmp.as_mut_ptr(), tmp.as_ptr());
                __gmpz_tstbit(tmp.as_ptr(), n as usize)
            }
        }
    }
}

#[unsafe(export_name = "gcry_mpi_set_bit")]
pub extern "C" fn gcry_mpi_set_bit(a: *mut gcry_mpi, n: c_uint) {
    let Some(dest) = (unsafe { gcry_mpi::as_mut(a) }) else {
        return;
    };
    unsafe {
        __gmpz_setbit(dest.numeric_mut().as_mut_ptr(), n as usize);
    }
}

#[unsafe(export_name = "gcry_mpi_clear_bit")]
pub extern "C" fn gcry_mpi_clear_bit(a: *mut gcry_mpi, n: c_uint) {
    let Some(dest) = (unsafe { gcry_mpi::as_mut(a) }) else {
        return;
    };
    unsafe {
        __gmpz_clrbit(dest.numeric_mut().as_mut_ptr(), n as usize);
    }
}

#[unsafe(export_name = "gcry_mpi_set_highbit")]
pub extern "C" fn gcry_mpi_set_highbit(a: *mut gcry_mpi, n: c_uint) {
    let Some(dest) = (unsafe { gcry_mpi::as_mut(a) }) else {
        return;
    };
    let mut tmp = Mpz::clone_from(dest.numeric_mut().as_ptr());
    unsafe {
        __gmpz_fdiv_r_2exp(tmp.as_mut_ptr(), tmp.as_ptr(), (n as usize) + 1);
        __gmpz_setbit(tmp.as_mut_ptr(), n as usize);
        __gmpz_set(dest.numeric_mut().as_mut_ptr(), tmp.as_ptr());
    }
}

#[unsafe(export_name = "gcry_mpi_clear_highbit")]
pub extern "C" fn gcry_mpi_clear_highbit(a: *mut gcry_mpi, n: c_uint) {
    let Some(dest) = (unsafe { gcry_mpi::as_mut(a) }) else {
        return;
    };
    let mut tmp = Mpz::clone_from(dest.numeric_mut().as_ptr());
    unsafe {
        __gmpz_fdiv_r_2exp(tmp.as_mut_ptr(), tmp.as_ptr(), n as usize);
        __gmpz_set(dest.numeric_mut().as_mut_ptr(), tmp.as_ptr());
    }
}

#[unsafe(export_name = "gcry_mpi_rshift")]
pub extern "C" fn gcry_mpi_rshift(x: *mut gcry_mpi, a: *mut gcry_mpi, n: c_uint) {
    let snapshot = gcry_mpi_copy(a);
    let Some(src) = (unsafe { gcry_mpi::as_ref(snapshot) }) else {
        return;
    };
    let dest = make_result_numeric(x, src.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            match &src.kind {
                MpiKind::Opaque(_) => __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0),
                MpiKind::Numeric(value) => {
                    __gmpz_tdiv_q_2exp(dest_ref.numeric_mut().as_mut_ptr(), value.as_ptr(), n as usize);
                }
            }
        }
    }
    gcry_mpi_release(snapshot);
}

#[unsafe(export_name = "gcry_mpi_lshift")]
pub extern "C" fn gcry_mpi_lshift(x: *mut gcry_mpi, a: *mut gcry_mpi, n: c_uint) {
    let snapshot = gcry_mpi_copy(a);
    let Some(src) = (unsafe { gcry_mpi::as_ref(snapshot) }) else {
        return;
    };
    let dest = make_result_numeric(x, src.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            match &src.kind {
                MpiKind::Opaque(_) => __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0),
                MpiKind::Numeric(value) => {
                    __gmpz_mul_2exp(dest_ref.numeric_mut().as_mut_ptr(), value.as_ptr(), n as usize);
                }
            }
        }
    }
    gcry_mpi_release(snapshot);
}

#[unsafe(export_name = "gcry_mpi_set_flag")]
pub extern "C" fn gcry_mpi_set_flag(a: *mut gcry_mpi, flag: c_int) {
    let Some(value) = (unsafe { gcry_mpi::as_mut(a) }) else {
        return;
    };
    match flag as c_uint {
        GCRYMPI_FLAG_SECURE => value.set_secure_flag(true),
        GCRYMPI_FLAG_IMMUTABLE => value.immutable = true,
        GCRYMPI_FLAG_CONST => {
            value.const_flag = true;
            value.immutable = true;
        }
        bits if bits & GCRYMPI_FLAG_USER_MASK != 0 => value.user_flags |= bits & GCRYMPI_FLAG_USER_MASK,
        _ => {}
    }
}

#[unsafe(export_name = "gcry_mpi_clear_flag")]
pub extern "C" fn gcry_mpi_clear_flag(a: *mut gcry_mpi, flag: c_int) {
    let Some(value) = (unsafe { gcry_mpi::as_mut(a) }) else {
        return;
    };
    match flag as c_uint {
        GCRYMPI_FLAG_IMMUTABLE if !value.const_flag => value.immutable = false,
        bits if bits & GCRYMPI_FLAG_USER_MASK != 0 => value.user_flags &= !(bits & GCRYMPI_FLAG_USER_MASK),
        _ => {}
    }
}

#[unsafe(export_name = "gcry_mpi_get_flag")]
pub extern "C" fn gcry_mpi_get_flag(a: *mut gcry_mpi, flag: c_int) -> c_int {
    let Some(value) = (unsafe { gcry_mpi::as_ref(a) }) else {
        return 0;
    };
    let set = match flag as c_uint {
        GCRYMPI_FLAG_SECURE => value.secure,
        GCRYMPI_FLAG_OPAQUE => value.is_opaque(),
        GCRYMPI_FLAG_IMMUTABLE => value.immutable,
        GCRYMPI_FLAG_CONST => value.const_flag,
        bits if bits & GCRYMPI_FLAG_USER_MASK != 0 => value.user_flags & bits != 0,
        _ => false,
    };
    set as c_int
}

#[unsafe(export_name = "gcry_mpi_randomize")]
pub extern "C" fn gcry_mpi_randomize(w: *mut gcry_mpi, nbits: c_uint, level: c_int) {
    let Some(dest) = (unsafe { gcry_mpi::as_mut(w) }) else {
        return;
    };
    if nbits == 0 {
        unsafe {
            __gmpz_set_ui(dest.numeric_mut().as_mut_ptr(), 0);
        }
        return;
    }

    let nbytes = (nbits as usize).div_ceil(8);
    let mut bytes = vec![0u8; nbytes];
    random::fill_mpi_random(&mut bytes, level);
    let excess_bits = nbytes * 8 - nbits as usize;
    if excess_bits != 0 {
        bytes[0] &= 0xff >> excess_bits;
    }
    bytes[0] |= 1u8 << (7 - excess_bits);
    let imported = import_unsigned_bytes(&bytes);
    dest.kind = MpiKind::Numeric(imported);
}

#[unsafe(export_name = "gcry_mpi_dump")]
pub extern "C" fn gcry_mpi_dump(a: *const gcry_mpi) {
    let text = if let Some(value) = unsafe { gcry_mpi::as_ref(a) } {
        format!(" {}", mpi_printable_hex(value))
    } else {
        " [null]".to_string()
    };
    log::emit_message(log::GCRY_LOG_INFO, &text);
}

#[unsafe(export_name = "gcry_log_debugmpi")]
pub extern "C" fn gcry_log_debugmpi(text: *const c_char, mpi: *mut gcry_mpi) {
    let prefix = if text.is_null() {
        "mpi".to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned()
    };
    let suffix = if let Some(value) = unsafe { gcry_mpi::as_ref(mpi) } {
        mpi_printable_hex(value)
    } else {
        "[null]".to_string()
    };
    log::emit_message(log::GCRY_LOG_DEBUG, &format!("{prefix}: {suffix}"));
}
