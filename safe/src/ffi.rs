use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::ptr::{copy_nonoverlapping, null_mut};
use std::sync::{Mutex, OnceLock};

const PACKAGE_VERSION: &[u8] = b"1.10.3\0";
const CONFIG_ALL: &[u8] =
    b"version:1.10.3\ncpu-arch:x86_64\nrng-type:standard:strong:very-strong:system:quick:secure\n\0";
const CONFIG_VERSION: &[u8] = b"version:1.10.3\0";
const CONFIG_CPU_ARCH: &[u8] = b"cpu-arch:x86_64\0";
const CONFIG_RNG_TYPE: &[u8] = b"rng-type:standard:strong:very-strong:system:quick:secure\0";
const STR_SUCCESS: &[u8] = b"Success\0";
const STR_GCRYPT: &[u8] = b"gcrypt\0";
const STR_NOT_IMPLEMENTED: &[u8] = b"Not implemented\0";
const STR_OUT_OF_MEMORY: &[u8] = b"Out of memory\0";
const STR_STUB_ERROR: &[u8] = b"libgcrypt compatibility stub\0";

const DEFAULT_SECMEM_POOL_SIZE: usize = 16 * 1024;
const SECURE_POOL_OVERHEAD: usize = 32;
const ENOMEM_VALUE: c_int = 12;

const GCRYCTL_DUMP_SECMEM_STATS: u32 = 14;
const GCRYCTL_SET_VERBOSITY: u32 = 19;
const GCRYCTL_SET_DEBUG_FLAGS: u32 = 20;
const GCRYCTL_INIT_SECMEM: u32 = 24;
const GCRYCTL_TERM_SECMEM: u32 = 25;
const GCRYCTL_DISABLE_SECMEM_WARN: u32 = 27;
const GCRYCTL_DISABLE_SECMEM: u32 = 37;
const GCRYCTL_INITIALIZATION_FINISHED: u32 = 38;
const GCRYCTL_INITIALIZATION_FINISHED_P: u32 = 39;
const GCRYCTL_ANY_INITIALIZATION_P: u32 = 40;
const GCRYCTL_ENABLE_QUICK_RANDOM: u32 = 44;
const GCRYCTL_FAST_POLL: u32 = 48;
const GCRYCTL_PRINT_CONFIG: u32 = 53;
const GCRYCTL_OPERATIONAL_P: u32 = 54;
const GCRYCTL_FIPS_MODE_P: u32 = 55;
const GCRYCTL_DISABLE_HWF: u32 = 63;

const GPG_ERR_SOURCE_GCRYPT: u32 = 1;
const GPG_ERR_SOURCE_SHIFT: u32 = 24;
const GPG_ERR_CODE_MASK: u32 = 0xffff;
const GPG_ERR_SYSTEM_ERROR: u32 = 1 << 15;
const GPG_ERR_NOT_IMPLEMENTED: u32 = 69;

type FILE = c_void;
type gcry_error_t = u32;
type gpg_error_t = u32;
type gcry_handler_no_mem_t = Option<unsafe extern "C" fn(*mut c_void, usize, c_uint) -> c_int>;

extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn fwrite(ptr: *const c_void, size: usize, nmemb: usize, stream: *mut FILE) -> usize;
    fn __errno_location() -> *mut c_int;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecureClass {
    Base,
    Overflow,
}

#[derive(Clone, Copy, Debug)]
struct AllocationRecord {
    charge: usize,
    secure: Option<SecureClass>,
}

#[derive(Clone, Copy, Debug)]
struct OutOfCoreHandler {
    callback: gcry_handler_no_mem_t,
    opaque: *mut c_void,
}

unsafe impl Send for OutOfCoreHandler {}

impl Default for OutOfCoreHandler {
    fn default() -> Self {
        Self {
            callback: None,
            opaque: std::ptr::null_mut(),
        }
    }
}

#[derive(Debug)]
struct GlobalState {
    allocations: HashMap<usize, AllocationRecord>,
    secmem_pool_size: usize,
    secmem_pool_used: usize,
    secmem_initialized: bool,
    initialization_finished: bool,
    any_initialization_done: bool,
    secmem_disabled: bool,
    secmem_warn_disabled: bool,
    verbosity: c_int,
    debug_flags: u32,
    outofcore: OutOfCoreHandler,
    prng_state: u64,
}

impl Default for GlobalState {
    fn default() -> Self {
        Self {
            allocations: HashMap::new(),
            secmem_pool_size: DEFAULT_SECMEM_POOL_SIZE,
            secmem_pool_used: 0,
            secmem_initialized: false,
            initialization_finished: false,
            any_initialization_done: false,
            secmem_disabled: false,
            secmem_warn_disabled: false,
            verbosity: 0,
            debug_flags: 0,
            outofcore: OutOfCoreHandler::default(),
            prng_state: 0x1a2b_3c4d_5e6f_7788,
        }
    }
}

fn state() -> &'static Mutex<GlobalState> {
    static STATE: OnceLock<Mutex<GlobalState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(GlobalState::default()))
}

fn lock_state() -> std::sync::MutexGuard<'static, GlobalState> {
    match state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn set_errno(value: c_int) {
    unsafe {
        *__errno_location() = value;
    }
}

fn allocation_size(size: usize) -> usize {
    size.max(1)
}

fn secure_limit(state: &GlobalState) -> usize {
    if state.secmem_initialized {
        state.secmem_pool_size.max(DEFAULT_SECMEM_POOL_SIZE)
    } else {
        DEFAULT_SECMEM_POOL_SIZE
    }
}

fn make_error(source: u32, code: u32) -> u32 {
    ((source & 0x7f) << GPG_ERR_SOURCE_SHIFT) | (code & GPG_ERR_CODE_MASK)
}

fn system_code_from_errno(err: c_int) -> u32 {
    if err <= 0 {
        0
    } else {
        GPG_ERR_SYSTEM_ERROR | ((err as u32) & 0x7fff)
    }
}

fn alloc_raw(size: usize, zeroed: bool) -> *mut c_void {
    unsafe {
        if zeroed {
            calloc(1, size)
        } else {
            malloc(size)
        }
    }
}

fn record_allocation(
    state: &mut GlobalState,
    ptr: *mut c_void,
    size: usize,
    secure: Option<SecureClass>,
) -> *mut c_void {
    if ptr.is_null() {
        return ptr;
    }

    let charge = if secure == Some(SecureClass::Base) {
        size + SECURE_POOL_OVERHEAD
    } else {
        0
    };

    if secure == Some(SecureClass::Base) {
        state.secmem_pool_used += charge;
    }

    state.allocations.insert(
        ptr as usize,
        AllocationRecord {
            charge,
            secure,
        },
    );
    ptr
}

fn plain_alloc(state: &mut GlobalState, size: usize, zeroed: bool) -> *mut c_void {
    let size = allocation_size(size);
    let ptr = alloc_raw(size, zeroed);
    if ptr.is_null() {
        set_errno(ENOMEM_VALUE);
        return null_mut();
    }
    record_allocation(state, ptr, size, None)
}

fn secure_alloc(
    state: &mut GlobalState,
    size: usize,
    zeroed: bool,
    allow_overflow: bool,
) -> *mut c_void {
    if state.secmem_disabled {
        return plain_alloc(state, size, zeroed);
    }

    let size = allocation_size(size);
    let base_charge = size + SECURE_POOL_OVERHEAD;
    let secure_class = if state.secmem_pool_used + base_charge <= secure_limit(state) {
        Some(SecureClass::Base)
    } else if allow_overflow {
        Some(SecureClass::Overflow)
    } else {
        None
    };

    let Some(secure_class) = secure_class else {
        set_errno(ENOMEM_VALUE);
        return null_mut();
    };

    let ptr = alloc_raw(size, zeroed);
    if ptr.is_null() {
        set_errno(ENOMEM_VALUE);
        return null_mut();
    }

    record_allocation(state, ptr, size, Some(secure_class))
}

fn remove_allocation(state: &mut GlobalState, ptr: *mut c_void) -> Option<AllocationRecord> {
    let removed = state.allocations.remove(&(ptr as usize));
    if let Some(record) = removed {
        if record.secure == Some(SecureClass::Base) {
            state.secmem_pool_used = state.secmem_pool_used.saturating_sub(record.charge);
        }
    }
    removed
}

fn realloc_tracked(ptr: *mut c_void, new_size: usize) -> *mut c_void {
    unsafe { realloc(ptr, allocation_size(new_size)) }
}

fn fill_random_bytes(state: &mut GlobalState, buffer: &mut [u8]) {
    for byte in buffer {
        let mut x = state.prng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.prng_state = x;
        *byte = (x & 0xff) as u8;
    }
}

fn duplicate_static_bytes(state: &mut GlobalState, bytes: &[u8]) -> *mut c_char {
    let ptr = plain_alloc(state, bytes.len(), false);
    if ptr.is_null() {
        return null_mut();
    }

    unsafe {
        copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
    }
    ptr.cast()
}

fn version_tuple(input: &str) -> Option<(u32, u32, u32)> {
    let text = input.rsplit(':').next().unwrap_or(input).trim();
    let mut parts = text.split('.');
    let major = parts.next()?.chars().take_while(|ch| ch.is_ascii_digit()).collect::<String>();
    let minor = parts.next()?.chars().take_while(|ch| ch.is_ascii_digit()).collect::<String>();
    let micro = parts.next()?.chars().take_while(|ch| ch.is_ascii_digit()).collect::<String>();

    Some((
        major.parse().ok()?,
        minor.parse().ok()?,
        micro.parse().ok()?,
    ))
}

fn version_matches(requirement: &CStr) -> bool {
    let req = requirement.to_string_lossy();
    match (version_tuple(&req), version_tuple("1.10.3")) {
        (Some(req_tuple), Some(cur_tuple)) => req_tuple <= cur_tuple,
        _ => req == "1.10.3",
    }
}

fn config_item_bytes(what: Option<&CStr>) -> Option<&'static [u8]> {
    match what.map(|item| item.to_bytes()) {
        None => Some(CONFIG_ALL),
        Some(b"version") => Some(CONFIG_VERSION),
        Some(b"cpu-arch") => Some(CONFIG_CPU_ARCH),
        Some(b"rng-type") => Some(CONFIG_RNG_TYPE),
        _ => None,
    }
}

fn error_string(err: u32) -> &'static [u8] {
    if err == 0 {
        STR_SUCCESS
    } else if err == GPG_ERR_NOT_IMPLEMENTED {
        STR_NOT_IMPLEMENTED
    } else if gcry_err_code_to_errno(err) == ENOMEM_VALUE {
        STR_OUT_OF_MEMORY
    } else {
        STR_STUB_ERROR
    }
}

#[export_name = "safe_gcry_check_version"]
pub extern "C" fn gcry_check_version(req_version: *const c_char) -> *const c_char {
    if req_version.is_null() {
        return PACKAGE_VERSION.as_ptr().cast();
    }

    let requirement = unsafe { CStr::from_ptr(req_version) };
    if version_matches(requirement) {
        PACKAGE_VERSION.as_ptr().cast()
    } else {
        std::ptr::null()
    }
}

#[export_name = "safe_gcry_err_code_from_errno"]
pub extern "C" fn gcry_err_code_from_errno(err: c_int) -> u32 {
    system_code_from_errno(err)
}

#[export_name = "safe_gcry_err_code_to_errno"]
pub extern "C" fn gcry_err_code_to_errno(code: u32) -> c_int {
    (code & 0x7fff) as c_int
}

#[export_name = "safe_gcry_err_make_from_errno"]
pub extern "C" fn gcry_err_make_from_errno(source: u32, err: c_int) -> u32 {
    make_error(source, system_code_from_errno(err))
}

#[export_name = "safe_gcry_error_from_errno"]
pub extern "C" fn gcry_error_from_errno(err: c_int) -> u32 {
    gcry_err_make_from_errno(GPG_ERR_SOURCE_GCRYPT, err)
}

#[export_name = "safe_gcry_strerror"]
pub extern "C" fn gcry_strerror(err: u32) -> *const c_char {
    error_string(err).as_ptr().cast()
}

#[export_name = "safe_gcry_strsource"]
pub extern "C" fn gcry_strsource(_err: u32) -> *const c_char {
    STR_GCRYPT.as_ptr().cast()
}

#[export_name = "safe_gcry_malloc"]
pub extern "C" fn gcry_malloc(n: usize) -> *mut c_void {
    plain_alloc(&mut lock_state(), n, false)
}

#[export_name = "safe_gcry_malloc_secure"]
pub extern "C" fn gcry_malloc_secure(n: usize) -> *mut c_void {
    secure_alloc(&mut lock_state(), n, false, false)
}

#[export_name = "safe_gcry_calloc"]
pub extern "C" fn gcry_calloc(n: usize, m: usize) -> *mut c_void {
    plain_alloc(&mut lock_state(), n.saturating_mul(m), true)
}

#[export_name = "safe_gcry_calloc_secure"]
pub extern "C" fn gcry_calloc_secure(n: usize, m: usize) -> *mut c_void {
    secure_alloc(&mut lock_state(), n.saturating_mul(m), true, false)
}

#[export_name = "safe_gcry_realloc"]
pub extern "C" fn gcry_realloc(a: *mut c_void, n: usize) -> *mut c_void {
    if a.is_null() {
        return gcry_malloc(n);
    }

    let mut state = lock_state();
    let old = remove_allocation(&mut state, a);
    let new_ptr = realloc_tracked(a, n);
    if new_ptr.is_null() {
        if let Some(record) = old {
            state.allocations.insert(a as usize, record);
            if record.secure == Some(SecureClass::Base) {
                state.secmem_pool_used += record.charge;
            }
        }
        set_errno(ENOMEM_VALUE);
        return null_mut();
    }

    let size = allocation_size(n);
    let secure = old.and_then(|record| record.secure);
    let secure = match secure {
        Some(SecureClass::Base) => {
            let charge = size + SECURE_POOL_OVERHEAD;
            if state.secmem_pool_used + charge <= secure_limit(&state) {
                Some(SecureClass::Base)
            } else {
                Some(SecureClass::Overflow)
            }
        }
        other => other,
    };

    record_allocation(&mut state, new_ptr, size, secure)
}

#[export_name = "safe_gcry_strdup"]
pub extern "C" fn gcry_strdup(string: *const c_char) -> *mut c_char {
    if string.is_null() {
        return null_mut();
    }

    let bytes = unsafe { CStr::from_ptr(string) }.to_bytes_with_nul();
    duplicate_static_bytes(&mut lock_state(), bytes)
}

#[export_name = "safe_gcry_is_secure"]
pub extern "C" fn gcry_is_secure(a: *const c_void) -> c_int {
    if a.is_null() {
        return 0;
    }

    let state = lock_state();
    state
        .allocations
        .get(&(a as usize))
        .and_then(|record| record.secure)
        .is_some() as c_int
}

#[export_name = "safe_gcry_xcalloc"]
pub extern "C" fn gcry_xcalloc(n: usize, m: usize) -> *mut c_void {
    let ptr = gcry_calloc(n, m);
    if ptr.is_null() {
        std::process::abort();
    }
    ptr
}

#[export_name = "safe_gcry_xcalloc_secure"]
pub extern "C" fn gcry_xcalloc_secure(n: usize, m: usize) -> *mut c_void {
    let ptr = secure_alloc(&mut lock_state(), n.saturating_mul(m), true, true);
    if ptr.is_null() {
        std::process::abort();
    }
    ptr
}

#[export_name = "safe_gcry_xmalloc"]
pub extern "C" fn gcry_xmalloc(n: usize) -> *mut c_void {
    let ptr = gcry_malloc(n);
    if ptr.is_null() {
        std::process::abort();
    }
    ptr
}

#[export_name = "safe_gcry_xmalloc_secure"]
pub extern "C" fn gcry_xmalloc_secure(n: usize) -> *mut c_void {
    let ptr = secure_alloc(&mut lock_state(), n, false, true);
    if ptr.is_null() {
        let state = lock_state();
        if let Some(callback) = state.outofcore.callback {
            unsafe {
                let _ = callback(state.outofcore.opaque, n, 1);
            }
        }
        std::process::abort();
    }
    ptr
}

#[export_name = "safe_gcry_xrealloc"]
pub extern "C" fn gcry_xrealloc(a: *mut c_void, n: usize) -> *mut c_void {
    let ptr = gcry_realloc(a, n);
    if ptr.is_null() {
        std::process::abort();
    }
    ptr
}

#[export_name = "safe_gcry_xstrdup"]
pub extern "C" fn gcry_xstrdup(a: *const c_char) -> *mut c_char {
    let ptr = gcry_strdup(a);
    if ptr.is_null() {
        std::process::abort();
    }
    ptr
}

#[export_name = "safe_gcry_free"]
pub extern "C" fn gcry_free(a: *mut c_void) {
    if a.is_null() {
        return;
    }

    let mut state = lock_state();
    remove_allocation(&mut state, a);
    unsafe {
        free(a);
    }
}

#[export_name = "safe_gcry_set_outofcore_handler"]
pub extern "C" fn gcry_set_outofcore_handler(handler: gcry_handler_no_mem_t, opaque: *mut c_void) {
    let mut state = lock_state();
    state.outofcore = OutOfCoreHandler {
        callback: handler,
        opaque,
    };
}

#[export_name = "safe_gcry_random_add_bytes"]
pub extern "C" fn gcry_random_add_bytes(
    _buffer: *const c_void,
    _length: usize,
    _quality: c_int,
) -> gcry_error_t {
    0
}

#[export_name = "safe_gcry_random_bytes"]
pub extern "C" fn gcry_random_bytes(nbytes: usize, _level: c_int) -> *mut c_void {
    let mut state = lock_state();
    let ptr = plain_alloc(&mut state, nbytes, false);
    if ptr.is_null() {
        return null_mut();
    }

    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr.cast::<u8>(), allocation_size(nbytes));
        fill_random_bytes(&mut state, slice);
    }
    ptr
}

#[export_name = "safe_gcry_random_bytes_secure"]
pub extern "C" fn gcry_random_bytes_secure(nbytes: usize, _level: c_int) -> *mut c_void {
    let mut state = lock_state();
    let ptr = secure_alloc(&mut state, nbytes, false, true);
    if ptr.is_null() {
        return null_mut();
    }

    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr.cast::<u8>(), allocation_size(nbytes));
        fill_random_bytes(&mut state, slice);
    }
    ptr
}

#[export_name = "safe_gcry_randomize"]
pub extern "C" fn gcry_randomize(buffer: *mut c_void, length: usize, _level: c_int) {
    if buffer.is_null() || length == 0 {
        return;
    }

    let mut state = lock_state();
    unsafe {
        let slice = std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length);
        fill_random_bytes(&mut state, slice);
    }
}

#[export_name = "safe_gcry_create_nonce"]
pub extern "C" fn gcry_create_nonce(buffer: *mut c_void, length: usize) {
    gcry_randomize(buffer, length, 0);
}

#[export_name = "safe_gcry_get_config"]
pub extern "C" fn gcry_get_config(mode: c_int, what: *const c_char) -> *mut c_char {
    if mode != 0 {
        set_errno(0);
        return null_mut();
    }

    let what = if what.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(what) })
    };

    let Some(bytes) = config_item_bytes(what) else {
        set_errno(0);
        return null_mut();
    };

    duplicate_static_bytes(&mut lock_state(), bytes)
}

#[export_name = "safe_gcry_md_get"]
pub extern "C" fn gcry_md_get(
    _hd: *mut c_void,
    _algo: c_int,
    _buffer: *mut u8,
    _buflen: c_int,
) -> gcry_error_t {
    GPG_ERR_NOT_IMPLEMENTED
}

#[no_mangle]
pub extern "C" fn safe_gcry_control_dispatch(
    cmd: u32,
    arg0: usize,
    _arg1: usize,
    _arg2: usize,
) -> gcry_error_t {
    let mut state = lock_state();
    match cmd {
        GCRYCTL_SET_VERBOSITY => {
            state.verbosity = arg0 as c_int;
            0
        }
        GCRYCTL_SET_DEBUG_FLAGS => {
            state.debug_flags = arg0 as u32;
            0
        }
        GCRYCTL_INIT_SECMEM => {
            state.secmem_pool_size = (arg0 as usize).max(DEFAULT_SECMEM_POOL_SIZE);
            state.secmem_pool_used = 0;
            state.secmem_initialized = true;
            state.any_initialization_done = true;
            0
        }
        GCRYCTL_TERM_SECMEM => {
            state.secmem_pool_used = 0;
            state.secmem_initialized = false;
            0
        }
        GCRYCTL_DISABLE_SECMEM_WARN => {
            state.secmem_warn_disabled = true;
            0
        }
        GCRYCTL_DISABLE_SECMEM => {
            state.secmem_disabled = true;
            state.any_initialization_done = true;
            0
        }
        GCRYCTL_INITIALIZATION_FINISHED => {
            state.initialization_finished = true;
            state.any_initialization_done = true;
            0
        }
        GCRYCTL_INITIALIZATION_FINISHED_P => state.initialization_finished as gcry_error_t,
        GCRYCTL_ANY_INITIALIZATION_P => state.any_initialization_done as gcry_error_t,
        GCRYCTL_ENABLE_QUICK_RANDOM => 0,
        GCRYCTL_FAST_POLL => 0,
        GCRYCTL_PRINT_CONFIG => {
            let stream = arg0 as *mut FILE;
            if !stream.is_null() {
                unsafe {
                    let _ = fwrite(
                        CONFIG_ALL.as_ptr().cast(),
                        1,
                        CONFIG_ALL.len().saturating_sub(1),
                        stream,
                    );
                }
            }
            0
        }
        GCRYCTL_OPERATIONAL_P => {
            (state.initialization_finished || state.secmem_disabled) as gcry_error_t
        }
        GCRYCTL_FIPS_MODE_P => 0,
        GCRYCTL_DISABLE_HWF => 0,
        GCRYCTL_DUMP_SECMEM_STATS => 0,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn safe_gcry_sexp_build_dispatch(
    retsexp: *mut *mut c_void,
    erroff: *mut usize,
    _format: *const c_char,
) -> gcry_error_t {
    if !retsexp.is_null() {
        unsafe {
            *retsexp = null_mut();
        }
    }
    if !erroff.is_null() {
        unsafe {
            *erroff = 0;
        }
    }
    GPG_ERR_NOT_IMPLEMENTED
}

#[no_mangle]
pub extern "C" fn safe_gcry_sexp_vlist_dispatch(_a: *mut c_void) -> *mut c_void {
    null_mut()
}

#[no_mangle]
pub extern "C" fn safe_gcry_sexp_extract_param_dispatch(
    _sexp: *mut c_void,
    _path: *const c_char,
    _list: *const c_char,
) -> gpg_error_t {
    GPG_ERR_NOT_IMPLEMENTED
}

#[no_mangle]
pub extern "C" fn safe_gcry_log_debug_dispatch(_message: *const c_char) {}

#[no_mangle]
pub extern "C" fn safe_gcry_stub_zero() -> usize {
    0
}
