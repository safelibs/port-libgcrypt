use std::collections::BTreeSet;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::{Mutex, OnceLock};

use crate::context;
use crate::error;
use crate::hwfeatures;
use crate::log;
use crate::random;
use crate::secmem::{self, SecureMemoryState};
use crate::upstream;
use crate::{
    PACKAGE_VERSION_BYTES, gcry_handler_alloc_t, gcry_handler_free_t, gcry_handler_no_mem_t,
    gcry_handler_realloc_t, gcry_handler_secure_check_t,
};

pub(crate) const GCRY_RNG_TYPE_STANDARD: c_int = 1;
pub(crate) const GCRY_RNG_TYPE_FIPS: c_int = 2;
pub(crate) const GCRY_RNG_TYPE_SYSTEM: c_int = 3;

const GCRYCTL_DUMP_RANDOM_STATS: u32 = 13;
const GCRYCTL_DUMP_SECMEM_STATS: u32 = 14;
const GCRYCTL_SET_VERBOSITY: u32 = 19;
const GCRYCTL_SET_DEBUG_FLAGS: u32 = 20;
const GCRYCTL_CLEAR_DEBUG_FLAGS: u32 = 21;
const GCRYCTL_USE_SECURE_RNDPOOL: u32 = 22;
const GCRYCTL_DUMP_MEMORY_STATS: u32 = 23;
const GCRYCTL_INIT_SECMEM: u32 = 24;
const GCRYCTL_TERM_SECMEM: u32 = 25;
const GCRYCTL_DISABLE_SECMEM_WARN: u32 = 27;
const GCRYCTL_SUSPEND_SECMEM_WARN: u32 = 28;
const GCRYCTL_RESUME_SECMEM_WARN: u32 = 29;
const GCRYCTL_DROP_PRIVS: u32 = 30;
const GCRYCTL_ENABLE_M_GUARD: u32 = 31;
const GCRYCTL_DISABLE_INTERNAL_LOCKING: u32 = 36;
const GCRYCTL_DISABLE_SECMEM: u32 = 37;
const GCRYCTL_INITIALIZATION_FINISHED: u32 = 38;
const GCRYCTL_INITIALIZATION_FINISHED_P: u32 = 39;
const GCRYCTL_ANY_INITIALIZATION_P: u32 = 40;
const GCRYCTL_ENABLE_QUICK_RANDOM: u32 = 44;
const GCRYCTL_SET_RANDOM_SEED_FILE: u32 = 45;
const GCRYCTL_UPDATE_RANDOM_SEED_FILE: u32 = 46;
const GCRYCTL_SET_THREAD_CBS: u32 = 47;
const GCRYCTL_FAST_POLL: u32 = 48;
const GCRYCTL_SET_RANDOM_DAEMON_SOCKET: u32 = 49;
const GCRYCTL_USE_RANDOM_DAEMON: u32 = 50;
const GCRYCTL_FAKED_RANDOM_P: u32 = 51;
const GCRYCTL_SET_RNDEGD_SOCKET: u32 = 52;
const GCRYCTL_PRINT_CONFIG: u32 = 53;
const GCRYCTL_OPERATIONAL_P: u32 = 54;
const GCRYCTL_FIPS_MODE_P: u32 = 55;
const GCRYCTL_FORCE_FIPS_MODE: u32 = 56;
const GCRYCTL_SELFTEST: u32 = 57;
const PRIV_CTL_INIT_EXTRNG_TEST: u32 = 58;
const PRIV_CTL_RUN_EXTRNG_TEST: u32 = 59;
const PRIV_CTL_DEINIT_EXTRNG_TEST: u32 = 60;
const PRIV_CTL_EXTERNAL_LOCK_TEST: u32 = 61;
const PRIV_CTL_DUMP_SECMEM_STATS: u32 = 62;
const GCRYCTL_DISABLE_HWF: u32 = 63;
const GCRYCTL_SET_ENFORCED_FIPS_FLAG: u32 = 64;
const GCRYCTL_SET_PREFERRED_RNG_TYPE: u32 = 65;
const GCRYCTL_GET_CURRENT_RNG_TYPE: u32 = 66;
const GCRYCTL_DISABLE_LOCKED_SECMEM: u32 = 67;
const GCRYCTL_DISABLE_PRIV_DROP: u32 = 68;
const GCRYCTL_CLOSE_RANDOM_DEVICE: u32 = 70;
const GCRYCTL_DRBG_REINIT: u32 = 74;
const GCRYCTL_REINIT_SYSCALL_CLAMP: u32 = 77;
const GCRYCTL_AUTO_EXPAND_SECMEM: u32 = 78;
const GCRYCTL_FIPS_SERVICE_INDICATOR_KDF: u32 = 82;
const GCRYCTL_NO_FIPS_MODE: u32 = 83;

const COMPAT_IDENTIFICATION: &[u8] =
    b"\n\nThis is Libgcrypt 1.10.3 - The GNU Crypto Library\n(runtime shell compatibility mode)\n\n\0";

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AllocationHandlers {
    pub(crate) alloc: gcry_handler_alloc_t,
    pub(crate) alloc_secure: gcry_handler_alloc_t,
    pub(crate) secure_check: gcry_handler_secure_check_t,
    pub(crate) realloc: gcry_handler_realloc_t,
    pub(crate) free: gcry_handler_free_t,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OutOfCoreHandler {
    pub(crate) callback: gcry_handler_no_mem_t,
    pub(crate) opaque: *mut c_void,
}

unsafe impl Send for OutOfCoreHandler {}

#[derive(Debug)]
pub(crate) struct RuntimeState {
    pub(crate) any_init_done: bool,
    pub(crate) init_finished: bool,
    pub(crate) fips_mode: bool,
    pub(crate) requested_fips_mode: Option<bool>,
    pub(crate) preferred_rng_type: Option<c_int>,
    pub(crate) active_rng_type: c_int,
    pub(crate) rng_frozen: bool,
    pub(crate) quick_random_enabled: bool,
    pub(crate) debug_flags: u32,
    pub(crate) alloc_handlers: AllocationHandlers,
    pub(crate) outofcore: OutOfCoreHandler,
    pub(crate) secmem: SecureMemoryState,
    pub(crate) disabled_hw_features: BTreeSet<String>,
    pub(crate) syscalls_clamped: bool,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            any_init_done: false,
            init_finished: false,
            fips_mode: false,
            requested_fips_mode: None,
            preferred_rng_type: None,
            active_rng_type: GCRY_RNG_TYPE_STANDARD,
            rng_frozen: false,
            quick_random_enabled: false,
            debug_flags: 0,
            alloc_handlers: AllocationHandlers::default(),
            outofcore: OutOfCoreHandler::default(),
            secmem: SecureMemoryState::default(),
            disabled_hw_features: BTreeSet::new(),
            syscalls_clamped: false,
        }
    }
}

fn state() -> &'static Mutex<RuntimeState> {
    static STATE: OnceLock<Mutex<RuntimeState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(RuntimeState::default()))
}

pub(crate) fn lock_runtime_state() -> std::sync::MutexGuard<'static, RuntimeState> {
    match state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn version_number(bytes: &[u8], mut index: usize) -> Option<(usize, u32)> {
    if index >= bytes.len() || !bytes[index].is_ascii_digit() {
        return None;
    }
    if bytes[index] == b'0' && bytes.get(index + 1).is_some_and(u8::is_ascii_digit) {
        return None;
    }

    let mut value = 0u32;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        value = value
            .checked_mul(10)?
            .checked_add((bytes[index] - b'0') as u32)?;
        index += 1;
    }
    Some((index, value))
}

fn parse_version_string(value: &CStr) -> Option<(u32, u32, u32)> {
    let bytes = value.to_bytes();
    let (index, major) = version_number(bytes, 0)?;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    let (index, minor) = version_number(bytes, index + 1)?;
    if bytes.get(index) != Some(&b'.') {
        return None;
    }
    let (_, micro) = version_number(bytes, index + 1)?;
    Some((major, minor, micro))
}

fn prefer_default_rng(state: &mut RuntimeState) {
    if !state.rng_frozen {
        state.preferred_rng_type = None;
    }
}

fn resolve_rng_type(state: &RuntimeState) -> c_int {
    if state.fips_mode {
        GCRY_RNG_TYPE_FIPS
    } else if state.rng_frozen {
        state.active_rng_type
    } else {
        state.preferred_rng_type.unwrap_or(GCRY_RNG_TYPE_STANDARD)
    }
}

fn freeze_rng_type(state: &mut RuntimeState) {
    if state.fips_mode {
        state.active_rng_type = GCRY_RNG_TYPE_FIPS;
        state.rng_frozen = true;
    } else if !state.rng_frozen {
        state.active_rng_type = state.preferred_rng_type.unwrap_or(GCRY_RNG_TYPE_STANDARD);
        state.rng_frozen = true;
    }
}

fn global_init_locked(state: &mut RuntimeState) {
    if state.any_init_done {
        return;
    }

    state.any_init_done = true;
    state.fips_mode = state
        .requested_fips_mode
        .unwrap_or_else(|| std::env::var_os("LIBGCRYPT_FORCE_FIPS_MODE").is_some());
}

fn truthy_success() -> u32 {
    error::gcry_error_from_code(error::GPG_ERR_GENERAL)
}

fn control_result(code: u32) -> u32 {
    error::gcry_error_from_code(code)
}

pub(crate) fn current_rng_type() -> c_int {
    let state = lock_runtime_state();
    resolve_rng_type(&state)
}

pub(crate) fn note_rng_use() {
    let mut state = lock_runtime_state();
    freeze_rng_type(&mut state);
}

#[unsafe(export_name = "safe_gcry_check_version")]
pub extern "C" fn gcry_check_version(req_version: *const c_char) -> *const c_char {
    if !req_version.is_null() {
        let request = unsafe { CStr::from_ptr(req_version) };
        let bytes = request.to_bytes();
        if bytes.len() >= 2 && bytes[0] == 1 && bytes[1] == 1 {
            return COMPAT_IDENTIFICATION.as_ptr().cast();
        }
    }

    {
        let mut state = lock_runtime_state();
        global_init_locked(&mut state);
    }

    if req_version.is_null() {
        return PACKAGE_VERSION_BYTES.as_ptr().cast();
    }

    let request = unsafe { CStr::from_ptr(req_version) };
    let Some((rq_major, rq_minor, rq_micro)) = parse_version_string(request) else {
        return std::ptr::null();
    };
    let current = unsafe { CStr::from_ptr(PACKAGE_VERSION_BYTES.as_ptr().cast()) };
    let Some((my_major, my_minor, my_micro)) = parse_version_string(current) else {
        return std::ptr::null();
    };

    if my_major > rq_major
        || (my_major == rq_major && my_minor > rq_minor)
        || (my_major == rq_major && my_minor == rq_minor && my_micro >= rq_micro)
    {
        PACKAGE_VERSION_BYTES.as_ptr().cast()
    } else {
        std::ptr::null()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn safe_gcry_control_dispatch(
    cmd: u32,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> u32 {
    let mut state = lock_runtime_state();
    let mut deferred_log = None;
    let mut deferred_print_config = None;

    let code = match cmd {
        GCRYCTL_ENABLE_M_GUARD => 0,
        GCRYCTL_ENABLE_QUICK_RANDOM => {
            prefer_default_rng(&mut state);
            state.quick_random_enabled = true;
            0
        }
        GCRYCTL_FAKED_RANDOM_P => {
            if state.quick_random_enabled {
                return truthy_success();
            }
            0
        }
        GCRYCTL_DUMP_RANDOM_STATS => {
            deferred_log = Some(random::dump_stats());
            0
        }
        GCRYCTL_DUMP_MEMORY_STATS => 0,
        GCRYCTL_DUMP_SECMEM_STATS => {
            deferred_log = Some(secmem::dump_stats(&state.secmem, false));
            0
        }
        PRIV_CTL_DUMP_SECMEM_STATS => {
            deferred_log = Some(secmem::dump_stats(&state.secmem, true));
            0
        }
        GCRYCTL_DROP_PRIVS => {
            global_init_locked(&mut state);
            0
        }
        GCRYCTL_DISABLE_SECMEM => {
            global_init_locked(&mut state);
            if !state.fips_mode {
                state.secmem.disabled = true;
            }
            0
        }
        GCRYCTL_INIT_SECMEM => {
            global_init_locked(&mut state);
            secmem::init_pool(&mut state.secmem, arg0);
            0
        }
        GCRYCTL_TERM_SECMEM => {
            secmem::term(&mut state.secmem);
            0
        }
        GCRYCTL_DISABLE_SECMEM_WARN => {
            prefer_default_rng(&mut state);
            state.secmem.warn_disabled = true;
            0
        }
        GCRYCTL_SUSPEND_SECMEM_WARN => {
            prefer_default_rng(&mut state);
            state.secmem.warn_suspended = true;
            0
        }
        GCRYCTL_RESUME_SECMEM_WARN => {
            prefer_default_rng(&mut state);
            state.secmem.warn_suspended = false;
            0
        }
        GCRYCTL_AUTO_EXPAND_SECMEM => {
            state.secmem.auto_expand = arg0 as u32;
            0
        }
        GCRYCTL_USE_SECURE_RNDPOOL => {
            global_init_locked(&mut state);
            0
        }
        GCRYCTL_SET_RANDOM_SEED_FILE | GCRYCTL_UPDATE_RANDOM_SEED_FILE => {
            prefer_default_rng(&mut state);
            0
        }
        GCRYCTL_SET_VERBOSITY => {
            prefer_default_rng(&mut state);
            log::set_verbosity(arg0 as c_int);
            0
        }
        GCRYCTL_SET_DEBUG_FLAGS => {
            state.debug_flags |= arg0 as u32;
            0
        }
        GCRYCTL_CLEAR_DEBUG_FLAGS => {
            state.debug_flags &= !(arg0 as u32);
            0
        }
        GCRYCTL_DISABLE_INTERNAL_LOCKING => {
            global_init_locked(&mut state);
            0
        }
        GCRYCTL_ANY_INITIALIZATION_P => {
            if state.any_init_done {
                return truthy_success();
            }
            0
        }
        GCRYCTL_INITIALIZATION_FINISHED_P => {
            if state.init_finished {
                return truthy_success();
            }
            0
        }
        GCRYCTL_INITIALIZATION_FINISHED => {
            global_init_locked(&mut state);
            freeze_rng_type(&mut state);
            state.init_finished = true;
            0
        }
        GCRYCTL_SET_THREAD_CBS => {
            prefer_default_rng(&mut state);
            global_init_locked(&mut state);
            0
        }
        GCRYCTL_FAST_POLL => {
            prefer_default_rng(&mut state);
            global_init_locked(&mut state);
            drop(state);
            random::fast_poll();
            return 0;
        }
        GCRYCTL_FIPS_SERVICE_INDICATOR_KDF => {
            if arg0 as c_int == 34 {
                0
            } else {
                error::GPG_ERR_NOT_SUPPORTED
            }
        }
        GCRYCTL_SET_RNDEGD_SOCKET
        | GCRYCTL_SET_RANDOM_DAEMON_SOCKET
        | GCRYCTL_USE_RANDOM_DAEMON => error::GPG_ERR_NOT_SUPPORTED,
        GCRYCTL_CLOSE_RANDOM_DEVICE => {
            drop(state);
            random::close_random_device();
            return 0;
        }
        GCRYCTL_PRINT_CONFIG => {
            prefer_default_rng(&mut state);
            deferred_print_config = Some(arg0 as *mut crate::FILE);
            0
        }
        GCRYCTL_OPERATIONAL_P => {
            prefer_default_rng(&mut state);
            if state.any_init_done && (!state.fips_mode || state.init_finished) {
                return truthy_success();
            }
            0
        }
        GCRYCTL_FIPS_MODE_P => {
            if state.fips_mode {
                return truthy_success();
            }
            0
        }
        GCRYCTL_FORCE_FIPS_MODE => {
            prefer_default_rng(&mut state);
            if !state.any_init_done {
                state.requested_fips_mode = Some(true);
                state.active_rng_type = GCRY_RNG_TYPE_FIPS;
                0
            } else if !state.init_finished {
                state.fips_mode = true;
                freeze_rng_type(&mut state);
                0
            } else {
                state.fips_mode = true;
                freeze_rng_type(&mut state);
                return truthy_success();
            }
        }
        GCRYCTL_SELFTEST => {
            prefer_default_rng(&mut state);
            if arg0 != 0 {
                error::GPG_ERR_INV_ARG
            } else {
                0
            }
        }
        GCRYCTL_NO_FIPS_MODE => {
            prefer_default_rng(&mut state);
            if !state.any_init_done {
                state.requested_fips_mode = Some(false);
                0
            } else if !state.init_finished {
                state.fips_mode = false;
                if state.active_rng_type == GCRY_RNG_TYPE_FIPS {
                    state.active_rng_type = GCRY_RNG_TYPE_STANDARD;
                }
                0
            } else {
                return truthy_success();
            }
        }
        GCRYCTL_DISABLE_HWF => {
            let Some(name) =
                (!arg0.eq(&0)).then(|| unsafe { CStr::from_ptr(arg0 as *const c_char) })
            else {
                return 0;
            };
            let sanitized = match hwfeatures::sanitize_disable_request(name) {
                Ok(value) => value,
                Err(code) => return control_result(code),
            };
            if let Some(ref names) = sanitized {
                let upstream_rc = upstream::disable_hw_features_preinit(names.as_c_str());
                if upstream_rc != 0 {
                    return upstream_rc;
                }
            }
            hwfeatures::remember_disabled_features(
                &mut state.disabled_hw_features,
                sanitized.as_deref(),
            );
            0
        }
        GCRYCTL_SET_ENFORCED_FIPS_FLAG => 0,
        GCRYCTL_SET_PREFERRED_RNG_TYPE => {
            let rng_type = arg0 as c_int;
            if rng_type <= 0 {
                0
            } else if !state.rng_frozen && !state.init_finished {
                state.preferred_rng_type = Some(rng_type);
                state.active_rng_type = rng_type;
                0
            } else if rng_type == GCRY_RNG_TYPE_STANDARD {
                state.preferred_rng_type = Some(GCRY_RNG_TYPE_STANDARD);
                state.active_rng_type = GCRY_RNG_TYPE_STANDARD;
                state.rng_frozen = true;
                0
            } else {
                0
            }
        }
        GCRYCTL_GET_CURRENT_RNG_TYPE => {
            if arg0 != 0 {
                unsafe {
                    *(arg0 as *mut c_int) = resolve_rng_type(&state);
                }
            }
            0
        }
        GCRYCTL_DISABLE_LOCKED_SECMEM => {
            prefer_default_rng(&mut state);
            state.secmem.locked_disabled = true;
            0
        }
        GCRYCTL_DISABLE_PRIV_DROP => {
            prefer_default_rng(&mut state);
            0
        }
        GCRYCTL_DRBG_REINIT => {
            drop(state);
            return control_result(random::drbg_reinit(
                arg0 as *const c_char,
                arg1 as *const crate::upstream::gcry_buffer_t,
                arg2 as c_int,
                arg3,
            ));
        }
        GCRYCTL_REINIT_SYSCALL_CLAMP => {
            state.syscalls_clamped = true;
            0
        }
        PRIV_CTL_INIT_EXTRNG_TEST => {
            drop(state);
            return control_result(random::init_extrng_test());
        }
        PRIV_CTL_RUN_EXTRNG_TEST => {
            drop(state);
            return control_result(random::run_extrng_test(
                arg0 as *const random::gcry_drbg_test_vector,
                arg1 as *mut u8,
            ));
        }
        PRIV_CTL_DEINIT_EXTRNG_TEST => {
            drop(state);
            return control_result(random::deinit_extrng_test());
        }
        PRIV_CTL_EXTERNAL_LOCK_TEST => context::external_lock_test(arg0 as c_int),
        _ => error::GPG_ERR_INV_OP,
    };

    drop(state);
    if let Some(stream) = deferred_print_config {
        crate::config::print_config_to_stream(stream);
    }
    if let Some(message) = deferred_log {
        log::emit_message(log::GCRY_LOG_INFO, &message);
    }
    control_result(code)
}
