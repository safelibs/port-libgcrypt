use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::{Mutex, OnceLock};

use crate::{gcry_gettext_handler_t, gcry_handler_error_t, gcry_handler_progress_t};

pub(crate) const GCRY_LOG_INFO: c_int = 10;
pub(crate) const GCRY_LOG_FATAL: c_int = 40;
pub(crate) const GCRY_LOG_DEBUG: c_int = 100;

const DEFAULT_FATAL_MESSAGE: &[u8] = b"Fatal error\0";

#[derive(Clone, Copy, Debug, Default)]
struct FatalHandler {
    callback: gcry_handler_error_t,
    opaque: *mut c_void,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default)]
struct ProgressHandler {
    callback: gcry_handler_progress_t,
    opaque: *mut c_void,
}

unsafe impl Send for FatalHandler {}
unsafe impl Send for ProgressHandler {}

#[derive(Debug, Default)]
struct LoggingState {
    verbosity: c_int,
    fatal: FatalHandler,
    progress: ProgressHandler,
    gettext: gcry_gettext_handler_t,
}

unsafe impl Send for LoggingState {}

unsafe extern "C" {
    fn safe_cabi_dispatch_log_message(level: c_int, message: *const c_char);
}

fn state() -> &'static Mutex<LoggingState> {
    static STATE: OnceLock<Mutex<LoggingState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(LoggingState::default()))
}

fn lock_state() -> std::sync::MutexGuard<'static, LoggingState> {
    match state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn sanitize_message(message: &str) -> CString {
    CString::new(message.replace('\0', " ")).expect("sanitized log message")
}

pub(crate) fn set_verbosity(level: c_int) {
    lock_state().verbosity = level;
}

pub(crate) fn emit_message(level: c_int, message: &str) {
    let message = sanitize_message(message);
    unsafe {
        safe_cabi_dispatch_log_message(level, message.as_ptr());
    }
}

#[allow(dead_code)]
pub(crate) fn dispatch_progress(what: &CStr, current: c_int, total: c_int) {
    let progress = lock_state().progress;
    if let Some(callback) = progress.callback {
        unsafe {
            callback(progress.opaque, what.as_ptr(), 0, current, total);
        }
    }
}

pub(crate) fn translate_pointer(default_message: *const c_char) -> *const c_char {
    let handler = lock_state().gettext;
    if let Some(callback) = handler {
        let translated = unsafe { callback(default_message) };
        if !translated.is_null() {
            return translated;
        }
    }
    default_message
}

pub(crate) fn fatal_error(code: u32, default_message: &'static [u8]) -> ! {
    let message_ptr = translate_pointer(default_message.as_ptr().cast());
    let fatal = lock_state().fatal;
    if let Some(callback) = fatal.callback {
        unsafe {
            callback(fatal.opaque, code as c_int, message_ptr);
        }
    }

    unsafe {
        safe_cabi_dispatch_log_message(GCRY_LOG_FATAL, message_ptr);
    }
    std::process::abort();
}

#[unsafe(export_name = "safe_gcry_set_progress_handler")]
pub extern "C" fn gcry_set_progress_handler(cb: gcry_handler_progress_t, cb_data: *mut c_void) {
    lock_state().progress = ProgressHandler {
        callback: cb,
        opaque: cb_data,
    };
}

#[unsafe(export_name = "safe_gcry_set_fatalerror_handler")]
pub extern "C" fn gcry_set_fatalerror_handler(fnc: gcry_handler_error_t, opaque: *mut c_void) {
    lock_state().fatal = FatalHandler {
        callback: fnc,
        opaque,
    };
}

#[unsafe(export_name = "safe_gcry_set_gettext_handler")]
pub extern "C" fn gcry_set_gettext_handler(f: gcry_gettext_handler_t) {
    lock_state().gettext = f;
}

#[unsafe(no_mangle)]
pub extern "C" fn safe_gcry_log_debug_dispatch(message: *const c_char) {
    if message.is_null() {
        unsafe {
            safe_cabi_dispatch_log_message(GCRY_LOG_DEBUG, DEFAULT_FATAL_MESSAGE.as_ptr().cast());
        }
        return;
    }

    unsafe {
        safe_cabi_dispatch_log_message(GCRY_LOG_DEBUG, message);
    }
}
