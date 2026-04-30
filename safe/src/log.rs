#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::{Mutex, OnceLock};

use crate::{gcry_gettext_handler_t, gcry_handler_error_t, gcry_handler_progress_t};

pub(crate) const GCRY_LOG_CONT: c_int = 0;
pub(crate) const GCRY_LOG_INFO: c_int = 10;
pub(crate) const GCRY_LOG_FATAL: c_int = 40;
pub(crate) const GCRY_LOG_DEBUG: c_int = 100;

const DEFAULT_FATAL_MESSAGE: &[u8] = b"Fatal error\0";

#[derive(Clone, Copy, Debug)]
struct FatalHandler {
    callback: gcry_handler_error_t,
    opaque: *mut c_void,
}

impl Default for FatalHandler {
    fn default() -> Self {
        Self {
            callback: None,
            opaque: std::ptr::null_mut(),
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
struct ProgressHandler {
    callback: gcry_handler_progress_t,
    opaque: *mut c_void,
}

impl Default for ProgressHandler {
    fn default() -> Self {
        Self {
            callback: None,
            opaque: std::ptr::null_mut(),
        }
    }
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

fn hex_byte(byte: u8) -> [char; 2] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    [
        HEX[(byte >> 4) as usize] as char,
        HEX[(byte & 0x0f) as usize] as char,
    ]
}

fn emit_hex_byte(byte: u8) {
    let [hi, lo] = hex_byte(byte);
    let mut message = String::with_capacity(2);
    message.push(hi);
    message.push(lo);
    emit_message(GCRY_LOG_CONT, &message);
}

#[unsafe(export_name = "safe_gcry_log_debughex")]
pub extern "C" fn gcry_log_debughex(text: *const c_char, buffer: *const c_void, length: usize) {
    let label = if text.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(text) }.to_string_lossy())
    };
    let bytes = if !buffer.is_null() && length != 0 {
        unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) }
    } else {
        &[]
    };

    if label.is_none() && bytes.is_empty() {
        return;
    }

    let wrap = label.as_ref().is_some_and(|item| !item.is_empty());
    let label_len = label.as_ref().map_or(0, |item| item.len());

    if wrap {
        let label = label.as_ref().expect("wrap implies label");
        emit_message(GCRY_LOG_DEBUG, &format!("{label}: "));
    }

    let mut count = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        emit_hex_byte(*byte);
        if wrap {
            count += 1;
            if count == 32 && index + 1 < bytes.len() {
                count = 0;
                emit_message(GCRY_LOG_CONT, " \\\n");
                emit_message(GCRY_LOG_DEBUG, &" ".repeat(label_len + 2));
            }
        }
    }
    if label.is_some() {
        emit_message(GCRY_LOG_CONT, "\n");
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
