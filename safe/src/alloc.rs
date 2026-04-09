#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::ptr::{copy_nonoverlapping, null_mut, write_bytes};

use crate::context;
use crate::error;
use crate::global::{AllocationHandlers, OutOfCoreHandler, lock_runtime_state};
use crate::log;
use crate::secmem;
use crate::{
    EINVAL_VALUE, ENOMEM_VALUE, gcry_handler_alloc_t, gcry_handler_free_t, gcry_handler_no_mem_t,
    gcry_handler_realloc_t, gcry_handler_secure_check_t, get_errno, set_errno,
};

const SECURE_OOM_MESSAGE: &[u8] = b"out of core in secure memory\0";

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

fn multiply_sizes(n: usize, m: usize) -> Option<usize> {
    n.checked_mul(m)
}

fn plain_malloc(size: usize, zeroed: bool) -> *mut c_void {
    if size == 0 {
        set_errno(EINVAL_VALUE);
        return null_mut();
    }

    let ptr = unsafe { malloc(size) };
    if ptr.is_null() {
        set_errno(ENOMEM_VALUE);
        return null_mut();
    }

    if zeroed {
        unsafe {
            write_bytes(ptr.cast::<u8>(), 0, size);
        }
    }
    ptr
}

fn try_allocate(size: usize, secure: bool, zeroed: bool, xhint: bool) -> *mut c_void {
    if size == 0 {
        set_errno(EINVAL_VALUE);
        return null_mut();
    }

    let mut state = lock_runtime_state();
    let handlers = state.alloc_handlers;
    let secmem_disabled = state.secmem.disabled;

    if secure && !secmem_disabled {
        if let Some(callback) = handlers.alloc_secure {
            drop(state);
            let ptr = unsafe { callback(size) };
            if ptr.is_null() {
                if get_errno() == 0 {
                    set_errno(ENOMEM_VALUE);
                }
                return null_mut();
            }
            if zeroed {
                unsafe {
                    write_bytes(ptr.cast::<u8>(), 0, size);
                }
            }
            return ptr;
        }

        return secmem::allocate(&mut state.secmem, size, zeroed, xhint);
    }

    if let Some(callback) = handlers.alloc {
        drop(state);
        let ptr = unsafe { callback(size) };
        if ptr.is_null() {
            if get_errno() == 0 {
                set_errno(ENOMEM_VALUE);
            }
            return null_mut();
        }
        if zeroed {
            unsafe {
                write_bytes(ptr.cast::<u8>(), 0, size);
            }
        }
        return ptr;
    }

    drop(state);
    plain_malloc(size, zeroed)
}

fn is_secure_internal(ptr: *const c_void) -> bool {
    if ptr.is_null() {
        return false;
    }

    if context::is_registered_secure_object(ptr) {
        return true;
    }

    let state = lock_runtime_state();
    if state.secmem.disabled {
        return false;
    }
    if let Some(callback) = state.alloc_handlers.secure_check {
        drop(state);
        return unsafe { callback(ptr) != 0 };
    }

    secmem::is_secure_pointer(&state.secmem, ptr)
}

fn invoke_outofcore(handler: OutOfCoreHandler, size: usize, flags: c_uint) -> bool {
    match handler.callback {
        Some(callback) => unsafe { callback(handler.opaque, size, flags) != 0 },
        None => false,
    }
}

fn current_outofcore_handler() -> OutOfCoreHandler {
    lock_runtime_state().outofcore
}

fn xallocate(size: usize, secure: bool, zeroed: bool, flags: c_uint) -> *mut c_void {
    loop {
        let ptr = try_allocate(size, secure, zeroed, true);
        if !ptr.is_null() {
            return ptr;
        }

        let handler = current_outofcore_handler();
        if invoke_outofcore(handler, size, flags) {
            continue;
        }

        let code = error::gpg_err_code_from_os_error(get_errno());
        let message = if secure {
            SECURE_OOM_MESSAGE
        } else {
            b"Out of memory\0"
        };
        log::fatal_error(code, message);
    }
}

pub(crate) fn copy_bytes(bytes: &[u8], secure: bool, xhint: bool) -> *mut c_char {
    let ptr = try_allocate(bytes.len(), secure, false, xhint);
    if ptr.is_null() {
        return null_mut();
    }

    unsafe {
        copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
    }
    ptr.cast()
}

#[unsafe(export_name = "safe_gcry_set_allocation_handler")]
pub extern "C" fn gcry_set_allocation_handler(
    func_alloc: gcry_handler_alloc_t,
    func_alloc_secure: gcry_handler_alloc_t,
    func_secure_check: gcry_handler_secure_check_t,
    func_realloc: gcry_handler_realloc_t,
    func_free: gcry_handler_free_t,
) {
    let mut state = lock_runtime_state();
    if state.fips_mode {
        return;
    }

    state.alloc_handlers = AllocationHandlers {
        alloc: func_alloc,
        alloc_secure: func_alloc_secure,
        secure_check: func_secure_check,
        realloc: func_realloc,
        free: func_free,
    };
}

#[unsafe(export_name = "safe_gcry_set_outofcore_handler")]
pub extern "C" fn gcry_set_outofcore_handler(handler: gcry_handler_no_mem_t, opaque: *mut c_void) {
    let mut state = lock_runtime_state();
    if state.fips_mode {
        return;
    }

    state.outofcore = OutOfCoreHandler {
        callback: handler,
        opaque,
    };
}

#[unsafe(export_name = "safe_gcry_malloc")]
pub extern "C" fn gcry_malloc(n: usize) -> *mut c_void {
    try_allocate(n, false, false, false)
}

#[unsafe(export_name = "safe_gcry_malloc_secure")]
pub extern "C" fn gcry_malloc_secure(n: usize) -> *mut c_void {
    try_allocate(n, true, false, false)
}

#[unsafe(export_name = "safe_gcry_calloc")]
pub extern "C" fn gcry_calloc(n: usize, m: usize) -> *mut c_void {
    let Some(bytes) = multiply_sizes(n, m) else {
        set_errno(ENOMEM_VALUE);
        return null_mut();
    };
    try_allocate(bytes.max(1), false, true, false)
}

#[unsafe(export_name = "safe_gcry_calloc_secure")]
pub extern "C" fn gcry_calloc_secure(n: usize, m: usize) -> *mut c_void {
    let Some(bytes) = multiply_sizes(n, m) else {
        set_errno(ENOMEM_VALUE);
        return null_mut();
    };
    try_allocate(bytes.max(1), true, true, false)
}

#[unsafe(export_name = "safe_gcry_realloc")]
pub extern "C" fn gcry_realloc(a: *mut c_void, n: usize) -> *mut c_void {
    if a.is_null() {
        return gcry_malloc(n);
    }
    if n == 0 {
        gcry_free(a);
        return null_mut();
    }

    let mut state = lock_runtime_state();
    if let Some(callback) = state.alloc_handlers.realloc {
        drop(state);
        let ptr = unsafe { callback(a, n) };
        if ptr.is_null() && get_errno() == 0 {
            set_errno(ENOMEM_VALUE);
        }
        return ptr;
    }

    if !state.secmem.disabled && secmem::is_secure_pointer(&state.secmem, a) {
        return secmem::reallocate(&mut state.secmem, a, n, false);
    }

    drop(state);
    let ptr = unsafe { realloc(a, n) };
    if ptr.is_null() {
        set_errno(ENOMEM_VALUE);
    }
    ptr
}

#[unsafe(export_name = "safe_gcry_strdup")]
pub extern "C" fn gcry_strdup(string: *const c_char) -> *mut c_char {
    if string.is_null() {
        return null_mut();
    }

    let bytes = unsafe { CStr::from_ptr(string) }.to_bytes_with_nul();
    copy_bytes(bytes, is_secure_internal(string.cast()), false)
}

#[unsafe(export_name = "safe_gcry_is_secure")]
pub extern "C" fn gcry_is_secure(a: *const c_void) -> c_int {
    is_secure_internal(a) as c_int
}

#[unsafe(export_name = "safe_gcry_xcalloc")]
pub extern "C" fn gcry_xcalloc(n: usize, m: usize) -> *mut c_void {
    let Some(bytes) = multiply_sizes(n, m) else {
        set_errno(ENOMEM_VALUE);
        log::fatal_error(
            error::gpg_err_code_from_os_error(ENOMEM_VALUE),
            b"Out of memory\0",
        );
    };
    xallocate(bytes.max(1), false, true, 0)
}

#[unsafe(export_name = "safe_gcry_xcalloc_secure")]
pub extern "C" fn gcry_xcalloc_secure(n: usize, m: usize) -> *mut c_void {
    let Some(bytes) = multiply_sizes(n, m) else {
        set_errno(ENOMEM_VALUE);
        log::fatal_error(
            error::gpg_err_code_from_os_error(ENOMEM_VALUE),
            SECURE_OOM_MESSAGE,
        );
    };
    xallocate(bytes.max(1), true, true, 1)
}

#[unsafe(export_name = "safe_gcry_xmalloc")]
pub extern "C" fn gcry_xmalloc(n: usize) -> *mut c_void {
    xallocate(n, false, false, 0)
}

#[unsafe(export_name = "safe_gcry_xmalloc_secure")]
pub extern "C" fn gcry_xmalloc_secure(n: usize) -> *mut c_void {
    xallocate(n, true, false, 1)
}

#[unsafe(export_name = "safe_gcry_xrealloc")]
pub extern "C" fn gcry_xrealloc(a: *mut c_void, n: usize) -> *mut c_void {
    loop {
        let ptr = gcry_realloc(a, n);
        if !ptr.is_null() {
            return ptr;
        }

        let flags = if is_secure_internal(a) { 3 } else { 2 };
        let handler = current_outofcore_handler();
        if invoke_outofcore(handler, n, flags) {
            continue;
        }

        let code = error::gpg_err_code_from_os_error(get_errno());
        let message = if flags & 1 != 0 {
            SECURE_OOM_MESSAGE
        } else {
            b"Out of memory\0"
        };
        log::fatal_error(code, message);
    }
}

#[unsafe(export_name = "safe_gcry_xstrdup")]
pub extern "C" fn gcry_xstrdup(a: *const c_char) -> *mut c_char {
    if a.is_null() {
        log::fatal_error(error::GPG_ERR_INV_ARG, b"Invalid argument\0");
    }

    loop {
        let ptr = gcry_strdup(a);
        if !ptr.is_null() {
            return ptr;
        }

        let secure = is_secure_internal(a.cast());
        let flags = if secure { 1 } else { 0 };
        let length = unsafe { CStr::from_ptr(a) }.to_bytes().len();
        let handler = current_outofcore_handler();
        if invoke_outofcore(handler, length, flags) {
            continue;
        }

        let code = error::gpg_err_code_from_os_error(get_errno());
        let message = if secure {
            SECURE_OOM_MESSAGE
        } else {
            b"Out of memory\0"
        };
        log::fatal_error(code, message);
    }
}

#[unsafe(export_name = "safe_gcry_free")]
pub extern "C" fn gcry_free(a: *mut c_void) {
    if a.is_null() {
        return;
    }

    let saved_errno = get_errno();
    let mut state = lock_runtime_state();
    if let Some(callback) = state.alloc_handlers.free {
        drop(state);
        unsafe {
            callback(a);
        }
    } else if !state.secmem.disabled && secmem::free_allocation(&mut state.secmem, a) {
    } else {
        drop(state);
        unsafe {
            free(a);
        }
    }

    if saved_errno != 0 {
        set_errno(saved_errno);
    }
}
