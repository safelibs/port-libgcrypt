use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use crate::error;

#[derive(Debug, Default)]
struct ExternalLockState {
    initialized: bool,
    locked: bool,
    secure_objects: HashSet<usize>,
}

fn state() -> &'static Mutex<ExternalLockState> {
    static STATE: OnceLock<Mutex<ExternalLockState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(ExternalLockState::default()))
}

fn lock_state() -> std::sync::MutexGuard<'static, ExternalLockState> {
    match state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(crate) fn external_lock_test(cmd: i32) -> u32 {
    let mut state = lock_state();

    match cmd {
        30111 => {
            state.initialized = true;
            state.locked = false;
            0
        }
        30112 => {
            if !state.initialized || state.locked {
                error::GPG_ERR_INV_OP
            } else {
                state.locked = true;
                0
            }
        }
        30113 => {
            if !state.initialized || !state.locked {
                error::GPG_ERR_INV_OP
            } else {
                state.locked = false;
                0
            }
        }
        30114 => {
            state.initialized = false;
            state.locked = false;
            0
        }
        _ => error::GPG_ERR_INV_OP,
    }
}

pub(crate) fn set_object_secure(ptr: *const c_void, secure: bool) {
    if ptr.is_null() {
        return;
    }

    let mut state = lock_state();
    if secure {
        state.secure_objects.insert(ptr as usize);
    } else {
        state.secure_objects.remove(&(ptr as usize));
    }
}

pub(crate) fn remove_object(ptr: *const c_void) {
    if ptr.is_null() {
        return;
    }

    lock_state().secure_objects.remove(&(ptr as usize));
}

pub(crate) fn is_registered_secure_object(ptr: *const c_void) -> bool {
    if ptr.is_null() {
        return false;
    }

    lock_state().secure_objects.contains(&(ptr as usize))
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_ctx_release(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }

    unsafe {
        (crate::pubkey::encoding::api().ctx_release)(ctx);
    }
}
