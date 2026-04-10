use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use crate::error;

#[derive(Debug, Default)]
struct ExternalLockState {
    initialized: bool,
    locked: bool,
    secure_objects: HashSet<usize>,
    random_override_contexts: HashMap<usize, Vec<u8>>,
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

pub(crate) fn new_random_override_context(bytes: &[u8]) -> Result<*mut c_void, u32> {
    let marker = Box::into_raw(Box::new(0u8)).cast::<c_void>();
    if marker.is_null() {
        return Err(error::gcry_error_from_errno(crate::ENOMEM_VALUE));
    }

    lock_state()
        .random_override_contexts
        .insert(marker as usize, bytes.to_vec());
    Ok(marker)
}

pub(crate) fn copy_random_override_context(ctx: *mut c_void) -> Option<Vec<u8>> {
    if ctx.is_null() {
        return None;
    }

    lock_state()
        .random_override_contexts
        .get(&(ctx as usize))
        .cloned()
}

pub(crate) fn is_random_override_context(ctx: *mut c_void) -> bool {
    if ctx.is_null() {
        return false;
    }

    lock_state().random_override_contexts.contains_key(&(ctx as usize))
}

#[no_mangle]
pub extern "C" fn gcry_ctx_release(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }

    if lock_state()
        .random_override_contexts
        .remove(&(ctx as usize))
        .is_some()
    {
        unsafe {
            drop(Box::from_raw(ctx.cast::<u8>()));
        }
        return;
    }
    let _ = crate::mpi::ec::release_local_context(ctx);
}
