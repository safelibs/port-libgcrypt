use std::sync::{Mutex, OnceLock};

use crate::error;

#[derive(Debug, Default)]
struct ExternalLockState {
    initialized: bool,
    locked: bool,
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
