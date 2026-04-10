use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::ptr::{copy_nonoverlapping, null_mut};
use std::sync::atomic::{Ordering, compiler_fence};

use crate::{EINVAL_VALUE, ENOMEM_VALUE, log, set_errno};

pub(crate) const DEFAULT_POOL_SIZE: usize = 16 * 1024;
const SECURE_CHARGE_OVERHEAD: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecureClass {
    Base,
    Overflow,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SecureAllocation {
    pub(crate) len: usize,
    pub(crate) charge: usize,
    pub(crate) class: SecureClass,
    pub(crate) locked: bool,
}

#[derive(Debug)]
pub(crate) struct SecureMemoryState {
    pub(crate) pool_limit: usize,
    pub(crate) pool_used: usize,
    pub(crate) initialized: bool,
    pub(crate) disabled: bool,
    pub(crate) warn_disabled: bool,
    pub(crate) warn_suspended: bool,
    pub(crate) locked_disabled: bool,
    pub(crate) auto_expand: u32,
    pub(crate) not_locked: bool,
    insecure_warned: bool,
    allocations: HashMap<usize, SecureAllocation>,
}

impl Default for SecureMemoryState {
    fn default() -> Self {
        Self {
            pool_limit: DEFAULT_POOL_SIZE,
            pool_used: 0,
            initialized: false,
            disabled: false,
            warn_disabled: false,
            warn_suspended: false,
            locked_disabled: false,
            auto_expand: 0,
            not_locked: false,
            insecure_warned: false,
            allocations: HashMap::new(),
        }
    }
}

extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn mlock(addr: *const c_void, len: usize) -> c_int;
    fn munlock(addr: *const c_void, len: usize) -> c_int;
}

fn zeroize(ptr: *mut u8, len: usize) {
    unsafe {
        for offset in 0..len {
            ptr.add(offset).write_volatile(0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

fn warn_insecure_memory(state: &mut SecureMemoryState) {
    if state.warn_disabled || state.warn_suspended || state.insecure_warned {
        return;
    }

    state.insecure_warned = true;
    log::emit_message(log::GCRY_LOG_INFO, "Warning: using insecure memory!\n");
}

fn release_allocation(ptr: *mut c_void, allocation: SecureAllocation) {
    if ptr.is_null() {
        return;
    }

    zeroize(ptr.cast::<u8>(), allocation.len);
    if allocation.locked {
        unsafe {
            let _ = munlock(ptr, allocation.len);
        }
    }
    unsafe {
        free(ptr);
    }
}

pub(crate) fn init_pool(state: &mut SecureMemoryState, requested: usize) {
    state.pool_limit = requested.max(DEFAULT_POOL_SIZE);
    state.pool_used = 0;
    state.initialized = true;
    state.not_locked = false;
    state.insecure_warned = false;
}

pub(crate) fn term(state: &mut SecureMemoryState) {
    let pending: Vec<(usize, SecureAllocation)> = state.allocations.drain().collect();
    state.pool_used = 0;
    state.initialized = false;

    for (ptr, allocation) in pending {
        release_allocation(ptr as *mut c_void, allocation);
    }
}

pub(crate) fn allocate(
    state: &mut SecureMemoryState,
    size: usize,
    zeroed: bool,
    xhint: bool,
) -> *mut c_void {
    if size == 0 {
        set_errno(EINVAL_VALUE);
        return null_mut();
    }

    let charge = size.saturating_add(SECURE_CHARGE_OVERHEAD);
    let allow_overflow = xhint || state.auto_expand > 0;
    let class = if state.pool_used.saturating_add(charge) <= state.pool_limit {
        SecureClass::Base
    } else if allow_overflow {
        SecureClass::Overflow
    } else {
        set_errno(ENOMEM_VALUE);
        return null_mut();
    };

    let ptr = unsafe {
        if zeroed {
            calloc(1, size)
        } else {
            malloc(size)
        }
    };
    if ptr.is_null() {
        set_errno(ENOMEM_VALUE);
        return null_mut();
    }

    let mut locked = false;
    if class == SecureClass::Base && !state.locked_disabled {
        locked = unsafe { mlock(ptr, size) == 0 };
        if !locked {
            state.not_locked = true;
            warn_insecure_memory(state);
        }
    } else if class == SecureClass::Overflow {
        warn_insecure_memory(state);
    }

    if class == SecureClass::Base {
        state.pool_used = state.pool_used.saturating_add(charge);
    }

    state.allocations.insert(
        ptr as usize,
        SecureAllocation {
            len: size,
            charge,
            class,
            locked,
        },
    );
    ptr
}

pub(crate) fn free_allocation(state: &mut SecureMemoryState, ptr: *mut c_void) -> bool {
    let Some(allocation) = state.allocations.remove(&(ptr as usize)) else {
        return false;
    };

    if allocation.class == SecureClass::Base {
        state.pool_used = state.pool_used.saturating_sub(allocation.charge);
    }
    release_allocation(ptr, allocation);
    true
}

pub(crate) fn reallocate(
    state: &mut SecureMemoryState,
    ptr: *mut c_void,
    new_size: usize,
    xhint: bool,
) -> *mut c_void {
    if ptr.is_null() {
        return allocate(state, new_size, false, xhint);
    }
    if new_size == 0 {
        free_allocation(state, ptr);
        return null_mut();
    }

    let Some(allocation) = state.allocations.remove(&(ptr as usize)) else {
        set_errno(EINVAL_VALUE);
        return null_mut();
    };

    if allocation.class == SecureClass::Base {
        state.pool_used = state.pool_used.saturating_sub(allocation.charge);
    }

    let new_ptr = allocate(
        state,
        new_size,
        false,
        xhint || allocation.class == SecureClass::Overflow,
    );
    if new_ptr.is_null() {
        if allocation.class == SecureClass::Base {
            state.pool_used = state.pool_used.saturating_add(allocation.charge);
        }
        state.allocations.insert(ptr as usize, allocation);
        return null_mut();
    }

    unsafe {
        copy_nonoverlapping(
            ptr.cast::<u8>(),
            new_ptr.cast::<u8>(),
            allocation.len.min(new_size),
        );
    }
    release_allocation(ptr, allocation);
    new_ptr
}

pub(crate) fn is_secure_pointer(state: &SecureMemoryState, ptr: *const c_void) -> bool {
    let address = ptr as usize;
    state
        .allocations
        .iter()
        .any(|(base, allocation)| address >= *base && address < base.saturating_add(allocation.len))
}

pub(crate) fn dump_stats(state: &SecureMemoryState, extended: bool) -> String {
    let base_blocks = state
        .allocations
        .values()
        .filter(|allocation| allocation.class == SecureClass::Base)
        .count();
    let overflow_blocks = state.allocations.len().saturating_sub(base_blocks);

    if extended {
        format!(
            "secmem: pool={}/{} blocks={} overflow={} locked-disabled={} not-locked={}\n",
            state.pool_used,
            state.pool_limit,
            state.allocations.len(),
            overflow_blocks,
            state.locked_disabled as u8,
            state.not_locked as u8
        )
    } else {
        format!(
            "secmem: pool={}/{} base={} overflow={}\n",
            state.pool_used, state.pool_limit, base_blocks, overflow_blocks
        )
    }
}
