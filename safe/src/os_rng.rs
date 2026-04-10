use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::get_errno;

const EINTR: i32 = 4;

#[repr(C)]
struct timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn getrandom(buffer: *mut u8, length: usize, flags: u32) -> isize;
    fn getpid() -> i32;
    fn clock_gettime(clock_id: i32, tp: *mut timespec) -> i32;
}

fn fallback_state() -> &'static Mutex<u64> {
    static STATE: OnceLock<Mutex<u64>> = OnceLock::new();
    STATE.get_or_init(|| {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0x6d5a_56b7_c3dd_e41b);
        Mutex::new(seed ^ 0x9e37_79b9_7f4a_7c15)
    })
}

fn fill_with_fallback(buffer: &mut [u8]) {
    let mut state = match fallback_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    for byte in buffer {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        *byte = (x & 0xff) as u8;
    }
}

fn fill_with_urandom(buffer: &mut [u8]) -> bool {
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(buffer))
        .is_ok()
}

fn fill_with_getrandom(buffer: &mut [u8]) -> bool {
    let mut offset = 0usize;
    while offset < buffer.len() {
        let result = unsafe { getrandom(buffer[offset..].as_mut_ptr(), buffer.len() - offset, 0) };
        if result > 0 {
            offset += result as usize;
            continue;
        }
        if result == -1 && get_errno() == EINTR {
            continue;
        }
        return false;
    }
    true
}

pub(crate) fn process_id() -> u32 {
    unsafe { getpid() as u32 }
}

pub(crate) fn monotonic_nanos() -> u64 {
    const CLOCK_MONOTONIC: i32 = 1;

    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) } == 0 {
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0)
    }
}

pub(crate) fn fill_fast_poll(buffer: &mut [u8]) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fill_random(buffer);

    let pid = process_id().to_le_bytes();
    let now = monotonic_nanos().to_le_bytes();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes();
    let stack_addr = (buffer.as_ptr() as usize as u64).to_le_bytes();
    let materials = [&pid[..], &now[..], &count[..], &stack_addr[..]];
    for (index, byte) in buffer.iter_mut().enumerate() {
        let material = materials[index % materials.len()];
        *byte ^= material[index % material.len()].rotate_left((index % 7) as u32);
    }
}

pub(crate) fn fill_random(buffer: &mut [u8]) {
    if buffer.is_empty() {
        return;
    }

    if fill_with_getrandom(buffer) {
        return;
    }
    if fill_with_urandom(buffer) {
        return;
    }
    fill_with_fallback(buffer);
}

pub(crate) fn close_random_device() {}
