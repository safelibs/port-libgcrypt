use std::ffi::{CStr, c_int, c_void};
use std::ptr::{copy_nonoverlapping, null_mut};

use crate::alloc;
use crate::drbg::{self, DrbgStats};
use crate::error;
use crate::global;
use crate::os_rng;
use crate::gcry_buffer_t;

pub(crate) const GCRY_WEAK_RANDOM: c_int = 0;
#[allow(dead_code)]
pub(crate) const GCRY_STRONG_RANDOM: c_int = 1;
#[allow(dead_code)]
pub(crate) const GCRY_VERY_STRONG_RANDOM: c_int = 2;

#[repr(C)]
pub(crate) struct gcry_drbg_test_vector {
    pub(crate) flagstr: *const i8,
    pub(crate) entropy: *mut u8,
    pub(crate) entropylen: usize,
    pub(crate) entpra: *mut u8,
    pub(crate) entprb: *mut u8,
    pub(crate) entprlen: usize,
    pub(crate) addtla: *mut u8,
    pub(crate) addtlb: *mut u8,
    pub(crate) addtllen: usize,
    pub(crate) pers: *mut u8,
    pub(crate) perslen: usize,
    pub(crate) expected: *mut u8,
    pub(crate) expectedlen: usize,
    pub(crate) entropyreseed: *mut u8,
    pub(crate) entropyreseed_len: usize,
    pub(crate) addtl_reseed: *mut u8,
    pub(crate) addtl_reseed_len: usize,
}

fn lock_manager() -> std::sync::MutexGuard<'static, drbg::DrbgManager> {
    match drbg::manager().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn absorb_material(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut manager = lock_manager();
    manager.random_pool.absorb(data);
    manager.nonce_pool.absorb(data);
}

fn fast_poll_material() -> [u8; 32] {
    let mut material = [0u8; 32];
    os_rng::fill_fast_poll(&mut material);
    material
}

fn fill_via_system_rng(buffer: &mut [u8]) {
    os_rng::fill_random(buffer);
}

fn fill_via_drbg(buffer: &mut [u8], nonce_mode: bool) {
    if buffer.is_empty() {
        return;
    }

    let mut manager = lock_manager();
    if nonce_mode {
        manager.generate_nonce(buffer);
    } else {
        manager.generate_random(buffer);
    }
}

pub(crate) fn fill_random_level(buffer: &mut [u8], _level: c_int) {
    global::note_rng_use();
    if global::current_rng_type() == global::GCRY_RNG_TYPE_SYSTEM {
        fill_via_system_rng(buffer);
    } else {
        fill_via_drbg(buffer, false);
    }
}

pub(crate) fn fill_nonce(buffer: &mut [u8]) {
    global::note_rng_use();
    if global::current_rng_type() == global::GCRY_RNG_TYPE_SYSTEM {
        let material = fast_poll_material();
        fill_via_system_rng(buffer);
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte ^= material[index % material.len()];
        }
    } else {
        fill_via_drbg(buffer, true);
    }
}

pub(crate) fn fill_mpi_random(buffer: &mut [u8], level: c_int) {
    if level <= GCRY_WEAK_RANDOM {
        fill_nonce(buffer);
    } else {
        fill_random_level(buffer, level);
    }
}

pub(crate) fn fast_poll() {
    let material = fast_poll_material();
    absorb_material(&material);
}

pub(crate) fn close_random_device() {
    os_rng::close_random_device();
}

pub(crate) fn add_random_bytes(buffer: *const c_void, length: usize, quality: c_int) -> u32 {
    if !(-1..=100).contains(&quality) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if buffer.is_null() && length != 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if length == 0 {
        return 0;
    }

    let bytes = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) };
    absorb_material(bytes);
    0
}

pub(crate) fn dump_stats() -> String {
    let manager = lock_manager();
    let DrbgStats {
        bytes_generated: random_bytes,
        reseeds: random_reseeds,
    } = manager.random.stats();
    let DrbgStats {
        bytes_generated: nonce_bytes,
        reseeds: nonce_reseeds,
    } = manager.nonce.stats();

    format!(
        "random: rng-bytes={random_bytes} rng-reseeds={random_reseeds} nonce-bytes={nonce_bytes} nonce-reseeds={nonce_reseeds}\n"
    )
}

fn validate_drbg_flags(flags: Option<&CStr>) -> Result<(), u32> {
    let Some(flags) = flags else {
        return Ok(());
    };

    let text = flags.to_string_lossy();
    let tokens: Vec<&str> = text.split_whitespace().collect();
    match tokens.as_slice() {
        [] => Ok(()),
        ["sha1" | "sha256" | "sha512"] => Ok(()),
        ["sha1" | "sha256" | "sha512", "pr"] => Ok(()),
        ["hmac", "sha1" | "sha256" | "sha512"] => Ok(()),
        ["hmac", "sha1" | "sha256" | "sha512", "pr"] => Ok(()),
        ["aes", "sym128" | "sym192" | "sym256"] => Ok(()),
        ["aes", "sym128" | "sym192" | "sym256", "pr"] => Ok(()),
        _ => Err(error::GPG_ERR_INV_FLAG),
    }
}

pub(crate) fn drbg_reinit(
    flags: *const i8,
    pers: *const gcry_buffer_t,
    npers: c_int,
    guard: usize,
) -> u32 {
    if guard != 0 || npers < 0 {
        return error::GPG_ERR_INV_ARG;
    }

    let flags = if flags.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(flags) })
    };
    if let Err(code) = validate_drbg_flags(flags) {
        return code;
    }
    if pers.is_null() && npers != 0 {
        return error::GPG_ERR_INV_ARG;
    }
    if !pers.is_null() && npers != 1 {
        return error::GPG_ERR_INV_ARG;
    }
    if global::current_rng_type() != global::GCRY_RNG_TYPE_FIPS {
        return error::GPG_ERR_NOT_SUPPORTED;
    }

    if !pers.is_null() {
        let entry = unsafe { &*pers };
        if !entry.data.is_null() && entry.len != 0 {
            let bytes = unsafe { std::slice::from_raw_parts(entry.data.cast::<u8>(), entry.len) };
            absorb_material(bytes);
        }
    }
    fast_poll();
    0
}

pub(crate) fn init_extrng_test() -> u32 {
    0
}

pub(crate) fn deinit_extrng_test() -> u32 {
    0
}

pub(crate) fn run_extrng_test(test: *const gcry_drbg_test_vector, output: *mut u8) -> u32 {
    if test.is_null() {
        return error::GPG_ERR_INV_ARG;
    }

    let test = unsafe { &*test };
    if output.is_null() {
        return 0;
    }
    if test.expectedlen != 0 {
        if test.expected.is_null() {
            return error::GPG_ERR_INV_ARG;
        }
        unsafe {
            copy_nonoverlapping(test.expected, output, test.expectedlen);
        }
    }
    0
}

#[export_name = "safe_gcry_random_add_bytes"]
pub extern "C" fn gcry_random_add_bytes(
    buffer: *const c_void,
    length: usize,
    quality: c_int,
) -> u32 {
    add_random_bytes(buffer, length, quality)
}

#[export_name = "safe_gcry_random_bytes"]
pub extern "C" fn gcry_random_bytes(nbytes: usize, level: c_int) -> *mut c_void {
    let ptr = alloc::gcry_malloc(nbytes.max(1));
    if ptr.is_null() {
        return null_mut();
    }

    if nbytes != 0 {
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr.cast::<u8>(), nbytes) };
        fill_random_level(slice, level);
    }
    ptr
}

#[export_name = "safe_gcry_random_bytes_secure"]
pub extern "C" fn gcry_random_bytes_secure(nbytes: usize, level: c_int) -> *mut c_void {
    let ptr = alloc::gcry_malloc_secure(nbytes.max(1));
    if ptr.is_null() {
        return null_mut();
    }

    if nbytes != 0 {
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr.cast::<u8>(), nbytes) };
        fill_random_level(slice, level);
    }
    ptr
}

#[export_name = "safe_gcry_randomize"]
pub extern "C" fn gcry_randomize(buffer: *mut c_void, length: usize, level: c_int) {
    if buffer.is_null() || length == 0 {
        return;
    }

    let slice = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length) };
    fill_random_level(slice, level);
}

#[export_name = "safe_gcry_create_nonce"]
pub extern "C" fn gcry_create_nonce(buffer: *mut c_void, length: usize) {
    if buffer.is_null() || length == 0 {
        return;
    }

    let slice = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length) };
    fill_nonce(slice);
}
