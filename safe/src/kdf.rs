use std::ffi::{c_int, c_uint, c_ulong, c_void};

use crate::upstream;

pub type gcry_kdf_hd_t = *mut gcry_kdf_handle;
pub type gcry_kdf_job_fn_t = Option<unsafe extern "C" fn(*mut c_void)>;
pub type gcry_kdf_dispatch_job_fn_t =
    Option<unsafe extern "C" fn(*mut c_void, gcry_kdf_job_fn_t, *mut c_void) -> c_int>;
pub type gcry_kdf_wait_all_jobs_fn_t = Option<unsafe extern "C" fn(*mut c_void) -> c_int>;

#[repr(C)]
pub struct gcry_kdf_handle {
    _private: [u8; 0],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct gcry_kdf_thread_ops_t {
    pub jobs_context: *mut c_void,
    pub dispatch_job: gcry_kdf_dispatch_job_fn_t,
    pub wait_all_jobs: gcry_kdf_wait_all_jobs_fn_t,
}

#[no_mangle]
pub extern "C" fn gcry_kdf_derive(
    passphrase: *const c_void,
    passphraselen: usize,
    algo: c_int,
    subalgo: c_int,
    salt: *const c_void,
    saltlen: usize,
    iterations: c_ulong,
    keysize: usize,
    keybuffer: *mut c_void,
) -> u32 {
    unsafe {
        (upstream::lib().kdf_derive)(
            passphrase,
            passphraselen,
            algo,
            subalgo,
            salt,
            saltlen,
            iterations,
            keysize,
            keybuffer,
        )
    }
}

#[no_mangle]
pub extern "C" fn gcry_kdf_open(
    hd: *mut gcry_kdf_hd_t,
    algo: c_int,
    subalgo: c_int,
    param: *const c_ulong,
    paramlen: c_uint,
    passphrase: *const c_void,
    passphraselen: usize,
    salt: *const c_void,
    saltlen: usize,
    key: *const c_void,
    keylen: usize,
    ad: *const c_void,
    adlen: usize,
) -> u32 {
    unsafe {
        (upstream::lib().kdf_open)(
            hd.cast(),
            algo,
            subalgo,
            param,
            paramlen,
            passphrase,
            passphraselen,
            salt,
            saltlen,
            key,
            keylen,
            ad,
            adlen,
        )
    }
}

#[no_mangle]
pub extern "C" fn gcry_kdf_compute(hd: gcry_kdf_hd_t, ops: *const gcry_kdf_thread_ops_t) -> u32 {
    unsafe { (upstream::lib().kdf_compute)(hd.cast(), ops) }
}

#[no_mangle]
pub extern "C" fn gcry_kdf_final(hd: gcry_kdf_hd_t, resultlen: usize, result: *mut c_void) -> u32 {
    unsafe { (upstream::lib().kdf_final)(hd.cast(), resultlen, result) }
}

#[no_mangle]
pub extern "C" fn gcry_kdf_close(hd: gcry_kdf_hd_t) {
    unsafe { (upstream::lib().kdf_close)(hd.cast()) }
}
