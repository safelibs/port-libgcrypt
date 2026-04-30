#![allow(dead_code)]

use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::sync::OnceLock;

const RTLD_NOW: c_int = 2;
const RTLD_LOCAL: c_int = 0;

type CipherOpenFn = unsafe extern "C" fn(*mut *mut c_void, c_int, c_int, c_uint) -> u32;
type CipherCloseFn = unsafe extern "C" fn(*mut c_void);
type CipherCtlFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, usize) -> u32;
type CipherInfoFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, *mut usize) -> u32;
type CipherCryptFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, usize, *const c_void, usize) -> u32;
type CipherSetKeyFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type CipherSetIvFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type CipherSetCtrFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type CipherAuthenticateFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type CipherGetTagFn = unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> u32;
type CipherCheckTagFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *const c_char;
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct gcry_buffer_t {
    pub(crate) size: usize,
    pub(crate) off: usize,
    pub(crate) len: usize,
    pub(crate) data: *mut c_void,
}

pub(crate) struct UpstreamLibgcrypt {
    _handle: usize,
    pub(crate) cipher_open: CipherOpenFn,
    pub(crate) cipher_close: CipherCloseFn,
    pub(crate) cipher_ctl: CipherCtlFn,
    pub(crate) cipher_info: CipherInfoFn,
    pub(crate) cipher_encrypt: CipherCryptFn,
    pub(crate) cipher_decrypt: CipherCryptFn,
    pub(crate) cipher_setkey: CipherSetKeyFn,
    pub(crate) cipher_setiv: CipherSetIvFn,
    pub(crate) cipher_setctr: CipherSetCtrFn,
    pub(crate) cipher_authenticate: CipherAuthenticateFn,
    pub(crate) cipher_gettag: CipherGetTagFn,
    pub(crate) cipher_checktag: CipherCheckTagFn,
}

unsafe impl Send for UpstreamLibgcrypt {}
unsafe impl Sync for UpstreamLibgcrypt {}

fn describe_dlerror() -> String {
    let ptr = unsafe { dlerror() };
    if ptr.is_null() {
        "unknown dynamic loader error".to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

unsafe fn load_symbol<T>(handle: *mut c_void, name: &'static str) -> T
where
    T: Copy,
{
    let name_c = CString::new(name).expect("symbol name without NUL");
    let symbol = unsafe { dlsym(handle, name_c.as_ptr()) };
    if symbol.is_null() {
        panic!(
            "failed to load upstream libgcrypt symbol {name}: {}",
            describe_dlerror()
        );
    }
    unsafe { std::mem::transmute_copy::<*mut c_void, T>(&symbol) }
}

unsafe fn open_upstream_handle() -> *mut c_void {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(path) = std::env::var_os("SAFE_SYSTEM_LIBGCRYPT_PATH") {
        candidates.push(path.to_string_lossy().into_owned());
    }
    if let Some(path) = option_env!("SAFE_SYSTEM_LIBGCRYPT_PATH") {
        candidates.push(path.to_string());
    }
    candidates.extend(
        [
            "/lib/x86_64-linux-gnu/libgcrypt.so.20",
            "/usr/lib/x86_64-linux-gnu/libgcrypt.so.20",
            "/lib64/libgcrypt.so.20",
            "/usr/lib64/libgcrypt.so.20",
        ]
        .into_iter()
        .map(str::to_string),
    );

    for path in candidates {
        let Ok(path) = CString::new(path) else {
            continue;
        };
        let handle = unsafe { dlopen(path.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
        if !handle.is_null() {
            return handle;
        }
    }

    panic!(
        "unable to load upstream libgcrypt.so.20: {}",
        describe_dlerror()
    );
}

struct UpstreamRawApi {
    handle: usize,
}

unsafe impl Send for UpstreamRawApi {}
unsafe impl Sync for UpstreamRawApi {}

fn raw_api() -> &'static UpstreamRawApi {
    static RAW: OnceLock<UpstreamRawApi> = OnceLock::new();
    RAW.get_or_init(|| {
        let handle = unsafe { open_upstream_handle() };
        UpstreamRawApi {
            handle: handle as usize,
        }
    })
}

fn init() -> UpstreamLibgcrypt {
    let handle = raw_api().handle as *mut c_void;
    let check_version: unsafe extern "C" fn(*const c_char) -> *const c_char =
        unsafe { load_symbol(handle, "gcry_check_version") };
    let version = unsafe { check_version(std::ptr::null()) };
    if version.is_null() {
        panic!("upstream libgcrypt initialization via gcry_check_version failed");
    }

    UpstreamLibgcrypt {
        _handle: handle as usize,
        cipher_open: unsafe { load_symbol(handle, "gcry_cipher_open") },
        cipher_close: unsafe { load_symbol(handle, "gcry_cipher_close") },
        cipher_ctl: unsafe { load_symbol(handle, "gcry_cipher_ctl") },
        cipher_info: unsafe { load_symbol(handle, "gcry_cipher_info") },
        cipher_encrypt: unsafe { load_symbol(handle, "gcry_cipher_encrypt") },
        cipher_decrypt: unsafe { load_symbol(handle, "gcry_cipher_decrypt") },
        cipher_setkey: unsafe { load_symbol(handle, "gcry_cipher_setkey") },
        cipher_setiv: unsafe { load_symbol(handle, "gcry_cipher_setiv") },
        cipher_setctr: unsafe { load_symbol(handle, "gcry_cipher_setctr") },
        cipher_authenticate: unsafe { load_symbol(handle, "gcry_cipher_authenticate") },
        cipher_gettag: unsafe { load_symbol(handle, "gcry_cipher_gettag") },
        cipher_checktag: unsafe { load_symbol(handle, "gcry_cipher_checktag") },
    }
}

pub(crate) fn lib() -> &'static UpstreamLibgcrypt {
    static LIB: OnceLock<UpstreamLibgcrypt> = OnceLock::new();
    LIB.get_or_init(init)
}

pub(crate) fn cipher_open(
    handle: *mut *mut c_void,
    algo: c_int,
    mode: c_int,
    flags: c_uint,
) -> u32 {
    unsafe { (lib().cipher_open)(handle, algo, mode, flags) }
}

pub(crate) fn cipher_close(handle: *mut c_void) {
    unsafe { (lib().cipher_close)(handle) }
}

pub(crate) fn cipher_ctl(
    handle: *mut c_void,
    cmd: c_int,
    buffer: *mut c_void,
    buflen: usize,
) -> u32 {
    unsafe { (lib().cipher_ctl)(handle, cmd, buffer, buflen) }
}

pub(crate) fn cipher_info(
    handle: *mut c_void,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    unsafe { (lib().cipher_info)(handle, what, buffer, nbytes) }
}

pub(crate) fn cipher_encrypt(
    handle: *mut c_void,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> u32 {
    unsafe { (lib().cipher_encrypt)(handle, out, outsize, input, inlen) }
}

pub(crate) fn cipher_decrypt(
    handle: *mut c_void,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> u32 {
    unsafe { (lib().cipher_decrypt)(handle, out, outsize, input, inlen) }
}

pub(crate) fn cipher_setkey(handle: *mut c_void, key: *const c_void, keylen: usize) -> u32 {
    unsafe { (lib().cipher_setkey)(handle, key, keylen) }
}

pub(crate) fn cipher_setiv(handle: *mut c_void, iv: *const c_void, ivlen: usize) -> u32 {
    unsafe { (lib().cipher_setiv)(handle, iv, ivlen) }
}

pub(crate) fn cipher_setctr(handle: *mut c_void, ctr: *const c_void, ctrlen: usize) -> u32 {
    unsafe { (lib().cipher_setctr)(handle, ctr, ctrlen) }
}

pub(crate) fn cipher_authenticate(handle: *mut c_void, abuf: *const c_void, abuflen: usize) -> u32 {
    unsafe { (lib().cipher_authenticate)(handle, abuf, abuflen) }
}

pub(crate) fn cipher_gettag(handle: *mut c_void, outtag: *mut c_void, taglen: usize) -> u32 {
    unsafe { (lib().cipher_gettag)(handle, outtag, taglen) }
}

pub(crate) fn cipher_checktag(handle: *mut c_void, intag: *const c_void, taglen: usize) -> u32 {
    unsafe { (lib().cipher_checktag)(handle, intag, taglen) }
}
