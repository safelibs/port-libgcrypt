use std::ffi::{c_char, c_int, c_uint, c_void, CString};
use std::sync::OnceLock;

const RTLD_NOW: c_int = 2;
const RTLD_LOCAL: c_int = 0;

type CipherOpenFn = unsafe extern "C" fn(*mut *mut c_void, c_int, c_int, c_uint) -> u32;
type CipherCloseFn = unsafe extern "C" fn(*mut c_void);
type CipherCtlFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, usize) -> u32;
type CipherInfoFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, *mut usize) -> u32;
type CipherAlgoInfoFn = unsafe extern "C" fn(c_int, c_int, *mut c_void, *mut usize) -> u32;
type CipherAlgoNameFn = unsafe extern "C" fn(c_int) -> *const c_char;
type CipherMapNameFn = unsafe extern "C" fn(*const c_char) -> c_int;
type CipherModeFromOidFn = unsafe extern "C" fn(*const c_char) -> c_int;
type CipherCryptFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, usize, *const c_void, usize) -> u32;
type CipherSetKeyFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type CipherSetIvFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type CipherSetCtrFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type CipherAuthenticateFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type CipherGetTagFn = unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> u32;
type CipherCheckTagFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type CipherGetAlgoLenFn = unsafe extern "C" fn(c_int) -> usize;

type ControlFn = unsafe extern "C" fn(c_int, ...) -> u32;

extern "C" {
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
    pub(crate) cipher_algo_info: CipherAlgoInfoFn,
    pub(crate) cipher_algo_name: CipherAlgoNameFn,
    pub(crate) cipher_map_name: CipherMapNameFn,
    pub(crate) cipher_mode_from_oid: CipherModeFromOidFn,
    pub(crate) cipher_encrypt: CipherCryptFn,
    pub(crate) cipher_decrypt: CipherCryptFn,
    pub(crate) cipher_setkey: CipherSetKeyFn,
    pub(crate) cipher_setiv: CipherSetIvFn,
    pub(crate) cipher_setctr: CipherSetCtrFn,
    pub(crate) cipher_authenticate: CipherAuthenticateFn,
    pub(crate) cipher_gettag: CipherGetTagFn,
    pub(crate) cipher_checktag: CipherCheckTagFn,
    pub(crate) cipher_get_algo_keylen: CipherGetAlgoLenFn,
    pub(crate) cipher_get_algo_blklen: CipherGetAlgoLenFn,
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

pub(crate) unsafe fn load_symbol<T>(handle: *mut c_void, name: &'static str) -> T
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

pub(crate) unsafe fn open_upstream_handle() -> *mut c_void {
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
    control: ControlFn,
}

unsafe impl Send for UpstreamRawApi {}
unsafe impl Sync for UpstreamRawApi {}

fn raw_api() -> &'static UpstreamRawApi {
    static RAW: OnceLock<UpstreamRawApi> = OnceLock::new();
    RAW.get_or_init(|| {
        let handle = unsafe { open_upstream_handle() };
        let control = unsafe { load_symbol(handle, "gcry_control") };
        UpstreamRawApi {
            handle: handle as usize,
            control,
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
        cipher_algo_info: unsafe { load_symbol(handle, "gcry_cipher_algo_info") },
        cipher_algo_name: unsafe { load_symbol(handle, "gcry_cipher_algo_name") },
        cipher_map_name: unsafe { load_symbol(handle, "gcry_cipher_map_name") },
        cipher_mode_from_oid: unsafe { load_symbol(handle, "gcry_cipher_mode_from_oid") },
        cipher_encrypt: unsafe { load_symbol(handle, "gcry_cipher_encrypt") },
        cipher_decrypt: unsafe { load_symbol(handle, "gcry_cipher_decrypt") },
        cipher_setkey: unsafe { load_symbol(handle, "gcry_cipher_setkey") },
        cipher_setiv: unsafe { load_symbol(handle, "gcry_cipher_setiv") },
        cipher_setctr: unsafe { load_symbol(handle, "gcry_cipher_setctr") },
        cipher_authenticate: unsafe { load_symbol(handle, "gcry_cipher_authenticate") },
        cipher_gettag: unsafe { load_symbol(handle, "gcry_cipher_gettag") },
        cipher_checktag: unsafe { load_symbol(handle, "gcry_cipher_checktag") },
        cipher_get_algo_keylen: unsafe { load_symbol(handle, "gcry_cipher_get_algo_keylen") },
        cipher_get_algo_blklen: unsafe { load_symbol(handle, "gcry_cipher_get_algo_blklen") },
    }
}

pub(crate) fn lib() -> &'static UpstreamLibgcrypt {
    static LIB: OnceLock<UpstreamLibgcrypt> = OnceLock::new();
    LIB.get_or_init(init)
}

pub(crate) fn disable_hw_features_preinit(names: &std::ffi::CStr) -> u32 {
    unsafe { (raw_api().control)(63, names.as_ptr(), std::ptr::null::<c_void>()) }
}
