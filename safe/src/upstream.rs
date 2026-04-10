use std::ffi::{c_char, c_int, c_void, CString};
use std::sync::OnceLock;

const RTLD_NOW: c_int = 2;
const RTLD_LOCAL: c_int = 0;

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
    control: ControlFn,
}

unsafe impl Send for UpstreamRawApi {}
unsafe impl Sync for UpstreamRawApi {}

fn raw_api() -> &'static UpstreamRawApi {
    static RAW: OnceLock<UpstreamRawApi> = OnceLock::new();
    RAW.get_or_init(|| {
        let handle = unsafe { open_upstream_handle() };
        let check_version: unsafe extern "C" fn(*const c_char) -> *const c_char =
            unsafe { load_symbol(handle, "gcry_check_version") };
        let version = unsafe { check_version(std::ptr::null()) };
        if version.is_null() {
            panic!("upstream libgcrypt initialization via gcry_check_version failed");
        }
        let control = unsafe { load_symbol(handle, "gcry_control") };
        UpstreamRawApi { control }
    })
}

pub(crate) fn disable_hw_features_preinit(names: &std::ffi::CStr) -> u32 {
    unsafe { (raw_api().control)(63, names.as_ptr(), std::ptr::null::<c_void>()) }
}
