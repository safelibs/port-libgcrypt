use std::ffi::{CString, c_char, c_int, c_uint, c_ulong, c_void};
use std::sync::OnceLock;

const RTLD_NOW: c_int = 2;
const RTLD_LOCAL: c_int = 0;

type MdAlgoInfoFn = unsafe extern "C" fn(c_int, c_int, *mut c_void, *mut usize) -> u32;
type MdAlgoNameFn = unsafe extern "C" fn(c_int) -> *const c_char;
type MdCloseFn = unsafe extern "C" fn(*mut c_void);
type MdCopyFn = unsafe extern "C" fn(*mut *mut c_void, *mut c_void) -> u32;
type MdCtlFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, usize) -> u32;
type MdEnableFn = unsafe extern "C" fn(*mut c_void, c_int) -> u32;
type MdGetAlgoFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type MdGetAlgoDlenFn = unsafe extern "C" fn(c_int) -> c_uint;
type MdHashBufferFn = unsafe extern "C" fn(c_int, *mut c_void, *const c_void, usize);
type MdHashBuffersFn =
    unsafe extern "C" fn(c_int, c_uint, *mut c_void, *const gcry_buffer_t, c_int) -> u32;
type MdInfoFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, *mut usize) -> u32;
type MdIsEnabledFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type MdIsSecureFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type MdMapNameFn = unsafe extern "C" fn(*const c_char) -> c_int;
type MdOpenFn = unsafe extern "C" fn(*mut *mut c_void, c_int, c_uint) -> u32;
type MdReadFn = unsafe extern "C" fn(*mut c_void, c_int) -> *mut u8;
type MdExtractFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, usize) -> u32;
type MdResetFn = unsafe extern "C" fn(*mut c_void);
type MdSetKeyFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type MdWriteFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize);
type MdDebugFn = unsafe extern "C" fn(*mut c_void, *const c_char);

type MacAlgoInfoFn = unsafe extern "C" fn(c_int, c_int, *mut c_void, *mut usize) -> u32;
type MacAlgoNameFn = unsafe extern "C" fn(c_int) -> *const c_char;
type MacMapNameFn = unsafe extern "C" fn(*const c_char) -> c_int;
type MacGetAlgoFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type MacGetAlgoMaclenFn = unsafe extern "C" fn(c_int) -> c_uint;
type MacGetAlgoKeylenFn = unsafe extern "C" fn(c_int) -> c_uint;
type MacOpenFn = unsafe extern "C" fn(*mut *mut c_void, c_int, c_uint, *mut c_void) -> u32;
type MacCloseFn = unsafe extern "C" fn(*mut c_void);
type MacSetKeyFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type MacSetIvFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type MacWriteFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type MacReadFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut usize) -> u32;
type MacVerifyFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> u32;
type MacCtlFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, usize) -> u32;

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

type KdfDeriveFn = unsafe extern "C" fn(
    *const c_void,
    usize,
    c_int,
    c_int,
    *const c_void,
    usize,
    c_ulong,
    usize,
    *mut c_void,
) -> u32;
type KdfOpenFn = unsafe extern "C" fn(
    *mut *mut c_void,
    c_int,
    c_int,
    *const c_ulong,
    c_uint,
    *const c_void,
    usize,
    *const c_void,
    usize,
    *const c_void,
    usize,
    *const c_void,
    usize,
) -> u32;
type KdfComputeFn =
    unsafe extern "C" fn(*mut c_void, *const crate::kdf::gcry_kdf_thread_ops_t) -> u32;
type KdfFinalFn = unsafe extern "C" fn(*mut c_void, usize, *mut c_void) -> u32;
type KdfCloseFn = unsafe extern "C" fn(*mut c_void);

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
    pub(crate) md_algo_info: MdAlgoInfoFn,
    pub(crate) md_algo_name: MdAlgoNameFn,
    pub(crate) md_close: MdCloseFn,
    pub(crate) md_copy: MdCopyFn,
    pub(crate) md_ctl: MdCtlFn,
    pub(crate) md_enable: MdEnableFn,
    pub(crate) md_get_algo: MdGetAlgoFn,
    pub(crate) md_get_algo_dlen: MdGetAlgoDlenFn,
    pub(crate) md_hash_buffer: MdHashBufferFn,
    pub(crate) md_hash_buffers: MdHashBuffersFn,
    pub(crate) md_info: MdInfoFn,
    pub(crate) md_is_enabled: MdIsEnabledFn,
    pub(crate) md_is_secure: MdIsSecureFn,
    pub(crate) md_map_name: MdMapNameFn,
    pub(crate) md_open: MdOpenFn,
    pub(crate) md_read: MdReadFn,
    pub(crate) md_extract: MdExtractFn,
    pub(crate) md_reset: MdResetFn,
    pub(crate) md_setkey: MdSetKeyFn,
    pub(crate) md_write: MdWriteFn,
    pub(crate) md_debug: MdDebugFn,
    pub(crate) mac_algo_info: MacAlgoInfoFn,
    pub(crate) mac_algo_name: MacAlgoNameFn,
    pub(crate) mac_map_name: MacMapNameFn,
    pub(crate) mac_get_algo: MacGetAlgoFn,
    pub(crate) mac_get_algo_maclen: MacGetAlgoMaclenFn,
    pub(crate) mac_get_algo_keylen: MacGetAlgoKeylenFn,
    pub(crate) mac_open: MacOpenFn,
    pub(crate) mac_close: MacCloseFn,
    pub(crate) mac_setkey: MacSetKeyFn,
    pub(crate) mac_setiv: MacSetIvFn,
    pub(crate) mac_write: MacWriteFn,
    pub(crate) mac_read: MacReadFn,
    pub(crate) mac_verify: MacVerifyFn,
    pub(crate) mac_ctl: MacCtlFn,
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
    pub(crate) kdf_derive: KdfDeriveFn,
    pub(crate) kdf_open: KdfOpenFn,
    pub(crate) kdf_compute: KdfComputeFn,
    pub(crate) kdf_final: KdfFinalFn,
    pub(crate) kdf_close: KdfCloseFn,
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
        panic!("failed to load upstream libgcrypt symbol {name}: {}", describe_dlerror());
    }
    unsafe { std::mem::transmute_copy::<*mut c_void, T>(&symbol) }
}

unsafe fn open_upstream_handle() -> *mut c_void {
    let mut candidates = Vec::new();
    if let Some(path) = option_env!("SAFE_SYSTEM_LIBGCRYPT_PATH") {
        candidates.push(path);
    }
    candidates.extend([
        "/lib/x86_64-linux-gnu/libgcrypt.so.20",
        "/usr/lib/x86_64-linux-gnu/libgcrypt.so.20",
        "/lib64/libgcrypt.so.20",
        "/usr/lib64/libgcrypt.so.20",
    ]);

    for path in candidates {
        let Ok(path) = CString::new(path) else {
            continue;
        };
        let handle = unsafe { dlopen(path.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
        if !handle.is_null() {
            return handle;
        }
    }

    panic!("unable to load upstream libgcrypt.so.20: {}", describe_dlerror());
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
        md_algo_info: unsafe { load_symbol(handle, "gcry_md_algo_info") },
        md_algo_name: unsafe { load_symbol(handle, "gcry_md_algo_name") },
        md_close: unsafe { load_symbol(handle, "gcry_md_close") },
        md_copy: unsafe { load_symbol(handle, "gcry_md_copy") },
        md_ctl: unsafe { load_symbol(handle, "gcry_md_ctl") },
        md_enable: unsafe { load_symbol(handle, "gcry_md_enable") },
        md_get_algo: unsafe { load_symbol(handle, "gcry_md_get_algo") },
        md_get_algo_dlen: unsafe { load_symbol(handle, "gcry_md_get_algo_dlen") },
        md_hash_buffer: unsafe { load_symbol(handle, "gcry_md_hash_buffer") },
        md_hash_buffers: unsafe { load_symbol(handle, "gcry_md_hash_buffers") },
        md_info: unsafe { load_symbol(handle, "gcry_md_info") },
        md_is_enabled: unsafe { load_symbol(handle, "gcry_md_is_enabled") },
        md_is_secure: unsafe { load_symbol(handle, "gcry_md_is_secure") },
        md_map_name: unsafe { load_symbol(handle, "gcry_md_map_name") },
        md_open: unsafe { load_symbol(handle, "gcry_md_open") },
        md_read: unsafe { load_symbol(handle, "gcry_md_read") },
        md_extract: unsafe { load_symbol(handle, "gcry_md_extract") },
        md_reset: unsafe { load_symbol(handle, "gcry_md_reset") },
        md_setkey: unsafe { load_symbol(handle, "gcry_md_setkey") },
        md_write: unsafe { load_symbol(handle, "gcry_md_write") },
        md_debug: unsafe { load_symbol(handle, "gcry_md_debug") },
        mac_algo_info: unsafe { load_symbol(handle, "gcry_mac_algo_info") },
        mac_algo_name: unsafe { load_symbol(handle, "gcry_mac_algo_name") },
        mac_map_name: unsafe { load_symbol(handle, "gcry_mac_map_name") },
        mac_get_algo: unsafe { load_symbol(handle, "gcry_mac_get_algo") },
        mac_get_algo_maclen: unsafe { load_symbol(handle, "gcry_mac_get_algo_maclen") },
        mac_get_algo_keylen: unsafe { load_symbol(handle, "gcry_mac_get_algo_keylen") },
        mac_open: unsafe { load_symbol(handle, "gcry_mac_open") },
        mac_close: unsafe { load_symbol(handle, "gcry_mac_close") },
        mac_setkey: unsafe { load_symbol(handle, "gcry_mac_setkey") },
        mac_setiv: unsafe { load_symbol(handle, "gcry_mac_setiv") },
        mac_write: unsafe { load_symbol(handle, "gcry_mac_write") },
        mac_read: unsafe { load_symbol(handle, "gcry_mac_read") },
        mac_verify: unsafe { load_symbol(handle, "gcry_mac_verify") },
        mac_ctl: unsafe { load_symbol(handle, "gcry_mac_ctl") },
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
        kdf_derive: unsafe { load_symbol(handle, "gcry_kdf_derive") },
        kdf_open: unsafe { load_symbol(handle, "gcry_kdf_open") },
        kdf_compute: unsafe { load_symbol(handle, "gcry_kdf_compute") },
        kdf_final: unsafe { load_symbol(handle, "gcry_kdf_final") },
        kdf_close: unsafe { load_symbol(handle, "gcry_kdf_close") },
    }
}

pub(crate) fn lib() -> &'static UpstreamLibgcrypt {
    static LIB: OnceLock<UpstreamLibgcrypt> = OnceLock::new();
    LIB.get_or_init(init)
}

pub(crate) fn disable_hw_features_preinit(names: &std::ffi::CStr) -> u32 {
    unsafe { (raw_api().control)(63, names.as_ptr(), std::ptr::null::<c_void>()) }
}
