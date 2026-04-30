pub(crate) mod algorithms;

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::ptr::copy_nonoverlapping;

use crate::error;
use crate::upstream::gcry_buffer_t;

pub type gcry_md_hd_t = *mut gcry_md_handle;

const GCRY_MD_FLAG_SECURE: c_uint = 1;
const GCRY_MD_FLAG_HMAC: c_uint = 2;
const GCRY_MD_FLAG_BUGEMU1: c_uint = 0x0100;
const GCRYCTL_RESET: c_int = 4;
const GCRYCTL_FINALIZE: c_int = 5;
const GCRYCTL_TEST_ALGO: c_int = 8;
const GCRYCTL_IS_SECURE: c_int = 9;
const GCRYCTL_GET_ASNOID: c_int = 10;
const GCRYCTL_IS_ALGO_ENABLED: c_int = 35;
const GCRYCTL_SELFTEST: c_int = 57;

#[repr(C)]
pub struct gcry_md_handle {
    pub ctx: *mut c_void,
    pub bufpos: c_int,
    pub bufsize: c_int,
    pub buf: [u8; 1],
}

#[derive(Clone)]
struct DigestEntry {
    algo: c_int,
    state: algorithms::HashState,
    keyed_blake2_key: Option<Vec<u8>>,
    keyed_blake2_data: Vec<u8>,
    bugemu_whirlpool: Option<whirlpool::LibgcryptBugemu1>,
    hmac_data: Vec<u8>,
    result: Vec<u8>,
    xof_offset: usize,
}

impl DigestEntry {
    fn new(algo: c_int, bugemu1: bool) -> Option<Self> {
        Some(Self {
            algo,
            state: algorithms::HashState::new(algo)?,
            keyed_blake2_key: None,
            keyed_blake2_data: Vec::new(),
            bugemu_whirlpool: (bugemu1 && algo == algorithms::GCRY_MD_WHIRLPOOL)
                .then(whirlpool::LibgcryptBugemu1::new),
            hmac_data: Vec::new(),
            result: Vec::new(),
            xof_offset: 0,
        })
    }

    fn reset(&mut self) {
        if let Some(state) = algorithms::HashState::new(self.algo) {
            self.state = state;
        }
        self.keyed_blake2_key = None;
        self.keyed_blake2_data.clear();
        if let Some(bugemu) = &mut self.bugemu_whirlpool {
            *bugemu = whirlpool::LibgcryptBugemu1::new();
        }
        self.hmac_data.clear();
        self.result.clear();
        self.xof_offset = 0;
    }
}

#[derive(Clone)]
pub(crate) struct DigestContext {
    flags: c_uint,
    entries: Vec<DigestEntry>,
    hmac_key: Vec<u8>,
}

impl DigestContext {
    fn new(flags: c_uint) -> Self {
        Self {
            flags,
            entries: Vec::new(),
            hmac_key: Vec::new(),
        }
    }

    fn is_hmac(&self) -> bool {
        self.flags & GCRY_MD_FLAG_HMAC != 0
    }

    fn is_secure(&self) -> bool {
        self.flags & GCRY_MD_FLAG_SECURE != 0
    }

    fn uses_bugemu1(&self) -> bool {
        self.flags & GCRY_MD_FLAG_BUGEMU1 != 0
    }

    fn enable(&mut self, algo: c_int) -> u32 {
        if self.entries.iter().any(|entry| entry.algo == algo) {
            return 0;
        }
        if self.is_hmac() && algorithms::is_xof(algo) {
            return error::gcry_error_from_code(error::GPG_ERR_DIGEST_ALGO);
        }
        let Some(entry) = DigestEntry::new(algo, self.uses_bugemu1()) else {
            return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
        };
        self.entries.push(entry);
        0
    }

    fn write(&mut self, data: &[u8]) {
        if self.is_hmac() {
            for entry in &mut self.entries {
                entry.hmac_data.extend_from_slice(data);
                entry.result.clear();
            }
        } else {
            let bugemu1 = self.uses_bugemu1();
            for entry in &mut self.entries {
                if bugemu1 && entry.algo == algorithms::GCRY_MD_WHIRLPOOL {
                    if let Some(bugemu) = &mut entry.bugemu_whirlpool {
                        bugemu.update(data);
                    }
                } else if entry.keyed_blake2_key.is_some() {
                    entry.keyed_blake2_data.extend_from_slice(data);
                } else {
                    entry.state.update(data);
                }
                entry.result.clear();
            }
        }
    }

    fn reset(&mut self) {
        for entry in &mut self.entries {
            entry.reset();
        }
    }

    fn read(&mut self, algo: c_int) -> *mut u8 {
        let Some(algo) = self.resolve_algo(algo) else {
            return std::ptr::null_mut();
        };
        let is_hmac = self.is_hmac();
        let bugemu1 = self.uses_bugemu1();
        let hmac_key = self.hmac_key.clone();
        let Some(entry) = self.entries.iter_mut().find(|entry| entry.algo == algo) else {
            return std::ptr::null_mut();
        };
        if entry.result.is_empty() {
            entry.result = if is_hmac {
                algorithms::hmac_once(algo, &hmac_key, &entry.hmac_data).unwrap_or_default()
            } else if let Some(key) = &entry.keyed_blake2_key {
                algorithms::blake2_keyed_once(algo, key, &entry.keyed_blake2_data)
                    .unwrap_or_default()
            } else if bugemu1 && entry.algo == algorithms::GCRY_MD_WHIRLPOOL {
                entry
                    .bugemu_whirlpool
                    .as_ref()
                    .map(whirlpool::LibgcryptBugemu1::finalize)
                    .unwrap_or([0u8; 64])
                    .to_vec()
            } else {
                entry.state.finalize_vec()
            };
        }
        entry.result.as_mut_ptr()
    }

    fn extract(&mut self, algo: c_int, length: usize) -> Option<Vec<u8>> {
        let algo = self.resolve_algo(algo)?;
        if !algorithms::is_xof(algo) {
            return None;
        }
        let entry = self.entries.iter_mut().find(|entry| entry.algo == algo)?;
        let end = entry.xof_offset.checked_add(length)?;
        let stream = entry.state.xof_vec(end)?;
        let out = stream[entry.xof_offset..end].to_vec();
        entry.xof_offset = end;
        Some(out)
    }

    fn set_non_hmac_key(&mut self, key: &[u8]) -> u32 {
        if self.entries.is_empty()
            || self
                .entries
                .iter()
                .any(|entry| !algorithms::is_blake2(entry.algo))
        {
            return error::gcry_error_from_code(error::GPG_ERR_DIGEST_ALGO);
        }
        if self
            .entries
            .iter()
            .any(|entry| !algorithms::blake2_key_valid(entry.algo, key))
        {
            return error::gcry_error_from_code(error::GPG_ERR_INV_KEYLEN);
        }
        for entry in &mut self.entries {
            if let Some(state) = algorithms::HashState::new(entry.algo) {
                entry.state = state;
            }
            entry.keyed_blake2_key = Some(key.to_vec());
            entry.keyed_blake2_data.clear();
            entry.hmac_data.clear();
            entry.result.clear();
            entry.xof_offset = 0;
        }
        0
    }

    fn resolve_algo(&self, requested: c_int) -> Option<c_int> {
        if requested != 0 {
            return self
                .entries
                .iter()
                .any(|entry| entry.algo == requested)
                .then_some(requested);
        }
        (self.entries.len() == 1).then_some(self.entries[0].algo)
    }
}

fn ctx_mut<'a>(hd: gcry_md_hd_t) -> Option<&'a mut DigestContext> {
    if hd.is_null() {
        return None;
    }
    let ctx = unsafe { (*hd).ctx.cast::<DigestContext>() };
    if ctx.is_null() {
        None
    } else {
        Some(unsafe { &mut *ctx })
    }
}

fn ctx_ref<'a>(hd: gcry_md_hd_t) -> Option<&'a DigestContext> {
    if hd.is_null() {
        return None;
    }
    let ctx = unsafe { (*hd).ctx.cast::<DigestContext>() };
    if ctx.is_null() {
        None
    } else {
        Some(unsafe { &*ctx })
    }
}

fn flush_putc_buffer(hd: gcry_md_hd_t) {
    if hd.is_null() {
        return;
    }
    let len = unsafe { (*hd).bufpos.max(0) as usize };
    if len == 0 {
        return;
    }
    let mut bytes = [0u8; 1];
    bytes[0] = unsafe { (*hd).buf[0] };
    if let Some(ctx) = ctx_mut(hd) {
        ctx.write(&bytes[..len.min(1)]);
    }
    unsafe {
        (*hd).bufpos = 0;
    }
}

fn iov_bytes<'a>(iov: *const gcry_buffer_t, index: usize) -> Result<&'a [u8], u32> {
    let entry = unsafe { &*iov.add(index) };
    if entry.data.is_null() {
        return if entry.len == 0 {
            Ok(&[])
        } else {
            Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG))
        };
    }
    let start = entry
        .off
        .checked_add(0)
        .ok_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_ARG))?;
    let end = start
        .checked_add(entry.len)
        .ok_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_ARG))?;
    if entry.size != 0 && end > entry.size {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
    }
    Ok(unsafe { std::slice::from_raw_parts(entry.data.cast::<u8>().add(start), entry.len) })
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_open(h: *mut gcry_md_hd_t, algo: c_int, flags: c_uint) -> u32 {
    if h.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let supported_flags = GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC | GCRY_MD_FLAG_BUGEMU1;
    if flags & !supported_flags != 0 {
        unsafe { *h = std::ptr::null_mut() };
        return error::gcry_error_from_code(error::GPG_ERR_INV_FLAG);
    }

    let mut ctx = Box::new(DigestContext::new(flags));
    if algo != 0 {
        let err = ctx.enable(algo);
        if err != 0 {
            unsafe { *h = std::ptr::null_mut() };
            return err;
        }
    }
    let ctx_ptr = Box::into_raw(ctx);
    let handle = Box::new(gcry_md_handle {
        ctx: ctx_ptr.cast(),
        bufpos: 0,
        bufsize: 1,
        buf: [0],
    });
    unsafe { *h = Box::into_raw(handle) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_close(hd: gcry_md_hd_t) {
    if hd.is_null() {
        return;
    }
    unsafe {
        let handle = Box::from_raw(hd);
        if !handle.ctx.is_null() {
            drop(Box::from_raw(handle.ctx.cast::<DigestContext>()));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_enable(hd: gcry_md_hd_t, algo: c_int) -> u32 {
    flush_putc_buffer(hd);
    ctx_mut(hd)
        .map(|ctx| ctx.enable(algo))
        .unwrap_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_ARG))
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_copy(dest: *mut gcry_md_hd_t, src: gcry_md_hd_t) -> u32 {
    if dest.is_null() || src.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    flush_putc_buffer(src);
    let Some(src_ctx) = ctx_ref(src) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    let ctx_ptr = Box::into_raw(Box::new(src_ctx.clone()));
    let handle = Box::new(gcry_md_handle {
        ctx: ctx_ptr.cast(),
        bufpos: 0,
        bufsize: 1,
        buf: [0],
    });
    unsafe { *dest = Box::into_raw(handle) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_reset(hd: gcry_md_hd_t) {
    if hd.is_null() {
        return;
    }
    unsafe { (*hd).bufpos = 0 };
    if let Some(ctx) = ctx_mut(hd) {
        ctx.reset();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_ctl(
    hd: gcry_md_hd_t,
    cmd: c_int,
    _buffer: *mut c_void,
    _buflen: usize,
) -> u32 {
    match cmd {
        GCRYCTL_RESET => {
            gcry_md_reset(hd);
            0
        }
        GCRYCTL_FINALIZE => {
            flush_putc_buffer(hd);
            0
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_write(hd: gcry_md_hd_t, buffer: *const c_void, length: usize) {
    if hd.is_null() {
        return;
    }
    flush_putc_buffer(hd);
    if length == 0 {
        return;
    }
    if buffer.is_null() {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) };
    if let Some(ctx) = ctx_mut(hd) {
        ctx.write(data);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_read(hd: gcry_md_hd_t, algo: c_int) -> *mut u8 {
    flush_putc_buffer(hd);
    ctx_mut(hd)
        .map(|ctx| ctx.read(algo))
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_extract(
    hd: gcry_md_hd_t,
    algo: c_int,
    buffer: *mut c_void,
    length: usize,
) -> u32 {
    if buffer.is_null() && length != 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    flush_putc_buffer(hd);
    let Some(ctx) = ctx_mut(hd) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    let Some(out) = ctx.extract(algo, length) else {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    };
    if length != 0 {
        unsafe { copy_nonoverlapping(out.as_ptr(), buffer.cast::<u8>(), length) };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_hash_buffer(
    algo: c_int,
    digest: *mut c_void,
    buffer: *const c_void,
    length: usize,
) {
    if digest.is_null() || (buffer.is_null() && length != 0) {
        return;
    }
    let data = if length == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) }
    };
    if let Some(out) = algorithms::digest_once(algo, data) {
        unsafe { copy_nonoverlapping(out.as_ptr(), digest.cast::<u8>(), out.len()) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_hash_buffers(
    algo: c_int,
    flags: c_uint,
    digest: *mut c_void,
    iov: *const gcry_buffer_t,
    iovcnt: c_int,
) -> u32 {
    if digest.is_null() || iov.is_null() || iovcnt < 0 || flags & !GCRY_MD_FLAG_HMAC != 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if algorithms::is_xof(algo) {
        return error::gcry_error_from_code(error::GPG_ERR_DIGEST_ALGO);
    }
    if flags & GCRY_MD_FLAG_HMAC != 0 {
        if iovcnt < 1 {
            return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
        }
        let key = match iov_bytes(iov, 0) {
            Ok(bytes) => bytes,
            Err(err) => return err,
        };
        let mut data = Vec::new();
        for index in 1..iovcnt as usize {
            match iov_bytes(iov, index) {
                Ok(bytes) => data.extend_from_slice(bytes),
                Err(err) => return err,
            }
        }
        let Some(out) = algorithms::hmac_once(algo, key, &data) else {
            return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
        };
        unsafe { copy_nonoverlapping(out.as_ptr(), digest.cast::<u8>(), out.len()) };
        return 0;
    }

    let Some(mut state) = algorithms::HashState::new(algo) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    for index in 0..iovcnt as usize {
        match iov_bytes(iov, index) {
            Ok(bytes) => state.update(bytes),
            Err(err) => return err,
        }
    }
    let out = state.finalize_vec();
    unsafe { copy_nonoverlapping(out.as_ptr(), digest.cast::<u8>(), out.len()) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_get_algo(hd: gcry_md_hd_t) -> c_int {
    ctx_ref(hd)
        .and_then(|ctx| ctx.resolve_algo(0))
        .unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_get_algo_dlen(algo: c_int) -> c_uint {
    algorithms::digest_len(algo) as c_uint
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_is_enabled(hd: gcry_md_hd_t, algo: c_int) -> c_int {
    ctx_ref(hd)
        .map(|ctx| ctx.entries.iter().any(|entry| entry.algo == algo) as c_int)
        .unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_is_secure(hd: gcry_md_hd_t) -> c_int {
    ctx_ref(hd)
        .map(|ctx| ctx.is_secure() as c_int)
        .unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_info(
    hd: gcry_md_hd_t,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    let Some(ctx) = ctx_ref(hd) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    if nbytes.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    match what {
        GCRYCTL_IS_SECURE => {
            unsafe { *nbytes = ctx.is_secure() as usize };
            0
        }
        GCRYCTL_IS_ALGO_ENABLED => {
            if buffer.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            let algo = unsafe { *(buffer.cast::<c_int>()) };
            unsafe { *nbytes = ctx.entries.iter().any(|entry| entry.algo == algo) as usize };
            0
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_algo_info(
    algo: c_int,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    match what {
        GCRYCTL_TEST_ALGO | GCRYCTL_SELFTEST => {
            if algorithms::lookup(algo).is_some() {
                0
            } else {
                error::gcry_error_from_code(error::GPG_ERR_INV_ARG)
            }
        }
        GCRYCTL_GET_ASNOID => {
            let Some(asnoid) = algorithms::asnoid(algo) else {
                return error::gcry_error_from_code(error::GPG_ERR_NOT_FOUND);
            };
            if nbytes.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            let available = unsafe { *nbytes };
            unsafe { *nbytes = asnoid.len() };
            if buffer.is_null() {
                return 0;
            }
            if available < asnoid.len() {
                return error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT);
            }
            unsafe { copy_nonoverlapping(asnoid.as_ptr(), buffer.cast::<u8>(), asnoid.len()) };
            0
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_algo_name(algo: c_int) -> *const c_char {
    algorithms::algo_name(algo)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_map_name(name: *const c_char) -> c_int {
    algorithms::map_name(name)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_setkey(hd: gcry_md_hd_t, key: *const c_void, keylen: usize) -> u32 {
    if key.is_null() && keylen != 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let Some(ctx) = ctx_mut(hd) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    if !ctx.is_hmac() {
        let key = if keylen == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(key.cast::<u8>(), keylen) }
        };
        return ctx.set_non_hmac_key(key);
    }
    ctx.hmac_key.clear();
    if keylen != 0 {
        let bytes = unsafe { std::slice::from_raw_parts(key.cast::<u8>(), keylen) };
        ctx.hmac_key.extend_from_slice(bytes);
    }
    for entry in &mut ctx.entries {
        entry.result.clear();
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_md_debug(_hd: gcry_md_hd_t, _suffix: *const c_char) {}

#[unsafe(export_name = "safe_gcry_md_get")]
pub extern "C" fn safe_gcry_md_get(
    hd: gcry_md_hd_t,
    algo: c_int,
    buffer: *mut u8,
    buflen: c_int,
) -> u32 {
    if hd.is_null() || buffer.is_null() || buflen < 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    if crate::global::lock_runtime_state().fips_mode {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    }

    let Some(resolved) = ctx_ref(hd).and_then(|ctx| {
        if algo == 0 {
            ctx.resolve_algo(0)
        } else {
            Some(algo)
        }
    }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };

    if algorithms::is_xof(resolved) {
        return gcry_md_extract(hd, resolved, buffer.cast(), buflen as usize);
    }

    let digest_len = gcry_md_get_algo_dlen(resolved) as usize;
    if digest_len == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if (buflen as usize) < digest_len {
        return error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT);
    }

    let digest = gcry_md_read(hd, resolved);
    if digest.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    unsafe {
        copy_nonoverlapping(digest, buffer, digest_len);
    }
    0
}
