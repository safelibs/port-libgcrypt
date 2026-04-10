use std::ffi::{c_int, c_uint, c_ulong, c_void};
use std::mem::{size_of, zeroed};
use std::ptr::{copy_nonoverlapping, drop_in_place, null_mut, write};

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use scrypt::{Params as ScryptParams, scrypt as scrypt_derive};

use crate::alloc;
use crate::digest;
use crate::error;

const GCRY_KDF_SIMPLE_S2K: c_int = 16;
const GCRY_KDF_SALTED_S2K: c_int = 17;
const GCRY_KDF_ITERSALTED_S2K: c_int = 19;
const GCRY_KDF_PBKDF1: c_int = 33;
const GCRY_KDF_PBKDF2: c_int = 34;
const GCRY_KDF_SCRYPT: c_int = 48;
const GCRY_KDF_ARGON2: c_int = 64;

const GCRY_KDF_ARGON2D: c_int = 0;
const GCRY_KDF_ARGON2I: c_int = 1;
const GCRY_KDF_ARGON2ID: c_int = 2;

const GPG_ERR_DIGEST_ALGO: u32 = 5;
const GPG_ERR_CANCELED: u32 = 99;
const GPG_ERR_INV_VALUE: u32 = 55;
const GPG_ERR_INV_DATA: u32 = 79;
const GPG_ERR_UNSUPPORTED_ALGORITHM: u32 = 84;
const GPG_ERR_UNKNOWN_ALGORITHM: u32 = 149;
const MAX_DIGEST_LEN: usize = 64;

const GCRY_MD_FLAG_SECURE: c_uint = 1;
const GCRY_MD_FLAG_HMAC: c_uint = 2;

pub type gcry_kdf_hd_t = *mut gcry_kdf_handle;
pub type gcry_kdf_job_fn_t = Option<unsafe extern "C" fn(*mut c_void)>;
pub type gcry_kdf_dispatch_job_fn_t =
    Option<unsafe extern "C" fn(*mut c_void, gcry_kdf_job_fn_t, *mut c_void) -> c_int>;
pub type gcry_kdf_wait_all_jobs_fn_t = Option<unsafe extern "C" fn(*mut c_void) -> c_int>;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct gcry_kdf_thread_ops_t {
    pub jobs_context: *mut c_void,
    pub dispatch_job: gcry_kdf_dispatch_job_fn_t,
    pub wait_all_jobs: gcry_kdf_wait_all_jobs_fn_t,
}

struct SecureBytes {
    ptr: *mut u8,
    len: usize,
}

impl SecureBytes {
    fn new_zeroed(len: usize) -> Option<Self> {
        if len == 0 {
            return Some(Self {
                ptr: null_mut(),
                len: 0,
            });
        }

        let ptr = alloc::gcry_calloc_secure(1, len).cast::<u8>();
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr, len })
        }
    }

    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr.cast_const(), self.len) }
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.len == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
        }
    }
}

impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        let mut copy = Self::new_zeroed(self.len).expect("secure byte clone allocation");
        copy.as_mut_slice().copy_from_slice(self.as_slice());
        copy
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            alloc::gcry_free(self.ptr.cast());
        }
    }
}

#[derive(Clone)]
enum ByteBuffer {
    Plain(Vec<u8>),
    Secure(SecureBytes),
}

impl ByteBuffer {
    fn new_zeroed(len: usize, secure: bool) -> Option<Self> {
        if secure {
            SecureBytes::new_zeroed(len).map(Self::Secure)
        } else {
            Some(Self::Plain(vec![0u8; len]))
        }
    }

    fn copy_from_slice(bytes: &[u8], secure: bool) -> Option<Self> {
        let mut buffer = Self::new_zeroed(bytes.len(), secure)?;
        buffer.as_mut_slice().copy_from_slice(bytes);
        Some(buffer)
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            ByteBuffer::Plain(buffer) => buffer.as_slice(),
            ByteBuffer::Secure(buffer) => buffer.as_slice(),
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            ByteBuffer::Plain(buffer) => buffer.as_mut_slice(),
            ByteBuffer::Secure(buffer) => buffer.as_mut_slice(),
        }
    }
}

struct Argon2Context {
    secure: bool,
    algorithm: Algorithm,
    output_len: usize,
    password: ByteBuffer,
    salt: ByteBuffer,
    secret: ByteBuffer,
    associated_data: ByteBuffer,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    result: Option<ByteBuffer>,
}

enum KdfState {
    Argon2(Argon2Context),
}

pub struct gcry_kdf_handle {
    state: KdfState,
}

fn slice_from_ptr<'a>(ptr: *const c_void, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) })
    }
}

fn slice_from_ptr_mut<'a>(ptr: *mut c_void, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        Some(&mut [])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts_mut(ptr.cast::<u8>(), len) })
    }
}

fn copy_buffer_from_ptr(
    ptr: *const c_void,
    len: usize,
    secure: bool,
    null_error: u32,
) -> Result<ByteBuffer, u32> {
    let bytes =
        slice_from_ptr(ptr, len).ok_or_else(|| error::gcry_error_from_code(null_error))?;
    ByteBuffer::copy_from_slice(bytes, secure)
        .ok_or_else(|| error::gcry_error_from_errno(crate::get_errno()))
}

fn md_open(algo: c_int, hmac: bool, secure: bool) -> Result<digest::gcry_md_hd_t, u32> {
    let mut hd = unsafe { zeroed() };
    let flags = if hmac { GCRY_MD_FLAG_HMAC } else { 0 } | if secure { GCRY_MD_FLAG_SECURE } else { 0 };
    let rc = digest::gcry_md_open(&mut hd, algo, flags);
    if rc == 0 {
        Ok(hd)
    } else {
        Err(rc)
    }
}

fn md_write_all(hd: digest::gcry_md_hd_t, data: &[u8]) {
    digest::gcry_md_write(hd, data.as_ptr().cast(), data.len());
}

fn md_read_into(hd: digest::gcry_md_hd_t, algo: c_int, output: &mut [u8]) -> Result<(), u32> {
    let dlen = digest::gcry_md_get_algo_dlen(algo) as usize;
    if dlen == 0 || output.len() != dlen {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    }

    let ptr = digest::gcry_md_read(hd, algo);
    if ptr.is_null() {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    }

    unsafe {
        copy_nonoverlapping(ptr.cast_const(), output.as_mut_ptr(), dlen);
    }
    Ok(())
}

fn openpgp_s2k(
    passphrase: *const c_void,
    passphraselen: usize,
    algo: c_int,
    hashalgo: c_int,
    salt: *const c_void,
    saltlen: usize,
    iterations: c_ulong,
    keybuffer: *mut c_void,
    keysize: usize,
) -> u32 {
    const ZERO_CHUNK: [u8; 64] = [0u8; 64];

    if (algo == GCRY_KDF_SALTED_S2K || algo == GCRY_KDF_ITERSALTED_S2K)
        && (salt.is_null() || saltlen != 8)
    {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }

    let pass = match slice_from_ptr(passphrase, passphraselen) {
        Some(bytes) => bytes,
        None => return error::gcry_error_from_code(GPG_ERR_INV_DATA),
    };
    let salt = match slice_from_ptr(salt, saltlen) {
        Some(bytes) => bytes,
        None => return error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    };
    let key = match slice_from_ptr_mut(keybuffer, keysize) {
        Some(bytes) => bytes,
        None => return error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    };

    let secure = alloc::gcry_is_secure(passphrase) != 0 || alloc::gcry_is_secure(keybuffer) != 0;
    let dlen = digest::gcry_md_get_algo_dlen(hashalgo) as usize;
    if dlen == 0 || dlen > MAX_DIGEST_LEN {
        return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
    }

    let md = match md_open(hashalgo, false, secure) {
        Ok(hd) => hd,
        Err(code) => return code,
    };

    let mut used = 0usize;
    let mut pass_index = 0usize;
    while used < key.len() {
        if pass_index > 0 {
            digest::gcry_md_reset(md);
            let mut remaining = pass_index;
            while remaining > 0 {
                let chunk_len = remaining.min(ZERO_CHUNK.len());
                md_write_all(md, &ZERO_CHUNK[..chunk_len]);
                remaining -= chunk_len;
            }
        }

        if algo == GCRY_KDF_SALTED_S2K || algo == GCRY_KDF_ITERSALTED_S2K {
            let len2 = pass.len() + 8;
            let mut count = if algo == GCRY_KDF_ITERSALTED_S2K {
                (iterations as usize).max(len2)
            } else {
                len2
            };

            while count > len2 {
                md_write_all(md, salt);
                md_write_all(md, pass);
                count -= len2;
            }

            if count < salt.len() {
                md_write_all(md, &salt[..count]);
            } else {
                md_write_all(md, salt);
                count -= salt.len();
                md_write_all(md, &pass[..count]);
            }
        } else {
            md_write_all(md, pass);
        }

        let digest_ptr = digest::gcry_md_read(md, hashalgo);
        if digest_ptr.is_null() {
            digest::gcry_md_close(md);
            return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
        }
        let take = dlen.min(key.len() - used);
        unsafe {
            copy_nonoverlapping(
                digest_ptr.cast_const(),
                key[used..used + take].as_mut_ptr(),
                take,
            );
        }
        used += take;
        pass_index += 1;
    }

    digest::gcry_md_close(md);
    0
}

fn pbkdf2(
    passphrase: *const c_void,
    passphraselen: usize,
    hashalgo: c_int,
    salt: *const c_void,
    saltlen: usize,
    iterations: c_ulong,
    keybuffer: *mut c_void,
    keysize: usize,
) -> u32 {
    if salt.is_null() || iterations == 0 || keysize == 0 {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }

    let hlen = digest::gcry_md_get_algo_dlen(hashalgo) as usize;
    if hlen == 0 {
        return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
    }

    let _pass = match slice_from_ptr(passphrase, passphraselen) {
        Some(bytes) => bytes,
        None => return error::gcry_error_from_code(GPG_ERR_INV_DATA),
    };
    let salt = match slice_from_ptr(salt, saltlen) {
        Some(bytes) => bytes,
        None => return error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    };
    let key = match slice_from_ptr_mut(keybuffer, keysize) {
        Some(bytes) => bytes,
        None => return error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    };

    let secure = alloc::gcry_is_secure(passphrase) != 0 || alloc::gcry_is_secure(keybuffer) != 0;
    let md = match md_open(hashalgo, true, secure) {
        Ok(hd) => hd,
        Err(code) => return code,
    };
    let setkey_rc = digest::gcry_md_setkey(md, passphrase, passphraselen);
    if setkey_rc != 0 {
        digest::gcry_md_close(md);
        return setkey_rc;
    }

    let l = ((key.len() - 1) / hlen) + 1;
    let r = key.len() - (l - 1) * hlen;
    if hlen > MAX_DIGEST_LEN {
        digest::gcry_md_close(md);
        return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
    }
    let Some(mut scratch) = ByteBuffer::new_zeroed(salt.len() + 4 + 2 * hlen, secure) else {
        digest::gcry_md_close(md);
        return error::gcry_error_from_errno(crate::get_errno());
    };
    let (salt_block, rest) = scratch.as_mut_slice().split_at_mut(salt.len() + 4);
    let (tbuf, ubuf) = rest.split_at_mut(hlen);
    salt_block[..salt.len()].copy_from_slice(salt);

    for block_index in 1..=l {
        let block_num = (block_index as u32).to_be_bytes();
        salt_block[salt.len()..].copy_from_slice(&block_num);

        digest::gcry_md_reset(md);
        md_write_all(md, &salt_block);
        if let Err(code) = md_read_into(md, hashalgo, ubuf) {
            digest::gcry_md_close(md);
            return code;
        }
        tbuf.copy_from_slice(ubuf);

        let mut iter = 1;
        while iter < iterations {
            digest::gcry_md_reset(md);
            md_write_all(md, ubuf);
            if let Err(code) = md_read_into(md, hashalgo, ubuf) {
                digest::gcry_md_close(md);
                return code;
            }
            for (acc, value) in tbuf.iter_mut().zip(ubuf.iter()) {
                *acc ^= *value;
            }
            iter += 1;
        }

        let offset = (block_index - 1) * hlen;
        let chunk_len = if block_index == l { r } else { hlen };
        key[offset..offset + chunk_len].copy_from_slice(&tbuf[..chunk_len]);
    }

    digest::gcry_md_close(md);
    0
}

fn power_of_two_log2(value: c_int) -> Option<u8> {
    let value = u32::try_from(value).ok()?;
    if value == 0 || !value.is_power_of_two() {
        None
    } else {
        Some(value.trailing_zeros() as u8)
    }
}

fn scrypt(
    passphrase: *const c_void,
    passphraselen: usize,
    algo: c_int,
    subalgo: c_int,
    salt: *const c_void,
    saltlen: usize,
    iterations: c_ulong,
    keybuffer: *mut c_void,
    keysize: usize,
) -> u32 {
    if subalgo < 1 || iterations == 0 {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }

    let r = match algo {
        GCRY_KDF_SCRYPT => 8,
        41 => 1,
        _ => return error::gcry_error_from_code(GPG_ERR_UNKNOWN_ALGORITHM),
    };

    let Some(log_n) = power_of_two_log2(subalgo) else {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    };

    let params = match ScryptParams::new(log_n, r, iterations as u32) {
        Ok(params) => params,
        Err(_) => return error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    };

    let pass = match slice_from_ptr(passphrase, passphraselen) {
        Some(bytes) => bytes,
        None => return error::gcry_error_from_code(GPG_ERR_INV_DATA),
    };
    let salt = match slice_from_ptr(salt, saltlen) {
        Some(bytes) => bytes,
        None => return error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    };
    let key = match slice_from_ptr_mut(keybuffer, keysize) {
        Some(bytes) => bytes,
        None => return error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    };

    match scrypt_derive(pass, salt, &params, key) {
        Ok(()) => 0,
        Err(_) => error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    }
}

fn argon2_error_code(err: argon2::Error) -> u32 {
    match err {
        argon2::Error::OutOfMemory => error::gcry_error_from_errno(crate::ENOMEM_VALUE),
        _ => error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    }
}

fn allocate_handle(state: KdfState, secure: bool) -> Option<gcry_kdf_hd_t> {
    let raw = if secure {
        alloc::gcry_calloc_secure(1, size_of::<gcry_kdf_handle>())
    } else {
        alloc::gcry_calloc(1, size_of::<gcry_kdf_handle>())
    }
    .cast::<gcry_kdf_handle>();
    if raw.is_null() {
        return None;
    }

    unsafe {
        write(raw, gcry_kdf_handle { state });
    }
    Some(raw)
}

fn parse_argon2_algorithm(subalgo: c_int) -> Result<Algorithm, u32> {
    match subalgo {
        GCRY_KDF_ARGON2D => Ok(Algorithm::Argon2d),
        GCRY_KDF_ARGON2I => Ok(Algorithm::Argon2i),
        GCRY_KDF_ARGON2ID => Ok(Algorithm::Argon2id),
        _ => Err(error::gcry_error_from_code(GPG_ERR_INV_VALUE)),
    }
}

fn build_argon2(
    context: &Argon2Context,
) -> Result<Argon2<'_>, u32> {
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(context.memory_cost)
        .t_cost(context.time_cost)
        .p_cost(context.parallelism)
        .output_len(context.output_len);

    if !context.associated_data.as_slice().is_empty() {
        let ad = AssociatedData::new(context.associated_data.as_slice())
            .map_err(argon2_error_code)?;
        builder.data(ad);
    }

    let params = builder.build().map_err(argon2_error_code)?;
    if context.secret.as_slice().is_empty() {
        Ok(Argon2::new(context.algorithm, Version::V0x13, params))
    } else {
        Argon2::new_with_secret(
            context.secret.as_slice(),
            context.algorithm,
            Version::V0x13,
            params,
        )
            .map_err(argon2_error_code)
    }
}

fn compute_argon2_serial(context: &mut Argon2Context) -> u32 {
    let argon2 = match build_argon2(context) {
        Ok(argon2) => argon2,
        Err(code) => return code,
    };

    let Some(mut out) = ByteBuffer::new_zeroed(context.output_len, context.secure) else {
        return error::gcry_error_from_errno(crate::get_errno());
    };
    if let Err(err) = argon2.hash_password_into(
        context.password.as_slice(),
        context.salt.as_slice(),
        out.as_mut_slice(),
    ) {
        return argon2_error_code(err);
    }

    context.result = Some(out);
    0
}

struct Argon2Job {
    context: *mut Argon2Context,
    rc: u32,
}

unsafe extern "C" fn run_argon2_job(job: *mut c_void) {
    let job = unsafe { &mut *job.cast::<Argon2Job>() };
    let context = unsafe { &mut *job.context };
    job.rc = compute_argon2_serial(context);
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
    if passphrase.is_null() {
        return error::gcry_error_from_code(GPG_ERR_INV_DATA);
    }
    if keybuffer.is_null() || keysize == 0 {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }

    match algo {
        GCRY_KDF_SIMPLE_S2K | GCRY_KDF_SALTED_S2K | GCRY_KDF_ITERSALTED_S2K => {
            if passphraselen == 0 {
                error::gcry_error_from_code(GPG_ERR_INV_DATA)
            } else {
                openpgp_s2k(
                    passphrase,
                    passphraselen,
                    algo,
                    subalgo,
                    salt,
                    saltlen,
                    iterations,
                    keybuffer,
                    keysize,
                )
            }
        }
        GCRY_KDF_PBKDF1 => error::gcry_error_from_code(GPG_ERR_UNSUPPORTED_ALGORITHM),
        GCRY_KDF_PBKDF2 => {
            if saltlen == 0 {
                error::gcry_error_from_code(GPG_ERR_INV_VALUE)
            } else {
                pbkdf2(
                    passphrase,
                    passphraselen,
                    subalgo,
                    salt,
                    saltlen,
                    iterations,
                    keybuffer,
                    keysize,
                )
            }
        }
        41 | GCRY_KDF_SCRYPT => scrypt(
            passphrase,
            passphraselen,
            algo,
            subalgo,
            salt,
            saltlen,
            iterations,
            keybuffer,
            keysize,
        ),
        _ => error::gcry_error_from_code(GPG_ERR_UNKNOWN_ALGORITHM),
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
    if hd.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    unsafe {
        *hd = null_mut();
    }

    match algo {
        GCRY_KDF_ARGON2 => {
            if passphraselen == 0 || saltlen == 0 {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            }

            let algorithm = match parse_argon2_algorithm(subalgo) {
                Ok(algorithm) => algorithm,
                Err(code) => return code,
            };

            if param.is_null() || !(3..=4).contains(&(paramlen as usize)) {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            }

            let params = unsafe { std::slice::from_raw_parts(param, paramlen as usize) };
            let output_len = params[0] as usize;
            let time_cost = params[1] as u32;
            let memory_cost = params[2] as u32;
            let parallelism = params.get(3).copied().unwrap_or(1) as u32;
            if parallelism == 0 {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            }

            let secure = alloc::gcry_is_secure(passphrase) != 0 || alloc::gcry_is_secure(key) != 0;
            let password = match copy_buffer_from_ptr(passphrase, passphraselen, secure, GPG_ERR_INV_VALUE) {
                Ok(bytes) => bytes,
                Err(code) => return code,
            };
            let salt = match copy_buffer_from_ptr(salt, saltlen, secure, GPG_ERR_INV_VALUE) {
                Ok(bytes) => bytes,
                Err(code) => return code,
            };
            let secret = match copy_buffer_from_ptr(key, keylen, secure, GPG_ERR_INV_VALUE) {
                Ok(bytes) => bytes,
                Err(code) => return code,
            };
            let associated_data =
                match copy_buffer_from_ptr(ad, adlen, secure, GPG_ERR_INV_VALUE) {
                    Ok(bytes) => bytes,
                    Err(code) => return code,
                };

            let state = KdfState::Argon2(Argon2Context {
                secure,
                algorithm,
                output_len,
                password,
                salt,
                secret,
                associated_data,
                memory_cost,
                time_cost,
                parallelism,
                result: None,
            });
            let Some(raw) = allocate_handle(state, secure) else {
                return error::gcry_error_from_errno(crate::get_errno());
            };

            unsafe {
                *hd = raw;
            }
            0
        }
        _ => error::gcry_error_from_code(GPG_ERR_UNKNOWN_ALGORITHM),
    }
}

#[no_mangle]
pub extern "C" fn gcry_kdf_compute(hd: gcry_kdf_hd_t, ops: *const gcry_kdf_thread_ops_t) -> u32 {
    if hd.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let state = unsafe { &mut *hd };
    match &mut state.state {
        KdfState::Argon2(context) => {
            context.result = None;
            if ops.is_null() {
                return compute_argon2_serial(context);
            }

            let ops = unsafe { &*ops };
            let Some(dispatch_job) = ops.dispatch_job else {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            };
            let Some(wait_all_jobs) = ops.wait_all_jobs else {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            };

            let mut job = Argon2Job {
                context,
                rc: 0,
            };
            let dispatch_rc = unsafe {
                dispatch_job(
                    ops.jobs_context,
                    Some(run_argon2_job),
                    (&mut job as *mut Argon2Job).cast(),
                )
            };
            if dispatch_rc < 0 {
                return error::gcry_error_from_code(GPG_ERR_CANCELED);
            }

            let wait_rc = unsafe { wait_all_jobs(ops.jobs_context) };
            if wait_rc < 0 {
                return error::gcry_error_from_code(GPG_ERR_CANCELED);
            }

            job.rc
        }
    }
}

#[no_mangle]
pub extern "C" fn gcry_kdf_final(hd: gcry_kdf_hd_t, resultlen: usize, result: *mut c_void) -> u32 {
    if hd.is_null() || (resultlen > 0 && result.is_null()) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let state = unsafe { &mut *hd };
    match &mut state.state {
        KdfState::Argon2(context) => {
            if resultlen != context.output_len {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            }

            let Some(output) = context.result.as_ref() else {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            };

            if resultlen > 0 {
                unsafe {
                    copy_nonoverlapping(output.as_slice().as_ptr(), result.cast::<u8>(), resultlen);
                }
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn gcry_kdf_close(hd: gcry_kdf_hd_t) {
    if hd.is_null() {
        return;
    }

    unsafe {
        drop_in_place(hd);
    }
    alloc::gcry_free(hd.cast());
}
