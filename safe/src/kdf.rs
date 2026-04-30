use std::ffi::{c_int, c_uint, c_ulong, c_void};
use std::ptr::copy_nonoverlapping;

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

use crate::digest::algorithms;
use crate::error;

pub type gcry_kdf_hd_t = *mut gcry_kdf_handle;
pub type gcry_kdf_job_fn_t = Option<unsafe extern "C" fn(*mut c_void)>;
pub type gcry_kdf_dispatch_job_fn_t =
    Option<unsafe extern "C" fn(*mut c_void, gcry_kdf_job_fn_t, *mut c_void) -> c_int>;
pub type gcry_kdf_wait_all_jobs_fn_t = Option<unsafe extern "C" fn(*mut c_void) -> c_int>;

const GCRY_KDF_SIMPLE_S2K: c_int = 16;
const GCRY_KDF_SALTED_S2K: c_int = 17;
const GCRY_KDF_ITERSALTED_S2K: c_int = 19;
const GCRY_KDF_PBKDF1: c_int = 33;
const GCRY_KDF_PBKDF2: c_int = 34;
const GCRY_KDF_SCRYPT_R1: c_int = 41;
const GCRY_KDF_SCRYPT: c_int = 48;
const GCRY_KDF_ARGON2: c_int = 64;
const GCRY_KDF_BALLOON: c_int = 65;
const GCRY_KDF_ARGON2D: c_int = 0;
const GCRY_KDF_ARGON2I: c_int = 1;
const GCRY_KDF_ARGON2ID: c_int = 2;
const GPG_ERR_INV_VALUE: u32 = 55;
const GPG_ERR_INV_DATA: u32 = 79;
const GPG_ERR_UNSUPPORTED_ALGORITHM: u32 = 84;
const GPG_ERR_UNKNOWN_ALGORITHM: u32 = 149;

#[repr(C)]
pub struct gcry_kdf_handle {
    algo: c_int,
    subalgo: c_int,
    param: Vec<c_ulong>,
    passphrase: Vec<u8>,
    salt: Vec<u8>,
    key: Vec<u8>,
    ad: Vec<u8>,
    result: Vec<u8>,
    computed: bool,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct gcry_kdf_thread_ops_t {
    pub jobs_context: *mut c_void,
    pub dispatch_job: gcry_kdf_dispatch_job_fn_t,
    pub wait_all_jobs: gcry_kdf_wait_all_jobs_fn_t,
}

fn input_slice<'a>(ptr: *const c_void, len: usize) -> Result<&'a [u8], u32> {
    if ptr.is_null() {
        if len == 0 {
            Ok(&[])
        } else {
            Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG))
        }
    } else {
        Ok(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) })
    }
}

fn s2k_derive(
    passphrase: &[u8],
    algo: c_int,
    hashalgo: c_int,
    salt: &[u8],
    iterations: c_ulong,
    out: &mut [u8],
) -> u32 {
    if !matches!(
        algo,
        GCRY_KDF_SIMPLE_S2K | GCRY_KDF_SALTED_S2K | GCRY_KDF_ITERSALTED_S2K
    ) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if matches!(algo, GCRY_KDF_SALTED_S2K | GCRY_KDF_ITERSALTED_S2K) && salt.len() != 8 {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }

    let mut offset = 0usize;
    let mut block_index = 0usize;
    while offset < out.len() {
        let mut material = Vec::new();
        material.resize(block_index, 0);
        match algo {
            GCRY_KDF_SIMPLE_S2K => material.extend_from_slice(passphrase),
            GCRY_KDF_SALTED_S2K => {
                material.extend_from_slice(salt);
                material.extend_from_slice(passphrase);
            }
            GCRY_KDF_ITERSALTED_S2K => {
                let repeated_len = salt.len().saturating_add(passphrase.len());
                if repeated_len == 0 {
                    return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
                }
                let count = (iterations as usize).max(repeated_len);
                let mut produced = 0usize;
                while produced < count {
                    let take_salt = salt.len().min(count - produced);
                    material.extend_from_slice(&salt[..take_salt]);
                    produced += take_salt;
                    if produced >= count {
                        break;
                    }
                    let take_pass = passphrase.len().min(count - produced);
                    material.extend_from_slice(&passphrase[..take_pass]);
                    produced += take_pass;
                }
            }
            _ => unreachable!(),
        }
        let Some(digest) = algorithms::digest_once(hashalgo, &material) else {
            return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
        };
        let take = digest.len().min(out.len() - offset);
        out[offset..offset + take].copy_from_slice(&digest[..take]);
        offset += take;
        block_index += 1;
    }
    0
}

fn pbkdf2_derive(
    passphrase: &[u8],
    hashalgo: c_int,
    salt: &[u8],
    iterations: c_ulong,
    out: &mut [u8],
) -> u32 {
    if iterations == 0 || iterations > u32::MAX as c_ulong {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if algorithms::pbkdf2_hmac(hashalgo, passphrase, salt, iterations as u32, out) {
        0
    } else {
        error::gcry_error_from_code(error::GPG_ERR_INV_ARG)
    }
}

fn log2_power_of_two(value: c_int) -> Option<u8> {
    if value <= 0 {
        return None;
    }
    let value = value as u32;
    value
        .is_power_of_two()
        .then_some(value.trailing_zeros() as u8)
}

fn scrypt_derive(
    passphrase: &[u8],
    algo: c_int,
    n_value: c_int,
    salt: &[u8],
    parallel: c_ulong,
    out: &mut [u8],
) -> u32 {
    let Some(log_n) = log2_power_of_two(n_value) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    if parallel == 0 || parallel > u32::MAX as c_ulong {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let r = if algo == GCRY_KDF_SCRYPT_R1 { 1 } else { 8 };
    let Ok(params) = scrypt::Params::new(log_n, r, parallel as u32, out.len()) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    scrypt::scrypt(passphrase, salt, &params, out)
        .map(|_| 0)
        .unwrap_or_else(|_| error::gcry_error_from_code(error::GPG_ERR_INV_ARG))
}

fn argon2_derive(
    subalgo: c_int,
    param: &[c_ulong],
    passphrase: &[u8],
    salt: &[u8],
    key: &[u8],
    ad: &[u8],
    out: &mut [u8],
) -> u32 {
    if param.len() < 3 || param.len() > 4 {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }
    let algorithm = match subalgo {
        GCRY_KDF_ARGON2D => Algorithm::Argon2d,
        GCRY_KDF_ARGON2I => Algorithm::Argon2i,
        GCRY_KDF_ARGON2ID => Algorithm::Argon2id,
        _ => return error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    };
    let tag_len = match usize::try_from(param[0]) {
        Ok(len) => len,
        Err(_) => return error::gcry_error_from_code(GPG_ERR_INV_VALUE),
    };
    let parallelism = param.get(3).copied().unwrap_or(1);
    if out.len() != tag_len {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }
    if param[1] > u32::MAX as c_ulong
        || param[2] > u32::MAX as c_ulong
        || parallelism > u32::MAX as c_ulong
    {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }

    let mut builder = ParamsBuilder::new();
    builder
        .t_cost(param[1] as u32)
        .m_cost(param[2] as u32)
        .p_cost(parallelism as u32)
        .output_len(tag_len);
    if !ad.is_empty() {
        let Ok(data) = AssociatedData::new(ad) else {
            return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
        };
        builder.data(data);
    }
    let Ok(params) = builder.build() else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    let result = if key.is_empty() {
        Argon2::new(algorithm, Version::V0x13, params).hash_password_into(passphrase, salt, out)
    } else {
        match Argon2::new_with_secret(key, algorithm, Version::V0x13, params) {
            Ok(argon2) => argon2.hash_password_into(passphrase, salt, out),
            Err(_) => return error::gcry_error_from_code(error::GPG_ERR_INV_ARG),
        }
    };
    result
        .map(|_| 0)
        .unwrap_or_else(|_| error::gcry_error_from_code(error::GPG_ERR_INV_ARG))
}

fn balloon_hash_algo(subalgo: c_int) -> c_int {
    if subalgo == 0 {
        algorithms::GCRY_MD_SHA256
    } else {
        subalgo
    }
}

fn balloon_hash(hashalgo: c_int, counter: &mut u64, parts: &[&[u8]]) -> Result<Vec<u8>, u32> {
    let mut material = Vec::new();
    material.extend_from_slice(&counter.to_le_bytes());
    *counter = counter.wrapping_add(1);
    for part in parts {
        material.extend_from_slice(part);
    }
    algorithms::digest_once(hashalgo, &material)
        .ok_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_ARG))
}

fn balloon_expand(hashalgo: c_int, input: &[u8], out: &mut [u8]) -> u32 {
    if out.is_empty() {
        return 0;
    }
    let digest_len = algorithms::digest_len(hashalgo);
    if digest_len == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if out.len() <= digest_len {
        let Some(block) = algorithms::digest_once(hashalgo, input) else {
            return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
        };
        out.copy_from_slice(&block[..out.len()]);
        return 0;
    }
    let mut offset = 0usize;
    let mut counter = 0u64;
    while offset < out.len() {
        let mut material = Vec::with_capacity(8 + input.len());
        material.extend_from_slice(&counter.to_le_bytes());
        material.extend_from_slice(input);
        let Some(block) = algorithms::digest_once(hashalgo, &material) else {
            return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
        };
        counter = counter.wrapping_add(1);
        let take = block.len().min(out.len() - offset);
        out[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
    }
    0
}

fn balloon_derive(
    passphrase: &[u8],
    subalgo: c_int,
    salt: &[u8],
    param: &[c_ulong],
    out: &mut [u8],
) -> u32 {
    if passphrase.is_empty() || salt.is_empty() || param.len() < 2 || param.len() > 3 {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }
    let hashalgo = balloon_hash_algo(subalgo);
    let digest_len = algorithms::digest_len(hashalgo);
    if digest_len == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let space_cost = param[0] as usize;
    let time_cost = param[1] as usize;
    let parallelism = param.get(2).copied().unwrap_or(1);
    if space_cost == 0 || time_cost == 0 || parallelism == 0 {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }
    if space_cost > (1 << 20) {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }

    const DELTA: usize = 3;
    let mut counter = 0u64;
    let mut buffer = Vec::with_capacity(space_cost);
    let first = match balloon_hash(hashalgo, &mut counter, &[passphrase, salt]) {
        Ok(block) => block,
        Err(err) => return err,
    };
    buffer.push(first);
    for idx in 1..space_cost {
        let prev = buffer[idx - 1].clone();
        let block = match balloon_hash(hashalgo, &mut counter, &[&prev]) {
            Ok(block) => block,
            Err(err) => return err,
        };
        buffer.push(block);
    }

    for time in 0..time_cost {
        let time_bytes = (time as u64).to_le_bytes();
        for idx in 0..space_cost {
            let prev_idx = if idx == 0 { space_cost - 1 } else { idx - 1 };
            let prev = buffer[prev_idx].clone();
            let current = buffer[idx].clone();
            buffer[idx] = match balloon_hash(hashalgo, &mut counter, &[&prev, &current]) {
                Ok(block) => block,
                Err(err) => return err,
            };

            let idx_bytes = (idx as u64).to_le_bytes();
            for mix in 0..DELTA {
                let mix_bytes = (mix as u64).to_le_bytes();
                let digest = match balloon_hash(
                    hashalgo,
                    &mut counter,
                    &[salt, &time_bytes, &idx_bytes, &mix_bytes],
                ) {
                    Ok(block) => block,
                    Err(err) => return err,
                };
                let mut lane = [0u8; 8];
                lane.copy_from_slice(&digest[..8]);
                let other_idx = u64::from_le_bytes(lane) as usize % space_cost;
                let other = buffer[other_idx].clone();
                let current = buffer[idx].clone();
                buffer[idx] = match balloon_hash(hashalgo, &mut counter, &[&current, &other]) {
                    Ok(block) => block,
                    Err(err) => return err,
                };
            }
        }
    }

    balloon_expand(hashalgo, &buffer[space_cost - 1], out)
}

fn derive_into(
    passphrase: &[u8],
    algo: c_int,
    subalgo: c_int,
    salt: &[u8],
    iterations: c_ulong,
    key: &[u8],
    ad: &[u8],
    param: &[c_ulong],
    out: &mut [u8],
) -> u32 {
    match algo {
        GCRY_KDF_SIMPLE_S2K | GCRY_KDF_SALTED_S2K | GCRY_KDF_ITERSALTED_S2K => {
            s2k_derive(passphrase, algo, subalgo, salt, iterations, out)
        }
        GCRY_KDF_PBKDF2 => pbkdf2_derive(passphrase, subalgo, salt, iterations, out),
        GCRY_KDF_SCRYPT | GCRY_KDF_SCRYPT_R1 => {
            scrypt_derive(passphrase, algo, subalgo, salt, iterations, out)
        }
        GCRY_KDF_ARGON2 => argon2_derive(subalgo, param, passphrase, salt, key, ad, out),
        GCRY_KDF_BALLOON => balloon_derive(passphrase, subalgo, salt, param, out),
        GCRY_KDF_PBKDF1 => error::gcry_error_from_code(GPG_ERR_UNSUPPORTED_ALGORITHM),
        _ => error::gcry_error_from_code(GPG_ERR_UNKNOWN_ALGORITHM),
    }
}

#[unsafe(no_mangle)]
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
    if matches!(algo, GCRY_KDF_SALTED_S2K | GCRY_KDF_ITERSALTED_S2K)
        && (salt.is_null() || saltlen != 8)
    {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }
    let passphrase = match input_slice(passphrase, passphraselen) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let salt = match input_slice(salt, saltlen) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let out = unsafe { std::slice::from_raw_parts_mut(keybuffer.cast::<u8>(), keysize) };
    if matches!(
        algo,
        GCRY_KDF_SIMPLE_S2K | GCRY_KDF_SALTED_S2K | GCRY_KDF_ITERSALTED_S2K
    ) && passphrase.is_empty()
    {
        return error::gcry_error_from_code(GPG_ERR_INV_DATA);
    }
    if algo == GCRY_KDF_PBKDF2 && salt.is_empty() {
        return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
    }
    derive_into(
        passphrase,
        algo,
        subalgo,
        salt,
        iterations,
        &[],
        &[],
        &[],
        out,
    )
}

#[unsafe(no_mangle)]
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
    if hd.is_null() || (param.is_null() && paramlen != 0) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    unsafe { *hd = std::ptr::null_mut() };
    let passphrase = match input_slice(passphrase, passphraselen) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let salt = match input_slice(salt, saltlen) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let key = match input_slice(key, keylen) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let ad = match input_slice(ad, adlen) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let params = if paramlen == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(param, paramlen as usize).to_vec() }
    };
    match algo {
        GCRY_KDF_ARGON2 => {
            if passphrase.is_empty() || salt.is_empty() {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            }
            if paramlen < 3 || paramlen > 4 {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            }
            if !matches!(
                subalgo,
                GCRY_KDF_ARGON2D | GCRY_KDF_ARGON2I | GCRY_KDF_ARGON2ID
            ) {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            }
            if params.get(3).copied().unwrap_or(1) == 0 {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            }
        }
        GCRY_KDF_BALLOON => {
            if passphrase.is_empty() || salt.is_empty() {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            }
            if paramlen != 2 && paramlen != 3 {
                return error::gcry_error_from_code(GPG_ERR_INV_VALUE);
            }
        }
        _ => return error::gcry_error_from_code(GPG_ERR_UNKNOWN_ALGORITHM),
    }

    let handle = Box::new(gcry_kdf_handle {
        algo,
        subalgo,
        param: params,
        passphrase: passphrase.to_vec(),
        salt: salt.to_vec(),
        key: key.to_vec(),
        ad: ad.to_vec(),
        result: Vec::new(),
        computed: false,
    });
    unsafe { *hd = Box::into_raw(handle) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_kdf_compute(hd: gcry_kdf_hd_t, _ops: *const gcry_kdf_thread_ops_t) -> u32 {
    if hd.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let handle = unsafe { &mut *hd };
    handle.computed = true;
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_kdf_final(hd: gcry_kdf_hd_t, resultlen: usize, result: *mut c_void) -> u32 {
    if hd.is_null() || (result.is_null() && resultlen != 0) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let handle = unsafe { &mut *hd };
    if !handle.computed {
        handle.computed = true;
    }
    let mut out = vec![0u8; resultlen];
    let err = derive_into(
        &handle.passphrase,
        handle.algo,
        handle.subalgo,
        &handle.salt,
        0,
        &handle.key,
        &handle.ad,
        &handle.param,
        &mut out,
    );
    if err != 0 {
        return err;
    }
    handle.result = out;
    if resultlen != 0 {
        unsafe { copy_nonoverlapping(handle.result.as_ptr(), result.cast::<u8>(), resultlen) };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_kdf_close(hd: gcry_kdf_hd_t) {
    if !hd.is_null() {
        unsafe { drop(Box::from_raw(hd)) };
    }
}
