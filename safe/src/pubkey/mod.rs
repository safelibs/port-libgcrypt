mod dsa;
mod ecc;
mod elgamal;
pub(crate) mod encoding;
mod keygrip;
mod rsa;

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::context;
use crate::digest::{self, gcry_md_hd_t};
use crate::error;
use crate::sexp;

pub(crate) const KEYGRIP_LEN: usize = 20;

const GCRYCTL_TEST_ALGO: c_int = 8;
const GCRYCTL_DISABLE_ALGO: c_int = 12;
const GCRYCTL_GET_ALGO_NPKEY: c_int = 15;
const GCRYCTL_GET_ALGO_NSKEY: c_int = 16;
const GCRYCTL_GET_ALGO_NSIGN: c_int = 17;
const GCRYCTL_GET_ALGO_NENCR: c_int = 18;
const GCRYCTL_GET_ALGO_USAGE: c_int = 34;

const GCRY_PK_RSA: c_int = 1;
const GCRY_PK_RSA_E: c_int = 2;
const GCRY_PK_RSA_S: c_int = 3;
const GCRY_PK_ELG_E: c_int = 16;
const GCRY_PK_DSA: c_int = 17;
const GCRY_PK_ECC: c_int = 18;
const GCRY_PK_ELG: c_int = 20;
const GCRY_PK_ECDSA: c_int = 301;
const GCRY_PK_ECDH: c_int = 302;
const GCRY_PK_EDDSA: c_int = 303;

const GCRY_PK_USAGE_SIGN: usize = 1;
const GCRY_PK_USAGE_ENCR: usize = 2;

const DISABLED_RSA: u32 = 1 << 0;
const DISABLED_DSA: u32 = 1 << 1;
const DISABLED_ELG: u32 = 1 << 2;
const DISABLED_ECC: u32 = 1 << 3;

static DISABLED_PK_ALGOS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
struct AlgoInfo {
    usage: usize,
    npkey: usize,
    nskey: usize,
    nsign: usize,
    nencr: usize,
}

fn map_algo(algo: c_int) -> c_int {
    match algo {
        GCRY_PK_RSA_E | GCRY_PK_RSA_S => GCRY_PK_RSA,
        GCRY_PK_ELG_E => GCRY_PK_ELG,
        GCRY_PK_ECDSA | GCRY_PK_ECDH | GCRY_PK_EDDSA => GCRY_PK_ECC,
        _ => algo,
    }
}

fn algo_disable_bit(algo: c_int) -> Option<u32> {
    match map_algo(algo) {
        GCRY_PK_RSA => Some(DISABLED_RSA),
        GCRY_PK_DSA => Some(DISABLED_DSA),
        GCRY_PK_ELG => Some(DISABLED_ELG),
        GCRY_PK_ECC => Some(DISABLED_ECC),
        _ => None,
    }
}

fn disable_algo(algo: c_int) {
    if let Some(bit) = algo_disable_bit(algo) {
        DISABLED_PK_ALGOS.fetch_or(bit, Ordering::Relaxed);
    }
}

fn algo_disabled(algo: c_int) -> bool {
    algo_disable_bit(algo)
        .map(|bit| DISABLED_PK_ALGOS.load(Ordering::Relaxed) & bit != 0)
        .unwrap_or(false)
}

fn algo_info_record(algo: c_int) -> Option<AlgoInfo> {
    match map_algo(algo) {
        GCRY_PK_RSA => Some(AlgoInfo {
            usage: GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR,
            npkey: 2,
            nskey: 6,
            nsign: 1,
            nencr: 1,
        }),
        GCRY_PK_DSA => Some(AlgoInfo {
            usage: GCRY_PK_USAGE_SIGN,
            npkey: 4,
            nskey: 5,
            nsign: 2,
            nencr: 0,
        }),
        GCRY_PK_ELG => Some(AlgoInfo {
            usage: GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR,
            npkey: 3,
            nskey: 4,
            nsign: 2,
            nencr: 2,
        }),
        GCRY_PK_ECC => Some(AlgoInfo {
            usage: GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR,
            npkey: 7,
            nskey: 8,
            nsign: 2,
            nencr: 2,
        }),
        _ => None,
    }
}

fn test_algo(algo: c_int, usage: usize) -> u32 {
    let Some(info) = algo_info_record(algo) else {
        return encoding::err(error::GPG_ERR_PUBKEY_ALGO);
    };
    if algo_disabled(algo) {
        return encoding::err(error::GPG_ERR_PUBKEY_ALGO);
    }
    if (usage & GCRY_PK_USAGE_SIGN != 0 && info.usage & GCRY_PK_USAGE_SIGN == 0)
        || (usage & GCRY_PK_USAGE_ENCR != 0 && info.usage & GCRY_PK_USAGE_ENCR == 0)
    {
        return encoding::err(error::GPG_ERR_PUBKEY_ALGO);
    }
    0
}

fn disabled_error(algo: c_int) -> Option<u32> {
    algo_disabled(algo).then(|| encoding::err(error::GPG_ERR_PUBKEY_ALGO))
}

fn fallback_algo_name(algo: c_int) -> *const c_char {
    rsa::fallback_name(algo)
        .or_else(|| dsa::fallback_name(algo))
        .or_else(|| elgamal::fallback_name(algo))
        .or_else(|| ecc::fallback_name(algo))
        .unwrap_or(std::ptr::null())
}

fn clear_result_slot(result: *mut *mut sexp::gcry_sexp) {
    if !result.is_null() {
        unsafe {
            *result = null_mut();
        }
    }
}

fn key_has(key: *mut sexp::gcry_sexp, token: &str) -> bool {
    if encoding::has_token(key, token) {
        return true;
    }
    let upper = token.to_ascii_uppercase();
    upper != token && encoding::has_token(key, &upper)
}

fn hash_name_from_template(template: &[u8]) -> Result<Option<&[u8]>, u32> {
    let Some(hash_start) = template.windows(6).position(|window| window == b"(hash ") else {
        return Err(encoding::err(error::GPG_ERR_DIGEST_ALGO));
    };
    let value = &template[hash_start + 6..];
    if value.starts_with(b"%s") {
        return Ok(None);
    }
    let end = value
        .iter()
        .position(|byte| *byte == b' ' || *byte == b')')
        .unwrap_or(value.len());
    if end == 0 {
        Err(encoding::err(error::GPG_ERR_DIGEST_ALGO))
    } else {
        Ok(Some(&value[..end]))
    }
}

fn digest_for_template(template: &[u8], hd: gcry_md_hd_t) -> Result<(&'static CStr, Vec<u8>), u32> {
    let fixed_hash = hash_name_from_template(template)?;
    let algo = if let Some(name) = fixed_hash {
        let Ok(c_name) = CString::new(name) else {
            return Err(encoding::err(error::GPG_ERR_DIGEST_ALGO));
        };
        digest::gcry_md_map_name(c_name.as_ptr())
    } else {
        digest::gcry_md_get_algo(hd)
    };
    let digest_len = digest::gcry_md_get_algo_dlen(algo) as usize;
    if algo == 0 || digest_len == 0 {
        return Err(encoding::err(error::GPG_ERR_DIGEST_ALGO));
    }
    let read_algo = if fixed_hash.is_some() { algo } else { 0 };
    let digest_ptr = digest::gcry_md_read(hd, read_algo);
    if digest_ptr.is_null() {
        return Err(encoding::err(error::GPG_ERR_DIGEST_ALGO));
    }
    let digest_bytes = unsafe { std::slice::from_raw_parts(digest_ptr, digest_len) }.to_vec();
    let name_ptr = digest::gcry_md_algo_name(algo);
    if name_ptr.is_null() {
        return Err(encoding::err(error::GPG_ERR_DIGEST_ALGO));
    }
    Ok((unsafe { CStr::from_ptr(name_ptr) }, digest_bytes))
}

fn render_hash_template(
    template: &[u8],
    algo_name: &CStr,
    digest_bytes: &[u8],
    override_bytes: Option<&[u8]>,
) -> Result<Vec<u8>, u32> {
    let mut out = Vec::with_capacity(template.len() + digest_bytes.len() * 2 + 32);
    let mut idx = 0usize;
    let mut binary_index = 0usize;
    while idx < template.len() {
        if template[idx] == b'%' && idx + 1 < template.len() {
            match template[idx + 1] {
                b's' => {
                    out.extend_from_slice(algo_name.to_bytes());
                    idx += 2;
                    continue;
                }
                b'b' => {
                    let bytes = if binary_index == 0 {
                        digest_bytes
                    } else {
                        override_bytes.ok_or_else(|| encoding::err(error::GPG_ERR_INV_ARG))?
                    };
                    out.extend_from_slice(encoding::hex_atom(bytes).as_bytes());
                    binary_index += 1;
                    idx += 2;
                    continue;
                }
                b'%' => {
                    out.push(b'%');
                    idx += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(template[idx]);
        idx += 1;
    }
    Ok(out)
}

fn hash_data_sexp(
    data_tmpl: *const c_char,
    hd: gcry_md_hd_t,
    ctx: *mut c_void,
) -> Result<*mut sexp::gcry_sexp, u32> {
    if data_tmpl.is_null() || hd.is_null() {
        return Err(encoding::err(error::GPG_ERR_INV_ARG));
    }
    let template = unsafe { CStr::from_ptr(data_tmpl) }.to_bytes();
    let (algo_name, digest_bytes) = digest_for_template(template, hd)?;
    let override_bytes = unsafe { context::random_override(ctx).map(|bytes| bytes.to_vec()) };
    let rendered = render_hash_template(
        template,
        algo_name,
        &digest_bytes,
        override_bytes.as_deref(),
    )?;
    let mut sexp = null_mut();
    let rc = sexp::gcry_sexp_sscan(
        &mut sexp,
        null_mut(),
        rendered.as_ptr().cast(),
        rendered.len(),
    );
    if rc != 0 { Err(rc) } else { Ok(sexp) }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_encrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return encoding::err(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);
    if key_has(pkey, "rsa") || key_has(pkey, "openpgp-rsa") {
        if let Some(err) = disabled_error(GCRY_PK_RSA) {
            return err;
        }
        rsa::encrypt(result, data, pkey)
    } else if key_has(pkey, "elg") || key_has(pkey, "elgamal") {
        if let Some(err) = disabled_error(GCRY_PK_ELG) {
            return err;
        }
        elgamal::encrypt(result, data, pkey)
    } else if key_has(pkey, "ecc") || key_has(pkey, "ecdh") {
        if let Some(err) = disabled_error(GCRY_PK_ECC) {
            return err;
        }
        ecc::encrypt(result, data, pkey)
    } else {
        encoding::err(error::GPG_ERR_NOT_SUPPORTED)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_decrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return encoding::err(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);
    if key_has(skey, "rsa") || key_has(skey, "openpgp-rsa") {
        if let Some(err) = disabled_error(GCRY_PK_RSA) {
            return err;
        }
        rsa::decrypt(result, data, skey)
    } else if key_has(skey, "elg") || key_has(skey, "elgamal") {
        if let Some(err) = disabled_error(GCRY_PK_ELG) {
            return err;
        }
        elgamal::decrypt(result, data, skey)
    } else if key_has(skey, "ecc") || key_has(skey, "ecdh") {
        if let Some(err) = disabled_error(GCRY_PK_ECC) {
            return err;
        }
        ecc::decrypt(result, data, skey)
    } else {
        encoding::err(error::GPG_ERR_NOT_SUPPORTED)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_sign(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return encoding::err(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);
    if key_has(skey, "rsa") || key_has(skey, "openpgp-rsa") {
        if let Some(err) = disabled_error(GCRY_PK_RSA) {
            return err;
        }
        rsa::sign(result, data, skey)
    } else if key_has(skey, "dsa") {
        if let Some(err) = disabled_error(GCRY_PK_DSA) {
            return err;
        }
        dsa::sign(result, data, skey)
    } else if key_has(skey, "elg") || key_has(skey, "elgamal") {
        if let Some(err) = disabled_error(GCRY_PK_ELG) {
            return err;
        }
        elgamal::sign(result, data, skey)
    } else if key_has(skey, "ecc") || key_has(skey, "ecdsa") {
        if let Some(err) = disabled_error(GCRY_PK_ECC) {
            return err;
        }
        ecc::sign(result, data, skey)
    } else {
        encoding::err(error::GPG_ERR_NOT_SUPPORTED)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_verify(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    if key_has(pkey, "rsa") || key_has(pkey, "openpgp-rsa") {
        if let Some(err) = disabled_error(GCRY_PK_RSA) {
            return err;
        }
        rsa::verify(sigval, data, pkey)
    } else if key_has(pkey, "dsa") {
        if let Some(err) = disabled_error(GCRY_PK_DSA) {
            return err;
        }
        dsa::verify(sigval, data, pkey)
    } else if key_has(pkey, "elg") || key_has(pkey, "elgamal") {
        if let Some(err) = disabled_error(GCRY_PK_ELG) {
            return err;
        }
        elgamal::verify(sigval, data, pkey)
    } else if key_has(pkey, "ecc") || key_has(pkey, "ecdsa") {
        if let Some(err) = disabled_error(GCRY_PK_ECC) {
            return err;
        }
        ecc::verify(sigval, data, pkey)
    } else {
        encoding::err(error::GPG_ERR_NOT_SUPPORTED)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_testkey(key: *mut sexp::gcry_sexp) -> u32 {
    if key_has(key, "rsa") || key_has(key, "openpgp-rsa") {
        if let Some(err) = disabled_error(GCRY_PK_RSA) {
            return err;
        }
        rsa::testkey(key)
    } else if key_has(key, "dsa") {
        if let Some(err) = disabled_error(GCRY_PK_DSA) {
            return err;
        }
        dsa::testkey(key)
    } else if key_has(key, "elg") || key_has(key, "elgamal") {
        if let Some(err) = disabled_error(GCRY_PK_ELG) {
            return err;
        }
        elgamal::testkey(key)
    } else if key_has(key, "ecc") || key_has(key, "ecdsa") || key_has(key, "eddsa") {
        if let Some(err) = disabled_error(GCRY_PK_ECC) {
            return err;
        }
        ecc::testkey(key)
    } else {
        encoding::err(error::GPG_ERR_NOT_SUPPORTED)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_genkey(
    result: *mut *mut sexp::gcry_sexp,
    parms: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return encoding::err(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);
    if key_has(parms, "rsa") {
        if let Some(err) = disabled_error(GCRY_PK_RSA) {
            return err;
        }
        rsa::genkey(result, parms)
    } else if key_has(parms, "dsa") {
        if let Some(err) = disabled_error(GCRY_PK_DSA) {
            return err;
        }
        dsa::genkey(result, parms)
    } else if key_has(parms, "elg") || key_has(parms, "elgamal") {
        if let Some(err) = disabled_error(GCRY_PK_ELG) {
            return err;
        }
        elgamal::genkey(result, parms)
    } else if key_has(parms, "ecc") || key_has(parms, "ecdsa") || key_has(parms, "eddsa") {
        if let Some(err) = disabled_error(GCRY_PK_ECC) {
            return err;
        }
        ecc::genkey(result, parms)
    } else {
        encoding::err(error::GPG_ERR_NOT_SUPPORTED)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_ctl(cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
    match cmd {
        GCRYCTL_DISABLE_ALGO => {
            if buffer.is_null() || buflen != std::mem::size_of::<c_int>() {
                return encoding::err(error::GPG_ERR_INV_ARG);
            }
            let algo = unsafe { *(buffer.cast::<c_int>()) };
            disable_algo(algo);
            0
        }
        _ => encoding::err(error::GPG_ERR_INV_OP),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_algo_info(
    algo: c_int,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    match what {
        GCRYCTL_TEST_ALGO => {
            if !buffer.is_null() {
                return encoding::err(error::GPG_ERR_INV_ARG);
            }
            let usage = if nbytes.is_null() {
                0
            } else {
                unsafe { *nbytes }
            };
            test_algo(algo, usage)
        }
        GCRYCTL_GET_ALGO_USAGE
        | GCRYCTL_GET_ALGO_NPKEY
        | GCRYCTL_GET_ALGO_NSKEY
        | GCRYCTL_GET_ALGO_NSIGN
        | GCRYCTL_GET_ALGO_NENCR => {
            if nbytes.is_null() {
                return encoding::err(error::GPG_ERR_INV_ARG);
            }
            let info = algo_info_record(algo);
            let value = match what {
                GCRYCTL_GET_ALGO_USAGE => info.map(|info| info.usage),
                GCRYCTL_GET_ALGO_NPKEY => info.map(|info| info.npkey),
                GCRYCTL_GET_ALGO_NSKEY => info.map(|info| info.nskey),
                GCRYCTL_GET_ALGO_NSIGN => info.map(|info| info.nsign),
                GCRYCTL_GET_ALGO_NENCR => info.map(|info| info.nencr),
                _ => None,
            }
            .unwrap_or(0);
            unsafe { *nbytes = value };
            0
        }
        _ => encoding::err(error::GPG_ERR_INV_OP),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_algo_name(algo: c_int) -> *const c_char {
    fallback_algo_name(algo)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_map_name(name: *const c_char) -> c_int {
    if name.is_null() {
        return 0;
    }
    let name = unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .to_ascii_lowercase();
    let algo = match name.as_str() {
        "rsa" | "openpgp-rsa" => 1,
        "dsa" => 17,
        "elg" | "elgamal" => 20,
        "ecc" | "gost" | "sm2" | "ecdsa" | "ecdh" | "eddsa" => 18,
        _ => 0,
    };
    if algo == 0 || algo_disabled(algo) {
        0
    } else {
        algo
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_get_nbits(key: *mut sexp::gcry_sexp) -> u32 {
    if key_has(key, "rsa") || key_has(key, "openpgp-rsa") {
        if algo_disabled(GCRY_PK_RSA) {
            return 0;
        }
        rsa::get_nbits(key)
    } else if key_has(key, "dsa") {
        if algo_disabled(GCRY_PK_DSA) {
            return 0;
        }
        dsa::get_nbits(key)
    } else if key_has(key, "elg") || key_has(key, "elgamal") {
        if algo_disabled(GCRY_PK_ELG) {
            return 0;
        }
        elgamal::get_nbits(key)
    } else if let Some(curve) =
        encoding::token_string(key, "curve").and_then(|name| crate::mpi::ec::curve_by_name(&name))
    {
        if algo_disabled(GCRY_PK_ECC) {
            return 0;
        }
        curve.p.bits() as u32
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_hash_sign(
    result: *mut *mut sexp::gcry_sexp,
    data_tmpl: *const c_char,
    skey: *mut sexp::gcry_sexp,
    hd: gcry_md_hd_t,
    ctx: *mut c_void,
) -> u32 {
    if result.is_null() {
        return encoding::err(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);
    let data = match hash_data_sexp(data_tmpl, hd, ctx) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let rc = gcry_pk_sign(result, data, skey);
    sexp::gcry_sexp_release(data);
    rc
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_hash_verify(
    sigval: *mut sexp::gcry_sexp,
    data_tmpl: *const c_char,
    pkey: *mut sexp::gcry_sexp,
    hd: gcry_md_hd_t,
    ctx: *mut c_void,
) -> u32 {
    let data = match hash_data_sexp(data_tmpl, hd, ctx) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let rc = gcry_pk_verify(sigval, data, pkey);
    sexp::gcry_sexp_release(data);
    rc
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_random_override_new(
    r_ctx: *mut *mut c_void,
    p: *const u8,
    len: usize,
) -> u32 {
    if r_ctx.is_null() || (p.is_null() && len != 0) {
        return encoding::err(error::GPG_ERR_INV_ARG);
    }
    let bytes = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(p, len) }.to_vec()
    };
    unsafe { *r_ctx = context::new_random_override(bytes) };
    0
}

#[unsafe(export_name = "safe_gcry_pk_register")]
pub extern "C" fn gcry_pk_register() -> u32 {
    encoding::err(error::GPG_ERR_NOT_SUPPORTED)
}
