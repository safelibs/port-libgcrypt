mod dsa;
mod ecc;
mod elgamal;
pub(crate) mod encoding;
mod keygrip;
mod rsa;

use std::collections::BTreeSet;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::mem;
use std::ptr::null_mut;
use std::sync::{Mutex, OnceLock};

use crate::context;
use crate::digest::{self, gcry_md_hd_t};
use crate::error;
use crate::mpi::{self, MpiKind, gcry_mpi};
use crate::sexp;

pub(crate) const KEYGRIP_LEN: usize = 20;

pub(crate) const GCRY_PK_RSA: c_int = 1;
pub(crate) const GCRY_PK_RSA_E: c_int = 2;
pub(crate) const GCRY_PK_RSA_S: c_int = 3;
pub(crate) const GCRY_PK_ELG_E: c_int = 16;
pub(crate) const GCRY_PK_DSA: c_int = 17;
pub(crate) const GCRY_PK_ECC: c_int = 18;
pub(crate) const GCRY_PK_ELG: c_int = 20;
pub(crate) const GCRY_PK_ECDSA: c_int = 301;
pub(crate) const GCRY_PK_ECDH: c_int = 302;
pub(crate) const GCRY_PK_EDDSA: c_int = 303;

pub(crate) const GCRYCTL_TEST_ALGO: c_int = 8;
pub(crate) const GCRYCTL_DISABLE_ALGO: c_int = 12;
pub(crate) const GCRYCTL_GET_ALGO_NPKEY: c_int = 15;
pub(crate) const GCRYCTL_GET_ALGO_NSKEY: c_int = 16;
pub(crate) const GCRYCTL_GET_ALGO_NSIGN: c_int = 17;
pub(crate) const GCRYCTL_GET_ALGO_NENCR: c_int = 18;
pub(crate) const GCRYCTL_GET_ALGO_USAGE: c_int = 34;

pub(crate) const GCRY_PK_USAGE_SIGN: usize = 1;
pub(crate) const GCRY_PK_USAGE_ENCR: usize = 2;
pub(crate) const GCRY_PK_USAGE_AUTH: usize = 8;

pub(crate) const GCRY_PK_GET_PUBKEY: c_int = 1;
pub(crate) const GCRY_PK_GET_SECKEY: c_int = 2;

pub(crate) const GPG_ERR_PUBKEY_ALGO: u32 = 4;
pub(crate) const GPG_ERR_DIGEST_ALGO: u32 = 5;
pub(crate) const GPG_ERR_BAD_SIGNATURE: u32 = 8;
pub(crate) const GPG_ERR_WRONG_PUBKEY_ALGO: u32 = 41;
pub(crate) const GPG_ERR_CONFLICT: u32 = 70;
pub(crate) const GPG_ERR_INV_FLAG: u32 = 72;
pub(crate) const GPG_ERR_ENCODING_PROBLEM: u32 = 155;
pub(crate) const GPG_ERR_NO_CRYPT_CTX: u32 = 191;
pub(crate) const GPG_ERR_WRONG_CRYPT_CTX: u32 = 192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Family {
    Rsa,
    Dsa,
    Elgamal,
    Ecc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataEncoding {
    Unknown,
    Raw,
    Pkcs1,
    Pkcs1Raw,
    Oaep,
    Pss,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DataFlags {
    pub(crate) has_flags: bool,
    pub(crate) raw_explicit: bool,
    pub(crate) rfc6979: bool,
    pub(crate) prehash: bool,
    pub(crate) gost: bool,
    pub(crate) sm2: bool,
    pub(crate) eddsa: bool,
}

pub(crate) struct OwnedMpi(*mut gcry_mpi);

impl OwnedMpi {
    pub(crate) fn new(ptr: *mut gcry_mpi) -> Self {
        Self(ptr)
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }

    pub(crate) fn raw(&self) -> *mut gcry_mpi {
        self.0
    }

    pub(crate) fn as_ref(&self) -> Option<&gcry_mpi> {
        unsafe { gcry_mpi::as_ref(self.0) }
    }

    pub(crate) fn into_raw(self) -> *mut gcry_mpi {
        let ptr = self.0;
        mem::forget(self);
        ptr
    }
}

impl Drop for OwnedMpi {
    fn drop(&mut self) {
        if !self.0.is_null() {
            mpi::gcry_mpi_release(self.0);
        }
    }
}

pub(crate) struct OwnedSexp(*mut sexp::gcry_sexp);

impl OwnedSexp {
    pub(crate) fn new(ptr: *mut sexp::gcry_sexp) -> Self {
        Self(ptr)
    }

    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }

    pub(crate) fn raw(&self) -> *mut sexp::gcry_sexp {
        self.0
    }

    pub(crate) fn into_raw(self) -> *mut sexp::gcry_sexp {
        let ptr = self.0;
        mem::forget(self);
        ptr
    }
}

impl Drop for OwnedSexp {
    fn drop(&mut self) {
        if !self.0.is_null() {
            sexp::gcry_sexp_release(self.0);
        }
    }
}

fn disabled_algorithms() -> &'static Mutex<BTreeSet<c_int>> {
    static STATE: OnceLock<Mutex<BTreeSet<c_int>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn lock_disabled_algorithms() -> std::sync::MutexGuard<'static, BTreeSet<c_int>> {
    match disabled_algorithms().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(crate) fn normalize_algorithm(algo: c_int) -> c_int {
    match algo {
        GCRY_PK_RSA_E | GCRY_PK_RSA_S => GCRY_PK_RSA,
        GCRY_PK_ELG_E => GCRY_PK_ELG,
        value => value,
    }
}

pub(crate) fn family_from_algorithm(algo: c_int) -> Option<Family> {
    match normalize_algorithm(algo) {
        GCRY_PK_RSA => Some(Family::Rsa),
        GCRY_PK_DSA => Some(Family::Dsa),
        GCRY_PK_ELG => Some(Family::Elgamal),
        GCRY_PK_ECC | GCRY_PK_ECDSA | GCRY_PK_ECDH | GCRY_PK_EDDSA => Some(Family::Ecc),
        _ => None,
    }
}

pub(crate) fn family_from_key(key: *mut sexp::gcry_sexp) -> Option<Family> {
    if key.is_null() {
        return None;
    }

    if rsa::has_key_token(key) {
        return Some(Family::Rsa);
    }
    if dsa::has_key_token(key) {
        return Some(Family::Dsa);
    }
    if elgamal::has_key_token(key) {
        return Some(Family::Elgamal);
    }
    if ecc::has_key_token(key) {
        return Some(Family::Ecc);
    }
    None
}

pub(crate) fn build_sexp(format: &str, args: &[usize]) -> Result<*mut sexp::gcry_sexp, u32> {
    let c_format = CString::new(format).expect("format without interior NUL");
    let mut result = null_mut();
    let rc = sexp::safe_gcry_sexp_build_dispatch(
        &mut result,
        null_mut(),
        c_format.as_ptr(),
        args.as_ptr(),
        args.len(),
    );
    if rc == 0 { Ok(result) } else { Err(rc) }
}

pub(crate) fn find_token(sexp_ptr: *mut sexp::gcry_sexp, name: &[u8]) -> OwnedSexp {
    OwnedSexp::new(sexp::gcry_sexp_find_token(
        sexp_ptr,
        name.as_ptr().cast(),
        0,
    ))
}

pub(crate) fn find_token_one(sexp_ptr: *mut sexp::gcry_sexp, name: &[u8]) -> OwnedSexp {
    OwnedSexp::new(sexp::gcry_sexp_find_token(
        sexp_ptr,
        name.as_ptr().cast(),
        1,
    ))
}

pub(crate) fn find_first_token(sexp_ptr: *mut sexp::gcry_sexp, names: &[&[u8]]) -> OwnedSexp {
    for name in names {
        let found = find_token(sexp_ptr, name);
        if !found.is_null() {
            return found;
        }
        if name.len() > 1 {
            let mut upper = name[..name.len() - 1].to_ascii_uppercase();
            upper.push(0);
            let found = find_token(sexp_ptr, &upper);
            if !found.is_null() {
                return found;
            }
        }
    }
    OwnedSexp::new(null_mut())
}

pub(crate) fn nth_data_bytes(sexp_ptr: *mut sexp::gcry_sexp, number: c_int) -> Option<Vec<u8>> {
    let mut len = 0usize;
    let data = sexp::gcry_sexp_nth_data(sexp_ptr, number, &mut len);
    if data.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) }.to_vec())
    }
}

pub(crate) fn nth_string(sexp_ptr: *mut sexp::gcry_sexp, number: c_int) -> Option<String> {
    let ptr = sexp::gcry_sexp_nth_string(sexp_ptr, number);
    if ptr.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
    crate::alloc::gcry_free(ptr.cast());
    Some(value)
}

pub(crate) fn token_data_bytes(sexp_ptr: *mut sexp::gcry_sexp, name: &[u8]) -> Option<Vec<u8>> {
    let found = find_token(sexp_ptr, name);
    nth_data_bytes(found.raw(), 1)
}

pub(crate) fn token_string_value(sexp_ptr: *mut sexp::gcry_sexp, name: &[u8]) -> Option<String> {
    let found = find_token(sexp_ptr, name);
    nth_string(found.raw(), 1)
}

pub(crate) fn token_usize(sexp_ptr: *mut sexp::gcry_sexp, name: &[u8]) -> Option<usize> {
    token_data_bytes(sexp_ptr, name).and_then(|value| {
        std::str::from_utf8(&value)
            .ok()
            .map(str::trim)
            .and_then(|item| item.parse::<usize>().ok())
    })
}

pub(crate) fn token_mpi(
    sexp_ptr: *mut sexp::gcry_sexp,
    name: &[u8],
    format: c_int,
) -> OwnedMpi {
    let found = find_token(sexp_ptr, name);
    OwnedMpi::new(sexp::gcry_sexp_nth_mpi(found.raw(), 1, format))
}

pub(crate) fn token_present(sexp_ptr: *mut sexp::gcry_sexp, name: &[u8]) -> bool {
    !find_token(sexp_ptr, name).is_null()
}

pub(crate) fn flag_present(sexp_ptr: *mut sexp::gcry_sexp, name: &[u8]) -> bool {
    let flags = find_token(sexp_ptr, b"flags\0");
    if flags.is_null() {
        return false;
    }

    let mut idx = 1;
    while let Some(value) = nth_data_bytes(flags.raw(), idx) {
        if value == &name[..name.len().saturating_sub(1)] {
            return true;
        }
        idx += 1;
    }
    false
}

pub(crate) fn has_flags_list(sexp_ptr: *mut sexp::gcry_sexp) -> bool {
    token_present(sexp_ptr, b"flags\0")
}

fn set_data_encoding(
    encoding: &mut DataEncoding,
    new_encoding: DataEncoding,
    ignore_invalid: bool,
) -> Result<(), u32> {
    if *encoding == DataEncoding::Unknown {
        *encoding = new_encoding;
        Ok(())
    } else if *encoding == new_encoding || ignore_invalid {
        Ok(())
    } else {
        Err(error::gcry_error_from_code(GPG_ERR_INV_FLAG))
    }
}

pub(crate) fn parse_data_flags(data: *mut sexp::gcry_sexp) -> Result<(DataEncoding, DataFlags), u32> {
    let flags = find_token(data, b"flags\0");
    if flags.is_null() {
        return Ok((DataEncoding::Unknown, DataFlags::default()));
    }

    let mut encoding = DataEncoding::Unknown;
    let mut parsed = DataFlags {
        has_flags: true,
        ..DataFlags::default()
    };
    let mut ignore_invalid = false;
    let mut idx = 1;
    while let Some(value) = nth_data_bytes(flags.raw(), idx) {
        match value.as_slice() {
            b"raw" => {
                set_data_encoding(&mut encoding, DataEncoding::Raw, ignore_invalid)?;
                parsed.raw_explicit = true;
            }
            b"pkcs1" => set_data_encoding(&mut encoding, DataEncoding::Pkcs1, ignore_invalid)?,
            b"pkcs1-raw" => {
                set_data_encoding(&mut encoding, DataEncoding::Pkcs1Raw, ignore_invalid)?
            }
            b"oaep" => set_data_encoding(&mut encoding, DataEncoding::Oaep, ignore_invalid)?,
            b"pss" => set_data_encoding(&mut encoding, DataEncoding::Pss, ignore_invalid)?,
            b"rfc6979" => parsed.rfc6979 = true,
            b"prehash" => parsed.prehash = true,
            b"gost" => {
                set_data_encoding(&mut encoding, DataEncoding::Raw, ignore_invalid)?;
                parsed.gost = true;
            }
            b"sm2" => {
                set_data_encoding(&mut encoding, DataEncoding::Raw, ignore_invalid)?;
                parsed.sm2 = true;
                parsed.raw_explicit = true;
            }
            b"eddsa" => {
                set_data_encoding(&mut encoding, DataEncoding::Raw, ignore_invalid)?;
                parsed.eddsa = true;
            }
            b"djb-tweak" | b"comp" | b"nocomp" | b"param" | b"noparam" | b"no-blinding"
            | b"use-x931" | b"transient-key" | b"no-keytest" => {}
            b"igninvflag" => ignore_invalid = true,
            _ if ignore_invalid => {}
            _ => return Err(error::gcry_error_from_code(GPG_ERR_INV_FLAG)),
        }
        idx += 1;
    }

    Ok((encoding, parsed))
}

pub(crate) fn mpi_to_bytes(mpi_ptr: *mut gcry_mpi) -> Option<Vec<u8>> {
    let mpi = unsafe { gcry_mpi::as_ref(mpi_ptr) }?;
    match &mpi.kind {
        MpiKind::Numeric(value) => Some(mpi::export_unsigned(value.as_ptr())),
        MpiKind::Opaque(value) => Some(value.as_slice().to_vec()),
    }
}

pub(crate) fn mpi_to_mpz(mpi_ptr: *mut gcry_mpi) -> Option<mpi::Mpz> {
    let mpi = unsafe { gcry_mpi::as_ref(mpi_ptr) }?;
    match &mpi.kind {
        MpiKind::Numeric(value) => Some(mpi::Mpz::clone_from(value.as_ptr())),
        MpiKind::Opaque(_) => None,
    }
}

pub(crate) fn bytes_to_mpi(bytes: &[u8], secure: bool) -> *mut gcry_mpi {
    gcry_mpi::from_numeric(mpi::import_unsigned_bytes(bytes), secure)
}

pub(crate) fn generic_keygrip(
    key: *mut sexp::gcry_sexp,
    elems: &[&[u8]],
) -> Option<[u8; KEYGRIP_LEN]> {
    use sha1::{Digest as _, Sha1};

    let mut hash = Sha1::new();
    for elem in elems {
        let value = token_data_bytes(key, elem)?;
        let tag = elem.first().copied().unwrap_or_default() as char;
        hash.update(format!("(1:{tag}{}:", value.len()).as_bytes());
        hash.update(&value);
        hash.update(b")");
    }
    let digest = hash.finalize();
    let mut out = [0u8; KEYGRIP_LEN];
    out.copy_from_slice(&digest[..KEYGRIP_LEN]);
    Some(out)
}

pub(crate) fn usize_to_arg(value: usize) -> usize {
    value
}

pub(crate) fn ptr_to_arg<T>(ptr: *const T) -> usize {
    ptr as usize
}

pub(crate) fn digest_algo_from_template(template: &CStr) -> Result<(Option<CString>, c_int), u32> {
    let text = template.to_string_lossy();
    let Some(start) = text.find("(hash ") else {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    };
    let tail = &text[start + 6..];
    if tail.starts_with("%s") {
        return Ok((None, 0));
    }
    let Some(end) = tail.find(' ') else {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    };
    let name = CString::new(&tail[..end]).expect("digest name without interior NUL");
    let algo = digest::gcry_md_map_name(name.as_ptr());
    if algo == 0 || digest::gcry_md_get_algo_dlen(algo) == 0 {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    }
    Ok((Some(name), algo))
}

fn build_hash_sexp_from_md(
    template: *const c_char,
    hd: gcry_md_hd_t,
    ctx: *mut c_void,
) -> Result<*mut sexp::gcry_sexp, u32> {
    if template.is_null() || hd.is_null() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
    }

    let template = unsafe { CStr::from_ptr(template) };
    let (fixed_name, fixed_algo) = digest_algo_from_template(template)?;
    let algo = if fixed_name.is_some() {
        fixed_algo
    } else {
        digest::gcry_md_get_algo(hd)
    };
    let digest_len = digest::gcry_md_get_algo_dlen(algo) as usize;
    if digest_len == 0 {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    }

    let digest_ptr = digest::gcry_md_read(hd, if fixed_name.is_some() { algo } else { 0 });
    if digest_ptr.is_null() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_NOT_IMPLEMENTED));
    }
    let digest_bytes = unsafe { std::slice::from_raw_parts(digest_ptr, digest_len) };

    let random_override = if ctx.is_null() {
        None
    } else {
        let value = context::copy_random_override_context(ctx)
            .ok_or(error::gcry_error_from_code(GPG_ERR_WRONG_CRYPT_CTX))?;
        Some(value)
    };

    let mut args = Vec::new();
    if let Some(name) = fixed_name.as_ref() {
        let _ = name;
    } else {
        let name = digest::gcry_md_algo_name(algo);
        if name.is_null() {
            return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
        }
        args.push(ptr_to_arg(name));
    }
    args.push(usize_to_arg(digest_len));
    args.push(ptr_to_arg(digest_bytes.as_ptr()));
    if let Some(override_bytes) = random_override.as_ref() {
        args.push(usize_to_arg(override_bytes.len()));
        args.push(ptr_to_arg(override_bytes.as_ptr()));
    }
    build_sexp(template.to_str().expect("template valid UTF-8"), &args)
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

#[no_mangle]
pub extern "C" fn gcry_pk_encrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);

    match family_from_key(pkey) {
        Some(Family::Rsa) => rsa::encrypt(result, data, pkey),
        Some(Family::Elgamal) => elgamal::encrypt(result, data, pkey),
        Some(Family::Ecc) => ecc::encrypt(result, data, pkey),
        _ => error::gcry_error_from_code(GPG_ERR_PUBKEY_ALGO),
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_decrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);

    match family_from_key(skey) {
        Some(Family::Rsa) => rsa::decrypt(result, data, skey),
        Some(Family::Elgamal) => elgamal::decrypt(result, data, skey),
        Some(Family::Ecc) => ecc::decrypt(result, data, skey),
        _ => error::gcry_error_from_code(GPG_ERR_PUBKEY_ALGO),
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_sign(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);

    match family_from_key(skey) {
        Some(Family::Rsa) => rsa::sign(result, data, skey),
        Some(Family::Dsa) => dsa::sign(result, data, skey),
        Some(Family::Elgamal) => elgamal::sign(result, data, skey),
        Some(Family::Ecc) => ecc::sign(result, data, skey),
        _ => error::gcry_error_from_code(GPG_ERR_PUBKEY_ALGO),
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_verify(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    match family_from_key(pkey) {
        Some(Family::Rsa) => rsa::verify(sigval, data, pkey),
        Some(Family::Dsa) => dsa::verify(sigval, data, pkey),
        Some(Family::Elgamal) => elgamal::verify(sigval, data, pkey),
        Some(Family::Ecc) => ecc::verify(sigval, data, pkey),
        _ => error::gcry_error_from_code(GPG_ERR_PUBKEY_ALGO),
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_testkey(key: *mut sexp::gcry_sexp) -> u32 {
    match family_from_key(key) {
        Some(Family::Rsa) => rsa::testkey(key),
        Some(Family::Dsa) => dsa::testkey(key),
        Some(Family::Elgamal) => elgamal::testkey(key),
        Some(Family::Ecc) => ecc::testkey(key),
        _ => error::gcry_error_from_code(GPG_ERR_PUBKEY_ALGO),
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_genkey(
    result: *mut *mut sexp::gcry_sexp,
    parms: *mut sexp::gcry_sexp,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);

    match family_from_key(parms) {
        Some(Family::Rsa) => rsa::genkey(result, parms),
        Some(Family::Dsa) => dsa::genkey(result, parms),
        Some(Family::Elgamal) => elgamal::genkey(result, parms),
        Some(Family::Ecc) => ecc::genkey(result, parms),
        _ => error::gcry_error_from_code(GPG_ERR_PUBKEY_ALGO),
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_ctl(cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
    if cmd != GCRYCTL_DISABLE_ALGO {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OP);
    }
    if buffer.is_null() || buflen != mem::size_of::<c_int>() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let algo = normalize_algorithm(unsafe { *(buffer.cast::<c_int>()) });
    lock_disabled_algorithms().insert(algo);
    0
}

fn local_algo_usage(algo: c_int) -> usize {
    match normalize_algorithm(algo) {
        GCRY_PK_RSA => GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR,
        GCRY_PK_DSA => GCRY_PK_USAGE_SIGN,
        GCRY_PK_ELG => GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR,
        GCRY_PK_ECC => GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR,
        GCRY_PK_ECDSA => GCRY_PK_USAGE_SIGN,
        GCRY_PK_ECDH => GCRY_PK_USAGE_ENCR | GCRY_PK_USAGE_AUTH,
        GCRY_PK_EDDSA => GCRY_PK_USAGE_SIGN,
        _ => 0,
    }
}

fn local_algo_counts(algo: c_int) -> Option<(usize, usize, usize, usize)> {
    match normalize_algorithm(algo) {
        GCRY_PK_RSA => Some((2, 6, 1, 1)),
        GCRY_PK_DSA => Some((4, 5, 2, 0)),
        GCRY_PK_ELG => Some((3, 4, 2, 2)),
        GCRY_PK_ECC | GCRY_PK_ECDSA | GCRY_PK_ECDH | GCRY_PK_EDDSA => Some((7, 8, 2, 2)),
        _ => None,
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_algo_info(
    algo: c_int,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    let algo = normalize_algorithm(algo);
    match what {
        GCRYCTL_TEST_ALGO => {
            if !buffer.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            let required_usage = if nbytes.is_null() { 0 } else { unsafe { *nbytes } };
            if local_algo_usage(algo) == 0
                || lock_disabled_algorithms().contains(&algo)
                || (required_usage != 0 && local_algo_usage(algo) & required_usage != required_usage)
            {
                error::gcry_error_from_code(GPG_ERR_PUBKEY_ALGO)
            } else {
                0
            }
        }
        GCRYCTL_GET_ALGO_USAGE => {
            if nbytes.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            unsafe {
                *nbytes = local_algo_usage(algo);
            }
            0
        }
        GCRYCTL_GET_ALGO_NPKEY
        | GCRYCTL_GET_ALGO_NSKEY
        | GCRYCTL_GET_ALGO_NSIGN
        | GCRYCTL_GET_ALGO_NENCR => {
            if nbytes.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            let Some((npkey, nskey, nsign, nencr)) = local_algo_counts(algo) else {
                unsafe {
                    *nbytes = 0;
                }
                return 0;
            };
            unsafe {
                *nbytes = match what {
                    GCRYCTL_GET_ALGO_NPKEY => npkey,
                    GCRYCTL_GET_ALGO_NSKEY => nskey,
                    GCRYCTL_GET_ALGO_NSIGN => nsign,
                    _ => nencr,
                };
            }
            0
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_algo_name(algo: c_int) -> *const c_char {
    match normalize_algorithm(algo) {
        GCRY_PK_ECC => b"ecc\0".as_ptr().cast(),
        GCRY_PK_ECDSA => b"ecdsa\0".as_ptr().cast(),
        GCRY_PK_ECDH => b"ecdh\0".as_ptr().cast(),
        GCRY_PK_EDDSA => b"eddsa\0".as_ptr().cast(),
        _ => fallback_algo_name(algo),
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_map_name(name: *const c_char) -> c_int {
    if name.is_null() {
        return 0;
    }
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy().to_ascii_lowercase();
    if let Some(algo) = rsa::map_name(&name) {
        return algo;
    }
    if let Some(algo) = dsa::map_name(&name) {
        return algo;
    }
    if let Some(algo) = elgamal::map_name(&name) {
        return algo;
    }
    match name.as_str() {
        "ecc" => GCRY_PK_ECC,
        "ecdsa" => GCRY_PK_ECDSA,
        "ecdh" => GCRY_PK_ECDH,
        "eddsa" => GCRY_PK_EDDSA,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_get_nbits(key: *mut sexp::gcry_sexp) -> c_uint {
    match family_from_key(key) {
        Some(Family::Rsa) => rsa::get_nbits(key),
        Some(Family::Dsa) => dsa::get_nbits(key),
        Some(Family::Elgamal) => elgamal::get_nbits(key),
        Some(Family::Ecc) => ecc::get_nbits(key),
        None => 0,
    }
}

#[no_mangle]
pub extern "C" fn gcry_pk_hash_sign(
    result: *mut *mut sexp::gcry_sexp,
    template: *const c_char,
    skey: *mut sexp::gcry_sexp,
    hd: gcry_md_hd_t,
    ctx: *mut c_void,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    clear_result_slot(result);

    let hash = match build_hash_sexp_from_md(template, hd, ctx) {
        Ok(value) => OwnedSexp::new(value),
        Err(err) => return err,
    };
    let rc = gcry_pk_sign(result, hash.raw(), skey);
    rc
}

#[no_mangle]
pub extern "C" fn gcry_pk_hash_verify(
    sigval: *mut sexp::gcry_sexp,
    template: *const c_char,
    pkey: *mut sexp::gcry_sexp,
    hd: gcry_md_hd_t,
    ctx: *mut c_void,
) -> u32 {
    let hash = match build_hash_sexp_from_md(template, hd, ctx) {
        Ok(value) => OwnedSexp::new(value),
        Err(err) => return err,
    };
    gcry_pk_verify(sigval, hash.raw(), pkey)
}

#[no_mangle]
pub extern "C" fn gcry_pk_random_override_new(
    r_ctx: *mut *mut c_void,
    p: *const u8,
    len: usize,
) -> u32 {
    if r_ctx.is_null() || (len != 0 && p.is_null()) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    unsafe {
        *r_ctx = null_mut();
    }

    let bytes = if len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(p, len) }
    };
    match context::new_random_override_context(bytes) {
        Ok(ctx) => {
            unsafe {
                *r_ctx = ctx;
            }
            0
        }
        Err(err) => err,
    }
}

#[export_name = "safe_gcry_pk_register"]
pub extern "C" fn safe_gcry_pk_register() -> u32 {
    error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED)
}
