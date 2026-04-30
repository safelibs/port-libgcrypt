use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr::null_mut;

use crate::digest::{self, algorithms};
use crate::error;
use crate::mpi::{self, GCRYMPI_FMT_OPAQUE, GCRYMPI_FMT_USG, Mpz, gcry_mpi};
use crate::sexp;

pub(crate) fn err(code: u32) -> u32 {
    error::gcry_error_from_code(code)
}

pub(crate) fn hex_atom(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push('#');
    for byte in bytes {
        out.push_str(&format!("{byte:02X}"));
    }
    out.push('#');
    out
}

pub(crate) fn string_atom(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for byte in text.bytes() {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push('"');
    out
}

pub(crate) fn build_sexp(text: &str) -> Result<*mut sexp::gcry_sexp, u32> {
    let mut out = null_mut();
    let rc = sexp::gcry_sexp_sscan(
        &mut out,
        null_mut(),
        text.as_ptr().cast::<c_char>(),
        text.len(),
    );
    if rc == 0 { Ok(out) } else { Err(rc) }
}

pub(crate) fn find_token(sexp: *mut sexp::gcry_sexp, token: &str) -> *mut sexp::gcry_sexp {
    let Ok(token) = CString::new(token) else {
        return null_mut();
    };
    sexp::gcry_sexp_find_token(sexp, token.as_ptr(), 0)
}

pub(crate) fn has_token(sexp: *mut sexp::gcry_sexp, token: &str) -> bool {
    let found = find_token(sexp, token);
    if found.is_null() {
        false
    } else {
        sexp::gcry_sexp_release(found);
        true
    }
}

pub(crate) fn nth_data(list: *mut sexp::gcry_sexp, index: i32) -> Option<Vec<u8>> {
    let mut len = 0usize;
    let ptr = sexp::gcry_sexp_nth_data(list, index, &mut len);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) }.to_vec())
    }
}

pub(crate) fn token_data(sexp: *mut sexp::gcry_sexp, token: &str) -> Option<Vec<u8>> {
    let found = find_token(sexp, token);
    if found.is_null() {
        return None;
    }
    let data = nth_data(found, 1);
    sexp::gcry_sexp_release(found);
    data
}

pub(crate) fn token_string(sexp: *mut sexp::gcry_sexp, token: &str) -> Option<String> {
    token_data(sexp, token).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

pub(crate) fn nth_mpi(
    list: *mut sexp::gcry_sexp,
    index: i32,
    opaque: bool,
) -> Option<*mut gcry_mpi> {
    let mpi = sexp::gcry_sexp_nth_mpi(
        list,
        index,
        if opaque {
            GCRYMPI_FMT_OPAQUE
        } else {
            GCRYMPI_FMT_USG
        },
    );
    (!mpi.is_null()).then_some(mpi)
}

pub(crate) fn token_mpi(sexp: *mut sexp::gcry_sexp, token: &str) -> Option<*mut gcry_mpi> {
    let found = find_token(sexp, token);
    if found.is_null() {
        return None;
    }
    let mpi = nth_mpi(found, 1, false);
    sexp::gcry_sexp_release(found);
    mpi
}

pub(crate) fn token_mpi_opaque(sexp: *mut sexp::gcry_sexp, token: &str) -> Option<*mut gcry_mpi> {
    let found = find_token(sexp, token);
    if found.is_null() {
        return None;
    }
    let mpi = nth_mpi(found, 1, true);
    sexp::gcry_sexp_release(found);
    mpi
}

pub(crate) fn mpi_to_mpz(mpi: *mut gcry_mpi) -> Option<Mpz> {
    let value = unsafe { gcry_mpi::as_ref(mpi) }?;
    Mpz::from_mpi(value)
}

pub(crate) fn token_mpz(sexp: *mut sexp::gcry_sexp, token: &str) -> Option<Mpz> {
    let mpi = token_mpi(sexp, token)?;
    let value = mpi_to_mpz(mpi);
    mpi::gcry_mpi_release(mpi);
    value
}

pub(crate) fn token_bytes_from_mpi(sexp: *mut sexp::gcry_sexp, token: &str) -> Option<Vec<u8>> {
    if let Some(raw) = token_data(sexp, token) {
        return Some(raw);
    }
    token_mpz(sexp, token).map(|value| value.to_be())
}

pub(crate) fn sexp_nth_mpz(sexp: *mut sexp::gcry_sexp, index: i32) -> Option<Mpz> {
    let mpi = nth_mpi(sexp, index, false)?;
    let value = mpi_to_mpz(mpi);
    mpi::gcry_mpi_release(mpi);
    value
}

pub(crate) fn has_flag(sexp: *mut sexp::gcry_sexp, flag: &str) -> bool {
    let flags = find_token(sexp, "flags");
    if flags.is_null() {
        return false;
    }
    let wanted = flag.as_bytes();
    let len = sexp::gcry_sexp_length(flags);
    let mut found = false;
    for idx in 1..len {
        if nth_data(flags, idx).is_some_and(|item| item.eq_ignore_ascii_case(wanted)) {
            found = true;
            break;
        }
    }
    sexp::gcry_sexp_release(flags);
    found
}

pub(crate) fn flag_atoms(sexp: *mut sexp::gcry_sexp) -> Vec<String> {
    let flags = find_token(sexp, "flags");
    if flags.is_null() {
        return Vec::new();
    }
    let len = sexp::gcry_sexp_length(flags);
    let mut out = Vec::new();
    for idx in 1..len {
        if let Some(item) = nth_data(flags, idx) {
            out.push(String::from_utf8_lossy(&item).to_ascii_lowercase());
        }
    }
    sexp::gcry_sexp_release(flags);
    out
}

pub(crate) fn data_value(data: *mut sexp::gcry_sexp) -> Option<Vec<u8>> {
    if let Some(bytes) = token_data(data, "value") {
        return Some(bytes);
    }
    if let Some(value) = token_mpz(data, "value") {
        return Some(value.to_be());
    }
    let mpi = nth_mpi(data, 0, true).or_else(|| nth_mpi(data, 0, false))?;
    let value = unsafe { gcry_mpi::as_ref(mpi) }.and_then(|mpi| {
        if let Some(opaque) = mpi.opaque() {
            Some(opaque.as_slice().to_vec())
        } else {
            Mpz::from_mpi(mpi).map(|value| value.to_be())
        }
    });
    mpi::gcry_mpi_release(mpi);
    value
}

pub(crate) fn hash_value(data: *mut sexp::gcry_sexp) -> Option<(String, Vec<u8>)> {
    let hash = find_token(data, "hash");
    if hash.is_null() {
        return None;
    }
    let name = nth_data(hash, 1).map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    let value = nth_data(hash, 2);
    sexp::gcry_sexp_release(hash);
    Some((name?, value?))
}

pub(crate) fn hash_algo_name(data: *mut sexp::gcry_sexp) -> Option<String> {
    token_string(data, "hash-algo").or_else(|| hash_value(data).map(|(name, _)| name))
}

pub(crate) fn digest_algo(name: &str) -> Option<c_int> {
    let c_name = CString::new(name).ok()?;
    let algo = digest::gcry_md_map_name(c_name.as_ptr());
    (algo != 0).then_some(algo)
}

fn bits2int(hash: &[u8], q: &Mpz) -> Mpz {
    let qbits = q.bits();
    let mut v = Mpz::from_be(hash);
    let hbits = hash.len() * 8;
    if hbits > qbits {
        v = v.shr(hbits - qbits);
    }
    v
}

fn bits2octets(hash: &[u8], q: &Mpz, rlen: usize) -> Vec<u8> {
    let mut z = bits2int(hash, q);
    if z.cmp(q) >= 0 {
        z = z.sub(q);
    }
    z.to_be_padded(rlen)
}

pub(crate) fn rfc6979_nonce(q: &Mpz, x: &Mpz, hash_name: &str, hash: &[u8]) -> Option<Mpz> {
    let algo = digest_algo(hash_name)?;
    let hlen = algorithms::digest_len(algo);
    if hlen == 0 || hlen != hash.len() || q.is_zero() {
        return None;
    }
    let qbits = q.bits();
    let rlen = qbits.div_ceil(8);
    let x_octets = x.to_be_padded(rlen);
    let h_octets = bits2octets(hash, q, rlen);
    let mut v = vec![0x01; hlen];
    let mut k = vec![0x00; hlen];

    let mut seed = Vec::with_capacity(hlen + 1 + rlen * 2);
    seed.extend_from_slice(&v);
    seed.push(0x00);
    seed.extend_from_slice(&x_octets);
    seed.extend_from_slice(&h_octets);
    k = algorithms::hmac_once(algo, &k, &seed)?;
    v = algorithms::hmac_once(algo, &k, &v)?;

    seed.clear();
    seed.extend_from_slice(&v);
    seed.push(0x01);
    seed.extend_from_slice(&x_octets);
    seed.extend_from_slice(&h_octets);
    k = algorithms::hmac_once(algo, &k, &seed)?;
    v = algorithms::hmac_once(algo, &k, &v)?;

    loop {
        let mut t = Vec::with_capacity(rlen + hlen);
        while t.len() * 8 < qbits {
            v = algorithms::hmac_once(algo, &k, &v)?;
            t.extend_from_slice(&v);
        }
        let candidate = bits2int(&t, q);
        if !candidate.is_zero() && candidate.cmp(q) < 0 {
            return Some(candidate);
        }
        let mut retry = Vec::with_capacity(v.len() + 1);
        retry.extend_from_slice(&v);
        retry.push(0x00);
        k = algorithms::hmac_once(algo, &k, &retry)?;
        v = algorithms::hmac_once(algo, &k, &v)?;
    }
}

pub(crate) fn random_override(data: *mut sexp::gcry_sexp) -> Option<Vec<u8>> {
    token_data(data, "random-override")
}

pub(crate) fn label(data: *mut sexp::gcry_sexp) -> Vec<u8> {
    token_data(data, "label").unwrap_or_default()
}

pub(crate) fn cstr_eq(ptr: *const c_char, name: &str) -> bool {
    if ptr.is_null() {
        return false;
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_bytes()
        .eq_ignore_ascii_case(name.as_bytes())
}
