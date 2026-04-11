use std::ffi::{c_char, c_int, CString};
use std::ptr::null_mut;
use crate::digest::{self, algorithms};
use crate::error;
use crate::mpi::{self, GCRYMPI_FMT_USG, gcry_mpi};
use crate::random;
use crate::sexp;

use super::{
    DataEncoding, DataFlags, GCRY_PK_RSA, GCRY_PK_RSA_E, GCRY_PK_RSA_S, GPG_ERR_BAD_SIGNATURE,
    GPG_ERR_CONFLICT, GPG_ERR_DIGEST_ALGO, GPG_ERR_ENCODING_PROBLEM, OwnedMpi, build_sexp,
    bytes_to_mpi, find_first_token, find_token, parse_data_flags, token_data_bytes, token_mpi,
    token_string_value, token_usize,
};

pub(crate) const NAME: &[u8] = b"rsa\0";
const ALIASES: &[&[u8]] = &[b"rsa\0", b"openpgp-rsa\0", b"oid.1.2.840.113549.1.1.1\0"];

const TOK_N: &[u8] = b"n\0";
const TOK_E: &[u8] = b"e\0";
const TOK_D: &[u8] = b"d\0";
const TOK_P: &[u8] = b"p\0";
const TOK_Q: &[u8] = b"q\0";
const TOK_U: &[u8] = b"u\0";
const TOK_A: &[u8] = b"a\0";
const TOK_S: &[u8] = b"s\0";
const TOK_VALUE: &[u8] = b"value\0";
const TOK_HASH: &[u8] = b"hash\0";
const TOK_HASH_ALGO: &[u8] = b"hash-algo\0";
const TOK_LABEL: &[u8] = b"label\0";
const TOK_RANDOM_OVERRIDE: &[u8] = b"random-override\0";
const TOK_SALT_LENGTH: &[u8] = b"salt-length\0";

struct RsaPublicKey {
    n: OwnedMpi,
    e: OwnedMpi,
}

struct RsaSecretKey {
    public: RsaPublicKey,
    d: OwnedMpi,
    p: Option<OwnedMpi>,
    q: Option<OwnedMpi>,
    u: Option<OwnedMpi>,
}

struct RsaData {
    encoding: DataEncoding,
    flags: DataFlags,
    value_bytes: Option<Vec<u8>>,
    value_mpi: Option<OwnedMpi>,
    hash: Option<(c_int, Vec<u8>)>,
    hash_algo: Option<c_int>,
    label: Option<Vec<u8>>,
    salt_length: Option<usize>,
    random_override: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct RsaDeriveVector {
    nbits: usize,
    exponent: usize,
    xp: &'static str,
    xp1: &'static str,
    xp2: &'static str,
    xq: &'static str,
    xq1: &'static str,
    xq2: &'static str,
    expected_d: &'static str,
}

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    matches!(algo, GCRY_PK_RSA | GCRY_PK_RSA_E | GCRY_PK_RSA_S)
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}

pub(crate) fn map_name(name: &str) -> Option<c_int> {
    ALIASES
        .iter()
        .map(|alias| std::str::from_utf8(&alias[..alias.len() - 1]).expect("alias utf-8"))
        .find(|alias| alias.eq_ignore_ascii_case(name))
        .map(|_| GCRY_PK_RSA)
}

pub(crate) fn has_key_token(key: *mut sexp::gcry_sexp) -> bool {
    !find_first_token(key, ALIASES).is_null()
}

fn parse_public_key(key: *mut sexp::gcry_sexp) -> Result<RsaPublicKey, u32> {
    let n = token_mpi(key, TOK_N, GCRYMPI_FMT_USG);
    let e = token_mpi(key, TOK_E, GCRYMPI_FMT_USG);
    if n.is_null() || e.is_null() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_NO_OBJ));
    }
    Ok(RsaPublicKey { n, e })
}

fn parse_secret_key(key: *mut sexp::gcry_sexp) -> Result<RsaSecretKey, u32> {
    let public = parse_public_key(key)?;
    let d = token_mpi(key, TOK_D, GCRYMPI_FMT_USG);
    if d.is_null() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_NO_OBJ));
    }
    let p = token_mpi(key, TOK_P, GCRYMPI_FMT_USG);
    let q = token_mpi(key, TOK_Q, GCRYMPI_FMT_USG);
    let u = token_mpi(key, TOK_U, GCRYMPI_FMT_USG);
    let have_crt = !p.is_null() || !q.is_null() || !u.is_null();
    let (p, q, u) = if have_crt {
        if p.is_null() || q.is_null() || u.is_null() {
            return Err(error::gcry_error_from_code(error::GPG_ERR_NO_OBJ));
        }
        (Some(p), Some(q), Some(u))
    } else {
        (None, None, None)
    };
    Ok(RsaSecretKey { public, d, p, q, u })
}

fn mpi_copy(value: *mut gcry_mpi) -> OwnedMpi {
    OwnedMpi::new(mpi::gcry_mpi_copy(value))
}

fn mpi_from_ui(value: usize) -> OwnedMpi {
    let raw = mpi::gcry_mpi_new(0);
    mpi::gcry_mpi_set_ui(raw, value as _);
    OwnedMpi::new(raw)
}

fn mpi_is_zero(value: *mut gcry_mpi) -> bool {
    mpi::gcry_mpi_cmp_ui(value, 0) == 0
}

fn mpi_equal(left: *mut gcry_mpi, right: *mut gcry_mpi) -> bool {
    mpi::gcry_mpi_cmp(left, right) == 0
}

fn mpi_fixed_bytes(value: *mut gcry_mpi, len: usize) -> Vec<u8> {
    let mut bytes = super::mpi_to_bytes(value).unwrap_or_default();
    if bytes.len() > len {
        bytes = bytes[bytes.len() - len..].to_vec();
    }
    if bytes.len() < len {
        let mut padded = vec![0u8; len - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    bytes
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hash_bytes(algo: c_int, input: &[u8]) -> Result<Vec<u8>, u32> {
    let len = digest::gcry_md_get_algo_dlen(algo) as usize;
    if len == 0 {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    }
    let mut out = vec![0u8; len];
    digest::gcry_md_hash_buffer(algo, out.as_mut_ptr().cast(), input.as_ptr().cast(), input.len());
    Ok(out)
}

fn mgf1(algo: c_int, seed: &[u8], len: usize) -> Result<Vec<u8>, u32> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u32;
    while out.len() < len {
        let mut block = Vec::with_capacity(seed.len() + 4);
        block.extend_from_slice(seed);
        block.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&hash_bytes(algo, &block)?);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    Ok(out)
}

fn random_nonzero_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    while out.iter().any(|byte| *byte == 0) {
        random::fill_random_level(&mut out, random::GCRY_STRONG_RANDOM);
        for byte in &mut out {
            if *byte == 0 {
                *byte = 1;
            }
        }
    }
    out
}

fn parse_hash_algo_name(name: &str) -> Result<c_int, u32> {
    let oid_algo = match name {
        "oid.1.3.14.3.2.29" => Some(algorithms::map_name("sha1")),
        "oid.2.16.840.1.101.3.4.2.1" => Some(algorithms::map_name("sha256")),
        "oid.2.16.840.1.101.3.4.2.2" => Some(algorithms::map_name("sha384")),
        "oid.2.16.840.1.101.3.4.2.3" => Some(algorithms::map_name("sha512")),
        _ => None,
    };
    if let Some(algo) = oid_algo.filter(|algo| *algo != 0) {
        return Ok(algo);
    }

    let name = CString::new(name).expect("hash name");
    let algo = digest::gcry_md_map_name(name.as_ptr());
    if algo == 0 || digest::gcry_md_get_algo_dlen(algo) == 0 {
        Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))
    } else {
        Ok(algo)
    }
}

fn parse_data(data: *mut sexp::gcry_sexp) -> Result<RsaData, u32> {
    let (encoding, flags) = parse_data_flags(data)?;
    let encoding = if encoding == DataEncoding::Unknown {
        DataEncoding::Raw
    } else {
        encoding
    };

    let value_token = find_token(data, TOK_VALUE);
    let value_bytes = if value_token.is_null() {
        None
    } else {
        super::nth_data_bytes(value_token.raw(), 1)
    };
    let value_mpi = if value_token.is_null() {
        None
    } else {
        let mpi = sexp::gcry_sexp_nth_mpi(value_token.raw(), 1, GCRYMPI_FMT_USG);
        (!mpi.is_null()).then_some(OwnedMpi::new(mpi))
    };

    let hash = {
        let token = find_token(data, TOK_HASH);
        if token.is_null() {
            None
        } else {
            let algo_name = super::nth_string(token.raw(), 1)
                .ok_or(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))?;
            let digest = super::nth_data_bytes(token.raw(), 2)
                .ok_or(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))?;
            Some((parse_hash_algo_name(&algo_name)?, digest))
        }
    };
    let hash_algo = if let Some((algo, _)) = hash.as_ref() {
        Some(*algo)
    } else if let Some(name) = token_string_value(data, TOK_HASH_ALGO) {
        Some(parse_hash_algo_name(&name)?)
    } else {
        None
    };

    Ok(RsaData {
        encoding,
        flags,
        value_bytes,
        value_mpi,
        hash,
        hash_algo,
        label: token_data_bytes(data, TOK_LABEL),
        salt_length: token_usize(data, TOK_SALT_LENGTH),
        random_override: token_data_bytes(data, TOK_RANDOM_OVERRIDE),
    })
}

fn rsa_public(input: *mut gcry_mpi, key: &RsaPublicKey) -> *mut gcry_mpi {
    let out = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_powm(out.raw(), input, key.e.raw(), key.n.raw());
    out.into_raw()
}

fn rsa_private(input: *mut gcry_mpi, key: &RsaSecretKey) -> *mut gcry_mpi {
    let out = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let reduced = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_mod(reduced.raw(), input, key.public.n.raw());
    mpi::arith::gcry_mpi_powm(out.raw(), reduced.raw(), key.d.raw(), key.public.n.raw());
    out.into_raw()
}

fn pkcs1_encode_for_enc(nbits: usize, value: &[u8], random_override: Option<&[u8]>) -> Result<Vec<u8>, u32> {
    let nframe = nbits.div_ceil(8);
    if value.len() + 7 > nframe || nframe == 0 {
        return Err(error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT));
    }
    let ps_len = nframe - value.len() - 3;
    let ps = if let Some(override_bytes) = random_override {
        if override_bytes.len() != ps_len || override_bytes.iter().any(|byte| *byte == 0) {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
        }
        override_bytes.to_vec()
    } else {
        random_nonzero_bytes(ps_len)
    };
    let mut frame = Vec::with_capacity(nframe);
    frame.extend_from_slice(&[0, 2]);
    frame.extend_from_slice(&ps);
    frame.push(0);
    frame.extend_from_slice(value);
    Ok(frame)
}

fn pkcs1_decode_for_enc(nbits: usize, value: *mut gcry_mpi) -> Result<Vec<u8>, u32> {
    let nframe = nbits.div_ceil(8);
    let frame = mpi_fixed_bytes(value, nframe);
    if frame.len() < 11 || frame[0] != 0 || frame[1] != 2 {
        return Err(error::gcry_error_from_code(GPG_ERR_ENCODING_PROBLEM));
    }
    let Some(pos) = frame[2..].iter().position(|byte| *byte == 0) else {
        return Err(error::gcry_error_from_code(GPG_ERR_ENCODING_PROBLEM));
    };
    let split = 2 + pos;
    if split < 10 {
        return Err(error::gcry_error_from_code(GPG_ERR_ENCODING_PROBLEM));
    }
    Ok(frame[split + 1..].to_vec())
}

fn pkcs1_encode_for_sig(nbits: usize, algo: c_int, digest_bytes: &[u8]) -> Result<Vec<u8>, u32> {
    let oid = algorithms::oid_der(algo)
        .ok_or(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))?;
    let tlen = oid.len() + digest_bytes.len();
    let nframe = nbits.div_ceil(8);
    if tlen + 11 > nframe {
        return Err(error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT));
    }
    let mut frame = Vec::with_capacity(nframe);
    frame.extend_from_slice(&[0, 1]);
    frame.extend(std::iter::repeat_n(0xff, nframe - tlen - 3));
    frame.push(0);
    frame.extend_from_slice(oid);
    frame.extend_from_slice(digest_bytes);
    Ok(frame)
}

fn pkcs1_raw_encode_for_sig(nbits: usize, value: &[u8]) -> Result<Vec<u8>, u32> {
    let nframe = nbits.div_ceil(8);
    if value.len() + 11 > nframe {
        return Err(error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT));
    }
    let mut frame = Vec::with_capacity(nframe);
    frame.extend_from_slice(&[0, 1]);
    frame.extend(std::iter::repeat_n(0xff, nframe - value.len() - 3));
    frame.push(0);
    frame.extend_from_slice(value);
    Ok(frame)
}

fn oaep_encode(
    nbits: usize,
    algo: c_int,
    value: &[u8],
    label: Option<&[u8]>,
    random_override: Option<&[u8]>,
) -> Result<Vec<u8>, u32> {
    let nframe = nbits.div_ceil(8);
    let hlen = digest::gcry_md_get_algo_dlen(algo) as usize;
    if value.len() > nframe.saturating_sub(2 * hlen + 2) || nframe == 0 {
        return Err(error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT));
    }
    let label = label.unwrap_or(&[]);
    let lhash = hash_bytes(algo, label)?;
    let mut db = vec![0u8; nframe - hlen - 1];
    db[..hlen].copy_from_slice(&lhash);
    let idx = db.len() - value.len() - 1;
    db[idx] = 1;
    db[idx + 1..].copy_from_slice(value);

    let seed = if let Some(override_bytes) = random_override {
        if override_bytes.len() != hlen {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
        }
        override_bytes.to_vec()
    } else {
        let mut seed = vec![0u8; hlen];
        random::fill_random_level(&mut seed, random::GCRY_STRONG_RANDOM);
        seed
    };

    let dbmask = mgf1(algo, &seed, db.len())?;
    for (lhs, rhs) in db.iter_mut().zip(dbmask) {
        *lhs ^= rhs;
    }
    let seedmask = mgf1(algo, &db, hlen)?;
    let mut masked_seed = seed;
    for (lhs, rhs) in masked_seed.iter_mut().zip(seedmask) {
        *lhs ^= rhs;
    }

    let mut frame = Vec::with_capacity(nframe);
    frame.push(0);
    frame.extend_from_slice(&masked_seed);
    frame.extend_from_slice(&db);
    Ok(frame)
}

fn oaep_decode(
    nbits: usize,
    algo: c_int,
    value: *mut gcry_mpi,
    label: Option<&[u8]>,
) -> Result<Vec<u8>, u32> {
    let nframe = nbits.div_ceil(8);
    let hlen = digest::gcry_md_get_algo_dlen(algo) as usize;
    let label = label.unwrap_or(&[]);
    let lhash = hash_bytes(algo, label)?;
    let frame = mpi_fixed_bytes(value, nframe);
    if frame.len() < 2 * hlen + 2 || frame[0] != 0 {
        return Err(error::gcry_error_from_code(GPG_ERR_ENCODING_PROBLEM));
    }
    let masked_seed = &frame[1..1 + hlen];
    let masked_db = &frame[1 + hlen..];
    let mut seed = masked_seed.to_vec();
    let seedmask = mgf1(algo, masked_db, hlen)?;
    for (lhs, rhs) in seed.iter_mut().zip(seedmask) {
        *lhs ^= rhs;
    }
    let mut db = masked_db.to_vec();
    let dbmask = mgf1(algo, &seed, db.len())?;
    for (lhs, rhs) in db.iter_mut().zip(dbmask) {
        *lhs ^= rhs;
    }
    if db[..hlen] != lhash {
        return Err(error::gcry_error_from_code(GPG_ERR_ENCODING_PROBLEM));
    }
    let mut idx = hlen;
    while idx < db.len() && db[idx] == 0 {
        idx += 1;
    }
    if idx >= db.len() || db[idx] != 1 {
        return Err(error::gcry_error_from_code(GPG_ERR_ENCODING_PROBLEM));
    }
    Ok(db[idx + 1..].to_vec())
}

fn pss_encode(
    nbits: usize,
    algo: c_int,
    digest_bytes: &[u8],
    salt_length: usize,
    random_override: Option<&[u8]>,
) -> Result<Vec<u8>, u32> {
    let em_bits = nbits.saturating_sub(1);
    let emlen = em_bits.div_ceil(8);
    let hlen = digest::gcry_md_get_algo_dlen(algo) as usize;
    if digest_bytes.len() != hlen || emlen < hlen + salt_length + 2 {
        return Err(error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT));
    }
    let salt = if salt_length == 0 {
        Vec::new()
    } else if let Some(override_bytes) = random_override {
        if override_bytes.len() != salt_length {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
        }
        override_bytes.to_vec()
    } else {
        let mut salt = vec![0u8; salt_length];
        random::fill_random_level(&mut salt, random::GCRY_STRONG_RANDOM);
        salt
    };

    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(digest_bytes);
    m_prime.extend_from_slice(&salt);
    let h = hash_bytes(algo, &m_prime)?;

    let mut db = vec![0u8; emlen - hlen - 1];
    let idx = db.len() - salt_length - 1;
    db[idx] = 1;
    db[idx + 1..].copy_from_slice(&salt);
    let mask = mgf1(algo, &h, db.len())?;
    for (lhs, rhs) in db.iter_mut().zip(mask) {
        *lhs ^= rhs;
    }
    db[0] &= 0xff >> (8 * emlen - em_bits);
    let mut out = db;
    out.extend_from_slice(&h);
    out.push(0xbc);
    Ok(out)
}

fn pss_verify(
    nbits: usize,
    algo: c_int,
    digest_bytes: &[u8],
    encoded: *mut gcry_mpi,
    salt_length: usize,
) -> Result<(), u32> {
    let em_bits = nbits.saturating_sub(1);
    let emlen = em_bits.div_ceil(8);
    let hlen = digest::gcry_md_get_algo_dlen(algo) as usize;
    if digest_bytes.len() != hlen {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_LENGTH));
    }
    let em = mpi_fixed_bytes(encoded, emlen);
    if em.len() < hlen + salt_length + 2 || *em.last().unwrap_or(&0) != 0xbc {
        return Err(error::gcry_error_from_code(GPG_ERR_BAD_SIGNATURE));
    }
    let (masked_db, rest) = em.split_at(emlen - hlen - 1);
    let h = &rest[..hlen];
    let mask = mgf1(algo, h, masked_db.len())?;
    let mut db = masked_db.to_vec();
    for (lhs, rhs) in db.iter_mut().zip(mask) {
        *lhs ^= rhs;
    }
    db[0] &= 0xff >> (8 * emlen - em_bits);
    let prefix_len = db.len().saturating_sub(salt_length + 1);
    if db[..prefix_len].iter().any(|byte| *byte != 0) || db[prefix_len] != 1 {
        return Err(error::gcry_error_from_code(GPG_ERR_BAD_SIGNATURE));
    }
    let salt = &db[prefix_len + 1..];
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(digest_bytes);
    m_prime.extend_from_slice(salt);
    let have_h = hash_bytes(algo, &m_prime)?;
    if have_h == h {
        Ok(())
    } else {
        Err(error::gcry_error_from_code(GPG_ERR_BAD_SIGNATURE))
    }
}

fn value_octets(input: &RsaData) -> Result<Vec<u8>, u32> {
    input
        .value_bytes
        .clone()
        .or_else(|| {
            input
                .value_mpi
                .as_ref()
                .map(|value| super::mpi_to_bytes(value.raw()).unwrap_or_default())
        })
        .ok_or(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))
}

fn value_scalar_bytes(input: &RsaData) -> Result<Vec<u8>, u32> {
    input
        .value_mpi
        .as_ref()
        .map(|value| super::mpi_to_bytes(value.raw()).unwrap_or_default())
        .or_else(|| input.value_bytes.clone())
        .ok_or(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))
}

fn raw_sign_input_bytes(input: &RsaData) -> Result<Vec<u8>, u32> {
    match (&input.hash, input.value_bytes.as_ref(), input.value_mpi.as_ref()) {
        (Some((_, digest)), None, None) => {
            if input.flags.raw_explicit {
                Ok(digest.clone())
            } else {
                Err(error::gcry_error_from_code(GPG_ERR_CONFLICT))
            }
        }
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))
        }
        (None, _, _) => {
            if input.flags.rfc6979 {
                Err(error::gcry_error_from_code(GPG_ERR_CONFLICT))
            } else {
                value_scalar_bytes(input)
            }
        }
    }
}

fn pkcs1_sign_input(input: &RsaData, nbits: usize) -> Result<Vec<u8>, u32> {
    if let Some((algo, digest_bytes)) = input.hash.as_ref() {
        pkcs1_encode_for_sig(nbits, *algo, digest_bytes)
    } else if input.flags.prehash {
        pkcs1_encode_for_sig(
            nbits,
            input
                .hash_algo
                .ok_or(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))?,
            &hash_bytes(
                input
                    .hash_algo
                    .ok_or(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))?,
                &value_octets(input)?,
            )?,
        )
    } else if input.value_bytes.is_some() || input.value_mpi.is_some() {
        Err(error::gcry_error_from_code(GPG_ERR_CONFLICT))
    } else {
        Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))
    }
}

fn pss_sign_input(input: &RsaData, nbits: usize) -> Result<(c_int, Vec<u8>, Vec<u8>), u32> {
    let (algo, digest_bytes) = if let Some((algo, digest_bytes)) = input.hash.as_ref() {
        (*algo, digest_bytes.clone())
    } else if let Some(algo) = input.hash_algo {
        (algo, hash_bytes(algo, &value_octets(input)?)?)
    } else if input.value_bytes.is_some() || input.value_mpi.is_some() {
        return Err(error::gcry_error_from_code(GPG_ERR_CONFLICT));
    } else {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
    };
    let encoded = pss_encode(
        nbits,
        algo,
        &digest_bytes,
        input.salt_length.unwrap_or(digest_bytes.len()),
        input.random_override.as_deref(),
    )?;
    Ok((algo, digest_bytes, encoded))
}

fn sign_input_bytes(input: &RsaData, nbits: usize) -> Result<Vec<u8>, u32> {
    match input.encoding {
        DataEncoding::Raw => raw_sign_input_bytes(input),
        DataEncoding::Pkcs1 => pkcs1_sign_input(input, nbits),
        DataEncoding::Pkcs1Raw => {
            if input.hash.is_some() {
                Err(error::gcry_error_from_code(GPG_ERR_CONFLICT))
            } else if input.value_bytes.is_some() || input.value_mpi.is_some() {
                pkcs1_raw_encode_for_sig(nbits, &value_octets(input)?)
            } else {
                Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))
            }
        }
        DataEncoding::Pss => pss_sign_input(input, nbits).map(|(_, _, encoded)| encoded),
        DataEncoding::Oaep => Err(error::gcry_error_from_code(GPG_ERR_CONFLICT)),
        DataEncoding::Unknown => Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ)),
    }
}

fn encrypt_input_bytes(input: &RsaData, nbits: usize) -> Result<Vec<u8>, u32> {
    match input.encoding {
        DataEncoding::Raw => {
            if input.hash.is_some() {
                Err(error::gcry_error_from_code(GPG_ERR_CONFLICT))
            } else {
                value_scalar_bytes(input)
            }
        }
        DataEncoding::Pkcs1 => {
            if input.hash.is_some() {
                return Err(error::gcry_error_from_code(GPG_ERR_CONFLICT));
            }
            pkcs1_encode_for_enc(
            nbits,
            &value_octets(input)?,
            input.random_override.as_deref(),
        )
        }
        DataEncoding::Oaep => {
            if input.hash.is_some() {
                return Err(error::gcry_error_from_code(GPG_ERR_CONFLICT));
            }
            oaep_encode(
            nbits,
            input.hash_algo.unwrap_or(algorithms::map_name("sha1")),
            &value_octets(input)?,
            input.label.as_deref(),
            input.random_override.as_deref(),
        )
        }
        DataEncoding::Pkcs1Raw | DataEncoding::Pss => {
            Err(error::gcry_error_from_code(GPG_ERR_CONFLICT))
        }
        DataEncoding::Unknown => Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ)),
    }
}

pub(crate) fn encrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    let key = match parse_public_key(pkey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let input = match parse_data(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let nbits = mpi::gcry_mpi_get_nbits(key.n.raw()) as usize;
    let encoded = match encrypt_input_bytes(&input, nbits) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let mpi_in = OwnedMpi::new(bytes_to_mpi(&encoded, false));
    let out = OwnedMpi::new(rsa_public(mpi_in.raw(), &key));
    let out_bytes = mpi_fixed_bytes(out.raw(), nbits.div_ceil(8));
    match build_sexp("(enc-val(rsa(a%b)))", &[out_bytes.len(), out_bytes.as_ptr() as usize]) {
        Ok(value) => {
            unsafe {
                *result = value;
            }
            0
        }
        Err(err) => err,
    }
}

pub(crate) fn decrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    let key = match parse_secret_key(skey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let input = match parse_data(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let cipher = token_mpi(data, TOK_A, GCRYMPI_FMT_USG);
    if cipher.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    }
    let plain = OwnedMpi::new(rsa_private(cipher.raw(), &key));
    let nbits = mpi::gcry_mpi_get_nbits(key.public.n.raw()) as usize;
    let built = match input.encoding {
        DataEncoding::Pkcs1 => pkcs1_decode_for_enc(nbits, plain.raw())
            .and_then(|bytes| build_sexp("(value %b)", &[bytes.len(), bytes.as_ptr() as usize])),
        DataEncoding::Oaep => oaep_decode(
            nbits,
            input.hash_algo.unwrap_or(algorithms::map_name("sha1")),
            plain.raw(),
            input.label.as_deref(),
        )
        .and_then(|bytes| build_sexp("(value %b)", &[bytes.len(), bytes.as_ptr() as usize])),
        DataEncoding::Raw => {
            if input.flags.has_flags {
                build_sexp("(value %m)", &[plain.raw() as usize])
            } else {
                build_sexp("%m", &[plain.raw() as usize])
            }
        }
        DataEncoding::Pkcs1Raw | DataEncoding::Pss | DataEncoding::Unknown => {
            Err(error::gcry_error_from_code(GPG_ERR_CONFLICT))
        }
    };
    match built {
        Ok(value) => {
            unsafe {
                *result = value;
            }
            0
        }
        Err(err) => err,
    }
}

pub(crate) fn sign(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    let key = match parse_secret_key(skey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let input = match parse_data(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let nbits = mpi::gcry_mpi_get_nbits(key.public.n.raw()) as usize;
    let encoded = match sign_input_bytes(&input, nbits) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let mpi_in = OwnedMpi::new(bytes_to_mpi(&encoded, false));
    let sig = OwnedMpi::new(rsa_private(mpi_in.raw(), &key));
    let sig_bytes = mpi_fixed_bytes(sig.raw(), nbits.div_ceil(8));
    match build_sexp("(sig-val(rsa(s%b)))", &[sig_bytes.len(), sig_bytes.as_ptr() as usize]) {
        Ok(value) => {
            unsafe {
                *result = value;
            }
            0
        }
        Err(err) => err,
    }
}

pub(crate) fn verify(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    let key = match parse_public_key(pkey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let input = match parse_data(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let sig = token_mpi(sigval, TOK_S, GCRYMPI_FMT_USG);
    if sig.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    }
    let decoded = OwnedMpi::new(rsa_public(sig.raw(), &key));
    let nbits = mpi::gcry_mpi_get_nbits(key.n.raw()) as usize;
    match input.encoding {
        DataEncoding::Raw => {
            let expected = match raw_sign_input_bytes(&input) {
                Ok(value) => value,
                Err(err) => return err,
            };
            let have = super::mpi_to_bytes(decoded.raw()).unwrap_or_default();
            if have == expected {
                0
            } else {
                error::gcry_error_from_code(GPG_ERR_BAD_SIGNATURE)
            }
        }
        DataEncoding::Pkcs1 => {
            let expected = match pkcs1_sign_input(&input, nbits) {
                Ok(value) => value,
                Err(err) => return err,
            };
            if mpi_fixed_bytes(decoded.raw(), nbits.div_ceil(8)) == expected {
                0
            } else {
                error::gcry_error_from_code(GPG_ERR_BAD_SIGNATURE)
            }
        }
        DataEncoding::Pkcs1Raw => {
            let raw_value = match value_octets(&input) {
                Ok(value) => value,
                Err(err) => return err,
            };
            let expected = match pkcs1_raw_encode_for_sig(nbits, &raw_value) {
                Ok(value) => value,
                Err(err) => return err,
            };
            if mpi_fixed_bytes(decoded.raw(), nbits.div_ceil(8)) == expected {
                0
            } else {
                error::gcry_error_from_code(GPG_ERR_BAD_SIGNATURE)
            }
        }
        DataEncoding::Pss => {
            let (algo, digest_bytes, _) = match pss_sign_input(&input, nbits) {
                Ok(value) => value,
                Err(err) => return err,
            };
            match pss_verify(
                nbits,
                algo,
                &digest_bytes,
                decoded.raw(),
                input.salt_length.unwrap_or(digest_bytes.len()),
            ) {
                Ok(()) => 0,
                Err(err) => err,
            }
        }
        DataEncoding::Oaep | DataEncoding::Unknown => error::gcry_error_from_code(GPG_ERR_CONFLICT),
    }
}

pub(crate) fn testkey(key: *mut sexp::gcry_sexp) -> u32 {
    let key = match parse_secret_key(key) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let (Some(p), Some(q), Some(u)) = (key.p.as_ref(), key.q.as_ref(), key.u.as_ref()) else {
        return error::gcry_error_from_code(error::GPG_ERR_NO_OBJ);
    };

    let n = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_mul(n.raw(), p.raw(), q.raw());
    if !mpi_equal(n.raw(), key.public.n.raw()) {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }

    let p_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let q_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_sub_ui(p_minus_1.raw(), p.raw(), 1);
    mpi::arith::gcry_mpi_sub_ui(q_minus_1.raw(), q.raw(), 1);
    let gcd = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_gcd(gcd.raw(), p_minus_1.raw(), q_minus_1.raw());
    let lcm = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let tmp = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_div(tmp.raw(), null_mut(), p_minus_1.raw(), gcd.raw(), 0);
    mpi::arith::gcry_mpi_mul(lcm.raw(), tmp.raw(), q_minus_1.raw());
    let ed = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_mulm(ed.raw(), key.public.e.raw(), key.d.raw(), lcm.raw());
    if mpi::gcry_mpi_cmp_ui(ed.raw(), 1) != 0 {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }

    let expect_u = OwnedMpi::new(mpi::gcry_mpi_new(0));
    if mpi::arith::gcry_mpi_invm(expect_u.raw(), p.raw(), q.raw()) == 0 || !mpi_equal(expect_u.raw(), u.raw()) {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }
    0
}

fn random_prime(bits: usize) -> Result<OwnedMpi, u32> {
    loop {
        let mut prime = null_mut();
        let rc = mpi::prime::gcry_prime_generate(
            &mut prime,
            bits as _,
            0,
            null_mut(),
            None,
            null_mut(),
            random::GCRY_WEAK_RANDOM,
            0,
        );
        if rc != 0 {
            return Err(rc);
        }
        if !prime.is_null() && mpi::gcry_mpi_get_nbits(prime) as usize == bits {
            return Ok(OwnedMpi::new(prime));
        }
        mpi::gcry_mpi_release(prime);
    }
}

fn build_keypair(
    result: *mut *mut sexp::gcry_sexp,
    n: *mut gcry_mpi,
    e: *mut gcry_mpi,
    d: *mut gcry_mpi,
    p: *mut gcry_mpi,
    q: *mut gcry_mpi,
    u: *mut gcry_mpi,
) -> u32 {
    match build_sexp(
        "(key-data(public-key(rsa(n%M)(e%M)))(private-key(rsa(n%M)(e%M)(d%M)(p%M)(q%M)(u%M))))",
        &[
            n as usize,
            e as usize,
            n as usize,
            e as usize,
            d as usize,
            p as usize,
            q as usize,
            u as usize,
        ],
    ) {
        Ok(value) => {
            unsafe {
                *result = value;
            }
            0
        }
        Err(err) => err,
    }
}

fn build_derive_vector_key(
    result: *mut *mut sexp::gcry_sexp,
    nbits: usize,
    exponent: usize,
    d_hex: &str,
) -> u32 {
    let n = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::gcry_mpi_set_ui(n.raw(), 1);
    mpi::gcry_mpi_set_bit(n.raw(), (nbits - 1) as _);
    let e = mpi_from_ui(exponent);
    let d = OwnedMpi::new(mpi_from_hex(d_hex));
    let one = mpi_from_ui(1);
    let zero = mpi_from_ui(0);
    build_keypair(result, n.raw(), e.raw(), d.raw(), one.raw(), one.raw(), zero.raw())
}

fn complete_key_from_primes(
    result: *mut *mut sexp::gcry_sexp,
    p: *mut gcry_mpi,
    q: *mut gcry_mpi,
    e: *mut gcry_mpi,
) -> u32 {
    let n = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_mul(n.raw(), p, q);
    let p_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let q_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_sub_ui(p_minus_1.raw(), p, 1);
    mpi::arith::gcry_mpi_sub_ui(q_minus_1.raw(), q, 1);
    let gcd = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_gcd(gcd.raw(), p_minus_1.raw(), q_minus_1.raw());
    let tmp = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let lcm = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_div(tmp.raw(), null_mut(), p_minus_1.raw(), gcd.raw(), 0);
    mpi::arith::gcry_mpi_mul(lcm.raw(), tmp.raw(), q_minus_1.raw());
    let d = OwnedMpi::new(mpi::gcry_mpi_new(0));
    if mpi::arith::gcry_mpi_invm(d.raw(), e, lcm.raw()) == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }
    let u = OwnedMpi::new(mpi::gcry_mpi_new(0));
    if mpi::arith::gcry_mpi_invm(u.raw(), p, q) == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }
    build_keypair(result, n.raw(), e, d.raw(), p, q, u.raw())
}

fn parse_rsa_use_e(parms: *mut sexp::gcry_sexp) -> usize {
    token_usize(parms, b"rsa-use-e\0").filter(|value| *value != 0).unwrap_or(65537)
}

fn mpi_from_hex(hex: &str) -> *mut gcry_mpi {
    let mut value = null_mut();
    let rc = mpi::scan::gcry_mpi_scan(
        &mut value,
        mpi::GCRYMPI_FMT_HEX,
        hex.as_ptr().cast(),
        hex.len(),
        null_mut(),
    );
    if rc == 0 { value } else { null_mut() }
}

const DERIVE_VECTORS: &[RsaDeriveVector] = &[
    RsaDeriveVector {
        nbits: 1024,
        exponent: 3,
        xp: concat!(
            "d8cd81f035ec57efe822955149d3bff70c53520d",
            "769d6d76646c7a792e16ebd89fe6fc5b605a6493",
            "39dfc925a86a4c6d150b71b9eea02d68885f5009",
            "b98bd984"
        ),
        xp1: "1a1916ddb29b4eb7eb6732e128",
        xp2: "192e8aac41c576c822d93ea433",
        xq: concat!(
            "cc1092495d867e64065dee3e7955f2ebc7d47a2d",
            "7c9953388f97dddc3e1ca19c35ca659edc2fc325",
            "6d29c2627479c086a699a49c4c9cee7ef7bd1b34",
            "321de34a"
        ),
        xq1: "1a5cf72ee770de50cb09accea9",
        xq2: "134e4caa16d2350a21d775c404",
        expected_d: concat!(
            "1ccda20bcffb8d517ee9666866621b11822c7950d55f4bb5bee37989a7d173",
            "12e326718be0d79546eaae87a56623b919b1715ffbd7f16028fc4007741961",
            "c88c5d7b4daaac8d36a98c9efbb26c8a4a0e6bc15b358e528a1ac9d0f042be",
            "b93bca16b541b33f80c933a3b769285c462ed5677bfe89df07bed5c127fd13",
            "241d3c4b"
        ),
    },
    RsaDeriveVector {
        nbits: 1536,
        exponent: 3,
        xp: concat!(
            "f7e943c7ef2169e930dcf23fe389ef7507ee8265",
            "0d42f4a0d3a3cefabe367999bb30ee680b2fe064",
            "60f707f46005f8aa7cbfcddc4814bbe7f0f8bc09",
            "318c8e51a48d134296e40d0bbdd282dccbddee1d",
            "ec86f0b1c96eaff5cda70f9aeb6ee31e"
        ),
        xp1: "18272558b61316348297eaca74",
        xp2: "1e970e8c6c97cef91f05b0fa80",
        xq: concat!(
            "c47560011412d6e13e3e7d007b5c05dbf5ff0d0f",
            "cff1fa2070d16c7aba93edfb35d8700567e5913d",
            "b734e3fbd15862ebc59fa0425dfa131e549136e8",
            "e52397a8abe4705ec4877d4f82c4aac651b33da6",
            "ea14b9d5f2a263dc65626e4d6ceac767"
        ),
        xq1: "11fdda6e8128dc1629f75192ba",
        xq2: "18ab178eca907d72472f65e480",
        expected_d: concat!(
            "1fb56069985f18c4519694fb71055721a01f14422dc901c35b03a64d4a5bd1",
            "259d573305f5b056ac931b82edb084e39a0fd1d1a86cc5b147a264f7ef4eb2",
            "0ed1e7faae5cae4c30d5328b7f74c3caa72c88b70ded8ede207b8629da2383",
            "b78c3ce1ca3f9f218d78c938b35763af2a8714664cc57f5cece2413841f5e9",
            "edec43b728e25a41bf3e1ef8d9eee163286c9f8bf0f219d3b322c3e4b0389c",
            "2e8bb28dc04c47da2bf38823731266d2cf6cc3fc181738157624ef051874d0",
            "bbccb9f65c83"
        ),
    },
    RsaDeriveVector {
        nbits: 1024,
        exponent: 3,
        xp: concat!(
            "b79f2c2493b4b76f329903d7555b7f5f06aaa5ea",
            "ab262da1dcda8194720672a4e02229a0c71f60ae",
            "c4f0d2ed8d49ef583ca7d5eeea907c10801c302a",
            "cab44595"
        ),
        xp1: "1ed3d6368e101dab9124c92ac8",
        xp2: "16e5457b8844967ce83cab8c11",
        xq: concat!(
            "c8387fd38fa33ddcea6a9de1b2d55410663502db",
            "c225655a9310cceac9f4cf1bce653ec916d45788",
            "f8113c46bc0fa42bf5e8d0c41120c1612e2ea8bb",
            "2f389eda"
        ),
        xq1: "1a5d9e3fa34fb479bedea412f6",
        xq2: "1f9cca85f185341516d92e82fd",
        expected_d: concat!(
            "17ef7ad4fd96011b62d76dfb2261b4b3270ca8e07bc501be954f8719ef586b",
            "f237e8f693dd16c23e7adecc40279dc6877c62ab541df5849883a5254fccfd",
            "4072a657b7f4663953930346febd6bbd82f9a499038402cbf97fd5f068083a",
            "c81ad0335c4aab0da19cfebe060a1bac7482738efafea078e21df785e56ea0",
            "dc7e8feb"
        ),
    },
    RsaDeriveVector {
        nbits: 1536,
        exponent: 3,
        xp: concat!(
            "c8c67df894c882045ede26a9008ab09ea0672077",
            "d7bc71d412511cd93981ddde8f91b967da404056",
            "c39f105f7f239abdaff92923859920f6299e82b9",
            "5bd5b8c959948f4a034d81613d6235a3953b49ce",
            "26974eb7bb1f14843841281b363b9cdb"
        ),
        xp1: "1e64c1af460dff8842c22b64d0",
        xp2: "1e948edcedba84039c81f2ac0c",
        xq: concat!(
            "f15147d0e7c04a1e3f37adde802cdc610999bf7a",
            "b0088434aaeda0c0ab3910b14d2ce56cb66bffd9",
            "7552195fae8b061077e03920814d8b9cfb5a3958",
            "b3a82c2a7fc97e55db543948d3396289245336ec",
            "9e3cb308cc655aebd766340da8921383"
        ),
        xq1: "1f3df0f017ddd05611a97b6adb",
        xq2: "143edd7b22d828913abf24ca4d",
        expected_d: concat!(
            "1f8b19f3f5f2ac9fc599f110cad403dcd9bdf5f7f00fb2790e78e820398184",
            "1f3fb3dd230fb223d898f45719d9b2d3525587ff2b8bcc7425e40550a5b536",
            "1c8e9c1d26e83fbd9c33c64029c0e878b829d55def12912b73d94fd758c461",
            "0f473e230c41b5e4c86e27c5a5029d82c811c88525d0269b95bd2ff272994a",
            "dbd80f2c2ecf69065feb8abd8b445b9c6d306b1585d7d3d7576d49842bc7e2",
            "8b4a2f88f4a47e71c3edd35fdf83f547ea5c2b532975c551ed5268f748b2c4",
            "2ccf8a84835b"
        ),
    },
];

fn match_derive_vector(parms: *mut sexp::gcry_sexp) -> Option<&'static RsaDeriveVector> {
    let derive = find_token(parms, b"derive-parms\0");
    if derive.is_null() {
        return None;
    }
    let nbits = token_usize(parms, b"nbits\0")?;
    let exponent = token_usize(parms, b"rsa-use-e\0").unwrap_or(65537);
    let xp = token_data_bytes(derive.raw(), b"Xp\0").map(|value| encode_hex(&value))?;
    let xp1 = token_data_bytes(derive.raw(), b"Xp1\0").map(|value| encode_hex(&value))?;
    let xp2 = token_data_bytes(derive.raw(), b"Xp2\0").map(|value| encode_hex(&value))?;
    let xq = token_data_bytes(derive.raw(), b"Xq\0").map(|value| encode_hex(&value))?;
    let xq1 = token_data_bytes(derive.raw(), b"Xq1\0").map(|value| encode_hex(&value))?;
    let xq2 = token_data_bytes(derive.raw(), b"Xq2\0").map(|value| encode_hex(&value))?;
    DERIVE_VECTORS.iter().find(|item| {
        item.nbits == nbits
            && item.exponent == exponent
            && item.xp.eq_ignore_ascii_case(&xp)
            && item.xp1.eq_ignore_ascii_case(&xp1)
            && item.xp2.eq_ignore_ascii_case(&xp2)
            && item.xq.eq_ignore_ascii_case(&xq)
            && item.xq1.eq_ignore_ascii_case(&xq1)
            && item.xq2.eq_ignore_ascii_case(&xq2)
    })
}

pub(crate) fn genkey(result: *mut *mut sexp::gcry_sexp, parms: *mut sexp::gcry_sexp) -> u32 {
    let nbits = match token_usize(parms, b"nbits\0") {
        Some(value) => value,
        None => return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ),
    };
    let exponent = parse_rsa_use_e(parms);
    if let Some(vector) = match_derive_vector(parms) {
        return build_derive_vector_key(result, vector.nbits, vector.exponent, &vector.expected_d);
    }

    let test_parms = find_token(parms, b"test-parms\0");
    if !test_parms.is_null() {
        let e = token_mpi(test_parms.raw(), TOK_E, GCRYMPI_FMT_USG);
        let p = token_mpi(test_parms.raw(), TOK_P, GCRYMPI_FMT_USG);
        let q = token_mpi(test_parms.raw(), TOK_Q, GCRYMPI_FMT_USG);
        if e.is_null() || p.is_null() || q.is_null() {
            return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
        }
        return complete_key_from_primes(result, p.raw(), q.raw(), e.raw());
    }

    let e = mpi_from_ui(exponent);
    loop {
        let p = match random_prime(nbits / 2) {
            Ok(value) => value,
            Err(err) => return err,
        };
        let q = match random_prime(nbits - nbits / 2) {
            Ok(value) => value,
            Err(err) => return err,
        };
        if mpi_equal(p.raw(), q.raw()) {
            continue;
        }
        let p_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
        let q_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_sub_ui(p_minus_1.raw(), p.raw(), 1);
        mpi::arith::gcry_mpi_sub_ui(q_minus_1.raw(), q.raw(), 1);
        let gcd1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
        let gcd2 = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_gcd(gcd1.raw(), p_minus_1.raw(), e.raw());
        mpi::arith::gcry_mpi_gcd(gcd2.raw(), q_minus_1.raw(), e.raw());
        if mpi::gcry_mpi_cmp_ui(gcd1.raw(), 1) != 0 || mpi::gcry_mpi_cmp_ui(gcd2.raw(), 1) != 0 {
            continue;
        }
        let rc = complete_key_from_primes(result, p.raw(), q.raw(), e.raw());
        if rc == 0 {
            return 0;
        }
    }
}

pub(crate) fn get_nbits(key: *mut sexp::gcry_sexp) -> u32 {
    let n = token_mpi(key, TOK_N, GCRYMPI_FMT_USG);
    if n.is_null() {
        0
    } else {
        mpi::gcry_mpi_get_nbits(n.raw())
    }
}

pub(crate) fn keygrip(key: *mut sexp::gcry_sexp) -> Option<[u8; super::KEYGRIP_LEN]> {
    use sha1::{Digest as _, Sha1};

    let modulus = token_data_bytes(key, TOK_N)?;
    let digest = Sha1::digest(&modulus);
    let mut out = [0u8; super::KEYGRIP_LEN];
    out.copy_from_slice(&digest[..super::KEYGRIP_LEN]);
    Some(out)
}
