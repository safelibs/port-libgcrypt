use std::ffi::{c_char, c_int, c_uint, c_void};
use std::ptr::null_mut;

use crate::context;
use crate::digest::algorithms;
use crate::error;
use crate::mpi::{self, Mpz};
use crate::os_rng;
use crate::sexp;

use super::encoding;

pub(crate) const NAME: &[u8] = b"ecc\0";

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    matches!(algo, 18 | 301 | 302 | 303)
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}

struct CurveListEntry {
    name: &'static str,
    c_name: &'static [u8],
    bits: u32,
}

const CURVE_LIST: &[CurveListEntry] = &[
    CurveListEntry { name: "NIST P-192", c_name: b"NIST P-192\0", bits: 192 },
    CurveListEntry { name: "NIST P-224", c_name: b"NIST P-224\0", bits: 224 },
    CurveListEntry { name: "NIST P-256", c_name: b"NIST P-256\0", bits: 256 },
    CurveListEntry { name: "NIST P-384", c_name: b"NIST P-384\0", bits: 384 },
    CurveListEntry { name: "NIST P-521", c_name: b"NIST P-521\0", bits: 521 },
    CurveListEntry { name: "brainpoolP160r1", c_name: b"brainpoolP160r1\0", bits: 160 },
    CurveListEntry { name: "brainpoolP192r1", c_name: b"brainpoolP192r1\0", bits: 192 },
    CurveListEntry { name: "brainpoolP224r1", c_name: b"brainpoolP224r1\0", bits: 224 },
    CurveListEntry { name: "brainpoolP256r1", c_name: b"brainpoolP256r1\0", bits: 256 },
    CurveListEntry { name: "brainpoolP320r1", c_name: b"brainpoolP320r1\0", bits: 320 },
    CurveListEntry { name: "brainpoolP384r1", c_name: b"brainpoolP384r1\0", bits: 384 },
    CurveListEntry { name: "brainpoolP512r1", c_name: b"brainpoolP512r1\0", bits: 512 },
    CurveListEntry { name: "GOST2001-test", c_name: b"GOST2001-test\0", bits: 256 },
    CurveListEntry { name: "GOST2001-CryptoPro-A", c_name: b"GOST2001-CryptoPro-A\0", bits: 256 },
    CurveListEntry { name: "GOST2001-CryptoPro-B", c_name: b"GOST2001-CryptoPro-B\0", bits: 256 },
    CurveListEntry { name: "GOST2001-CryptoPro-C", c_name: b"GOST2001-CryptoPro-C\0", bits: 256 },
    CurveListEntry { name: "GOST2012-256-A", c_name: b"GOST2012-256-A\0", bits: 256 },
    CurveListEntry { name: "GOST2012-512-test", c_name: b"GOST2012-512-test\0", bits: 512 },
    CurveListEntry { name: "GOST2012-512-tc26-A", c_name: b"GOST2012-512-tc26-A\0", bits: 512 },
    CurveListEntry { name: "GOST2012-512-tc26-B", c_name: b"GOST2012-512-tc26-B\0", bits: 512 },
    CurveListEntry { name: "GOST2012-512-tc26-C", c_name: b"GOST2012-512-tc26-C\0", bits: 512 },
    CurveListEntry { name: "secp256k1", c_name: b"secp256k1\0", bits: 256 },
    CurveListEntry { name: "sm2p256v1", c_name: b"sm2p256v1\0", bits: 256 },
    CurveListEntry { name: "Curve25519", c_name: b"Curve25519\0", bits: 255 },
    CurveListEntry { name: "Ed25519", c_name: b"Ed25519\0", bits: 255 },
    CurveListEntry { name: "X448", c_name: b"X448\0", bits: 448 },
    CurveListEntry { name: "Ed448", c_name: b"Ed448\0", bits: 448 },
];

fn canonical_curve_name(name: &str) -> Option<&'static str> {
    if let Some(curve) = mpi::ec::curve_by_name(name) {
        return Some(curve.name);
    }
    let lower = name.to_ascii_lowercase();
    let mapped = match lower.as_str() {
        "brainpoolp160r1" | "1.3.36.3.3.2.8.1.1.1" => "brainpoolP160r1",
        "brainpoolp192r1" | "1.3.36.3.3.2.8.1.1.3" => "brainpoolP192r1",
        "brainpoolp224r1" | "1.3.36.3.3.2.8.1.1.5" => "brainpoolP224r1",
        "brainpoolp256r1" | "1.3.36.3.3.2.8.1.1.7" => "brainpoolP256r1",
        "brainpoolp320r1" | "1.3.36.3.3.2.8.1.1.9" => "brainpoolP320r1",
        "brainpoolp384r1" | "1.3.36.3.3.2.8.1.1.11" => "brainpoolP384r1",
        "brainpoolp512r1" | "1.3.36.3.3.2.8.1.1.13" => "brainpoolP512r1",
        "ed448" | "1.3.101.113" => "Ed448",
        "gost2012-512-test" | "gost2012-test" => "GOST2012-512-test",
        "1.2.643.7.1.2.1.2.0" => "GOST2012-512-test",
        "gost2012-512-tc26-a" | "gost2012-tc26-a" | "1.2.643.7.1.2.1.2.1" => "GOST2012-512-tc26-A",
        "gost2012-512-tc26-b" | "gost2012-tc26-b" | "1.2.643.7.1.2.1.2.2" => "GOST2012-512-tc26-B",
        "gost2012-512-tc26-c" | "1.2.643.7.1.2.1.2.3" => "GOST2012-512-tc26-C",
        "gost2012-256-tc26-a" | "1.2.643.7.1.2.1.1.1" => "GOST2012-256-A",
        "gost2001-test" | "1.2.643.2.2.35.0" => "GOST2001-test",
        "gost2001-cryptopro-a" | "1.2.643.2.2.35.1" | "1.2.643.7.1.2.1.1.2" => {
            "GOST2001-CryptoPro-A"
        }
        "gost2001-cryptopro-b" | "1.2.643.2.2.35.2" | "gost2012-256-tc26-b" | "1.2.643.7.1.2.1.1.3" => {
            "GOST2001-CryptoPro-B"
        }
        "gost2001-cryptopro-c" | "1.2.643.2.2.35.3" | "gost2012-256-tc26-c" | "1.2.643.7.1.2.1.1.4"
        | "gost2012-256-tc26-d" => "GOST2001-CryptoPro-C",
        "gost2001-cryptopro-xcha" | "1.2.643.2.2.36.0" => "GOST2001-CryptoPro-A",
        "gost2001-cryptopro-xchb" | "1.2.643.2.2.36.1" => "GOST2001-CryptoPro-C",
        "sm2p256v1" | "1.2.156.10197.1.301" => "sm2p256v1",
        _ => return None,
    };
    Some(mapped)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_get_curve(
    key: *mut sexp::gcry_sexp,
    iterator: c_int,
    nbits: *mut c_uint,
) -> *const c_char {
    if key.is_null() {
        if iterator < 0 {
            return std::ptr::null();
        }
        let Some(entry) = CURVE_LIST.get(iterator as usize) else {
            return std::ptr::null();
        };
        if !nbits.is_null() {
            unsafe { *nbits = entry.bits };
        }
        return entry.c_name.as_ptr().cast();
    }
    if iterator > 0 {
        return std::ptr::null();
    }
    let name = encoding::token_string(key, "curve")
        .and_then(|name| canonical_curve_name(&name).map(str::to_string))
        .or_else(|| {
            let p = encoding::token_mpz(key, "p")?;
            if p.cmp(&Mpz::from_hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")) == 0 {
                Some("NIST P-256".to_string())
            } else if p.cmp(&Mpz::from_hex("E95E4A5F737059DC60DFC7AD95B3D8139515620F")) == 0 {
                Some("brainpoolP160r1".to_string())
            } else {
                None
            }
        });
    let Some(name) = name else {
        return std::ptr::null();
    };
    let bits = CURVE_LIST
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(&name))
        .map(|entry| entry.bits)
        .unwrap_or(0);
    if !nbits.is_null() {
        unsafe { *nbits = bits };
    }
    CURVE_LIST
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(&name))
        .map(|entry| entry.c_name.as_ptr().cast())
        .unwrap_or(std::ptr::null())
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_get_param(algo: c_int, name: *const c_char) -> *mut sexp::gcry_sexp {
    if !owns_algorithm(algo) || name.is_null() {
        return null_mut();
    }
    let name = unsafe { std::ffi::CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned();
    let Some(canonical) = canonical_curve_name(&name) else {
        return null_mut();
    };
    let Some(curve) = mpi::ec::curve_by_name(canonical) else {
        return null_mut();
    };
    let Some(p) = mpi::ec::curve_param_bytes(&curve, "p") else {
        return null_mut();
    };
    let Some(a) = mpi::ec::curve_param_bytes(&curve, "a") else {
        return null_mut();
    };
    let Some(b) = mpi::ec::curve_param_bytes(&curve, "b") else {
        return null_mut();
    };
    let Some(g) = mpi::ec::curve_param_bytes(&curve, "g") else {
        return null_mut();
    };
    let Some(n) = mpi::ec::curve_param_bytes(&curve, "n") else {
        return null_mut();
    };
    let Some(h) = mpi::ec::curve_param_bytes(&curve, "h") else {
        return null_mut();
    };
    let text = format!(
        "(public-key(ecc(p {})(a {})(b {})(g {})(n {})(h {})))",
        encoding::hex_atom(&p),
        encoding::hex_atom(&a),
        encoding::hex_atom(&b),
        encoding::hex_atom(&g),
        encoding::hex_atom(&n),
        encoding::hex_atom(&h)
    );
    encoding::build_sexp(&text).unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pubkey_get_sexp(
    result: *mut *mut sexp::gcry_sexp,
    mode: c_int,
    ctx: *mut c_void,
) -> u32 {
    if result.is_null() {
        return encoding::err(error::GPG_ERR_INV_ARG);
    }
    unsafe { *result = null_mut() };
    let Some(ctx) = (unsafe { context::ec_ref(ctx) }) else {
        return encoding::err(error::GPG_ERR_BAD_CRYPT_CTX);
    };
    let curve = mpi::ec::context_curve(ctx);
    let q = mpi::ec::context_q(ctx);
    let d = mpi::ec::context_d(ctx);
    if mode == 2 && d.is_none() {
        return encoding::err(error::GPG_ERR_NO_SECKEY);
    }
    if q.is_none() && d.is_none() {
        return encoding::err(error::GPG_ERR_BAD_CRYPT_CTX);
    }
    let q = q
        .cloned()
        .or_else(|| d.map(|d| mpi::ec::scalar_mul_secret(curve, d, &mpi::ec::base_point(curve))));
    let Some(q) = q else {
        return encoding::err(error::GPG_ERR_BAD_CRYPT_CTX);
    };
    let q_bytes = mpi::ec::encode_point(curve, &q);
    let text = if mode == 2 || (mode == 0 && d.is_some()) {
        format!(
            "(private-key (ecc (curve {})(q {})(d {})))",
            encoding::string_atom(curve.name),
            encoding::hex_atom(&q_bytes),
            encoding::hex_atom(&d.unwrap().to_be())
        )
    } else {
        format!(
            "(public-key (ecc (curve {})(q {})))",
            encoding::string_atom(curve.name),
            encoding::hex_atom(&q_bytes)
        )
    };
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_ecc_get_algo_keylen(curveid: c_int) -> c_uint {
    match curveid {
        1 => 32,
        2 => 56,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_ecc_mul_point(
    curveid: c_int,
    result: *mut u8,
    scalar: *const u8,
    point: *const u8,
) -> u32 {
    if result.is_null() || scalar.is_null() || point.is_null() {
        return encoding::err(error::GPG_ERR_INV_ARG);
    }
    let (name, len) = match curveid {
        1 => ("Curve25519", 32),
        2 => ("X448", 56),
        _ => return encoding::err(error::GPG_ERR_NOT_SUPPORTED),
    };
    let Some(curve) = mpi::ec::curve_by_name(name) else {
        return encoding::err(error::GPG_ERR_NOT_SUPPORTED);
    };
    let scalar = unsafe { std::slice::from_raw_parts(scalar, len) };
    let point = unsafe { std::slice::from_raw_parts(point, len) };
    let q = mpi::ec::scalar_mul_secret(
        &curve,
        &Mpz::from_le(scalar),
        &mpi::ec::EcPoint::montgomery(Mpz::from_le(point)),
    );
    let out = q.x.as_ref().unwrap().to_le_padded(len);
    unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), result, len) };
    0
}

pub(crate) fn encrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    let curve_name = encoding::token_string(pkey, "curve").unwrap_or_default();
    let Some(curve) = mpi::ec::curve_by_name(&curve_name) else {
        return encoding::err(error::GPG_ERR_INV_NAME);
    };
    let q_bytes = encoding::token_data(pkey, "q").unwrap_or_else(|| {
        encoding::token_mpz(pkey, "q")
            .map(|value| value.to_be())
            .unwrap_or_default()
    });
    let peer = if q_bytes.first() == Some(&0x40) {
        Mpz::from_le(&q_bytes[1..])
    } else {
        Mpz::from_le(&q_bytes)
    };
    let mut scalar = encoding::data_value(data).unwrap_or_default();
    if curve.name == "Curve25519" {
        scalar.reverse();
    }
    let q = mpi::ec::scalar_mul_secret(
        &curve,
        &Mpz::from_le(&scalar),
        &mpi::ec::EcPoint::montgomery(peer),
    );
    let mut secret = q.x.as_ref().unwrap().to_le_padded(curve.field_bytes);
    if curve.name == "Curve25519" {
        let mut with_prefix = vec![0x40];
        with_prefix.extend_from_slice(&secret);
        secret = with_prefix;
    }
    let text = format!("(enc-val (ecdh (s {})))", encoding::hex_atom(&secret));
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
}

struct EccKey {
    curve: mpi::ec::Curve,
    q: Option<mpi::ec::EcPoint>,
    d: Option<Mpz>,
}

fn parse_key(key: *mut sexp::gcry_sexp) -> Result<EccKey, u32> {
    let curve_name = encoding::token_string(key, "curve").ok_or(error::GPG_ERR_INV_OBJ)?;
    let curve = mpi::ec::curve_by_name(&curve_name).ok_or(error::GPG_ERR_INV_NAME)?;
    let q = encoding::token_bytes_from_mpi(key, "q")
        .and_then(|bytes| mpi::ec::decode_point(&curve, &bytes));
    let d = encoding::token_mpz(key, "d");
    let q = q.or_else(|| {
        d.as_ref()
            .map(|d| mpi::ec::scalar_mul_secret(&curve, d, &mpi::ec::base_point(&curve)))
    });
    Ok(EccKey { curve, q, d })
}

fn point_matches(left: &mpi::ec::EcPoint, right: &mpi::ec::EcPoint) -> bool {
    match (&left.x, &right.x, &left.y, &right.y) {
        (Some(lx), Some(rx), Some(ly), Some(ry)) => lx.cmp(rx) == 0 && ly.cmp(ry) == 0,
        (Some(lx), Some(rx), None, None) => lx.cmp(rx) == 0,
        (None, None, _, _) => true,
        _ => false,
    }
}

pub(crate) fn testkey(key: *mut sexp::gcry_sexp) -> u32 {
    let parsed = match parse_key(key) {
        Ok(key) => key,
        Err(err) => return encoding::err(err),
    };
    let Some(d) = parsed.d.as_ref() else {
        return encoding::err(error::GPG_ERR_NO_SECKEY);
    };
    let Some(q) = parsed.q.as_ref() else {
        return encoding::err(error::GPG_ERR_BAD_SECKEY);
    };
    let scalar = if parsed.curve.name == "Ed25519" && encoding::has_flag(key, "eddsa") {
        let Some(seed) = ed25519_secret_seed(key) else {
            return encoding::err(error::GPG_ERR_NO_SECKEY);
        };
        let Some((scalar, _)) = ed25519_expanded(&seed) else {
            return encoding::err(error::GPG_ERR_DIGEST_ALGO);
        };
        scalar
    } else if parsed.curve.name == "Ed448" && encoding::has_flag(key, "eddsa") {
        let Some(seed) = ed448_secret_seed(key) else {
            return encoding::err(error::GPG_ERR_NO_SECKEY);
        };
        let Some((scalar, _)) = ed448_expanded(&seed) else {
            return encoding::err(error::GPG_ERR_DIGEST_ALGO);
        };
        scalar
    } else {
        d.clone()
    };
    let expected = mpi::ec::scalar_mul_secret(
        &parsed.curve,
        &scalar,
        &mpi::ec::base_point(&parsed.curve),
    );
    if point_matches(q, &expected) {
        0
    } else {
        encoding::err(error::GPG_ERR_BAD_SECKEY)
    }
}

fn bits2int(hash: &[u8], order: &Mpz) -> Mpz {
    let qbits = order.bits();
    let mut v = Mpz::from_be(hash);
    let hbits = hash.len() * 8;
    if hbits > qbits {
        v = v.shr(hbits - qbits);
    }
    v
}

fn data_digest(data: *mut sexp::gcry_sexp, order: &Mpz) -> Mpz {
    let bytes = encoding::hash_value(data)
        .map(|(_, hash)| hash)
        .or_else(|| encoding::data_value(data))
        .unwrap_or_default();
    bits2int(&bytes, order)
}

fn ed25519_secret_seed(skey: *mut sexp::gcry_sexp) -> Option<Vec<u8>> {
    let mut seed = encoding::token_bytes_from_mpi(skey, "d")?;
    if seed.len() > 32 {
        seed = seed[seed.len() - 32..].to_vec();
    }
    if seed.len() < 32 {
        let mut padded = vec![0u8; 32 - seed.len()];
        padded.extend_from_slice(&seed);
        seed = padded;
    }
    Some(seed)
}

fn ed25519_public_bytes(key: *mut sexp::gcry_sexp, curve: &mpi::ec::Curve) -> Option<Vec<u8>> {
    let q_bytes = encoding::token_bytes_from_mpi(key, "q")?;
    if q_bytes.len() == 32 {
        return Some(q_bytes);
    }
    let q = mpi::ec::decode_point(curve, &q_bytes)?;
    Some(mpi::ec::encode_eddsa(&q, 32))
}

fn ed25519_expanded(seed: &[u8]) -> Option<(Mpz, Vec<u8>)> {
    let digest = algorithms::digest_once(algorithms::GCRY_MD_SHA512, seed)?;
    let mut scalar = digest[..32].to_vec();
    scalar[0] &= 248;
    scalar[31] &= 63;
    scalar[31] |= 64;
    Some((Mpz::from_le(&scalar), digest[32..].to_vec()))
}

fn ed25519_message(data: *mut sexp::gcry_sexp) -> Vec<u8> {
    encoding::data_value(data).unwrap_or_default()
}

fn ed25519_sign(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
    curve: &mpi::ec::Curve,
) -> u32 {
    let Some(seed) = ed25519_secret_seed(skey) else {
        return encoding::err(error::GPG_ERR_NO_SECKEY);
    };
    let Some((a, prefix)) = ed25519_expanded(&seed) else {
        return encoding::err(error::GPG_ERR_DIGEST_ALGO);
    };
    let message = ed25519_message(data);
    let public = ed25519_public_bytes(skey, curve).unwrap_or_else(|| {
        let point = mpi::ec::scalar_mul_secret(curve, &a, &mpi::ec::base_point(curve));
        mpi::ec::encode_eddsa(&point, 32)
    });
    let order = mpi::ec::curve_order(curve);
    let mut r_input = Vec::with_capacity(prefix.len() + message.len());
    r_input.extend_from_slice(&prefix);
    r_input.extend_from_slice(&message);
    let Some(r_digest) = algorithms::digest_once(algorithms::GCRY_MD_SHA512, &r_input) else {
        return encoding::err(error::GPG_ERR_DIGEST_ALGO);
    };
    let r = Mpz::from_le(&r_digest).modulo(order);
    let r_point = mpi::ec::scalar_mul_secret(curve, &r, &mpi::ec::base_point(curve));
    let r_bytes = mpi::ec::encode_eddsa(&r_point, 32);

    let mut k_input = Vec::with_capacity(64 + public.len() + message.len());
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(&public);
    k_input.extend_from_slice(&message);
    let Some(k_digest) = algorithms::digest_once(algorithms::GCRY_MD_SHA512, &k_input) else {
        return encoding::err(error::GPG_ERR_DIGEST_ALGO);
    };
    let k = Mpz::from_le(&k_digest).modulo(order);
    let s = r.mod_add(&k.mod_mul(&a, order), order);
    let s_bytes = s.to_le_padded(32);
    let text = format!(
        "(sig-val (eddsa (r {})(s {})))",
        encoding::hex_atom(&r_bytes),
        encoding::hex_atom(&s_bytes)
    );
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
}

fn ed25519_verify(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
    key: &EccKey,
) -> u32 {
    let Some(q) = key.q.as_ref() else {
        return encoding::err(error::GPG_ERR_BAD_PUBKEY);
    };
    let Some(r_bytes) = encoding::token_bytes_from_mpi(sigval, "r") else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    let Some(s_bytes) = encoding::token_bytes_from_mpi(sigval, "s") else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    if r_bytes.len() != 32 || s_bytes.len() != 32 {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    }
    let Some(r_point) = mpi::ec::decode_point(&key.curve, &r_bytes) else {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    };
    let order = mpi::ec::curve_order(&key.curve);
    let s = Mpz::from_le(&s_bytes);
    if s.cmp(order) >= 0 {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    }
    let public = ed25519_public_bytes(pkey, &key.curve)
        .unwrap_or_else(|| mpi::ec::encode_eddsa(q, 32));
    let message = ed25519_message(data);
    let mut k_input = Vec::with_capacity(64 + public.len() + message.len());
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(&public);
    k_input.extend_from_slice(&message);
    let Some(k_digest) = algorithms::digest_once(algorithms::GCRY_MD_SHA512, &k_input) else {
        return encoding::err(error::GPG_ERR_DIGEST_ALGO);
    };
    let k = Mpz::from_le(&k_digest).modulo(order);
    let left = mpi::ec::scalar_mul(&key.curve, &s, &mpi::ec::base_point(&key.curve));
    let k_a = mpi::ec::scalar_mul(&key.curve, &k, q);
    let right = mpi::ec::add_points(&key.curve, &r_point, &k_a);
    let left_bytes = mpi::ec::encode_eddsa(&left, 32);
    let right_bytes = mpi::ec::encode_eddsa(&right, 32);
    if left_bytes == right_bytes {
        return 0;
    }
    let cofactor = Mpz::from_ui(8);
    let left8 = mpi::ec::scalar_mul(&key.curve, &cofactor, &left);
    let right8 = mpi::ec::scalar_mul(&key.curve, &cofactor, &right);
    if mpi::ec::encode_eddsa(&left8, 32) == mpi::ec::encode_eddsa(&right8, 32) {
        0
    } else {
        encoding::err(error::GPG_ERR_BAD_SIGNATURE)
    }
}

fn shake256(data: &[u8], len: usize) -> Option<Vec<u8>> {
    let mut state = algorithms::HashState::new(algorithms::GCRY_MD_SHAKE256)?;
    state.update(data);
    state.xof_vec(len)
}

fn ed448_secret_seed(skey: *mut sexp::gcry_sexp) -> Option<Vec<u8>> {
    let mut seed = encoding::token_bytes_from_mpi(skey, "d")?;
    if seed.len() > 57 {
        seed = seed[seed.len() - 57..].to_vec();
    }
    if seed.len() < 57 {
        let mut padded = vec![0u8; 57 - seed.len()];
        padded.extend_from_slice(&seed);
        seed = padded;
    }
    Some(seed)
}

fn ed448_public_bytes(key: *mut sexp::gcry_sexp, curve: &mpi::ec::Curve) -> Option<Vec<u8>> {
    let q_bytes = encoding::token_bytes_from_mpi(key, "q")?;
    if q_bytes.len() == 57 {
        return Some(q_bytes);
    }
    let q = mpi::ec::decode_point(curve, &q_bytes)?;
    Some(mpi::ec::encode_eddsa(&q, 57))
}

fn ed448_expanded(seed: &[u8]) -> Option<(Mpz, Vec<u8>)> {
    let digest = shake256(seed, 114)?;
    let mut scalar = digest[..57].to_vec();
    scalar[0] &= 252;
    scalar[55] |= 128;
    scalar[56] = 0;
    Some((Mpz::from_le(&scalar), digest[57..].to_vec()))
}

fn ed448_dom(data: *mut sexp::gcry_sexp) -> Option<Vec<u8>> {
    let ctx = encoding::label(data);
    if ctx.len() > 255 {
        return None;
    }
    let mut dom = Vec::with_capacity(10 + ctx.len());
    dom.extend_from_slice(b"SigEd448");
    dom.push(if encoding::has_flag(data, "prehash") { 1 } else { 0 });
    dom.push(ctx.len() as u8);
    dom.extend_from_slice(&ctx);
    Some(dom)
}

fn ed448_message(data: *mut sexp::gcry_sexp) -> Option<Vec<u8>> {
    let message = encoding::data_value(data).unwrap_or_default();
    if encoding::has_flag(data, "prehash") {
        shake256(&message, 64)
    } else {
        Some(message)
    }
}

fn ed448_sign(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
    curve: &mpi::ec::Curve,
) -> u32 {
    let Some(seed) = ed448_secret_seed(skey) else {
        return encoding::err(error::GPG_ERR_NO_SECKEY);
    };
    let Some((a, prefix)) = ed448_expanded(&seed) else {
        return encoding::err(error::GPG_ERR_DIGEST_ALGO);
    };
    let Some(dom) = ed448_dom(data) else {
        return encoding::err(error::GPG_ERR_INV_VALUE);
    };
    let Some(message) = ed448_message(data) else {
        return encoding::err(error::GPG_ERR_DIGEST_ALGO);
    };
    let public = ed448_public_bytes(skey, curve).unwrap_or_else(|| {
        let point = mpi::ec::scalar_mul_secret(curve, &a, &mpi::ec::base_point(curve));
        mpi::ec::encode_eddsa(&point, 57)
    });
    let order = mpi::ec::curve_order(curve);
    let mut r_input = Vec::with_capacity(dom.len() + prefix.len() + message.len());
    r_input.extend_from_slice(&dom);
    r_input.extend_from_slice(&prefix);
    r_input.extend_from_slice(&message);
    let Some(r_digest) = shake256(&r_input, 114) else {
        return encoding::err(error::GPG_ERR_DIGEST_ALGO);
    };
    let r = Mpz::from_le(&r_digest).modulo(order);
    let r_point = mpi::ec::scalar_mul_secret(curve, &r, &mpi::ec::base_point(curve));
    let r_bytes = mpi::ec::encode_eddsa(&r_point, 57);

    let mut k_input = Vec::with_capacity(dom.len() + 114 + message.len());
    k_input.extend_from_slice(&dom);
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(&public);
    k_input.extend_from_slice(&message);
    let Some(k_digest) = shake256(&k_input, 114) else {
        return encoding::err(error::GPG_ERR_DIGEST_ALGO);
    };
    let k = Mpz::from_le(&k_digest).modulo(order);
    let s = r.mod_add(&k.mod_mul(&a, order), order);
    let s_bytes = s.to_le_padded(57);
    let text = format!(
        "(sig-val (eddsa (r {})(s {})))",
        encoding::hex_atom(&r_bytes),
        encoding::hex_atom(&s_bytes)
    );
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
}

fn ed448_verify(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
    key: &EccKey,
) -> u32 {
    let Some(q) = key.q.as_ref() else {
        return encoding::err(error::GPG_ERR_BAD_PUBKEY);
    };
    let Some(r_bytes) = encoding::token_bytes_from_mpi(sigval, "r") else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    let Some(s_bytes) = encoding::token_bytes_from_mpi(sigval, "s") else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    if r_bytes.len() != 57 || s_bytes.len() != 57 {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    }
    let Some(r_point) = mpi::ec::decode_point(&key.curve, &r_bytes) else {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    };
    let order = mpi::ec::curve_order(&key.curve);
    let s = Mpz::from_le(&s_bytes);
    if s.cmp(order) >= 0 {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    }
    let Some(dom) = ed448_dom(data) else {
        return encoding::err(error::GPG_ERR_INV_VALUE);
    };
    let Some(message) = ed448_message(data) else {
        return encoding::err(error::GPG_ERR_DIGEST_ALGO);
    };
    let public = ed448_public_bytes(pkey, &key.curve)
        .unwrap_or_else(|| mpi::ec::encode_eddsa(q, 57));
    let mut k_input = Vec::with_capacity(dom.len() + 114 + message.len());
    k_input.extend_from_slice(&dom);
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(&public);
    k_input.extend_from_slice(&message);
    let Some(k_digest) = shake256(&k_input, 114) else {
        return encoding::err(error::GPG_ERR_DIGEST_ALGO);
    };
    let k = Mpz::from_le(&k_digest).modulo(order);
    let left = mpi::ec::scalar_mul(&key.curve, &s, &mpi::ec::base_point(&key.curve));
    let k_a = mpi::ec::scalar_mul(&key.curve, &k, q);
    let right = mpi::ec::add_points(&key.curve, &r_point, &k_a);
    if mpi::ec::encode_eddsa(&left, 57) == mpi::ec::encode_eddsa(&right, 57) {
        return 0;
    }
    let cofactor = Mpz::from_ui(4);
    let left4 = mpi::ec::scalar_mul(&key.curve, &cofactor, &left);
    let right4 = mpi::ec::scalar_mul(&key.curve, &cofactor, &right);
    if mpi::ec::encode_eddsa(&left4, 57) == mpi::ec::encode_eddsa(&right4, 57) {
        0
    } else {
        encoding::err(error::GPG_ERR_BAD_SIGNATURE)
    }
}

pub(crate) fn sign(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    let key = match parse_key(skey) {
        Ok(key) => key,
        Err(err) => return encoding::err(err),
    };
    let Some(d) = key.d.as_ref() else {
        return encoding::err(error::GPG_ERR_NO_SECKEY);
    };
    if key.curve.name == "Ed25519"
        && (encoding::has_flag(data, "eddsa") || encoding::has_flag(skey, "eddsa"))
    {
        return ed25519_sign(result, data, skey, &key.curve);
    }
    if key.curve.name == "Ed448" {
        return ed448_sign(result, data, skey, &key.curve);
    }
    let order = mpi::ec::curve_order(&key.curve);
    let supplied_k = {
        let bytes = encoding::label(data);
        (!bytes.is_empty()).then(|| Mpz::from_be(&bytes))
    };
    for _ in 0..128 {
        let k = if let Some(k) = supplied_k.clone() {
            k
        } else if encoding::has_flag(data, "rfc6979") {
            let Some((hash_name, hash)) = encoding::hash_value(data) else {
                return encoding::err(error::GPG_ERR_CONFLICT);
            };
            let Some(k) = encoding::rfc6979_nonce(order, d, &hash_name, &hash) else {
                return encoding::err(error::GPG_ERR_DIGEST_ALGO);
            };
            k
        } else {
            random_scalar(&key.curve)
        };
        let p = mpi::ec::scalar_mul_secret(&key.curve, &k, &mpi::ec::base_point(&key.curve));
        let Some(x) = p.x.as_ref() else {
            continue;
        };
        let r = x.modulo(order);
        if r.is_zero() {
            continue;
        }
        let Some(kinv) = k.invert(order) else {
            continue;
        };
        let z = data_digest(data, order);
        let s = kinv.mod_mul(&z.mod_add(&d.mod_mul(&r, order), order), order);
        if s.is_zero() {
            continue;
        }
        let text = format!(
            "(sig-val (ecdsa (r {})(s {})))",
            encoding::hex_atom(&r.to_be()),
            encoding::hex_atom(&s.to_be())
        );
        return match encoding::build_sexp(&text) {
            Ok(sexp) => unsafe {
                *result = sexp;
                0
            },
            Err(err) => err,
        };
    }
    encoding::err(error::GPG_ERR_GENERAL)
}

pub(crate) fn verify(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    let key = match parse_key(pkey) {
        Ok(key) => key,
        Err(err) => return encoding::err(err),
    };
    let Some(q) = key.q.as_ref() else {
        return encoding::err(error::GPG_ERR_BAD_PUBKEY);
    };
    if key.curve.name == "Ed25519"
        && (encoding::has_token(sigval, "eddsa") || encoding::has_flag(data, "eddsa"))
    {
        return ed25519_verify(sigval, data, pkey, &key);
    }
    if key.curve.name == "Ed448" {
        return ed448_verify(sigval, data, pkey, &key);
    }
    let Some(r) = encoding::token_mpz(sigval, "r") else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    let Some(s) = encoding::token_mpz(sigval, "s") else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    let order = mpi::ec::curve_order(&key.curve);
    if r.is_zero() || r.cmp(order) >= 0 || s.is_zero() || s.cmp(order) >= 0 {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    }
    let Some(w) = s.invert(order) else {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    };
    let z = data_digest(data, order);
    let u1 = z.mod_mul(&w, order);
    let u2 = r.mod_mul(&w, order);
    let p1 = mpi::ec::scalar_mul(&key.curve, &u1, &mpi::ec::base_point(&key.curve));
    let p2 = mpi::ec::scalar_mul(&key.curve, &u2, q);
    let p = mpi::ec::add_points(&key.curve, &p1, &p2);
    let Some(x) = p.x.as_ref() else {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    };
    if x.modulo(order).cmp(&r) == 0 {
        0
    } else {
        encoding::err(error::GPG_ERR_BAD_SIGNATURE)
    }
}

fn random_scalar(curve: &mpi::ec::Curve) -> Mpz {
    let order = mpi::ec::curve_order(curve);
    let len = curve.field_bytes.max(1);
    loop {
        let mut bytes = vec![0u8; len];
        os_rng::fill_random(&mut bytes);
        let value = Mpz::from_be(&bytes).modulo(order);
        if !value.is_zero() {
            return value;
        }
    }
}

pub(crate) fn genkey(result: *mut *mut sexp::gcry_sexp, spec: *mut sexp::gcry_sexp) -> u32 {
    let curve_name = encoding::token_string(spec, "curve").unwrap_or_else(|| "NIST P-256".into());
    let Some(curve) = mpi::ec::curve_by_name(&curve_name) else {
        return encoding::err(error::GPG_ERR_INV_NAME);
    };
    let d = random_scalar(&curve);
    let q = mpi::ec::scalar_mul_secret(&curve, &d, &mpi::ec::base_point(&curve));
    let q_bytes = if encoding::has_flag(spec, "eddsa") || curve.name == "Ed448" {
        mpi::ec::encode_eddsa(&q, curve.field_bytes)
    } else {
        mpi::ec::encode_point(&curve, &q)
    };
    let text = format!(
        "(key-data (public-key (ecc (curve {})(q {}))) (private-key (ecc (curve {})(q {})(d {}))))",
        encoding::string_atom(curve.name),
        encoding::hex_atom(&q_bytes),
        encoding::string_atom(curve.name),
        encoding::hex_atom(&q_bytes),
        encoding::hex_atom(&d.to_be())
    );
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
}
