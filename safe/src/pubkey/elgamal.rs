use std::ffi::{c_char, c_int};

use crate::error;
use crate::mpi::Mpz;
use crate::os_rng;
use crate::sexp;

use super::encoding;

pub(crate) const NAME: &[u8] = b"elg\0";

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    matches!(algo, 16 | 20)
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}

struct ElgKey {
    p: Mpz,
    g: Mpz,
    y: Mpz,
    x: Option<Mpz>,
}

fn elg_part(key: *mut sexp::gcry_sexp) -> Option<*mut sexp::gcry_sexp> {
    let private = encoding::find_token(key, "private-key");
    if !private.is_null() {
        let elg = encoding::find_token(private, "elg");
        let elg = if elg.is_null() {
            encoding::find_token(private, "ELG")
        } else {
            elg
        };
        let elg = if elg.is_null() {
            encoding::find_token(private, "elgamal")
        } else {
            elg
        };
        let elg = if elg.is_null() {
            encoding::find_token(private, "ELGAMAL")
        } else {
            elg
        };
        sexp::gcry_sexp_release(private);
        if !elg.is_null() {
            return Some(elg);
        }
    }
    let elg = encoding::find_token(key, "elg");
    if !elg.is_null() {
        return Some(elg);
    }
    let elg = encoding::find_token(key, "ELG");
    if !elg.is_null() {
        return Some(elg);
    }
    let elgamal = encoding::find_token(key, "elgamal");
    if !elgamal.is_null() {
        return Some(elgamal);
    }
    let elgamal = encoding::find_token(key, "ELGAMAL");
    (!elgamal.is_null()).then_some(elgamal)
}

fn parse_key(key: *mut sexp::gcry_sexp) -> Result<ElgKey, u32> {
    let elg = elg_part(key).ok_or_else(|| encoding::err(error::GPG_ERR_BAD_PUBKEY))?;
    let parsed = (|| {
        Ok(ElgKey {
            p: encoding::token_mpz(elg, "p").ok_or(error::GPG_ERR_BAD_PUBKEY)?,
            g: encoding::token_mpz(elg, "g").ok_or(error::GPG_ERR_BAD_PUBKEY)?,
            y: encoding::token_mpz(elg, "y").ok_or(error::GPG_ERR_BAD_PUBKEY)?,
            x: encoding::token_mpz(elg, "x"),
        })
    })();
    sexp::gcry_sexp_release(elg);
    parsed.map_err(encoding::err)
}

pub(crate) fn testkey(key: *mut sexp::gcry_sexp) -> u32 {
    let key = match parse_key(key) {
        Ok(key) => key,
        Err(err) => return err,
    };
    let Some(x) = key.x.as_ref() else {
        return encoding::err(error::GPG_ERR_NO_SECKEY);
    };
    if key.p.cmp_ui(3) < 0 || key.g.cmp_ui(1) <= 0 || key.g.cmp(&key.p) >= 0 {
        return encoding::err(error::GPG_ERR_BAD_SECKEY);
    }
    if key.g.powm_sec(x, &key.p).cmp(&key.y) == 0 {
        0
    } else {
        encoding::err(error::GPG_ERR_BAD_SECKEY)
    }
}

fn random_mpz_below(limit: &Mpz) -> Mpz {
    let len = limit.bits().div_ceil(8).max(1);
    loop {
        let mut bytes = vec![0u8; len];
        os_rng::fill_random(&mut bytes);
        let value = Mpz::from_be(&bytes).modulo(limit);
        if !value.is_zero() {
            return value;
        }
    }
}

fn random_prime(bits: usize) -> Mpz {
    loop {
        let mut bytes = vec![0u8; bits.div_ceil(8).max(1)];
        os_rng::fill_random(&mut bytes);
        bytes[0] |= 1 << ((bits.saturating_sub(1)) % 8);
        if let Some(last) = bytes.last_mut() {
            *last |= 1;
        }
        let p = Mpz::from_be(&bytes).next_prime();
        if p.bits() == bits {
            return p;
        }
    }
}

fn secret_powm(base: &Mpz, exponent: &Mpz, p: &Mpz) -> Mpz {
    let p_minus_1 = p.sub_ui(1);
    let blind = random_mpz_below(&p_minus_1).mul(&p_minus_1);
    base.powm_sec(&exponent.add(&blind), p)
}

fn validate_sign_data(data: *mut sexp::gcry_sexp) -> Result<(), u32> {
    let flags = encoding::flag_atoms(data);
    for flag in &flags {
        if !matches!(
            flag.as_str(),
            "raw" | "pkcs1" | "pkcs1-raw" | "pss" | "oaep"
        ) {
            return Err(encoding::err(error::GPG_ERR_INV_FLAG));
        }
    }
    if flags
        .iter()
        .any(|flag| matches!(flag.as_str(), "pkcs1" | "pkcs1-raw" | "pss" | "oaep"))
    {
        return Err(encoding::err(error::GPG_ERR_CONFLICT));
    }
    if encoding::has_token(data, "hash") {
        return Err(encoding::err(error::GPG_ERR_CONFLICT));
    }
    Ok(())
}

fn validate_encrypt_data(data: *mut sexp::gcry_sexp) -> Result<(), u32> {
    let flags = encoding::flag_atoms(data);
    for flag in &flags {
        if !matches!(
            flag.as_str(),
            "raw" | "no-blinding" | "pss" | "pkcs1" | "oaep"
        ) {
            return Err(encoding::err(error::GPG_ERR_INV_FLAG));
        }
    }
    if flags
        .iter()
        .any(|flag| matches!(flag.as_str(), "pss" | "pkcs1" | "oaep"))
        || encoding::has_token(data, "hash")
        || encoding::has_token(data, "hash-algo")
    {
        return Err(encoding::err(error::GPG_ERR_CONFLICT));
    }
    Ok(())
}

fn validate_decrypt_hint(data: *mut sexp::gcry_sexp) -> Result<(), u32> {
    let flags = encoding::flag_atoms(data);
    for flag in &flags {
        if !matches!(flag.as_str(), "raw" | "pkcs1" | "oaep" | "pss") {
            return Err(encoding::err(error::GPG_ERR_INV_FLAG));
        }
    }
    if flags
        .iter()
        .any(|flag| matches!(flag.as_str(), "pkcs1" | "oaep" | "pss"))
    {
        return Err(encoding::err(error::GPG_ERR_ENCODING_PROBLEM));
    }
    Ok(())
}

fn data_as_mpz(data: *mut sexp::gcry_sexp) -> Mpz {
    encoding::token_mpz(data, "value")
        .or_else(|| encoding::data_value(data).map(|bytes| Mpz::from_be(&bytes)))
        .unwrap_or_else(|| Mpz::from_ui(0))
}

pub(crate) fn encrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    if let Err(err) = validate_encrypt_data(data) {
        return err;
    }
    let key = match parse_key(pkey) {
        Ok(key) => key,
        Err(err) => return err,
    };
    let m = encoding::token_mpz(data, "value")
        .or_else(|| encoding::data_value(data).map(|bytes| Mpz::from_be(&bytes)));
    let Some(m) = m else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    if m.cmp(&key.p) >= 0 {
        return encoding::err(error::GPG_ERR_TOO_LARGE);
    }
    let p_minus_1 = key.p.sub_ui(1);
    let k = random_mpz_below(&p_minus_1);
    let a = secret_powm(&key.g, &k, &key.p);
    let b = secret_powm(&key.y, &k, &key.p).mod_mul(&m, &key.p);
    let text = format!(
        "(enc-val (elg (a {})(b {})))",
        encoding::hex_atom(&a.to_be()),
        encoding::hex_atom(&b.to_be())
    );
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
}

pub(crate) fn decrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    if let Err(err) = validate_decrypt_hint(data) {
        return err;
    }
    let key = match parse_key(skey) {
        Ok(key) => key,
        Err(err) => return err,
    };
    let Some(x) = key.x.as_ref() else {
        return encoding::err(error::GPG_ERR_NO_SECKEY);
    };
    let Some(a) = encoding::token_mpz(data, "a") else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    let Some(b) = encoding::token_mpz(data, "b") else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    let shared = secret_powm(&a, x, &key.p);
    let Some(inv) = shared.invert(&key.p) else {
        return encoding::err(error::GPG_ERR_DECRYPT_FAILED);
    };
    let m = b.mod_mul(&inv, &key.p);
    let text = if encoding::has_token(data, "flags") {
        format!("(value {})", encoding::hex_atom(&m.to_be()))
    } else {
        encoding::hex_atom(&m.to_be())
    };
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
}

pub(crate) fn sign(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    if let Err(err) = validate_sign_data(data) {
        return err;
    }
    let key = match parse_key(skey) {
        Ok(key) => key,
        Err(err) => return err,
    };
    let Some(x) = key.x.as_ref() else {
        return encoding::err(error::GPG_ERR_NO_SECKEY);
    };
    let p_minus_1 = key.p.sub_ui(1);
    let m = data_as_mpz(data).modulo(&p_minus_1);
    for _ in 0..128 {
        let k = random_mpz_below(&p_minus_1);
        if !k.gcd(&p_minus_1).is_one() {
            continue;
        }
        let Some(kinv) = k.invert(&p_minus_1) else {
            continue;
        };
        let r = secret_powm(&key.g, &k, &key.p);
        if r.is_zero() {
            continue;
        }
        let s = kinv.mod_mul(
            &m.mod_sub(&x.mod_mul(&r, &p_minus_1), &p_minus_1),
            &p_minus_1,
        );
        if s.is_zero() {
            continue;
        }
        let text = format!(
            "(sig-val (elg (r {})(s {})))",
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
        Err(err) => return err,
    };
    let Some(r) = encoding::token_mpz(sigval, "r") else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    let Some(s) = encoding::token_mpz(sigval, "s") else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    if r.cmp_ui(1) <= 0 || r.cmp(&key.p) >= 0 || s.is_zero() || s.cmp(&key.p.sub_ui(1)) >= 0 {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    }
    let p_minus_1 = key.p.sub_ui(1);
    let m = data_as_mpz(data).modulo(&p_minus_1);
    let lhs = key.y.powm(&r, &key.p).mod_mul(&r.powm(&s, &key.p), &key.p);
    let rhs = key.g.powm(&m, &key.p);
    if lhs.cmp(&rhs) == 0 {
        0
    } else {
        encoding::err(error::GPG_ERR_BAD_SIGNATURE)
    }
}

pub(crate) fn genkey(result: *mut *mut sexp::gcry_sexp, spec: *mut sexp::gcry_sexp) -> u32 {
    let nbits = encoding::token_string(spec, "nbits")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2048);
    let p = random_prime(nbits.max(512));
    let g = Mpz::from_ui(2);
    let p_minus_1 = p.sub_ui(1);
    let x = encoding::token_data(spec, "xvalue")
        .map(|bytes| {
            let value = Mpz::from_be(&bytes).modulo(&p_minus_1);
            if value.is_zero() {
                Mpz::from_ui(1)
            } else {
                value
            }
        })
        .unwrap_or_else(|| random_mpz_below(&p_minus_1));
    let y = secret_powm(&g, &x, &p);
    let text = format!(
        "(key-data (public-key (elg (p {})(g {})(y {}))) (private-key (elg (p {})(g {})(y {})(x {}))))",
        encoding::hex_atom(&p.to_be()),
        encoding::hex_atom(&g.to_be()),
        encoding::hex_atom(&y.to_be()),
        encoding::hex_atom(&p.to_be()),
        encoding::hex_atom(&g.to_be()),
        encoding::hex_atom(&y.to_be()),
        encoding::hex_atom(&x.to_be())
    );
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
}

pub(crate) fn get_nbits(key: *mut sexp::gcry_sexp) -> u32 {
    parse_key(key).map(|key| key.p.bits() as u32).unwrap_or(0)
}
