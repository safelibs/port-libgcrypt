use std::ffi::{CString, c_char, c_int};

use crate::digest;
use crate::digest::algorithms;
use crate::error;
use crate::mpi::Mpz;
use crate::os_rng;
use crate::sexp;

use super::encoding;

pub(crate) const NAME: &[u8] = b"rsa\0";

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    matches!(algo, 1..=3)
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}

#[derive(Clone)]
pub(crate) struct RsaKey {
    n: Mpz,
    e: Mpz,
    d: Option<Mpz>,
    p: Option<Mpz>,
    q: Option<Mpz>,
    u: Option<Mpz>,
}

impl RsaKey {
    fn public(&self) -> Self {
        Self {
            n: self.n.clone(),
            e: self.e.clone(),
            d: None,
            p: None,
            q: None,
            u: None,
        }
    }

    fn bytes(&self) -> usize {
        self.n.bits().div_ceil(8)
    }
}

fn rsa_part(key: *mut sexp::gcry_sexp) -> Option<*mut sexp::gcry_sexp> {
    let rsa = encoding::find_token(key, "rsa");
    if !rsa.is_null() {
        return Some(rsa);
    }
    let rsa = encoding::find_token(key, "RSA");
    if !rsa.is_null() {
        return Some(rsa);
    }
    let openpgp = encoding::find_token(key, "openpgp-rsa");
    if !openpgp.is_null() {
        return Some(openpgp);
    }
    let openpgp = encoding::find_token(key, "OPENPGP-RSA");
    (!openpgp.is_null()).then_some(openpgp)
}

pub(crate) fn parse_key(key: *mut sexp::gcry_sexp) -> Result<RsaKey, u32> {
    let rsa = rsa_part(key).ok_or_else(|| encoding::err(error::GPG_ERR_BAD_PUBKEY))?;
    let parsed = (|| {
        let n = encoding::token_mpz(rsa, "n").ok_or(error::GPG_ERR_BAD_PUBKEY)?;
        let e = encoding::token_mpz(rsa, "e").ok_or(error::GPG_ERR_BAD_PUBKEY)?;
        let d = encoding::token_mpz(rsa, "d");
        let p = encoding::token_mpz(rsa, "p");
        let q = encoding::token_mpz(rsa, "q");
        let u = encoding::token_mpz(rsa, "u");
        Ok(RsaKey { n, e, d, p, q, u })
    })();
    sexp::gcry_sexp_release(rsa);
    parsed.map_err(encoding::err)
}

fn random_nonzero(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut offset = 0usize;
    while offset < len {
        os_rng::fill_random(&mut out[offset..]);
        while offset < len && out[offset] != 0 {
            offset += 1;
        }
    }
    out
}

fn left_pad(mut bytes: Vec<u8>, len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        return bytes[bytes.len() - len..].to_vec();
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.append(&mut bytes);
    out
}

fn rsa_public(key: &RsaKey, em: &[u8]) -> Vec<u8> {
    Mpz::from_be(em)
        .powm(&key.e, &key.n)
        .to_be_padded(key.bytes())
}

fn rsa_private(key: &RsaKey, em: &[u8]) -> Result<Vec<u8>, u32> {
    let Some(d) = &key.d else {
        return Err(encoding::err(error::GPG_ERR_NO_SECKEY));
    };
    let input = Mpz::from_be(em).modulo(&key.n);
    for _ in 0..32 {
        let r = random_mpz_below(&key.n);
        let Some(ri) = r.invert(&key.n) else {
            continue;
        };
        let blinded = input.mod_mul(&r.powm(&key.e, &key.n), &key.n);
        let plain = blinded.powm_sec(d, &key.n).mod_mul(&ri, &key.n);
        return Ok(plain.to_be_padded(key.bytes()));
    }
    Ok(input.powm_sec(d, &key.n).to_be_padded(key.bytes()))
}

fn canonical_hash_name(name: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "oid.1.3.14.3.2.29" => "sha1".to_string(),
        _ => name.to_ascii_lowercase(),
    }
}

fn digest_algo(name: &str) -> Option<c_int> {
    let canonical = canonical_hash_name(name);
    let c_name = CString::new(canonical).ok()?;
    let algo = digest::gcry_md_map_name(c_name.as_ptr());
    (algo != 0).then_some(algo)
}

pub(crate) fn digest_once_name(name: &str, data: &[u8]) -> Option<Vec<u8>> {
    algorithms::digest_once(digest_algo(name)?, data)
}

fn digest_info_prefix(name: &str) -> Option<&'static [u8]> {
    match canonical_hash_name(name).as_str() {
        "sha1" => Some(&[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ]),
        "sha224" => Some(&[
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00, 0x04, 0x1c,
        ]),
        "sha256" => Some(&[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]),
        "sha384" => Some(&[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ]),
        "sha512" => Some(&[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ]),
        "sha512224" | "sha512_224" | "sha512-224" => Some(&[
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x05, 0x05, 0x00, 0x04, 0x1c,
        ]),
        "sha512256" | "sha512_256" | "sha512-256" => Some(&[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x06, 0x05, 0x00, 0x04, 0x20,
        ]),
        _ => None,
    }
}

fn has_value_token(data: *mut sexp::gcry_sexp) -> bool {
    encoding::has_token(data, "value")
}

fn has_hash_token(data: *mut sexp::gcry_sexp) -> bool {
    encoding::has_token(data, "hash")
}

fn has_hash_algo_token(data: *mut sexp::gcry_sexp) -> bool {
    encoding::has_token(data, "hash-algo")
}

fn only_known_flags(flags: &[String], allowed: &[&str]) -> Result<(), u32> {
    for flag in flags {
        if !allowed.iter().any(|known| flag == known) {
            return Err(encoding::err(error::GPG_ERR_INV_FLAG));
        }
    }
    Ok(())
}

fn validate_sign_data(data: *mut sexp::gcry_sexp) -> Result<(), u32> {
    let flags = encoding::flag_atoms(data);
    only_known_flags(&flags, &["raw", "pkcs1", "pkcs1-raw", "pss", "oaep"])?;
    let has_hash = has_hash_token(data);
    let has_hash_algo = has_hash_algo_token(data);
    let has_value = has_value_token(data);
    if flags.iter().any(|flag| flag == "oaep") {
        return Err(encoding::err(error::GPG_ERR_CONFLICT));
    }
    if encoding::has_flag(data, "pkcs1") {
        if has_value && !has_hash_algo {
            return Err(encoding::err(error::GPG_ERR_CONFLICT));
        }
        if !has_hash && !(has_hash_algo && has_value) {
            return Err(encoding::err(error::GPG_ERR_INV_OBJ));
        }
    } else if encoding::has_flag(data, "pkcs1-raw") {
        if has_hash || has_hash_algo || !has_value {
            return Err(encoding::err(error::GPG_ERR_CONFLICT));
        }
    } else if encoding::has_flag(data, "pss") {
        if !has_hash && !(has_hash_algo && has_value) {
            return Err(encoding::err(error::GPG_ERR_CONFLICT));
        }
    } else if has_hash || (has_hash_algo && !has_value) {
        return Err(encoding::err(error::GPG_ERR_CONFLICT));
    }
    Ok(())
}

fn validate_encrypt_data(data: *mut sexp::gcry_sexp) -> Result<(), u32> {
    let flags = encoding::flag_atoms(data);
    only_known_flags(&flags, &["raw", "no-blinding", "pkcs1", "oaep", "pss"])?;
    if encoding::has_flag(data, "pss")
        || has_hash_token(data)
        || (has_hash_algo_token(data)
            && !encoding::has_flag(data, "oaep")
            && !encoding::has_flag(data, "pkcs1"))
    {
        return Err(encoding::err(error::GPG_ERR_CONFLICT));
    }
    Ok(())
}

fn signature_hash(data: *mut sexp::gcry_sexp) -> Result<Option<(String, Vec<u8>)>, u32> {
    if let Some((name, hash)) = encoding::hash_value(data) {
        let canonical = canonical_hash_name(&name);
        if digest_algo(&canonical).is_none() {
            return Err(encoding::err(error::GPG_ERR_DIGEST_ALGO));
        }
        return Ok(Some((canonical, hash)));
    }
    if let Some(name) = encoding::token_string(data, "hash-algo") {
        let canonical = canonical_hash_name(&name);
        let value =
            encoding::data_value(data).ok_or_else(|| encoding::err(error::GPG_ERR_INV_OBJ))?;
        let digest = digest_once_name(&canonical, &value)
            .ok_or_else(|| encoding::err(error::GPG_ERR_DIGEST_ALGO))?;
        return Ok(Some((canonical, digest)));
    }
    Ok(None)
}

fn mgf1(seed: &[u8], len: usize, hash_name: &str) -> Result<Vec<u8>, u32> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u32;
    while out.len() < len {
        let mut input = Vec::with_capacity(seed.len() + 4);
        input.extend_from_slice(seed);
        input.extend_from_slice(&counter.to_be_bytes());
        let digest = digest_once_name(hash_name, &input)
            .ok_or_else(|| encoding::err(error::GPG_ERR_DIGEST_ALGO))?;
        out.extend_from_slice(&digest);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    Ok(out)
}

fn oaep_encode(data: *mut sexp::gcry_sexp, k: usize) -> Result<Vec<u8>, u32> {
    let msg = encoding::data_value(data).ok_or_else(|| encoding::err(error::GPG_ERR_INV_OBJ))?;
    let hash_name = encoding::hash_algo_name(data).unwrap_or_else(|| "sha1".to_string());
    let l_hash = digest_once_name(&hash_name, &encoding::label(data))
        .ok_or_else(|| encoding::err(error::GPG_ERR_DIGEST_ALGO))?;
    let h_len = l_hash.len();
    if msg.len() > k.saturating_sub(2 * h_len + 2) {
        return Err(encoding::err(error::GPG_ERR_TOO_LARGE));
    }
    let seed = encoding::random_override(data).unwrap_or_else(|| {
        let mut seed = vec![0u8; h_len];
        os_rng::fill_random(&mut seed);
        seed
    });
    let mut db = Vec::with_capacity(k - h_len - 1);
    db.extend_from_slice(&l_hash);
    db.resize(k - msg.len() - h_len - 2, 0);
    db.push(1);
    db.extend_from_slice(&msg);
    let db_mask = mgf1(&seed, k - h_len - 1, &hash_name)?;
    let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    let seed_mask = mgf1(&masked_db, h_len, &hash_name)?;
    let masked_seed: Vec<u8> = seed
        .iter()
        .zip(seed_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let mut em = Vec::with_capacity(k);
    em.push(0);
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&masked_db);
    Ok(em)
}

fn oaep_decode(data: *mut sexp::gcry_sexp, em: &[u8]) -> Result<Vec<u8>, u32> {
    let hash_name = encoding::hash_algo_name(data).unwrap_or_else(|| "sha1".to_string());
    let l_hash = digest_once_name(&hash_name, &encoding::label(data))
        .ok_or_else(|| encoding::err(error::GPG_ERR_DIGEST_ALGO))?;
    let h_len = l_hash.len();
    if em.len() < 2 * h_len + 2 || em.first().copied() != Some(0) {
        return Err(encoding::err(error::GPG_ERR_ENCODING_PROBLEM));
    }
    let (masked_seed, masked_db) = em[1..].split_at(h_len);
    let seed_mask = mgf1(masked_db, h_len, &hash_name)?;
    let seed: Vec<u8> = masked_seed
        .iter()
        .zip(seed_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let db_mask = mgf1(&seed, em.len() - h_len - 1, &hash_name)?;
    let db: Vec<u8> = masked_db
        .iter()
        .zip(db_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    if db.get(..h_len) != Some(l_hash.as_slice()) {
        return Err(encoding::err(error::GPG_ERR_ENCODING_PROBLEM));
    }
    let rest = &db[h_len..];
    let Some(pos) = rest.iter().position(|byte| *byte == 1) else {
        return Err(encoding::err(error::GPG_ERR_ENCODING_PROBLEM));
    };
    if rest[..pos].iter().any(|byte| *byte != 0) {
        return Err(encoding::err(error::GPG_ERR_ENCODING_PROBLEM));
    }
    Ok(rest[pos + 1..].to_vec())
}

fn pkcs1_encrypt_encode(data: *mut sexp::gcry_sexp, k: usize) -> Result<Vec<u8>, u32> {
    let msg = encoding::data_value(data).ok_or_else(|| encoding::err(error::GPG_ERR_INV_OBJ))?;
    if msg.len() > k.saturating_sub(11) {
        return Err(encoding::err(error::GPG_ERR_TOO_LARGE));
    }
    let ps_len = k - msg.len() - 3;
    let ps = encoding::random_override(data).unwrap_or_else(|| random_nonzero(ps_len));
    let mut em = Vec::with_capacity(k);
    em.extend_from_slice(&[0, 2]);
    em.extend_from_slice(&ps[..ps_len.min(ps.len())]);
    while em.len() < 2 + ps_len {
        em.push(0xff);
    }
    for byte in &mut em[2..] {
        if *byte == 0 {
            *byte = 0xff;
        }
    }
    em.push(0);
    em.extend_from_slice(&msg);
    Ok(em)
}

fn pkcs1_decrypt_decode(em: &[u8]) -> Result<Vec<u8>, u32> {
    if em.len() < 11 || em.get(0) != Some(&0) || em.get(1) != Some(&2) {
        return Err(encoding::err(error::GPG_ERR_ENCODING_PROBLEM));
    }
    let Some(pos) = em[2..].iter().position(|byte| *byte == 0) else {
        return Err(encoding::err(error::GPG_ERR_ENCODING_PROBLEM));
    };
    if pos < 8 {
        return Err(encoding::err(error::GPG_ERR_ENCODING_PROBLEM));
    }
    Ok(em[2 + pos + 1..].to_vec())
}

fn pkcs1_sign_encode(data: *mut sexp::gcry_sexp, k: usize) -> Result<Vec<u8>, u32> {
    let (hash_name, hash) =
        signature_hash(data)?.ok_or_else(|| encoding::err(error::GPG_ERR_INV_OBJ))?;
    let prefix =
        digest_info_prefix(&hash_name).ok_or_else(|| encoding::err(error::GPG_ERR_DIGEST_ALGO))?;
    let t_len = prefix.len() + hash.len();
    if k < t_len + 11 {
        return Err(encoding::err(error::GPG_ERR_TOO_SHORT));
    }
    let mut em = Vec::with_capacity(k);
    em.extend_from_slice(&[0, 1]);
    em.resize(k - t_len - 1, 0xff);
    em.push(0);
    em.extend_from_slice(prefix);
    em.extend_from_slice(&hash);
    Ok(em)
}

fn pss_encode(data: *mut sexp::gcry_sexp, em_bits: usize) -> Result<Vec<u8>, u32> {
    let (hash_name, hash) =
        signature_hash(data)?.ok_or_else(|| encoding::err(error::GPG_ERR_INV_OBJ))?;
    let h_len = hash.len();
    let em_len = em_bits.div_ceil(8);
    let salt_len = encoding::token_string(data, "salt-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(h_len);
    let salt = encoding::random_override(data).unwrap_or_else(|| {
        let mut salt = vec![0u8; salt_len];
        os_rng::fill_random(&mut salt);
        salt
    });
    if em_len < h_len + salt.len() + 2 {
        return Err(encoding::err(error::GPG_ERR_TOO_SHORT));
    }
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(&hash);
    m_prime.extend_from_slice(&salt);
    let h = digest_once_name(&hash_name, &m_prime)
        .ok_or_else(|| encoding::err(error::GPG_ERR_DIGEST_ALGO))?;
    let ps_len = em_len - salt.len() - h_len - 2;
    let mut db = vec![0u8; ps_len];
    db.push(1);
    db.extend_from_slice(&salt);
    let db_mask = mgf1(&h, em_len - h_len - 1, &hash_name)?;
    let mut masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    let unused = 8 * em_len - em_bits;
    if unused != 0 {
        masked_db[0] &= 0xff >> unused;
    }
    let mut em = masked_db;
    em.extend_from_slice(&h);
    em.push(0xbc);
    Ok(em)
}

fn pss_verify(data: *mut sexp::gcry_sexp, em: &[u8], em_bits: usize) -> Result<(), u32> {
    let (hash_name, hash) =
        signature_hash(data)?.ok_or_else(|| encoding::err(error::GPG_ERR_INV_OBJ))?;
    let h_len = hash.len();
    let em_len = em_bits.div_ceil(8);
    if em.len() != em_len || em_len < h_len + 2 || em.last().copied() != Some(0xbc) {
        return Err(encoding::err(error::GPG_ERR_BAD_SIGNATURE));
    }
    let (masked_db, h_and_trailer) = em.split_at(em_len - h_len - 1);
    let h = &h_and_trailer[..h_len];
    let unused = 8 * em_len - em_bits;
    if unused != 0 && masked_db[0] & (!0u8 << (8 - unused)) != 0 {
        return Err(encoding::err(error::GPG_ERR_BAD_SIGNATURE));
    }
    let db_mask = mgf1(h, em_len - h_len - 1, &hash_name)?;
    let mut db: Vec<u8> = masked_db
        .iter()
        .zip(db_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    if unused != 0 {
        db[0] &= 0xff >> unused;
    }
    let Some(pos) = db.iter().position(|byte| *byte == 1) else {
        return Err(encoding::err(error::GPG_ERR_BAD_SIGNATURE));
    };
    if db[..pos].iter().any(|byte| *byte != 0) {
        return Err(encoding::err(error::GPG_ERR_BAD_SIGNATURE));
    }
    let salt = &db[pos + 1..];
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(&hash);
    m_prime.extend_from_slice(salt);
    let expected = digest_once_name(&hash_name, &m_prime)
        .ok_or_else(|| encoding::err(error::GPG_ERR_DIGEST_ALGO))?;
    if expected == h {
        Ok(())
    } else {
        Err(encoding::err(error::GPG_ERR_BAD_SIGNATURE))
    }
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
    let k = key.bytes();
    let em = if encoding::has_flag(data, "oaep") {
        match oaep_encode(data, k) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else if encoding::has_flag(data, "pkcs1") {
        match pkcs1_encrypt_encode(data, k) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        let value = encoding::token_mpz(data, "value")
            .or_else(|| encoding::data_value(data).map(|bytes| Mpz::from_be(&bytes)));
        let Some(value) = value else {
            return encoding::err(error::GPG_ERR_INV_OBJ);
        };
        value.to_be()
    };
    let c = rsa_public(&key, &em);
    let text = format!("(enc-val (rsa (a {})))", encoding::hex_atom(&c));
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
    let key = match parse_key(skey) {
        Ok(key) => key,
        Err(err) => return err,
    };
    let c = match encoding::token_bytes_from_mpi(data, "a") {
        Some(value) => value,
        None => return encoding::err(error::GPG_ERR_INV_OBJ),
    };
    let em = match rsa_private(&key, &c) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let out = if encoding::has_flag(data, "oaep") {
        match oaep_decode(data, &em) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else if encoding::has_flag(data, "pkcs1") {
        match pkcs1_decrypt_decode(&em) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        let value = Mpz::from_be(&em).to_be();
        let text = format!("{}", encoding::hex_atom(&value));
        match encoding::build_sexp(&text) {
            Ok(sexp) => unsafe {
                *result = sexp;
                return 0;
            },
            Err(err) => return err,
        }
    };
    let text = format!("(value {})", encoding::hex_atom(&out));
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
    let em = if encoding::has_flag(data, "pss") {
        match pss_encode(data, key.n.bits().saturating_sub(1)) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else if encoding::has_flag(data, "pkcs1") {
        match pkcs1_sign_encode(data, key.bytes()) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else if let Some((_name, hash)) = match signature_hash(data) {
        Ok(value) => value,
        Err(err) => return err,
    } {
        hash
    } else {
        encoding::data_value(data).unwrap_or_default()
    };
    let sig = match rsa_private(&key, &em) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let text = format!("(sig-val (rsa (s {})))", encoding::hex_atom(&sig));
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
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
    let sig = match encoding::token_bytes_from_mpi(sigval, "s") {
        Some(value) => value,
        None => return encoding::err(error::GPG_ERR_INV_OBJ),
    };
    let em = rsa_public(&key, &sig);
    if encoding::has_flag(data, "pss") {
        return match pss_verify(
            data,
            &em[em.len() - key.n.bits().saturating_sub(1).div_ceil(8)..],
            key.n.bits().saturating_sub(1),
        ) {
            Ok(()) => 0,
            Err(err) => err,
        };
    }
    let expected = if encoding::has_flag(data, "pkcs1") {
        match pkcs1_sign_encode(data, key.bytes()) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else if let Some((_name, hash)) = match signature_hash(data) {
        Ok(value) => value,
        Err(err) => return err,
    } {
        left_pad(hash, key.bytes())
    } else {
        left_pad(encoding::data_value(data).unwrap_or_default(), key.bytes())
    };
    if em == expected {
        0
    } else {
        encoding::err(error::GPG_ERR_BAD_SIGNATURE)
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

fn random_prime(bits: usize, e: &Mpz) -> Mpz {
    loop {
        let mut bytes = vec![0u8; bits.div_ceil(8).max(1)];
        os_rng::fill_random(&mut bytes);
        bytes[0] |= 1 << ((bits - 1) % 8);
        if let Some(last) = bytes.last_mut() {
            *last |= 1;
        }
        let p = Mpz::from_be(&bytes).next_prime();
        if p.bits() != bits {
            continue;
        }
        if p.sub_ui(1).gcd(e).is_one() {
            return p;
        }
    }
}

fn find_x931_prime(first: &Mpz) -> Mpz {
    let mut prime = if first.rem_ui(2) == 0 {
        first.add_ui(1)
    } else {
        first.clone()
    };
    while !prime.probable_prime() {
        prime = prime.add_ui(2);
    }
    prime
}

fn derive_x931_prime(xp: &Mpz, xp1: &Mpz, xp2: &Mpz, e: &Mpz) -> Option<Mpz> {
    if e.rem_ui(2) == 0 {
        return None;
    }
    let p1 = find_x931_prime(xp1);
    let p2 = find_x931_prime(xp2);
    let p1p2 = p1.mul(&p2);
    let r1_left = p2.invert(&p1)?.mul(&p2);
    let r1_right = p1.invert(&p2)?.mul(&p1);
    let mut r1 = r1_left.sub(&r1_right);
    if r1.cmp_ui(0) < 0 {
        r1 = r1.add(&p1p2);
    }
    let mut yp0 = xp.add(&r1.mod_sub(xp, &p1p2));
    if yp0.cmp(xp) < 0 {
        yp0 = yp0.add(&p1p2);
    }
    let step = p1p2.sub_ui(1);
    let mut candidate_minus_one = yp0.sub_ui(1);
    loop {
        let gcd_is_one = e.gcd(&candidate_minus_one).is_one();
        let candidate = candidate_minus_one.add_ui(1);
        if gcd_is_one && candidate.probable_prime() {
            return Some(candidate);
        }
        candidate_minus_one = candidate.add(&step);
    }
}

fn derived_x931_key(nbits: usize, e: &Mpz, spec: *mut sexp::gcry_sexp) -> Option<(RsaKey, bool)> {
    if nbits < 1024 || nbits % 256 != 0 || e.cmp_ui(3) < 0 || e.rem_ui(2) == 0 {
        return None;
    }
    let derive = encoding::find_token(spec, "derive-parms");
    if derive.is_null() {
        return None;
    }
    let params = (
        encoding::token_mpz(derive, "Xp1"),
        encoding::token_mpz(derive, "Xp2"),
        encoding::token_mpz(derive, "Xp"),
        encoding::token_mpz(derive, "Xq1"),
        encoding::token_mpz(derive, "Xq2"),
        encoding::token_mpz(derive, "Xq"),
    );
    sexp::gcry_sexp_release(derive);
    let (Some(xp1), Some(xp2), Some(xp), Some(xq1), Some(xq2), Some(xq)) = params else {
        return None;
    };
    let mut p = derive_x931_prime(&xp, &xp1, &xp2, e)?;
    let mut q = derive_x931_prime(&xq, &xq1, &xq2, e)?;
    let mut swapped = false;
    if p.cmp(&q) > 0 {
        std::mem::swap(&mut p, &mut q);
        swapped = true;
    }
    let n = p.mul(&q);
    let pm1 = p.sub_ui(1);
    let qm1 = q.sub_ui(1);
    let phi = pm1.mul(&qm1);
    let lcm_divisor = pm1.gcd(&qm1);
    let (lcm, _) = phi.div_rem(&lcm_divisor);
    let d = e.invert(&lcm)?;
    let u = p.invert(&q)?;
    Some((
        RsaKey {
            n,
            e: e.clone(),
            d: Some(d),
            p: Some(p),
            q: Some(q),
            u: Some(u),
        },
        swapped,
    ))
}

pub(crate) fn genkey(result: *mut *mut sexp::gcry_sexp, spec: *mut sexp::gcry_sexp) -> u32 {
    let nbits = encoding::token_string(spec, "nbits")
        .and_then(|value| value.parse::<usize>().ok())
        .or_else(|| {
            encoding::token_mpz(spec, "nbits").map(|value| {
                value
                    .to_be()
                    .iter()
                    .fold(0usize, |a, b| (a << 8) | *b as usize)
            })
        })
        .unwrap_or(2048);
    let e = encoding::token_string(spec, "rsa-use-e")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .map(Mpz::from_ui)
        .unwrap_or_else(|| Mpz::from_ui(65537));
    if let Some((key, swapped)) = derived_x931_key(nbits, &e, spec) {
        let misc = if swapped {
            " (misc-key-info (p-q-swapped))"
        } else {
            ""
        };
        let text = format!(
            "(key-data (public-key (rsa (n {})(e {}))) (private-key (rsa (n {})(e {})(d {})(p {})(q {})(u {}))){} )",
            encoding::hex_atom(&key.n.to_be()),
            encoding::hex_atom(&key.e.to_be()),
            encoding::hex_atom(&key.n.to_be()),
            encoding::hex_atom(&key.e.to_be()),
            encoding::hex_atom(&key.d.as_ref().unwrap().to_be()),
            encoding::hex_atom(&key.p.as_ref().unwrap().to_be()),
            encoding::hex_atom(&key.q.as_ref().unwrap().to_be()),
            encoding::hex_atom(&key.u.as_ref().unwrap().to_be()),
            misc
        );
        return match encoding::build_sexp(&text) {
            Ok(sexp) => unsafe {
                *result = sexp;
                0
            },
            Err(err) => err,
        };
    }
    let (p, q) = if let Some(test) = {
        let found = encoding::find_token(spec, "test-parms");
        if found.is_null() { None } else { Some(found) }
    } {
        let p = encoding::token_mpz(test, "p");
        let q = encoding::token_mpz(test, "q");
        sexp::gcry_sexp_release(test);
        match (p, q) {
            (Some(p), Some(q)) => (p, q),
            _ => return encoding::err(error::GPG_ERR_INV_OBJ),
        }
    } else {
        (
            random_prime(nbits / 2, &e),
            random_prime(nbits - nbits / 2, &e),
        )
    };
    let n = p.mul(&q);
    let phi = p.sub_ui(1).mul(&q.sub_ui(1));
    let Some(d) = e.invert(&phi) else {
        return encoding::err(error::GPG_ERR_BAD_SECKEY);
    };
    let u = p.invert(&q).unwrap_or_else(|| Mpz::from_ui(0));
    let key = RsaKey {
        n,
        e,
        d: Some(d),
        p: Some(p),
        q: Some(q),
        u: Some(u),
    };
    let text = format!(
        "(key-data (public-key (rsa (n {})(e {}))) (private-key (rsa (n {})(e {})(d {})(p {})(q {})(u {}))))",
        encoding::hex_atom(&key.n.to_be()),
        encoding::hex_atom(&key.e.to_be()),
        encoding::hex_atom(&key.n.to_be()),
        encoding::hex_atom(&key.e.to_be()),
        encoding::hex_atom(&key.d.as_ref().unwrap().to_be()),
        encoding::hex_atom(&key.p.as_ref().unwrap().to_be()),
        encoding::hex_atom(&key.q.as_ref().unwrap().to_be()),
        encoding::hex_atom(&key.u.as_ref().unwrap().to_be())
    );
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
}

pub(crate) fn testkey(key: *mut sexp::gcry_sexp) -> u32 {
    let key = match parse_key(key) {
        Ok(key) => key,
        Err(err) => return err,
    };
    let Some(d) = &key.d else {
        return encoding::err(error::GPG_ERR_NO_SECKEY);
    };
    if key.p.is_none() || key.q.is_none() || key.u.is_none() {
        return encoding::err(error::GPG_ERR_NO_OBJ);
    }
    let sample = random_mpz_below(&key.n);
    let round = sample.powm(&key.e, &key.n).powm_sec(d, &key.n);
    if sample.cmp(&round) == 0 {
        0
    } else {
        encoding::err(error::GPG_ERR_BAD_SECKEY)
    }
}

pub(crate) fn get_nbits(key: *mut sexp::gcry_sexp) -> u32 {
    parse_key(key).map(|key| key.n.bits() as u32).unwrap_or(0)
}

pub(crate) fn public_key(key: *mut sexp::gcry_sexp) -> Result<RsaKey, u32> {
    parse_key(key).map(|key| key.public())
}
