use std::ffi::{c_char, c_int};

use crate::digest::algorithms;
use crate::error;
use crate::mpi::Mpz;
use crate::os_rng;
use crate::sexp;

use super::encoding;

pub(crate) const NAME: &[u8] = b"dsa\0";

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    algo == 17
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}

struct DsaKey {
    p: Mpz,
    q: Mpz,
    g: Mpz,
    y: Mpz,
    x: Option<Mpz>,
}

fn dsa_part(key: *mut sexp::gcry_sexp) -> Option<*mut sexp::gcry_sexp> {
    let private = encoding::find_token(key, "private-key");
    if !private.is_null() {
        let dsa = encoding::find_token(private, "dsa");
        let dsa = if dsa.is_null() {
            encoding::find_token(private, "DSA")
        } else {
            dsa
        };
        sexp::gcry_sexp_release(private);
        if !dsa.is_null() {
            return Some(dsa);
        }
    }
    let dsa = encoding::find_token(key, "dsa");
    if !dsa.is_null() {
        return Some(dsa);
    }
    let dsa = encoding::find_token(key, "DSA");
    (!dsa.is_null()).then_some(dsa)
}

fn parse_key(key: *mut sexp::gcry_sexp) -> Result<DsaKey, u32> {
    let dsa = dsa_part(key).ok_or_else(|| encoding::err(error::GPG_ERR_BAD_PUBKEY))?;
    let parsed = (|| {
        Ok(DsaKey {
            p: encoding::token_mpz(dsa, "p").ok_or(error::GPG_ERR_BAD_PUBKEY)?,
            q: encoding::token_mpz(dsa, "q").ok_or(error::GPG_ERR_BAD_PUBKEY)?,
            g: encoding::token_mpz(dsa, "g").ok_or(error::GPG_ERR_BAD_PUBKEY)?,
            y: encoding::token_mpz(dsa, "y").ok_or(error::GPG_ERR_BAD_PUBKEY)?,
            x: encoding::token_mpz(dsa, "x"),
        })
    })();
    sexp::gcry_sexp_release(dsa);
    parsed.map_err(encoding::err)
}

fn dsa_domain_valid(p: &Mpz, q: &Mpz, g: &Mpz) -> bool {
    if p.bits() < 2 * q.bits() || q.bits() < 160 {
        return false;
    }
    if !p.probable_prime() || !q.probable_prime() {
        return false;
    }
    if !p.sub_ui(1).modulo(q).is_zero() {
        return false;
    }
    if g.cmp_ui(1) <= 0 || g.cmp(p) >= 0 {
        return false;
    }
    g.powm(q, p).is_one()
}

pub(crate) fn testkey(key: *mut sexp::gcry_sexp) -> u32 {
    let key = match parse_key(key) {
        Ok(key) => key,
        Err(err) => return err,
    };
    let Some(x) = key.x.as_ref() else {
        return encoding::err(error::GPG_ERR_NO_SECKEY);
    };
    if x.is_zero() || x.cmp(&key.q) >= 0 || !dsa_domain_valid(&key.p, &key.q, &key.g) {
        return encoding::err(error::GPG_ERR_BAD_SECKEY);
    }
    if key.g.powm_sec(x, &key.p).cmp(&key.y) == 0 {
        0
    } else {
        encoding::err(error::GPG_ERR_BAD_SECKEY)
    }
}

fn random_below(q: &Mpz) -> Mpz {
    let len = q.bits().div_ceil(8).max(1);
    loop {
        let mut bytes = vec![0u8; len];
        os_rng::fill_random(&mut bytes);
        let value = Mpz::from_be(&bytes).modulo(q);
        if !value.is_zero() {
            return value;
        }
    }
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

fn validate_sign_data(data: *mut sexp::gcry_sexp) -> Result<(), u32> {
    let flags = encoding::flag_atoms(data);
    for flag in &flags {
        if !matches!(
            flag.as_str(),
            "raw" | "rfc6979" | "pkcs1" | "pkcs1-raw" | "pss" | "oaep"
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
    if encoding::has_token(data, "hash")
        && !encoding::has_flag(data, "rfc6979")
        && !encoding::has_flag(data, "raw")
    {
        return Err(encoding::err(error::GPG_ERR_CONFLICT));
    }
    Ok(())
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
    let hash_parts = encoding::hash_value(data);
    let hash = hash_parts
        .as_ref()
        .map(|(_, hash)| hash.clone())
        .or_else(|| encoding::data_value(data))
        .unwrap_or_default();
    let z = bits2int(&hash, &key.q);
    let supplied_k = {
        let bytes = encoding::label(data);
        (!bytes.is_empty()).then(|| Mpz::from_be(&bytes))
    };
    for _ in 0..128 {
        let k = if let Some(k) = supplied_k.clone() {
            k
        } else if encoding::has_flag(data, "rfc6979") {
            let Some((hash_name, hash)) = hash_parts.as_ref() else {
                return encoding::err(error::GPG_ERR_CONFLICT);
            };
            let Some(k) = encoding::rfc6979_nonce(&key.q, x, hash_name, hash) else {
                return encoding::err(error::GPG_ERR_DIGEST_ALGO);
            };
            k
        } else {
            random_below(&key.q)
        };
        let r = key.g.powm_sec(&k, &key.p).modulo(&key.q);
        if r.is_zero() {
            continue;
        }
        let Some(kinv) = k.invert(&key.q) else {
            continue;
        };
        let s = kinv.mod_mul(&z.mod_add(&x.mod_mul(&r, &key.q), &key.q), &key.q);
        if s.is_zero() {
            continue;
        }
        let text = format!(
            "(sig-val (dsa (r {})(s {})))",
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
    if r.is_zero() || r.cmp(&key.q) >= 0 || s.is_zero() || s.cmp(&key.q) >= 0 {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    }
    let hash = encoding::hash_value(data)
        .map(|(_, hash)| hash)
        .or_else(|| encoding::data_value(data))
        .unwrap_or_default();
    let z = bits2int(&hash, &key.q);
    let Some(w) = s.invert(&key.q) else {
        return encoding::err(error::GPG_ERR_BAD_SIGNATURE);
    };
    let u1 = z.mod_mul(&w, &key.q);
    let u2 = r.mod_mul(&w, &key.q);
    let v = key
        .g
        .powm(&u1, &key.p)
        .mod_mul(&key.y.powm(&u2, &key.p), &key.p)
        .modulo(&key.q);
    if v.cmp(&r) == 0 {
        0
    } else {
        encoding::err(error::GPG_ERR_BAD_SIGNATURE)
    }
}

fn pow2(bits: usize) -> Mpz {
    Mpz::from_ui(1).shl(bits)
}

fn clear_high_bits(value: &Mpz, bits: usize) -> Mpz {
    value.modulo(&pow2(bits))
}

fn set_highbit(value: &Mpz, bit: usize) -> Mpz {
    value.modulo(&pow2(bit + 1)).bit_or(&pow2(bit))
}

fn increment_be(value: &mut [u8]) {
    for byte in value.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn hash_once(algo: c_int, data: &[u8]) -> Option<Vec<u8>> {
    algorithms::digest_once(algo, data)
}

struct FipsDomain {
    p: Mpz,
    q: Mpz,
    g: Mpz,
    seed: Vec<u8>,
    counter: usize,
    h: Mpz,
}

fn fips_generator(p: &Mpz, q: &Mpz) -> (Mpz, Mpz) {
    let e = p.sub_ui(1).div_rem(q).0;
    let mut h = Mpz::from_ui(1);
    loop {
        h = h.add_ui(1);
        let g = h.powm(&e, p);
        if !g.is_one() {
            return (g, h);
        }
    }
}

fn fips186_2_domain(seed: &[u8]) -> Option<FipsDomain> {
    if seed.len() < 20 {
        return None;
    }
    let pbits = 1024usize;
    let qbits = 160usize;
    let mut seed_plus = seed.to_vec();

    increment_be(&mut seed_plus);
    let first = hash_once(algorithms::GCRY_MD_SHA1, seed)?;
    let second = hash_once(algorithms::GCRY_MD_SHA1, &seed_plus)?;
    let u = first
        .iter()
        .zip(second.iter())
        .map(|(left, right)| left ^ right)
        .collect::<Vec<_>>();
    let q = set_highbit(&Mpz::from_be(&u), qbits - 1).bit_or(&Mpz::from_ui(1));
    if !q.probable_prime() {
        return None;
    }

    let value_n = (pbits - 1) / qbits;
    let value_b = (pbits - 1) - value_n * qbits;
    let mut counter = 0usize;
    loop {
        let mut w = Mpz::from_ui(0);
        for k in 0..=value_n {
            increment_be(&mut seed_plus);
            let digest = hash_once(algorithms::GCRY_MD_SHA1, &seed_plus)?;
            let mut part = Mpz::from_be(&digest);
            if k == value_n {
                part = clear_high_bits(&part, value_b);
            }
            w = w.add(&part.shl(k * qbits));
        }
        let x = pow2(pbits - 1).add(&w);
        let c = x.modulo(&q.mul_ui(2));
        let p = x.sub(&c.sub_ui(1));
        if p.bits() >= pbits - 1 && p.probable_prime() {
            let (g, h) = fips_generator(&p, &q);
            return Some(FipsDomain {
                p,
                q,
                g,
                seed: seed.to_vec(),
                counter,
                h,
            });
        }
        counter += 1;
        if counter >= 4096 {
            return None;
        }
    }
}

fn fips186_3_domain(nbits: usize, qbits: usize, seed: &[u8]) -> Option<FipsDomain> {
    let algo = match (nbits, qbits) {
        (2048, 224) => algorithms::GCRY_MD_SHA224,
        (2048, 256) | (3072, 256) => algorithms::GCRY_MD_SHA256,
        _ => return None,
    };
    if seed.len() < qbits / 8 {
        return None;
    }
    let mut u = hash_once(algo, seed)?;
    if u.len() != qbits / 8 {
        return None;
    }
    if u.last().is_some_and(|byte| byte & 1 == 0) {
        increment_be(&mut u);
    }
    let q = set_highbit(&Mpz::from_be(&u), qbits - 1);
    if !q.probable_prime() {
        return None;
    }

    let value_n = nbits.div_ceil(qbits) - 1;
    let value_b = nbits - 1 - value_n * qbits;
    let mut seed_plus = seed.to_vec();
    let mut counter = 0usize;
    loop {
        let mut w = Mpz::from_ui(0);
        for j in 0..=value_n {
            increment_be(&mut seed_plus);
            let digest = hash_once(algo, &seed_plus)?;
            let mut part = Mpz::from_be(&digest);
            if j == value_n {
                part = clear_high_bits(&part, value_b);
            }
            w = w.add(&part.shl(j * qbits));
        }
        let x = pow2(nbits - 1).add(&w);
        let c = x.modulo(&q.mul_ui(2));
        let p = x.sub(&c.sub_ui(1));
        if p.bits() >= nbits - 1 && p.probable_prime() {
            let (g, h) = fips_generator(&p, &q);
            return Some(FipsDomain {
                p,
                q,
                g,
                seed: seed.to_vec(),
                counter,
                h,
            });
        }
        counter += 1;
        if counter >= 4 * nbits {
            return None;
        }
    }
}

fn derive_seed(spec: *mut sexp::gcry_sexp) -> Option<Vec<u8>> {
    let derive = encoding::find_token(spec, "derive-parms");
    if derive.is_null() {
        return None;
    }
    let seed = encoding::token_bytes_from_mpi(derive, "seed");
    sexp::gcry_sexp_release(derive);
    seed
}

fn parsed_bits(spec: *mut sexp::gcry_sexp, token: &str) -> Option<usize> {
    encoding::token_string(spec, token)
        .and_then(|value| value.parse::<usize>().ok())
        .or_else(|| {
            encoding::token_mpz(spec, token)
                .map(|v| v.to_be().iter().fold(0usize, |a, b| (a << 8) | *b as usize))
        })
}

fn default_qbits(nbits: usize) -> Option<usize> {
    if (512..=1024).contains(&nbits) {
        Some(160)
    } else {
        match nbits {
            2048 => Some(224),
            3072 => Some(256),
            7680 => Some(384),
            15360 => Some(512),
            _ => None,
        }
    }
}

fn requested_sizes(spec: *mut sexp::gcry_sexp, fips186_2: bool) -> Option<(usize, usize)> {
    let nbits = parsed_bits(spec, "nbits").unwrap_or(if fips186_2 { 1024 } else { 2048 });
    let qbits = parsed_bits(spec, "qbits").or_else(|| default_qbits(nbits))?;
    if fips186_2 && (nbits != 1024 || qbits != 160) {
        return None;
    }
    if qbits < 160 || qbits > 512 || qbits % 8 != 0 || nbits < 2 * qbits || nbits > 15360 {
        return None;
    }
    Some((nbits, qbits))
}

fn random_bits(bits: usize, odd: bool) -> Mpz {
    let len = bits.div_ceil(8).max(1);
    let mut bytes = vec![0u8; len];
    os_rng::fill_random(&mut bytes);
    let excess = len * 8 - bits;
    if excess != 0 {
        bytes[0] &= 0xff >> excess;
    }
    bytes[0] |= 1 << (7 - excess);
    if odd {
        if let Some(last) = bytes.last_mut() {
            *last |= 1;
        }
    } else if let Some(last) = bytes.last_mut() {
        *last &= !1;
    }
    Mpz::from_be(&bytes)
}

fn random_prime_bits(bits: usize) -> Mpz {
    loop {
        let candidate = random_bits(bits, true);
        let prime = candidate.next_prime();
        if prime.bits() == bits {
            return prime;
        }
    }
}

fn has_small_factor(value: &Mpz) -> bool {
    const SMALL_PRIMES: &[usize] = &[
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
    ];
    SMALL_PRIMES
        .iter()
        .any(|prime| value.rem_ui(*prime as _) == 0)
}

fn generated_domain(nbits: usize, qbits: usize) -> Option<(Mpz, Mpz, Mpz)> {
    let rbits = nbits.checked_sub(qbits)?;
    for _ in 0..128 {
        let q = random_prime_bits(qbits);
        let mut r = random_bits(rbits, false);
        for _ in 0..(16 * nbits).max(4096) {
            let p = r.mul(&q).add_ui(1);
            match p.bits().cmp(&nbits) {
                std::cmp::Ordering::Greater => break,
                std::cmp::Ordering::Less => {
                    r = r.add_ui(2);
                    continue;
                }
                std::cmp::Ordering::Equal => {}
            }
            if !has_small_factor(&p) && p.probable_prime() {
                let (g, _) = fips_generator(&p, &q);
                return Some((p, q, g));
            }
            r = r.add_ui(2);
        }
    }
    None
}

fn build_key(
    result: *mut *mut sexp::gcry_sexp,
    p: &Mpz,
    q: &Mpz,
    g: &Mpz,
    x: &Mpz,
    seed_info: Option<&FipsDomain>,
) -> u32 {
    let y = g.powm_sec(x, p);
    let misc = seed_info
        .map(|info| {
            format!(
                " (misc-key-info (seed-values (counter {})(seed {})(h {})))",
                encoding::string_atom(&info.counter.to_string()),
                encoding::hex_atom(&info.seed),
                encoding::hex_atom(&info.h.to_be())
            )
        })
        .unwrap_or_default();
    let text = format!(
        "(key-data (public-key (dsa (p {})(q {})(g {})(y {}))) (private-key (dsa (p {})(q {})(g {})(y {})(x {}))){} )",
        encoding::hex_atom(&p.to_be()),
        encoding::hex_atom(&q.to_be()),
        encoding::hex_atom(&g.to_be()),
        encoding::hex_atom(&y.to_be()),
        encoding::hex_atom(&p.to_be()),
        encoding::hex_atom(&q.to_be()),
        encoding::hex_atom(&g.to_be()),
        encoding::hex_atom(&y.to_be()),
        encoding::hex_atom(&x.to_be()),
        misc
    );
    match encoding::build_sexp(&text) {
        Ok(sexp) => unsafe {
            *result = sexp;
            0
        },
        Err(err) => err,
    }
}

pub(crate) fn genkey(result: *mut *mut sexp::gcry_sexp, spec: *mut sexp::gcry_sexp) -> u32 {
    let use_fips186_2 = encoding::has_token(spec, "use-fips186-2");
    let use_fips186 = encoding::has_token(spec, "use-fips186") || use_fips186_2;
    if use_fips186 {
        let Some((nbits, qbits)) = requested_sizes(spec, use_fips186_2) else {
            return encoding::err(error::GPG_ERR_INV_VALUE);
        };
        if let Some(seed) = derive_seed(spec) {
            let Some(info) = (if use_fips186_2 {
                fips186_2_domain(&seed)
            } else {
                fips186_3_domain(nbits, qbits, &seed)
            }) else {
                return encoding::err(error::GPG_ERR_INV_VALUE);
            };
            if info.p.bits() != nbits || info.q.bits() != qbits {
                return encoding::err(error::GPG_ERR_INV_VALUE);
            }
            let x = random_below(&info.q);
            return build_key(result, &info.p, &info.q, &info.g, &x, Some(&info));
        }
    }

    let (p, q, g) = if let Some(domain) = {
        let found = encoding::find_token(spec, "domain");
        if found.is_null() { None } else { Some(found) }
    } {
        let p = encoding::token_mpz(domain, "p");
        let q = encoding::token_mpz(domain, "q");
        let g = encoding::token_mpz(domain, "g");
        sexp::gcry_sexp_release(domain);
        match (p, q, g) {
            (Some(p), Some(q), Some(g)) => {
                if let Some(nbits) = parsed_bits(spec, "nbits") {
                    if p.bits() != nbits {
                        return encoding::err(error::GPG_ERR_INV_VALUE);
                    }
                }
                if let Some(qbits) = parsed_bits(spec, "qbits") {
                    if q.bits() != qbits {
                        return encoding::err(error::GPG_ERR_INV_VALUE);
                    }
                }
                (p, q, g)
            }
            _ => return encoding::err(error::GPG_ERR_INV_OBJ),
        }
    } else {
        let Some((nbits, qbits)) = requested_sizes(spec, false) else {
            return encoding::err(error::GPG_ERR_INV_VALUE);
        };
        let Some(domain) = generated_domain(nbits, qbits) else {
            return encoding::err(error::GPG_ERR_GENERAL);
        };
        domain
    };
    let x = random_below(&q);
    build_key(result, &p, &q, &g, &x, None)
}

pub(crate) fn get_nbits(key: *mut sexp::gcry_sexp) -> u32 {
    parse_key(key).map(|key| key.p.bits() as u32).unwrap_or(0)
}
