use std::ffi::{c_char, c_int};
use std::ptr::null_mut;

use crate::error;
use crate::mpi::{self, GCRYMPI_FMT_USG, gcry_mpi};
use crate::sexp;

use super::{
    GCRY_PK_ELG, GCRY_PK_ELG_E, OwnedMpi, build_sexp, bytes_to_mpi, find_first_token, find_token,
    has_flags_list, token_mpi, token_usize,
};

pub(crate) const NAME: &[u8] = b"elg\0";
const ALIASES: &[&[u8]] = &[b"elg\0", b"openpgp-elg\0", b"openpgp-elg-sig\0"];

const TOK_P: &[u8] = b"p\0";
const TOK_G: &[u8] = b"g\0";
const TOK_Y: &[u8] = b"y\0";
const TOK_X: &[u8] = b"x\0";
const TOK_A: &[u8] = b"a\0";
const TOK_B: &[u8] = b"b\0";
const TOK_R: &[u8] = b"r\0";
const TOK_S: &[u8] = b"s\0";
const TOK_VALUE: &[u8] = b"value\0";

struct ElgKey {
    p: OwnedMpi,
    g: OwnedMpi,
    y: OwnedMpi,
    x: Option<OwnedMpi>,
}

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    matches!(algo, GCRY_PK_ELG | GCRY_PK_ELG_E)
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}

pub(crate) fn map_name(name: &str) -> Option<c_int> {
    ALIASES
        .iter()
        .map(|alias| std::str::from_utf8(&alias[..alias.len() - 1]).expect("alias utf-8"))
        .find(|alias| alias.eq_ignore_ascii_case(name))
        .map(|_| GCRY_PK_ELG)
}

pub(crate) fn has_key_token(key: *mut sexp::gcry_sexp) -> bool {
    !find_first_token(key, ALIASES).is_null()
}

fn parse_key(key: *mut sexp::gcry_sexp, secret: bool) -> Result<ElgKey, u32> {
    let p = token_mpi(key, TOK_P, GCRYMPI_FMT_USG);
    let g = token_mpi(key, TOK_G, GCRYMPI_FMT_USG);
    let y = token_mpi(key, TOK_Y, GCRYMPI_FMT_USG);
    if p.is_null() || g.is_null() || y.is_null() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_NO_OBJ));
    }
    let x = if secret {
        let value = token_mpi(key, TOK_X, GCRYMPI_FMT_USG);
        let value = if value.is_null() {
            let found = find_token(key, TOK_X);
            let Some(bytes) = super::nth_data_bytes(found.raw(), 1) else {
                return Err(error::gcry_error_from_code(error::GPG_ERR_NO_OBJ));
            };
            OwnedMpi::new(bytes_to_mpi(&bytes, false))
        } else {
            value
        };
        if value.is_null() {
            return Err(error::gcry_error_from_code(error::GPG_ERR_NO_OBJ));
        }
        Some(value)
    } else {
        None
    };
    Ok(ElgKey { p, g, y, x })
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

fn mpi_random_less_than(modulus: *mut gcry_mpi) -> OwnedMpi {
    let bits = mpi::gcry_mpi_get_nbits(modulus);
    loop {
        let candidate = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::gcry_mpi_randomize(candidate.raw(), bits, crate::random::GCRY_WEAK_RANDOM);
        mpi::arith::gcry_mpi_mod(candidate.raw(), candidate.raw(), modulus);
        if !mpi_is_zero(candidate.raw()) {
            return candidate;
        }
    }
}

fn parse_data_value(data: *mut sexp::gcry_sexp) -> Result<OwnedMpi, u32> {
    let value = token_mpi(data, TOK_VALUE, GCRYMPI_FMT_USG);
    if !value.is_null() {
        return Ok(value);
    }
    let list = find_token(data, TOK_VALUE);
    let bytes = super::nth_data_bytes(list.raw(), 1)
        .ok_or(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))?;
    Ok(OwnedMpi::new(bytes_to_mpi(&bytes, false)))
}

pub(crate) fn encrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    let key = match parse_key(pkey, false) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let input = match parse_data_value(data) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let k = mpi_random_less_than(key.p.raw());
    let a = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let s = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let b = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_powm(a.raw(), key.g.raw(), k.raw(), key.p.raw());
    mpi::arith::gcry_mpi_powm(s.raw(), key.y.raw(), k.raw(), key.p.raw());
    mpi::arith::gcry_mpi_mulm(b.raw(), s.raw(), input.raw(), key.p.raw());

    match build_sexp("(enc-val(elg(a%M)(b%M)))", &[a.raw() as usize, b.raw() as usize]) {
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
    let key = match parse_key(skey, true) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let a = token_mpi(data, TOK_A, GCRYMPI_FMT_USG);
    let b = token_mpi(data, TOK_B, GCRYMPI_FMT_USG);
    if a.is_null() || b.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    }
    let a = a;
    let b = b;

    let s = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let sinv = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let plain = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_powm(
        s.raw(),
        a.raw(),
        key.x.as_ref().expect("secret key x").raw(),
        key.p.raw(),
    );
    if mpi::arith::gcry_mpi_invm(sinv.raw(), s.raw(), key.p.raw()) == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }
    mpi::arith::gcry_mpi_mulm(plain.raw(), b.raw(), sinv.raw(), key.p.raw());

    let built = if has_flags_list(data) {
        build_sexp("(value %m)", &[plain.raw() as usize])
    } else {
        build_sexp("%m", &[plain.raw() as usize])
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
    let key = match parse_key(skey, true) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let input = match parse_data_value(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let p_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_sub_ui(p_minus_1.raw(), key.p.raw(), 1);

    loop {
        let k = mpi_random_less_than(p_minus_1.raw());
        let inv = OwnedMpi::new(mpi::gcry_mpi_new(0));
        if mpi::arith::gcry_mpi_invm(inv.raw(), k.raw(), p_minus_1.raw()) == 0 {
            continue;
        }

        let r = OwnedMpi::new(mpi::gcry_mpi_new(0));
        let xr = OwnedMpi::new(mpi::gcry_mpi_new(0));
        let diff = OwnedMpi::new(mpi::gcry_mpi_new(0));
        let s = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_powm(r.raw(), key.g.raw(), k.raw(), key.p.raw());
        mpi::arith::gcry_mpi_mulm(
            xr.raw(),
            key.x.as_ref().expect("secret key x").raw(),
            r.raw(),
            p_minus_1.raw(),
        );
        mpi::arith::gcry_mpi_subm(diff.raw(), input.raw(), xr.raw(), p_minus_1.raw());
        mpi::arith::gcry_mpi_mulm(s.raw(), diff.raw(), inv.raw(), p_minus_1.raw());
        match build_sexp("(sig-val(elg(r%M)(s%M)))", &[r.raw() as usize, s.raw() as usize]) {
            Ok(value) => {
                unsafe {
                    *result = value;
                }
                return 0;
            }
            Err(err) => return err,
        }
    }
}

pub(crate) fn verify(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    let key = match parse_key(pkey, false) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let input = match parse_data_value(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let r = token_mpi(sigval, TOK_R, GCRYMPI_FMT_USG);
    let s = token_mpi(sigval, TOK_S, GCRYMPI_FMT_USG);
    if r.is_null() || s.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }

    let left = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let yr = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let rs = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let right = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_powm(yr.raw(), key.y.raw(), r.raw(), key.p.raw());
    mpi::arith::gcry_mpi_powm(rs.raw(), r.raw(), s.raw(), key.p.raw());
    mpi::arith::gcry_mpi_mulm(left.raw(), yr.raw(), rs.raw(), key.p.raw());
    mpi::arith::gcry_mpi_powm(right.raw(), key.g.raw(), input.raw(), key.p.raw());
    if mpi_equal(left.raw(), right.raw()) {
        0
    } else {
        error::gcry_error_from_code(error::GPG_ERR_BAD_DATA)
    }
}

pub(crate) fn testkey(key: *mut sexp::gcry_sexp) -> u32 {
    let key = match parse_key(key, true) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let have_y = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_powm(
        have_y.raw(),
        key.g.raw(),
        key.x.as_ref().expect("secret key x").raw(),
        key.p.raw(),
    );
    if mpi_equal(have_y.raw(), key.y.raw()) {
        0
    } else {
        error::gcry_error_from_code(error::GPG_ERR_BAD_DATA)
    }
}

fn generate_domain(nbits: usize) -> Result<(OwnedMpi, OwnedMpi), u32> {
    let mut prime = null_mut();
    let rc = mpi::prime::gcry_prime_generate(
        &mut prime,
        nbits as _,
        0,
        null_mut(),
        None,
        null_mut(),
        crate::random::GCRY_WEAK_RANDOM,
        0,
    );
    if rc != 0 {
        return Err(rc);
    }
    let p = OwnedMpi::new(prime);
    let p_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_sub_ui(p_minus_1.raw(), p.raw(), 1);
    let g = loop {
        let candidate = mpi_random_less_than(p.raw());
        if mpi::gcry_mpi_cmp_ui(candidate.raw(), 1) > 0 {
            break candidate;
        }
    };
    Ok((p, g))
}

pub(crate) fn genkey(result: *mut *mut sexp::gcry_sexp, parms: *mut sexp::gcry_sexp) -> u32 {
    let nbits = match token_usize(parms, b"nbits\0") {
        Some(value) => value,
        None => return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ),
    };
    let (p, g) = match generate_domain(nbits) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let p_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_sub_ui(p_minus_1.raw(), p.raw(), 1);
    let xvalue = {
        let found = find_token(parms, b"xvalue\0");
        let raw = sexp::gcry_sexp_nth_mpi(found.raw(), 1, 0);
        if raw.is_null() {
            mpi_random_less_than(p_minus_1.raw())
        } else {
            let normalized = super::mpi_to_bytes(raw)
                .map(|value| bytes_to_mpi(&value, false))
                .unwrap_or(raw);
            if normalized != raw {
                mpi::gcry_mpi_release(raw);
            }
            OwnedMpi::new(normalized)
        }
    };
    if mpi_is_zero(xvalue.raw()) || mpi::gcry_mpi_cmp(xvalue.raw(), p_minus_1.raw()) >= 0 {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }
    let y = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_powm(y.raw(), g.raw(), xvalue.raw(), p.raw());
    match build_sexp(
        "(key-data(public-key(elg(p%M)(g%M)(y%M)))(private-key(elg(p%M)(g%M)(y%M)(x%M))))",
        &[
            p.raw() as usize,
            g.raw() as usize,
            y.raw() as usize,
            p.raw() as usize,
            g.raw() as usize,
            y.raw() as usize,
            xvalue.raw() as usize,
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

pub(crate) fn get_nbits(key: *mut sexp::gcry_sexp) -> u32 {
    let p = token_mpi(key, TOK_P, GCRYMPI_FMT_USG);
    if p.is_null() {
        0
    } else {
        mpi::gcry_mpi_get_nbits(p.raw())
    }
}

pub(crate) fn keygrip(key: *mut sexp::gcry_sexp) -> Option<[u8; super::KEYGRIP_LEN]> {
    super::generic_keygrip(key, &[TOK_P, TOK_G, TOK_Y])
}
