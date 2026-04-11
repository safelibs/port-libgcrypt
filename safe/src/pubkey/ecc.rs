use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::ptr::{null, null_mut};

use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha512};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::context;
use crate::error;
use crate::mpi::{self, GCRYMPI_FMT_OPAQUE, GCRYMPI_FMT_USG, gcry_mpi};
use crate::random;
use crate::sexp;

use super::encoding;
use super::{
    KEYGRIP_LEN, OwnedMpi, OwnedSexp, build_sexp, bytes_to_mpi, dsa, find_first_token,
    find_token_one, flag_present, mpi_to_bytes, ptr_to_arg, token_mpi, token_present,
    token_string_value,
};

pub(crate) const NAME: &[u8] = b"ecc\0";
const ALIASES: &[&[u8]] = &[b"ecc\0", b"ecdsa\0", b"ecdh\0", b"eddsa\0"];

const TOK_PRIVATE_KEY: &[u8] = b"private-key\0";
const TOK_PUBLIC_KEY: &[u8] = b"public-key\0";
const TOK_D: &[u8] = b"d\0";
const TOK_E: &[u8] = b"e\0";
const TOK_G: &[u8] = b"g\0";
const TOK_N: &[u8] = b"n\0";
const TOK_Q: &[u8] = b"q\0";
const TOK_Q_EDDSA: &[u8] = b"q@eddsa\0";
const TOK_R: &[u8] = b"r\0";
const TOK_S: &[u8] = b"s\0";

const GPG_ERR_NO_SECKEY: u32 = 17;
const GPG_ERR_BROKEN_PUBKEY: u32 = 195;
const ED25519_KEYGRIP_A: &[u8] = &[0x01];
const ED25519_KEYGRIP_B: &[u8] = &[
    0x2d, 0xfc, 0x93, 0x11, 0xd4, 0x90, 0x01, 0x8c, 0x73, 0x38, 0xbf, 0x86, 0x88, 0x86, 0x17,
    0x67, 0xff, 0x8f, 0xf5, 0xb2, 0xbe, 0xbe, 0x27, 0x54, 0x8a, 0x14, 0xb2, 0x35, 0xec, 0xa6,
    0x87, 0x4a,
];
const CURVE25519_KEYGRIP_G: &[u8] = &[
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x09, 0x20, 0xae, 0x19, 0xa1, 0xb8, 0xa0, 0x86, 0xb4, 0xe0, 0x1e, 0xdd, 0x2c,
    0x77, 0x48, 0xd1, 0x4c, 0x92, 0x3d, 0x4d, 0x7e, 0x6d, 0x7c, 0x61, 0xb2, 0x29, 0xe9, 0xc5,
    0xa2, 0x7e, 0xce, 0xd3, 0xd9,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EccMode {
    Ecdsa,
    Ecdh,
    Eddsa,
}

struct OwnedCtx(*mut c_void);

impl OwnedCtx {
    fn raw(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for OwnedCtx {
    fn drop(&mut self) {
        if !self.0.is_null() {
            crate::context::gcry_ctx_release(self.0);
        }
    }
}

struct OwnedPoint(*mut c_void);

impl OwnedPoint {
    fn new(ptr: *mut c_void) -> Self {
        Self(ptr)
    }

    fn raw(&self) -> *mut c_void {
        self.0
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl Drop for OwnedPoint {
    fn drop(&mut self) {
        if !self.0.is_null() {
            crate::mpi::ec::gcry_mpi_point_release(self.0);
        }
    }
}

struct EddsaParams {
    scalar_len: usize,
    digest_len: usize,
    dom: &'static [u8],
}

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    matches!(algo, 18 | 301 | 302 | 303)
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}

pub(crate) fn has_key_token(key: *mut sexp::gcry_sexp) -> bool {
    !find_first_token(key, ALIASES).is_null()
}

fn curve_name(key: *mut sexp::gcry_sexp) -> Option<String> {
    let ptr = crate::mpi::ec::pk_get_curve_name(key, 0, null_mut());
    // `pk_get_curve_name` returns a borrowed static curve-name pointer.
    (!ptr.is_null()).then(|| unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
}

fn store_result(result: *mut *mut sexp::gcry_sexp, value: *mut sexp::gcry_sexp) {
    // All result slots come from the C ABI and are validated by the public entrypoints.
    unsafe {
        *result = value;
    }
}

fn mode_from_key(key: *mut sexp::gcry_sexp) -> EccMode {
    let curve = curve_name(key);
    if !find_first_token(key, &[b"eddsa\0"]).is_null()
        || flag_present(key, b"eddsa\0")
        || curve.as_deref() == Some("Ed448")
    {
        EccMode::Eddsa
    } else if !find_first_token(key, &[b"ecdh\0"]).is_null()
        || matches!(curve.as_deref(), Some("Curve25519" | "X448"))
    {
        EccMode::Ecdh
    } else {
        EccMode::Ecdsa
    }
}

fn q_name(mode: EccMode) -> &'static [u8] {
    if mode == EccMode::Eddsa {
        TOK_Q_EDDSA
    } else {
        TOK_Q
    }
}

fn eddsa_params(curve: &str) -> Option<EddsaParams> {
    match curve {
        "Ed25519" => Some(EddsaParams {
            scalar_len: 32,
            digest_len: 64,
            dom: b"SigEd25519 no Ed25519 collisions",
        }),
        "Ed448" => Some(EddsaParams {
            scalar_len: 57,
            digest_len: 114,
            dom: b"SigEd448",
        }),
        _ => None,
    }
}

fn new_ctx(key: *mut sexp::gcry_sexp) -> Result<OwnedCtx, u32> {
    let mut raw = null_mut();
    let rc = crate::mpi::ec::gcry_mpi_ec_new(&mut raw, key, null());
    if rc != 0 {
        Err(rc)
    } else if raw.is_null() {
        Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))
    } else {
        Ok(OwnedCtx(raw))
    }
}

fn point_new() -> Result<OwnedPoint, u32> {
    let point = OwnedPoint::new(crate::mpi::ec::gcry_mpi_point_new(0));
    if point.is_null() {
        Err(error::gcry_error_from_errno(crate::ENOMEM_VALUE))
    } else {
        Ok(point)
    }
}

fn ec_get_mpi(ctx: &OwnedCtx, name: &[u8]) -> OwnedMpi {
    OwnedMpi::new(crate::mpi::ec::gcry_mpi_ec_get_mpi(
        name.as_ptr().cast(),
        ctx.raw(),
        1,
    ))
}

fn ec_get_point(ctx: &OwnedCtx, name: &[u8]) -> OwnedPoint {
    OwnedPoint::new(crate::mpi::ec::gcry_mpi_ec_get_point(
        name.as_ptr().cast(),
        ctx.raw(),
        1,
    ))
}

fn ec_set_point(ctx: &OwnedCtx, name: &[u8], point: *mut c_void) -> u32 {
    crate::mpi::ec::gcry_mpi_ec_set_point(name.as_ptr().cast(), point, ctx.raw())
}

fn point_mul(ctx: &OwnedCtx, scalar: *mut gcry_mpi, point: *mut c_void) -> Result<OwnedPoint, u32> {
    let result = point_new()?;
    crate::mpi::ec::gcry_mpi_ec_mul(result.raw(), scalar, point, ctx.raw());
    Ok(result)
}

fn point_add(
    ctx: &OwnedCtx,
    left: *mut c_void,
    right: *mut c_void,
) -> Result<OwnedPoint, u32> {
    let result = point_new()?;
    crate::mpi::ec::gcry_mpi_ec_add(result.raw(), left, right, ctx.raw());
    Ok(result)
}

fn point_sub(
    ctx: &OwnedCtx,
    left: *mut c_void,
    right: *mut c_void,
) -> Result<OwnedPoint, u32> {
    let result = point_new()?;
    crate::mpi::ec::gcry_mpi_ec_sub(result.raw(), left, right, ctx.raw());
    Ok(result)
}

fn affine_x(point: *mut c_void, ctx: &OwnedCtx) -> Option<OwnedMpi> {
    let x = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let y = OwnedMpi::new(mpi::gcry_mpi_new(0));
    (crate::mpi::ec::gcry_mpi_ec_get_affine(x.raw(), y.raw(), point, ctx.raw()) == 0).then_some(x)
}

fn get_curve_nbits(key: *mut sexp::gcry_sexp) -> c_uint {
    let mut nbits = 0u32;
    let ptr = crate::mpi::ec::pk_get_curve_name(key, 0, &mut nbits);
    if !ptr.is_null() {
        return nbits;
    }

    match new_ctx(key) {
        Ok(ctx) => {
            let p = ec_get_mpi(&ctx, b"p\0");
            if p.is_null() {
                0
            } else {
                mpi::gcry_mpi_get_nbits(p.raw())
            }
        }
        Err(_) => 0,
    }
}

fn mpi_is_zero(value: *mut gcry_mpi) -> bool {
    mpi::gcry_mpi_cmp_ui(value, 0) == 0
}

fn numeric_mpi_from_le(bytes: &[u8], secure: bool) -> *mut gcry_mpi {
    let mut be = bytes.to_vec();
    be.reverse();
    bytes_to_mpi(&be, secure)
}

fn mpi_to_le_fixed(value: *mut gcry_mpi, len: usize) -> Vec<u8> {
    let mut bytes = mpi_to_bytes(value).unwrap_or_default();
    if bytes.len() > len {
        bytes = bytes[bytes.len() - len..].to_vec();
    }
    if bytes.len() < len {
        let mut padded = vec![0u8; len - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    bytes.reverse();
    bytes
}

fn hash_sha512(chunks: &[&[u8]]) -> Vec<u8> {
    let mut state = Sha512::new();
    for chunk in chunks {
        Sha2Digest::update(&mut state, chunk);
    }
    state.finalize().to_vec()
}

fn hash_shake256(chunks: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut state = Shake256::default();
    for chunk in chunks {
        state.update(chunk);
    }
    let mut reader = state.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

fn eddsa_hash(curve: &str, chunks: &[&[u8]], out_len: usize) -> Option<Vec<u8>> {
    match curve {
        "Ed25519" => Some(hash_sha512(chunks)),
        "Ed448" => Some(hash_shake256(chunks, out_len)),
        _ => None,
    }
}

fn eddsa_dom_prefix(curve: &str, prehash: bool, label: &[u8]) -> Vec<u8> {
    let Some(params) = eddsa_params(curve) else {
        return Vec::new();
    };
    if curve == "Ed25519" && !prehash && label.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(params.dom.len() + 2 + label.len());
    out.extend_from_slice(params.dom);
    out.push(prehash as u8);
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out
}

fn eddsa_prehash(curve: &str, message: &[u8]) -> Option<Vec<u8>> {
    match curve {
        "Ed25519" => Some(hash_sha512(&[message])),
        "Ed448" => Some(hash_shake256(&[message], 64)),
        _ => None,
    }
}

fn eddsa_expand_secret(
    curve: &str,
    seed: &[u8],
) -> Option<(OwnedMpi, Vec<u8>, EddsaParams)> {
    let params = eddsa_params(curve)?;
    let digest = eddsa_hash(curve, &[seed], params.digest_len)?;
    let mut scalar = digest[..params.scalar_len].to_vec();
    scalar.reverse();
    match curve {
        "Ed25519" => {
            scalar[0] = (scalar[0] & 0x7f) | 0x40;
            scalar[params.scalar_len - 1] &= 0xf8;
        }
        "Ed448" => {
            scalar[0] = 0;
            scalar[1] |= 0x80;
            scalar[params.scalar_len - 1] &= 0xfc;
        }
        _ => return None,
    }

    Some((
        OwnedMpi::new(bytes_to_mpi(&scalar, true)),
        digest[params.scalar_len..(2 * params.scalar_len)].to_vec(),
        params,
    ))
}

fn digest_to_scalar(digest: &[u8], modulus: *mut gcry_mpi) -> Option<OwnedMpi> {
    let mut be = digest.to_vec();
    be.reverse();
    let scalar = OwnedMpi::new(bytes_to_mpi(&be, false));
    if scalar.is_null() {
        return None;
    }
    mpi::arith::gcry_mpi_mod(scalar.raw(), scalar.raw(), modulus);
    Some(scalar)
}

fn encode_point(key: *mut sexp::gcry_sexp, point: *mut c_void, mode: EccMode) -> Result<OwnedMpi, u32> {
    let ctx = new_ctx(key)?;
    let rc = ec_set_point(&ctx, TOK_Q, point);
    if rc != 0 {
        return Err(rc);
    }
    let mpi = ec_get_mpi(&ctx, q_name(mode));
    if mpi.is_null() {
        Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))
    } else {
        Ok(mpi)
    }
}

fn key_ref<'a>(
    key: *mut sexp::gcry_sexp,
    secret_token: bool,
    nested: &'a mut Option<OwnedSexp>,
) -> *mut sexp::gcry_sexp {
    if !token_present(key, b"key-data\0") {
        return key;
    }
    let token = if secret_token {
        find_token_one(key, TOK_PRIVATE_KEY)
    } else {
        find_token_one(key, TOK_PUBLIC_KEY)
    };
    if token.is_null() {
        key
    } else {
        *nested = Some(token);
        nested.as_ref().expect("stored token").raw()
    }
}

fn build_secret_only_key(
    curve: &str,
    mode: EccMode,
    d: *mut gcry_mpi,
) -> Result<OwnedSexp, u32> {
    let is_curve25519 = curve == "Curve25519";
    let curve = CString::new(curve).expect("curve names are NUL-free");
    let built = match mode {
        EccMode::Eddsa => build_sexp(
            "(private-key(ecc(curve %s)(flags eddsa)(d%M)))",
            &[ptr_to_arg(curve.as_ptr()), d as usize],
        )?,
        EccMode::Ecdh if is_curve25519 => build_sexp(
            "(private-key(ecc(curve %s)(flags djb-tweak)(d%M)))",
            &[ptr_to_arg(curve.as_ptr()), d as usize],
        )?,
        _ => build_sexp(
            "(private-key(ecc(curve %s)(d%M)))",
            &[ptr_to_arg(curve.as_ptr()), d as usize],
        )?,
    };
    Ok(OwnedSexp::new(built))
}

fn build_key_data(
    result: *mut *mut sexp::gcry_sexp,
    curve: &str,
    mode: EccMode,
    q: *mut gcry_mpi,
    d: *mut gcry_mpi,
) -> u32 {
    let is_curve25519 = curve == "Curve25519";
    let curve = CString::new(curve).expect("curve names are NUL-free");
    let built = match mode {
        EccMode::Eddsa => build_sexp(
            "(key-data(public-key(ecc(curve %s)(flags eddsa)(q%M)))(private-key(ecc(curve %s)(flags eddsa)(q%M)(d%M))))",
            &[
                ptr_to_arg(curve.as_ptr()),
                q as usize,
                ptr_to_arg(curve.as_ptr()),
                q as usize,
                d as usize,
            ],
        ),
        EccMode::Ecdh if is_curve25519 => build_sexp(
            "(key-data(public-key(ecc(curve %s)(flags djb-tweak)(q%M)))(private-key(ecc(curve %s)(flags djb-tweak)(q%M)(d%M))))",
            &[
                ptr_to_arg(curve.as_ptr()),
                q as usize,
                ptr_to_arg(curve.as_ptr()),
                q as usize,
                d as usize,
            ],
        ),
        _ => build_sexp(
            "(key-data(public-key(ecc(curve %s)(q%M)))(private-key(ecc(curve %s)(q%M)(d%M))))",
            &[
                ptr_to_arg(curve.as_ptr()),
                q as usize,
                ptr_to_arg(curve.as_ptr()),
                q as usize,
                d as usize,
            ],
        ),
    };

    match built {
        Ok(value) => {
            store_result(result, value);
            0
        }
        Err(err) => err,
    }
}

fn sign_ecdsa(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    let ctx = match new_ctx(skey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let n = ec_get_mpi(&ctx, TOK_N);
    let d = ec_get_mpi(&ctx, TOK_D);
    let g = ec_get_point(&ctx, TOK_G);
    if n.is_null() || d.is_null() || g.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_NO_OBJ);
    }

    let qbits = mpi::gcry_mpi_get_nbits(n.raw()) as usize;
    let parsed = match dsa::parse_sign_input(data, qbits) {
        Ok(value) => value,
        Err(err) => return err,
    };
    if parsed.input.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    }

    loop {
        let k = if let Some(label) = parsed.label.as_ref() {
            OwnedMpi::new(bytes_to_mpi(label, false))
        } else if parsed.use_rfc6979 {
            let hash_algo = match parsed.hash_algo {
                Some(value) => value,
                None => return error::gcry_error_from_code(super::GPG_ERR_DIGEST_ALGO),
            };
            let raw_hash = match parsed.raw_hash.as_deref() {
                Some(value) => value,
                None => return error::gcry_error_from_code(super::GPG_ERR_CONFLICT),
            };
            match dsa::rfc6979_generate_k(
                d.raw(),
                n.raw(),
                hash_algo,
                raw_hash,
            ) {
                Ok(value) => OwnedMpi::new(value),
                Err(err) => return err,
            }
        } else {
            dsa::mpi_random_less_than(n.raw())
        };
        if k.is_null() {
            return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
        }

        let point = match point_mul(&ctx, k.raw(), g.raw()) {
            Ok(value) => value,
            Err(err) => return err,
        };
        let Some(x) = affine_x(point.raw(), &ctx) else {
            continue;
        };
        let r = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_mod(r.raw(), x.raw(), n.raw());
        if mpi_is_zero(r.raw()) {
            continue;
        }

        let kinv = OwnedMpi::new(mpi::gcry_mpi_new(0));
        if mpi::arith::gcry_mpi_invm(kinv.raw(), k.raw(), n.raw()) == 0 {
            continue;
        }

        let dr = OwnedMpi::new(mpi::gcry_mpi_new(0));
        let sum = OwnedMpi::new(mpi::gcry_mpi_new(0));
        let s = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_mulm(dr.raw(), d.raw(), r.raw(), n.raw());
        mpi::arith::gcry_mpi_addm(sum.raw(), parsed.input.raw(), dr.raw(), n.raw());
        mpi::arith::gcry_mpi_mulm(s.raw(), kinv.raw(), sum.raw(), n.raw());
        if mpi_is_zero(s.raw()) {
            continue;
        }

        return match build_sexp("(sig-val(ecdsa(r%M)(s%M)))", &[r.raw() as usize, s.raw() as usize]) {
            Ok(sig) => {
                store_result(result, sig);
                0
            }
            Err(err) => err,
        };
    }
}

fn verify_ecdsa(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    let ctx = match new_ctx(pkey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let n = ec_get_mpi(&ctx, TOK_N);
    let g = ec_get_point(&ctx, TOK_G);
    let q = ec_get_point(&ctx, TOK_Q);
    let r = token_mpi(sigval, TOK_R, GCRYMPI_FMT_USG);
    let s = token_mpi(sigval, TOK_S, GCRYMPI_FMT_USG);
    if n.is_null() || g.is_null() || q.is_null() || r.is_null() || s.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }
    if mpi_is_zero(r.raw())
        || mpi_is_zero(s.raw())
        || mpi::gcry_mpi_cmp(r.raw(), n.raw()) >= 0
        || mpi::gcry_mpi_cmp(s.raw(), n.raw()) >= 0
    {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }

    let qbits = mpi::gcry_mpi_get_nbits(n.raw()) as usize;
    let parsed = match dsa::parse_sign_input(data, qbits) {
        Ok(value) => value,
        Err(err) => return err,
    };
    if parsed.input.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    }

    let w = OwnedMpi::new(mpi::gcry_mpi_new(0));
    if mpi::arith::gcry_mpi_invm(w.raw(), s.raw(), n.raw()) == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }

    let u1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let u2 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_mulm(u1.raw(), parsed.input.raw(), w.raw(), n.raw());
    mpi::arith::gcry_mpi_mulm(u2.raw(), r.raw(), w.raw(), n.raw());

    let p1 = match point_mul(&ctx, u1.raw(), g.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let p2 = match point_mul(&ctx, u2.raw(), q.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let sum = match point_add(&ctx, p1.raw(), p2.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let Some(x) = affine_x(sum.raw(), &ctx) else {
        return error::gcry_error_from_code(super::GPG_ERR_BAD_SIGNATURE);
    };
    let v = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_mod(v.raw(), x.raw(), n.raw());

    if mpi::gcry_mpi_cmp(v.raw(), r.raw()) == 0 {
        0
    } else {
        error::gcry_error_from_code(super::GPG_ERR_BAD_SIGNATURE)
    }
}

fn parse_eddsa_input(data: *mut sexp::gcry_sexp) -> Result<(Vec<u8>, Vec<u8>, bool), u32> {
    let Some(message) = encoding::token_data(data, b"value\0") else {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
    };
    let label = token_string_value(data, b"label\0")
        .map(|value| value.into_bytes())
        .or_else(|| super::token_data_bytes(data, b"label\0"))
        .unwrap_or_default();
    Ok((message, label, flag_present(data, b"prehash\0")))
}

fn sign_eddsa(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    skey: *mut sexp::gcry_sexp,
) -> u32 {
    let Some(curve) = curve_name(skey) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };
    let (message, label, prehash) = match parse_eddsa_input(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let Some(params) = eddsa_params(&curve) else {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    };

    let ctx = match new_ctx(skey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let d = ec_get_mpi(&ctx, TOK_D);
    let n = ec_get_mpi(&ctx, TOK_N);
    let g = ec_get_point(&ctx, TOK_G);
    let q = ec_get_mpi(&ctx, TOK_Q_EDDSA);
    if d.is_null() || n.is_null() || g.is_null() || q.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_NO_OBJ);
    }

    let Some(seed) = mpi_to_bytes(d.raw()) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };
    let Some((a, prefix, _)) = eddsa_expand_secret(&curve, &seed) else {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    };
    let Some(q_bytes) = mpi_to_bytes(q.raw()) else {
        return error::gcry_error_from_code(GPG_ERR_BROKEN_PUBKEY);
    };
    let dom = eddsa_dom_prefix(&curve, prehash, &label);
    let msg = if prehash {
        match eddsa_prehash(&curve, &message) {
            Some(value) => value,
            None => return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED),
        }
    } else {
        message
    };

    let mut chunks = Vec::new();
    if !dom.is_empty() {
        chunks.push(dom.as_slice());
    }
    chunks.push(prefix.as_slice());
    chunks.push(msg.as_slice());
    let Some(r_digest) = eddsa_hash(&curve, &chunks, params.digest_len) else {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    };
    let Some(r_scalar) = digest_to_scalar(&r_digest, n.raw()) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };

    let r_point = match point_mul(&ctx, r_scalar.raw(), g.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let r_mpi = match encode_point(skey, r_point.raw(), EccMode::Eddsa) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let Some(r_bytes) = mpi_to_bytes(r_mpi.raw()) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };

    let mut h_chunks = Vec::new();
    if !dom.is_empty() {
        h_chunks.push(dom.as_slice());
    }
    h_chunks.push(r_bytes.as_slice());
    h_chunks.push(q_bytes.as_slice());
    h_chunks.push(msg.as_slice());
    let Some(h_digest) = eddsa_hash(&curve, &h_chunks, params.digest_len) else {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    };
    let Some(h_scalar) = digest_to_scalar(&h_digest, n.raw()) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };

    let s = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let t = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_mulm(t.raw(), h_scalar.raw(), a.raw(), n.raw());
    mpi::arith::gcry_mpi_addm(s.raw(), t.raw(), r_scalar.raw(), n.raw());
    let s_bytes = mpi_to_le_fixed(s.raw(), params.scalar_len);

    let r_out = OwnedMpi::new(crate::mpi::opaque::gcry_mpi_set_opaque_copy(
        null_mut(),
        r_bytes.as_ptr().cast(),
        (r_bytes.len() * 8) as c_uint,
    ));
    let s_out = OwnedMpi::new(crate::mpi::opaque::gcry_mpi_set_opaque_copy(
        null_mut(),
        s_bytes.as_ptr().cast(),
        (s_bytes.len() * 8) as c_uint,
    ));
    if r_out.is_null() || s_out.is_null() {
        return error::gcry_error_from_errno(crate::ENOMEM_VALUE);
    }

    match build_sexp("(sig-val(eddsa(r%M)(s%M)))", &[r_out.raw() as usize, s_out.raw() as usize]) {
        Ok(sig) => {
            store_result(result, sig);
            0
        }
        Err(err) => err,
    }
}

fn verify_eddsa(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    let Some(curve) = curve_name(pkey) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };
    let (message, label, prehash) = match parse_eddsa_input(data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let Some(params) = eddsa_params(&curve) else {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    };

    let ctx = match new_ctx(pkey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let n = ec_get_mpi(&ctx, TOK_N);
    let g = ec_get_point(&ctx, TOK_G);
    let q = ec_get_point(&ctx, TOK_Q);
    if n.is_null() || g.is_null() || q.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_NO_OBJ);
    }
    if crate::mpi::ec::gcry_mpi_ec_curve_point(q.raw(), ctx.raw()) == 0 {
        return error::gcry_error_from_code(GPG_ERR_BROKEN_PUBKEY);
    }

    let r = token_mpi(sigval, TOK_R, GCRYMPI_FMT_OPAQUE);
    let s = token_mpi(sigval, TOK_S, GCRYMPI_FMT_OPAQUE);
    if r.is_null() || s.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }
    let Some(r_bytes) = mpi_to_bytes(r.raw()) else {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    };
    let Some(s_bytes) = mpi_to_bytes(s.raw()) else {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    };
    if r_bytes.len() != params.scalar_len || s_bytes.len() != params.scalar_len {
        return error::gcry_error_from_code(error::GPG_ERR_INV_LENGTH);
    }

    let q_bytes = {
        let q_mpi = ec_get_mpi(&ctx, TOK_Q_EDDSA);
        if q_mpi.is_null() {
            return error::gcry_error_from_code(GPG_ERR_BROKEN_PUBKEY);
        }
        let Some(bytes) = mpi_to_bytes(q_mpi.raw()) else {
            return error::gcry_error_from_code(GPG_ERR_BROKEN_PUBKEY);
        };
        bytes
    };

    let dom = eddsa_dom_prefix(&curve, prehash, &label);
    let msg = if prehash {
        match eddsa_prehash(&curve, &message) {
            Some(value) => value,
            None => return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED),
        }
    } else {
        message
    };

    let mut h_chunks = Vec::new();
    if !dom.is_empty() {
        h_chunks.push(dom.as_slice());
    }
    h_chunks.push(r_bytes.as_slice());
    h_chunks.push(q_bytes.as_slice());
    h_chunks.push(msg.as_slice());
    let Some(h_digest) = eddsa_hash(&curve, &h_chunks, params.digest_len) else {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    };
    let Some(h_scalar) = digest_to_scalar(&h_digest, n.raw()) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };
    let s_scalar = OwnedMpi::new(numeric_mpi_from_le(&s_bytes, false));
    if s_scalar.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    }

    let p1 = match point_mul(&ctx, s_scalar.raw(), g.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let p2 = match point_mul(&ctx, h_scalar.raw(), q.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let check = match point_sub(&ctx, p1.raw(), p2.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let r_check = match encode_point(pkey, check.raw(), EccMode::Eddsa) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let Some(check_bytes) = mpi_to_bytes(r_check.raw()) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };

    if check_bytes == r_bytes {
        0
    } else {
        error::gcry_error_from_code(super::GPG_ERR_BAD_SIGNATURE)
    }
}

pub(crate) fn encrypt(
    result: *mut *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    let mode = mode_from_key(pkey);
    let curve = curve_name(pkey);
    let ctx = match new_ctx(pkey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let q = ec_get_point(&ctx, TOK_Q);
    let g = ec_get_point(&ctx, TOK_G);
    if q.is_null() || g.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_NO_OBJ);
    }

    let scalar = OwnedMpi::new(encoding::data_value_mpi(
        data,
        if mode == EccMode::Ecdh && curve.as_deref() != Some("Curve25519") {
            GCRYMPI_FMT_OPAQUE
        } else {
            GCRYMPI_FMT_USG
        },
    ));
    if scalar.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    }
    if mode == EccMode::Ecdh && curve.as_deref() == Some("Curve25519") {
        mpi::gcry_mpi_clear_bit(scalar.raw(), 0);
        mpi::gcry_mpi_clear_bit(scalar.raw(), 1);
        mpi::gcry_mpi_clear_bit(scalar.raw(), 2);
        mpi::gcry_mpi_set_highbit(scalar.raw(), 254);
    }

    let shared = match point_mul(&ctx, scalar.raw(), q.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let eph = match point_mul(&ctx, scalar.raw(), g.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let s = match encode_point(pkey, shared.raw(), mode) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let e = match encode_point(pkey, eph.raw(), mode) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match build_sexp("(enc-val(ecdh(s%M)(e%M)))", &[s.raw() as usize, e.raw() as usize]) {
        Ok(value) => {
            store_result(result, value);
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
    let mode = mode_from_key(skey);
    let ctx = match new_ctx(skey) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let d = ec_get_mpi(&ctx, TOK_D);
    if d.is_null() {
        return error::gcry_error_from_code(GPG_ERR_NO_SECKEY);
    }

    let enc = find_token_one(data, TOK_E);
    let encoded = if enc.is_null() { data } else { enc.raw() };
    let point_mpi = OwnedMpi::new(sexp::gcry_sexp_nth_mpi(encoded, 1, GCRYMPI_FMT_OPAQUE));
    if point_mpi.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    }

    let point = match point_new() {
        Ok(value) => value,
        Err(err) => return err,
    };
    let rc = crate::mpi::ec::gcry_mpi_ec_decode_point(point.raw(), point_mpi.raw(), ctx.raw());
    if rc != 0 {
        return rc;
    }
    if crate::mpi::ec::gcry_mpi_ec_curve_point(point.raw(), ctx.raw()) == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }

    let shared = match point_mul(&ctx, d.raw(), point.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let value = match encode_point(skey, shared.raw(), mode) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match build_sexp("(value %M)", &[value.raw() as usize]) {
        Ok(plain) => {
            store_result(result, plain);
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
    match mode_from_key(skey) {
        EccMode::Eddsa => sign_eddsa(result, data, skey),
        _ => sign_ecdsa(result, data, skey),
    }
}

pub(crate) fn verify(
    sigval: *mut sexp::gcry_sexp,
    data: *mut sexp::gcry_sexp,
    pkey: *mut sexp::gcry_sexp,
) -> u32 {
    match mode_from_key(pkey) {
        EccMode::Eddsa => verify_eddsa(sigval, data, pkey),
        _ => verify_ecdsa(sigval, data, pkey),
    }
}

pub(crate) fn testkey(key: *mut sexp::gcry_sexp) -> u32 {
    let mut nested = None;
    let key = key_ref(key, true, &mut nested);
    let mode = mode_from_key(key);
    let Some(curve) = curve_name(key) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };
    let ctx = match new_ctx(key) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let d = ec_get_mpi(&ctx, TOK_D);
    let q = ec_get_mpi(&ctx, q_name(mode));
    if d.is_null() || q.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_NO_OBJ);
    }

    let secret_only = match build_secret_only_key(&curve, mode, d.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let derived_ctx = match new_ctx(secret_only.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let q_have = ec_get_mpi(&derived_ctx, q_name(mode));
    if q_have.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_NO_OBJ);
    }

    if mpi_to_bytes(q.raw()) == mpi_to_bytes(q_have.raw()) {
        0
    } else {
        error::gcry_error_from_code(error::GPG_ERR_BAD_DATA)
    }
}

pub(crate) fn genkey(
    result: *mut *mut sexp::gcry_sexp,
    parms: *mut sexp::gcry_sexp,
) -> u32 {
    let curve = if let Some(curve) = curve_name(parms).or_else(|| token_string_value(parms, b"curve\0")) {
        curve
    } else if let Some(nbits) = super::token_usize(parms, b"nbits\0") {
        if nbits > c_uint::MAX as usize {
            return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
        }
        match crate::mpi::ec::genkey_curve_name_for_nbits(nbits as c_uint) {
            Ok(curve) => curve.to_string(),
            Err(err) => return err,
        }
    } else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };
    let mode = mode_from_key(parms);
    let params = eddsa_params(&curve);

    let d = if mode == EccMode::Eddsa {
        let Some(params) = params else {
            return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
        };
        let mut seed = vec![0u8; params.scalar_len];
        random::fill_random_level(
            &mut seed,
            if flag_present(parms, b"transient-key\0") {
                random::GCRY_STRONG_RANDOM
            } else {
                random::GCRY_VERY_STRONG_RANDOM
            },
        );
        OwnedMpi::new(crate::mpi::opaque::gcry_mpi_set_opaque_copy(
            null_mut(),
            seed.as_ptr().cast(),
            (seed.len() * 8) as c_uint,
        ))
    } else {
        let curve_name = CString::new(curve.as_str()).expect("curve names are NUL-free");
        let curve_key = match build_sexp(
            "(public-key(ecc(curve %s)))",
            &[ptr_to_arg(curve_name.as_ptr())],
        ) {
            Ok(value) => OwnedSexp::new(value),
            Err(err) => return err,
        };
        let ctx = match new_ctx(curve_key.raw()) {
            Ok(value) => value,
            Err(err) => return err,
        };
        let n = ec_get_mpi(&ctx, TOK_N);
        if n.is_null() {
            return error::gcry_error_from_code(error::GPG_ERR_NO_OBJ);
        }
        dsa::mpi_random_less_than(n.raw())
    };
    if d.is_null() {
        return error::gcry_error_from_errno(crate::ENOMEM_VALUE);
    }

    let secret_only = match build_secret_only_key(&curve, mode, d.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let ctx = match new_ctx(secret_only.raw()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let q = ec_get_mpi(&ctx, q_name(mode));
    if q.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_NO_OBJ);
    }

    build_key_data(result, &curve, mode, q.raw(), d.raw())
}

pub(crate) fn get_nbits(key: *mut sexp::gcry_sexp) -> c_uint {
    let mut nested = None;
    let key = key_ref(key, false, &mut nested);
    get_curve_nbits(key)
}

pub(crate) fn keygrip(key: *mut sexp::gcry_sexp) -> Option<[u8; KEYGRIP_LEN]> {
    let mut nested = None;
    let key = key_ref(key, false, &mut nested);
    let curve = curve_name(key);
    let mode = mode_from_key(key);
    let ctx = new_ctx(key).ok()?;

    let names = [
        (b'p', b"p\0".as_slice()),
        (b'a', b"a\0".as_slice()),
        (b'b', b"b\0".as_slice()),
        (b'g', TOK_G),
        (b'n', TOK_N),
        (b'q', q_name(mode)),
    ];

    let mut hash = Sha1::new();
    for (tag, name) in names {
        let mpi = ec_get_mpi(&ctx, name);
        if mpi.is_null() {
            return None;
        }
        let mut bytes = mpi_to_bytes(mpi.raw())?;
        if curve.as_deref() == Some("Ed25519") {
            match tag {
                b'a' => bytes = ED25519_KEYGRIP_A.to_vec(),
                b'b' => bytes = ED25519_KEYGRIP_B.to_vec(),
                _ => {}
            }
        } else if curve.as_deref() == Some("Curve25519") && tag == b'g' {
            bytes = CURVE25519_KEYGRIP_G.to_vec();
        }
        if tag == b'q'
            && curve.as_deref() == Some("Curve25519")
            && bytes.len() > 1
            && bytes[0] == 0x40
        {
            bytes.remove(0);
        }
        Sha1Digest::update(
            &mut hash,
            format!("(1:{}{}:", tag as char, bytes.len()).as_bytes(),
        );
        Sha1Digest::update(&mut hash, &bytes);
        Sha1Digest::update(&mut hash, b")");
    }

    let digest = hash.finalize();
    let mut out = [0u8; KEYGRIP_LEN];
    out.copy_from_slice(&digest[..KEYGRIP_LEN]);
    Some(out)
}

#[no_mangle]
pub extern "C" fn gcry_pk_get_curve(
    key: *mut sexp::gcry_sexp,
    iterator: c_int,
    nbits: *mut c_uint,
) -> *const c_char {
    crate::mpi::ec::pk_get_curve_name(key, iterator, nbits)
}

#[no_mangle]
pub extern "C" fn gcry_pk_get_param(algo: c_int, name: *const c_char) -> *mut sexp::gcry_sexp {
    crate::mpi::ec::pk_get_param_sexp(algo, name)
}

#[no_mangle]
pub extern "C" fn gcry_pubkey_get_sexp(
    result: *mut *mut sexp::gcry_sexp,
    mode: c_int,
    ctx: *mut c_void,
) -> u32 {
    if result.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    store_result(result, null_mut());

    if ctx.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if context::is_random_override_context(ctx) || !crate::mpi::ec::is_local_context(ctx) {
        return error::gcry_error_from_code(super::GPG_ERR_WRONG_CRYPT_CTX);
    }
    crate::mpi::ec::local_pubkey_get_sexp(result, mode, ctx)
}

#[no_mangle]
pub extern "C" fn gcry_ecc_get_algo_keylen(curveid: c_int) -> c_uint {
    crate::mpi::ec::ecc_get_algo_keylen(curveid)
}

#[no_mangle]
pub extern "C" fn gcry_ecc_mul_point(
    curveid: c_int,
    result: *mut u8,
    scalar: *const u8,
    point: *const u8,
) -> u32 {
    crate::mpi::ec::ecc_mul_point_bytes(curveid, result, scalar, point)
}
