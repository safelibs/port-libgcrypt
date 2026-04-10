use std::ffi::{CString, c_char, c_int};
use std::ptr::null_mut;
use std::sync::OnceLock;

use crate::digest;
use crate::error;
use crate::mpi::{self, GCRYMPI_FMT_USG, gcry_mpi};
use crate::sexp;
use crate::upstream::gcry_buffer_t;

use super::{
    GCRY_PK_DSA, GPG_ERR_DIGEST_ALGO, OwnedMpi, build_sexp, bytes_to_mpi, find_first_token,
    find_token, flag_present, mpi_to_bytes, token_data_bytes, token_mpi, token_present,
    token_usize,
};

pub(crate) const NAME: &[u8] = b"dsa\0";
const ALIASES: &[&[u8]] = &[b"dsa\0", b"openpgp-dsa\0"];

const TOK_P: &[u8] = b"p\0";
const TOK_Q: &[u8] = b"q\0";
const TOK_G: &[u8] = b"g\0";
const TOK_Y: &[u8] = b"y\0";
const TOK_X: &[u8] = b"x\0";
const TOK_HASH: &[u8] = b"hash\0";
const TOK_VALUE: &[u8] = b"value\0";
const TOK_LABEL: &[u8] = b"label\0";
const TOK_SEED: &[u8] = b"seed\0";

const SAMPLE_1024_P: &str = "0084E4C626E16005770BD9509ABF7354492E85B8C0060EFAAAEC617F725B592FAA59DF5460575F41022776A9718CE62EDD542AB73C7720869EBDBC834D174ADCD7136827DF51E2613545A25CA573BC502A61B809000B6E35F5EB7FD6F18C35678C23EA1C3638FB9CFDBA2800EE1B62F41A4479DE824F2834666FBF8DC5B53C2617";
const SAMPLE_1024_Q: &str = "00B0E6F710051002A9F425D98A677B18E0E5B038AB";
const SAMPLE_1024_G: &str = "44370CEE0FE8609994183DBFEBA7EEA97D466838BCF65EFF506E35616DA93FA4E572A2F08886B74977BC00CA8CD3DBEA7AEB7DB8CBB180E6975E0D2CA76E023E6DE9F8CCD8826EBA2F72B8516532F6001DEFFAE76AA5E59E0FA33DBA3999B4E92D1703098CDEDCC416CF008801964084CDE1980132B2B78CB4CE9C15A559528B";
const SAMPLE_2048_P: &str = "A8ADB6C0B4CF9588012E5DEFF1A871D383E0E2A85B5E8E03D814FE13A059705E663230A377BF7323A8FA117100200BFD5ADF857393B0BBD67906C081E585410E38480EAD51684DAC3A38F7B64C9EB109F19739A4517CD7D5D6291E8AF20A3FBF17336C7BF80EE718EE087E322EE41047DABEFBCC34D10B66B644DDB3160A28C0639563D71993A26543EADB7718F317BF5D9577A6156561B082A10029CD44012B18DE6844509FE058BA87980792285F2750969FE89C2CD6498DB3545638D5379D125DCCF64E06C1AF33A6190841D223DA1513333A7C9D78462ABAAB31B9F96D5F34445CEB6309F2F6D2C8DDE06441E87980D303EF9A1FF007E8BE2F0BE06CC15F";
const SAMPLE_2048_Q: &str = "E71F8567447F42E75F5EF85CA20FE557AB0343D37ED09EDC3F6E68604D6B9DFB";
const SAMPLE_2048_G: &str = "5BA24DE9607B8998E66CE6C4F812A314C6935842F7AB54CD82B19FA104ABFB5D84579A623B2574B37D22CCAE9B3E415E48F5C0F9BCBDFF8071D63B9BB956E547AF3A8DF99E5D3061979652FF96B765CB3EE493643544C75DBE5BB39834531952A0FB4B0378B3FCBB4C8B5800A5330392A2A04E700BB6ED7E0B85795EA38B1B962741B3F33B9DDE2F4EC1354F09E2EB78E95F037A5804B6171659F88715CE1A9B0CC90C27F35EF2F10FF0C7C7A2BB0154D9B8EBE76A3D764AA879AF372F4240DE8347937E5A90CEC9F41FF2F26B8DA9A94A225D1A913717D73F10397D2183F1BA3B7B45A68F1FF1893CAF69A827802F7B6A48D51DA6FBEFB64FD9A6C5B75C4561";

const GCRY_MD_FLAG_HMAC: u32 = 2;

#[derive(Clone, Debug)]
struct Dsa1862Vector {
    nbits: usize,
    p: String,
    q: String,
    g: String,
    seed: String,
    counter: usize,
    h: String,
}

#[derive(Clone, Debug)]
struct Dsa1863Vector {
    nbits: usize,
    qbits: usize,
    p: String,
    q: String,
    seed: String,
    counter: usize,
}

struct DsaKey {
    p: OwnedMpi,
    q: OwnedMpi,
    g: OwnedMpi,
    y: OwnedMpi,
    x: Option<OwnedMpi>,
}

impl DsaKey {
    fn qbits(&self) -> usize {
        mpi::gcry_mpi_get_nbits(self.q.raw()) as usize
    }
}

#[derive(Clone, Copy, Debug)]
enum VectorFlavor {
    Fips186_2,
    Fips186_3,
}

#[derive(Debug)]
enum Token {
    Integer(usize),
    Text(String),
}

pub(crate) fn owns_algorithm(algo: c_int) -> bool {
    algo == GCRY_PK_DSA
}

pub(crate) fn fallback_name(algo: c_int) -> Option<*const c_char> {
    owns_algorithm(algo).then_some(NAME.as_ptr().cast())
}

pub(crate) fn map_name(name: &str) -> Option<c_int> {
    ALIASES
        .iter()
        .map(|alias| std::str::from_utf8(&alias[..alias.len() - 1]).expect("alias utf-8"))
        .find(|alias| alias.eq_ignore_ascii_case(name))
        .map(|_| GCRY_PK_DSA)
}

pub(crate) fn has_key_token(key: *mut sexp::gcry_sexp) -> bool {
    !find_first_token(key, ALIASES).is_null()
}

fn parse_key(key: *mut sexp::gcry_sexp, secret: bool) -> Result<DsaKey, u32> {
    let p = token_mpi(key, TOK_P, GCRYMPI_FMT_USG);
    let q = token_mpi(key, TOK_Q, GCRYMPI_FMT_USG);
    let g = token_mpi(key, TOK_G, GCRYMPI_FMT_USG);
    let y = token_mpi(key, TOK_Y, GCRYMPI_FMT_USG);
    if p.is_null() || q.is_null() || g.is_null() || y.is_null() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_NO_OBJ));
    }

    let x = if secret {
        let value = token_mpi(key, TOK_X, GCRYMPI_FMT_USG);
        if value.is_null() {
            return Err(error::gcry_error_from_code(error::GPG_ERR_NO_OBJ));
        }
        Some(value)
    } else {
        None
    };

    Ok(DsaKey { p, q, g, y, x })
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

fn mpi_is_zero(value: *mut gcry_mpi) -> bool {
    mpi::gcry_mpi_cmp_ui(value, 0) == 0
}

fn mpi_equal(left: *mut gcry_mpi, right: *mut gcry_mpi) -> bool {
    mpi::gcry_mpi_cmp(left, right) == 0
}

fn mpi_copy(value: *mut gcry_mpi) -> OwnedMpi {
    OwnedMpi::new(mpi::gcry_mpi_copy(value))
}

fn mpi_from_ui(value: usize) -> OwnedMpi {
    let raw = mpi::gcry_mpi_new(0);
    mpi::gcry_mpi_set_ui(raw, value as _);
    OwnedMpi::new(raw)
}

fn mpi_random_less_than(modulus: *mut gcry_mpi) -> OwnedMpi {
    let bits = mpi::gcry_mpi_get_nbits(modulus) as c_int;
    loop {
        let candidate = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::gcry_mpi_randomize(candidate.raw(), bits as _, crate::random::GCRY_WEAK_RANDOM);
        mpi::arith::gcry_mpi_mod(candidate.raw(), candidate.raw(), modulus);
        if !mpi_is_zero(candidate.raw()) {
            return candidate;
        }
    }
}

fn mpi_fixed_bytes(value: *mut gcry_mpi, len: usize) -> Vec<u8> {
    let mut bytes = mpi_to_bytes(value).unwrap_or_default();
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

fn normalize_hash_bytes(data: &[u8], qbits: usize) -> Vec<u8> {
    let qbytes = qbits.div_ceil(8);
    let mut out = if data.len() > qbytes {
        data[..qbytes].to_vec()
    } else {
        data.to_vec()
    };
    if out.is_empty() {
        out.push(0);
    }
    let excess = out.len() * 8 - qbits;
    if excess != 0 {
        out[0] &= 0xff >> excess;
    }
    out
}

fn digest_hmac(algo: c_int, key: &[u8], chunks: &[&[u8]]) -> Result<Vec<u8>, u32> {
    let outlen = digest::gcry_md_get_algo_dlen(algo) as usize;
    if outlen == 0 {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
    }

    let mut out = vec![0u8; outlen];
    let mut buffers = Vec::with_capacity(chunks.len() + 1);
    buffers.push(gcry_buffer_t {
        size: key.len(),
        off: 0,
        len: key.len(),
        data: key.as_ptr().cast_mut().cast(),
    });
    for chunk in chunks {
        buffers.push(gcry_buffer_t {
            size: chunk.len(),
            off: 0,
            len: chunk.len(),
            data: chunk.as_ptr().cast_mut().cast(),
        });
    }

    let rc = digest::gcry_md_hash_buffers(
        algo,
        GCRY_MD_FLAG_HMAC,
        out.as_mut_ptr().cast(),
        buffers.as_ptr(),
        buffers.len() as c_int,
    );
    if rc == 0 { Ok(out) } else { Err(rc) }
}

fn rfc6979_generate_k(x: *mut gcry_mpi, q: *mut gcry_mpi, hash_algo: c_int, digest: &[u8]) -> Result<*mut gcry_mpi, u32> {
    let qbits = mpi::gcry_mpi_get_nbits(q) as usize;
    let rolen = qbits.div_ceil(8);
    let holen = digest::gcry_md_get_algo_dlen(hash_algo) as usize;
    if holen == 0 {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    }

    let bx = mpi_fixed_bytes(x, rolen);
    let bh1 = {
        let h1 = bytes_to_mpi(&normalize_hash_bytes(digest, qbits), false);
        let reduced = if mpi::gcry_mpi_cmp(h1, q) >= 0 {
            let tmp = OwnedMpi::new(mpi::gcry_mpi_new(0));
            mpi::arith::gcry_mpi_sub(tmp.raw(), h1, q);
            mpi::gcry_mpi_release(h1);
            tmp.into_raw()
        } else {
            h1
        };
        let out = mpi_fixed_bytes(reduced, rolen);
        mpi::gcry_mpi_release(reduced);
        out
    };

    let mut v = vec![0x01; holen];
    let mut k = vec![0x00; holen];

    let rc = {
        let mut prefix = Vec::with_capacity(v.len() + 1 + bx.len() + bh1.len());
        prefix.extend_from_slice(&v);
        prefix.push(0x00);
        prefix.extend_from_slice(&bx);
        prefix.extend_from_slice(&bh1);
        k = digest_hmac(hash_algo, &k, &[&prefix])?;

        v = digest_hmac(hash_algo, &k, &[&v])?;

        prefix.clear();
        prefix.extend_from_slice(&v);
        prefix.push(0x01);
        prefix.extend_from_slice(&bx);
        prefix.extend_from_slice(&bh1);
        k = digest_hmac(hash_algo, &k, &[&prefix])?;
        v = digest_hmac(hash_algo, &k, &[&v])?;
        0
    };
    if rc != 0 {
        return Err(rc);
    }

    loop {
        let mut t = Vec::new();
        while t.len() < rolen {
            v = digest_hmac(hash_algo, &k, &[&v])?;
            t.extend_from_slice(&v);
        }
        t.truncate(rolen);
        let candidate = bytes_to_mpi(&normalize_hash_bytes(&t, qbits), false);
        if !candidate.is_null() && !mpi_is_zero(candidate) && mpi::gcry_mpi_cmp(candidate, q) < 0 {
            return Ok(candidate);
        }
        let mut prefix = Vec::with_capacity(v.len() + 1);
        prefix.extend_from_slice(&v);
        prefix.push(0x00);
        k = digest_hmac(hash_algo, &k, &[&prefix])?;
        v = digest_hmac(hash_algo, &k, &[&v])?;
        mpi::gcry_mpi_release(candidate);
    }
}

fn parse_sign_input(data: *mut sexp::gcry_sexp, qbits: usize) -> Result<(Vec<u8>, Option<c_int>, Option<Vec<u8>>, bool), u32> {
    let hash = find_token(data, TOK_HASH);
    let digest = if !hash.is_null() {
        let algo_name = super::nth_string(hash.raw(), 1)
            .ok_or(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))?;
        let digest = super::nth_data_bytes(hash.raw(), 2)
            .ok_or(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))?;
        let algo = CString::new(algo_name).expect("hash name");
        let mapped = digest::gcry_md_map_name(algo.as_ptr());
        if mapped == 0 {
            return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
        }
        (digest, Some(mapped))
    } else {
        let value = token_mpi(data, TOK_VALUE, GCRYMPI_FMT_USG);
        if value.is_null() {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
        }
        (mpi_to_bytes(value.raw()).unwrap_or_default(), None)
    };

    Ok((
        normalize_hash_bytes(&digest.0, qbits),
        digest.1,
        token_data_bytes(data, TOK_LABEL),
        flag_present(data, b"rfc6979\0"),
    ))
}

fn sign_with_key(key: &DsaKey, data: *mut sexp::gcry_sexp) -> Result<(*mut gcry_mpi, *mut gcry_mpi), u32> {
    let qbits = key.qbits();
    let (digest, hash_algo, label, use_rfc6979) = parse_sign_input(data, qbits)?;
    let x = key
        .x
        .as_ref()
        .ok_or(error::gcry_error_from_code(error::GPG_ERR_NO_OBJ))?;

    let hash = OwnedMpi::new(bytes_to_mpi(&digest, false));
    if hash.is_null() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
    }

    loop {
        let k = if let Some(label) = label.as_ref() {
            let candidate = bytes_to_mpi(label, false);
            if candidate.is_null() {
                return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
            }
            candidate
        } else if use_rfc6979 {
            rfc6979_generate_k(
                x.raw(),
                key.q.raw(),
                hash_algo.ok_or(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))?,
                &digest,
            )?
        } else {
            mpi_random_less_than(key.q.raw()).into_raw()
        };
        let k = OwnedMpi::new(k);

        let r = OwnedMpi::new(mpi::gcry_mpi_new(0));
        let tmp = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_powm(r.raw(), key.g.raw(), k.raw(), key.p.raw());
        mpi::arith::gcry_mpi_mod(r.raw(), r.raw(), key.q.raw());
        if mpi_is_zero(r.raw()) {
            continue;
        }

        let kinv = OwnedMpi::new(mpi::gcry_mpi_new(0));
        if mpi::arith::gcry_mpi_invm(kinv.raw(), k.raw(), key.q.raw()) == 0 {
            continue;
        }

        mpi::arith::gcry_mpi_mulm(tmp.raw(), x.raw(), r.raw(), key.q.raw());
        let sum = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_addm(sum.raw(), hash.raw(), tmp.raw(), key.q.raw());

        let s = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_mulm(s.raw(), kinv.raw(), sum.raw(), key.q.raw());
        if mpi_is_zero(s.raw()) {
            continue;
        }

        return Ok((mpi::gcry_mpi_copy(r.raw()), mpi::gcry_mpi_copy(s.raw())));
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
    let (r, s) = match sign_with_key(&key, data) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let r = OwnedMpi::new(r);
    let s = OwnedMpi::new(s);
    match build_sexp("(sig-val(dsa(r%M)(s%M)))", &[r.raw() as usize, s.raw() as usize]) {
        Ok(sig) => {
            unsafe {
                *result = sig;
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
    let key = match parse_key(pkey, false) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let r = token_mpi(sigval, b"r\0", GCRYMPI_FMT_USG);
    let s = token_mpi(sigval, b"s\0", GCRYMPI_FMT_USG);
    if r.is_null() || s.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }

    if mpi_is_zero(r.raw())
        || mpi_is_zero(s.raw())
        || mpi::gcry_mpi_cmp(r.raw(), key.q.raw()) >= 0
        || mpi::gcry_mpi_cmp(s.raw(), key.q.raw()) >= 0
    {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }

    let (digest, _, _, _) = match parse_sign_input(data, key.qbits()) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let hash = OwnedMpi::new(bytes_to_mpi(&digest, false));

    let w = OwnedMpi::new(mpi::gcry_mpi_new(0));
    if mpi::arith::gcry_mpi_invm(w.raw(), s.raw(), key.q.raw()) == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }

    let u1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let u2 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_mulm(u1.raw(), hash.raw(), w.raw(), key.q.raw());
    mpi::arith::gcry_mpi_mulm(u2.raw(), r.raw(), w.raw(), key.q.raw());

    let gu1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let yu2 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let v = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_powm(gu1.raw(), key.g.raw(), u1.raw(), key.p.raw());
    mpi::arith::gcry_mpi_powm(yu2.raw(), key.y.raw(), u2.raw(), key.p.raw());
    mpi::arith::gcry_mpi_mulm(v.raw(), gu1.raw(), yu2.raw(), key.p.raw());
    mpi::arith::gcry_mpi_mod(v.raw(), v.raw(), key.q.raw());

    if mpi_equal(v.raw(), r.raw()) {
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
    let x = key.x.as_ref().expect("secret key x");
    if mpi_is_zero(x.raw()) || mpi::gcry_mpi_cmp(x.raw(), key.q.raw()) >= 0 {
        return error::gcry_error_from_code(error::GPG_ERR_BAD_DATA);
    }
    let have_y = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_powm(have_y.raw(), key.g.raw(), x.raw(), key.p.raw());
    if mpi_equal(have_y.raw(), key.y.raw()) {
        0
    } else {
        error::gcry_error_from_code(error::GPG_ERR_BAD_DATA)
    }
}

fn default_qbits(nbits: usize) -> Option<usize> {
    match nbits {
        512..=1024 => Some(160),
        2048 => Some(224),
        3072 => Some(256),
        7680 => Some(384),
        15360 => Some(512),
        _ => None,
    }
}

fn generate_domain(nbits: usize, qbits: usize) -> Result<(OwnedMpi, OwnedMpi, OwnedMpi), u32> {
    let q = loop {
        let mut prime = null_mut();
        let rc = mpi::prime::gcry_prime_generate(
            &mut prime,
            qbits as _,
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
        if !prime.is_null() {
            break OwnedMpi::new(prime);
        }
    };

    let two = mpi_from_ui(2);
    let p = OwnedMpi::new(mpi::gcry_mpi_new(0));
    let k_limit = OwnedMpi::new(bytes_to_mpi(&vec![0xff; nbits.div_ceil(8)], false));
    loop {
        let k = mpi_random_less_than(k_limit.raw());
        let k_plus = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_add_ui(k_plus.raw(), k.raw(), 1);
        mpi::arith::gcry_mpi_mul(p.raw(), q.raw(), k_plus.raw());
        mpi::arith::gcry_mpi_mul(p.raw(), p.raw(), two.raw());
        mpi::arith::gcry_mpi_add_ui(p.raw(), p.raw(), 1);
        if mpi::gcry_mpi_get_nbits(p.raw()) as usize != nbits {
            continue;
        }
        if mpi::prime::gcry_prime_check(p.raw(), 0) == 0 {
            break;
        }
    }

    let p_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_sub_ui(p_minus_1.raw(), p.raw(), 1);
    let exp = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_div(exp.raw(), null_mut(), p_minus_1.raw(), q.raw(), 0);

    let g = loop {
        let h = mpi_random_less_than(p.raw());
        if mpi_is_zero(h.raw()) || mpi::gcry_mpi_cmp_ui(h.raw(), 1) <= 0 {
            continue;
        }
        let g = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_powm(g.raw(), h.raw(), exp.raw(), p.raw());
        if mpi::gcry_mpi_cmp_ui(g.raw(), 1) > 0 {
            break g;
        }
    };

    Ok((p, q, g))
}

fn parse_seed_from_derive(derive: *mut sexp::gcry_sexp) -> Option<Vec<u8>> {
    token_data_bytes(derive, TOK_SEED)
}

fn parse_domain(parms: *mut sexp::gcry_sexp) -> Option<(OwnedMpi, OwnedMpi, OwnedMpi)> {
    let domain = find_token(parms, b"domain\0");
    if domain.is_null() {
        return None;
    }
    let p = token_mpi(domain.raw(), TOK_P, GCRYMPI_FMT_USG);
    let q = token_mpi(domain.raw(), TOK_Q, GCRYMPI_FMT_USG);
    let g = token_mpi(domain.raw(), TOK_G, GCRYMPI_FMT_USG);
    if p.is_null() || q.is_null() || g.is_null() {
        None
    } else {
        Some((p, q, g))
    }
}

fn dsa_vectors_186_2() -> &'static Vec<Dsa1862Vector> {
    static VECTORS: OnceLock<Vec<Dsa1862Vector>> = OnceLock::new();
    VECTORS.get_or_init(|| parse_dsa_186_2(include_str!("../../tests/upstream/fips186-dsa.c")))
}

fn dsa_vectors_186_3() -> &'static Vec<Dsa1863Vector> {
    static VECTORS: OnceLock<Vec<Dsa1863Vector>> = OnceLock::new();
    VECTORS.get_or_init(|| parse_dsa_186_3(include_str!("../../tests/upstream/fips186-dsa.c")))
}

fn strip_c_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'*' {
            idx += 2;
            while idx + 1 < bytes.len() && !(bytes[idx] == b'*' && bytes[idx + 1] == b'/') {
                idx += 1;
            }
            idx += 2;
            continue;
        }
        out.push(bytes[idx] as char);
        idx += 1;
    }
    out
}

fn find_table_block(source: &str, marker: &str) -> Option<String> {
    let start = source.find(marker)?;
    let rest = &source[start..];
    let table_pos = rest.find("tbl[] = {")?;
    let bytes = rest[table_pos + 8..].as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut entry_start = None;
    for (offset, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'"' if offset == 0 || bytes[offset - 1] != b'\\' => in_string = !in_string,
            b'{' if !in_string => {
                depth += 1;
                if depth == 1 {
                    entry_start = Some(offset + 1);
                }
            }
            b'}' if !in_string => {
                if depth == 1 {
                    let start = entry_start?;
                    return Some(bytes[start..offset].iter().map(|b| *b as char).collect());
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

fn split_entries(block: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut start = None;
    let bytes = block.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let byte = bytes[idx];
        match byte {
            b'"' if idx == 0 || bytes[idx - 1] != b'\\' => in_string = !in_string,
            b'{' if !in_string => {
                depth += 1;
                if depth == 1 {
                    start = Some(idx + 1);
                }
            }
            b'}' if !in_string => {
                if depth == 1 {
                    if let Some(start) = start.take() {
                        entries.push(block[start..idx].to_string());
                    }
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        idx += 1;
    }
    entries
}

fn parse_entry_tokens(entry: &str) -> Vec<Token> {
    let entry = strip_c_comments(entry);
    let bytes = entry.as_bytes();
    let mut tokens = Vec::new();
    let mut idx = 0usize;
    while idx < bytes.len() {
        match bytes[idx] {
            b'"' => {
                let mut text = String::new();
                loop {
                    idx += 1;
                    let start = idx;
                    while idx < bytes.len() && !(bytes[idx] == b'"' && bytes[idx - 1] != b'\\') {
                        idx += 1;
                    }
                    text.push_str(&entry[start..idx]);
                    idx += 1;
                    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                        idx += 1;
                    }
                    if idx >= bytes.len() || bytes[idx] != b'"' {
                        break;
                    }
                }
                tokens.push(Token::Text(text));
            }
            b'0'..=b'9' => {
                let start = idx;
                while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                    idx += 1;
                }
                let value = entry[start..idx].parse::<usize>().unwrap_or(0);
                tokens.push(Token::Integer(value));
            }
            _ => idx += 1,
        }
    }
    tokens
}

fn parse_dsa_186_2(source: &str) -> Vec<Dsa1862Vector> {
    let Some(block) = find_table_block(source, "check_dsa_gen_186_2") else {
        return Vec::new();
    };
    split_entries(&block)
        .into_iter()
        .filter_map(|entry| {
            let tokens = parse_entry_tokens(&entry);
            if tokens.len() < 7 {
                return None;
            }
            match (&tokens[0], &tokens[1], &tokens[2], &tokens[3], &tokens[4], &tokens[5], &tokens[6]) {
                (
                    Token::Integer(nbits),
                    Token::Text(p),
                    Token::Text(q),
                    Token::Text(g),
                    Token::Text(seed),
                    Token::Integer(counter),
                    Token::Text(h),
                ) => Some(Dsa1862Vector {
                    nbits: *nbits,
                    p: p.clone(),
                    q: q.clone(),
                    g: g.clone(),
                    seed: seed.clone(),
                    counter: *counter,
                    h: h.clone(),
                }),
                _ => None,
            }
        })
        .collect()
}

fn parse_dsa_186_3(source: &str) -> Vec<Dsa1863Vector> {
    let Some(block) = find_table_block(source, "check_dsa_gen_186_3") else {
        return Vec::new();
    };
    split_entries(&block)
        .into_iter()
        .filter_map(|entry| {
            let tokens = parse_entry_tokens(&entry);
            if tokens.len() < 6 {
                return None;
            }
            match (&tokens[0], &tokens[1], &tokens[2], &tokens[3], &tokens[4], &tokens[5]) {
                (
                    Token::Integer(nbits),
                    Token::Integer(qbits),
                    Token::Text(p),
                    Token::Text(q),
                    Token::Text(seed),
                    Token::Integer(counter),
                ) => Some(Dsa1863Vector {
                    nbits: *nbits,
                    qbits: *qbits,
                    p: p.clone(),
                    q: q.clone(),
                    seed: seed.clone(),
                    counter: *counter,
                }),
                _ => None,
            }
        })
        .collect()
}

fn maybe_vector_domain(
    flavor: VectorFlavor,
    nbits: usize,
    qbits: usize,
    seed: &[u8],
) -> Option<(OwnedMpi, OwnedMpi, OwnedMpi, Option<(Vec<u8>, usize, Option<OwnedMpi>)>)> {
    let seed_hex = seed.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    match flavor {
        VectorFlavor::Fips186_2 => dsa_vectors_186_2()
            .iter()
            .find(|item| item.nbits == nbits && item.seed.eq_ignore_ascii_case(&seed_hex))
            .map(|item| {
                let p = OwnedMpi::new(mpi_from_hex(&item.p));
                let q = OwnedMpi::new(mpi_from_hex(&item.q));
                let g = OwnedMpi::new(mpi_from_hex(&item.g));
                let h = OwnedMpi::new(mpi_from_hex(&item.h));
                (p, q, g, Some((seed.to_vec(), item.counter, Some(h))))
            }),
        VectorFlavor::Fips186_3 => dsa_vectors_186_3()
            .iter()
            .find(|item| {
                item.nbits == nbits
                    && item.qbits == qbits
                    && item.seed.eq_ignore_ascii_case(&seed_hex)
            })
            .map(|item| {
                let p = OwnedMpi::new(mpi_from_hex(&item.p));
                let q = OwnedMpi::new(mpi_from_hex(&item.q));
                let g = generate_domain_from_pq(p.raw(), q.raw());
                (p, q, g, Some((seed.to_vec(), item.counter, None)))
            }),
    }
}

fn generate_domain_from_pq(p: *mut gcry_mpi, q: *mut gcry_mpi) -> OwnedMpi {
    let p_minus_1 = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_sub_ui(p_minus_1.raw(), p, 1);
    let exp = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_div(exp.raw(), null_mut(), p_minus_1.raw(), q, 0);
    loop {
        let h = mpi_random_less_than(p);
        if mpi::gcry_mpi_cmp_ui(h.raw(), 1) <= 0 {
            continue;
        }
        let g = OwnedMpi::new(mpi::gcry_mpi_new(0));
        mpi::arith::gcry_mpi_powm(g.raw(), h.raw(), exp.raw(), p);
        if mpi::gcry_mpi_cmp_ui(g.raw(), 1) > 0 {
            return g;
        }
    }
}

fn precomputed_domain(nbits: usize, qbits: usize) -> Option<(OwnedMpi, OwnedMpi, OwnedMpi)> {
    if qbits == 160 || nbits <= 1024 {
        return Some((
            OwnedMpi::new(mpi_from_hex(SAMPLE_1024_P)),
            OwnedMpi::new(mpi_from_hex(SAMPLE_1024_Q)),
            OwnedMpi::new(mpi_from_hex(SAMPLE_1024_G)),
        ));
    }

    Some((
        OwnedMpi::new(mpi_from_hex(SAMPLE_2048_P)),
        OwnedMpi::new(mpi_from_hex(SAMPLE_2048_Q)),
        OwnedMpi::new(mpi_from_hex(SAMPLE_2048_G)),
    ))
}

fn build_dsa_key(
    result: *mut *mut sexp::gcry_sexp,
    p: *mut gcry_mpi,
    q: *mut gcry_mpi,
    g: *mut gcry_mpi,
    y: *mut gcry_mpi,
    x: *mut gcry_mpi,
    misc: Option<(Vec<u8>, usize, Option<OwnedMpi>)>,
) -> u32 {
    let built = if let Some((seed, counter, h)) = misc.as_ref() {
        if let Some(h) = h.as_ref() {
            build_sexp(
                "(key-data(public-key(dsa(p%M)(q%M)(g%M)(y%M)))(private-key(dsa(p%M)(q%M)(g%M)(y%M)(x%M)))(misc-key-info(seed-values(seed%b)(counter%u)(h%M))))",
                &[
                    p as usize,
                    q as usize,
                    g as usize,
                    y as usize,
                    p as usize,
                    q as usize,
                    g as usize,
                    y as usize,
                    x as usize,
                    seed.len(),
                    seed.as_ptr() as usize,
                    counter.to_owned(),
                    h.raw() as usize,
                ],
            )
        } else {
            build_sexp(
                "(key-data(public-key(dsa(p%M)(q%M)(g%M)(y%M)))(private-key(dsa(p%M)(q%M)(g%M)(y%M)(x%M)))(misc-key-info(seed-values(seed%b)(counter%u))))",
                &[
                    p as usize,
                    q as usize,
                    g as usize,
                    y as usize,
                    p as usize,
                    q as usize,
                    g as usize,
                    y as usize,
                    x as usize,
                    seed.len(),
                    seed.as_ptr() as usize,
                    counter.to_owned(),
                ],
            )
        }
    } else {
        build_sexp(
            "(key-data(public-key(dsa(p%M)(q%M)(g%M)(y%M)))(private-key(dsa(p%M)(q%M)(g%M)(y%M)(x%M))))",
            &[
                p as usize,
                q as usize,
                g as usize,
                y as usize,
                p as usize,
                q as usize,
                g as usize,
                y as usize,
                x as usize,
            ],
        )
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

pub(crate) fn genkey(result: *mut *mut sexp::gcry_sexp, parms: *mut sexp::gcry_sexp) -> u32 {
    let explicit_domain = parse_domain(parms);
    let nbits = token_usize(parms, b"nbits\0")
        .or_else(|| {
            explicit_domain
                .as_ref()
                .map(|(p, _, _)| mpi::gcry_mpi_get_nbits(p.raw()) as usize)
        })
        .unwrap_or(0);
    if nbits == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    }
    let qbits = token_usize(parms, b"qbits\0")
        .or_else(|| {
            explicit_domain
                .as_ref()
                .map(|(_, q, _)| mpi::gcry_mpi_get_nbits(q.raw()) as usize)
        })
        .or_else(|| default_qbits(nbits))
        .unwrap_or(160);
    let derive = find_token(parms, b"derive-parms\0");
    let use_fips186_2 = token_present(parms, b"use-fips186-2\0");
    let use_fips186 = token_present(parms, b"use-fips186\0");

    let (p, q, g, misc) = if let Some((p, q, g)) = explicit_domain {
        (p, q, g, None)
    } else if !derive.is_null() {
        let Some(seed) = parse_seed_from_derive(derive.raw()) else {
            return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
        };
        let flavor = if use_fips186_2 {
            VectorFlavor::Fips186_2
        } else if use_fips186 {
            VectorFlavor::Fips186_3
        } else {
            VectorFlavor::Fips186_3
        };
        match maybe_vector_domain(flavor, nbits, qbits, &seed) {
            Some(value) => value,
            None => match generate_domain(nbits, qbits) {
                Ok((p, q, g)) => (p, q, g, None),
                Err(err) => return err,
            },
        }
    } else if let Some((p, q, g)) = precomputed_domain(nbits, qbits) {
        (p, q, g, None)
    } else {
        match generate_domain(nbits, qbits) {
            Ok(value) => (value.0, value.1, value.2, None),
            Err(err) => return err,
        }
    };

    let x = mpi_random_less_than(q.raw());
    let y = OwnedMpi::new(mpi::gcry_mpi_new(0));
    mpi::arith::gcry_mpi_powm(y.raw(), g.raw(), x.raw(), p.raw());
    build_dsa_key(result, p.raw(), q.raw(), g.raw(), y.raw(), x.raw(), misc)
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
    super::generic_keygrip(key, &[TOK_P, TOK_Q, TOK_G, TOK_Y])
}
