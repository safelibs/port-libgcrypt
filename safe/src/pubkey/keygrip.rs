use std::ptr::{copy_nonoverlapping, null_mut};

use crate::alloc;
use crate::digest::algorithms;
use crate::mpi::{self, Mpz};
use crate::sexp;

use super::{KEYGRIP_LEN, encoding};

fn canonical_atom(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(bytes.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(bytes);
}

fn add_param_record(key: *mut sexp::gcry_sexp, name: &str, out: &mut Vec<u8>) -> bool {
    let Some(bytes) = encoding::token_bytes_from_mpi(key, name) else {
        return false;
    };
    out.push(b'(');
    canonical_atom(name.as_bytes(), out);
    canonical_atom(&bytes, out);
    out.push(b')');
    true
}

fn add_raw_param_record(name: &str, bytes: &[u8], out: &mut Vec<u8>) {
    out.push(b'(');
    canonical_atom(name.as_bytes(), out);
    canonical_atom(bytes, out);
    out.push(b')');
}

fn ecc_curve(key: *mut sexp::gcry_sexp) -> Option<mpi::ec::Curve> {
    encoding::token_string(key, "curve")
        .and_then(|name| mpi::ec::curve_by_name(&name))
        .or_else(|| {
            let p = encoding::token_mpz(key, "p")?;
            if p.cmp(&Mpz::from_hex(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            )) == 0
            {
                mpi::ec::curve_by_name("NIST P-256")
            } else {
                None
            }
        })
}

fn ecc_param_bytes(
    key: *mut sexp::gcry_sexp,
    curve: Option<&mpi::ec::Curve>,
    name: &str,
) -> Option<Vec<u8>> {
    if let Some(value) = encoding::token_mpz(key, name).map(|value| value.to_be()) {
        return Some(value);
    }
    if let Some(curve) = curve {
        if curve.name == "Ed25519" {
            return match name {
                "a" => Some(vec![1]),
                "b" => Some(
                    Mpz::from_hex(
                        "2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A",
                    )
                    .to_be(),
                ),
                _ => mpi::ec::curve_param_bytes(curve, name),
            };
        }
        if curve.name == "Curve25519" {
            return match name {
                "a" => Some(Mpz::from_hex("01DB41").to_be()),
                "g" => {
                    let mut point = vec![4];
                    point.extend_from_slice(&Mpz::from_ui(9).to_be_padded(32));
                    point.extend_from_slice(
                        &Mpz::from_hex(
                            "20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9",
                        )
                        .to_be_padded(32),
                    );
                    Some(point)
                }
                _ => mpi::ec::curve_param_bytes(curve, name),
            };
        }
    }
    curve.and_then(|curve| mpi::ec::curve_param_bytes(curve, name))
}

fn ecc_q_bytes(key: *mut sexp::gcry_sexp, curve: Option<&mpi::ec::Curve>) -> Option<Vec<u8>> {
    let mut q = encoding::token_mpz(key, "q").map(|value| value.to_be())?;
    if encoding::has_flag(key, "eddsa") {
        if let Some(curve) = curve {
            if let Some(point) = mpi::ec::decode_point(curve, &q) {
                q = mpi::ec::encode_eddsa(&point, curve.field_bytes);
            }
        }
    } else if encoding::has_flag(key, "djb-tweak") {
        if q.first() == Some(&0x40) {
            q.remove(0);
        }
    } else if q.first().is_some_and(|byte| *byte == 0x02 || *byte == 0x03) {
        if let Some(curve) = curve {
            if let Some(point) = mpi::ec::decode_point(curve, &q) {
                q = mpi::ec::encode_point(curve, &point);
            }
        }
    }
    Some(q)
}

fn material(key: *mut sexp::gcry_sexp) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if has_any_token(key, &["rsa", "RSA", "openpgp-rsa", "OPENPGP-RSA"]) {
        out.extend_from_slice(&encoding::token_bytes_from_mpi(key, "n")?);
        Some(out)
    } else if has_any_token(key, &["dsa", "DSA"]) {
        for name in ["p", "q", "g", "y"] {
            add_param_record(key, name, &mut out);
        }
        Some(out)
    } else if has_any_token(key, &["elg", "ELG", "elgamal", "ELGAMAL"]) {
        for name in ["p", "g", "y"] {
            add_param_record(key, name, &mut out);
        }
        Some(out)
    } else if has_any_token(
        key,
        &[
            "ecc", "ECC", "ecdsa", "ECDSA", "eddsa", "EDDSA", "ecdh", "ECDH",
        ],
    ) {
        let curve = ecc_curve(key);
        for name in ["p", "a", "b", "g", "n"] {
            let bytes = ecc_param_bytes(key, curve.as_ref(), name)?;
            add_raw_param_record(name, &bytes, &mut out);
        }
        let q = ecc_q_bytes(key, curve.as_ref())?;
        add_raw_param_record("q", &q, &mut out);
        Some(out)
    } else {
        None
    }
}

fn has_any_token(key: *mut sexp::gcry_sexp, names: &[&str]) -> bool {
    names.iter().any(|name| encoding::has_token(key, name))
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_pk_get_keygrip(key: *mut sexp::gcry_sexp, array: *mut u8) -> *mut u8 {
    let Some(material) = material(key) else {
        return null_mut();
    };
    let Some(digest_storage) = algorithms::digest_once(algorithms::GCRY_MD_SHA1, &material) else {
        return null_mut();
    };
    let digest = &digest_storage;
    let out = if array.is_null() {
        alloc::gcry_malloc(KEYGRIP_LEN).cast::<u8>()
    } else {
        array
    };
    if out.is_null() {
        return null_mut();
    }
    unsafe { copy_nonoverlapping(digest.as_ptr(), out, KEYGRIP_LEN) };
    out
}
