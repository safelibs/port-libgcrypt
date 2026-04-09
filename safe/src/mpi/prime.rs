use std::ffi::{c_int, c_uint, c_void};
use std::ptr::{copy_nonoverlapping, null_mut};

use crate::alloc;
use crate::error;
use crate::os_rng;

use super::{
    __gmpz_add_ui, __gmpz_cmp_ui, __gmpz_mod, __gmpz_mul, __gmpz_mul_2exp, __gmpz_nextprime,
    __gmpz_powm, __gmpz_probab_prime_p, __gmpz_set, __gmpz_set_ui, __gmpz_sub_ui, alloc_output_bytes,
    gcry_mpi, GCRY_PRIME_FLAG_SECRET, GCRY_PRIME_FLAG_SPECIAL_FACTOR, MpiKind, Mpz,
};

type gcry_prime_check_func_t = Option<unsafe extern "C" fn(*mut c_void, c_int, *mut gcry_mpi) -> c_int>;

fn probable_prime(number: &Mpz) -> bool {
    unsafe { __gmpz_probab_prime_p(number.as_ptr(), 32) != 0 }
}

fn random_odd_with_bits(bits: usize) -> Mpz {
    let nbytes = bits.div_ceil(8);
    let mut bytes = vec![0u8; nbytes.max(1)];
    os_rng::fill_random(&mut bytes);
    if let Some(first) = bytes.first_mut() {
        let top_mask = if bits % 8 == 0 {
            0xff
        } else {
            ((1u16 << (bits % 8)) - 1) as u8
        };
        *first &= top_mask;
        let top_bit = 1u8 << ((bits - 1) % 8);
        *first |= top_bit;
    }
    if let Some(last) = bytes.last_mut() {
        *last |= 1;
    }
    super::import_unsigned_bytes(&bytes)
}

fn generate_prime_bits(bits: usize) -> Mpz {
    loop {
        let candidate = random_odd_with_bits(bits);
        let mut prime = Mpz::new(bits);
        unsafe {
            __gmpz_nextprime(prime.as_mut_ptr(), candidate.as_ptr());
        }
        if unsafe { super::__gmpz_sizeinbase(prime.as_ptr(), 2) } == bits && probable_prime(&prime) {
            return prime;
        }
    }
}

fn build_factor_array(items: Vec<*mut gcry_mpi>) -> *mut *mut gcry_mpi {
    let ptr = alloc::gcry_calloc(items.len() + 1, std::mem::size_of::<*mut gcry_mpi>());
    if ptr.is_null() {
        return null_mut();
    }
    unsafe {
        copy_nonoverlapping(items.as_ptr(), ptr.cast::<*mut gcry_mpi>(), items.len());
    }
    ptr.cast()
}

#[unsafe(export_name = "gcry_prime_generate")]
pub extern "C" fn gcry_prime_generate(
    prime: *mut *mut gcry_mpi,
    prime_bits: c_uint,
    factor_bits: c_uint,
    factors: *mut *mut *mut gcry_mpi,
    cb_func: gcry_prime_check_func_t,
    cb_arg: *mut c_void,
    _random_level: c_int,
    flags: c_uint,
) -> u32 {
    if !prime.is_null() {
        unsafe {
            *prime = null_mut();
        }
    }
    if !factors.is_null() {
        unsafe {
            *factors = null_mut();
        }
    }
    if prime.is_null() || prime_bits < 2 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let secure = flags & GCRY_PRIME_FLAG_SECRET != 0;
    let mut q = if factor_bits != 0 {
        generate_prime_bits(factor_bits as usize)
    } else {
        Mpz::from_ui(2)
    };

    let p = loop {
        let mut candidate = if factor_bits != 0 && flags & GCRY_PRIME_FLAG_SPECIAL_FACTOR != 0 {
            let cofactor_bits = (prime_bits.saturating_sub(factor_bits + 1)) as usize;
            let cofactor = random_odd_with_bits(cofactor_bits.max(2));
            let mut tmp = Mpz::new(prime_bits as usize);
            unsafe {
                __gmpz_mul(tmp.as_mut_ptr(), q.as_ptr(), cofactor.as_ptr());
                __gmpz_mul_2exp(tmp.as_mut_ptr(), tmp.as_ptr(), 1);
                __gmpz_add_ui(tmp.as_mut_ptr(), tmp.as_ptr(), 1);
            }
            tmp
        } else {
            generate_prime_bits(prime_bits as usize)
        };

        if unsafe { super::__gmpz_sizeinbase(candidate.as_ptr(), 2) } != prime_bits as usize {
            continue;
        }
        if !probable_prime(&candidate) {
            continue;
        }

        let raw = gcry_mpi::from_numeric(Mpz::clone_from(candidate.as_ptr()), secure);
        let accepted = if let Some(callback) = cb_func {
            unsafe { callback(cb_arg, 0, raw) == 0 }
        } else {
            true
        };
        if accepted {
            super::gcry_mpi_release(raw);
            break candidate;
        }
        super::gcry_mpi_release(raw);
    };

    unsafe {
        *prime = gcry_mpi::from_numeric(p, secure);
    }

    if !factors.is_null() {
        let mut items = Vec::new();
        items.push(super::consts::const_value(2).deep_copy());
        if factor_bits != 0 {
            items.push(gcry_mpi::from_numeric(q, secure));
        }
        unsafe {
            *factors = build_factor_array(items);
        }
    }

    0
}

#[unsafe(export_name = "gcry_prime_check")]
pub extern "C" fn gcry_prime_check(x: *mut gcry_mpi, _flags: c_uint) -> u32 {
    let Some(value) = (unsafe { gcry_mpi::as_ref(x) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    match &value.kind {
        MpiKind::Numeric(number) if probable_prime(number) => 0,
        _ => error::gcry_error_from_code(error::GPG_ERR_NO_PRIME),
    }
}

#[unsafe(export_name = "gcry_prime_group_generator")]
pub extern "C" fn gcry_prime_group_generator(
    r_g: *mut *mut gcry_mpi,
    prime: *mut gcry_mpi,
    factors: *mut *mut gcry_mpi,
    start_g: *mut gcry_mpi,
) -> u32 {
    if !r_g.is_null() {
        unsafe {
            *r_g = null_mut();
        }
    }
    let Some(prime_value) = (unsafe { gcry_mpi::as_ref(prime) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    let MpiKind::Numeric(prime_num) = &prime_value.kind else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };

    let mut p_minus_1 = Mpz::clone_from(prime_num.as_ptr());
    unsafe {
        __gmpz_sub_ui(p_minus_1.as_mut_ptr(), p_minus_1.as_ptr(), 1);
    }

    let mut candidate = if let Some(start) = unsafe { gcry_mpi::as_ref(start_g) } {
        if let MpiKind::Numeric(value) = &start.kind {
            Mpz::clone_from(value.as_ptr())
        } else {
            Mpz::from_ui(2)
        }
    } else {
        Mpz::from_ui(2)
    };

    loop {
        let mut ok = true;
        let mut idx = 0usize;
        while !factors.is_null() {
            let factor = unsafe { *factors.add(idx) };
            if factor.is_null() {
                break;
            }
            let Some(factor_value) = (unsafe { gcry_mpi::as_ref(factor) }) else {
                break;
            };
            let MpiKind::Numeric(factor_num) = &factor_value.kind else {
                idx += 1;
                continue;
            };
            let mut exp = Mpz::new(0);
            unsafe {
                super::__gmpz_tdiv_qr(exp.as_mut_ptr(), Mpz::new(0).as_mut_ptr(), p_minus_1.as_ptr(), factor_num.as_ptr());
            }
            let mut residue = Mpz::new(0);
            unsafe {
                __gmpz_powm(residue.as_mut_ptr(), candidate.as_ptr(), exp.as_ptr(), prime_num.as_ptr());
            }
            if unsafe { __gmpz_cmp_ui(residue.as_ptr(), 1) } == 0 {
                ok = false;
                break;
            }
            idx += 1;
        }
        if ok {
            if !r_g.is_null() {
                unsafe {
                    *r_g = gcry_mpi::from_numeric(candidate, false);
                }
            }
            return 0;
        }
        unsafe {
            __gmpz_add_ui(candidate.as_mut_ptr(), candidate.as_ptr(), 1);
        }
    }
}

#[unsafe(export_name = "gcry_prime_release_factors")]
pub extern "C" fn gcry_prime_release_factors(factors: *mut *mut gcry_mpi) {
    if factors.is_null() {
        return;
    }
    let mut idx = 0usize;
    loop {
        let item = unsafe { *factors.add(idx) };
        if item.is_null() {
            break;
        }
        super::gcry_mpi_release(item);
        idx += 1;
    }
    alloc::gcry_free(factors.cast());
}
