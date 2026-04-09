use std::ffi::{c_int, c_ulong};
use std::ptr::null_mut;

use super::{
    __gmpz_add, __gmpz_add_ui, __gmpz_fdiv_qr, __gmpz_fdiv_r, __gmpz_gcd, __gmpz_invert,
    __gmpz_mod, __gmpz_mul, __gmpz_mul_2exp, __gmpz_mul_ui, __gmpz_powm, __gmpz_powm_sec,
    __gmpz_set, __gmpz_set_ui, __gmpz_sub, __gmpz_sub_ui, __gmpz_tdiv_qr, MpiKind, Mpz, compare,
    gcry_mpi, gcry_mpi_copy, gcry_mpi_release, make_result_numeric, maybe_secret_powm,
};

fn numeric_pair<'a>(u: *mut gcry_mpi, v: *mut gcry_mpi) -> Option<(&'a gcry_mpi, &'a gcry_mpi)> {
    unsafe { Some((gcry_mpi::as_ref(u)?, gcry_mpi::as_ref(v)?)) }
}

fn assign_binary_op(
    w: *mut gcry_mpi,
    u: *mut gcry_mpi,
    v: *mut gcry_mpi,
    op: unsafe extern "C" fn(
        *mut super::__mpz_struct,
        *const super::__mpz_struct,
        *const super::__mpz_struct,
    ),
) {
    let left_copy = gcry_mpi_copy(u);
    let right_copy = gcry_mpi_copy(v);
    let Some((left, right)) = numeric_pair(left_copy, right_copy) else {
        gcry_mpi_release(left_copy);
        gcry_mpi_release(right_copy);
        return;
    };
    let dest = make_result_numeric(w, left.secure || right.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            match (&left.kind, &right.kind) {
                (MpiKind::Numeric(l), MpiKind::Numeric(r)) => {
                    op(dest_ref.numeric_mut().as_mut_ptr(), l.as_ptr(), r.as_ptr());
                }
                _ => __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0),
            }
        }
    }
    gcry_mpi_release(left_copy);
    gcry_mpi_release(right_copy);
}

#[unsafe(export_name = "gcry_mpi_add")]
pub extern "C" fn gcry_mpi_add(w: *mut gcry_mpi, u: *mut gcry_mpi, v: *mut gcry_mpi) {
    assign_binary_op(w, u, v, __gmpz_add);
}

#[unsafe(export_name = "gcry_mpi_sub")]
pub extern "C" fn gcry_mpi_sub(w: *mut gcry_mpi, u: *mut gcry_mpi, v: *mut gcry_mpi) {
    assign_binary_op(w, u, v, __gmpz_sub);
}

#[unsafe(export_name = "gcry_mpi_mul")]
pub extern "C" fn gcry_mpi_mul(w: *mut gcry_mpi, u: *mut gcry_mpi, v: *mut gcry_mpi) {
    assign_binary_op(w, u, v, __gmpz_mul);
}

#[unsafe(export_name = "gcry_mpi_add_ui")]
pub extern "C" fn gcry_mpi_add_ui(w: *mut gcry_mpi, u: *mut gcry_mpi, v: c_ulong) {
    let copy = gcry_mpi_copy(u);
    let Some(src) = (unsafe { gcry_mpi::as_ref(copy) }) else {
        return;
    };
    let dest = make_result_numeric(w, src.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            match &src.kind {
                MpiKind::Numeric(number) => {
                    __gmpz_add_ui(dest_ref.numeric_mut().as_mut_ptr(), number.as_ptr(), v)
                }
                MpiKind::Opaque(_) => __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0),
            }
        }
    }
    gcry_mpi_release(copy);
}

#[unsafe(export_name = "gcry_mpi_sub_ui")]
pub extern "C" fn gcry_mpi_sub_ui(w: *mut gcry_mpi, u: *mut gcry_mpi, v: c_ulong) {
    let copy = gcry_mpi_copy(u);
    let Some(src) = (unsafe { gcry_mpi::as_ref(copy) }) else {
        return;
    };
    let dest = make_result_numeric(w, src.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            match &src.kind {
                MpiKind::Numeric(number) => {
                    __gmpz_sub_ui(dest_ref.numeric_mut().as_mut_ptr(), number.as_ptr(), v)
                }
                MpiKind::Opaque(_) => __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0),
            }
        }
    }
    gcry_mpi_release(copy);
}

#[unsafe(export_name = "gcry_mpi_mul_ui")]
pub extern "C" fn gcry_mpi_mul_ui(w: *mut gcry_mpi, u: *mut gcry_mpi, v: c_ulong) {
    let copy = gcry_mpi_copy(u);
    let Some(src) = (unsafe { gcry_mpi::as_ref(copy) }) else {
        return;
    };
    let dest = make_result_numeric(w, src.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            match &src.kind {
                MpiKind::Numeric(number) => {
                    __gmpz_mul_ui(dest_ref.numeric_mut().as_mut_ptr(), number.as_ptr(), v)
                }
                MpiKind::Opaque(_) => __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0),
            }
        }
    }
    gcry_mpi_release(copy);
}

fn assign_mod_op(
    w: *mut gcry_mpi,
    u: *mut gcry_mpi,
    v: *mut gcry_mpi,
    m: *mut gcry_mpi,
    op: unsafe extern "C" fn(
        *mut super::__mpz_struct,
        *const super::__mpz_struct,
        *const super::__mpz_struct,
    ),
) {
    let base_copy = gcry_mpi_copy(u);
    let other_copy = gcry_mpi_copy(v);
    let mod_copy = gcry_mpi_copy(m);
    let Some(base) = (unsafe { gcry_mpi::as_ref(base_copy) }) else {
        return;
    };
    let Some(other) = (unsafe { gcry_mpi::as_ref(other_copy) }) else {
        return;
    };
    let Some(modulus) = (unsafe { gcry_mpi::as_ref(mod_copy) }) else {
        return;
    };
    let dest = make_result_numeric(w, base.secure || other.secure || modulus.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            if let (MpiKind::Numeric(lhs), MpiKind::Numeric(rhs), MpiKind::Numeric(modn)) =
                (&base.kind, &other.kind, &modulus.kind)
            {
                let mut tmp = Mpz::new(0);
                op(tmp.as_mut_ptr(), lhs.as_ptr(), rhs.as_ptr());
                __gmpz_mod(
                    dest_ref.numeric_mut().as_mut_ptr(),
                    tmp.as_ptr(),
                    modn.as_ptr(),
                );
            } else {
                __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0);
            }
        }
    }
    gcry_mpi_release(base_copy);
    gcry_mpi_release(other_copy);
    gcry_mpi_release(mod_copy);
}

#[unsafe(export_name = "gcry_mpi_addm")]
pub extern "C" fn gcry_mpi_addm(
    w: *mut gcry_mpi,
    u: *mut gcry_mpi,
    v: *mut gcry_mpi,
    m: *mut gcry_mpi,
) {
    assign_mod_op(w, u, v, m, __gmpz_add);
}

#[unsafe(export_name = "gcry_mpi_subm")]
pub extern "C" fn gcry_mpi_subm(
    w: *mut gcry_mpi,
    u: *mut gcry_mpi,
    v: *mut gcry_mpi,
    m: *mut gcry_mpi,
) {
    assign_mod_op(w, u, v, m, __gmpz_sub);
}

#[unsafe(export_name = "gcry_mpi_mulm")]
pub extern "C" fn gcry_mpi_mulm(
    w: *mut gcry_mpi,
    u: *mut gcry_mpi,
    v: *mut gcry_mpi,
    m: *mut gcry_mpi,
) {
    assign_mod_op(w, u, v, m, __gmpz_mul);
}

#[unsafe(export_name = "gcry_mpi_mul_2exp")]
pub extern "C" fn gcry_mpi_mul_2exp(w: *mut gcry_mpi, u: *mut gcry_mpi, cnt: c_ulong) {
    let copy = gcry_mpi_copy(u);
    let Some(src) = (unsafe { gcry_mpi::as_ref(copy) }) else {
        return;
    };
    let dest = make_result_numeric(w, src.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            match &src.kind {
                MpiKind::Numeric(number) => {
                    __gmpz_mul_2exp(
                        dest_ref.numeric_mut().as_mut_ptr(),
                        number.as_ptr(),
                        cnt as usize,
                    );
                }
                MpiKind::Opaque(_) => __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0),
            }
        }
    }
    gcry_mpi_release(copy);
}

#[unsafe(export_name = "gcry_mpi_div")]
pub extern "C" fn gcry_mpi_div(
    q: *mut gcry_mpi,
    r: *mut gcry_mpi,
    dividend: *mut gcry_mpi,
    divisor: *mut gcry_mpi,
    round: c_int,
) {
    let num_copy = gcry_mpi_copy(dividend);
    let den_copy = gcry_mpi_copy(divisor);
    let Some(num) = (unsafe { gcry_mpi::as_ref(num_copy) }) else {
        return;
    };
    let Some(den) = (unsafe { gcry_mpi::as_ref(den_copy) }) else {
        return;
    };
    if !matches!(
        (&num.kind, &den.kind),
        (MpiKind::Numeric(_), MpiKind::Numeric(_))
    ) {
        return;
    }

    let qdest = if q.is_null() {
        null_mut()
    } else {
        make_result_numeric(q, num.secure || den.secure)
    };
    let rdest = if r.is_null() {
        null_mut()
    } else {
        make_result_numeric(r, num.secure || den.secure)
    };

    unsafe {
        let lhs = match &num.kind {
            MpiKind::Numeric(value) => value,
            _ => unreachable!(),
        };
        let rhs = match &den.kind {
            MpiKind::Numeric(value) => value,
            _ => unreachable!(),
        };
        let mut qtmp = Mpz::new(0);
        let mut rtmp = Mpz::new(0);
        if round < 0 {
            __gmpz_fdiv_qr(
                qtmp.as_mut_ptr(),
                rtmp.as_mut_ptr(),
                lhs.as_ptr(),
                rhs.as_ptr(),
            );
        } else {
            __gmpz_tdiv_qr(
                qtmp.as_mut_ptr(),
                rtmp.as_mut_ptr(),
                lhs.as_ptr(),
                rhs.as_ptr(),
            );
        }
        if let Some(dest) = gcry_mpi::as_mut(qdest) {
            __gmpz_set(dest.numeric_mut().as_mut_ptr(), qtmp.as_ptr());
        }
        if let Some(dest) = gcry_mpi::as_mut(rdest) {
            __gmpz_set(dest.numeric_mut().as_mut_ptr(), rtmp.as_ptr());
        }
    }
    gcry_mpi_release(num_copy);
    gcry_mpi_release(den_copy);
}

#[unsafe(export_name = "gcry_mpi_mod")]
pub extern "C" fn gcry_mpi_mod(r: *mut gcry_mpi, dividend: *mut gcry_mpi, divisor: *mut gcry_mpi) {
    let num_copy = gcry_mpi_copy(dividend);
    let den_copy = gcry_mpi_copy(divisor);
    let Some(num) = (unsafe { gcry_mpi::as_ref(num_copy) }) else {
        return;
    };
    let Some(den) = (unsafe { gcry_mpi::as_ref(den_copy) }) else {
        return;
    };
    let dest = make_result_numeric(r, num.secure || den.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            if let (MpiKind::Numeric(lhs), MpiKind::Numeric(rhs)) = (&num.kind, &den.kind) {
                __gmpz_fdiv_r(
                    dest_ref.numeric_mut().as_mut_ptr(),
                    lhs.as_ptr(),
                    rhs.as_ptr(),
                );
            } else {
                __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0);
            }
        }
    }
    gcry_mpi_release(num_copy);
    gcry_mpi_release(den_copy);
}

#[unsafe(export_name = "gcry_mpi_powm")]
pub extern "C" fn gcry_mpi_powm(
    w: *mut gcry_mpi,
    b: *const gcry_mpi,
    e: *const gcry_mpi,
    m: *const gcry_mpi,
) {
    let base_copy = gcry_mpi_copy(b.cast_mut());
    let exp_copy = gcry_mpi_copy(e.cast_mut());
    let mod_copy = gcry_mpi_copy(m.cast_mut());
    let Some(base) = (unsafe { gcry_mpi::as_ref(base_copy) }) else {
        return;
    };
    let Some(exp) = (unsafe { gcry_mpi::as_ref(exp_copy) }) else {
        return;
    };
    let Some(modulus) = (unsafe { gcry_mpi::as_ref(mod_copy) }) else {
        return;
    };
    let dest = make_result_numeric(w, base.secure || exp.secure || modulus.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            if let (MpiKind::Numeric(bn), MpiKind::Numeric(en), MpiKind::Numeric(mn)) =
                (&base.kind, &exp.kind, &modulus.kind)
            {
                if maybe_secret_powm(exp, modulus)
                    && compare(modulus, super::consts::const_value(1)) > 0
                {
                    __gmpz_powm_sec(
                        dest_ref.numeric_mut().as_mut_ptr(),
                        bn.as_ptr(),
                        en.as_ptr(),
                        mn.as_ptr(),
                    );
                } else {
                    __gmpz_powm(
                        dest_ref.numeric_mut().as_mut_ptr(),
                        bn.as_ptr(),
                        en.as_ptr(),
                        mn.as_ptr(),
                    );
                }
            } else {
                __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0);
            }
        }
    }
    gcry_mpi_release(base_copy);
    gcry_mpi_release(exp_copy);
    gcry_mpi_release(mod_copy);
}

#[unsafe(export_name = "gcry_mpi_gcd")]
pub extern "C" fn gcry_mpi_gcd(g: *mut gcry_mpi, a: *mut gcry_mpi, b: *mut gcry_mpi) -> c_int {
    let left_copy = gcry_mpi_copy(a);
    let right_copy = gcry_mpi_copy(b);
    let Some(left) = (unsafe { gcry_mpi::as_ref(left_copy) }) else {
        return 0;
    };
    let Some(right) = (unsafe { gcry_mpi::as_ref(right_copy) }) else {
        return 0;
    };
    let dest = make_result_numeric(g, left.secure || right.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            if let (MpiKind::Numeric(lhs), MpiKind::Numeric(rhs)) = (&left.kind, &right.kind) {
                __gmpz_gcd(
                    dest_ref.numeric_mut().as_mut_ptr(),
                    lhs.as_ptr(),
                    rhs.as_ptr(),
                );
            } else {
                __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0);
            }
            let result = (super::gcry_mpi_cmp_ui(dest, 1) == 0) as c_int;
            gcry_mpi_release(left_copy);
            gcry_mpi_release(right_copy);
            return result;
        }
    }
    gcry_mpi_release(left_copy);
    gcry_mpi_release(right_copy);
    0
}

#[unsafe(export_name = "gcry_mpi_invm")]
pub extern "C" fn gcry_mpi_invm(x: *mut gcry_mpi, a: *mut gcry_mpi, m: *mut gcry_mpi) -> c_int {
    let value_copy = gcry_mpi_copy(a);
    let mod_copy = gcry_mpi_copy(m);
    let Some(value) = (unsafe { gcry_mpi::as_ref(value_copy) }) else {
        return 0;
    };
    let Some(modulus) = (unsafe { gcry_mpi::as_ref(mod_copy) }) else {
        return 0;
    };
    let dest = make_result_numeric(x, value.secure || modulus.secure);
    unsafe {
        if let Some(dest_ref) = gcry_mpi::as_mut(dest) {
            if let (MpiKind::Numeric(lhs), MpiKind::Numeric(rhs)) = (&value.kind, &modulus.kind) {
                let result = __gmpz_invert(
                    dest_ref.numeric_mut().as_mut_ptr(),
                    lhs.as_ptr(),
                    rhs.as_ptr(),
                ) as c_int;
                gcry_mpi_release(value_copy);
                gcry_mpi_release(mod_copy);
                return result;
            }
            __gmpz_set_ui(dest_ref.numeric_mut().as_mut_ptr(), 0);
        }
    }
    gcry_mpi_release(value_copy);
    gcry_mpi_release(mod_copy);
    0
}
