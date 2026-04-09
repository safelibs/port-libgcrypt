use std::sync::OnceLock;

use super::{gcry_mpi, GCRYMPI_FLAG_CONST, GCRYMPI_FLAG_IMMUTABLE, Mpz};

fn init_const(value: u64) -> *mut gcry_mpi {
    let raw = gcry_mpi::from_numeric(Mpz::from_ui(value as _), false);
    unsafe {
        (*raw).const_flag = true;
        (*raw).immutable = true;
    }
    raw
}

pub(crate) fn const_value(no: i32) -> &'static gcry_mpi {
    static ONE: OnceLock<usize> = OnceLock::new();
    static TWO: OnceLock<usize> = OnceLock::new();
    static THREE: OnceLock<usize> = OnceLock::new();
    static FOUR: OnceLock<usize> = OnceLock::new();
    static EIGHT: OnceLock<usize> = OnceLock::new();

    let ptr = match no {
        1 => *ONE.get_or_init(|| init_const(1) as usize),
        2 => *TWO.get_or_init(|| init_const(2) as usize),
        3 => *THREE.get_or_init(|| init_const(3) as usize),
        4 => *FOUR.get_or_init(|| init_const(4) as usize),
        8 => *EIGHT.get_or_init(|| init_const(8) as usize),
        _ => 0,
    };

    if ptr == 0 {
        // This path is only used for invalid callers.
        static ZERO: OnceLock<usize> = OnceLock::new();
        let zero = *ZERO.get_or_init(|| init_const(0) as usize);
        unsafe { &*(zero as *const gcry_mpi) }
    } else {
        unsafe { &*(ptr as *const gcry_mpi) }
    }
}

#[unsafe(export_name = "_gcry_mpi_get_const")]
pub extern "C" fn _gcry_mpi_get_const(no: i32) -> *mut gcry_mpi {
    match no {
        1 | 2 | 3 | 4 | 8 => const_value(no) as *const gcry_mpi as *mut gcry_mpi,
        _ => std::ptr::null_mut(),
    }
}
