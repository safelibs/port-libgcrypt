use std::ffi::{CStr, c_int, c_void};
use std::ptr::{copy_nonoverlapping, null_mut};

use crate::alloc;
use crate::error;

use super::{
    __gmpz_abs, __gmpz_neg, __gmpz_set_ui, GCRYMPI_FMT_HEX, GCRYMPI_FMT_OPAQUE, GCRYMPI_FMT_PGP,
    GCRYMPI_FMT_SSH, GCRYMPI_FMT_STD, GCRYMPI_FMT_USG, MAX_EXTERN_MPI_BYTES, MAX_EXTERN_PGP_BITS,
    MpiKind, Mpz, export_unsigned, gcry_mpi, import_unsigned_bytes, mpz_sgn, set_errno_oom,
};

fn std_bytes_from_numeric(value: &gcry_mpi) -> Vec<u8> {
    let MpiKind::Numeric(number) = &value.kind else {
        return Vec::new();
    };

    let sign = unsafe { mpz_sgn(number.as_ptr()) };
    if sign == 0 {
        return Vec::new();
    }

    if sign > 0 {
        let mut out = export_unsigned(number.as_ptr());
        if out.first().is_some_and(|byte| byte & 0x80 != 0) {
            out.insert(0, 0);
        }
        return out;
    }

    let mut abs_value = Mpz::clone_from(number.as_ptr());
    unsafe {
        __gmpz_abs(abs_value.as_mut_ptr(), abs_value.as_ptr());
    }
    let abs_bits = unsafe { super::__gmpz_sizeinbase(abs_value.as_ptr(), 2) };
    let mut limit = Mpz::from_ui(1);
    unsafe {
        super::__gmpz_mul_2exp(
            limit.as_mut_ptr(),
            limit.as_ptr(),
            abs_bits.saturating_sub(1),
        );
    }
    let exact_boundary = unsafe { super::__gmpz_cmp(abs_value.as_ptr(), limit.as_ptr()) } == 0;
    let nbytes = if exact_boundary {
        abs_bits.div_ceil(8)
    } else {
        (abs_bits + 1).div_ceil(8)
    };

    let mut two_comp = Mpz::new(nbytes * 8);
    unsafe {
        __gmpz_set_ui(two_comp.as_mut_ptr(), 1);
        super::__gmpz_mul_2exp(two_comp.as_mut_ptr(), two_comp.as_ptr(), nbytes * 8);
        super::__gmpz_sub(two_comp.as_mut_ptr(), two_comp.as_ptr(), abs_value.as_ptr());
    }
    let mut out = export_unsigned(two_comp.as_ptr());
    if out.len() < nbytes {
        let mut padded = vec![0u8; nbytes - out.len()];
        padded.extend_from_slice(&out);
        out = padded;
    }
    out
}

fn usg_bytes_from_numeric(value: &gcry_mpi) -> Vec<u8> {
    match &value.kind {
        MpiKind::Opaque(opaque) => opaque.as_slice().to_vec(),
        MpiKind::Numeric(number) => {
            let mut abs_value = Mpz::clone_from(number.as_ptr());
            unsafe {
                __gmpz_abs(abs_value.as_mut_ptr(), abs_value.as_ptr());
            }
            export_unsigned(abs_value.as_ptr())
        }
    }
}

pub(crate) fn mpi_to_hex_bytes(value: &gcry_mpi) -> Vec<u8> {
    let negative =
        matches!(&value.kind, MpiKind::Numeric(number) if unsafe { mpz_sgn(number.as_ptr()) } < 0);
    let mut magnitude = usg_bytes_from_numeric(value);
    if magnitude.is_empty() || magnitude.first().is_some_and(|byte| byte & 0x80 != 0) {
        magnitude.insert(0, 0);
    }

    let mut out = Vec::with_capacity(magnitude.len() * 2 + if negative { 2 } else { 1 });
    if negative {
        out.push(b'-');
    }
    for byte in magnitude {
        let hi = b"0123456789ABCDEF"[(byte >> 4) as usize];
        let lo = b"0123456789ABCDEF"[(byte & 0x0f) as usize];
        out.push(hi);
        out.push(lo);
    }
    out.push(0);
    out
}

fn print_bytes(format: c_int, value: &gcry_mpi) -> Result<Vec<u8>, u32> {
    match format {
        GCRYMPI_FMT_STD => Ok(std_bytes_from_numeric(value)),
        GCRYMPI_FMT_USG => Ok(usg_bytes_from_numeric(value)),
        GCRYMPI_FMT_SSH => {
            let std = std_bytes_from_numeric(value);
            let mut out = Vec::with_capacity(4 + std.len());
            out.extend_from_slice(&(std.len() as u32).to_be_bytes());
            out.extend_from_slice(&std);
            Ok(out)
        }
        GCRYMPI_FMT_PGP => {
            if super::gcry_mpi_is_neg((value as *const gcry_mpi).cast_mut()) != 0 {
                return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
            }
            let usg = usg_bytes_from_numeric(value);
            let nbits = super::gcry_mpi_get_nbits((value as *const gcry_mpi).cast_mut()) as u16;
            let mut out = Vec::with_capacity(2 + usg.len());
            out.extend_from_slice(&nbits.to_be_bytes());
            out.extend_from_slice(&usg);
            Ok(out)
        }
        GCRYMPI_FMT_HEX => Ok(mpi_to_hex_bytes(value)),
        GCRYMPI_FMT_OPAQUE => {
            if let MpiKind::Opaque(opaque) = &value.kind {
                Ok(opaque.as_slice().to_vec())
            } else {
                Ok(Vec::new())
            }
        }
        _ => Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG)),
    }
}

fn read_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn scan_hex(buffer: *const c_void, buflen: usize) -> Result<(Mpz, bool, usize), u32> {
    if buffer.is_null() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
    }

    let bytes = if buflen == 0 {
        unsafe { CStr::from_ptr(buffer.cast()) }.to_bytes()
    } else {
        unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), buflen) }
    };

    let mut negative = false;
    let mut start = 0usize;
    if bytes.first() == Some(&b'-') {
        negative = true;
        start = 1;
    }
    let digits =
        if bytes.get(start) == Some(&b'0') && matches!(bytes.get(start + 1), Some(b'x' | b'X')) {
            &bytes[start + 2..]
        } else {
            &bytes[start..]
        };
    if digits.is_empty() {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
    }

    let mut raw = Vec::with_capacity(digits.len().div_ceil(2));
    let mut idx = 0usize;
    if digits.len() % 2 == 1 {
        let Some(nibble) = read_hex_digit(digits[0]) else {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
        };
        raw.push(nibble);
        idx = 1;
    }
    while idx < digits.len() {
        let Some(hi) = read_hex_digit(digits[idx]) else {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
        };
        let Some(lo) = read_hex_digit(digits[idx + 1]) else {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
        };
        raw.push((hi << 4) | lo);
        idx += 2;
    }

    while raw.len() > 1 && raw[0] == 0 {
        raw.remove(0);
    }

    let mut value = import_unsigned_bytes(&raw);
    if negative {
        unsafe {
            __gmpz_neg(value.as_mut_ptr(), value.as_ptr());
        }
    }
    Ok((value, negative, bytes.len()))
}

fn scan_std_like(bytes: &[u8], signed: bool) -> Mpz {
    if bytes.is_empty() {
        return Mpz::new(0);
    }
    let negative = signed && (bytes[0] & 0x80) != 0;
    let mut imported = import_unsigned_bytes(bytes);
    if negative {
        let mut two_pow = Mpz::new(bytes.len() * 8);
        unsafe {
            __gmpz_set_ui(two_pow.as_mut_ptr(), 1);
            super::__gmpz_mul_2exp(two_pow.as_mut_ptr(), two_pow.as_ptr(), bytes.len() * 8);
            super::__gmpz_sub(imported.as_mut_ptr(), imported.as_ptr(), two_pow.as_ptr());
        }
    }
    imported
}

fn import_mpi(format: c_int, buffer: *const c_void, buflen: usize) -> Result<(Mpz, usize), u32> {
    if buflen > MAX_EXTERN_MPI_BYTES {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
    }

    match format {
        GCRYMPI_FMT_HEX => {
            let (value, _, nread) = scan_hex(buffer, buflen)?;
            Ok((value, nread))
        }
        GCRYMPI_FMT_STD => {
            let bytes = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), buflen) };
            Ok((scan_std_like(bytes, true), buflen))
        }
        GCRYMPI_FMT_USG => {
            let bytes = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), buflen) };
            Ok((scan_std_like(bytes, false), buflen))
        }
        GCRYMPI_FMT_SSH => {
            if buflen < 4 {
                return Err(error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT));
            }
            let bytes = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), buflen) };
            let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            if 4 + len > buflen {
                return Err(error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT));
            }
            Ok((scan_std_like(&bytes[4..4 + len], true), 4 + len))
        }
        GCRYMPI_FMT_PGP => {
            if buflen < 2 {
                return Err(error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT));
            }
            let bytes = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), buflen) };
            let nbits = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if nbits > MAX_EXTERN_PGP_BITS {
                return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
            }
            let nbytes = nbits.div_ceil(8);
            if 2 + nbytes > buflen {
                return Err(error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT));
            }
            Ok((scan_std_like(&bytes[2..2 + nbytes], false), 2 + nbytes))
        }
        GCRYMPI_FMT_OPAQUE => {
            let bytes = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), buflen) };
            Ok((import_unsigned_bytes(bytes), buflen))
        }
        _ => Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG)),
    }
}

#[unsafe(export_name = "gcry_mpi_scan")]
pub extern "C" fn gcry_mpi_scan(
    ret_mpi: *mut *mut gcry_mpi,
    format: c_int,
    buffer: *const c_void,
    buflen: usize,
    nscanned: *mut usize,
) -> u32 {
    if !ret_mpi.is_null() {
        unsafe {
            *ret_mpi = null_mut();
        }
    }
    if !nscanned.is_null() {
        unsafe {
            *nscanned = 0;
        }
    }

    if ret_mpi.is_null() || buffer.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let result = match import_mpi(format, buffer, buflen) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let raw = gcry_mpi::from_numeric(result.0, false);
    unsafe {
        *ret_mpi = raw;
        if !nscanned.is_null() {
            *nscanned = result.1;
        }
    }
    0
}

#[unsafe(export_name = "gcry_mpi_print")]
pub extern "C" fn gcry_mpi_print(
    format: c_int,
    buffer: *mut u8,
    buflen: usize,
    nwritten: *mut usize,
    a: *const gcry_mpi,
) -> u32 {
    if !nwritten.is_null() {
        unsafe {
            *nwritten = 0;
        }
    }

    let Some(value) = (unsafe { gcry_mpi::as_ref(a) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };

    let rendered = match print_bytes(format, value) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let required = if format == GCRYMPI_FMT_HEX {
        rendered.len().saturating_sub(1)
    } else {
        rendered.len()
    };

    if !nwritten.is_null() {
        unsafe {
            *nwritten = required;
        }
    }

    if buffer.is_null() {
        return 0;
    }
    if buflen < required {
        return error::gcry_error_from_code(error::GPG_ERR_BUFFER_TOO_SHORT);
    }

    unsafe {
        copy_nonoverlapping(rendered.as_ptr(), buffer, required);
        if format == GCRYMPI_FMT_HEX && buflen > required {
            *buffer.add(required) = 0;
        }
    }
    0
}

#[unsafe(export_name = "gcry_mpi_aprint")]
pub extern "C" fn gcry_mpi_aprint(
    format: c_int,
    buffer: *mut *mut u8,
    nwritten: *mut usize,
    a: *const gcry_mpi,
) -> u32 {
    if !buffer.is_null() {
        unsafe {
            *buffer = null_mut();
        }
    }
    if !nwritten.is_null() {
        unsafe {
            *nwritten = 0;
        }
    }

    let Some(value) = (unsafe { gcry_mpi::as_ref(a) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };

    let rendered = match print_bytes(format, value) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let required = rendered.len();
    if !nwritten.is_null() {
        unsafe {
            *nwritten = if format == GCRYMPI_FMT_HEX {
                required.saturating_sub(1)
            } else {
                required
            };
        }
    }
    if buffer.is_null() {
        return 0;
    }

    let ptr = alloc::gcry_malloc(required.max(1));
    if ptr.is_null() {
        return set_errno_oom();
    }
    unsafe {
        copy_nonoverlapping(rendered.as_ptr(), ptr.cast::<u8>(), required);
        *buffer = ptr.cast();
    }
    0
}
