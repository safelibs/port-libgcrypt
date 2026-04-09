use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::ptr::{copy_nonoverlapping, null, null_mut};

use crate::alloc;
use crate::context;
use crate::error;
use crate::log;
use crate::mpi::{self, gcry_mpi, GCRYMPI_FMT_OPAQUE, GCRYMPI_FMT_STD, GCRYMPI_FMT_USG};

#[repr(C)]
struct GcryBuffer {
    size: usize,
    off: usize,
    len: usize,
    data: *mut c_void,
}

type FreeFunc = Option<unsafe extern "C" fn(*mut c_void)>;

#[derive(Clone, Debug)]
enum Sexpr {
    Atom(Vec<u8>),
    List(Vec<Sexpr>),
}

#[derive(Debug)]
pub struct gcry_sexp {
    root: Sexpr,
    secure: bool,
}

impl Drop for gcry_sexp {
    fn drop(&mut self) {
        context::remove_object((self as *mut Self).cast());
    }
}

impl gcry_sexp {
    fn new(root: Sexpr, secure: bool) -> *mut gcry_sexp {
        let raw = Box::into_raw(Box::new(Self {
            root,
            secure,
        }));
        context::set_object_secure(raw.cast(), secure);
        raw
    }

    unsafe fn as_ref<'a>(ptr: *const gcry_sexp) -> Option<&'a gcry_sexp> {
        unsafe { ptr.as_ref() }
    }

    unsafe fn as_mut<'a>(ptr: *mut gcry_sexp) -> Option<&'a mut gcry_sexp> {
        unsafe { ptr.as_mut() }
    }

    fn list(&self) -> Option<&[Sexpr]> {
        match &self.root {
            Sexpr::List(items) => Some(items),
            Sexpr::Atom(_) => None,
        }
    }
}

fn atom(bytes: &[u8]) -> Sexpr {
    Sexpr::Atom(bytes.to_vec())
}

fn single_element(sexp: &gcry_sexp) -> Sexpr {
    match sexp.list() {
        Some([single]) => single.clone(),
        Some(items) => Sexpr::List(items.to_vec()),
        None => sexp.root.clone(),
    }
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\x0b')) {
            self.pos += 1;
        }
    }

    fn parse_root(&mut self) -> Result<Sexpr, (usize, u32)> {
        self.skip_ws();
        let result = self.parse_list()?;
        self.skip_ws();
        match self.peek() {
            None => Ok(result),
            Some(b')') => Err((self.pos, error::GPG_ERR_SEXP_UNMATCHED_PAREN)),
            Some(_) => Err((self.pos, error::GPG_ERR_SEXP_BAD_CHARACTER)),
        }
    }

    fn parse_list(&mut self) -> Result<Sexpr, (usize, u32)> {
        if self.bump() != Some(b'(') {
            return Err((self.pos, error::GPG_ERR_SEXP_BAD_CHARACTER));
        }
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b')') => {
                    self.pos += 1;
                    break;
                }
                Some(_) => items.push(self.parse_element()?),
                None => return Err((self.pos, error::GPG_ERR_SEXP_UNMATCHED_PAREN)),
            }
        }
        Ok(Sexpr::List(items))
    }

    fn parse_element(&mut self) -> Result<Sexpr, (usize, u32)> {
        self.skip_ws();
        match self.peek() {
            Some(b'(') => self.parse_list(),
            Some(b'"') => self.parse_quoted_atom(),
            Some(b'#') => self.parse_hex_atom(),
            Some(b'|') => self.parse_base64_atom(),
            Some(b'0'..=b'9') => self.parse_len_or_token(),
            Some(_) => self.parse_token(),
            None => Err((self.pos, error::GPG_ERR_SEXP_UNMATCHED_PAREN)),
        }
    }

    fn parse_len_or_token(&mut self) -> Result<Sexpr, (usize, u32)> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.peek() == Some(b':') {
            if self.pos - start > 1 && self.input[start] == b'0' {
                return Err((start, error::GPG_ERR_SEXP_ZERO_PREFIX));
            }
            let len = std::str::from_utf8(&self.input[start..self.pos])
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or((start, error::GPG_ERR_SEXP_INV_LEN_SPEC))?;
            self.pos += 1;
            if self.pos + len > self.input.len() {
                return Err((self.input.len(), error::GPG_ERR_SEXP_STRING_TOO_LONG));
            }
            let data = self.input[self.pos..self.pos + len].to_vec();
            self.pos += len;
            Ok(Sexpr::Atom(data))
        } else {
            self.pos = start;
            self.parse_token()
        }
    }

    fn parse_token(&mut self) -> Result<Sexpr, (usize, u32)> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\x0b' | b'(' | b')' | b'"' | b'#' | b'|') {
                break;
            }
            self.pos += 1;
        }
        if start == self.pos {
            return Err((self.pos, error::GPG_ERR_SEXP_BAD_CHARACTER));
        }
        Ok(Sexpr::Atom(self.input[start..self.pos].to_vec()))
    }

    fn parse_quoted_atom(&mut self) -> Result<Sexpr, (usize, u32)> {
        self.pos += 1;
        let mut out = Vec::new();
        while let Some(byte) = self.bump() {
            match byte {
                b'"' => return Ok(Sexpr::Atom(out)),
                b'\\' => {
                    let escaped = match self.bump() {
                        Some(b'b') => b'\x08',
                        Some(b't') => b'\t',
                        Some(b'v') => b'\x0b',
                        Some(b'n') => b'\n',
                        Some(b'f') => b'\x0c',
                        Some(b'r') => b'\r',
                        Some(b'"') => b'"',
                        Some(b'\'') => b'\'',
                        Some(b'\\') => b'\\',
                        Some(b'x') => {
                            let hi = self.bump().ok_or((self.pos, error::GPG_ERR_SEXP_BAD_QUOTATION))?;
                            let lo = self.bump().ok_or((self.pos, error::GPG_ERR_SEXP_BAD_QUOTATION))?;
                            let hi = hex_nibble(hi).ok_or((self.pos, error::GPG_ERR_SEXP_BAD_HEX_CHAR))?;
                            let lo = hex_nibble(lo).ok_or((self.pos, error::GPG_ERR_SEXP_BAD_HEX_CHAR))?;
                            (hi << 4) | lo
                        }
                        _ => return Err((self.pos, error::GPG_ERR_SEXP_BAD_QUOTATION)),
                    };
                    out.push(escaped);
                }
                _ => out.push(byte),
            }
        }
        Err((self.pos, error::GPG_ERR_SEXP_UNMATCHED_PAREN))
    }

    fn parse_hex_atom(&mut self) -> Result<Sexpr, (usize, u32)> {
        self.pos += 1;
        let mut digits = Vec::new();
        while let Some(byte) = self.peek() {
            match byte {
                b'#' => break,
                b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\x0b' => {
                    self.pos += 1;
                }
                b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                    digits.push(byte);
                    self.pos += 1;
                }
                _ => return Err((self.pos, error::GPG_ERR_SEXP_BAD_HEX_CHAR)),
            }
        }
        if self.peek().is_none() {
            return Err((self.pos, error::GPG_ERR_SEXP_UNMATCHED_PAREN));
        }
        if digits.len() % 2 != 0 {
            return Err((self.pos, error::GPG_ERR_SEXP_ODD_HEX_NUMBERS));
        }
        let mut out = Vec::with_capacity(digits.len() / 2);
        for pair in digits.chunks_exact(2) {
            let hi = hex_nibble(pair[0]).ok_or((self.pos, error::GPG_ERR_SEXP_BAD_HEX_CHAR))?;
            let lo = hex_nibble(pair[1]).ok_or((self.pos, error::GPG_ERR_SEXP_BAD_HEX_CHAR))?;
            out.push((hi << 4) | lo);
        }
        self.pos += 1;
        Ok(Sexpr::Atom(out))
    }

    fn parse_base64_atom(&mut self) -> Result<Sexpr, (usize, u32)> {
        self.pos += 1;
        let start = self.pos;
        while self.peek() != Some(b'|') {
            if self.peek().is_none() {
                return Err((self.pos, error::GPG_ERR_SEXP_UNMATCHED_PAREN));
            }
            self.pos += 1;
        }
        let data = decode_base64(&self.input[start..self.pos])?;
        self.pos += 1;
        Ok(Sexpr::Atom(data))
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_base64(input: &[u8]) -> Result<Vec<u8>, (usize, u32)> {
    let mut table = [0u8; 256];
    for (idx, byte) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
        table[*byte as usize] = idx as u8;
    }
    let mut out = Vec::new();
    let mut chunk = [0u8; 4];
    let mut used = 0usize;
    for (idx, byte) in input.iter().copied().enumerate() {
        if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        chunk[used] = byte;
        used += 1;
        if used == 4 {
            let pad = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
            let mut value = 0u32;
            for item in chunk {
                value <<= 6;
                if item != b'=' {
                    if !b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".contains(&item) {
                        return Err((idx, error::GPG_ERR_BAD_DATA));
                    }
                    value |= table[item as usize] as u32;
                }
            }
            out.push(((value >> 16) & 0xff) as u8);
            if pad < 2 {
                out.push(((value >> 8) & 0xff) as u8);
            }
            if pad == 0 {
                out.push((value & 0xff) as u8);
            }
            used = 0;
        }
    }
    if used != 0 {
        return Err((input.len(), error::GPG_ERR_BAD_DATA));
    }
    Ok(out)
}

fn canonical_len_internal(buffer: &[u8], pos: &mut usize) -> Result<(), (usize, u32)> {
    let mut count = *pos;
    let mut datalen = 0usize;
    let mut level = 0usize;

    if count >= buffer.len() || buffer[count] != b'(' {
        return Err((count, error::GPG_ERR_SEXP_NOT_CANONICAL));
    }

    loop {
        if count >= buffer.len() {
            return Err((count, error::GPG_ERR_SEXP_STRING_TOO_LONG));
        }

        let byte = buffer[count];
        if datalen != 0 {
            if byte == b':' {
                if count + datalen >= buffer.len() {
                    return Err((count, error::GPG_ERR_SEXP_STRING_TOO_LONG));
                }
                count += datalen + 1;
                datalen = 0;
                continue;
            }
            if byte.is_ascii_digit() {
                datalen = datalen
                    .checked_mul(10)
                    .and_then(|value| value.checked_add((byte - b'0') as usize))
                    .ok_or((count, error::GPG_ERR_SEXP_INV_LEN_SPEC))?;
                count += 1;
                continue;
            }
            return Err((count, error::GPG_ERR_SEXP_INV_LEN_SPEC));
        }

        match byte {
            b'(' => {
                level += 1;
                count += 1;
            }
            b')' => {
                if level == 0 {
                    return Err((count, error::GPG_ERR_SEXP_UNMATCHED_PAREN));
                }
                level -= 1;
                count += 1;
                if level == 0 {
                    *pos = count;
                    return Ok(());
                }
            }
            b'1'..=b'9' => {
                datalen = (byte - b'0') as usize;
                count += 1;
            }
            b'0' => return Err((count, error::GPG_ERR_SEXP_ZERO_PREFIX)),
            b'&' | b'\\' => return Err((count, error::GPG_ERR_SEXP_UNEXPECTED_PUNC)),
            _ => return Err((count, error::GPG_ERR_SEXP_BAD_CHARACTER)),
        }
    }
}

unsafe fn canonical_len_unbounded(buffer: *const u8) -> Result<usize, (usize, u32)> {
    if buffer.is_null() {
        return Err((0, error::GPG_ERR_SEXP_NOT_CANONICAL));
    }

    let mut count = 0usize;
    let mut datalen = 0usize;
    let mut level = 0usize;

    if unsafe { *buffer } != b'(' {
        return Err((0, error::GPG_ERR_SEXP_NOT_CANONICAL));
    }

    loop {
        let byte = unsafe { *buffer.add(count) };
        if datalen != 0 {
            if byte == b':' {
                count += datalen + 1;
                datalen = 0;
                continue;
            }
            if byte.is_ascii_digit() {
                datalen = datalen
                    .checked_mul(10)
                    .and_then(|value| value.checked_add((byte - b'0') as usize))
                    .ok_or((count, error::GPG_ERR_SEXP_INV_LEN_SPEC))?;
                count += 1;
                continue;
            }
            return Err((count, error::GPG_ERR_SEXP_INV_LEN_SPEC));
        }

        match byte {
            b'(' => {
                level += 1;
                count += 1;
            }
            b')' => {
                if level == 0 {
                    return Err((count, error::GPG_ERR_SEXP_UNMATCHED_PAREN));
                }
                level -= 1;
                count += 1;
                if level == 0 {
                    return Ok(count);
                }
            }
            b'1'..=b'9' => {
                datalen = (byte - b'0') as usize;
                count += 1;
            }
            b'0' => return Err((count, error::GPG_ERR_SEXP_ZERO_PREFIX)),
            b'&' | b'\\' => return Err((count, error::GPG_ERR_SEXP_UNEXPECTED_PUNC)),
            _ => return Err((count, error::GPG_ERR_SEXP_BAD_CHARACTER)),
        }
    }
}

fn suitable_encoding(bytes: &[u8]) -> u8 {
    if bytes.is_empty() {
        return 1;
    }
    if bytes[0] & 0x80 != 0 {
        return 0;
    }

    let mut maybe_token = !bytes[0].is_ascii_digit();
    for byte in bytes {
        if *byte == 0 {
            return 0;
        }
        if (*byte < 0x20 || (*byte >= 0x7f && *byte <= 0xa0))
            && !matches!(*byte, b'\x08' | b'\t' | b'\x0b' | b'\n' | b'\x0c' | b'\r' | b'"' | b'\'' | b'\\')
        {
            return 0;
        }
        if maybe_token
            && !(byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'/' | b':' | b'+' | b'*' | b'='))
        {
            maybe_token = false;
        }
    }
    if maybe_token {
        2
    } else {
        1
    }
}

fn append_advanced_atom(bytes: &[u8], out: &mut Vec<u8>) {
    match suitable_encoding(bytes) {
        2 => out.extend_from_slice(bytes),
        1 => {
            out.push(b'"');
            for byte in bytes {
                match *byte {
                    b'\x08' => out.extend_from_slice(br"\b"),
                    b'\t' => out.extend_from_slice(br"\t"),
                    b'\x0b' => out.extend_from_slice(br"\v"),
                    b'\n' => out.extend_from_slice(br"\n"),
                    b'\x0c' => out.extend_from_slice(br"\f"),
                    b'\r' => out.extend_from_slice(br"\r"),
                    b'"' => out.extend_from_slice(br#"\""#),
                    b'\'' => out.extend_from_slice(br"\'"),
                    b'\\' => out.extend_from_slice(br"\\"),
                    value if value < 0x20 || (0x7f..=0xa0).contains(&value) => {
                        let hex = format!(r"\x{value:02x}");
                        out.extend_from_slice(hex.as_bytes());
                    }
                    value => out.push(value),
                }
            }
            out.push(b'"');
        }
        _ => {
            out.push(b'#');
            for byte in bytes {
                let hex = format!("{byte:02X}");
                out.extend_from_slice(hex.as_bytes());
            }
            out.push(b'#');
        }
    }
}

fn sprint_canon(node: &Sexpr, out: &mut Vec<u8>) {
    match node {
        Sexpr::Atom(bytes) => {
            out.extend_from_slice(bytes.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(bytes);
        }
        Sexpr::List(items) => {
            out.push(b'(');
            for item in items {
                sprint_canon(item, out);
            }
            out.push(b')');
        }
    }
}

fn sprint_advanced(node: &Sexpr, out: &mut Vec<u8>) {
    match node {
        Sexpr::Atom(bytes) => append_advanced_atom(bytes, out),
        Sexpr::List(items) => {
            out.push(b'(');
            for (idx, item) in items.iter().enumerate() {
                if idx != 0 {
                    out.push(b' ');
                }
                sprint_advanced(item, out);
            }
            out.push(b')');
        }
    }
}

fn nth_element<'a>(sexp: &'a gcry_sexp, number: c_int) -> Option<&'a Sexpr> {
    if number < 0 {
        return None;
    }
    sexp.list()?.get(number as usize)
}

fn nth_atom<'a>(sexp: &'a gcry_sexp, number: c_int) -> Option<&'a [u8]> {
    match nth_element(sexp, number)? {
        Sexpr::Atom(bytes) => Some(bytes.as_slice()),
        Sexpr::List(_) => None,
    }
}

fn make_element_sexp(node: &Sexpr, secure: bool) -> *mut gcry_sexp {
    match node {
        Sexpr::Atom(_) => gcry_sexp::new(Sexpr::List(vec![node.clone()]), secure),
        Sexpr::List(items) => gcry_sexp::new(Sexpr::List(items.clone()), secure),
    }
}

fn find_token_recursive(node: &Sexpr, token: &[u8], secure: bool) -> Option<*mut gcry_sexp> {
    match node {
        Sexpr::Atom(_) => None,
        Sexpr::List(items) => {
            if let Some(Sexpr::Atom(head)) = items.first() {
                if head == token {
                    return Some(gcry_sexp::new(Sexpr::List(items.clone()), secure));
                }
            }
            for item in items {
                if let Some(found) = find_token_recursive(item, token, secure) {
                    return Some(found);
                }
            }
            None
        }
    }
}

fn parse_bytes(buffer: *const c_void, length: usize) -> Result<Sexpr, (usize, u32)> {
    let input = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) };
    let mut parser = Parser::new(input);
    parser.parse_root()
}

fn input_length(buffer: *const c_void, length: usize) -> usize {
    if length != 0 {
        length
    } else {
        unsafe { CStr::from_ptr(buffer.cast()).to_bytes().len() }
    }
}

fn extract_path<'a>(mut sexp: &'a gcry_sexp, path: Option<&CStr>) -> Result<&'a gcry_sexp, u32> {
    let Some(path) = path else {
        return Ok(sexp);
    };
    let mut current = sexp;
    for part in path.to_bytes().split(|byte| *byte == b'!') {
        if part.is_empty() {
            return Err(error::GPG_ERR_NOT_FOUND);
        }
        let found = find_token_recursive(&current.root, part, current.secure).ok_or(error::GPG_ERR_NOT_FOUND)?;
        current = unsafe { gcry_sexp::as_ref(found) }.expect("temporary sexp");
    }
    Ok(current)
}

#[derive(Debug)]
enum Cleanup {
    Mpi(*mut *mut gcry_mpi),
    String(*mut *mut c_char),
    Buffer(*mut GcryBuffer, bool),
}

fn cleanup_on_error(items: &[Cleanup]) {
    for item in items.iter().rev() {
        match *item {
            Cleanup::Mpi(slot) => unsafe {
                if !slot.is_null() {
                    mpi::gcry_mpi_release(*slot);
                    *slot = null_mut();
                }
            },
            Cleanup::String(slot) => unsafe {
                if !slot.is_null() && !(*slot).is_null() {
                    alloc::gcry_free((*slot).cast());
                    *slot = null_mut();
                }
            },
            Cleanup::Buffer(slot, allocated) => unsafe {
                if !slot.is_null() {
                    if allocated && !(*slot).data.is_null() {
                        alloc::gcry_free((*slot).data);
                        (*slot).data = null_mut();
                        (*slot).size = 0;
                        (*slot).off = 0;
                    }
                    (*slot).len = 0;
                }
            },
        }
    }
}

fn extract_param_internal(
    sexp: &gcry_sexp,
    path: Option<&CStr>,
    list: &CStr,
    args: &[*mut c_void],
) -> u32 {
    let mut mode = b'+';
    let mut submode = 0u8;
    let mut arg_index = 0usize;
    let mut cleanup = Vec::new();

    let path_root = match extract_path(sexp, path) {
        Ok(value) => value,
        Err(code) => return error::gcry_error_from_code(code),
    };

    let bytes = list.to_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let byte = bytes[idx];
        match byte {
            b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\x0b' => idx += 1,
            b'&' | b'+' | b'-' | b'/' => {
                mode = byte;
                submode = 0;
                idx += 1;
            }
            b'%' => {
                idx += 1;
                if idx >= bytes.len() {
                    break;
                }
                match bytes[idx] {
                    b's' | b'u' | b'd' => {
                        mode = bytes[idx];
                        submode = 0;
                    }
                    b'l' if idx + 1 < bytes.len() && matches!(bytes[idx + 1], b'u' | b'd') => {
                        mode = bytes[idx + 1];
                        submode = b'l';
                        idx += 1;
                    }
                    b'z' if idx + 1 < bytes.len() && bytes[idx + 1] == b'u' => {
                        mode = b'u';
                        submode = b'z';
                        idx += 1;
                    }
                    b'#' if idx + 1 < bytes.len() && bytes[idx + 1] == b's' => {
                        mode = b's';
                        submode = b'#';
                        idx += 1;
                    }
                    _ => {}
                }
                idx += 1;
            }
            b'?' => idx += 1,
            _ => {
                let (name, next_idx) = if byte == b'\'' {
                    let start = idx + 1;
                    let Some(end) = bytes[start..].iter().position(|value| *value == b'\'') else {
                        cleanup_on_error(&cleanup);
                        return error::gcry_error_from_code(error::GPG_ERR_SYNTAX);
                    };
                    (&bytes[start..start + end], start + end + 1)
                } else {
                    (&bytes[idx..idx + 1], idx + 1)
                };
                let optional = matches!(bytes.get(next_idx), Some(b'?'));
                let Some(slot) = args.get(arg_index).copied() else {
                    cleanup_on_error(&cleanup);
                    return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
                };
                let found = find_token_recursive(&path_root.root, name, path_root.secure);
                if found.is_none() && optional {
                    match mode {
                        b'&' => unsafe {
                            let spec = slot.cast::<GcryBuffer>();
                            if !(*spec).data.is_null() {
                                (*spec).len = 0;
                            } else {
                                (*spec).size = 0;
                                (*spec).off = 0;
                                (*spec).len = 0;
                            }
                        },
                        b's' => unsafe {
                            *(slot.cast::<*mut c_char>()) = null_mut();
                        },
                        b'd' => unsafe {
                            if submode == b'l' {
                                *(slot.cast::<isize>()) = 0;
                            } else {
                                *(slot.cast::<c_int>()) = 0;
                            }
                        },
                        b'u' => unsafe {
                            if submode == b'l' {
                                *(slot.cast::<usize>()) = 0;
                            } else if submode == b'z' {
                                *(slot.cast::<usize>()) = 0;
                            } else {
                                *(slot.cast::<c_uint>()) = 0;
                            }
                        },
                        _ => unsafe {
                            *(slot.cast::<*mut gcry_mpi>()) = null_mut();
                        },
                    }
                } else if let Some(found_sexp) = found {
                    let found_ref = unsafe { gcry_sexp::as_ref(found_sexp) }.expect("sexp");
                    match mode {
                        b'&' => unsafe {
                            let spec = slot.cast::<GcryBuffer>();
                            let Some(data) = nth_atom(found_ref, 1) else {
                                cleanup_on_error(&cleanup);
                                return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
                            };
                            if (*spec).data.is_null() {
                                let allocated = mpi::alloc_output_bytes(data, false);
                                if allocated.is_null() && !data.is_empty() {
                                    cleanup_on_error(&cleanup);
                                    return error::gcry_error_from_code(error::GPG_ERR_GENERAL);
                                }
                                (*spec).data = allocated;
                                (*spec).size = data.len();
                                (*spec).off = 0;
                                (*spec).len = data.len();
                                cleanup.push(Cleanup::Buffer(spec, true));
                            } else {
                                if (*spec).off + data.len() > (*spec).size {
                                    cleanup_on_error(&cleanup);
                                    return error::gcry_error_from_code(error::GPG_ERR_BUFFER_TOO_SHORT);
                                }
                                copy_nonoverlapping(
                                    data.as_ptr(),
                                    ((*spec).data as *mut u8).add((*spec).off),
                                    data.len(),
                                );
                                (*spec).len = data.len();
                                cleanup.push(Cleanup::Buffer(spec, false));
                            }
                        },
                        b's' => {
                            let string = if submode == b'#' {
                                let mut text = Vec::new();
                                if let Some(items) = found_ref.list() {
                                    for item in items.iter().skip(1) {
                                        if !text.is_empty() {
                                            text.push(b' ');
                                        }
                                        match item {
                                            Sexpr::Atom(bytes) => text.extend_from_slice(bytes),
                                            Sexpr::List(_) => text.extend_from_slice(b"()"),
                                        }
                                    }
                                }
                                text
                            } else {
                                nth_atom(found_ref, 1).unwrap_or_default().to_vec()
                            };
                            let ptr = if string.is_empty() {
                                alloc::gcry_calloc(1, 1)
                            } else {
                                let mut bytes = string;
                                bytes.push(0);
                                mpi::alloc_output_bytes(&bytes, false)
                            };
                            if ptr.is_null() {
                                cleanup_on_error(&cleanup);
                                return error::gcry_error_from_code(error::GPG_ERR_GENERAL);
                            }
                            unsafe {
                                *(slot.cast::<*mut c_char>()) = ptr.cast();
                            }
                            cleanup.push(Cleanup::String(slot.cast()));
                        }
                        b'd' | b'u' => {
                            let raw = nth_atom(found_ref, 1).unwrap_or_default();
                            let text = String::from_utf8_lossy(raw);
                            if mode == b'd' {
                                let parsed = text.parse::<isize>().unwrap_or(0);
                                unsafe {
                                    if submode == b'l' {
                                        *(slot.cast::<isize>()) = parsed;
                                    } else {
                                        *(slot.cast::<c_int>()) = parsed as c_int;
                                    }
                                }
                            } else {
                                let parsed = text.parse::<usize>().unwrap_or(0);
                                unsafe {
                                    if submode == b'l' || submode == b'z' {
                                        *(slot.cast::<usize>()) = parsed;
                                    } else {
                                        *(slot.cast::<c_uint>()) = parsed as c_uint;
                                    }
                                }
                            }
                        }
                        _ => {
                            let mpi_ptr = if mode == b'/' {
                                let data = nth_atom(found_ref, 1).unwrap_or_default();
                                mpi::opaque::gcry_mpi_set_opaque_copy(null_mut(), data.as_ptr().cast(), (data.len() * 8) as c_uint)
                            } else {
                                let mut result = null_mut();
                                let data = nth_atom(found_ref, 1).unwrap_or_default();
                                let format = if mode == b'-' { GCRYMPI_FMT_STD } else { GCRYMPI_FMT_USG };
                                let err = mpi::scan::gcry_mpi_scan(
                                    &mut result,
                                    format,
                                    data.as_ptr().cast(),
                                    data.len(),
                                    null_mut(),
                                );
                                if err != 0 {
                                    null_mut()
                                } else {
                                    result
                                }
                            };
                            if mpi_ptr.is_null() {
                                cleanup_on_error(&cleanup);
                                return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
                            }
                            unsafe {
                                *(slot.cast::<*mut gcry_mpi>()) = mpi_ptr;
                            }
                            cleanup.push(Cleanup::Mpi(slot.cast()));
                        }
                    }
                } else {
                    cleanup_on_error(&cleanup);
                    return error::gcry_error_from_code(error::GPG_ERR_NO_OBJ);
                }
                arg_index += 1;
                idx = next_idx + optional as usize;
            }
        }
    }

    0
}

fn parse_format_long_name(bytes: &[u8], idx: &mut usize) -> Option<Vec<u8>> {
    if bytes.get(*idx) == Some(&b'\'') {
        let start = *idx + 1;
        let end = bytes[start..].iter().position(|value| *value == b'\'')?;
        *idx = start + end + 1;
        Some(bytes[start..start + end].to_vec())
    } else {
        let value = vec![*bytes.get(*idx)?];
        *idx += 1;
        Some(value)
    }
}

enum BuildArg<'a> {
    Ptr(*mut c_void),
    Int(isize),
    UInt(usize),
    BorrowedSexp(&'a gcry_sexp),
    BorrowedMpi(&'a gcry_mpi),
}

fn build_from_format(format: &CStr, args: &[usize]) -> Result<(*mut gcry_sexp, usize), u32> {
    let bytes = format.to_bytes();
    let mut out = Vec::new();
    let mut idx = 0usize;
    let mut arg_index = 0usize;
    let mut secure = false;
    while idx < bytes.len() {
        if bytes[idx] != b'%' {
            out.push(bytes[idx]);
            idx += 1;
            continue;
        }
        idx += 1;
        let Some(spec) = bytes.get(idx).copied() else {
            return Err(error::gcry_error_from_code(error::GPG_ERR_SEXP_INV_LEN_SPEC));
        };
        match spec {
            b'm' | b'M' => {
                let Some(raw) = args.get(arg_index).copied() else {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_MISSING_VALUE));
                };
                let mpi = unsafe { gcry_mpi::as_ref(raw as *const gcry_mpi) }
                    .ok_or(error::gcry_error_from_code(error::GPG_ERR_INV_ARG))?;
                let mut rendered = vec![0u8; 0];
                let mut nwritten = 0usize;
                let format = if spec == b'm' { GCRYMPI_FMT_STD } else { GCRYMPI_FMT_USG };
                let needed = mpi::scan::gcry_mpi_print(format, null_mut(), 0, &mut nwritten, raw as *const gcry_mpi);
                if needed != 0 {
                    return Err(needed);
                }
                rendered.resize(nwritten.max(1), 0);
                let err = mpi::scan::gcry_mpi_print(format, rendered.as_mut_ptr(), rendered.len(), &mut nwritten, raw as *const gcry_mpi);
                if err != 0 {
                    return Err(err);
                }
                rendered.truncate(nwritten);
                if spec == b'M' && mpi::gcry_mpi_is_neg((raw as *mut gcry_mpi)) != 0 {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
                }
                secure |= mpi.secure;
                out.extend_from_slice(nwritten.to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(&rendered);
                arg_index += 1;
            }
            b's' => {
                let Some(raw) = args.get(arg_index).copied() else {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_MISSING_VALUE));
                };
                let text = unsafe { CStr::from_ptr(raw as *const c_char) }.to_bytes();
                out.extend_from_slice(text.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(text);
                arg_index += 1;
            }
            b'b' => {
                let Some(len_raw) = args.get(arg_index).copied() else {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_MISSING_VALUE));
                };
                let Some(ptr_raw) = args.get(arg_index + 1).copied() else {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_MISSING_VALUE));
                };
                let len = len_raw as isize;
                if len < 0 {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
                }
                let slice = unsafe { std::slice::from_raw_parts(ptr_raw as *const u8, len as usize) };
                secure |= alloc::gcry_is_secure(ptr_raw as *const c_void) != 0;
                out.extend_from_slice(slice.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(slice);
                arg_index += 2;
            }
            b'd' | b'u' => {
                let Some(raw) = args.get(arg_index).copied() else {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_MISSING_VALUE));
                };
                let text = if spec == b'd' {
                    (raw as isize).to_string()
                } else {
                    raw.to_string()
                };
                out.extend_from_slice(text.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(text.as_bytes());
                arg_index += 1;
            }
            b'S' => {
                let Some(raw) = args.get(arg_index).copied() else {
                    return Err(error::gcry_error_from_code(error::GPG_ERR_MISSING_VALUE));
                };
                let sexp = unsafe { gcry_sexp::as_ref(raw as *const gcry_sexp) }
                    .ok_or(error::gcry_error_from_code(error::GPG_ERR_INV_ARG))?;
                let mut rendered = Vec::new();
                sprint_canon(&sexp.root, &mut rendered);
                out.extend_from_slice(&rendered);
                secure |= sexp.secure;
                arg_index += 1;
            }
            _ => return Err(error::gcry_error_from_code(error::GPG_ERR_SEXP_INV_LEN_SPEC)),
        }
        idx += 1;
    }

    let root = parse_bytes(out.as_ptr().cast(), out.len()).map_err(|(_, code)| error::gcry_error_from_code(code))?;
    Ok((gcry_sexp::new(root, secure), arg_index))
}

#[unsafe(export_name = "gcry_sexp_new")]
pub extern "C" fn gcry_sexp_new(
    retsexp: *mut *mut gcry_sexp,
    buffer: *const c_void,
    length: usize,
    autodetect: c_int,
) -> u32 {
    if !retsexp.is_null() {
        unsafe {
            *retsexp = null_mut();
        }
    }
    if retsexp.is_null() || buffer.is_null() || !(0..=1).contains(&autodetect) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let len = if length == 0 && autodetect == 0 {
        match unsafe { canonical_len_unbounded(buffer.cast()) } {
            Ok(len) => len,
            Err((_, code)) => return error::gcry_error_from_code(code),
        }
    } else {
        input_length(buffer, length)
    };
    match parse_bytes(buffer, len) {
        Ok(root) => {
            let secure = alloc::gcry_is_secure(buffer) != 0;
            unsafe {
                *retsexp = gcry_sexp::new(root, secure);
            }
            0
        }
        Err((_, code)) => error::gcry_error_from_code(code),
    }
}

#[unsafe(export_name = "gcry_sexp_create")]
pub extern "C" fn gcry_sexp_create(
    retsexp: *mut *mut gcry_sexp,
    buffer: *mut c_void,
    length: usize,
    autodetect: c_int,
    freefnc: FreeFunc,
) -> u32 {
    if !retsexp.is_null() {
        unsafe {
            *retsexp = null_mut();
        }
    }
    if retsexp.is_null() || buffer.is_null() || !(0..=1).contains(&autodetect) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let len = if length == 0 && autodetect == 0 {
        match unsafe { canonical_len_unbounded(buffer.cast()) } {
            Ok(len) => len,
            Err((_, code)) => return error::gcry_error_from_code(code),
        }
    } else {
        input_length(buffer, length)
    };
    match parse_bytes(buffer, len) {
        Ok(root) => {
            let secure = alloc::gcry_is_secure(buffer) != 0;
            if let Some(callback) = freefnc {
                unsafe {
                    callback(buffer);
                }
            }
            unsafe {
                *retsexp = gcry_sexp::new(root, secure);
            }
            0
        }
        Err((_, code)) => error::gcry_error_from_code(code),
    }
}

#[unsafe(export_name = "gcry_sexp_sscan")]
pub extern "C" fn gcry_sexp_sscan(
    retsexp: *mut *mut gcry_sexp,
    erroff: *mut usize,
    buffer: *const c_char,
    length: usize,
) -> u32 {
    if !retsexp.is_null() {
        unsafe {
            *retsexp = null_mut();
        }
    }
    if !erroff.is_null() {
        unsafe {
            *erroff = 0;
        }
    }
    if retsexp.is_null() || buffer.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let len = if length != 0 { length } else { unsafe { CStr::from_ptr(buffer) }.to_bytes().len() };
    match parse_bytes(buffer.cast(), len) {
        Ok(root) => {
            unsafe {
                *retsexp = gcry_sexp::new(root, alloc::gcry_is_secure(buffer.cast()) != 0);
            }
            0
        }
        Err((offset, code)) => {
            if !erroff.is_null() {
                unsafe {
                    *erroff = offset;
                }
            }
            error::gcry_error_from_code(code)
        }
    }
}

#[unsafe(export_name = "gcry_sexp_build_array")]
pub extern "C" fn gcry_sexp_build_array(
    retsexp: *mut *mut gcry_sexp,
    erroff: *mut usize,
    format: *const c_char,
    arg_list: *mut *mut c_void,
) -> u32 {
    if !retsexp.is_null() {
        unsafe {
            *retsexp = null_mut();
        }
    }
    if !erroff.is_null() {
        unsafe {
            *erroff = 0;
        }
    }
    if retsexp.is_null() || format.is_null() || arg_list.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let format = unsafe { CStr::from_ptr(format) };
    let args: Vec<usize> = (0..64).map(|idx| unsafe { *arg_list.add(idx) as usize }).collect();
    match build_from_format(format, &args) {
        Ok((sexp, _)) => {
            unsafe {
                *retsexp = sexp;
            }
            0
        }
        Err(code) => code,
    }
}

#[unsafe(export_name = "gcry_sexp_release")]
pub extern "C" fn gcry_sexp_release(sexp: *mut gcry_sexp) {
    if sexp.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(sexp));
    }
}

#[unsafe(export_name = "gcry_sexp_canon_len")]
pub extern "C" fn gcry_sexp_canon_len(
    buffer: *const u8,
    length: usize,
    erroff: *mut usize,
    errcode: *mut u32,
) -> usize {
    if !erroff.is_null() {
        unsafe {
            *erroff = 0;
        }
    }
    if !errcode.is_null() {
        unsafe {
            *errcode = 0;
        }
    }
    if buffer.is_null() {
        return 0;
    }
    let result = if length == 0 {
        unsafe { canonical_len_unbounded(buffer) }
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(buffer, length) };
        let mut pos = 0usize;
        canonical_len_internal(bytes, &mut pos).map(|()| pos)
    };
    match result {
        Ok(pos) => pos,
        Err((offset, code)) => {
            if !erroff.is_null() {
                unsafe {
                    *erroff = offset;
                }
            }
            if !errcode.is_null() {
                unsafe {
                    *errcode = error::gcry_error_from_code(code);
                }
            }
            0
        }
    }
}

#[unsafe(export_name = "gcry_sexp_sprint")]
pub extern "C" fn gcry_sexp_sprint(
    sexp: *mut gcry_sexp,
    mode: c_int,
    buffer: *mut c_void,
    maxlength: usize,
) -> usize {
    let Some(value) = (unsafe { gcry_sexp::as_ref(sexp) }) else {
        return 0;
    };
    let mut rendered = Vec::new();
    match mode {
        1 => sprint_canon(&value.root, &mut rendered),
        2 | 3 | 0 => sprint_advanced(&value.root, &mut rendered),
        _ => sprint_advanced(&value.root, &mut rendered),
    }
    let needed = rendered.len() + 1;
    if buffer.is_null() || maxlength == 0 {
        return needed;
    }
    if maxlength < needed {
        return 0;
    }
    unsafe {
        copy_nonoverlapping(rendered.as_ptr(), buffer.cast::<u8>(), rendered.len());
        *buffer.cast::<u8>().add(rendered.len()) = 0;
    }
    rendered.len()
}

#[unsafe(export_name = "gcry_sexp_dump")]
pub extern "C" fn gcry_sexp_dump(a: *const gcry_sexp) {
    let Some(value) = (unsafe { gcry_sexp::as_ref(a) }) else {
        return;
    };
    let mut rendered = Vec::new();
    sprint_advanced(&value.root, &mut rendered);
    log::emit_message(log::GCRY_LOG_INFO, &String::from_utf8_lossy(&rendered));
}

#[unsafe(export_name = "gcry_sexp_cons")]
pub extern "C" fn gcry_sexp_cons(a: *const gcry_sexp, b: *const gcry_sexp) -> *mut gcry_sexp {
    let Some(left) = (unsafe { gcry_sexp::as_ref(a) }) else {
        return null_mut();
    };
    let Some(right) = (unsafe { gcry_sexp::as_ref(b) }) else {
        return null_mut();
    };
    gcry_sexp::new(
        Sexpr::List(vec![single_element(left), single_element(right)]),
        left.secure || right.secure,
    )
}

#[unsafe(export_name = "gcry_sexp_alist")]
pub extern "C" fn gcry_sexp_alist(array: *const *mut gcry_sexp) -> *mut gcry_sexp {
    if array.is_null() {
        return null_mut();
    }
    let mut items = Vec::new();
    let mut secure = false;
    let mut idx = 0usize;
    loop {
        let ptr = unsafe { *array.add(idx) };
        if ptr.is_null() {
            break;
        }
        let Some(value) = (unsafe { gcry_sexp::as_ref(ptr) }) else {
            break;
        };
        secure |= value.secure;
        items.push(single_element(value));
        idx += 1;
    }
    gcry_sexp::new(Sexpr::List(items), secure)
}

#[unsafe(export_name = "gcry_sexp_append")]
pub extern "C" fn gcry_sexp_append(a: *const gcry_sexp, n: *const gcry_sexp) -> *mut gcry_sexp {
    let Some(left) = (unsafe { gcry_sexp::as_ref(a) }) else {
        return null_mut();
    };
    let Some(next) = (unsafe { gcry_sexp::as_ref(n) }) else {
        return null_mut();
    };
    let mut items = left.list().map(|list| list.to_vec()).unwrap_or_default();
    items.push(single_element(next));
    gcry_sexp::new(Sexpr::List(items), left.secure || next.secure)
}

#[unsafe(export_name = "gcry_sexp_prepend")]
pub extern "C" fn gcry_sexp_prepend(a: *const gcry_sexp, n: *const gcry_sexp) -> *mut gcry_sexp {
    let Some(left) = (unsafe { gcry_sexp::as_ref(a) }) else {
        return null_mut();
    };
    let Some(next) = (unsafe { gcry_sexp::as_ref(n) }) else {
        return null_mut();
    };
    let mut items = vec![single_element(next)];
    items.extend(left.list().map(|list| list.to_vec()).unwrap_or_default());
    gcry_sexp::new(Sexpr::List(items), left.secure || next.secure)
}

#[unsafe(export_name = "gcry_sexp_find_token")]
pub extern "C" fn gcry_sexp_find_token(
    list: *mut gcry_sexp,
    tok: *const c_char,
    toklen: usize,
) -> *mut gcry_sexp {
    let Some(value) = (unsafe { gcry_sexp::as_ref(list) }) else {
        return null_mut();
    };
    if tok.is_null() {
        return null_mut();
    }
    let token = if toklen == 0 {
        unsafe { CStr::from_ptr(tok) }.to_bytes().to_vec()
    } else {
        unsafe { std::slice::from_raw_parts(tok.cast::<u8>(), toklen) }.to_vec()
    };
    find_token_recursive(&value.root, &token, value.secure).unwrap_or(null_mut())
}

#[unsafe(export_name = "gcry_sexp_length")]
pub extern "C" fn gcry_sexp_length(list: *const gcry_sexp) -> c_int {
    unsafe { gcry_sexp::as_ref(list) }
        .and_then(gcry_sexp::list)
        .map_or(0, |items| items.len() as c_int)
}

#[unsafe(export_name = "gcry_sexp_nth")]
pub extern "C" fn gcry_sexp_nth(list: *const gcry_sexp, number: c_int) -> *mut gcry_sexp {
    let Some(value) = (unsafe { gcry_sexp::as_ref(list) }) else {
        return null_mut();
    };
    nth_element(value, number)
        .map(|node| make_element_sexp(node, value.secure))
        .unwrap_or(null_mut())
}

#[unsafe(export_name = "gcry_sexp_car")]
pub extern "C" fn gcry_sexp_car(list: *const gcry_sexp) -> *mut gcry_sexp {
    gcry_sexp_nth(list, 0)
}

#[unsafe(export_name = "gcry_sexp_cdr")]
pub extern "C" fn gcry_sexp_cdr(list: *const gcry_sexp) -> *mut gcry_sexp {
    let Some(value) = (unsafe { gcry_sexp::as_ref(list) }) else {
        return null_mut();
    };
    let Some(items) = value.list() else {
        return null_mut();
    };
    let rest = if items.len() > 1 { items[1..].to_vec() } else { Vec::new() };
    gcry_sexp::new(Sexpr::List(rest), value.secure)
}

#[unsafe(export_name = "gcry_sexp_cadr")]
pub extern "C" fn gcry_sexp_cadr(list: *const gcry_sexp) -> *mut gcry_sexp {
    gcry_sexp_nth(list, 1)
}

#[unsafe(export_name = "gcry_sexp_nth_data")]
pub extern "C" fn gcry_sexp_nth_data(
    list: *const gcry_sexp,
    number: c_int,
    datalen: *mut usize,
) -> *const c_char {
    if !datalen.is_null() {
        unsafe {
            *datalen = 0;
        }
    }
    let Some(value) = (unsafe { gcry_sexp::as_ref(list) }) else {
        return null();
    };
    let Some(data) = nth_atom(value, number) else {
        return null();
    };
    if !datalen.is_null() {
        unsafe {
            *datalen = data.len();
        }
    }
    data.as_ptr().cast()
}

#[unsafe(export_name = "gcry_sexp_nth_buffer")]
pub extern "C" fn gcry_sexp_nth_buffer(
    list: *const gcry_sexp,
    number: c_int,
    rlength: *mut usize,
) -> *mut c_void {
    if !rlength.is_null() {
        unsafe {
            *rlength = 0;
        }
    }
    let Some(value) = (unsafe { gcry_sexp::as_ref(list) }) else {
        return null_mut();
    };
    let Some(data) = nth_atom(value, number) else {
        return null_mut();
    };
    if !rlength.is_null() {
        unsafe {
            *rlength = data.len();
        }
    }
    mpi::alloc_output_bytes(data, false)
}

#[unsafe(export_name = "gcry_sexp_nth_string")]
pub extern "C" fn gcry_sexp_nth_string(list: *mut gcry_sexp, number: c_int) -> *mut c_char {
    let Some(value) = (unsafe { gcry_sexp::as_ref(list) }) else {
        return null_mut();
    };
    let Some(data) = nth_atom(value, number) else {
        return null_mut();
    };
    let mut bytes = data.to_vec();
    bytes.push(0);
    mpi::alloc_output_bytes(&bytes, false).cast()
}

#[unsafe(export_name = "gcry_sexp_nth_mpi")]
pub extern "C" fn gcry_sexp_nth_mpi(list: *mut gcry_sexp, number: c_int, mpifmt: c_int) -> *mut gcry_mpi {
    let Some(value) = (unsafe { gcry_sexp::as_ref(list) }) else {
        return null_mut();
    };
    let Some(data) = nth_atom(value, number) else {
        return null_mut();
    };
    if mpifmt == GCRYMPI_FMT_OPAQUE {
        return mpi::opaque::gcry_mpi_set_opaque_copy(null_mut(), data.as_ptr().cast(), (data.len() * 8) as c_uint);
    }
    let mut result = null_mut();
    let format = if mpifmt == 0 { GCRYMPI_FMT_STD } else { mpifmt };
    let err = mpi::scan::gcry_mpi_scan(&mut result, format, data.as_ptr().cast(), data.len(), null_mut());
    if err == 0 { result } else { null_mut() }
}

#[unsafe(no_mangle)]
pub extern "C" fn safe_gcry_sexp_build_dispatch(
    retsexp: *mut *mut gcry_sexp,
    erroff: *mut usize,
    format: *const c_char,
    args: *const usize,
    argc: usize,
) -> u32 {
    if !retsexp.is_null() {
        unsafe {
            *retsexp = null_mut();
        }
    }
    if !erroff.is_null() {
        unsafe {
            *erroff = 0;
        }
    }
    if retsexp.is_null() || format.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let format = unsafe { CStr::from_ptr(format) };
    let args = if args.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(args, argc) } };
    match build_from_format(format, args) {
        Ok((sexp, _)) => {
            unsafe {
                *retsexp = sexp;
            }
            0
        }
        Err(code) => code,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn safe_gcry_sexp_vlist_dispatch(
    a: *const gcry_sexp,
    rest: *const *mut gcry_sexp,
    count: usize,
) -> *mut gcry_sexp {
    let Some(first) = (unsafe { gcry_sexp::as_ref(a) }) else {
        return null_mut();
    };
    let mut items = vec![single_element(first)];
    let mut secure = first.secure;
    if !rest.is_null() {
        for idx in 0..count {
            let ptr = unsafe { *rest.add(idx) };
            let Some(item) = (unsafe { gcry_sexp::as_ref(ptr) }) else {
                continue;
            };
            secure |= item.secure;
            items.push(single_element(item));
        }
    }
    gcry_sexp::new(Sexpr::List(items), secure)
}

#[unsafe(no_mangle)]
pub extern "C" fn safe_gcry_sexp_extract_param_dispatch(
    sexp: *mut gcry_sexp,
    path: *const c_char,
    list: *const c_char,
    args: *const *mut c_void,
    argc: usize,
) -> u32 {
    let Some(value) = (unsafe { gcry_sexp::as_ref(sexp) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    if list.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let path = if path.is_null() { None } else { Some(unsafe { CStr::from_ptr(path) }) };
    let list = unsafe { CStr::from_ptr(list) };
    let args = if args.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(args, argc) } };
    extract_param_internal(value, path, list, args)
}
