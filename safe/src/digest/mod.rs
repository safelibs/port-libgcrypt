pub(crate) mod algorithms;

use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::mem::{align_of, offset_of, size_of};
use std::ptr::{copy_nonoverlapping, drop_in_place, null_mut, write};

use ::digest::{Digest as _, ExtendableOutput as _, Update, XofReader as _};
use gost94::Gost94CryptoPro;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake128Reader, Shake256, Shake256Reader,
};
use sm3::Sm3;
use streebog::{Streebog256, Streebog512};

use crate::alloc;
use crate::error;
use crate::upstream::gcry_buffer_t;

const GCRYCTL_RESET: c_int = 4;
const GCRYCTL_FINALIZE: c_int = 5;
const GCRYCTL_TEST_ALGO: c_int = 8;
const GCRYCTL_IS_SECURE: c_int = 9;
const GCRYCTL_GET_ASNOID: c_int = 10;
const GCRYCTL_IS_ALGO_ENABLED: c_int = 35;
const GCRYCTL_SELFTEST: c_int = 57;

const GCRY_MD_FLAG_SECURE: c_uint = 1;
const GCRY_MD_FLAG_HMAC: c_uint = 2;
const GCRY_MD_FLAG_BUGEMU1: c_uint = 0x0100;

const GPG_ERR_DIGEST_ALGO: u32 = 5;
const SECURE_BUF_SIZE: usize = 512;
const DEFAULT_BUF_SIZE: usize = 1024;
const MAX_DIGEST_ENTRIES: usize = 32;
const MAX_FIXED_DIGEST_LEN: usize = 64;
const MAX_HMAC_BLOCK_LEN: usize = 144;

pub type gcry_md_hd_t = *mut gcry_md_handle;

#[repr(C)]
pub struct gcry_md_handle {
    pub ctx: *mut c_void,
    pub bufpos: c_int,
    pub bufsize: c_int,
    pub buf: [u8; 1],
}

struct SecureBytes {
    ptr: *mut u8,
    len: usize,
}

impl SecureBytes {
    fn new_zeroed(len: usize) -> Option<Self> {
        if len == 0 {
            return Some(Self {
                ptr: null_mut(),
                len: 0,
            });
        }

        let ptr = alloc::gcry_calloc_secure(1, len).cast::<u8>();
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr, len })
        }
    }

    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr.cast_const(), self.len) }
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.len == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
        }
    }
}

impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        let mut copy = Self::new_zeroed(self.len).expect("secure byte clone allocation");
        copy.as_mut_slice().copy_from_slice(self.as_slice());
        copy
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            alloc::gcry_free(self.ptr.cast());
        }
    }
}

#[derive(Clone)]
enum ByteBuffer {
    Plain(Vec<u8>),
    Secure(SecureBytes),
}

impl ByteBuffer {
    fn new_zeroed(len: usize, secure: bool) -> Option<Self> {
        if secure {
            SecureBytes::new_zeroed(len).map(Self::Secure)
        } else {
            Some(Self::Plain(vec![0u8; len]))
        }
    }

    fn filled(len: usize, byte: u8, secure: bool) -> Option<Self> {
        let mut buffer = Self::new_zeroed(len, secure)?;
        buffer.as_mut_slice().fill(byte);
        Some(buffer)
    }

    fn copy_from_slice(bytes: &[u8], secure: bool) -> Option<Self> {
        let mut buffer = Self::new_zeroed(bytes.len(), secure)?;
        buffer.as_mut_slice().copy_from_slice(bytes);
        Some(buffer)
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            ByteBuffer::Plain(buffer) => buffer.as_slice(),
            ByteBuffer::Secure(buffer) => buffer.as_slice(),
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            ByteBuffer::Plain(buffer) => buffer.as_mut_slice(),
            ByteBuffer::Secure(buffer) => buffer.as_mut_slice(),
        }
    }

    fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }
}

#[derive(Clone)]
enum FixedDigestState {
    Md5(Md5),
    Sha1(Sha1),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha512_224(Sha512_224),
    Sha512_256(Sha512_256),
    Sha3_224(Sha3_224),
    Sha3_256(Sha3_256),
    Sha3_384(Sha3_384),
    Sha3_512(Sha3_512),
    Sm3(Sm3),
    Gost94CryptoPro(Gost94CryptoPro),
    Streebog256(Streebog256),
    Streebog512(Streebog512),
}

#[derive(Clone)]
enum XofDigestState {
    Shake128(Shake128),
    Shake256(Shake256),
}

#[derive(Clone)]
enum XofReaderState {
    Shake128(Shake128Reader),
    Shake256(Shake256Reader),
}

#[derive(Clone)]
enum DigestState {
    Fixed(FixedDigestState),
    Xof(XofDigestState),
}

#[derive(Clone)]
struct DigestEntry {
    algo: c_int,
    state: DigestState,
    inner_seed: Option<DigestState>,
    outer_seed: Option<DigestState>,
    fixed_output: Option<ByteBuffer>,
    xof_reader: Option<XofReaderState>,
}

#[derive(Clone)]
struct DigestEntries {
    len: usize,
    items: [Option<DigestEntry>; MAX_DIGEST_ENTRIES],
}

impl DigestEntries {
    fn new() -> Self {
        Self {
            len: 0,
            items: std::array::from_fn(|_| None),
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn contains_algo(&self, algo: c_int) -> bool {
        self.iter().any(|entry| entry.algo == algo)
    }

    fn insert_front(&mut self, entry: DigestEntry) -> bool {
        if self.len == MAX_DIGEST_ENTRIES {
            return false;
        }

        for idx in (0..self.len).rev() {
            self.items[idx + 1] = self.items[idx].take();
        }
        self.items[0] = Some(entry);
        self.len += 1;
        true
    }

    fn first(&self) -> Option<&DigestEntry> {
        (self.len > 0)
            .then_some(())
            .and_then(|_| self.items[0].as_ref())
    }

    fn iter(&self) -> impl Iterator<Item = &DigestEntry> {
        self.items[..self.len]
            .iter()
            .map(|entry| entry.as_ref().expect("occupied digest entry"))
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = &mut DigestEntry> {
        self.items[..self.len]
            .iter_mut()
            .map(|entry| entry.as_mut().expect("occupied digest entry"))
    }

    fn find(&self, algo: c_int) -> Option<&DigestEntry> {
        self.iter().find(|entry| entry.algo == algo)
    }

    fn find_mut(&mut self, algo: c_int) -> Option<&mut DigestEntry> {
        self.iter_mut().find(|entry| entry.algo == algo)
    }
}

#[derive(Clone)]
struct MdContext {
    secure: bool,
    hmac: bool,
    _bugemu1: bool,
    finalized: bool,
    key: Option<ByteBuffer>,
    entries: DigestEntries,
}

impl FixedDigestState {
    fn update(&mut self, data: &[u8]) {
        match self {
            FixedDigestState::Md5(state) => Update::update(state, data),
            FixedDigestState::Sha1(state) => Update::update(state, data),
            FixedDigestState::Sha224(state) => Update::update(state, data),
            FixedDigestState::Sha256(state) => Update::update(state, data),
            FixedDigestState::Sha384(state) => Update::update(state, data),
            FixedDigestState::Sha512(state) => Update::update(state, data),
            FixedDigestState::Sha512_224(state) => Update::update(state, data),
            FixedDigestState::Sha512_256(state) => Update::update(state, data),
            FixedDigestState::Sha3_224(state) => Update::update(state, data),
            FixedDigestState::Sha3_256(state) => Update::update(state, data),
            FixedDigestState::Sha3_384(state) => Update::update(state, data),
            FixedDigestState::Sha3_512(state) => Update::update(state, data),
            FixedDigestState::Sm3(state) => Update::update(state, data),
            FixedDigestState::Gost94CryptoPro(state) => Update::update(state, data),
            FixedDigestState::Streebog256(state) => Update::update(state, data),
            FixedDigestState::Streebog512(state) => Update::update(state, data),
        }
    }

    fn finalize_into(&self, output: &mut [u8]) {
        match self {
            FixedDigestState::Md5(state) => output.copy_from_slice(state.clone().finalize().as_ref()),
            FixedDigestState::Sha1(state) => output.copy_from_slice(state.clone().finalize().as_ref()),
            FixedDigestState::Sha224(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Sha256(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Sha384(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Sha512(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Sha512_224(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Sha512_256(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Sha3_224(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Sha3_256(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Sha3_384(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Sha3_512(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Sm3(state) => output.copy_from_slice(state.clone().finalize().as_ref()),
            FixedDigestState::Gost94CryptoPro(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Streebog256(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
            FixedDigestState::Streebog512(state) => {
                output.copy_from_slice(state.clone().finalize().as_ref())
            }
        }
    }

    fn finalize_boxed(&self) -> Box<[u8]> {
        match self {
            FixedDigestState::Md5(state) => state.clone().finalize().to_vec().into_boxed_slice(),
            FixedDigestState::Sha1(state) => state.clone().finalize().to_vec().into_boxed_slice(),
            FixedDigestState::Sha224(state) => state.clone().finalize().to_vec().into_boxed_slice(),
            FixedDigestState::Sha256(state) => state.clone().finalize().to_vec().into_boxed_slice(),
            FixedDigestState::Sha384(state) => state.clone().finalize().to_vec().into_boxed_slice(),
            FixedDigestState::Sha512(state) => state.clone().finalize().to_vec().into_boxed_slice(),
            FixedDigestState::Sha512_224(state) => {
                state.clone().finalize().to_vec().into_boxed_slice()
            }
            FixedDigestState::Sha512_256(state) => {
                state.clone().finalize().to_vec().into_boxed_slice()
            }
            FixedDigestState::Sha3_224(state) => {
                state.clone().finalize().to_vec().into_boxed_slice()
            }
            FixedDigestState::Sha3_256(state) => {
                state.clone().finalize().to_vec().into_boxed_slice()
            }
            FixedDigestState::Sha3_384(state) => {
                state.clone().finalize().to_vec().into_boxed_slice()
            }
            FixedDigestState::Sha3_512(state) => {
                state.clone().finalize().to_vec().into_boxed_slice()
            }
            FixedDigestState::Sm3(state) => state.clone().finalize().to_vec().into_boxed_slice(),
            FixedDigestState::Gost94CryptoPro(state) => {
                state.clone().finalize().to_vec().into_boxed_slice()
            }
            FixedDigestState::Streebog256(state) => {
                state.clone().finalize().to_vec().into_boxed_slice()
            }
            FixedDigestState::Streebog512(state) => {
                state.clone().finalize().to_vec().into_boxed_slice()
            }
        }
    }
}

impl XofDigestState {
    fn update(&mut self, data: &[u8]) {
        match self {
            XofDigestState::Shake128(state) => Update::update(state, data),
            XofDigestState::Shake256(state) => Update::update(state, data),
        }
    }

    fn finalize_reader(&self) -> XofReaderState {
        match self {
            XofDigestState::Shake128(state) => XofReaderState::Shake128(state.clone().finalize_xof()),
            XofDigestState::Shake256(state) => XofReaderState::Shake256(state.clone().finalize_xof()),
        }
    }
}

impl XofReaderState {
    fn read(&mut self, buffer: &mut [u8]) {
        match self {
            XofReaderState::Shake128(reader) => reader.read(buffer),
            XofReaderState::Shake256(reader) => reader.read(buffer),
        }
    }
}

impl DigestState {
    fn update(&mut self, data: &[u8]) {
        match self {
            DigestState::Fixed(state) => state.update(data),
            DigestState::Xof(state) => state.update(data),
        }
    }

    fn finalize_fixed(&self) -> Option<Box<[u8]>> {
        match self {
            DigestState::Fixed(state) => Some(state.finalize_boxed()),
            DigestState::Xof(_) => None,
        }
    }

    fn finalize_fixed_into(&self, output: &mut [u8]) -> bool {
        match self {
            DigestState::Fixed(state) => {
                state.finalize_into(output);
                true
            }
            DigestState::Xof(_) => false,
        }
    }

    fn finalize_fixed_bytes(&self, algo: c_int, secure: bool) -> Option<ByteBuffer> {
        let mut output = ByteBuffer::new_zeroed(algorithms::digest_output_len(algo), secure)?;
        self.finalize_fixed_into(output.as_mut_slice()).then_some(output)
    }

    fn finalize_xof(&self) -> Option<XofReaderState> {
        match self {
            DigestState::Fixed(_) => None,
            DigestState::Xof(state) => Some(state.finalize_reader()),
        }
    }
}

impl DigestEntry {
    fn new(algo: c_int) -> Option<Self> {
        Some(Self {
            algo,
            state: new_digest_state(algo)?,
            inner_seed: None,
            outer_seed: None,
            fixed_output: None,
            xof_reader: None,
        })
    }

    fn clear_output(&mut self) {
        self.fixed_output = None;
        self.xof_reader = None;
    }
}

impl MdContext {
    fn enable_algo(&mut self, algo: c_int) -> u32 {
        if self.entries.contains_algo(algo) {
            return 0;
        }

        let Some(info) = algorithms::info(algo) else {
            return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
        };
        if !info.available || (self.hmac && info.xof) {
            return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
        }

        let Some(mut entry) = DigestEntry::new(algo) else {
            return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
        };
        if self.hmac {
            if let Some(ref key) = self.key {
                let rc = initialize_hmac_entry(&mut entry, key.as_slice(), self.secure);
                if rc != 0 {
                    return rc;
                }
            }
        }

        if !self.entries.insert_front(entry) {
            return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
        }
        self.finalized = false;
        0
    }

    fn reset(&mut self) {
        self.finalized = false;
        for entry in self.entries.iter_mut() {
            entry.clear_output();
            entry.state = if self.hmac {
                entry
                    .inner_seed
                    .clone()
                    .unwrap_or_else(|| new_digest_state(entry.algo).expect("supported digest"))
            } else {
                new_digest_state(entry.algo).expect("supported digest")
            };
        }
    }
}

fn new_digest_state(algo: c_int) -> Option<DigestState> {
    let state = match algo {
        algorithms::GCRY_MD_MD5 => DigestState::Fixed(FixedDigestState::Md5(Md5::new())),
        algorithms::GCRY_MD_SHA1 => DigestState::Fixed(FixedDigestState::Sha1(Sha1::new())),
        algorithms::GCRY_MD_SHA224 => DigestState::Fixed(FixedDigestState::Sha224(Sha224::new())),
        algorithms::GCRY_MD_SHA256 => DigestState::Fixed(FixedDigestState::Sha256(Sha256::new())),
        algorithms::GCRY_MD_SHA384 => DigestState::Fixed(FixedDigestState::Sha384(Sha384::new())),
        algorithms::GCRY_MD_SHA512 => DigestState::Fixed(FixedDigestState::Sha512(Sha512::new())),
        algorithms::GCRY_MD_SHA512_224 => {
            DigestState::Fixed(FixedDigestState::Sha512_224(Sha512_224::new()))
        }
        algorithms::GCRY_MD_SHA512_256 => {
            DigestState::Fixed(FixedDigestState::Sha512_256(Sha512_256::new()))
        }
        algorithms::GCRY_MD_SHA3_224 => {
            DigestState::Fixed(FixedDigestState::Sha3_224(Sha3_224::new()))
        }
        algorithms::GCRY_MD_SHA3_256 => {
            DigestState::Fixed(FixedDigestState::Sha3_256(Sha3_256::new()))
        }
        algorithms::GCRY_MD_SHA3_384 => {
            DigestState::Fixed(FixedDigestState::Sha3_384(Sha3_384::new()))
        }
        algorithms::GCRY_MD_SHA3_512 => {
            DigestState::Fixed(FixedDigestState::Sha3_512(Sha3_512::new()))
        }
        algorithms::GCRY_MD_SHAKE128 => DigestState::Xof(XofDigestState::Shake128(Shake128::default())),
        algorithms::GCRY_MD_SHAKE256 => DigestState::Xof(XofDigestState::Shake256(Shake256::default())),
        algorithms::GCRY_MD_SM3 => DigestState::Fixed(FixedDigestState::Sm3(Sm3::new())),
        algorithms::GCRY_MD_GOSTR3411_CP => {
            DigestState::Fixed(FixedDigestState::Gost94CryptoPro(Gost94CryptoPro::new()))
        }
        algorithms::GCRY_MD_STRIBOG256 => {
            DigestState::Fixed(FixedDigestState::Streebog256(Streebog256::new()))
        }
        algorithms::GCRY_MD_STRIBOG512 => {
            DigestState::Fixed(FixedDigestState::Streebog512(Streebog512::new()))
        }
        _ => return None,
    };
    Some(state)
}

fn hash_chunks_fixed_internal(algo: c_int, chunks: &[&[u8]]) -> Result<Box<[u8]>, u32> {
    if !algorithms::digest_is_available(algo) || algorithms::is_xof(algo) {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    }

    let mut state = new_digest_state(algo).ok_or_else(|| error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))?;
    for chunk in chunks {
        state.update(chunk);
    }
    state
        .finalize_fixed()
        .ok_or_else(|| error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))
}

fn build_hmac_pads(
    algo: c_int,
    key: &[u8],
    secure: bool,
) -> Result<(ByteBuffer, ByteBuffer), u32> {
    let block_len = algorithms::digest_block_len(algo);
    if block_len == 0 || block_len > MAX_HMAC_BLOCK_LEN {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    }

    let digest_len = algorithms::digest_output_len(algo);
    if digest_len > MAX_FIXED_DIGEST_LEN {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    }

    let hashed_key = if key.len() > block_len {
        let mut state =
            new_digest_state(algo).ok_or_else(|| error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))?;
        let Some(mut digest) = ByteBuffer::new_zeroed(digest_len, secure) else {
            return Err(error::gcry_error_from_errno(crate::get_errno()));
        };
        state.update(key);
        if !state.finalize_fixed_into(digest.as_mut_slice()) {
            return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
        }
        Some(digest)
    } else {
        None
    };

    let key_material = hashed_key
        .as_ref()
        .map_or(key, |digest| digest.as_slice());

    let Some(mut inner_pad) = ByteBuffer::filled(block_len, 0x36, secure) else {
        return Err(error::gcry_error_from_errno(crate::get_errno()));
    };
    let Some(mut outer_pad) = ByteBuffer::filled(block_len, 0x5c, secure) else {
        return Err(error::gcry_error_from_errno(crate::get_errno()));
    };
    for (idx, byte) in key_material.iter().enumerate() {
        inner_pad.as_mut_slice()[idx] ^= *byte;
        outer_pad.as_mut_slice()[idx] ^= *byte;
    }

    Ok((inner_pad, outer_pad))
}

fn initialize_hmac_entry(entry: &mut DigestEntry, key: &[u8], secure: bool) -> u32 {
    if !algorithms::supports_hmac(entry.algo) {
        return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
    }

    let (inner_pad, outer_pad) = match build_hmac_pads(entry.algo, key, secure) {
        Ok(value) => value,
        Err(code) => return code,
    };

    let mut inner = match new_digest_state(entry.algo) {
        Some(state) => state,
        None => return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO),
    };
    inner.update(inner_pad.as_slice());

    let mut outer = match new_digest_state(entry.algo) {
        Some(state) => state,
        None => return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO),
    };
    outer.update(outer_pad.as_slice());

    entry.state = inner.clone();
    entry.inner_seed = Some(inner);
    entry.outer_seed = Some(outer);
    entry.clear_output();
    0
}

fn align_up(value: usize, align: usize) -> usize {
    let mask = align - 1;
    (value + mask) & !mask
}

fn handle_prefix_size(bufsize: usize) -> usize {
    align_up(offset_of!(gcry_md_handle, buf) + bufsize, align_of::<MdContext>())
}

fn handle_total_size(bufsize: usize) -> usize {
    handle_prefix_size(bufsize) + size_of::<MdContext>()
}

unsafe fn md_ctx(hd: gcry_md_hd_t) -> *mut MdContext {
    unsafe { (*hd).ctx.cast() }
}

unsafe fn handle_buffer<'a>(hd: gcry_md_hd_t) -> &'a mut [u8] {
    unsafe { std::slice::from_raw_parts_mut((*hd).buf.as_mut_ptr(), (*hd).bufsize as usize) }
}

fn allocate_handle(ctx: MdContext) -> Option<gcry_md_hd_t> {
    let bufsize = if ctx.secure { SECURE_BUF_SIZE } else { DEFAULT_BUF_SIZE };
    let total = handle_total_size(bufsize);
    let base = if ctx.secure {
        alloc::gcry_calloc_secure(1, total)
    } else {
        alloc::gcry_calloc(1, total)
    }
    .cast::<u8>();
    if base.is_null() {
        return None;
    }

    let hd = base.cast::<gcry_md_handle>();
    let ctx_ptr = unsafe { base.add(handle_prefix_size(bufsize)).cast::<MdContext>() };
    unsafe {
        write(ctx_ptr, ctx);
        (*hd).ctx = ctx_ptr.cast();
        (*hd).bufpos = 0;
        (*hd).bufsize = bufsize as c_int;
    }
    Some(hd)
}

unsafe fn flush_visible_buffer(hd: gcry_md_hd_t, ctx: &mut MdContext) {
    if hd.is_null() || (*hd).bufpos <= 0 || ctx.finalized {
        if !hd.is_null() {
            (*hd).bufpos = 0;
        }
        return;
    }

    let len = (*hd).bufpos as usize;
    let buffer = handle_buffer(hd);
    for entry in ctx.entries.iter_mut() {
        entry.state.update(&buffer[..len]);
        entry.clear_output();
    }
    (*hd).bufpos = 0;
}

unsafe fn finalize_context(hd: gcry_md_hd_t, ctx: &mut MdContext) {
    if ctx.finalized {
        return;
    }

    flush_visible_buffer(hd, ctx);
    for entry in ctx.entries.iter_mut() {
        entry.clear_output();
        if ctx.hmac {
            let Some(inner) = entry.state.finalize_fixed_bytes(entry.algo, ctx.secure) else {
                continue;
            };
            let Some(mut outer) = entry.outer_seed.clone() else {
                continue;
            };
            outer.update(inner.as_slice());
            entry.fixed_output = outer.finalize_fixed_bytes(entry.algo, ctx.secure);
        } else if let Some(output) = entry.state.finalize_fixed_bytes(entry.algo, ctx.secure) {
            entry.fixed_output = Some(output);
        } else if let Some(reader) = entry.state.finalize_xof() {
            entry.xof_reader = Some(reader);
        }
    }
    ctx.finalized = true;
}

fn fixed_output_ptr(ctx: &MdContext, algo: c_int) -> *mut u8 {
    ctx.entries
        .find(algo)
        .and_then(|entry| entry.fixed_output.as_ref())
        .map_or(null_mut(), |output| output.as_ptr().cast_mut())
}

fn xof_reader_mut(ctx: &mut MdContext, algo: c_int) -> Option<&mut XofReaderState> {
    ctx.entries.find_mut(algo).and_then(|entry| entry.xof_reader.as_mut())
}

fn slice_from_ptr<'a>(ptr: *const c_void, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) })
    }
}

fn iov_slice<'a>(iov: *const gcry_buffer_t, count: c_int) -> Result<Vec<&'a [u8]>, u32> {
    if iov.is_null() || count < 0 {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
    }

    let mut slices = Vec::with_capacity(count as usize);
    let items = unsafe { std::slice::from_raw_parts(iov, count as usize) };
    for item in items {
        let Some(base) = slice_from_ptr(item.data.cast_const(), item.off.saturating_add(item.len)) else {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
        };
        if item.off > base.len() {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_ARG));
        }
        let end = item.off.saturating_add(item.len).min(base.len());
        slices.push(&base[item.off..end]);
    }
    Ok(slices)
}

pub(crate) fn digest_block_len(algo: c_int) -> usize {
    algorithms::digest_block_len(algo)
}

pub(crate) fn hmac_compute(algo: c_int, key: &[u8], chunks: &[&[u8]]) -> Result<Box<[u8]>, u32> {
    if !algorithms::supports_hmac(algo) {
        return Err(error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO));
    }

    let (inner_pad, outer_pad) = build_hmac_pads(algo, key, false)?;

    let mut inner = new_digest_state(algo)
        .ok_or_else(|| error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))?;
    inner.update(inner_pad.as_slice());
    for chunk in chunks {
        inner.update(chunk);
    }
    let inner_digest = inner
        .finalize_fixed()
        .ok_or_else(|| error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))?;

    let mut outer = new_digest_state(algo)
        .ok_or_else(|| error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))?;
    outer.update(outer_pad.as_slice());
    outer.update(&inner_digest);
    outer
        .finalize_fixed()
        .ok_or_else(|| error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO))
}

#[no_mangle]
pub extern "C" fn gcry_md_open(h: *mut gcry_md_hd_t, algo: c_int, flags: c_uint) -> u32 {
    if h.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    if flags & !(GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC | GCRY_MD_FLAG_BUGEMU1) != 0 {
        unsafe {
            *h = null_mut();
        }
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let mut ctx = MdContext {
        secure: flags & GCRY_MD_FLAG_SECURE != 0,
        hmac: flags & GCRY_MD_FLAG_HMAC != 0,
        _bugemu1: flags & GCRY_MD_FLAG_BUGEMU1 != 0,
        finalized: false,
        key: None,
        entries: DigestEntries::new(),
    };

    if algo != 0 {
        let rc = ctx.enable_algo(algo);
        if rc != 0 {
            unsafe {
                *h = null_mut();
            }
            return rc;
        }
    }

    let Some(hd) = allocate_handle(ctx) else {
        unsafe {
            *h = null_mut();
        }
        return error::gcry_error_from_errno(crate::get_errno());
    };

    unsafe {
        *h = hd;
    }
    0
}

#[no_mangle]
pub extern "C" fn gcry_md_close(hd: gcry_md_hd_t) {
    if hd.is_null() {
        return;
    }

    unsafe {
        drop_in_place(md_ctx(hd));
    }
    alloc::gcry_free(hd.cast());
}

#[no_mangle]
pub extern "C" fn gcry_md_enable(hd: gcry_md_hd_t, algo: c_int) -> u32 {
    if hd.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let ctx = unsafe { &mut *md_ctx(hd) };
    ctx.enable_algo(algo)
}

#[no_mangle]
pub extern "C" fn gcry_md_copy(dest: *mut gcry_md_hd_t, src: gcry_md_hd_t) -> u32 {
    if dest.is_null() || src.is_null() {
        if !dest.is_null() {
            unsafe {
                *dest = null_mut();
            }
        }
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let cloned = unsafe {
        let src_ctx = &mut *md_ctx(src);
        flush_visible_buffer(src, src_ctx);
        src_ctx.clone()
    };

    let Some(copy) = allocate_handle(cloned) else {
        unsafe {
            *dest = null_mut();
        }
        return error::gcry_error_from_errno(crate::get_errno());
    };

    unsafe {
        *dest = copy;
    }
    0
}

#[no_mangle]
pub extern "C" fn gcry_md_reset(hd: gcry_md_hd_t) {
    if hd.is_null() {
        return;
    }

    unsafe {
        (*hd).bufpos = 0;
        (*md_ctx(hd)).reset();
    }
}

#[no_mangle]
pub extern "C" fn gcry_md_ctl(
    hd: gcry_md_hd_t,
    cmd: c_int,
    _buffer: *mut c_void,
    _buflen: usize,
) -> u32 {
    if hd.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    match cmd {
        GCRYCTL_FINALIZE => {
            unsafe {
                finalize_context(hd, &mut *md_ctx(hd));
            }
            0
        }
        GCRYCTL_RESET => {
            gcry_md_reset(hd);
            0
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[no_mangle]
pub extern "C" fn gcry_md_write(hd: gcry_md_hd_t, buffer: *const c_void, length: usize) {
    if hd.is_null() {
        return;
    }

    let ctx = unsafe { &mut *md_ctx(hd) };
    if ctx.finalized {
        unsafe {
            (*hd).bufpos = 0;
        }
        return;
    }

    unsafe {
        flush_visible_buffer(hd, ctx);
    }
    if length == 0 {
        return;
    }

    let Some(bytes) = slice_from_ptr(buffer, length) else {
        return;
    };
    for entry in ctx.entries.iter_mut() {
        entry.state.update(bytes);
        entry.clear_output();
    }
}

#[no_mangle]
pub extern "C" fn gcry_md_read(hd: gcry_md_hd_t, algo: c_int) -> *mut u8 {
    if hd.is_null() {
        return null_mut();
    }

    let Some(algo) = algorithms::resolve_read_algo(hd, algo) else {
        return null_mut();
    };
    if algorithms::is_xof(algo) {
        return null_mut();
    }

    let ctx = unsafe { &mut *md_ctx(hd) };
    unsafe {
        finalize_context(hd, ctx);
    }
    fixed_output_ptr(ctx, algo)
}

#[no_mangle]
pub extern "C" fn gcry_md_extract(
    hd: gcry_md_hd_t,
    algo: c_int,
    buffer: *mut c_void,
    length: usize,
) -> u32 {
    if hd.is_null() || (length > 0 && buffer.is_null()) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let Some(algo) = algorithms::resolve_read_algo(hd, algo) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    if !algorithms::is_xof(algo) {
        return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
    }

    let ctx = unsafe { &mut *md_ctx(hd) };
    unsafe {
        finalize_context(hd, ctx);
    }
    if length == 0 {
        return 0;
    }

    let Some(reader) = xof_reader_mut(ctx, algo) else {
        return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
    };
    let output = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length) };
    reader.read(output);
    0
}

#[no_mangle]
pub extern "C" fn gcry_md_hash_buffer(
    algo: c_int,
    digest: *mut c_void,
    buffer: *const c_void,
    length: usize,
) {
    if digest.is_null() {
        return;
    }

    let Some(bytes) = slice_from_ptr(buffer, length) else {
        return;
    };
    let Ok(output) = hash_chunks_fixed_internal(algo, &[bytes]) else {
        return;
    };
    unsafe {
        copy_nonoverlapping(output.as_ptr(), digest.cast::<u8>(), output.len());
    }
}

#[no_mangle]
pub extern "C" fn gcry_md_hash_buffers(
    algo: c_int,
    flags: c_uint,
    digest: *mut c_void,
    iov: *const gcry_buffer_t,
    iovcnt: c_int,
) -> u32 {
    if digest.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if flags & !GCRY_MD_FLAG_HMAC != 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let chunks = match iov_slice(iov, iovcnt) {
        Ok(value) => value,
        Err(code) => return code,
    };
    if flags & GCRY_MD_FLAG_HMAC != 0 {
        let Some((key, data)) = chunks.split_first() else {
            return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
        };
        let Ok(output) = hmac_compute(algo, key, data) else {
            return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
        };
        unsafe {
            copy_nonoverlapping(output.as_ptr(), digest.cast::<u8>(), output.len());
        }
        return 0;
    }

    let Ok(output) = hash_chunks_fixed_internal(algo, &chunks) else {
        return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
    };
    unsafe {
        copy_nonoverlapping(output.as_ptr(), digest.cast::<u8>(), output.len());
    }
    0
}

#[no_mangle]
pub extern "C" fn gcry_md_get_algo(hd: gcry_md_hd_t) -> c_int {
    if hd.is_null() {
        return 0;
    }

    let ctx = unsafe { &*md_ctx(hd) };
    ctx.entries.first().map_or(0, |entry| entry.algo)
}

#[no_mangle]
pub extern "C" fn gcry_md_get_algo_dlen(algo: c_int) -> c_uint {
    algorithms::digest_output_len(algo) as c_uint
}

#[no_mangle]
pub extern "C" fn gcry_md_is_enabled(hd: gcry_md_hd_t, algo: c_int) -> c_int {
    if hd.is_null() {
        return 0;
    }

    let ctx = unsafe { &*md_ctx(hd) };
    ctx.entries.contains_algo(algo) as c_int
}

#[no_mangle]
pub extern "C" fn gcry_md_is_secure(hd: gcry_md_hd_t) -> c_int {
    if hd.is_null() {
        return 0;
    }

    let ctx = unsafe { &*md_ctx(hd) };
    ctx.secure as c_int
}

#[no_mangle]
pub extern "C" fn gcry_md_info(
    hd: gcry_md_hd_t,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    if hd.is_null() || nbytes.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let ctx = unsafe { &*md_ctx(hd) };
    match what {
        GCRYCTL_IS_SECURE => {
            unsafe {
                *nbytes = ctx.secure as usize;
            }
            0
        }
        GCRYCTL_IS_ALGO_ENABLED => {
            if buffer.is_null() || unsafe { *nbytes } != size_of::<c_int>() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            let algo = unsafe { *(buffer.cast::<c_int>()) };
            unsafe {
                *nbytes = ctx.entries.contains_algo(algo) as usize;
            }
            0
        }
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[no_mangle]
pub extern "C" fn gcry_md_algo_info(
    algo: c_int,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    match what {
        GCRYCTL_TEST_ALGO => {
            if !buffer.is_null() || !nbytes.is_null() {
                return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
            }
            if algorithms::digest_is_available(algo) {
                0
            } else {
                error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO)
            }
        }
        GCRYCTL_GET_ASNOID => {
            if !algorithms::digest_is_available(algo) {
                return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
            }
            let Some(oid) = algorithms::oid_der(algo) else {
                return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
            };

            if !buffer.is_null() {
                if nbytes.is_null() {
                    return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
                }
                let available = unsafe { *nbytes };
                if available < oid.len() {
                    return error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT);
                }
                unsafe {
                    copy_nonoverlapping(oid.as_ptr(), buffer.cast::<u8>(), oid.len());
                    *nbytes = oid.len();
                }
                0
            } else if !nbytes.is_null() {
                unsafe {
                    *nbytes = oid.len();
                }
                0
            } else {
                error::gcry_error_from_code(error::GPG_ERR_INV_ARG)
            }
        }
        GCRYCTL_SELFTEST => error::gcry_error_from_code(error::GPG_ERR_NOT_IMPLEMENTED),
        _ => error::gcry_error_from_code(error::GPG_ERR_INV_OP),
    }
}

#[no_mangle]
pub extern "C" fn gcry_md_algo_name(algo: c_int) -> *const c_char {
    algorithms::canonical_name_bytes(algo)
        .map_or(b"?\0".as_ptr().cast(), |name| name.as_ptr().cast())
}

#[no_mangle]
pub extern "C" fn gcry_md_map_name(name: *const c_char) -> c_int {
    if name.is_null() {
        return 0;
    }

    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    algorithms::map_name(&name)
}

#[no_mangle]
pub extern "C" fn gcry_md_setkey(hd: gcry_md_hd_t, key: *const c_void, keylen: usize) -> u32 {
    if hd.is_null() || (keylen > 0 && key.is_null()) {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let ctx = unsafe { &mut *md_ctx(hd) };
    let key_bytes = match slice_from_ptr(key, keylen) {
        Some(value) => value,
        None => return error::gcry_error_from_code(error::GPG_ERR_INV_ARG),
    };

    if !ctx.hmac {
        return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
    }
    if ctx.entries.is_empty() {
        return error::gcry_error_from_code(GPG_ERR_DIGEST_ALGO);
    }

    let mut init_rc = 0;
    for entry in ctx.entries.iter_mut() {
        init_rc = initialize_hmac_entry(entry, key_bytes, ctx.secure);
        if init_rc != 0 {
            break;
        }
    }
    if init_rc != 0 {
        ctx.reset();
        return init_rc;
    }
    let Some(key_copy) = ByteBuffer::copy_from_slice(key_bytes, ctx.secure) else {
        return error::gcry_error_from_errno(crate::get_errno());
    };
    ctx.key = Some(key_copy);
    unsafe {
        (*hd).bufpos = 0;
    }
    ctx.finalized = false;
    0
}

#[no_mangle]
pub extern "C" fn gcry_md_debug(_hd: gcry_md_hd_t, _suffix: *const c_char) {}

#[export_name = "safe_gcry_md_get"]
pub extern "C" fn safe_gcry_md_get(
    hd: gcry_md_hd_t,
    algo: c_int,
    buffer: *mut u8,
    buflen: c_int,
) -> u32 {
    if hd.is_null() || buffer.is_null() || buflen < 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    if crate::global::lock_runtime_state().fips_mode {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    }

    let Some(algo) = algorithms::resolve_read_algo(hd, algo) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };

    if algorithms::is_xof(algo) {
        return gcry_md_extract(hd, algo, buffer.cast(), buflen as usize);
    }

    let digest_len = gcry_md_get_algo_dlen(algo) as usize;
    if digest_len == 0 {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    if (buflen as usize) < digest_len {
        return error::gcry_error_from_code(error::GPG_ERR_TOO_SHORT);
    }

    let digest = gcry_md_read(hd, algo);
    if digest.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    unsafe {
        copy_nonoverlapping(digest, buffer, digest_len);
    }
    0
}
