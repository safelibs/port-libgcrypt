use std::ffi::{CStr, c_int, c_uint, c_void};
use std::ops::Deref;
use std::ptr::{copy_nonoverlapping, null_mut, write_bytes};

use blowfish::Blowfish;
use camellia::{Camellia128, Camellia192, Camellia256};
use cast5::Cast5;
use cipher04::generic_array::GenericArray;
use cipher04::{
    BlockDecrypt as BlockDecrypt04, BlockEncrypt as BlockEncrypt04, KeyInit as KeyInit04,
};
use cipher05::{Block as Block05, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as KeyInit05};
use des::{Des, TdesEde3, weak_key_test};
use gost_crypto::Gost28147;
use idea::Idea;
use kisaseed::SEED;
use rc2::Rc2;
use serpent::Serpent;
use sm4::Sm4;
use twofish::Twofish;

use super::registry;
use crate::{alloc, error, mac};

const GCRY_CIPHER_IDEA: c_int = 1;
const GCRY_CIPHER_3DES: c_int = 2;
const GCRY_CIPHER_CAST5: c_int = 3;
const GCRY_CIPHER_BLOWFISH: c_int = 4;
const GCRY_CIPHER_AES: c_int = 7;
const GCRY_CIPHER_AES192: c_int = 8;
const GCRY_CIPHER_AES256: c_int = 9;
const GCRY_CIPHER_TWOFISH: c_int = 10;
const GCRY_CIPHER_ARCFOUR: c_int = 301;
const GCRY_CIPHER_DES: c_int = 302;
const GCRY_CIPHER_TWOFISH128: c_int = 303;
const GCRY_CIPHER_SERPENT128: c_int = 304;
const GCRY_CIPHER_SERPENT192: c_int = 305;
const GCRY_CIPHER_SERPENT256: c_int = 306;
const GCRY_CIPHER_RFC2268_40: c_int = 307;
const GCRY_CIPHER_RFC2268_128: c_int = 308;
const GCRY_CIPHER_SEED: c_int = 309;
const GCRY_CIPHER_CAMELLIA128: c_int = 310;
const GCRY_CIPHER_CAMELLIA192: c_int = 311;
const GCRY_CIPHER_CAMELLIA256: c_int = 312;
const GCRY_CIPHER_SALSA20: c_int = 313;
const GCRY_CIPHER_SALSA20R12: c_int = 314;
const GCRY_CIPHER_GOST28147: c_int = 315;
const GCRY_CIPHER_CHACHA20: c_int = 316;
const GCRY_CIPHER_GOST28147_MESH: c_int = 317;
const GCRY_CIPHER_SM4: c_int = 318;

const MODE_ECB: c_int = 1;
const MODE_CFB: c_int = 2;
const MODE_CBC: c_int = 3;
const MODE_STREAM: c_int = 4;
const MODE_OFB: c_int = 5;
const MODE_CTR: c_int = 6;
const MODE_AESWRAP: c_int = 7;
const MODE_CCM: c_int = 8;
const MODE_GCM: c_int = 9;
const MODE_POLY1305: c_int = 10;
const MODE_OCB: c_int = 11;
const MODE_CFB8: c_int = 12;
const MODE_XTS: c_int = 13;
const MODE_EAX: c_int = 14;
const MODE_SIV: c_int = 15;
const MODE_GCM_SIV: c_int = 16;
const MODE_INTERNAL: c_int = 0x10000;

const FLAG_SECURE: c_uint = 1;
const FLAG_ENABLE_SYNC: c_uint = 2;
const FLAG_CBC_CTS: c_uint = 4;
const FLAG_CBC_MAC: c_uint = 8;
const FLAG_EXTENDED: c_uint = 16;
const SUPPORTED_FLAGS: c_uint =
    FLAG_SECURE | FLAG_ENABLE_SYNC | FLAG_CBC_CTS | FLAG_CBC_MAC | FLAG_EXTENDED;

const GCRYCTL_CFB_SYNC: c_int = 3;
const GCRYCTL_RESET: c_int = 4;
const GCRYCTL_FINALIZE: c_int = 5;
const GCRYCTL_GET_KEYLEN: c_int = 6;
const GCRYCTL_SET_CBC_CTS: c_int = 41;
const GCRYCTL_SET_CBC_MAC: c_int = 42;
const GCRYCTL_SET_CCM_LENGTHS: c_int = 69;
const GCRYCTL_SET_SBOX: c_int = 73;
const GCRYCTL_SET_TAGLEN: c_int = 75;
const GCRYCTL_GET_TAGLEN: c_int = 76;
const GCRYCTL_SET_ALLOW_WEAK_KEY: c_int = 79;
const GCRYCTL_SET_DECRYPTION_TAG: c_int = 80;

const GPG_ERR_MISSING_KEY: u32 = 181;
const GPG_ERR_VALUE_NOT_FOUND: u32 = 28;

type GostSbox = &'static [[u8; 16]; 8];

const GOST_MESH_LIMIT: usize = 1024;
const GOST_CRYPTOPRO_KEY_MESHING_KEY: [u8; 32] = [
    0x69, 0x00, 0x72, 0x22, 0x64, 0xc9, 0x04, 0x23, 0x8d, 0x3a, 0xdb, 0x96, 0x46, 0xe9, 0x2a, 0xc4,
    0x18, 0xfe, 0xac, 0x94, 0x00, 0xed, 0x07, 0x12, 0xc0, 0x86, 0xdc, 0xc2, 0xef, 0x4c, 0xa9, 0x2b,
];

fn err(code: u32) -> u32 {
    error::gcry_error_from_code(code)
}

enum BlockState {
    Aes(mac::AesKey),
    Tdes(TdesEde3),
    Des(Des),
    Cast5(Cast5),
    Blowfish(Blowfish),
    Twofish(Twofish),
    Serpent(Serpent),
    Camellia128(Camellia128),
    Camellia192(Camellia192),
    Camellia256(Camellia256),
    Idea(Idea),
    Rc2(Rc2),
    Seed(SEED),
    Gost(GostBlock),
    Sm4(Sm4),
}

struct GostBlock {
    cipher: Gost28147,
    key: [u8; 32],
    sbox: GostSbox,
    mesh_limit: usize,
    mesh_counter: usize,
}

impl GostBlock {
    fn new(key: &[u8; 32], sbox: GostSbox, keymeshing: bool) -> Self {
        Self {
            cipher: Gost28147::with_sbox(key, sbox),
            key: *key,
            sbox,
            mesh_limit: if keymeshing { GOST_MESH_LIMIT } else { 0 },
            mesh_counter: 0,
        }
    }

    fn encrypt_plain(&self, input: &[u8]) -> Option<Vec<u8>> {
        Some(
            self.cipher
                .encrypt_block_raw(input.try_into().ok()?)
                .to_vec(),
        )
    }

    fn decrypt_plain(&self, input: &[u8]) -> Option<Vec<u8>> {
        Some(
            self.cipher
                .decrypt_block_raw(input.try_into().ok()?)
                .to_vec(),
        )
    }

    fn encrypt(&mut self, input: &[u8]) -> Option<Vec<u8>> {
        let mut block: [u8; 8] = input.try_into().ok()?;
        if self.mesh_limit != 0 && self.mesh_counter == self.mesh_limit {
            self.cryptopro_key_mesh();
            block = self.cipher.encrypt_block_raw(block);
        }
        let out = self.cipher.encrypt_block_raw(block);
        self.mesh_counter += 8;
        Some(out.to_vec())
    }

    fn cryptopro_key_mesh(&mut self) {
        let mut new_key = [0u8; 32];
        for (src, dst) in GOST_CRYPTOPRO_KEY_MESHING_KEY
            .chunks_exact(8)
            .zip(new_key.chunks_exact_mut(8))
        {
            dst.copy_from_slice(&self.cipher.decrypt_block_raw(src.try_into().unwrap()));
        }
        self.key = new_key;
        self.cipher = Gost28147::with_sbox(&self.key, self.sbox);
        self.mesh_counter = 0;
    }
}

struct CipherKey {
    ptr: *mut u8,
    len: usize,
    cap: usize,
    secure: bool,
}

impl CipherKey {
    fn new(secure: bool) -> Self {
        Self {
            ptr: null_mut(),
            len: 0,
            cap: 0,
            secure,
        }
    }

    fn replace_from_slice(&mut self, bytes: &[u8]) -> Result<(), u32> {
        if bytes.len() > self.cap {
            let new_cap = bytes.len().max(1);
            let new_ptr = if self.secure {
                alloc::gcry_malloc_secure(new_cap)
            } else {
                alloc::gcry_malloc(new_cap)
            }
            .cast::<u8>();
            if new_ptr.is_null() {
                return Err(error::gcry_error_from_errno(crate::ENOMEM_VALUE));
            }
            self.wipe_free();
            self.ptr = new_ptr;
            self.cap = new_cap;
        } else if self.cap != 0 {
            unsafe {
                write_bytes(self.ptr, 0, self.len);
            }
        }

        if !bytes.is_empty() {
            unsafe {
                copy_nonoverlapping(bytes.as_ptr(), self.ptr, bytes.len());
            }
        }
        self.len = bytes.len();
        Ok(())
    }

    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }

    fn wipe_free(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                write_bytes(self.ptr, 0, self.cap);
            }
            alloc::gcry_free(self.ptr.cast());
        }
        self.ptr = null_mut();
        self.len = 0;
        self.cap = 0;
    }
}

impl Deref for CipherKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Drop for CipherKey {
    fn drop(&mut self) {
        self.wipe_free();
    }
}

pub(crate) struct CipherContext {
    algo: c_int,
    mode: c_int,
    flags: c_uint,
    block_len: usize,
    key: CipherKey,
    key_set: bool,
    block: Option<BlockState>,
    iv: Vec<u8>,
    ctr: Vec<u8>,
    allow_weak_key: bool,
    cbc_cts: bool,
    cbc_mac: bool,
    finalized: bool,
    aad: Vec<u8>,
    aad_parts: Vec<Vec<u8>>,
    auth_data: Vec<u8>,
    ccm_lengths: Option<(usize, usize, usize)>,
    tag_len: usize,
    decrypt_tag: Option<Vec<u8>>,
    wrap_plen: [u8; 4],
    gost_sbox: GostSbox,
    gost_keymeshing: bool,
    arcfour: Option<ArcFour>,
    keystream: Vec<u8>,
    keystream_pos: usize,
    stream_offset: usize,
    ocb_offset: [u8; 16],
    ocb_checksum: [u8; 16],
    ocb_blocks: usize,
    ocb_initialized: bool,
    siv_nonce_set: bool,
    siv_tag: Vec<u8>,
}

impl CipherContext {
    pub(crate) fn open(algo: c_int, mode: c_int, flags: c_uint) -> Result<Self, u32> {
        if mode >= MODE_INTERNAL {
            return Err(err(error::GPG_ERR_INV_CIPHER_MODE));
        }
        let block_len = block_len_for_algo(algo).ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        if !registry::algorithm_available_for_open(algo) {
            return Err(err(error::GPG_ERR_CIPHER_ALGO));
        }
        if invalid_open_flags(flags) {
            return Err(err(error::GPG_ERR_CIPHER_ALGO));
        }
        if !valid_mode_for_algo(algo, mode) {
            return Err(err(error::GPG_ERR_INV_CIPHER_MODE));
        }
        let secure = flags & FLAG_SECURE != 0;
        let tag_len = match mode {
            MODE_GCM | MODE_EAX | MODE_OCB | MODE_SIV | MODE_GCM_SIV | MODE_POLY1305 => 16,
            MODE_CCM => 0,
            _ => 0,
        };
        Ok(Self {
            algo,
            mode,
            flags,
            block_len,
            key: CipherKey::new(secure),
            key_set: false,
            block: None,
            iv: vec![0; block_len.max(1)],
            ctr: vec![0; block_len.max(1)],
            allow_weak_key: false,
            cbc_cts: flags & FLAG_CBC_CTS != 0,
            cbc_mac: flags & FLAG_CBC_MAC != 0,
            finalized: false,
            aad: Vec::new(),
            aad_parts: Vec::new(),
            auth_data: Vec::new(),
            ccm_lengths: None,
            tag_len,
            decrypt_tag: None,
            wrap_plen: [0; 4],
            gost_sbox: mac::gost28147_default_cipher_sbox(),
            gost_keymeshing: false,
            arcfour: None,
            keystream: Vec::new(),
            keystream_pos: 0,
            stream_offset: 0,
            ocb_offset: [0; 16],
            ocb_checksum: [0; 16],
            ocb_blocks: 0,
            ocb_initialized: false,
            siv_nonce_set: false,
            siv_tag: Vec::new(),
        })
    }

    pub(crate) fn is_secure(&self) -> bool {
        self.flags & FLAG_SECURE != 0
    }

    pub(crate) fn has_key(&self) -> bool {
        self.key_set
    }

    pub(crate) fn supports_authenticate(&self) -> bool {
        matches!(
            self.mode,
            MODE_CCM | MODE_GCM | MODE_POLY1305 | MODE_OCB | MODE_EAX | MODE_SIV | MODE_GCM_SIV
        )
    }

    pub(crate) fn setkey(&mut self, key: &[u8]) -> u32 {
        if !self.valid_context_key_len(key.len()) {
            return err(error::GPG_ERR_INV_KEYLEN);
        }
        if matches!(self.algo, GCRY_CIPHER_DES | GCRY_CIPHER_3DES)
            && !self.allow_weak_key
            && weak_key_test(key).is_err()
        {
            return err(error::GPG_ERR_WEAK_KEY);
        }
        if let Err(rc) = self.key.replace_from_slice(key) {
            return rc;
        }
        self.block = match make_block(self.algo, key, self.gost_sbox, self.gost_keymeshing) {
            Some(block) => Some(block),
            None if matches!(self.mode, MODE_XTS | MODE_SIV) => None,
            None if self.algo == GCRY_CIPHER_ARCFOUR => {
                self.arcfour = ArcFour::new(key);
                None
            }
            None if matches!(
                self.algo,
                GCRY_CIPHER_SALSA20 | GCRY_CIPHER_SALSA20R12 | GCRY_CIPHER_CHACHA20
            ) =>
            {
                None
            }
            None => return err(error::GPG_ERR_INV_KEYLEN),
        };
        self.key_set = true;
        self.reset_state();
        0
    }

    pub(crate) fn setiv(&mut self, iv: &[u8]) -> u32 {
        if self.mode == MODE_SIV {
            self.iv.clear();
            self.iv.extend_from_slice(iv);
            self.aad_parts.push(iv.to_vec());
            self.siv_nonce_set = true;
            return 0;
        }
        self.iv.clear();
        if matches!(self.mode, MODE_STREAM | MODE_POLY1305)
            && matches!(self.algo, GCRY_CIPHER_CHACHA20)
        {
            if matches!(iv.len(), 8 | 12 | 16) {
                self.iv.extend_from_slice(iv);
            }
        } else if iv.is_empty()
            && matches!(
                self.mode,
                MODE_CBC | MODE_CFB | MODE_CFB8 | MODE_OFB | MODE_CTR | MODE_XTS
            )
        {
            self.iv.resize(self.block_len, 0);
        } else {
            self.iv.extend_from_slice(iv);
        }
        if self.mode == MODE_GCM {
            self.ctr = self.iv.clone();
        } else if self.mode == MODE_EAX {
            self.ctr = vec![0; self.block_len];
        }
        if matches!(
            self.mode,
            MODE_CCM | MODE_GCM | MODE_EAX | MODE_OCB | MODE_GCM_SIV | MODE_POLY1305
        ) {
            self.aad.clear();
            self.auth_data.clear();
            self.decrypt_tag = None;
            self.siv_tag.clear();
            self.finalized = false;
            self.ocb_offset = [0; 16];
            self.ocb_checksum = [0; 16];
            self.ocb_blocks = 0;
            self.ocb_initialized = false;
        }
        self.keystream.clear();
        self.keystream_pos = 0;
        self.stream_offset = 0;
        self.ocb_offset = [0; 16];
        self.ocb_checksum = [0; 16];
        self.ocb_blocks = 0;
        self.ocb_initialized = false;
        if self.mode == MODE_STREAM && self.algo == GCRY_CIPHER_ARCFOUR {
            self.arcfour = ArcFour::new(&self.key);
        }
        0
    }

    pub(crate) fn setctr(&mut self, ctr: &[u8]) -> u32 {
        self.ctr.clear();
        if ctr.is_empty() {
            self.ctr.resize(self.block_len.max(1), 0);
        } else if ctr.len() == self.block_len {
            self.ctr.extend_from_slice(ctr);
        } else {
            return err(error::GPG_ERR_INV_ARG);
        }
        self.keystream.clear();
        self.keystream_pos = 0;
        self.stream_offset = 0;
        0
    }

    pub(crate) fn ctl(&mut self, cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
        match cmd {
            GCRYCTL_RESET => {
                self.reset_state();
                0
            }
            GCRYCTL_CFB_SYNC => 0,
            GCRYCTL_FINALIZE => {
                if !buffer.is_null() || buflen != 0 {
                    return err(error::GPG_ERR_INV_ARG);
                }
                self.finalized = true;
                0
            }
            GCRYCTL_SET_CBC_CTS => {
                if buflen != 0 {
                    if self.cbc_mac {
                        return err(error::GPG_ERR_INV_FLAG);
                    }
                    self.cbc_cts = true;
                    self.flags |= FLAG_CBC_CTS;
                } else {
                    self.cbc_cts = false;
                    self.flags &= !FLAG_CBC_CTS;
                }
                0
            }
            GCRYCTL_SET_CBC_MAC => {
                if buflen != 0 {
                    if self.cbc_cts {
                        return err(error::GPG_ERR_INV_FLAG);
                    }
                    self.cbc_mac = true;
                    self.flags |= FLAG_CBC_MAC;
                } else {
                    self.cbc_mac = false;
                    self.flags &= !FLAG_CBC_MAC;
                }
                0
            }
            GCRYCTL_SET_ALLOW_WEAK_KEY => {
                self.allow_weak_key = buflen != 0;
                0
            }
            GCRYCTL_SET_CCM_LENGTHS => {
                if self.mode != MODE_CCM {
                    return err(error::GPG_ERR_INV_CIPHER_MODE);
                }
                if buffer.is_null() || buflen != 3 * std::mem::size_of::<u64>() {
                    return err(error::GPG_ERR_INV_ARG);
                }
                let words = unsafe {
                    [
                        std::ptr::read_unaligned(buffer.cast::<u64>()),
                        std::ptr::read_unaligned(buffer.cast::<u64>().add(1)),
                        std::ptr::read_unaligned(buffer.cast::<u64>().add(2)),
                    ]
                };
                if !valid_ccm_tag_len(words[2] as usize) {
                    return err(error::GPG_ERR_INV_LENGTH);
                }
                self.ccm_lengths = Some((words[0] as usize, words[1] as usize, words[2] as usize));
                self.tag_len = words[2] as usize;
                0
            }
            GCRYCTL_SET_TAGLEN => {
                if buffer.is_null() || buflen != std::mem::size_of::<c_int>() {
                    return err(error::GPG_ERR_INV_ARG);
                }
                if self.mode != MODE_OCB {
                    return err(error::GPG_ERR_INV_CIPHER_MODE);
                }
                let value = unsafe { std::ptr::read_unaligned(buffer.cast::<c_int>()) };
                if !matches!(value, 8 | 12 | 16) {
                    return err(error::GPG_ERR_INV_LENGTH);
                }
                self.tag_len = value as usize;
                0
            }
            GCRYCTL_SET_DECRYPTION_TAG => {
                if buffer.is_null() {
                    return err(error::GPG_ERR_INV_ARG);
                }
                if !matches!(self.mode, MODE_SIV | MODE_GCM_SIV) {
                    return err(error::GPG_ERR_INV_CIPHER_MODE);
                }
                if buflen != 16 {
                    return err(error::GPG_ERR_INV_ARG);
                }
                let tag = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), buflen) };
                self.decrypt_tag = Some(tag.to_vec());
                0
            }
            GCRYCTL_SET_SBOX => {
                if !matches!(
                    self.algo,
                    GCRY_CIPHER_GOST28147 | GCRY_CIPHER_GOST28147_MESH
                ) {
                    return err(error::GPG_ERR_NOT_SUPPORTED);
                }
                if buffer.is_null() {
                    return err(error::GPG_ERR_INV_ARG);
                }
                let oid = unsafe { CStr::from_ptr(buffer.cast()) }.to_bytes();
                let Some((sbox, keymeshing)) = mac::gost28147_sbox_info_from_oid(oid) else {
                    return err(GPG_ERR_VALUE_NOT_FOUND);
                };
                self.gost_sbox = sbox;
                self.gost_keymeshing = keymeshing;
                if !self.key.is_empty() {
                    self.block =
                        make_block(self.algo, &self.key, self.gost_sbox, self.gost_keymeshing);
                }
                0
            }
            _ => err(error::GPG_ERR_INV_OP),
        }
    }

    pub(crate) fn info(&self, what: c_int, buffer: *mut c_void, nbytes: *mut usize) -> u32 {
        match what {
            GCRYCTL_GET_TAGLEN => {
                if !buffer.is_null() || nbytes.is_null() {
                    return err(error::GPG_ERR_INV_ARG);
                }
                let tag_len = match self.mode {
                    MODE_OCB | MODE_CCM => self.tag_len,
                    MODE_EAX | MODE_GCM | MODE_POLY1305 | MODE_SIV | MODE_GCM_SIV => 16,
                    _ => return err(error::GPG_ERR_INV_CIPHER_MODE),
                };
                unsafe {
                    *nbytes = tag_len;
                }
                0
            }
            GCRYCTL_GET_KEYLEN => {
                if buffer.is_null() || nbytes.is_null() {
                    return err(error::GPG_ERR_INV_ARG);
                }
                if self.mode != MODE_AESWRAP {
                    return err(error::GPG_ERR_INV_CIPHER_MODE);
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(self.wrap_plen.as_ptr(), buffer.cast::<u8>(), 4);
                    *nbytes = 4;
                }
                0
            }
            _ => err(error::GPG_ERR_INV_OP),
        }
    }

    pub(crate) fn authenticate(&mut self, data: &[u8]) -> u32 {
        if !self.supports_authenticate() {
            return err(error::GPG_ERR_INV_CIPHER_MODE);
        }
        if self.mode == MODE_SIV {
            if self.siv_nonce_set {
                return err(error::GPG_ERR_INV_STATE);
            }
            self.aad_parts.push(data.to_vec());
        }
        self.aad.extend_from_slice(data);
        0
    }

    pub(crate) fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, u32> {
        if !self.has_key() {
            return Err(err(GPG_ERR_MISSING_KEY));
        }
        match self.mode {
            MODE_ECB => self.ecb(input, true),
            MODE_CBC if self.cbc_cts => self.cbc_cts_encrypt(input),
            MODE_CBC => self.cbc(input, true),
            MODE_CFB => self.cfb(input, true),
            MODE_CFB8 => self.cfb8(input, true),
            MODE_OFB => self.ofb(input),
            MODE_CTR => self.ctr_crypt(input),
            MODE_STREAM => self.stream_crypt(input),
            MODE_AESWRAP => self.aeswrap_encrypt(input),
            MODE_XTS => self.xts(input, true),
            MODE_GCM => self.gcm_crypt(input, true),
            MODE_CCM => self.ccm_crypt(input, true),
            MODE_EAX => self.eax_crypt(input, true),
            MODE_OCB => self.ocb_crypt(input, true),
            MODE_SIV => self.siv_crypt(input, true),
            MODE_GCM_SIV => self.gcm_siv_crypt(input, true),
            MODE_POLY1305 => self.compat_aead_crypt(input, true),
            _ => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
        }
    }

    pub(crate) fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, u32> {
        if !self.has_key() {
            return Err(err(GPG_ERR_MISSING_KEY));
        }
        match self.mode {
            MODE_ECB => self.ecb(input, false),
            MODE_CBC if self.cbc_cts => self.cbc_cts_decrypt(input),
            MODE_CBC => self.cbc(input, false),
            MODE_CFB => self.cfb(input, false),
            MODE_CFB8 => self.cfb8(input, false),
            MODE_OFB => self.ofb(input),
            MODE_CTR => self.ctr_crypt(input),
            MODE_STREAM => self.stream_crypt(input),
            MODE_AESWRAP => self.aeswrap_decrypt(input),
            MODE_XTS => self.xts(input, false),
            MODE_GCM => self.gcm_crypt(input, false),
            MODE_CCM => self.ccm_crypt(input, false),
            MODE_EAX => self.eax_crypt(input, false),
            MODE_OCB => self.ocb_crypt(input, false),
            MODE_SIV => self.siv_crypt(input, false),
            MODE_GCM_SIV => self.gcm_siv_crypt(input, false),
            MODE_POLY1305 => self.compat_aead_crypt(input, false),
            _ => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
        }
    }

    pub(crate) fn gettag(&mut self, out: &mut [u8]) -> u32 {
        if self.mode == MODE_GCM && !valid_gcm_gettag_len(out.len()) {
            return err(error::GPG_ERR_INV_LENGTH);
        }
        let tag = match self.compute_tag() {
            Some(tag) => tag,
            None => return err(error::GPG_ERR_INV_CIPHER_MODE),
        };
        let copy_len = out.len().min(tag.len());
        out[..copy_len].copy_from_slice(&tag[..copy_len]);
        0
    }

    pub(crate) fn checktag(&mut self, expected: &[u8]) -> u32 {
        if self.mode == MODE_GCM && !valid_gcm_tag_len(expected.len()) {
            return err(error::GPG_ERR_CHECKSUM);
        }
        let tag = match self.compute_tag() {
            Some(tag) => tag,
            None => return err(error::GPG_ERR_INV_CIPHER_MODE),
        };
        if expected.len() > tag.len() || !ct_eq(expected, &tag[..expected.len()]) {
            return err(error::GPG_ERR_CHECKSUM);
        }
        0
    }

    fn reset_state(&mut self) {
        self.iv = vec![0; self.block_len.max(1)];
        self.ctr = vec![0; self.block_len.max(1)];
        self.aad.clear();
        self.aad_parts.clear();
        self.auth_data.clear();
        self.finalized = false;
        self.decrypt_tag = None;
        self.keystream.clear();
        self.keystream_pos = 0;
        self.stream_offset = 0;
        self.ocb_offset = [0; 16];
        self.ocb_checksum = [0; 16];
        self.ocb_blocks = 0;
        self.ocb_initialized = false;
        self.siv_nonce_set = false;
        self.siv_tag.clear();
        if self.algo == GCRY_CIPHER_ARCFOUR {
            self.arcfour = ArcFour::new(&self.key);
        }
    }

    fn block_encrypt(&self, block: &[u8]) -> Option<Vec<u8>> {
        self.block.as_ref()?.encrypt(block)
    }

    fn block_encrypt_mut(&mut self, block: &[u8]) -> Option<Vec<u8>> {
        self.block.as_mut()?.encrypt_mut(block)
    }

    fn block_decrypt(&self, block: &[u8]) -> Option<Vec<u8>> {
        self.block.as_ref()?.decrypt(block)
    }

    fn valid_context_key_len(&self, len: usize) -> bool {
        if self.mode == MODE_GCM_SIV {
            return matches!(len, 16 | 32) && valid_key_len(self.algo, len);
        }
        if matches!(self.mode, MODE_XTS | MODE_SIV) {
            let half = len / 2;
            return len % 2 == 0 && valid_key_len(self.algo, half);
        }
        valid_key_len(self.algo, len)
    }

    fn ecb(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        if input.len() % self.block_len != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let mut out = Vec::with_capacity(input.len());
        for block in input.chunks_exact(self.block_len) {
            out.extend(
                if encrypt {
                    self.block_encrypt_mut(block)
                } else {
                    self.block_decrypt(block)
                }
                .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?,
            );
        }
        Ok(out)
    }

    fn cbc(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        if input.len() % self.block_len != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let mut out = Vec::with_capacity(input.len());
        for block in input.chunks_exact(self.block_len) {
            if encrypt {
                let mixed = xor(block, &self.iv);
                let ct = self
                    .block_encrypt_mut(&mixed)
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
                self.iv = ct.clone();
                if !self.cbc_mac {
                    out.extend(ct);
                }
            } else {
                let pt = self
                    .block_decrypt(block)
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
                out.extend(xor(&pt, &self.iv));
                self.iv.clear();
                self.iv.extend_from_slice(block);
            }
        }
        if self.cbc_mac {
            out.clear();
            out.extend_from_slice(&self.iv);
        }
        Ok(out)
    }

    fn cfb(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        let mut out = Vec::with_capacity(input.len());
        for chunk in input.chunks(self.block_len) {
            let iv = self.iv.clone();
            let ks = self
                .block_encrypt_mut(&iv)
                .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
            let part = xor(chunk, &ks[..chunk.len()]);
            if encrypt {
                self.iv.drain(..chunk.len());
                self.iv.extend_from_slice(&part);
            } else {
                self.iv.drain(..chunk.len());
                self.iv.extend_from_slice(chunk);
            }
            out.extend(part);
        }
        Ok(out)
    }

    fn cfb8(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            let iv = self.iv.clone();
            let ks = self
                .block_encrypt_mut(&iv)
                .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
            let value = byte ^ ks[0];
            self.iv.remove(0);
            self.iv.push(if encrypt { value } else { byte });
            out.push(value);
        }
        Ok(out)
    }

    fn ofb(&mut self, input: &[u8]) -> Result<Vec<u8>, u32> {
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.keystream_pos >= self.keystream.len() {
                let iv = self.iv.clone();
                self.keystream = self
                    .block_encrypt_mut(&iv)
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
                self.iv = self.keystream.clone();
                self.keystream_pos = 0;
            }
            out.push(byte ^ self.keystream[self.keystream_pos]);
            self.keystream_pos += 1;
        }
        Ok(out)
    }

    fn ctr_crypt(&mut self, input: &[u8]) -> Result<Vec<u8>, u32> {
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.keystream_pos >= self.keystream.len() {
                let ctr = self.ctr.clone();
                self.keystream = self
                    .block_encrypt_mut(&ctr)
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
                inc_be(&mut self.ctr);
                self.keystream_pos = 0;
            }
            out.push(byte ^ self.keystream[self.keystream_pos]);
            self.keystream_pos += 1;
        }
        Ok(out)
    }

    fn stream_crypt(&mut self, input: &[u8]) -> Result<Vec<u8>, u32> {
        match self.algo {
            GCRY_CIPHER_ARCFOUR => self
                .arcfour
                .as_mut()
                .ok_or_else(|| err(error::GPG_ERR_INV_STATE))
                .map(|s| s.apply(input)),
            GCRY_CIPHER_SALSA20 | GCRY_CIPHER_SALSA20R12 => {
                let out = salsa_xor_at(
                    &self.key,
                    &self.iv,
                    if self.algo == GCRY_CIPHER_SALSA20 {
                        20
                    } else {
                        12
                    },
                    self.stream_offset,
                    input,
                );
                self.stream_offset = self.stream_offset.saturating_add(input.len());
                Ok(out)
            }
            GCRY_CIPHER_CHACHA20 => {
                let out = chacha20_xor_at(&self.key, &self.iv, 0, self.stream_offset, input);
                self.stream_offset = self.stream_offset.saturating_add(input.len());
                Ok(out)
            }
            _ => Err(err(error::GPG_ERR_CIPHER_ALGO)),
        }
    }

    fn gcm_ctr_crypt(&mut self, input: &[u8]) -> Result<Vec<u8>, u32> {
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.keystream_pos >= self.keystream.len() {
                let mut ctr = [0u8; 16];
                ctr.copy_from_slice(&self.ctr[..16]);
                self.keystream = self
                    .block_encrypt(&ctr)
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
                inc32(&mut ctr);
                self.ctr.copy_from_slice(&ctr);
                self.keystream_pos = 0;
            }
            out.push(byte ^ self.keystream[self.keystream_pos]);
            self.keystream_pos += 1;
        }
        Ok(out)
    }

    fn gcm_crypt(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        let h = u128::from_be_bytes(
            self.block_encrypt(&[0; 16])
                .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?
                .try_into()
                .unwrap(),
        );
        let j0 = gcm_j0(h, &self.iv);
        if self.auth_data.is_empty() {
            self.ctr = (j0 + 1).to_be_bytes().to_vec();
        }
        let out = self.gcm_ctr_crypt(input)?;
        if encrypt {
            self.auth_data.extend_from_slice(&out);
        } else {
            self.auth_data.extend_from_slice(input);
        }
        Ok(out)
    }

    fn ccm_crypt(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        let (msg_len, _, tag_len) = self
            .ccm_lengths
            .unwrap_or((input.len(), self.aad.len(), 16));
        self.tag_len = tag_len;
        if self.iv.len() < 7 || self.iv.len() > 13 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let l = 15 - self.iv.len();
        if self.auth_data.is_empty() && self.keystream_pos >= self.keystream.len() {
            self.ctr = ccm_counter_block(&self.iv, l, 1).to_vec();
            self.keystream.clear();
            self.keystream_pos = 0;
        }
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            if self.keystream_pos >= self.keystream.len() {
                self.keystream = self
                    .block_encrypt(&self.ctr)
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
                inc_be_tail(&mut self.ctr, l);
                self.keystream_pos = 0;
            }
            out.push(byte ^ self.keystream[self.keystream_pos]);
            self.keystream_pos += 1;
        }
        if encrypt {
            self.auth_data.extend_from_slice(input);
        } else {
            self.auth_data.extend_from_slice(&out);
        }
        if self.auth_data.len() > msg_len {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        Ok(out)
    }

    fn eax_crypt(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        if self.ctr.iter().all(|&b| b == 0) || self.ctr.len() != self.block_len {
            self.ctr = eax_omac(self, 0, &self.iv)?;
        }
        let out = self.ctr_crypt(input)?;
        if encrypt {
            self.auth_data.extend_from_slice(&out);
        } else {
            self.auth_data.extend_from_slice(input);
        }
        Ok(out)
    }

    fn ocb_init(&mut self) -> Result<(), u32> {
        if self.ocb_initialized {
            return Ok(());
        }
        if self.block_len != 16 || self.iv.len() > 15 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        self.ocb_offset = ocb_nonce_offset(self, self.tag_len)?;
        self.ocb_checksum = [0; 16];
        self.ocb_blocks = 0;
        self.ocb_initialized = true;
        Ok(())
    }

    fn ocb_crypt(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        self.ocb_init()?;
        if !self.finalized && input.len() % 16 != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }

        let full_len = if self.finalized {
            input.len() / 16 * 16
        } else {
            input.len()
        };
        let mut out = Vec::with_capacity(input.len());
        for block in input[..full_len].chunks_exact(16) {
            self.ocb_blocks += 1;
            let l = ocb_l_for_index(self, self.ocb_blocks)?;
            xor_in_place(&mut self.ocb_offset, &l);
            let masked = xor(block, &self.ocb_offset);
            let crypted = if encrypt {
                self.block_encrypt(&masked)
            } else {
                self.block_decrypt(&masked)
            }
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
            let plain_or_cipher = xor(&crypted, &self.ocb_offset);
            if encrypt {
                xor_in_place(&mut self.ocb_checksum, block);
                out.extend_from_slice(&plain_or_cipher);
            } else {
                xor_in_place(&mut self.ocb_checksum, &plain_or_cipher);
                out.extend_from_slice(&plain_or_cipher);
            }
        }

        let partial = &input[full_len..];
        if !partial.is_empty() {
            let l_star = ocb_l_star(self)?;
            xor_in_place(&mut self.ocb_offset, &l_star);
            let pad = self
                .block_encrypt(&self.ocb_offset)
                .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
            let part = xor(partial, &pad[..partial.len()]);
            out.extend_from_slice(&part);
            let mut padded = [0u8; 16];
            if encrypt {
                padded[..partial.len()].copy_from_slice(partial);
            } else {
                padded[..partial.len()].copy_from_slice(&part);
            }
            padded[partial.len()] = 0x80;
            xor_in_place(&mut self.ocb_checksum, &padded);
        }

        Ok(out)
    }

    fn siv_crypt(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        if self.key.len() % 2 != 0 {
            return Err(err(error::GPG_ERR_INV_KEYLEN));
        }
        let half = self.key.len() / 2;
        if encrypt {
            let tag = aes_siv_s2v(self.algo, &self.key[..half], &self.aad_parts, input)?;
            let out = aes_siv_ctr(self.algo, &self.key[half..], &tag, input)?;
            self.auth_data.clear();
            self.auth_data.extend_from_slice(input);
            self.siv_tag = tag.to_vec();
            Ok(out)
        } else {
            let tag = self
                .decrypt_tag
                .clone()
                .ok_or_else(|| err(error::GPG_ERR_INV_STATE))?;
            let out = aes_siv_ctr(self.algo, &self.key[half..], &tag, input)?;
            self.auth_data.clear();
            self.auth_data.extend_from_slice(&out);
            self.siv_tag =
                aes_siv_s2v(self.algo, &self.key[..half], &self.aad_parts, &out)?.to_vec();
            Ok(out)
        }
    }

    fn gcm_siv_crypt(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        let (auth_key, enc_key) = gcm_siv_keys(self.algo, &self.key, &self.iv)?;
        if encrypt {
            let tag = gcm_siv_tag(self.algo, &auth_key, &enc_key, &self.iv, &self.aad, input)?;
            let out = gcm_siv_ctr(self.algo, &enc_key, &tag, input)?;
            self.auth_data.clear();
            self.auth_data.extend_from_slice(input);
            self.siv_tag = tag.to_vec();
            Ok(out)
        } else {
            let tag = self
                .decrypt_tag
                .clone()
                .ok_or_else(|| err(error::GPG_ERR_INV_STATE))?;
            let out = gcm_siv_ctr(self.algo, &enc_key, &tag, input)?;
            self.auth_data.clear();
            self.auth_data.extend_from_slice(&out);
            self.siv_tag =
                gcm_siv_tag(self.algo, &auth_key, &enc_key, &self.iv, &self.aad, &out)?.to_vec();
            Ok(out)
        }
    }

    fn compat_aead_crypt(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        let out = match self.mode {
            MODE_POLY1305 if self.algo == GCRY_CIPHER_CHACHA20 => {
                chacha20_xor_at(&self.key, &self.iv, 1, self.auth_data.len(), input)
            }
            MODE_OCB | MODE_SIV | MODE_GCM_SIV => self.ctr_crypt(input)?,
            _ => self.ctr_crypt(input)?,
        };
        if encrypt {
            self.auth_data.extend_from_slice(&out);
        } else {
            self.auth_data.extend_from_slice(input);
        }
        Ok(out)
    }

    fn compute_tag(&mut self) -> Option<Vec<u8>> {
        match self.mode {
            MODE_GCM => {
                let h = u128::from_be_bytes(self.block_encrypt(&[0; 16])?.try_into().ok()?);
                let j0 = gcm_j0(h, &self.iv);
                let s = ghash_aad_cipher(h, &self.aad, &self.auth_data);
                let mask =
                    u128::from_be_bytes(self.block_encrypt(&j0.to_be_bytes())?.try_into().ok()?);
                Some((s ^ mask).to_be_bytes().to_vec())
            }
            MODE_CCM => self.ccm_tag(),
            MODE_EAX => {
                let n = eax_omac(self, 0, &self.iv).ok()?;
                let h = eax_omac(self, 1, &self.aad).ok()?;
                let c = eax_omac(self, 2, &self.auth_data).ok()?;
                Some(
                    n.iter()
                        .zip(h.iter())
                        .zip(c.iter())
                        .map(|((a, b), c)| a ^ b ^ c)
                        .collect(),
                )
            }
            MODE_POLY1305 if self.algo == GCRY_CIPHER_CHACHA20 => {
                let mut otk_stream = chacha20_xor(&self.key, &self.iv, 0, &[0; 64]);
                let mut key = [0u8; 32];
                key.copy_from_slice(&otk_stream[..32]);
                otk_stream.fill(0);
                let mut data = Vec::new();
                data.extend_from_slice(&self.aad);
                pad16(&mut data);
                data.extend_from_slice(&self.auth_data);
                pad16(&mut data);
                data.extend_from_slice(&(self.aad.len() as u64).to_le_bytes());
                data.extend_from_slice(&(self.auth_data.len() as u64).to_le_bytes());
                Some(mac::poly1305_mac(&key, &data).to_vec())
            }
            MODE_OCB => self.ocb_tag(),
            MODE_SIV => {
                if self.siv_tag.is_empty() {
                    let half = self.key.len() / 2;
                    aes_siv_s2v(
                        self.algo,
                        &self.key[..half],
                        &self.aad_parts,
                        &self.auth_data,
                    )
                    .ok()
                    .map(|tag| tag.to_vec())
                } else {
                    Some(self.siv_tag.clone())
                }
            }
            MODE_GCM_SIV => {
                if self.siv_tag.is_empty() {
                    let (auth_key, enc_key) = gcm_siv_keys(self.algo, &self.key, &self.iv).ok()?;
                    gcm_siv_tag(
                        self.algo,
                        &auth_key,
                        &enc_key,
                        &self.iv,
                        &self.aad,
                        &self.auth_data,
                    )
                    .ok()
                    .map(|tag| tag.to_vec())
                } else {
                    Some(self.siv_tag.clone())
                }
            }
            _ => None,
        }
    }

    fn ocb_tag(&mut self) -> Option<Vec<u8>> {
        self.ocb_init().ok()?;
        let l_dollar = ocb_l_dollar(self).ok()?;
        let aad_hash = ocb_hash(self, &self.aad).ok()?;
        let mut tag_block = self.ocb_checksum;
        xor_in_place(&mut tag_block, &self.ocb_offset);
        xor_in_place(&mut tag_block, &l_dollar);
        let encrypted = self.block_encrypt(&tag_block)?;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&encrypted);
        xor_in_place(&mut tag, &aad_hash);
        Some(tag[..self.tag_len.min(16)].to_vec())
    }

    fn ccm_tag(&self) -> Option<Vec<u8>> {
        let (msg_len, _, tag_len) =
            self.ccm_lengths
                .unwrap_or((self.auth_data.len(), self.aad.len(), 16));
        let l = 15 - self.iv.len();
        let mut b0 = [0u8; 16];
        b0[0] = if !self.aad.is_empty() { 0x40 } else { 0 }
            | ((((tag_len - 2) / 2) as u8) << 3)
            | ((l - 1) as u8);
        b0[1..1 + self.iv.len()].copy_from_slice(&self.iv);
        encode_be_len(&mut b0[16 - l..], msg_len as u64);
        let mut mac_data = b0.to_vec();
        if !self.aad.is_empty() {
            encode_ccm_aad_len(&mut mac_data, self.aad.len());
            mac_data.extend_from_slice(&self.aad);
            pad16(&mut mac_data);
        }
        mac_data.extend_from_slice(&self.auth_data);
        pad16(&mut mac_data);
        let mut y = [0u8; 16];
        for block in mac_data.chunks_exact(16) {
            let mixed = xor(&y, block);
            y.copy_from_slice(&self.block_encrypt(&mixed)?);
        }
        let s0 = self.block_encrypt(&ccm_counter_block(&self.iv, l, 0))?;
        Some(xor(&y, &s0)[..tag_len].to_vec())
    }

    fn aeswrap_encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, u32> {
        if self.algo != GCRY_CIPHER_AES
            && self.algo != GCRY_CIPHER_AES192
            && self.algo != GCRY_CIPHER_AES256
        {
            return Err(err(error::GPG_ERR_CIPHER_ALGO));
        }
        if self.flags & FLAG_EXTENDED != 0 || input.len() % 8 != 0 || input.len() == 8 {
            aes_kwp_wrap(&self.key, input)
        } else {
            aes_kw_wrap(&self.key, input)
        }
    }

    fn aeswrap_decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, u32> {
        if input.len() < 16 || input.len() % 8 != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let result = if self.flags & FLAG_EXTENDED != 0 {
            let (plain, plen) = aes_kwp_unwrap(&self.key, input)?;
            self.wrap_plen = plen;
            plain
        } else {
            self.wrap_plen = [0; 4];
            aes_kw_unwrap(&self.key, input)?
        };
        Ok(result)
    }

    fn xts(&mut self, input: &[u8], encrypt: bool) -> Result<Vec<u8>, u32> {
        if self.key.len() % 2 != 0 || input.is_empty() || input.len() < 16 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let half = self.key.len() / 2;
        let data_key = make_block(self.algo, &self.key[..half], self.gost_sbox, false)
            .ok_or_else(|| err(error::GPG_ERR_INV_KEYLEN))?;
        let tweak_key = make_block(self.algo, &self.key[half..], self.gost_sbox, false)
            .ok_or_else(|| err(error::GPG_ERR_INV_KEYLEN))?;
        let mut tweak = tweak_key
            .encrypt(&self.iv)
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        let mut out = Vec::with_capacity(input.len());
        let rem = input.len() % 16;
        let full_len = input.len() - rem;
        let normal_full_len = if rem == 0 { full_len } else { full_len - 16 };
        for block in input[..normal_full_len].chunks_exact(16) {
            let x = xor(block, &tweak);
            let y = if encrypt {
                data_key.encrypt(&x)
            } else {
                data_key.decrypt(&x)
            }
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
            out.extend(xor(&y, &tweak));
            xts_mul_alpha(&mut tweak);
        }
        if rem == 0 {
            return Ok(out);
        }

        let full = &input[normal_full_len..normal_full_len + 16];
        let partial = &input[normal_full_len + 16..];
        if encrypt {
            let cc = xor(
                &data_key
                    .encrypt(&xor(full, &tweak))
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?,
                &tweak,
            );
            let mut next_tweak = tweak.clone();
            xts_mul_alpha(&mut next_tweak);
            let mut stolen_plain = vec![0u8; 16];
            stolen_plain[..rem].copy_from_slice(partial);
            stolen_plain[rem..].copy_from_slice(&cc[rem..]);
            let c_full = xor(
                &data_key
                    .encrypt(&xor(&stolen_plain, &next_tweak))
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?,
                &next_tweak,
            );
            out.extend_from_slice(&c_full);
            out.extend_from_slice(&cc[..rem]);
        } else {
            let c_full = full;
            let c_partial = partial;
            let mut next_tweak = tweak.clone();
            xts_mul_alpha(&mut next_tweak);
            let pp = xor(
                &data_key
                    .decrypt(&xor(c_full, &next_tweak))
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?,
                &next_tweak,
            );
            let mut c_tmp = vec![0u8; 16];
            c_tmp[..rem].copy_from_slice(c_partial);
            c_tmp[rem..].copy_from_slice(&pp[rem..]);
            let p_full = xor(
                &data_key
                    .decrypt(&xor(&c_tmp, &tweak))
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?,
                &tweak,
            );
            out.extend_from_slice(&p_full);
            out.extend_from_slice(&pp[..rem]);
        }
        Ok(out)
    }

    fn cbc_cts_encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, u32> {
        if input.len() <= self.block_len {
            return self.cbc(input, true);
        }
        let b = self.block_len;
        let rem = input.len() % b;
        if rem == 0 {
            let split = input.len() - 2 * b;
            let mut cbc = self.cbc(input, true)?;
            cbc[split..].rotate_left(b);
            return Ok(cbc);
        }

        let prefix_len = input.len() - b - rem;
        let mut out = Vec::with_capacity(input.len());
        if prefix_len > 0 {
            out.extend(self.cbc(&input[..prefix_len], true)?);
        }

        let penultimate = &input[prefix_len..prefix_len + b];
        let partial = &input[prefix_len + b..];
        let c_penultimate = self
            .block_encrypt_mut(&xor(penultimate, &self.iv))
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        let mut padded = vec![0u8; b];
        padded[..rem].copy_from_slice(partial);
        let c_final = self
            .block_encrypt_mut(&xor(&padded, &c_penultimate))
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        out.extend_from_slice(&c_final);
        out.extend_from_slice(&c_penultimate[..rem]);
        self.iv = c_final;
        Ok(out)
    }

    fn cbc_cts_decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, u32> {
        if input.len() <= self.block_len {
            return self.cbc(input, false);
        }
        let b = self.block_len;
        let rem = input.len() % b;
        if rem == 0 {
            let split = input.len() - 2 * b;
            let mut reordered = input.to_vec();
            reordered[split..].rotate_left(b);
            return self.cbc(&reordered, false);
        }

        let prefix_len = input.len() - b - rem;
        let mut out = Vec::with_capacity(input.len());
        let c_prev = self.iv.clone();
        if prefix_len > 0 {
            out.extend(self.cbc(&input[..prefix_len], false)?);
        }
        let prev_chain = if prefix_len > 0 {
            input[prefix_len - b..prefix_len].to_vec()
        } else {
            c_prev
        };
        let c_final = &input[prefix_len..prefix_len + b];
        let c_stolen = &input[prefix_len + b..];
        let d_final = self
            .block_decrypt(c_final)
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        let mut c_penultimate = vec![0u8; b];
        c_penultimate[..rem].copy_from_slice(c_stolen);
        c_penultimate[rem..].copy_from_slice(&d_final[rem..]);

        let penultimate = self
            .block_decrypt(&c_penultimate)
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        out.extend(xor(&penultimate, &prev_chain));
        out.extend(xor(&d_final[..rem], c_stolen));
        self.iv = c_final.to_vec();
        Ok(out)
    }
}

impl BlockState {
    fn encrypt(&self, input: &[u8]) -> Option<Vec<u8>> {
        match self {
            BlockState::Aes(key) => Some(key.encrypt_block(input.try_into().ok()?).to_vec()),
            BlockState::Tdes(c) => enc05(c, input),
            BlockState::Des(c) => enc05(c, input),
            BlockState::Cast5(c) => enc05(c, input),
            BlockState::Blowfish(c) => enc05(c, input),
            BlockState::Twofish(c) => enc05(c, input),
            BlockState::Serpent(c) => enc05(c, input),
            BlockState::Camellia128(c) => enc05(c, input),
            BlockState::Camellia192(c) => enc05(c, input),
            BlockState::Camellia256(c) => enc05(c, input),
            BlockState::Idea(c) => enc05(c, input),
            BlockState::Rc2(c) => enc05(c, input),
            BlockState::Seed(c) => enc04(c, input),
            BlockState::Gost(c) => c.encrypt_plain(input),
            BlockState::Sm4(c) => enc05(c, input),
        }
    }

    fn encrypt_mut(&mut self, input: &[u8]) -> Option<Vec<u8>> {
        match self {
            BlockState::Gost(c) => c.encrypt(input),
            _ => self.encrypt(input),
        }
    }

    fn decrypt(&self, input: &[u8]) -> Option<Vec<u8>> {
        match self {
            BlockState::Aes(key) => Some(key.decrypt_block(input.try_into().ok()?).to_vec()),
            BlockState::Tdes(c) => dec05(c, input),
            BlockState::Des(c) => dec05(c, input),
            BlockState::Cast5(c) => dec05(c, input),
            BlockState::Blowfish(c) => dec05(c, input),
            BlockState::Twofish(c) => dec05(c, input),
            BlockState::Serpent(c) => dec05(c, input),
            BlockState::Camellia128(c) => dec05(c, input),
            BlockState::Camellia192(c) => dec05(c, input),
            BlockState::Camellia256(c) => dec05(c, input),
            BlockState::Idea(c) => dec05(c, input),
            BlockState::Rc2(c) => dec05(c, input),
            BlockState::Seed(c) => dec04(c, input),
            BlockState::Gost(c) => c.decrypt_plain(input),
            BlockState::Sm4(c) => dec05(c, input),
        }
    }
}

fn make_block(
    algo: c_int,
    key: &[u8],
    gost_sbox: GostSbox,
    gost_keymeshing: bool,
) -> Option<BlockState> {
    Some(match algo {
        GCRY_CIPHER_AES | GCRY_CIPHER_AES192 | GCRY_CIPHER_AES256 => {
            BlockState::Aes(mac::AesKey::new(key)?)
        }
        GCRY_CIPHER_3DES => BlockState::Tdes(TdesEde3::new_from_slice(key).ok()?),
        GCRY_CIPHER_DES => BlockState::Des(Des::new_from_slice(key).ok()?),
        GCRY_CIPHER_CAST5 => BlockState::Cast5(Cast5::new_from_slice(key).ok()?),
        GCRY_CIPHER_BLOWFISH => BlockState::Blowfish(Blowfish::new_from_slice(key).ok()?),
        GCRY_CIPHER_TWOFISH | GCRY_CIPHER_TWOFISH128 => {
            BlockState::Twofish(Twofish::new_from_slice(key).ok()?)
        }
        GCRY_CIPHER_SERPENT128 | GCRY_CIPHER_SERPENT192 | GCRY_CIPHER_SERPENT256 => {
            BlockState::Serpent(make_serpent(key)?)
        }
        GCRY_CIPHER_CAMELLIA128 | GCRY_CIPHER_CAMELLIA192 | GCRY_CIPHER_CAMELLIA256 => {
            make_camellia(key)?
        }
        GCRY_CIPHER_IDEA => BlockState::Idea(Idea::new_from_slice(key).ok()?),
        GCRY_CIPHER_RFC2268_40 | GCRY_CIPHER_RFC2268_128 => {
            BlockState::Rc2(Rc2::new_with_eff_key_len(key, key.len() * 8))
        }
        GCRY_CIPHER_SEED => BlockState::Seed(SEED::new_from_slice(key).ok()?),
        GCRY_CIPHER_GOST28147 | GCRY_CIPHER_GOST28147_MESH => {
            let key: &[u8; 32] = key.try_into().ok()?;
            BlockState::Gost(GostBlock::new(
                key,
                gost_sbox,
                algo == GCRY_CIPHER_GOST28147_MESH && gost_keymeshing,
            ))
        }
        GCRY_CIPHER_SM4 => BlockState::Sm4(Sm4::new_from_slice(key).ok()?),
        _ => return None,
    })
}

fn enc05<C>(cipher: &C, input: &[u8]) -> Option<Vec<u8>>
where
    C: BlockCipherEncrypt + KeyInit05,
{
    let mut block = Block05::<C>::try_from(input).ok()?.clone();
    cipher.encrypt_block(&mut block);
    Some(block.as_slice().to_vec())
}

fn dec05<C>(cipher: &C, input: &[u8]) -> Option<Vec<u8>>
where
    C: BlockCipherDecrypt + KeyInit05,
{
    let mut block = Block05::<C>::try_from(input).ok()?.clone();
    cipher.decrypt_block(&mut block);
    Some(block.as_slice().to_vec())
}

fn make_camellia(key: &[u8]) -> Option<BlockState> {
    match key.len() {
        16 => Some(BlockState::Camellia128(
            Camellia128::new_from_slice(key).ok()?,
        )),
        24 => Some(BlockState::Camellia192(
            Camellia192::new_from_slice(key).ok()?,
        )),
        32 => Some(BlockState::Camellia256(
            Camellia256::new_from_slice(key).ok()?,
        )),
        _ => None,
    }
}

fn make_serpent(key: &[u8]) -> Option<Serpent> {
    if key.len() > 32 {
        return None;
    }
    let mut prepared = [0u8; 32];
    let whole_len = key.len() / 4 * 4;
    prepared[..whole_len].copy_from_slice(&key[..whole_len]);
    if whole_len < prepared.len() {
        prepared[whole_len] = 1;
    }
    Serpent::new_from_slice(&prepared).ok()
}

fn enc04<C>(cipher: &C, input: &[u8]) -> Option<Vec<u8>>
where
    C: BlockEncrypt04 + KeyInit04,
{
    let mut block = GenericArray::clone_from_slice(input);
    cipher.encrypt_block(&mut block);
    Some(block.to_vec())
}

fn dec04<C>(cipher: &C, input: &[u8]) -> Option<Vec<u8>>
where
    C: BlockDecrypt04 + KeyInit04,
{
    let mut block = GenericArray::clone_from_slice(input);
    cipher.decrypt_block(&mut block);
    Some(block.to_vec())
}

fn valid_mode_for_algo(algo: c_int, mode: c_int) -> bool {
    match mode {
        MODE_STREAM => matches!(
            algo,
            GCRY_CIPHER_ARCFOUR
                | GCRY_CIPHER_SALSA20
                | GCRY_CIPHER_SALSA20R12
                | GCRY_CIPHER_CHACHA20
        ),
        MODE_POLY1305 => algo == GCRY_CIPHER_CHACHA20,
        MODE_AESWRAP => matches!(
            algo,
            GCRY_CIPHER_AES | GCRY_CIPHER_AES192 | GCRY_CIPHER_AES256
        ),
        MODE_CCM | MODE_GCM | MODE_OCB | MODE_XTS | MODE_SIV | MODE_GCM_SIV => {
            block_len_for_algo(algo) == Some(16)
        }
        MODE_ECB | MODE_CFB | MODE_CBC | MODE_OFB | MODE_CTR | MODE_CFB8 | MODE_EAX => {
            is_block_cipher_algo(algo)
        }
        _ => false,
    }
}

fn is_block_cipher_algo(algo: c_int) -> bool {
    block_len_for_algo(algo).is_some() && !is_stream_cipher_algo(algo)
}

fn is_stream_cipher_algo(algo: c_int) -> bool {
    matches!(
        algo,
        GCRY_CIPHER_ARCFOUR | GCRY_CIPHER_SALSA20 | GCRY_CIPHER_SALSA20R12 | GCRY_CIPHER_CHACHA20
    )
}

fn block_len_for_algo(algo: c_int) -> Option<usize> {
    Some(match algo {
        GCRY_CIPHER_ARCFOUR
        | GCRY_CIPHER_SALSA20
        | GCRY_CIPHER_SALSA20R12
        | GCRY_CIPHER_CHACHA20 => 1,
        GCRY_CIPHER_IDEA
        | GCRY_CIPHER_3DES
        | GCRY_CIPHER_CAST5
        | GCRY_CIPHER_BLOWFISH
        | GCRY_CIPHER_DES
        | GCRY_CIPHER_RFC2268_40
        | GCRY_CIPHER_RFC2268_128
        | GCRY_CIPHER_GOST28147
        | GCRY_CIPHER_GOST28147_MESH => 8,
        GCRY_CIPHER_AES
        | GCRY_CIPHER_AES192
        | GCRY_CIPHER_AES256
        | GCRY_CIPHER_TWOFISH
        | GCRY_CIPHER_TWOFISH128
        | GCRY_CIPHER_SERPENT128
        | GCRY_CIPHER_SERPENT192
        | GCRY_CIPHER_SERPENT256
        | GCRY_CIPHER_SEED
        | GCRY_CIPHER_CAMELLIA128
        | GCRY_CIPHER_CAMELLIA192
        | GCRY_CIPHER_CAMELLIA256
        | GCRY_CIPHER_SM4 => 16,
        _ => return None,
    })
}

fn valid_key_len(algo: c_int, len: usize) -> bool {
    match algo {
        GCRY_CIPHER_AES | GCRY_CIPHER_AES192 | GCRY_CIPHER_AES256 => {
            matches!(len, 16 | 24 | 32)
        }
        GCRY_CIPHER_TWOFISH | GCRY_CIPHER_TWOFISH128 => matches!(len, 16 | 32),
        GCRY_CIPHER_SERPENT128 | GCRY_CIPHER_SERPENT192 | GCRY_CIPHER_SERPENT256 => len <= 32,
        GCRY_CIPHER_CAMELLIA128 | GCRY_CIPHER_CAMELLIA192 | GCRY_CIPHER_CAMELLIA256 => {
            matches!(len, 16 | 24 | 32)
        }
        GCRY_CIPHER_RFC2268_40 | GCRY_CIPHER_RFC2268_128 => (5..=128).contains(&len),
        GCRY_CIPHER_3DES => len == 24,
        GCRY_CIPHER_DES => len == 8,
        GCRY_CIPHER_BLOWFISH => (1..=72).contains(&len),
        GCRY_CIPHER_SEED | GCRY_CIPHER_SM4 | GCRY_CIPHER_CAST5 | GCRY_CIPHER_IDEA => len == 16,
        GCRY_CIPHER_GOST28147 | GCRY_CIPHER_GOST28147_MESH => len == 32,
        GCRY_CIPHER_SALSA20 | GCRY_CIPHER_SALSA20R12 | GCRY_CIPHER_CHACHA20 => {
            matches!(len, 16 | 32)
        }
        GCRY_CIPHER_ARCFOUR => len >= 5,
        _ => false,
    }
}

fn invalid_open_flags(flags: c_uint) -> bool {
    flags & !SUPPORTED_FLAGS != 0 || flags & FLAG_CBC_CTS != 0 && flags & FLAG_CBC_MAC != 0
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn xor_in_place(out: &mut [u8; 16], input: &[u8]) {
    for (a, b) in out.iter_mut().zip(input) {
        *a ^= *b;
    }
}

fn ocb_l_star(ctx: &CipherContext) -> Result<[u8; 16], u32> {
    let block = ctx
        .block_encrypt(&[0u8; 16])
        .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

fn ocb_l_dollar(ctx: &CipherContext) -> Result<[u8; 16], u32> {
    Ok(ocb_double(ocb_l_star(ctx)?))
}

fn ocb_l_for_index(ctx: &CipherContext, index: usize) -> Result<[u8; 16], u32> {
    let mut value = ocb_double(ocb_l_dollar(ctx)?);
    for _ in 0..index.trailing_zeros() {
        value = ocb_double(value);
    }
    Ok(value)
}

fn ocb_double(input: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (input[i] << 1) | carry;
        carry = input[i] >> 7;
    }
    if carry != 0 {
        out[15] ^= 0x87;
    }
    out
}

fn ocb_nonce_offset(ctx: &CipherContext, tag_len: usize) -> Result<[u8; 16], u32> {
    let nonce = &ctx.iv;
    if nonce.len() > 15 {
        return Err(err(error::GPG_ERR_INV_LENGTH));
    }
    let mut block = [0u8; 16];
    block[16 - nonce.len()..].copy_from_slice(nonce);
    block[15 - nonce.len()] = 1;
    let tag_bits = ((tag_len.min(16) * 8) % 128) as u8;
    block[0] = (block[0] & 1) | (tag_bits << 1);
    let bottom = (block[15] & 0x3f) as usize;
    block[15] &= 0xc0;
    let ktop = ctx
        .block_encrypt(&block)
        .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
    let mut stretch = [0u8; 24];
    stretch[..16].copy_from_slice(&ktop);
    for i in 0..8 {
        stretch[16 + i] = ktop[i] ^ ktop[i + 1];
    }
    Ok(bit_slice_128(&stretch, bottom))
}

fn bit_slice_128(input: &[u8], start_bit: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..128 {
        if get_bit(input, start_bit + i) {
            set_bit(&mut out, i);
        }
    }
    out
}

fn get_bit(input: &[u8], bit: usize) -> bool {
    ((input[bit / 8] >> (7 - (bit % 8))) & 1) != 0
}

fn set_bit(out: &mut [u8], bit: usize) {
    out[bit / 8] |= 1 << (7 - (bit % 8));
}

fn ocb_hash(ctx: &CipherContext, aad: &[u8]) -> Result<[u8; 16], u32> {
    let mut offset = [0u8; 16];
    let mut sum = [0u8; 16];
    let full_len = aad.len() / 16 * 16;
    for (idx, block) in aad[..full_len].chunks_exact(16).enumerate() {
        let l = ocb_l_for_index(ctx, idx + 1)?;
        xor_in_place(&mut offset, &l);
        let encrypted = ctx
            .block_encrypt(&xor(block, &offset))
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        xor_in_place(&mut sum, &encrypted);
    }
    let partial = &aad[full_len..];
    if !partial.is_empty() {
        let l_star = ocb_l_star(ctx)?;
        xor_in_place(&mut offset, &l_star);
        let mut padded = [0u8; 16];
        padded[..partial.len()].copy_from_slice(partial);
        padded[partial.len()] = 0x80;
        let encrypted = ctx
            .block_encrypt(&xor(&padded, &offset))
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        xor_in_place(&mut sum, &encrypted);
    }
    Ok(sum)
}

fn inc_be(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

fn inc_be_tail(counter: &mut [u8], tail_len: usize) {
    let start = counter.len().saturating_sub(tail_len);
    inc_be(&mut counter[start..]);
}

fn inc32(block: &mut [u8; 16]) {
    let mut low = u32::from_be_bytes(block[12..].try_into().unwrap());
    low = low.wrapping_add(1);
    block[12..].copy_from_slice(&low.to_be_bytes());
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn valid_gcm_tag_len(len: usize) -> bool {
    matches!(len, 4 | 8 | 12..=16)
}

fn valid_ccm_tag_len(len: usize) -> bool {
    matches!(len, 4 | 6 | 8 | 10 | 12 | 14 | 16)
}

fn valid_gcm_gettag_len(len: usize) -> bool {
    len == 4 || len == 8 || len >= 12
}

fn gcm_j0(h: u128, iv: &[u8]) -> u128 {
    if iv.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        u128::from_be_bytes(j0)
    } else {
        let mut y = mac::ghash_blocks(h, 0, iv);
        let mut lengths = [0u8; 16];
        lengths[8..].copy_from_slice(&(iv.len() as u64 * 8).to_be_bytes());
        y = mac::ghash_block(h, y, &lengths);
        y
    }
}

fn ghash_aad_cipher(h: u128, aad: &[u8], ciphertext: &[u8]) -> u128 {
    let mut y = mac::ghash_blocks(h, 0, aad);
    y = mac::ghash_blocks(h, y, ciphertext);
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64 * 8).to_be_bytes());
    mac::ghash_block(h, y, &lengths)
}

fn pad16(data: &mut Vec<u8>) {
    let rem = data.len() % 16;
    if rem != 0 {
        data.resize(data.len() + 16 - rem, 0);
    }
}

fn encode_be_len(out: &mut [u8], mut value: u64) {
    for byte in out.iter_mut().rev() {
        *byte = value as u8;
        value >>= 8;
    }
}

fn encode_ccm_aad_len(out: &mut Vec<u8>, len: usize) {
    if len < 0xff00 {
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= u32::MAX as usize {
        out.extend_from_slice(&0xfffeu16.to_be_bytes());
        out.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&0xffffu16.to_be_bytes());
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
}

fn ccm_counter_block(nonce: &[u8], l: usize, counter: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = (l - 1) as u8;
    out[1..1 + nonce.len()].copy_from_slice(nonce);
    encode_be_len(&mut out[16 - l..], counter);
    out
}

fn eax_omac(ctx: &CipherContext, domain: u8, data: &[u8]) -> Result<Vec<u8>, u32> {
    let n = ctx.block_len;
    let l = ctx
        .block_encrypt(&vec![0u8; n])
        .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
    let k1 = cmac_double(&l);
    let k2 = cmac_double(&k1);
    let mut msg = vec![0u8; n + data.len()];
    msg[n - 1] = domain;
    msg[n..].copy_from_slice(data);
    let complete = !msg.is_empty() && msg.len() % n == 0;
    let pre_blocks = if complete {
        msg.len() / n - 1
    } else {
        msg.len() / n
    };
    let mut state = vec![0u8; n];
    for block in msg[..pre_blocks * n].chunks_exact(n) {
        state = ctx
            .block_encrypt(&xor(&state, block))
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
    }
    let mut last = vec![0u8; n];
    if complete {
        last.copy_from_slice(&msg[msg.len() - n..]);
        last = xor(&last, &k1);
    } else {
        let rem = &msg[pre_blocks * n..];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] = 0x80;
        last = xor(&last, &k2);
    }
    ctx.block_encrypt(&xor(&state, &last))
        .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))
}

fn cmac_with_key(algo: c_int, key: &[u8], data: &[u8]) -> Result<[u8; 16], u32> {
    let block = make_block(algo, key, mac::gost28147_default_cipher_sbox(), false)
        .ok_or_else(|| err(error::GPG_ERR_INV_KEYLEN))?;
    let l = block
        .encrypt(&[0u8; 16])
        .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
    let k1 = cmac_double(&l);
    let k2 = cmac_double(&k1);
    let complete = !data.is_empty() && data.len() % 16 == 0;
    let pre_blocks = if complete {
        data.len() / 16 - 1
    } else {
        data.len() / 16
    };
    let mut state = vec![0u8; 16];
    for chunk in data[..pre_blocks * 16].chunks_exact(16) {
        state = block
            .encrypt(&xor(&state, chunk))
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
    }
    let mut last = vec![0u8; 16];
    if complete {
        last.copy_from_slice(&data[data.len() - 16..]);
        last = xor(&last, &k1);
    } else {
        let rem = &data[pre_blocks * 16..];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] = 0x80;
        last = xor(&last, &k2);
    }
    let tag = block
        .encrypt(&xor(&state, &last))
        .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    Ok(out)
}

fn aes_siv_s2v(
    algo: c_int,
    mac_key: &[u8],
    aad_parts: &[Vec<u8>],
    plaintext: &[u8],
) -> Result<[u8; 16], u32> {
    let mut d = cmac_with_key(algo, mac_key, &[0u8; 16])?;
    for part in aad_parts {
        d = vec_to_block(cmac_double(&d));
        let mac = cmac_with_key(algo, mac_key, part)?;
        xor_in_place(&mut d, &mac);
    }
    if plaintext.len() >= 16 {
        let mut data = plaintext.to_vec();
        let start = data.len() - 16;
        for i in 0..16 {
            data[start + i] ^= d[i];
        }
        cmac_with_key(algo, mac_key, &data)
    } else {
        let mut padded = [0u8; 16];
        padded[..plaintext.len()].copy_from_slice(plaintext);
        padded[plaintext.len()] = 0x80;
        d = vec_to_block(cmac_double(&d));
        xor_in_place(&mut d, &padded);
        cmac_with_key(algo, mac_key, &d)
    }
}

fn aes_siv_ctr(algo: c_int, ctr_key: &[u8], tag: &[u8], input: &[u8]) -> Result<Vec<u8>, u32> {
    if tag.len() != 16 {
        return Err(err(error::GPG_ERR_INV_LENGTH));
    }
    let block = make_block(algo, ctr_key, mac::gost28147_default_cipher_sbox(), false)
        .ok_or_else(|| err(error::GPG_ERR_INV_KEYLEN))?;
    let mut ctr = tag.to_vec();
    ctr[8] &= 0x7f;
    ctr[12] &= 0x7f;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(16) {
        let ks = block
            .encrypt(&ctr)
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        out.extend(xor(chunk, &ks[..chunk.len()]));
        inc_be(&mut ctr);
    }
    Ok(out)
}

fn gcm_siv_keys(algo: c_int, key: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>), u32> {
    if nonce.len() != 12 {
        return Err(err(error::GPG_ERR_INV_LENGTH));
    }
    let block = make_block(algo, key, mac::gost28147_default_cipher_sbox(), false)
        .ok_or_else(|| err(error::GPG_ERR_INV_KEYLEN))?;
    let enc_key_len = key.len();
    let mut material = Vec::with_capacity(16 + enc_key_len);
    let blocks = (16 + enc_key_len).div_ceil(8);
    for counter in 0..blocks {
        let mut input = [0u8; 16];
        input[..4].copy_from_slice(&(counter as u32).to_le_bytes());
        input[4..].copy_from_slice(nonce);
        let out = block
            .encrypt(&input)
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        material.extend_from_slice(&out[..8]);
    }
    Ok((
        material[..16].to_vec(),
        material[16..16 + enc_key_len].to_vec(),
    ))
}

fn gcm_siv_tag(
    algo: c_int,
    auth_key: &[u8],
    enc_key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<[u8; 16], u32> {
    let mut data = Vec::new();
    data.extend_from_slice(aad);
    pad16(&mut data);
    data.extend_from_slice(plaintext);
    pad16(&mut data);
    data.extend_from_slice(&((aad.len() as u64) * 8).to_le_bytes());
    data.extend_from_slice(&((plaintext.len() as u64) * 8).to_le_bytes());
    let mut s = polyval(auth_key, &data);
    for i in 0..12 {
        s[i] ^= nonce[i];
    }
    s[15] &= 0x7f;
    let block = make_block(algo, enc_key, mac::gost28147_default_cipher_sbox(), false)
        .ok_or_else(|| err(error::GPG_ERR_INV_KEYLEN))?;
    let tag = block
        .encrypt(&s)
        .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    Ok(out)
}

fn gcm_siv_ctr(algo: c_int, enc_key: &[u8], tag: &[u8], input: &[u8]) -> Result<Vec<u8>, u32> {
    if tag.len() != 16 {
        return Err(err(error::GPG_ERR_INV_LENGTH));
    }
    let block = make_block(algo, enc_key, mac::gost28147_default_cipher_sbox(), false)
        .ok_or_else(|| err(error::GPG_ERR_INV_KEYLEN))?;
    let mut ctr = [0u8; 16];
    ctr.copy_from_slice(tag);
    ctr[15] |= 0x80;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(16) {
        let ks = block
            .encrypt(&ctr)
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        out.extend(xor(chunk, &ks[..chunk.len()]));
        inc_le32_first(&mut ctr);
    }
    Ok(out)
}

fn polyval(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut h_block = [0u8; 16];
    h_block.copy_from_slice(key);
    h_block.reverse();
    let mut h = u128::from_be_bytes(h_block);
    h = if h & 1 == 0 {
        h >> 1
    } else {
        (h >> 1) ^ 0xe1000000000000000000000000000000
    };
    let mut y = 0u128;
    for block in data.chunks_exact(16) {
        let mut swapped = [0u8; 16];
        swapped.copy_from_slice(block);
        swapped.reverse();
        y = mac::ghash_block(h, y, &swapped);
    }
    let mut out = y.to_be_bytes();
    out.reverse();
    out
}

fn inc_le32_first(block: &mut [u8; 16]) {
    let mut low = u32::from_le_bytes(block[..4].try_into().unwrap());
    low = low.wrapping_add(1);
    block[..4].copy_from_slice(&low.to_le_bytes());
}

fn vec_to_block(input: Vec<u8>) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&input);
    out
}

fn cmac_double(input: &[u8]) -> Vec<u8> {
    let rb = if input.len() == 8 { 0x1b } else { 0x87 };
    let carry = input[0] & 0x80 != 0;
    let mut out = vec![0u8; input.len()];
    let mut shifted = 0u8;
    for i in (0..input.len()).rev() {
        out[i] = (input[i] << 1) | shifted;
        shifted = input[i] >> 7;
    }
    if carry {
        let last = out.len() - 1;
        out[last] ^= rb;
    }
    out
}

fn xts_mul_alpha(tweak: &mut [u8]) {
    let mut carry = 0u8;
    for byte in tweak.iter_mut() {
        let next = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

fn aes_kw_wrap(key: &[u8], input: &[u8]) -> Result<Vec<u8>, u32> {
    if input.len() < 16 || input.len() % 8 != 0 {
        return Err(err(error::GPG_ERR_INV_LENGTH));
    }
    let n = input.len() / 8;
    let mut a = [0xa6u8; 8];
    let mut r: Vec<[u8; 8]> = input
        .chunks_exact(8)
        .map(|c| c.try_into().unwrap())
        .collect();
    for j in 0..6 {
        for i in 0..n {
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(&r[i]);
            let b = mac::aes_encrypt_block(key, &block)
                .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
            a.copy_from_slice(&b[..8]);
            let t = (n * j + i + 1) as u64;
            for (dst, src) in a.iter_mut().zip(t.to_be_bytes()) {
                *dst ^= src;
            }
            r[i].copy_from_slice(&b[8..]);
        }
    }
    let mut out = Vec::with_capacity(input.len() + 8);
    out.extend_from_slice(&a);
    for block in r {
        out.extend_from_slice(&block);
    }
    Ok(out)
}

fn aes_kw_unwrap(key: &[u8], input: &[u8]) -> Result<Vec<u8>, u32> {
    let n = input.len() / 8 - 1;
    let mut a: [u8; 8] = input[..8].try_into().unwrap();
    let mut r: Vec<[u8; 8]> = input[8..]
        .chunks_exact(8)
        .map(|c| c.try_into().unwrap())
        .collect();
    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = (n * j + i + 1) as u64;
            let mut aa = a;
            for (dst, src) in aa.iter_mut().zip(t.to_be_bytes()) {
                *dst ^= src;
            }
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&aa);
            block[8..].copy_from_slice(&r[i]);
            let b = mac::aes_decrypt_block(key, &block)
                .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
            a.copy_from_slice(&b[..8]);
            r[i].copy_from_slice(&b[8..]);
        }
    }
    if a != [0xa6u8; 8] {
        return Err(err(error::GPG_ERR_CHECKSUM));
    }
    let mut out = Vec::with_capacity(n * 8);
    for block in r {
        out.extend_from_slice(&block);
    }
    Ok(out)
}

fn aes_kwp_wrap(key: &[u8], input: &[u8]) -> Result<Vec<u8>, u32> {
    let mli = input.len() as u32;
    let mut padded = input.to_vec();
    let pad = (8 - padded.len() % 8) % 8;
    padded.resize(padded.len() + pad, 0);
    let mut aiv = [0u8; 8];
    aiv[..4].copy_from_slice(&[0xa6, 0x59, 0x59, 0xa6]);
    aiv[4..].copy_from_slice(&mli.to_be_bytes());
    if padded.len() == 8 {
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&aiv);
        block[8..].copy_from_slice(&padded);
        return Ok(mac::aes_encrypt_block(key, &block)
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?
            .to_vec());
    }
    let mut wrapped = aes_kw_wrap_with_aiv(key, &padded, aiv)?;
    Ok(std::mem::take(&mut wrapped))
}

fn aes_kw_wrap_with_aiv(key: &[u8], input: &[u8], mut a: [u8; 8]) -> Result<Vec<u8>, u32> {
    let n = input.len() / 8;
    let mut r: Vec<[u8; 8]> = input
        .chunks_exact(8)
        .map(|c| c.try_into().unwrap())
        .collect();
    for j in 0..6 {
        for i in 0..n {
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(&r[i]);
            let b = mac::aes_encrypt_block(key, &block)
                .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
            a.copy_from_slice(&b[..8]);
            let t = (n * j + i + 1) as u64;
            for (dst, src) in a.iter_mut().zip(t.to_be_bytes()) {
                *dst ^= src;
            }
            r[i].copy_from_slice(&b[8..]);
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(&a);
    for block in r {
        out.extend_from_slice(&block);
    }
    Ok(out)
}

fn aes_kwp_unwrap(key: &[u8], input: &[u8]) -> Result<(Vec<u8>, [u8; 4]), u32> {
    let n = input.len() / 8 - 1;
    let mut a: [u8; 8] = input[..8].try_into().unwrap();
    let mut r: Vec<[u8; 8]> = input[8..]
        .chunks_exact(8)
        .map(|c| c.try_into().unwrap())
        .collect();
    if n == 1 {
        let b = mac::aes_decrypt_block(key, input.try_into().unwrap())
            .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
        a.copy_from_slice(&b[..8]);
        r[0].copy_from_slice(&b[8..]);
    } else {
        for j in (0..6).rev() {
            for i in (0..n).rev() {
                let t = (n * j + i + 1) as u64;
                let mut aa = a;
                for (dst, src) in aa.iter_mut().zip(t.to_be_bytes()) {
                    *dst ^= src;
                }
                let mut block = [0u8; 16];
                block[..8].copy_from_slice(&aa);
                block[8..].copy_from_slice(&r[i]);
                let b = mac::aes_decrypt_block(key, &block)
                    .ok_or_else(|| err(error::GPG_ERR_CIPHER_ALGO))?;
                a.copy_from_slice(&b[..8]);
                r[i].copy_from_slice(&b[8..]);
            }
        }
    }
    if a[..4] != [0xa6, 0x59, 0x59, 0xa6] {
        return Err(err(error::GPG_ERR_CHECKSUM));
    }
    let mli = u32::from_be_bytes(a[4..].try_into().unwrap()) as usize;
    let mut out = Vec::new();
    for block in r {
        out.extend_from_slice(&block);
    }
    if mli > out.len() || out[mli..].iter().any(|&b| b != 0) {
        return Err(err(error::GPG_ERR_CHECKSUM));
    }
    out.truncate(mli);
    Ok((out, a[4..].try_into().unwrap()))
}

#[derive(Clone)]
struct ArcFour {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl ArcFour {
    fn new(key: &[u8]) -> Option<Self> {
        if key.is_empty() {
            return None;
        }
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Some(Self { s, i: 0, j: 0 })
    }

    fn apply(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[self.s[self.i as usize].wrapping_add(self.s[self.j as usize]) as usize];
            out.push(b ^ k);
        }
        out
    }
}

fn salsa_xor_at(key: &[u8], nonce: &[u8], rounds: usize, offset: usize, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let nonce8 = if nonce.len() >= 8 {
        &nonce[..8]
    } else {
        &[0u8; 8][..]
    };
    let mut counter = (offset / 64) as u64;
    let mut block_pos = offset % 64;
    let mut block = salsa_block(key, nonce8, counter, rounds);
    for &byte in input {
        if block_pos == 64 {
            counter = counter.wrapping_add(1);
            block = salsa_block(key, nonce8, counter, rounds);
            block_pos = 0;
        }
        out.push(byte ^ block[block_pos]);
        block_pos += 1;
    }
    out
}

fn salsa_block(key: &[u8], nonce: &[u8], counter: u64, rounds: usize) -> [u8; 64] {
    let constants = if key.len() == 32 {
        b"expand 32-byte k"
    } else {
        b"expand 16-byte k"
    };
    let mut state = [0u32; 16];
    state[0] = u32::from_le_bytes(constants[0..4].try_into().unwrap());
    state[5] = u32::from_le_bytes(constants[4..8].try_into().unwrap());
    state[10] = u32::from_le_bytes(constants[8..12].try_into().unwrap());
    state[15] = u32::from_le_bytes(constants[12..16].try_into().unwrap());
    for i in 0..4 {
        state[1 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        let tail = if key.len() == 32 { 16 } else { 0 };
        state[11 + i] = u32::from_le_bytes(key[tail + i * 4..tail + i * 4 + 4].try_into().unwrap());
    }
    state[6] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    state[7] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    state[8] = counter as u32;
    state[9] = (counter >> 32) as u32;
    let mut x = state;
    for _ in 0..rounds / 2 {
        salsa_qr(&mut x, 0, 4, 8, 12);
        salsa_qr(&mut x, 5, 9, 13, 1);
        salsa_qr(&mut x, 10, 14, 2, 6);
        salsa_qr(&mut x, 15, 3, 7, 11);
        salsa_qr(&mut x, 0, 1, 2, 3);
        salsa_qr(&mut x, 5, 6, 7, 4);
        salsa_qr(&mut x, 10, 11, 8, 9);
        salsa_qr(&mut x, 15, 12, 13, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&x[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

fn salsa_qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
    x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}

fn chacha20_xor(key: &[u8], nonce: &[u8], initial_counter: u32, input: &[u8]) -> Vec<u8> {
    chacha20_xor_at(key, nonce, initial_counter, 0, input)
}

fn chacha20_xor_at(
    key: &[u8],
    nonce: &[u8],
    initial_counter: u32,
    offset: usize,
    input: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut counter = initial_counter as u64 + (offset / 64) as u64;
    let mut block_pos = offset % 64;
    let mut block = chacha_block(key, nonce, counter);
    for &byte in input {
        if block_pos == 64 {
            counter = counter.wrapping_add(1);
            block = chacha_block(key, nonce, counter);
            block_pos = 0;
        }
        out.push(byte ^ block[block_pos]);
        block_pos += 1;
    }
    out
}

fn chacha_block(key: &[u8], nonce: &[u8], counter: u64) -> [u8; 64] {
    let constants = if key.len() == 32 {
        b"expand 32-byte k"
    } else {
        b"expand 16-byte k"
    };
    let mut state = [0u32; 16];
    for i in 0..4 {
        state[i] = u32::from_le_bytes(constants[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 0..4 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        let tail = if key.len() == 32 { 16 } else { 0 };
        state[8 + i] = u32::from_le_bytes(key[tail + i * 4..tail + i * 4 + 4].try_into().unwrap());
    }
    let counter_lo = counter as u32;
    let counter_hi = (counter >> 32) as u32;
    if nonce.len() == 16 {
        let base = u32::from_le_bytes(nonce[0..4].try_into().unwrap()) as u64 + counter;
        state[12] = base as u32;
        state[13] =
            u32::from_le_bytes(nonce[4..8].try_into().unwrap()).wrapping_add((base >> 32) as u32);
        state[14] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
        state[15] = u32::from_le_bytes(nonce[12..16].try_into().unwrap());
    } else if nonce.len() == 12 {
        state[12] = counter_lo;
        state[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
        state[13] = state[13].wrapping_add(counter_hi);
        state[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
        state[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
    } else {
        state[12] = counter_lo;
        state[13] = counter_hi;
        let n = if nonce.len() >= 8 {
            &nonce[..8]
        } else {
            &[0u8; 8][..]
        };
        state[14] = u32::from_le_bytes(n[0..4].try_into().unwrap());
        state[15] = u32::from_le_bytes(n[4..8].try_into().unwrap());
    }
    let mut x = state;
    for _ in 0..10 {
        chacha_qr(&mut x, 0, 4, 8, 12);
        chacha_qr(&mut x, 1, 5, 9, 13);
        chacha_qr(&mut x, 2, 6, 10, 14);
        chacha_qr(&mut x, 3, 7, 11, 15);
        chacha_qr(&mut x, 0, 5, 10, 15);
        chacha_qr(&mut x, 1, 6, 11, 12);
        chacha_qr(&mut x, 2, 7, 8, 13);
        chacha_qr(&mut x, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&x[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

fn chacha_qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}
