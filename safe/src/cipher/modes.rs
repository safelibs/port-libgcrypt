use std::convert::TryInto;
use std::ffi::{c_int, c_uint, c_void, CStr};
use std::slice;

use aes::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, StreamCipher,
};
use aes::soft::{Aes128 as SoftAes128, Aes192 as SoftAes192, Aes256 as SoftAes256};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm_siv::{
    AeadInOut as _, Aes128GcmSiv, Aes256GcmSiv, KeyInit as GcmSivKeyInit, Nonce as GcmSivNonce,
    Tag as GcmSivTag,
};
use aes_kw::{KwpAes128, KwpAes192, KwpAes256};
use aes_siv::siv::{Aes128Siv, Aes256Siv, Siv as GenericSiv};
use blowfish::Blowfish;
use camellia::{Camellia128, Camellia192, Camellia256};
use cast5::Cast5;
use cmac::Cmac;
use des::{Des, TdesEde3};
use ghash::{universal_hash::UniversalHash, GHash};
use idea::Idea;
use poly1305::Poly1305;
use polyval::Polyval;
use rc2::Rc2;
use rc4::Rc4;
use serpent::Serpent;
use sm4::Sm4;
use subtle::ConstantTimeEq;
use twofish::Twofish;

use super::gcry_cipher_hd_t;
use super::registry::{
    algorithm_from_id, algorithm_is_locally_supported, mode_from_oid_str, mode_supported,
    mode_supported_for_algorithm, CipherAlgorithm, GCRYCTL_CFB_SYNC, GCRYCTL_FINALIZE,
    GCRYCTL_GET_KEYLEN, GCRYCTL_GET_TAGLEN, GCRYCTL_RESET, GCRYCTL_SET_ALLOW_WEAK_KEY,
    GCRYCTL_SET_CBC_CTS, GCRYCTL_SET_CBC_MAC, GCRYCTL_SET_CCM_LENGTHS,
    GCRYCTL_SET_DECRYPTION_TAG, GCRYCTL_SET_TAGLEN, GCRY_CIPHER_CBC_CTS,
    GCRY_CIPHER_CBC_MAC, GCRY_CIPHER_ENABLE_SYNC, GCRY_CIPHER_EXTENDED, GCRY_CIPHER_MODE_AESWRAP,
    GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_MODE_CCM, GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_MODE_CFB8,
    GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_MODE_EAX, GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_MODE_GCM,
    GCRY_CIPHER_MODE_GCM_SIV, GCRY_CIPHER_MODE_NONE, GCRY_CIPHER_MODE_OCB,
    GCRY_CIPHER_MODE_OFB, GCRY_CIPHER_MODE_POLY1305, GCRY_CIPHER_MODE_SIV,
    GCRY_CIPHER_MODE_STREAM, GCRY_CIPHER_MODE_XTS,
};
use crate::{error, global};

const BLOCK_LEN: usize = 16;
const OCB_PRECOMP_LEVELS: usize = 64;

type Aes192Siv = GenericSiv<Aes192, Cmac<Aes192>>;

type Block = [u8; BLOCK_LEN];

fn err(code: u32) -> u32 {
    error::gcry_error_from_code(code)
}

fn copy_input(
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
) -> Result<Vec<u8>, u32> {
    if input.is_null() {
        if outsize == 0 {
            return Ok(Vec::new());
        }
        if out.is_null() {
            return Err(err(error::GPG_ERR_INV_ARG));
        }
        let out_slice = unsafe { slice::from_raw_parts(out.cast::<u8>(), outsize) };
        return Ok(out_slice.to_vec());
    }

    if inlen == 0 {
        return Ok(Vec::new());
    }

    let in_ptr = input.cast::<u8>();
    if out.is_null() || outsize == 0 {
        let in_slice = unsafe { slice::from_raw_parts(in_ptr, inlen) };
        return Ok(in_slice.to_vec());
    }

    let out_start = out as usize;
    let out_end = out_start.saturating_add(outsize);
    let in_start = in_ptr as usize;
    let in_end = in_start.saturating_add(inlen);
    let overlaps = out_start < in_end && in_start < out_end;

    let in_slice = unsafe { slice::from_raw_parts(in_ptr, inlen) };
    if overlaps {
        Ok(in_slice.to_vec())
    } else {
        Ok(in_slice.to_vec())
    }
}

fn out_slice<'a>(out: *mut c_void, outsize: usize) -> Result<&'a mut [u8], u32> {
    if outsize == 0 {
        return Ok(&mut []);
    }
    if out.is_null() {
        return Err(err(error::GPG_ERR_INV_ARG));
    }
    Ok(unsafe { slice::from_raw_parts_mut(out.cast::<u8>(), outsize) })
}

fn xor_block(a: &Block, b: &Block) -> Block {
    let mut out = [0u8; BLOCK_LEN];
    for idx in 0..BLOCK_LEN {
        out[idx] = a[idx] ^ b[idx];
    }
    out
}

fn xor_block_in_place(dst: &mut Block, src: &Block) {
    for idx in 0..BLOCK_LEN {
        dst[idx] ^= src[idx];
    }
}

fn xor_slice(out: &mut [u8], left: &[u8], right: &[u8]) {
    for idx in 0..out.len() {
        out[idx] = left[idx] ^ right[idx];
    }
}

fn pad_with_0x80(input: &[u8]) -> Block {
    let mut out = [0u8; BLOCK_LEN];
    out[..input.len()].copy_from_slice(input);
    if input.len() < BLOCK_LEN {
        out[input.len()] = 0x80;
    }
    out
}

fn inc_be(counter: &mut Block) {
    for byte in counter.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

fn inc32(counter: &mut Block) {
    for byte in counter[12..].iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

fn double_ocb(block: &mut Block) {
    let mut carry = 0u8;
    for byte in block.iter_mut().rev() {
        let next_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next_carry;
    }
    if carry != 0 {
        block[BLOCK_LEN - 1] ^= 0x87;
    }
}

fn xts_gfmul_by_a(block: &mut Block) {
    let mut lo = u64::from_le_bytes(block[0..8].try_into().unwrap());
    let mut hi = u64::from_le_bytes(block[8..16].try_into().unwrap());
    let carry = (hi >> 63) * 0x87;
    hi = (hi << 1) | (lo >> 63);
    lo = (lo << 1) ^ carry;
    block[0..8].copy_from_slice(&lo.to_le_bytes());
    block[8..16].copy_from_slice(&hi.to_le_bytes());
}

fn u64_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn ghash_finalize(aad: &[u8], ciphertext: &[u8], h: &Block) -> Block {
    let key = ghash::Key::from(*h);
    let mut ghash = GHash::new(&key);
    ghash.update_padded(aad);
    ghash.update_padded(ciphertext);
    let mut lens = [0u8; BLOCK_LEN];
    lens[..8].copy_from_slice(&u64_be((aad.len() as u64) * 8));
    lens[8..].copy_from_slice(&u64_be((ciphertext.len() as u64) * 8));
    ghash.update_padded(&lens);
    ghash.finalize().into()
}

fn gcm_valid_gettag_len(taglen: usize) -> bool {
    taglen >= 16 || matches!(taglen, 4 | 8 | 12 | 13 | 14 | 15)
}

fn gcm_valid_checktag_len(taglen: usize) -> bool {
    taglen >= 16 || matches!(taglen, 4 | 8 | 12 | 13 | 14 | 15)
}

fn be_len_bytes(value: usize, width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    let bytes = (value as u64).to_be_bytes();
    out.copy_from_slice(&bytes[bytes.len() - width..]);
    out
}

#[derive(Clone)]
enum AesCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
    Aes128Soft(SoftAes128),
    Aes192Soft(SoftAes192),
    Aes256Soft(SoftAes256),
    Camellia128(Camellia128),
    Camellia192(Camellia192),
    Camellia256(Camellia256),
    Serpent(Serpent),
    Sm4(Sm4),
    Twofish(Twofish),
}

impl AesCipher {
    fn force_soft_aes() -> bool {
        let disabled = &global::lock_runtime_state().disabled_hw_features;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            return disabled.contains("intel-aesni")
                || disabled.contains("intel-vaes-vpclmul")
                || disabled.contains("padlock-aes");
        }
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        {
            return disabled.contains("arm-aes") || disabled.contains("arm-pmull");
        }
        #[cfg(not(any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "arm",
            target_arch = "aarch64"
        )))]
        {
            false
        }
    }

    fn new(algo: CipherAlgorithm, key: &[u8]) -> Result<Self, u32> {
        let force_soft = Self::force_soft_aes();
        match algo {
            CipherAlgorithm::Aes128 | CipherAlgorithm::Aes192 | CipherAlgorithm::Aes256 => {
                match key.len() {
                    16 => {
                        if force_soft {
                            SoftAes128::new_from_slice(key)
                                .map(Self::Aes128Soft)
                                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))
                        } else {
                            Aes128::new_from_slice(key)
                                .map(Self::Aes128)
                                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))
                        }
                    }
                    24 => {
                        if force_soft {
                            SoftAes192::new_from_slice(key)
                                .map(Self::Aes192Soft)
                                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))
                        } else {
                            Aes192::new_from_slice(key)
                                .map(Self::Aes192)
                                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))
                        }
                    }
                    32 => {
                        if force_soft {
                            SoftAes256::new_from_slice(key)
                                .map(Self::Aes256Soft)
                                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))
                        } else {
                            Aes256::new_from_slice(key)
                                .map(Self::Aes256)
                                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))
                        }
                    }
                    _ => Err(err(error::GPG_ERR_INV_KEYLEN)),
                }
            }
            CipherAlgorithm::Camellia128 => Camellia128::new_from_slice(key)
                .map(Self::Camellia128)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            CipherAlgorithm::Camellia192 => Camellia192::new_from_slice(key)
                .map(Self::Camellia192)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            CipherAlgorithm::Camellia256 => Camellia256::new_from_slice(key)
                .map(Self::Camellia256)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            CipherAlgorithm::Sm4 => Sm4::new_from_slice(key)
                .map(Self::Sm4)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            CipherAlgorithm::Twofish | CipherAlgorithm::Twofish128 => Twofish::new_from_slice(key)
                .map(Self::Twofish)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            CipherAlgorithm::Serpent128
            | CipherAlgorithm::Serpent192
            | CipherAlgorithm::Serpent256 => Serpent::new_from_slice(key)
                .map(Self::Serpent)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            _ => Err(err(error::GPG_ERR_CIPHER_ALGO)),
        }
    }

    fn encrypt_block(&self, block: &mut Block) {
        let mut tmp = aes::Block::default();
        tmp.copy_from_slice(block);
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Aes192(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Aes256(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Aes128Soft(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Aes192Soft(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Aes256Soft(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Camellia128(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Camellia192(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Camellia256(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Serpent(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Sm4(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Twofish(cipher) => cipher.encrypt_block(&mut tmp),
        }
        block.copy_from_slice(&tmp);
    }

    fn decrypt_block(&self, block: &mut Block) {
        let mut tmp = aes::Block::default();
        tmp.copy_from_slice(block);
        match self {
            Self::Aes128(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Aes192(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Aes256(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Aes128Soft(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Aes192Soft(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Aes256Soft(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Camellia128(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Camellia192(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Camellia256(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Serpent(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Sm4(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Twofish(cipher) => cipher.decrypt_block(&mut tmp),
        }
        block.copy_from_slice(&tmp);
    }
}

#[derive(Clone)]
struct OcbKeyState {
    l_star: Block,
    l_dollar: Block,
    l_values: Vec<Block>,
}

impl OcbKeyState {
    fn new(cipher: &AesCipher) -> Self {
        let mut l_star = [0u8; BLOCK_LEN];
        cipher.encrypt_block(&mut l_star);

        let mut l_dollar = l_star;
        double_ocb(&mut l_dollar);

        let mut current = l_dollar;
        double_ocb(&mut current);
        let mut l_values = Vec::with_capacity(OCB_PRECOMP_LEVELS);
        l_values.push(current);
        for _ in 1..OCB_PRECOMP_LEVELS {
            let mut next = *l_values.last().unwrap();
            double_ocb(&mut next);
            l_values.push(next);
        }

        Self {
            l_star,
            l_dollar,
            l_values,
        }
    }

    fn l(&self, block_index: u64) -> &Block {
        let tz = block_index.trailing_zeros() as usize;
        &self.l_values[tz.min(self.l_values.len() - 1)]
    }

    fn offset0(&self, cipher: &AesCipher, tag_len: usize, nonce: &[u8]) -> Result<Block, u32> {
        if nonce.len() < 8 || nonce.len() > 15 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }

        let mut ktop = [0u8; BLOCK_LEN];
        ktop[BLOCK_LEN - nonce.len()..].copy_from_slice(nonce);
        ktop[0] = (((tag_len * 8) % 128) as u8) << 1;
        ktop[BLOCK_LEN - nonce.len() - 1] |= 1;
        let bottom = (ktop[BLOCK_LEN - 1] & 0x3f) as usize;
        ktop[BLOCK_LEN - 1] &= 0xc0;
        cipher.encrypt_block(&mut ktop);

        let mut stretch = [0u8; 24];
        stretch[..BLOCK_LEN].copy_from_slice(&ktop);
        for idx in 0..8 {
            stretch[BLOCK_LEN + idx] = ktop[idx] ^ ktop[idx + 1];
        }

        let byteoff = bottom / 8;
        let shift = bottom % 8;
        let mut out = [0u8; BLOCK_LEN];
        for idx in 0..BLOCK_LEN {
            let current = stretch[byteoff + idx];
            let next = stretch[byteoff + idx + 1];
            out[idx] = if shift == 0 {
                current
            } else {
                (current << shift) | (next >> (8 - shift))
            };
        }
        Ok(out)
    }
}

#[derive(Default)]
struct CbcState {
    iv: Block,
}

#[derive(Default)]
struct CfbState {
    iv: Block,
    lastiv: Block,
    unused: usize,
}

#[derive(Default)]
struct OfbState {
    iv: Block,
    unused: usize,
}

#[derive(Default)]
struct CtrState {
    iv: Block,
    ctr: Block,
    keystream: Block,
    unused: usize,
}

#[derive(Default)]
struct AesWrapState {
    last_plaintext_len: u32,
    alternative_iv: Option<[u8; 8]>,
}

#[derive(Default)]
struct GcmState {
    nonce: Vec<u8>,
    nonce_set: bool,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    aad_finalized: bool,
    data_finalized: bool,
    tag: Option<Block>,
    j0: Block,
    ctr: Block,
    keystream: Block,
    unused: usize,
}

#[derive(Default)]
struct EaxState {
    nonce: Vec<u8>,
    nonce_set: bool,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Option<Block>,
    ctr: Block,
    keystream: Block,
    unused: usize,
}

#[derive(Default)]
struct CcmState {
    nonce: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
    tag: Option<Block>,
    ctr: Block,
    keystream: Block,
    unused: usize,
    aad_remaining: Option<u64>,
    msg_remaining: Option<u64>,
    tag_len: usize,
}

#[derive(Default)]
struct OcbState {
    nonce: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
    offset: Block,
    data_blocks: u64,
    aad_finalized: bool,
    data_finalized: bool,
    tag: Option<Block>,
}

#[derive(Default)]
struct XtsState {
    iv: Block,
}

#[derive(Default)]
struct SivState {
    aad_parts: Vec<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    computed_tag: Option<Block>,
    decryption_tag: Option<Block>,
    tag_finalized: bool,
}

#[derive(Default)]
struct GcmSivState {
    nonce: Option<[u8; 12]>,
    aad: Vec<u8>,
    tag_value: Option<Block>,
    decryption_tag: Option<Block>,
    aad_finalized: bool,
    data_finalized: bool,
    tag_set: bool,
}

enum CipherState {
    None,
    Ecb,
    Cbc(CbcState),
    Cfb(CfbState),
    Cfb8(CbcState),
    Ofb(OfbState),
    Ctr(CtrState),
    AesWrap(AesWrapState),
    Gcm(GcmState),
    Eax(EaxState),
    Ccm(CcmState),
    Ocb(OcbState),
    Xts(XtsState),
    Siv(SivState),
    GcmSiv(GcmSivState),
}

struct CipherHandle {
    algo: CipherAlgorithm,
    mode: c_int,
    flags: c_uint,
    allow_weak_key: bool,
    finalize_requested: bool,
    ocb_tag_len: usize,
    raw_key: Vec<u8>,
    base_cipher: Option<AesCipher>,
    tweak_cipher: Option<AesCipher>,
    ocb_key: Option<OcbKeyState>,
    state: CipherState,
}

impl Drop for CipherHandle {
    fn drop(&mut self) {
        self.raw_key.fill(0);
    }
}

impl CipherHandle {
    fn new(algo: CipherAlgorithm, mode: c_int, flags: c_uint) -> Result<Self, u32> {
        if !mode_supported(mode) || !mode_supported_for_algorithm(mode, algo) {
            return Err(err(error::GPG_ERR_INV_CIPHER_MODE));
        }
        if (flags & GCRY_CIPHER_CBC_CTS) != 0 && (flags & GCRY_CIPHER_CBC_MAC) != 0 {
            return Err(err(error::GPG_ERR_INV_FLAG));
        }

        let mut handle = Self {
            algo,
            mode,
            flags,
            allow_weak_key: false,
            finalize_requested: false,
            ocb_tag_len: 16,
            raw_key: Vec::new(),
            base_cipher: None,
            tweak_cipher: None,
            ocb_key: None,
            state: CipherState::None,
        };
        handle.state = handle.fresh_state();
        Ok(handle)
    }

    fn fresh_state(&self) -> CipherState {
        match self.mode {
            GCRY_CIPHER_MODE_NONE => CipherState::None,
            GCRY_CIPHER_MODE_ECB => CipherState::Ecb,
            GCRY_CIPHER_MODE_CBC => CipherState::Cbc(CbcState::default()),
            GCRY_CIPHER_MODE_CFB => CipherState::Cfb(CfbState::default()),
            GCRY_CIPHER_MODE_CFB8 => CipherState::Cfb8(CbcState::default()),
            GCRY_CIPHER_MODE_OFB => CipherState::Ofb(OfbState::default()),
            GCRY_CIPHER_MODE_CTR => CipherState::Ctr(CtrState::default()),
            GCRY_CIPHER_MODE_AESWRAP => CipherState::AesWrap(AesWrapState::default()),
            GCRY_CIPHER_MODE_GCM => CipherState::Gcm(GcmState::default()),
            GCRY_CIPHER_MODE_EAX => CipherState::Eax(EaxState::default()),
            GCRY_CIPHER_MODE_CCM => CipherState::Ccm(CcmState::default()),
            GCRY_CIPHER_MODE_OCB => CipherState::Ocb(OcbState::default()),
            GCRY_CIPHER_MODE_XTS => CipherState::Xts(XtsState::default()),
            GCRY_CIPHER_MODE_SIV => CipherState::Siv(SivState::default()),
            GCRY_CIPHER_MODE_GCM_SIV => CipherState::GcmSiv(GcmSivState::default()),
            _ => CipherState::None,
        }
    }

    fn reset_runtime(&mut self) {
        self.finalize_requested = false;
        if self.mode == GCRY_CIPHER_MODE_OCB {
            self.ocb_tag_len = 16;
        }
        self.state = self.fresh_state();
    }

    fn base_cipher(&self) -> Result<&AesCipher, u32> {
        self.base_cipher
            .as_ref()
            .ok_or_else(|| err(error::GPG_ERR_MISSING_KEY))
    }

    fn tweak_cipher(&self) -> Result<&AesCipher, u32> {
        self.tweak_cipher
            .as_ref()
            .ok_or_else(|| err(error::GPG_ERR_MISSING_KEY))
    }

    fn ocb_key(&self) -> Result<&OcbKeyState, u32> {
        self.ocb_key
            .as_ref()
            .ok_or_else(|| err(error::GPG_ERR_MISSING_KEY))
    }

    fn setkey(&mut self, key: &[u8]) -> Result<(), u32> {
        let mut weak_key = false;
        let (base_key, tweak_key, key_component_len) = match self.mode {
            GCRY_CIPHER_MODE_XTS => {
                if key.len() % 2 != 0 {
                    return Err(err(error::GPG_ERR_INV_KEYLEN));
                }
                let half = key.len() / 2;
                if !matches!(half, 16 | 24 | 32) {
                    return Err(err(error::GPG_ERR_INV_KEYLEN));
                }
                if global::lock_runtime_state().fips_mode
                    && bool::from(key[..half].ct_eq(&key[half..]))
                {
                    weak_key = true;
                }
                (&key[..half], Some(&key[half..]), half)
            }
            GCRY_CIPHER_MODE_SIV => {
                if key.len() % 2 != 0 {
                    return Err(err(error::GPG_ERR_INV_KEYLEN));
                }
                let half = key.len() / 2;
                if !matches!(half, 16 | 24 | 32) {
                    return Err(err(error::GPG_ERR_INV_KEYLEN));
                }
                (&key[..half], None, half)
            }
            GCRY_CIPHER_MODE_GCM_SIV => {
                if !matches!(key.len(), 16 | 32) {
                    return Err(err(error::GPG_ERR_INV_KEYLEN));
                }
                (key, None, key.len())
            }
            _ => {
                if !matches!(key.len(), 16 | 24 | 32) {
                    return Err(err(error::GPG_ERR_INV_KEYLEN));
                }
                (key, None, key.len())
            }
        };

        let _ = key_component_len;

        if weak_key && !self.allow_weak_key {
            return Err(err(error::GPG_ERR_WEAK_KEY));
        }

        self.raw_key.clear();
        self.raw_key.extend_from_slice(key);
        self.base_cipher = Some(AesCipher::new(self.algo, base_key)?);
        self.tweak_cipher = tweak_key
            .map(|part| AesCipher::new(self.algo, part))
            .transpose()?;
        self.ocb_key = if self.mode == GCRY_CIPHER_MODE_OCB {
            Some(OcbKeyState::new(self.base_cipher.as_ref().unwrap()))
        } else {
            None
        };
        self.finalize_requested = false;
        self.state = self.fresh_state();
        if weak_key {
            Err(err(error::GPG_ERR_WEAK_KEY))
        } else {
            Ok(())
        }
    }

    fn setiv(&mut self, iv: Option<&[u8]>, explicit_zero_length: bool) -> Result<(), u32> {
        self.finalize_requested = false;
        let this = self as *mut Self;
        match &mut self.state {
            CipherState::None | CipherState::Ecb => Ok(()),
            CipherState::Cbc(state) | CipherState::Cfb8(state) => {
                state.iv = [0u8; BLOCK_LEN];
                if let Some(iv) = iv {
                    if iv.len() != BLOCK_LEN {
                        return Err(err(error::GPG_ERR_INV_ARG));
                    }
                    state.iv.copy_from_slice(iv);
                }
                Ok(())
            }
            CipherState::Cfb(state) => {
                state.iv = [0u8; BLOCK_LEN];
                state.lastiv = [0u8; BLOCK_LEN];
                state.unused = 0;
                if let Some(iv) = iv {
                    if iv.len() != BLOCK_LEN {
                        return Err(err(error::GPG_ERR_INV_ARG));
                    }
                    state.iv.copy_from_slice(iv);
                }
                Ok(())
            }
            CipherState::Ofb(state) => {
                state.iv = [0u8; BLOCK_LEN];
                state.unused = 0;
                if let Some(iv) = iv {
                    if iv.len() != BLOCK_LEN {
                        return Err(err(error::GPG_ERR_INV_ARG));
                    }
                    state.iv.copy_from_slice(iv);
                }
                Ok(())
            }
            CipherState::Ctr(state) => {
                state.iv = [0u8; BLOCK_LEN];
                state.ctr = [0u8; BLOCK_LEN];
                state.keystream = [0u8; BLOCK_LEN];
                state.unused = 0;
                if let Some(iv) = iv {
                    if iv.len() != BLOCK_LEN {
                        return Err(err(error::GPG_ERR_INV_ARG));
                    }
                    state.iv.copy_from_slice(iv);
                }
                Ok(())
            }
            CipherState::Gcm(state) => {
                if explicit_zero_length {
                    return Err(err(error::GPG_ERR_INV_LENGTH));
                }
                unsafe { (&*this).gcm_set_nonce(state, iv.unwrap_or(&[])) }
            }
            CipherState::Eax(state) => unsafe { (&*this).eax_set_nonce(state, iv.unwrap_or(&[])) },
            CipherState::Ccm(state) => {
                let nonce = iv.unwrap_or(&[]);
                if !(7..=13).contains(&nonce.len()) {
                    return Err(err(error::GPG_ERR_INV_LENGTH));
                }
                state.nonce.clear();
                state.nonce.extend_from_slice(nonce);
                state.aad.clear();
                state.plaintext.clear();
                state.aad_remaining = None;
                state.msg_remaining = None;
                state.tag_len = 0;
                state.tag = None;
                state.ctr = [0u8; BLOCK_LEN];
                state.keystream = [0u8; BLOCK_LEN];
                state.unused = 0;
                Ok(())
            }
            CipherState::Ocb(state) => {
                let nonce = iv.unwrap_or(&[]);
                let offset0 = unsafe {
                    (&*this).ocb_key()?.offset0(
                        (&*this).base_cipher()?,
                        (&*this).ocb_tag_len,
                        nonce,
                    )?
                };
                state.nonce.clear();
                state.nonce.extend_from_slice(nonce);
                state.aad.clear();
                state.plaintext.clear();
                state.offset = offset0;
                state.data_blocks = 0;
                state.aad_finalized = false;
                state.data_finalized = false;
                state.tag = None;
                Ok(())
            }
            CipherState::Xts(state) => {
                state.iv = [0u8; BLOCK_LEN];
                if let Some(iv) = iv {
                    if iv.len() != BLOCK_LEN {
                        return Err(err(error::GPG_ERR_INV_ARG));
                    }
                    state.iv.copy_from_slice(iv);
                }
                Ok(())
            }
            CipherState::Siv(state) => {
                if state.tag_finalized || state.nonce.is_some() {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                state.nonce = Some(iv.unwrap_or(&[]).to_vec());
                state.computed_tag = None;
                Ok(())
            }
            CipherState::GcmSiv(state) => {
                if state.nonce.is_some() {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                let nonce = iv.unwrap_or(&[]);
                if nonce.len() != 12 {
                    return Err(err(error::GPG_ERR_INV_LENGTH));
                }
                let mut stored = [0u8; 12];
                stored.copy_from_slice(nonce);
                state.nonce = Some(stored);
                state.aad.clear();
                state.aad_finalized = false;
                state.data_finalized = false;
                if let Some(tag) = state.decryption_tag {
                    state.tag_value = Some(tag);
                    state.tag_set = true;
                } else {
                    state.tag_value = None;
                    state.tag_set = false;
                }
                Ok(())
            }
            CipherState::AesWrap(state) => {
                state.alternative_iv = None;
                if let Some(iv) = iv {
                    if !matches!(iv.len(), 8 | BLOCK_LEN) {
                        return Err(err(error::GPG_ERR_INV_ARG));
                    }
                    let mut stored = [0u8; 8];
                    stored.copy_from_slice(&iv[iv.len() - 8..]);
                    state.alternative_iv = Some(stored);
                }
                Ok(())
            }
        }
    }

    fn gcm_set_nonce(&self, state: &mut GcmState, nonce: &[u8]) -> Result<(), u32> {
        state.nonce.clear();
        state.nonce.extend_from_slice(nonce);
        state.nonce_set = true;
        state.aad.clear();
        state.ciphertext.clear();
        state.aad_finalized = false;
        state.data_finalized = false;
        state.tag = None;
        state.keystream = [0u8; BLOCK_LEN];
        state.unused = 0;
        let h = self.gcm_hash_subkey()?;
        state.j0 = gcm_j0(&h, &state.nonce);
        state.ctr = state.j0;
        inc32(&mut state.ctr);
        Ok(())
    }

    fn ensure_gcm_nonce(&self, state: &mut GcmState) -> Result<(), u32> {
        if !state.nonce_set {
            self.gcm_set_nonce(state, &[0u8; BLOCK_LEN])?;
        }
        Ok(())
    }

    fn eax_set_nonce(&self, state: &mut EaxState, nonce: &[u8]) -> Result<(), u32> {
        state.nonce.clear();
        state.nonce.extend_from_slice(nonce);
        state.nonce_set = true;
        state.aad.clear();
        state.ciphertext.clear();
        state.tag = None;
        state.keystream = [0u8; BLOCK_LEN];
        state.unused = 0;
        state.ctr = self.eax_cmac(0, &state.nonce)?;
        Ok(())
    }

    fn ensure_eax_nonce(&self, state: &mut EaxState) -> Result<(), u32> {
        if !state.nonce_set {
            self.eax_set_nonce(state, &[])?;
        }
        Ok(())
    }

    fn setctr(&mut self, ctr: Option<&[u8]>) -> Result<(), u32> {
        let CipherState::Ctr(state) = &mut self.state else {
            return Err(err(error::GPG_ERR_INV_ARG));
        };
        state.ctr = [0u8; BLOCK_LEN];
        state.keystream = [0u8; BLOCK_LEN];
        state.unused = 0;
        if let Some(ctr) = ctr {
            if ctr.len() != BLOCK_LEN {
                return Err(err(error::GPG_ERR_INV_ARG));
            }
            state.ctr.copy_from_slice(ctr);
        }
        Ok(())
    }

    fn info(&self, what: c_int, buffer: *mut c_void, nbytes: *mut usize) -> u32 {
        match what {
            GCRYCTL_GET_TAGLEN => {
                if !buffer.is_null() || nbytes.is_null() {
                    return err(error::GPG_ERR_INV_ARG);
                }

                let value = match &self.state {
                    CipherState::Ocb(_) => self.ocb_tag_len,
                    CipherState::Ccm(state) => state.tag_len,
                    CipherState::Eax(_) => BLOCK_LEN,
                    CipherState::Gcm(_) | CipherState::Siv(_) | CipherState::GcmSiv(_) => BLOCK_LEN,
                    _ => return err(error::GPG_ERR_INV_CIPHER_MODE),
                };

                unsafe {
                    *nbytes = value;
                }
                0
            }
            GCRYCTL_GET_KEYLEN => {
                if nbytes.is_null() || buffer.is_null() {
                    return err(error::GPG_ERR_INV_ARG);
                }
                let CipherState::AesWrap(state) = &self.state else {
                    return err(error::GPG_ERR_INV_CIPHER_MODE);
                };
                unsafe {
                    *nbytes = 4;
                    let out = slice::from_raw_parts_mut(buffer.cast::<u8>(), 4);
                    out.copy_from_slice(&state.last_plaintext_len.to_be_bytes());
                }
                0
            }
            _ => err(error::GPG_ERR_INV_OP),
        }
    }

    fn ctl(&mut self, cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
        let result = match cmd {
            GCRYCTL_RESET => {
                self.reset_runtime();
                Ok(())
            }
            GCRYCTL_FINALIZE => {
                if !buffer.is_null() || buflen != 0 {
                    Err(err(error::GPG_ERR_INV_ARG))
                } else {
                    self.finalize_requested = true;
                    Ok(())
                }
            }
            GCRYCTL_CFB_SYNC => self.cfb_sync(),
            GCRYCTL_SET_CBC_CTS => {
                if buflen != 0 {
                    if (self.flags & GCRY_CIPHER_CBC_MAC) != 0 {
                        Err(err(error::GPG_ERR_INV_FLAG))
                    } else {
                        self.flags |= GCRY_CIPHER_CBC_CTS;
                        Ok(())
                    }
                } else {
                    self.flags &= !GCRY_CIPHER_CBC_CTS;
                    Ok(())
                }
            }
            GCRYCTL_SET_CBC_MAC => {
                if buflen != 0 {
                    if (self.flags & GCRY_CIPHER_CBC_CTS) != 0 {
                        Err(err(error::GPG_ERR_INV_FLAG))
                    } else {
                        self.flags |= GCRY_CIPHER_CBC_MAC;
                        Ok(())
                    }
                } else {
                    self.flags &= !GCRY_CIPHER_CBC_MAC;
                    Ok(())
                }
            }
            GCRYCTL_SET_CCM_LENGTHS => self.set_ccm_lengths(buffer, buflen),
            GCRYCTL_SET_DECRYPTION_TAG => self.set_decryption_tag(buffer, buflen),
            GCRYCTL_SET_TAGLEN => self.set_ocb_tag_len(buffer, buflen),
            GCRYCTL_SET_ALLOW_WEAK_KEY => {
                if !buffer.is_null() || buflen > 1 {
                    Err(err(error::GPG_ERR_CIPHER_ALGO))
                } else {
                    self.allow_weak_key = buflen != 0;
                    Ok(())
                }
            }
            _ => Err(err(error::GPG_ERR_INV_OP)),
        };

        match result {
            Ok(()) => 0,
            Err(code) => code,
        }
    }

    fn cfb_sync(&mut self) -> Result<(), u32> {
        if (self.flags & GCRY_CIPHER_ENABLE_SYNC) == 0 {
            return Ok(());
        }
        let CipherState::Cfb(state) = &mut self.state else {
            return Ok(());
        };
        if state.unused == 0 {
            return Ok(());
        }
        let blocksize = BLOCK_LEN;
        let unused = state.unused;
        let mut next = [0u8; BLOCK_LEN];
        next[unused..].copy_from_slice(&state.iv[..blocksize - unused]);
        next[..unused].copy_from_slice(&state.lastiv[blocksize - unused..]);
        state.iv = next;
        state.unused = 0;
        Ok(())
    }

    fn set_ccm_lengths(&mut self, buffer: *mut c_void, buflen: usize) -> Result<(), u32> {
        let CipherState::Ccm(state) = &mut self.state else {
            return Err(err(error::GPG_ERR_INV_CIPHER_MODE));
        };
        if buffer.is_null() || buflen != 3 * std::mem::size_of::<u64>() {
            return Err(err(error::GPG_ERR_INV_ARG));
        }
        if state.nonce.is_empty() {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        if state.tag_len != 0 {
            return Err(err(error::GPG_ERR_INV_STATE));
        }

        let params = unsafe { slice::from_raw_parts(buffer.cast::<u64>(), 3) };
        let msg_len = params[0];
        let aad_len = params[1];
        let tag_len = params[2] as usize;

        if !matches!(tag_len, 4 | 6 | 8 | 10 | 12 | 14 | 16) {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }

        state.msg_remaining = Some(msg_len);
        state.aad_remaining = Some(aad_len);
        state.tag_len = tag_len;
        state.ctr = ccm_initial_counter(&state.nonce, 1);
        state.keystream = [0u8; BLOCK_LEN];
        state.unused = 0;
        Ok(())
    }

    fn set_decryption_tag(&mut self, buffer: *mut c_void, buflen: usize) -> Result<(), u32> {
        if buffer.is_null() {
            return Err(err(error::GPG_ERR_INV_ARG));
        }
        let tag_bytes = unsafe { slice::from_raw_parts(buffer.cast::<u8>(), buflen) };

        match &mut self.state {
            CipherState::Siv(state) => {
                if buflen != BLOCK_LEN {
                    return Err(err(error::GPG_ERR_INV_ARG));
                }
                if state.tag_finalized {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                let mut tag = [0u8; BLOCK_LEN];
                tag.copy_from_slice(tag_bytes);
                state.decryption_tag = Some(tag);
                Ok(())
            }
            CipherState::GcmSiv(state) => {
                if buflen != BLOCK_LEN {
                    return Err(err(error::GPG_ERR_INV_ARG));
                }
                if state.tag_set {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                let mut tag = [0u8; BLOCK_LEN];
                tag.copy_from_slice(tag_bytes);
                state.decryption_tag = Some(tag);
                state.tag_value = Some(tag);
                state.tag_set = true;
                Ok(())
            }
            _ => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
        }
    }

    fn set_ocb_tag_len(&mut self, buffer: *mut c_void, buflen: usize) -> Result<(), u32> {
        if buffer.is_null() || buflen != std::mem::size_of::<c_int>() {
            return Err(err(error::GPG_ERR_INV_ARG));
        }
        if self.mode != GCRY_CIPHER_MODE_OCB {
            return Err(err(error::GPG_ERR_INV_CIPHER_MODE));
        }

        let value = unsafe { *(buffer.cast::<c_int>()) as usize };
        if !matches!(value, 8 | 12 | 16) {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        self.ocb_tag_len = value;
        Ok(())
    }

    fn authenticate(&mut self, aad: &[u8]) -> Result<(), u32> {
        let this = self as *const Self;
        match &mut self.state {
            CipherState::Gcm(state) => {
                unsafe { (&*this).ensure_gcm_nonce(state)? };
                if state.tag.is_some() || state.aad_finalized || state.data_finalized {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                state.aad.extend_from_slice(aad);
                Ok(())
            }
            CipherState::Eax(state) => {
                unsafe { (&*this).ensure_eax_nonce(state)? };
                if state.tag.is_some() {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                state.aad.extend_from_slice(aad);
                Ok(())
            }
            CipherState::Ccm(state) => {
                if state.tag.is_some() {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                let Some(remaining) = state.aad_remaining else {
                    return Err(err(error::GPG_ERR_INV_STATE));
                };
                if aad.len() as u64 > remaining {
                    return Err(err(error::GPG_ERR_INV_LENGTH));
                }
                state.aad.extend_from_slice(aad);
                state.aad_remaining = Some(remaining - aad.len() as u64);
                Ok(())
            }
            CipherState::Ocb(state) => {
                if state.tag.is_some() || state.aad_finalized {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                state.aad.extend_from_slice(aad);
                Ok(())
            }
            CipherState::Siv(state) => {
                if state.tag_finalized || state.nonce.is_some() {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                state.aad_parts.push(aad.to_vec());
                Ok(())
            }
            CipherState::GcmSiv(state) => {
                if state.tag_set
                    || state.nonce.is_none()
                    || state.aad_finalized
                    || state.data_finalized
                {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                state.aad.extend_from_slice(aad);
                Ok(())
            }
            _ => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
        }
    }

    fn encrypt(&mut self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        let this = self as *const Self;
        match &mut self.state {
            CipherState::None => {
                if out.len() < input.len() {
                    return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
                }
                out[..input.len()].copy_from_slice(input);
                Ok(())
            }
            CipherState::Ecb => unsafe { (&*this).ecb_encrypt(out, input) },
            CipherState::Cbc(state) => unsafe { (&*this).cbc_encrypt(state, out, input) },
            CipherState::Cfb(state) => unsafe { (&*this).cfb_encrypt(state, out, input) },
            CipherState::Cfb8(state) => unsafe { (&*this).cfb8_encrypt(state, out, input) },
            CipherState::Ofb(state) => unsafe { (&*this).ofb_crypt(state, out, input) },
            CipherState::Ctr(state) => unsafe { (&*this).ctr_crypt(state, out, input) },
            CipherState::AesWrap(state) => unsafe { (&*this).aeswrap_encrypt(state, out, input) },
            CipherState::Gcm(state) => unsafe { (&*this).gcm_encrypt(state, out, input) },
            CipherState::Eax(state) => unsafe { (&*this).eax_encrypt(state, out, input) },
            CipherState::Ccm(state) => unsafe { (&*this).ccm_encrypt(state, out, input) },
            CipherState::Ocb(state) => unsafe { (&*this).ocb_encrypt(state, out, input) },
            CipherState::Xts(state) => unsafe { (&*this).xts_crypt(state, out, input, true) },
            CipherState::Siv(state) => unsafe { (&*this).siv_encrypt(state, out, input) },
            CipherState::GcmSiv(state) => unsafe { (&*this).gcm_siv_encrypt(state, out, input) },
        }
    }

    fn decrypt(&mut self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        let this = self as *const Self;
        match &mut self.state {
            CipherState::None => {
                if out.len() < input.len() {
                    return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
                }
                out[..input.len()].copy_from_slice(input);
                Ok(())
            }
            CipherState::Ecb => unsafe { (&*this).ecb_decrypt(out, input) },
            CipherState::Cbc(state) => unsafe { (&*this).cbc_decrypt(state, out, input) },
            CipherState::Cfb(state) => unsafe { (&*this).cfb_decrypt(state, out, input) },
            CipherState::Cfb8(state) => unsafe { (&*this).cfb8_decrypt(state, out, input) },
            CipherState::Ofb(state) => unsafe { (&*this).ofb_crypt(state, out, input) },
            CipherState::Ctr(state) => unsafe { (&*this).ctr_crypt(state, out, input) },
            CipherState::AesWrap(state) => unsafe { (&*this).aeswrap_decrypt(state, out, input) },
            CipherState::Gcm(state) => unsafe { (&*this).gcm_decrypt(state, out, input) },
            CipherState::Eax(state) => unsafe { (&*this).eax_decrypt(state, out, input) },
            CipherState::Ccm(state) => unsafe { (&*this).ccm_decrypt(state, out, input) },
            CipherState::Ocb(state) => unsafe { (&*this).ocb_decrypt(state, out, input) },
            CipherState::Xts(state) => unsafe { (&*this).xts_crypt(state, out, input, false) },
            CipherState::Siv(state) => unsafe { (&*this).siv_decrypt(state, out, input) },
            CipherState::GcmSiv(state) => unsafe { (&*this).gcm_siv_decrypt(state, out, input) },
        }
    }

    fn gettag(&mut self, outtag: &mut [u8]) -> Result<usize, u32> {
        let this = self as *const Self;
        match &mut self.state {
            CipherState::Gcm(state) => {
                if !gcm_valid_gettag_len(outtag.len()) {
                    return Err(err(error::GPG_ERR_INV_LENGTH));
                }
                let tag = unsafe { (&*this).finalize_gcm_tag(state)? };
                let n = outtag.len().min(BLOCK_LEN);
                outtag[..n].copy_from_slice(&tag[..n]);
                Ok(n)
            }
            CipherState::Eax(state) => {
                let tag = unsafe { (&*this).finalize_eax_tag(state)? };
                let n = outtag.len().min(BLOCK_LEN);
                outtag[..n].copy_from_slice(&tag[..n]);
                Ok(n)
            }
            CipherState::Ccm(state) => {
                if outtag.len() != state.tag_len || outtag.is_empty() {
                    return Err(err(error::GPG_ERR_INV_LENGTH));
                }
                let tag = unsafe { (&*this).finalize_ccm_tag(state)? };
                outtag.copy_from_slice(&tag[..outtag.len()]);
                Ok(outtag.len())
            }
            CipherState::Ocb(state) => {
                if !state.data_finalized {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                if outtag.len() < self.ocb_tag_len {
                    return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
                }
                let tag = unsafe { (&*this).finalize_ocb_tag(state)? };
                outtag[..self.ocb_tag_len].copy_from_slice(&tag[..self.ocb_tag_len]);
                Ok(self.ocb_tag_len)
            }
            CipherState::Siv(state) => {
                if state.decryption_tag.is_some() {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                let tag = unsafe { (&*this).siv_current_tag(state)? };
                let n = outtag.len().min(BLOCK_LEN);
                outtag[..n].copy_from_slice(&tag[..n]);
                Ok(n)
            }
            CipherState::GcmSiv(state) => {
                let tag = unsafe { (&*this).gcm_siv_current_tag(state)? };
                let n = outtag.len().min(BLOCK_LEN);
                outtag[..n].copy_from_slice(&tag[..n]);
                Ok(n)
            }
            _ => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
        }
    }

    fn checktag(&mut self, tag: &[u8]) -> Result<(), u32> {
        let this = self as *const Self;
        match &mut self.state {
            CipherState::Gcm(state) => {
                if !gcm_valid_checktag_len(tag.len()) {
                    return Err(err(error::GPG_ERR_INV_LENGTH));
                }
                let expected = unsafe { (&*this).finalize_gcm_tag(state)? };
                if !matches!(tag.len(), 4 | 8 | 12 | 13 | 14 | 15 | 16) {
                    return Err(err(error::GPG_ERR_CHECKSUM));
                }
                if bool::from(expected[..tag.len()].ct_eq(tag)) {
                    Ok(())
                } else {
                    Err(err(error::GPG_ERR_CHECKSUM))
                }
            }
            CipherState::Eax(state) => {
                let expected = unsafe { (&*this).finalize_eax_tag(state)? };
                if tag.len() <= BLOCK_LEN && bool::from(expected[..tag.len()].ct_eq(tag)) {
                    Ok(())
                } else {
                    Err(err(error::GPG_ERR_CHECKSUM))
                }
            }
            CipherState::Ccm(state) => {
                if tag.len() != state.tag_len || tag.is_empty() {
                    return Err(err(error::GPG_ERR_INV_LENGTH));
                }
                let expected = unsafe { (&*this).finalize_ccm_tag(state)? };
                if bool::from(expected[..tag.len()].ct_eq(tag)) {
                    Ok(())
                } else {
                    Err(err(error::GPG_ERR_CHECKSUM))
                }
            }
            CipherState::Ocb(state) => {
                if !state.data_finalized {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                let expected = unsafe { (&*this).finalize_ocb_tag(state)? };
                let cmp_len = tag.len().min(self.ocb_tag_len);
                if cmp_len != self.ocb_tag_len
                    || !bool::from(expected[..cmp_len].ct_eq(&tag[..cmp_len]))
                {
                    Err(err(error::GPG_ERR_CHECKSUM))
                } else {
                    Ok(())
                }
            }
            CipherState::Siv(state) => {
                if tag.len() != BLOCK_LEN {
                    return Err(err(error::GPG_ERR_CHECKSUM));
                }
                let expected = unsafe { (&*this).siv_current_tag(state)? };
                if bool::from(expected.ct_eq(tag.try_into().unwrap())) {
                    Ok(())
                } else {
                    Err(err(error::GPG_ERR_CHECKSUM))
                }
            }
            CipherState::GcmSiv(state) => {
                if tag.len() != BLOCK_LEN {
                    return Err(err(error::GPG_ERR_CHECKSUM));
                }
                let expected = unsafe { (&*this).gcm_siv_current_tag(state)? };
                if bool::from(expected.ct_eq(tag.try_into().unwrap())) {
                    Ok(())
                } else {
                    Err(err(error::GPG_ERR_CHECKSUM))
                }
            }
            _ => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
        }
    }

    fn gcm_hash_subkey(&self) -> Result<Block, u32> {
        let cipher = self.base_cipher()?;
        let mut h = [0u8; BLOCK_LEN];
        cipher.encrypt_block(&mut h);
        Ok(h)
    }

    fn compute_gcm_tag(&self, state: &GcmState) -> Result<Block, u32> {
        if !state.nonce_set {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        let h = self.gcm_hash_subkey()?;
        let auth = ghash_finalize(&state.aad, &state.ciphertext, &h);
        let mut s = state.j0;
        self.base_cipher()?.encrypt_block(&mut s);
        Ok(xor_block(&auth, &s))
    }

    fn finalize_gcm_tag(&self, state: &mut GcmState) -> Result<Block, u32> {
        self.ensure_gcm_nonce(state)?;
        if let Some(tag) = state.tag {
            return Ok(tag);
        }
        state.aad_finalized = true;
        state.data_finalized = true;
        let tag = self.compute_gcm_tag(state)?;
        state.tag = Some(tag);
        Ok(tag)
    }

    fn eax_cmac(&self, domain: u8, data: &[u8]) -> Result<Block, u32> {
        Ok(cmac16_with_cipher(self.base_cipher()?, domain, data))
    }

    fn compute_eax_tag(&self, state: &EaxState) -> Result<Block, u32> {
        if !state.nonce_set {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        let nonce_tag = self.eax_cmac(0, &state.nonce)?;
        let header_tag = self.eax_cmac(1, &state.aad)?;
        let cipher_tag = self.eax_cmac(2, &state.ciphertext)?;
        Ok(xor_block(&xor_block(&nonce_tag, &header_tag), &cipher_tag))
    }

    fn finalize_eax_tag(&self, state: &mut EaxState) -> Result<Block, u32> {
        self.ensure_eax_nonce(state)?;
        if let Some(tag) = state.tag {
            return Ok(tag);
        }
        let tag = self.compute_eax_tag(state)?;
        state.tag = Some(tag);
        Ok(tag)
    }

    fn compute_ccm_tag(&self, state: &CcmState) -> Result<Block, u32> {
        if state.nonce.is_empty() || state.tag_len == 0 {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        if state.aad_remaining != Some(0) {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        if state.msg_remaining != Some(0) {
            return Err(err(error::GPG_ERR_UNFINISHED));
        }

        let nonce_len = state.nonce.len();
        let q = 15 - nonce_len;
        let flags = ((if !state.aad.is_empty() { 1 } else { 0 }) << 6)
            | ((((state.tag_len - 2) / 2) as u8) << 3)
            | ((q - 1) as u8);
        let mut mac = [0u8; BLOCK_LEN];
        mac[0] = flags;
        mac[1..1 + nonce_len].copy_from_slice(&state.nonce);
        mac[1 + nonce_len..].copy_from_slice(&be_len_bytes(state.plaintext.len(), q));
        self.base_cipher()?.encrypt_block(&mut mac);

        if !state.aad.is_empty() {
            let mut header = Vec::new();
            let aad_len = state.aad.len() as u64;
            if aad_len <= 0xfeff {
                header.extend_from_slice(&(aad_len as u16).to_be_bytes());
            } else if aad_len <= u32::MAX as u64 {
                header.extend_from_slice(&[0xff, 0xfe]);
                header.extend_from_slice(&(aad_len as u32).to_be_bytes());
            } else {
                header.extend_from_slice(&[0xff, 0xff]);
                header.extend_from_slice(&aad_len.to_be_bytes());
            }
            header.extend_from_slice(&state.aad);
            cbc_mac_bytes(self.base_cipher()?, &mut mac, &header);
        }

        cbc_mac_bytes(self.base_cipher()?, &mut mac, &state.plaintext);

        let mut s0 = ccm_initial_counter(&state.nonce, 0);
        self.base_cipher()?.encrypt_block(&mut s0);
        Ok(xor_block(&mac, &s0))
    }

    fn finalize_ccm_tag(&self, state: &mut CcmState) -> Result<Block, u32> {
        if let Some(tag) = state.tag {
            return Ok(tag);
        }
        let tag = self.compute_ccm_tag(state)?;
        state.tag = Some(tag);
        Ok(tag)
    }

    fn finalize_ocb_tag(&self, state: &mut OcbState) -> Result<Block, u32> {
        if let Some(tag) = state.tag {
            return Ok(tag);
        }
        let tag = self.compute_ocb_tag(state)?;
        state.aad_finalized = true;
        state.tag = Some(tag);
        Ok(tag)
    }

    fn compute_ocb_tag(&self, state: &OcbState) -> Result<Block, u32> {
        let key = self.ocb_key()?;
        let cipher = self.base_cipher()?;
        let mut aad_offset = [0u8; BLOCK_LEN];
        let mut aad_sum = [0u8; BLOCK_LEN];
        let mut aad_blocks = 0u64;

        for chunk in state.aad.chunks(BLOCK_LEN) {
            if chunk.len() == BLOCK_LEN {
                aad_blocks += 1;
                xor_block_in_place(&mut aad_offset, key.l(aad_blocks));
                let mut tmp = xor_block(&aad_offset, &chunk.try_into().unwrap());
                cipher.encrypt_block(&mut tmp);
                xor_block_in_place(&mut aad_sum, &tmp);
            } else {
                xor_block_in_place(&mut aad_offset, &key.l_star);
                let mut tmp = xor_block(&aad_offset, &pad_with_0x80(chunk));
                cipher.encrypt_block(&mut tmp);
                xor_block_in_place(&mut aad_sum, &tmp);
            }
        }

        let mut offset = key.offset0(cipher, self.ocb_tag_len, &state.nonce)?;
        let mut checksum = [0u8; BLOCK_LEN];
        let mut data_blocks = 0u64;
        let mut tail = None;
        for chunk in state.plaintext.chunks(BLOCK_LEN) {
            if chunk.len() == BLOCK_LEN {
                data_blocks += 1;
                xor_block_in_place(&mut offset, key.l(data_blocks));
                let block: Block = chunk.try_into().unwrap();
                xor_block_in_place(&mut checksum, &block);
            } else {
                tail = Some(chunk);
            }
        }
        if let Some(chunk) = tail {
            xor_block_in_place(&mut offset, &key.l_star);
            xor_block_in_place(&mut checksum, &pad_with_0x80(chunk));
        }
        let mut tag = xor_block(&xor_block(&checksum, &offset), &key.l_dollar);
        cipher.encrypt_block(&mut tag);
        xor_block_in_place(&mut tag, &aad_sum);
        Ok(tag)
    }

    fn siv_headers<'a>(&'a self, state: &'a SivState) -> Vec<&'a [u8]> {
        let mut headers: Vec<&[u8]> = state.aad_parts.iter().map(Vec::as_slice).collect();
        if let Some(nonce) = &state.nonce {
            headers.push(nonce.as_slice());
        }
        headers
    }

    fn siv_generic_tag(&self, state: &SivState, plaintext: &[u8]) -> Result<Block, u32> {
        let mac_cipher = self.base_cipher()?;
        let mut d = cmac16_raw_with_cipher(mac_cipher, &[0u8; BLOCK_LEN]);

        for aad in &state.aad_parts {
            double_ocb(&mut d);
            let mac = cmac16_raw_with_cipher(mac_cipher, aad);
            d = xor_block(&d, &mac);
        }

        if let Some(nonce) = &state.nonce {
            double_ocb(&mut d);
            let mac = cmac16_raw_with_cipher(mac_cipher, nonce);
            d = xor_block(&d, &mac);
        }

        if plaintext.len() >= BLOCK_LEN {
            let mut data = plaintext.to_vec();
            let last = data.len() - BLOCK_LEN;
            for idx in 0..BLOCK_LEN {
                data[last + idx] ^= d[idx];
            }
            Ok(cmac16_raw_with_cipher(mac_cipher, &data))
        } else {
            double_ocb(&mut d);
            let mut padded = [0u8; BLOCK_LEN];
            padded[..plaintext.len()].copy_from_slice(plaintext);
            padded[plaintext.len()] = 0x80;
            xor_block_in_place(&mut padded, &d);
            Ok(cmac16_raw_with_cipher(mac_cipher, &padded))
        }
    }

    fn gcm_siv_derive_keys(&self, nonce: &[u8; 12]) -> Result<(AesCipher, Polyval), u32> {
        let key_generating_cipher = self.base_cipher()?;
        let mut mac_key = [0u8; BLOCK_LEN];
        let mut enc_key = vec![0u8; self.raw_key.len()];
        let mut counter = 0u32;

        for derived in [&mut mac_key[..], enc_key.as_mut_slice()] {
            for chunk in derived.chunks_mut(8) {
                let mut block = [0u8; BLOCK_LEN];
                block[..4].copy_from_slice(&counter.to_le_bytes());
                block[4..].copy_from_slice(nonce);
                key_generating_cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block[..8]);
                counter = counter.wrapping_add(1);
            }
        }

        let enc_cipher = AesCipher::new(self.algo, &enc_key)?;
        let polyval = Polyval::new((&mac_key).into());
        Ok((enc_cipher, polyval))
    }

    fn gcm_siv_finish_tag(
        &self,
        polyval: &mut Polyval,
        nonce: &[u8; 12],
        associated_data_len: usize,
        buffer_len: usize,
        enc_cipher: &AesCipher,
    ) -> Block {
        let mut length_block = polyval::Block::default();
        length_block[..8].copy_from_slice(&((associated_data_len as u64) * 8).to_le_bytes());
        length_block[8..].copy_from_slice(&((buffer_len as u64) * 8).to_le_bytes());
        polyval.update(&[length_block]);

        let mut tag = [0u8; BLOCK_LEN];
        tag.copy_from_slice(&polyval.finalize_reset());
        for idx in 0..12 {
            tag[idx] ^= nonce[idx];
        }
        tag[15] &= 0x7f;
        enc_cipher.encrypt_block(&mut tag);
        tag
    }

    fn siv_current_tag(&self, state: &mut SivState) -> Result<Block, u32> {
        if let Some(tag) = state.computed_tag {
            return Ok(tag);
        }
        let mut buf = [];
        let tag: Block = if self.algo.is_aes() {
            let headers = self.siv_headers(state);
            match self.raw_key.len() {
                32 => {
                    let mut siv = <Aes128Siv as KeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    siv.encrypt_inout_detached(headers, (&mut buf[..]).into())
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                48 => {
                    let mut siv = <Aes192Siv as KeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    siv.encrypt_inout_detached(headers, (&mut buf[..]).into())
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                64 => {
                    let mut siv = <Aes256Siv as KeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    siv.encrypt_inout_detached(headers, (&mut buf[..]).into())
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                _ => return Err(err(error::GPG_ERR_INV_KEYLEN)),
            }
        } else {
            self.siv_generic_tag(state, &buf)?
        };
        state.computed_tag = Some(tag);
        state.tag_finalized = true;
        Ok(tag)
    }

    fn gcm_siv_current_tag(&self, state: &mut GcmSivState) -> Result<Block, u32> {
        if !state.tag_set {
            let mut empty = [];
            self.gcm_siv_encrypt(state, &mut empty, &[])?;
        }
        if !state.data_finalized {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        state.tag_value.ok_or_else(|| err(error::GPG_ERR_INV_STATE))
    }

    fn ecb_encrypt(&self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK_LEN != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        for (chunk_in, chunk_out) in input.chunks(BLOCK_LEN).zip(out.chunks_mut(BLOCK_LEN)) {
            let mut block: Block = chunk_in.try_into().unwrap();
            self.base_cipher()?.encrypt_block(&mut block);
            chunk_out.copy_from_slice(&block);
        }
        Ok(())
    }

    fn ecb_decrypt(&self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK_LEN != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        for (chunk_in, chunk_out) in input.chunks(BLOCK_LEN).zip(out.chunks_mut(BLOCK_LEN)) {
            let mut block: Block = chunk_in.try_into().unwrap();
            self.base_cipher()?.decrypt_block(&mut block);
            chunk_out.copy_from_slice(&block);
        }
        Ok(())
    }

    fn cbc_encrypt(&self, state: &mut CbcState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        let mac_mode = (self.flags & GCRY_CIPHER_CBC_MAC) != 0;
        let cts_mode = (self.flags & GCRY_CIPHER_CBC_CTS) != 0;
        if mac_mode {
            if input.len() % BLOCK_LEN != 0 {
                return Err(err(error::GPG_ERR_INV_LENGTH));
            }
            if out.len() < BLOCK_LEN {
                return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
            }
            let mut iv = state.iv;
            let cipher = self.base_cipher()?;
            for chunk in input.chunks(BLOCK_LEN) {
                let mut block = xor_block(&iv, &chunk.try_into().unwrap());
                cipher.encrypt_block(&mut block);
                iv = block;
            }
            state.iv = iv;
            out[..BLOCK_LEN].copy_from_slice(&iv);
            return Ok(());
        }
        if cts_mode {
            return self.cbc_cts_encrypt(state, out, input);
        }
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK_LEN != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let cipher = self.base_cipher()?;
        for (chunk_in, chunk_out) in input.chunks(BLOCK_LEN).zip(out.chunks_mut(BLOCK_LEN)) {
            let mut block = xor_block(&state.iv, &chunk_in.try_into().unwrap());
            cipher.encrypt_block(&mut block);
            state.iv = block;
            chunk_out.copy_from_slice(&block);
        }
        Ok(())
    }

    fn cbc_cts_encrypt(
        &self,
        state: &mut CbcState,
        out: &mut [u8],
        input: &[u8],
    ) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK_LEN != 0 && input.len() <= BLOCK_LEN {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let cipher = self.base_cipher()?;
        let mut iv = state.iv;
        let mut pos = 0usize;
        let mut full_blocks = input.len() / BLOCK_LEN;
        if input.len() > BLOCK_LEN && input.len() % BLOCK_LEN == 0 {
            full_blocks -= 1;
        }
        while pos < full_blocks * BLOCK_LEN {
            let mut block = xor_block(&iv, &input[pos..pos + BLOCK_LEN].try_into().unwrap());
            cipher.encrypt_block(&mut block);
            out[pos..pos + BLOCK_LEN].copy_from_slice(&block);
            iv = block;
            pos += BLOCK_LEN;
        }
        if input.len() > BLOCK_LEN {
            let rest = if input.len() % BLOCK_LEN == 0 {
                BLOCK_LEN
            } else {
                input.len() % BLOCK_LEN
            };
            let prev = pos - BLOCK_LEN;
            let mut final_block = [0u8; BLOCK_LEN];
            final_block[..rest].copy_from_slice(&input[pos..pos + rest]);
            for idx in 0..BLOCK_LEN {
                final_block[idx] ^= iv[idx];
            }
            cipher.encrypt_block(&mut final_block);
            let stolen = out[prev..prev + rest].to_vec();
            out[pos..pos + rest].copy_from_slice(&stolen);
            out[prev..prev + BLOCK_LEN].copy_from_slice(&final_block);
            iv = final_block;
        }
        state.iv = iv;
        Ok(())
    }

    fn cbc_decrypt(&self, state: &mut CbcState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if (self.flags & GCRY_CIPHER_CBC_MAC) != 0 {
            return Err(err(error::GPG_ERR_INV_CIPHER_MODE));
        }
        if (self.flags & GCRY_CIPHER_CBC_CTS) != 0 {
            return self.cbc_cts_decrypt(state, out, input);
        }
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK_LEN != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let cipher = self.base_cipher()?;
        for (chunk_in, chunk_out) in input.chunks(BLOCK_LEN).zip(out.chunks_mut(BLOCK_LEN)) {
            let current: Block = chunk_in.try_into().unwrap();
            let mut block = current;
            cipher.decrypt_block(&mut block);
            xor_block_in_place(&mut block, &state.iv);
            state.iv = current;
            chunk_out.copy_from_slice(&block);
        }
        Ok(())
    }

    fn cbc_cts_decrypt(
        &self,
        state: &mut CbcState,
        out: &mut [u8],
        input: &[u8],
    ) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK_LEN != 0 && input.len() <= BLOCK_LEN {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let cipher = self.base_cipher()?;
        let mut iv = state.iv;
        let mut pos = 0usize;
        let mut nblocks = input.len() / BLOCK_LEN;
        if input.len() > BLOCK_LEN {
            nblocks -= 1;
            if input.len() % BLOCK_LEN == 0 {
                nblocks -= 1;
            }
        }
        while pos < nblocks * BLOCK_LEN {
            let current: Block = input[pos..pos + BLOCK_LEN].try_into().unwrap();
            let mut block = current;
            cipher.decrypt_block(&mut block);
            xor_block_in_place(&mut block, &iv);
            iv = current;
            out[pos..pos + BLOCK_LEN].copy_from_slice(&block);
            pos += BLOCK_LEN;
        }

        if input.len() > BLOCK_LEN {
            let rest = if input.len() % BLOCK_LEN == 0 {
                BLOCK_LEN
            } else {
                input.len() % BLOCK_LEN
            };
            let last_full = &input[pos..pos + BLOCK_LEN];
            let tail = &input[pos + BLOCK_LEN..];

            let mut tmp_iv = [0u8; BLOCK_LEN];
            tmp_iv[..rest].copy_from_slice(tail);
            let mut decrypted = last_full.try_into().unwrap();
            cipher.decrypt_block(&mut decrypted);
            for idx in 0..rest {
                decrypted[idx] ^= tmp_iv[idx];
            }
            out[pos + BLOCK_LEN..pos + BLOCK_LEN + rest].copy_from_slice(&decrypted[..rest]);
            for idx in rest..BLOCK_LEN {
                tmp_iv[idx] = decrypted[idx];
            }
            let mut block = tmp_iv;
            cipher.decrypt_block(&mut block);
            xor_block_in_place(&mut block, &iv);
            out[pos..pos + BLOCK_LEN].copy_from_slice(&block);
            iv = tmp_iv;
        }
        state.iv = iv;
        Ok(())
    }

    fn cfb_encrypt(&self, state: &mut CfbState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut inpos = 0usize;
        if input.len() <= state.unused {
            let start = BLOCK_LEN - state.unused;
            for idx in 0..input.len() {
                let val = state.iv[start + idx] ^ input[idx];
                out[idx] = val;
                state.iv[start + idx] = val;
            }
            state.unused -= input.len();
            return Ok(());
        }
        if state.unused != 0 {
            let count = state.unused;
            let start = BLOCK_LEN - count;
            for idx in 0..count {
                let val = state.iv[start + idx] ^ input[idx];
                out[idx] = val;
                state.iv[start + idx] = val;
            }
            inpos += count;
            state.unused = 0;
        }
        while input.len() - inpos >= BLOCK_LEN {
            state.lastiv = state.iv;
            cipher.encrypt_block(&mut state.iv);
            for idx in 0..BLOCK_LEN {
                let val = state.iv[idx] ^ input[inpos + idx];
                out[inpos + idx] = val;
                state.iv[idx] = val;
            }
            inpos += BLOCK_LEN;
        }
        if inpos < input.len() {
            state.lastiv = state.iv;
            cipher.encrypt_block(&mut state.iv);
            let remaining = input.len() - inpos;
            for idx in 0..remaining {
                let val = state.iv[idx] ^ input[inpos + idx];
                out[inpos + idx] = val;
                state.iv[idx] = val;
            }
            state.unused = BLOCK_LEN - remaining;
        }
        Ok(())
    }

    fn cfb_decrypt(&self, state: &mut CfbState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut inpos = 0usize;
        if input.len() <= state.unused {
            let start = BLOCK_LEN - state.unused;
            for idx in 0..input.len() {
                let c = input[idx];
                out[idx] = state.iv[start + idx] ^ c;
                state.iv[start + idx] = c;
            }
            state.unused -= input.len();
            return Ok(());
        }
        if state.unused != 0 {
            let count = state.unused;
            let start = BLOCK_LEN - count;
            for idx in 0..count {
                let c = input[idx];
                out[idx] = state.iv[start + idx] ^ c;
                state.iv[start + idx] = c;
            }
            inpos += count;
            state.unused = 0;
        }
        while input.len() - inpos >= BLOCK_LEN {
            state.lastiv = state.iv;
            cipher.encrypt_block(&mut state.iv);
            for idx in 0..BLOCK_LEN {
                let c = input[inpos + idx];
                out[inpos + idx] = state.iv[idx] ^ c;
                state.iv[idx] = c;
            }
            inpos += BLOCK_LEN;
        }
        if inpos < input.len() {
            state.lastiv = state.iv;
            cipher.encrypt_block(&mut state.iv);
            let remaining = input.len() - inpos;
            for idx in 0..remaining {
                let c = input[inpos + idx];
                out[inpos + idx] = state.iv[idx] ^ c;
                state.iv[idx] = c;
            }
            state.unused = BLOCK_LEN - remaining;
        }
        Ok(())
    }

    fn cfb8_encrypt(&self, state: &mut CbcState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        for idx in 0..input.len() {
            let mut tmp = state.iv;
            cipher.encrypt_block(&mut tmp);
            out[idx] = tmp[0] ^ input[idx];
            state.iv.copy_within(1.., 0);
            state.iv[BLOCK_LEN - 1] = out[idx];
        }
        Ok(())
    }

    fn cfb8_decrypt(&self, state: &mut CbcState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        for idx in 0..input.len() {
            let mut tmp = state.iv;
            cipher.encrypt_block(&mut tmp);
            let c = input[idx];
            out[idx] = c ^ tmp[0];
            state.iv.copy_within(1.., 0);
            state.iv[BLOCK_LEN - 1] = c;
        }
        Ok(())
    }

    fn ofb_crypt(&self, state: &mut OfbState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut pos = 0usize;
        if input.len() <= state.unused {
            let start = BLOCK_LEN - state.unused;
            xor_slice(
                &mut out[..input.len()],
                input,
                &state.iv[start..start + input.len()],
            );
            state.unused -= input.len();
            return Ok(());
        }
        if state.unused != 0 {
            let start = BLOCK_LEN - state.unused;
            let count = state.unused;
            xor_slice(&mut out[..count], &input[..count], &state.iv[start..]);
            pos += count;
            state.unused = 0;
        }
        while pos < input.len() {
            cipher.encrypt_block(&mut state.iv);
            let remaining = input.len() - pos;
            let take = remaining.min(BLOCK_LEN);
            xor_slice(
                &mut out[pos..pos + take],
                &input[pos..pos + take],
                &state.iv[..take],
            );
            pos += take;
            if take < BLOCK_LEN {
                state.unused = BLOCK_LEN - take;
            }
        }
        Ok(())
    }

    fn ctr_crypt(&self, state: &mut CtrState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut pos = 0usize;
        if input.len() <= state.unused {
            let start = BLOCK_LEN - state.unused;
            xor_slice(
                &mut out[..input.len()],
                input,
                &state.keystream[start..start + input.len()],
            );
            state.unused -= input.len();
            return Ok(());
        }
        if state.unused != 0 {
            let start = BLOCK_LEN - state.unused;
            let count = state.unused;
            xor_slice(
                &mut out[..count],
                &input[..count],
                &state.keystream[start..],
            );
            pos += count;
            state.unused = 0;
        }
        while pos < input.len() {
            state.keystream = state.ctr;
            cipher.encrypt_block(&mut state.keystream);
            inc_be(&mut state.ctr);
            let remaining = input.len() - pos;
            let take = remaining.min(BLOCK_LEN);
            xor_slice(
                &mut out[pos..pos + take],
                &input[pos..pos + take],
                &state.keystream[..take],
            );
            pos += take;
            if take < BLOCK_LEN {
                state.unused = BLOCK_LEN - take;
            }
        }
        Ok(())
    }

    fn aeswrap_encrypt(
        &self,
        state: &mut AesWrapState,
        out: &mut [u8],
        input: &[u8],
    ) -> Result<(), u32> {
        let extended = (self.flags & GCRY_CIPHER_EXTENDED) != 0;
        let written = if !extended {
            let aiv = state.alternative_iv.unwrap_or([0xa6; 8]);
            self.kw_wrap_with_iv(aiv, out, input)?
        } else {
            match self.raw_key.len() {
                16 => KwpAes128::new_from_slice(&self.raw_key)
                    .unwrap()
                    .wrap_key(input, out),
                24 => KwpAes192::new_from_slice(&self.raw_key)
                    .unwrap()
                    .wrap_key(input, out),
                32 => KwpAes256::new_from_slice(&self.raw_key)
                    .unwrap()
                    .wrap_key(input, out),
                _ => return Err(err(error::GPG_ERR_INV_KEYLEN)),
            }
            .map_err(map_aeskw_error)?
            .len()
        };
        state.last_plaintext_len = input.len() as u32;
        let _ = written;
        Ok(())
    }

    fn aeswrap_decrypt(
        &self,
        state: &mut AesWrapState,
        out: &mut [u8],
        input: &[u8],
    ) -> Result<(), u32> {
        let extended = (self.flags & GCRY_CIPHER_EXTENDED) != 0;
        let plaintext_len = if !extended {
            let aiv = state.alternative_iv.unwrap_or([0xa6; 8]);
            self.kw_unwrap_with_iv(aiv, out, input)?
        } else {
            match self.raw_key.len() {
                16 => KwpAes128::new_from_slice(&self.raw_key)
                    .unwrap()
                    .unwrap_key(input, out),
                24 => KwpAes192::new_from_slice(&self.raw_key)
                    .unwrap()
                    .unwrap_key(input, out),
                32 => KwpAes256::new_from_slice(&self.raw_key)
                    .unwrap()
                    .unwrap_key(input, out),
                _ => return Err(err(error::GPG_ERR_INV_KEYLEN)),
            }
            .map_err(map_aeskw_error)?
            .len()
        };
        state.last_plaintext_len = plaintext_len as u32;
        Ok(())
    }

    fn gcm_encrypt(&self, state: &mut GcmState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        self.ensure_gcm_nonce(state)?;
        if state.tag.is_some() || state.data_finalized {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        if !state.aad_finalized {
            state.aad_finalized = true;
        }
        self.gcm_crypt(state, out, input, true)
    }

    fn gcm_decrypt(&self, state: &mut GcmState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        self.ensure_gcm_nonce(state)?;
        if state.tag.is_some() || state.data_finalized {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        if !state.aad_finalized {
            state.aad_finalized = true;
        }
        self.gcm_crypt(state, out, input, false)
    }

    fn gcm_crypt(
        &self,
        state: &mut GcmState,
        out: &mut [u8],
        input: &[u8],
        encrypting: bool,
    ) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut pos = 0usize;
        while pos < input.len() {
            if state.unused == 0 {
                state.keystream = state.ctr;
                cipher.encrypt_block(&mut state.keystream);
                inc32(&mut state.ctr);
            }
            let start = BLOCK_LEN - state.unused;
            let available = if state.unused == 0 {
                BLOCK_LEN
            } else {
                state.unused
            };
            let take = (input.len() - pos).min(available);
            let stream_start = if state.unused == 0 { 0 } else { start };
            xor_slice(
                &mut out[pos..pos + take],
                &input[pos..pos + take],
                &state.keystream[stream_start..stream_start + take],
            );
            if encrypting {
                state.ciphertext.extend_from_slice(&out[pos..pos + take]);
            } else {
                state.ciphertext.extend_from_slice(&input[pos..pos + take]);
            }
            pos += take;
            state.unused = available - take;
        }
        Ok(())
    }

    fn eax_encrypt(&self, state: &mut EaxState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        self.ensure_eax_nonce(state)?;
        if state.tag.is_some() {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        self.eax_crypt(state, out, input, true)
    }

    fn eax_decrypt(&self, state: &mut EaxState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        self.ensure_eax_nonce(state)?;
        if state.tag.is_some() {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        self.eax_crypt(state, out, input, false)
    }

    fn eax_crypt(
        &self,
        state: &mut EaxState,
        out: &mut [u8],
        input: &[u8],
        encrypting: bool,
    ) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut pos = 0usize;
        while pos < input.len() {
            if state.unused == 0 {
                state.keystream = state.ctr;
                cipher.encrypt_block(&mut state.keystream);
                inc_be(&mut state.ctr);
            }
            let start = BLOCK_LEN - state.unused;
            let available = if state.unused == 0 {
                BLOCK_LEN
            } else {
                state.unused
            };
            let take = (input.len() - pos).min(available);
            let stream_start = if state.unused == 0 { 0 } else { start };
            xor_slice(
                &mut out[pos..pos + take],
                &input[pos..pos + take],
                &state.keystream[stream_start..stream_start + take],
            );
            if encrypting {
                state.ciphertext.extend_from_slice(&out[pos..pos + take]);
            } else {
                state.ciphertext.extend_from_slice(&input[pos..pos + take]);
            }
            pos += take;
            state.unused = available - take;
        }
        Ok(())
    }

    fn ccm_encrypt(&self, state: &mut CcmState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        self.ccm_crypt(state, out, input, true)
    }

    fn ccm_decrypt(&self, state: &mut CcmState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        self.ccm_crypt(state, out, input, false)
    }

    fn ccm_crypt(
        &self,
        state: &mut CcmState,
        out: &mut [u8],
        input: &[u8],
        encrypting: bool,
    ) -> Result<(), u32> {
        let Some(remaining) = state.msg_remaining else {
            return Err(err(error::GPG_ERR_INV_STATE));
        };
        if state.tag.is_some()
            || state.aad_remaining != Some(0)
            || state.nonce.is_empty()
            || state.tag_len == 0
        {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        if input.len() as u64 > remaining {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let mut tmp = CtrState {
            iv: [0u8; BLOCK_LEN],
            ctr: state.ctr,
            keystream: state.keystream,
            unused: state.unused,
        };
        self.ctr_crypt(&mut tmp, out, input)?;
        state.ctr = tmp.ctr;
        state.keystream = tmp.keystream;
        state.unused = tmp.unused;
        state.msg_remaining = Some(remaining - input.len() as u64);
        if encrypting {
            state.plaintext.extend_from_slice(input);
        } else {
            state.plaintext.extend_from_slice(&out[..input.len()]);
        }
        Ok(())
    }

    fn ocb_encrypt(&self, state: &mut OcbState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        self.ocb_crypt(state, out, input, true)
    }

    fn ocb_decrypt(&self, state: &mut OcbState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        self.ocb_crypt(state, out, input, false)
    }

    fn ocb_crypt(
        &self,
        state: &mut OcbState,
        out: &mut [u8],
        input: &[u8],
        encrypting: bool,
    ) -> Result<(), u32> {
        if state.nonce.is_empty() || state.data_finalized {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if !self.finalize_requested && input.len() % BLOCK_LEN != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }

        let cipher = self.base_cipher()?;
        let key = self.ocb_key()?;
        let mut pos = 0usize;
        while input.len() - pos >= BLOCK_LEN {
            state.data_blocks += 1;
            xor_block_in_place(&mut state.offset, key.l(state.data_blocks));
            let mut block = xor_block(
                &state.offset,
                &input[pos..pos + BLOCK_LEN].try_into().unwrap(),
            );
            if encrypting {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
            xor_block_in_place(&mut block, &state.offset);
            out[pos..pos + BLOCK_LEN].copy_from_slice(&block);
            if encrypting {
                state
                    .plaintext
                    .extend_from_slice(&input[pos..pos + BLOCK_LEN]);
            } else {
                state.plaintext.extend_from_slice(&block);
            }
            pos += BLOCK_LEN;
        }

        if pos < input.len() {
            if !self.finalize_requested {
                return Err(err(error::GPG_ERR_INV_LENGTH));
            }
            xor_block_in_place(&mut state.offset, &key.l_star);
            let mut pad = state.offset;
            cipher.encrypt_block(&mut pad);
            let tail = &input[pos..];
            if encrypting {
                xor_slice(&mut out[pos..pos + tail.len()], tail, &pad[..tail.len()]);
                state.plaintext.extend_from_slice(tail);
            } else {
                let mut plain = vec![0u8; tail.len()];
                xor_slice(&mut plain, tail, &pad[..tail.len()]);
                out[pos..pos + tail.len()].copy_from_slice(&plain);
                state.plaintext.extend_from_slice(&plain);
            }
        }

        if self.finalize_requested {
            state.data_finalized = true;
        }
        Ok(())
    }

    fn xts_crypt(
        &self,
        state: &mut XtsState,
        out: &mut [u8],
        input: &[u8],
        encrypting: bool,
    ) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() < BLOCK_LEN {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() > (BLOCK_LEN << 20) {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let data_cipher = self.base_cipher()?;
        let tweak_cipher = self.tweak_cipher()?;
        let mut tweak = state.iv;
        tweak_cipher.encrypt_block(&mut tweak);
        let mut pos = 0usize;
        let mut remaining = input.len();
        let mut nblocks = input.len() / BLOCK_LEN;
        if !encrypting && input.len() % BLOCK_LEN != 0 {
            nblocks -= 1;
        }
        while nblocks > 0 {
            let mut block = xor_block(&tweak, &input[pos..pos + BLOCK_LEN].try_into().unwrap());
            if encrypting {
                data_cipher.encrypt_block(&mut block);
            } else {
                data_cipher.decrypt_block(&mut block);
            }
            xor_block_in_place(&mut block, &tweak);
            out[pos..pos + BLOCK_LEN].copy_from_slice(&block);
            pos += BLOCK_LEN;
            remaining -= BLOCK_LEN;
            nblocks -= 1;
            xts_gfmul_by_a(&mut tweak);
        }

        if remaining != 0 {
            if !encrypting {
                let mut next_tweak = tweak;
                xts_gfmul_by_a(&mut next_tweak);
                let mut block = xor_block(
                    &next_tweak,
                    &input[pos..pos + BLOCK_LEN].try_into().unwrap(),
                );
                data_cipher.decrypt_block(&mut block);
                xor_block_in_place(&mut block, &next_tweak);
                out[pos..pos + BLOCK_LEN].copy_from_slice(&block);
                pos += BLOCK_LEN;
                remaining -= BLOCK_LEN;
            }
            debug_assert!(remaining < BLOCK_LEN);
            let prev = pos - BLOCK_LEN;
            let mut tmp = [0u8; BLOCK_LEN];
            tmp.copy_from_slice(&out[prev..prev + BLOCK_LEN]);
            tmp[..remaining].copy_from_slice(&input[pos..pos + remaining]);
            let stolen = out[prev..prev + remaining].to_vec();
            out[pos..pos + remaining].copy_from_slice(&stolen);
            xor_block_in_place(&mut tmp, &tweak);
            if encrypting {
                data_cipher.encrypt_block(&mut tmp);
            } else {
                data_cipher.decrypt_block(&mut tmp);
            }
            xor_block_in_place(&mut tmp, &tweak);
            out[prev..prev + BLOCK_LEN].copy_from_slice(&tmp);
        }

        inc_be(&mut state.iv);
        Ok(())
    }

    fn siv_encrypt(&self, state: &mut SivState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if state.tag_finalized || state.decryption_tag.is_some() {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        out[..input.len()].copy_from_slice(input);
        let tag: Block = if self.algo.is_aes() {
            let headers = self.siv_headers(state);
            match self.raw_key.len() {
                32 => {
                    let mut siv = <Aes128Siv as KeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    siv.encrypt_inout_detached(headers, (&mut out[..input.len()]).into())
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                48 => {
                    let mut siv = <Aes192Siv as KeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    siv.encrypt_inout_detached(headers, (&mut out[..input.len()]).into())
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                64 => {
                    let mut siv = <Aes256Siv as KeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    siv.encrypt_inout_detached(headers, (&mut out[..input.len()]).into())
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                _ => return Err(err(error::GPG_ERR_INV_KEYLEN)),
            }
        } else {
            let tag = self.siv_generic_tag(state, input)?;
            let ctr_key = &self.raw_key[self.raw_key.len() / 2..];
            let mut ctr = tag;
            let mut q_lo = u64::from_be_bytes(ctr[8..16].try_into().unwrap());
            q_lo &= !((1u64 << 31) | (1u64 << 63));
            ctr[8..16].copy_from_slice(&q_lo.to_be_bytes());
            let mut ctr_state = CtrState {
                iv: [0u8; BLOCK_LEN],
                ctr,
                keystream: [0u8; BLOCK_LEN],
                unused: 0,
            };
            let ctr_cipher = AesCipher::new(self.algo, ctr_key)?;
            ctr_crypt_with_cipher(&ctr_cipher, &mut ctr_state, &mut out[..input.len()], input)?;
            tag
        };
        state.computed_tag = Some(tag);
        state.tag_finalized = true;
        Ok(())
    }

    fn siv_decrypt(&self, state: &mut SivState, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if state.tag_finalized {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        let tag = state
            .decryption_tag
            .ok_or_else(|| err(error::GPG_ERR_INV_STATE))?;
        out[..input.len()].copy_from_slice(input);
        let ctr_key = &self.raw_key[self.raw_key.len() / 2..];
        let mut ctr = tag;
        let mut q_lo = u64::from_be_bytes(ctr[8..16].try_into().unwrap());
        q_lo &= !((1u64 << 31) | (1u64 << 63));
        ctr[8..16].copy_from_slice(&q_lo.to_be_bytes());
        let mut ctr_state = CtrState {
            iv: [0u8; BLOCK_LEN],
            ctr,
            keystream: [0u8; BLOCK_LEN],
            unused: 0,
        };
        let ctr_cipher = AesCipher::new(self.algo, ctr_key)?;
        ctr_crypt_with_cipher(&ctr_cipher, &mut ctr_state, &mut out[..input.len()], input)?;

        let expected: Block = if self.algo.is_aes() {
            let headers = self.siv_headers(state);
            let mut tag_input = out[..input.len()].to_vec();
            match self.raw_key.len() {
                32 => {
                    let mut siv = <Aes128Siv as KeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    siv.encrypt_inout_detached(headers, (&mut tag_input[..]).into())
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                48 => {
                    let mut siv = <Aes192Siv as KeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    siv.encrypt_inout_detached(headers, (&mut tag_input[..]).into())
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                64 => {
                    let mut siv = <Aes256Siv as KeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    siv.encrypt_inout_detached(headers, (&mut tag_input[..]).into())
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                _ => return Err(err(error::GPG_ERR_INV_KEYLEN)),
            }
        } else {
            self.siv_generic_tag(state, &out[..input.len()])?
        };
        state.computed_tag = Some(expected);
        state.tag_finalized = true;
        if bool::from(expected.ct_eq(&tag)) {
            Ok(())
        } else {
            out[..input.len()].fill(0);
            Err(err(error::GPG_ERR_CHECKSUM))
        }
    }

    fn gcm_siv_encrypt(
        &self,
        state: &mut GcmSivState,
        out: &mut [u8],
        input: &[u8],
    ) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if state.tag_set || state.nonce.is_none() || state.data_finalized {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        let nonce = state.nonce.ok_or_else(|| err(error::GPG_ERR_INV_STATE))?;
        let nonce = GcmSivNonce::try_from(&nonce[..]).map_err(|_| err(error::GPG_ERR_INV_ARG))?;
        if !state.aad_finalized {
            state.aad_finalized = true;
        }
        out[..input.len()].copy_from_slice(input);
        let tag: Block = if self.algo.is_aes() {
            match self.raw_key.len() {
                16 => {
                    let cipher = <Aes128GcmSiv as GcmSivKeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    cipher
                        .encrypt_inout_detached(
                            &nonce,
                            state.aad.as_slice(),
                            (&mut out[..input.len()]).into(),
                        )
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                32 => {
                    let cipher = <Aes256GcmSiv as GcmSivKeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    cipher
                        .encrypt_inout_detached(
                            &nonce,
                            state.aad.as_slice(),
                            (&mut out[..input.len()]).into(),
                        )
                        .map_err(|_| err(error::GPG_ERR_INTERNAL))?
                        .into()
                }
                _ => return Err(err(error::GPG_ERR_INV_KEYLEN)),
            }
        } else {
            let nonce_bytes: [u8; 12] = nonce.as_slice().try_into().unwrap();
            let (enc_cipher, mut polyval) = self.gcm_siv_derive_keys(&nonce_bytes)?;
            polyval.update_padded(state.aad.as_slice());
            polyval.update_padded(input);
            let tag =
                self.gcm_siv_finish_tag(&mut polyval, &nonce_bytes, state.aad.len(), input.len(), &enc_cipher);
            let mut counter_block = tag;
            counter_block[15] |= 0x80;
            ctr32le_crypt_with_cipher(&enc_cipher, &counter_block, &mut out[..input.len()], input)?;
            tag
        };
        state.tag_value = Some(tag);
        state.tag_set = true;
        state.data_finalized = true;
        Ok(())
    }

    fn gcm_siv_decrypt(
        &self,
        state: &mut GcmSivState,
        out: &mut [u8],
        input: &[u8],
    ) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if !state.tag_set || state.nonce.is_none() || state.data_finalized {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        let nonce = state.nonce.ok_or_else(|| err(error::GPG_ERR_INV_STATE))?;
        let tag = state
            .decryption_tag
            .ok_or_else(|| err(error::GPG_ERR_INV_STATE))?;
        let nonce = GcmSivNonce::try_from(&nonce[..]).map_err(|_| err(error::GPG_ERR_INV_ARG))?;
        let tag = GcmSivTag::try_from(&tag[..]).map_err(|_| err(error::GPG_ERR_INV_ARG))?;
        if !state.aad_finalized {
            state.aad_finalized = true;
        }
        out[..input.len()].copy_from_slice(input);
        state.data_finalized = true;
        let decrypt_result = if self.algo.is_aes() {
            match self.raw_key.len() {
                16 => {
                    let cipher = <Aes128GcmSiv as GcmSivKeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    cipher
                        .decrypt_inout_detached(
                            &nonce,
                            state.aad.as_slice(),
                            (&mut out[..input.len()]).into(),
                            &tag,
                        )
                        .map_err(|_| err(error::GPG_ERR_CHECKSUM))
                }
                32 => {
                    let cipher = <Aes256GcmSiv as GcmSivKeyInit>::new_from_slice(&self.raw_key)
                        .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?;
                    cipher
                        .decrypt_inout_detached(
                            &nonce,
                            state.aad.as_slice(),
                            (&mut out[..input.len()]).into(),
                            &tag,
                        )
                        .map_err(|_| err(error::GPG_ERR_CHECKSUM))
                }
                _ => return Err(err(error::GPG_ERR_INV_KEYLEN)),
            }
        } else {
            let nonce_bytes: [u8; 12] = nonce.as_slice().try_into().unwrap();
            let (enc_cipher, mut polyval) = self.gcm_siv_derive_keys(&nonce_bytes)?;
            let mut counter_block: Block = tag.into();
            counter_block[15] |= 0x80;
            ctr32le_crypt_with_cipher(&enc_cipher, &counter_block, &mut out[..input.len()], input)?;
            polyval.update_padded(state.aad.as_slice());
            polyval.update_padded(&out[..input.len()]);
            let expected =
                self.gcm_siv_finish_tag(&mut polyval, &nonce_bytes, state.aad.len(), input.len(), &enc_cipher);
            state.tag_value = Some(expected);
            if bool::from(expected.ct_eq(tag.as_slice().try_into().unwrap())) {
                Ok(())
            } else {
                Err(err(error::GPG_ERR_CHECKSUM))
            }
        };
        if let Err(code) = decrypt_result {
            out[..input.len()].fill(0);
            return Err(code);
        }
        Ok(())
    }

    fn kw_wrap_with_iv(&self, aiv: [u8; 8], out: &mut [u8], input: &[u8]) -> Result<usize, u32> {
        if input.len() % 8 != 0 || input.len() < 16 {
            return Err(err(error::GPG_ERR_INV_ARG));
        }
        if out.len() < input.len() + 8 {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }

        let cipher = self.base_cipher()?;
        let blocks = input.len() / 8;
        out[..8].copy_from_slice(&aiv);
        out[8..8 + input.len()].copy_from_slice(input);
        for round in 0..6 {
            for block_idx in 1..=blocks {
                let mut buf = [0u8; BLOCK_LEN];
                buf[..8].copy_from_slice(&out[..8]);
                buf[8..].copy_from_slice(&out[block_idx * 8..(block_idx + 1) * 8]);
                cipher.encrypt_block(&mut buf);
                let counter = ((round * blocks) + block_idx) as u64;
                let counter_bytes = counter.to_be_bytes();
                for idx in 0..8 {
                    out[idx] = buf[idx] ^ counter_bytes[idx];
                }
                out[block_idx * 8..(block_idx + 1) * 8].copy_from_slice(&buf[8..]);
            }
        }
        Ok(input.len() + 8)
    }

    fn kw_unwrap_with_iv(&self, aiv: [u8; 8], out: &mut [u8], input: &[u8]) -> Result<usize, u32> {
        if input.len() % 8 != 0 || input.len() < 24 {
            return Err(err(error::GPG_ERR_INV_ARG));
        }
        if out.len() + 8 < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }

        let cipher = self.base_cipher()?;
        let blocks = (input.len() / 8) - 1;
        let plaintext_len = input.len() - 8;
        let out = &mut out[..plaintext_len];
        out.copy_from_slice(&input[8..]);
        let mut a = [0u8; 8];
        a.copy_from_slice(&input[..8]);

        for round in (0..6).rev() {
            for block_idx in (1..=blocks).rev() {
                let counter = ((round * blocks) + block_idx) as u64;
                let counter_bytes = counter.to_be_bytes();
                let mut buf = [0u8; BLOCK_LEN];
                for idx in 0..8 {
                    buf[idx] = a[idx] ^ counter_bytes[idx];
                }
                buf[8..].copy_from_slice(&out[(block_idx - 1) * 8..block_idx * 8]);
                cipher.decrypt_block(&mut buf);
                a.copy_from_slice(&buf[..8]);
                out[(block_idx - 1) * 8..block_idx * 8].copy_from_slice(&buf[8..]);
            }
        }

        if !bool::from(a.ct_eq(&aiv)) {
            return Err(err(error::GPG_ERR_CHECKSUM));
        }
        Ok(plaintext_len)
    }
}

fn map_aeskw_error(error: aes_kw::Error) -> u32 {
    match error {
        aes_kw::Error::InvalidOutputSize { .. } => err(error::GPG_ERR_BUFFER_TOO_SHORT),
        aes_kw::Error::InvalidDataSize => err(error::GPG_ERR_INV_LENGTH),
        aes_kw::Error::IntegrityCheckFailed => err(error::GPG_ERR_CHECKSUM),
    }
}

fn ctr_crypt_with_cipher(
    cipher: &AesCipher,
    state: &mut CtrState,
    out: &mut [u8],
    input: &[u8],
) -> Result<(), u32> {
    if out.len() < input.len() {
        return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
    }
    let mut pos = 0usize;
    if input.len() <= state.unused {
        let start = BLOCK_LEN - state.unused;
        xor_slice(
            &mut out[..input.len()],
            input,
            &state.keystream[start..start + input.len()],
        );
        state.unused -= input.len();
        return Ok(());
    }
    if state.unused != 0 {
        let start = BLOCK_LEN - state.unused;
        let count = state.unused;
        xor_slice(
            &mut out[..count],
            &input[..count],
            &state.keystream[start..],
        );
        pos += count;
        state.unused = 0;
    }
    while pos < input.len() {
        state.keystream = state.ctr;
        cipher.encrypt_block(&mut state.keystream);
        inc_be(&mut state.ctr);
        let remaining = input.len() - pos;
        let take = remaining.min(BLOCK_LEN);
        xor_slice(
            &mut out[pos..pos + take],
            &input[pos..pos + take],
            &state.keystream[..take],
        );
        pos += take;
        if take < BLOCK_LEN {
            state.unused = BLOCK_LEN - take;
        }
    }
    Ok(())
}

fn ctr32le_crypt_with_cipher(
    cipher: &AesCipher,
    counter_block: &Block,
    out: &mut [u8],
    input: &[u8],
) -> Result<(), u32> {
    if out.len() < input.len() {
        return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
    }

    let mut counter = u32::from_le_bytes(counter_block[..4].try_into().unwrap());
    let mut pos = 0usize;
    while pos < input.len() {
        let mut keystream = *counter_block;
        keystream[..4].copy_from_slice(&counter.to_le_bytes());
        cipher.encrypt_block(&mut keystream);
        let take = (input.len() - pos).min(BLOCK_LEN);
        xor_slice(
            &mut out[pos..pos + take],
            &input[pos..pos + take],
            &keystream[..take],
        );
        counter = counter.wrapping_add(1);
        pos += take;
    }
    Ok(())
}

fn cbc_mac_bytes(cipher: &AesCipher, mac: &mut Block, data: &[u8]) {
    for chunk in data.chunks(BLOCK_LEN) {
        let block = if chunk.len() == BLOCK_LEN {
            chunk.try_into().unwrap()
        } else {
            pad_zero(chunk)
        };
        xor_block_in_place(mac, &block);
        cipher.encrypt_block(mac);
    }
}

fn cmac16_raw_with_cipher(cipher: &AesCipher, data: &[u8]) -> Block {
    let mut l = [0u8; BLOCK_LEN];
    cipher.encrypt_block(&mut l);

    let mut k1 = l;
    double_ocb(&mut k1);
    let mut k2 = k1;
    double_ocb(&mut k2);

    let full_last = data.len() % BLOCK_LEN == 0 && !data.is_empty();
    let split = if full_last {
        data.len() - BLOCK_LEN
    } else {
        data.len() - (data.len() % BLOCK_LEN)
    };

    let mut mac = [0u8; BLOCK_LEN];
    for chunk in data[..split].chunks(BLOCK_LEN) {
        let block: Block = chunk.try_into().unwrap();
        xor_block_in_place(&mut mac, &block);
        cipher.encrypt_block(&mut mac);
    }

    let mut last = [0u8; BLOCK_LEN];
    let tail = &data[split..];
    if full_last {
        last.copy_from_slice(tail);
        xor_block_in_place(&mut last, &k1);
    } else {
        last[..tail.len()].copy_from_slice(tail);
        last[tail.len()] = 0x80;
        xor_block_in_place(&mut last, &k2);
    }
    xor_block_in_place(&mut mac, &last);
    cipher.encrypt_block(&mut mac);
    mac
}

fn cmac16_with_cipher(cipher: &AesCipher, domain: u8, data: &[u8]) -> Block {
    let mut msg = Vec::with_capacity(BLOCK_LEN + data.len());
    msg.extend_from_slice(&[0u8; BLOCK_LEN - 1]);
    msg.push(domain);
    msg.extend_from_slice(data);
    cmac16_raw_with_cipher(cipher, &msg)
}

fn pad_zero(input: &[u8]) -> Block {
    let mut out = [0u8; BLOCK_LEN];
    out[..input.len()].copy_from_slice(input);
    out
}

fn ccm_initial_counter(nonce: &[u8], counter: usize) -> Block {
    let q = 15 - nonce.len();
    let mut ctr = [0u8; BLOCK_LEN];
    ctr[0] = (q - 1) as u8;
    ctr[1..1 + nonce.len()].copy_from_slice(nonce);
    ctr[1 + nonce.len()..].copy_from_slice(&be_len_bytes(counter, q));
    ctr
}

fn gcm_j0(h: &Block, nonce: &[u8]) -> Block {
    if nonce.len() == 12 {
        let mut j0 = [0u8; BLOCK_LEN];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        return j0;
    }
    let mut ghash = GHash::new(&ghash::Key::from(*h));
    ghash.update_padded(nonce);
    let mut lens = [0u8; BLOCK_LEN];
    lens[8..].copy_from_slice(&u64_be((nonce.len() as u64) * 8));
    ghash.update_padded(&lens);
    ghash.finalize().into()
}

const BLOCK8_LEN: usize = 8;

type Block8 = [u8; BLOCK8_LEN];

fn xor_block8(left: &Block8, right: &Block8) -> Block8 {
    let mut out = [0u8; BLOCK8_LEN];
    for idx in 0..BLOCK8_LEN {
        out[idx] = left[idx] ^ right[idx];
    }
    out
}

fn xor_block8_in_place(dst: &mut Block8, src: &Block8) {
    for idx in 0..BLOCK8_LEN {
        dst[idx] ^= src[idx];
    }
}

fn inc_be8(counter: &mut Block8) {
    for byte in counter.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

fn double_cmac8(block: &mut Block8) {
    let mut carry = 0u8;
    for byte in block.iter_mut().rev() {
        let next_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next_carry;
    }
    if carry != 0 {
        block[BLOCK8_LEN - 1] ^= 0x1b;
    }
}

#[derive(Clone)]
enum Block8Cipher {
    Idea(Idea),
    TripleDes(TdesEde3),
    Cast5(Cast5),
    Blowfish(Blowfish),
    Des(Des),
    Rc2(Rc2),
}

impl Block8Cipher {
    fn new(algo: CipherAlgorithm, key: &[u8]) -> Result<Self, u32> {
        match algo {
            CipherAlgorithm::Idea => Idea::new_from_slice(key)
                .map(Self::Idea)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            CipherAlgorithm::TripleDes => TdesEde3::new_from_slice(key)
                .map(Self::TripleDes)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            CipherAlgorithm::Cast5 => Cast5::new_from_slice(key)
                .map(Self::Cast5)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            CipherAlgorithm::Blowfish => Blowfish::new_from_slice(key)
                .map(Self::Blowfish)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            CipherAlgorithm::Des => Des::new_from_slice(key)
                .map(Self::Des)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            CipherAlgorithm::Rc2_40 | CipherAlgorithm::Rc2_128 => Rc2::new_from_slice(key)
                .map(Self::Rc2)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN)),
            _ => Err(err(error::GPG_ERR_CIPHER_ALGO)),
        }
    }

    fn encrypt_block(&self, block: &mut Block8) {
        let mut tmp = cast5::cipher::Block::<Cast5>::default();
        tmp.copy_from_slice(block);
        match self {
            Self::Idea(cipher) => cipher.encrypt_block(&mut tmp),
            Self::TripleDes(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Cast5(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Blowfish(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Des(cipher) => cipher.encrypt_block(&mut tmp),
            Self::Rc2(cipher) => cipher.encrypt_block(&mut tmp),
        }
        block.copy_from_slice(&tmp);
    }

    fn decrypt_block(&self, block: &mut Block8) {
        let mut tmp = cast5::cipher::Block::<Cast5>::default();
        tmp.copy_from_slice(block);
        match self {
            Self::Idea(cipher) => cipher.decrypt_block(&mut tmp),
            Self::TripleDes(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Cast5(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Blowfish(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Des(cipher) => cipher.decrypt_block(&mut tmp),
            Self::Rc2(cipher) => cipher.decrypt_block(&mut tmp),
        }
        block.copy_from_slice(&tmp);
    }
}

#[derive(Default)]
struct CbcState8 {
    iv: Block8,
}

#[derive(Default)]
struct CfbState8 {
    iv: Block8,
    lastiv: Block8,
    unused: usize,
}

#[derive(Default)]
struct OfbState8 {
    iv: Block8,
    unused: usize,
}

#[derive(Default)]
struct CtrState8 {
    iv: Block8,
    ctr: Block8,
    keystream: Block8,
    unused: usize,
}

#[derive(Default)]
struct EaxState8 {
    nonce: Vec<u8>,
    nonce_set: bool,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Option<Block8>,
    ctr: Block8,
    keystream: Block8,
    unused: usize,
}

enum Block8State {
    None,
    Ecb,
    Cbc(CbcState8),
    Cfb(CfbState8),
    Cfb8(CbcState8),
    Ofb(OfbState8),
    Ctr(CtrState8),
    Eax(EaxState8),
}

struct Block8Handle {
    algo: CipherAlgorithm,
    mode: c_int,
    flags: c_uint,
    allow_weak_key: bool,
    raw_key: Vec<u8>,
    base_cipher: Option<Block8Cipher>,
    state: Block8State,
}

impl Drop for Block8Handle {
    fn drop(&mut self) {
        self.raw_key.fill(0);
    }
}

impl Block8Handle {
    fn new(algo: CipherAlgorithm, mode: c_int, flags: c_uint) -> Result<Self, u32> {
        if !mode_supported(mode) || !mode_supported_for_algorithm(mode, algo) {
            return Err(err(error::GPG_ERR_INV_CIPHER_MODE));
        }
        if (flags & GCRY_CIPHER_CBC_CTS) != 0 && (flags & GCRY_CIPHER_CBC_MAC) != 0 {
            return Err(err(error::GPG_ERR_INV_FLAG));
        }

        let mut handle = Self {
            algo,
            mode,
            flags,
            allow_weak_key: false,
            raw_key: Vec::new(),
            base_cipher: None,
            state: Block8State::None,
        };
        handle.state = handle.fresh_state();
        Ok(handle)
    }

    fn fresh_state(&self) -> Block8State {
        match self.mode {
            GCRY_CIPHER_MODE_NONE => Block8State::None,
            GCRY_CIPHER_MODE_ECB => Block8State::Ecb,
            GCRY_CIPHER_MODE_CBC => Block8State::Cbc(CbcState8::default()),
            GCRY_CIPHER_MODE_CFB => Block8State::Cfb(CfbState8::default()),
            GCRY_CIPHER_MODE_CFB8 => Block8State::Cfb8(CbcState8::default()),
            GCRY_CIPHER_MODE_OFB => Block8State::Ofb(OfbState8::default()),
            GCRY_CIPHER_MODE_CTR => Block8State::Ctr(CtrState8::default()),
            GCRY_CIPHER_MODE_EAX => Block8State::Eax(EaxState8::default()),
            _ => Block8State::None,
        }
    }

    fn reset_runtime(&mut self) {
        self.state = self.fresh_state();
    }

    fn base_cipher(&self) -> Result<&Block8Cipher, u32> {
        self.base_cipher
            .as_ref()
            .ok_or_else(|| err(error::GPG_ERR_MISSING_KEY))
    }

    fn setkey(&mut self, key: &[u8]) -> Result<(), u32> {
        let weak_key = matches!(self.algo, CipherAlgorithm::Des | CipherAlgorithm::TripleDes)
            && des::weak_key_test(key).is_err();
        if weak_key && !self.allow_weak_key {
            return Err(err(error::GPG_ERR_WEAK_KEY));
        }

        self.raw_key.clear();
        self.raw_key.extend_from_slice(key);
        self.base_cipher = Some(Block8Cipher::new(self.algo, key)?);
        self.state = self.fresh_state();
        if weak_key {
            Err(err(error::GPG_ERR_WEAK_KEY))
        } else {
            Ok(())
        }
    }

    fn setiv(&mut self, iv: Option<&[u8]>) -> Result<(), u32> {
        let this = self as *const Self;
        match &mut self.state {
            Block8State::None | Block8State::Ecb => Ok(()),
            Block8State::Cbc(state) | Block8State::Cfb8(state) => {
                state.iv = [0u8; BLOCK8_LEN];
                if let Some(iv) = iv {
                    if iv.len() != BLOCK8_LEN {
                        return Err(err(error::GPG_ERR_INV_ARG));
                    }
                    state.iv.copy_from_slice(iv);
                }
                Ok(())
            }
            Block8State::Cfb(state) => {
                state.iv = [0u8; BLOCK8_LEN];
                state.lastiv = [0u8; BLOCK8_LEN];
                state.unused = 0;
                if let Some(iv) = iv {
                    if iv.len() != BLOCK8_LEN {
                        return Err(err(error::GPG_ERR_INV_ARG));
                    }
                    state.iv.copy_from_slice(iv);
                }
                Ok(())
            }
            Block8State::Ofb(state) => {
                state.iv = [0u8; BLOCK8_LEN];
                state.unused = 0;
                if let Some(iv) = iv {
                    if iv.len() != BLOCK8_LEN {
                        return Err(err(error::GPG_ERR_INV_ARG));
                    }
                    state.iv.copy_from_slice(iv);
                }
                Ok(())
            }
            Block8State::Ctr(state) => {
                state.iv = [0u8; BLOCK8_LEN];
                state.ctr = [0u8; BLOCK8_LEN];
                state.keystream = [0u8; BLOCK8_LEN];
                state.unused = 0;
                if let Some(iv) = iv {
                    if iv.len() != BLOCK8_LEN {
                        return Err(err(error::GPG_ERR_INV_ARG));
                    }
                    state.iv.copy_from_slice(iv);
                }
                Ok(())
            }
            Block8State::Eax(state) => unsafe { (&*this).eax_set_nonce(state, iv.unwrap_or(&[])) },
        }
    }

    fn eax_set_nonce(&self, state: &mut EaxState8, nonce: &[u8]) -> Result<(), u32> {
        state.nonce.clear();
        state.nonce.extend_from_slice(nonce);
        state.nonce_set = true;
        state.aad.clear();
        state.ciphertext.clear();
        state.tag = None;
        state.keystream = [0u8; BLOCK8_LEN];
        state.unused = 0;
        state.ctr = self.eax_cmac(0, &state.nonce)?;
        Ok(())
    }

    fn ensure_eax_nonce(&self, state: &mut EaxState8) -> Result<(), u32> {
        if !state.nonce_set {
            self.eax_set_nonce(state, &[])?;
        }
        Ok(())
    }

    fn setctr(&mut self, ctr: Option<&[u8]>) -> Result<(), u32> {
        let Block8State::Ctr(state) = &mut self.state else {
            return Err(err(error::GPG_ERR_INV_ARG));
        };
        state.ctr = [0u8; BLOCK8_LEN];
        state.keystream = [0u8; BLOCK8_LEN];
        state.unused = 0;
        if let Some(ctr) = ctr {
            if ctr.len() != BLOCK8_LEN {
                return Err(err(error::GPG_ERR_INV_ARG));
            }
            state.ctr.copy_from_slice(ctr);
        }
        Ok(())
    }

    fn info(&self, what: c_int, buffer: *mut c_void, nbytes: *mut usize) -> u32 {
        match what {
            GCRYCTL_GET_TAGLEN => {
                if !buffer.is_null() || nbytes.is_null() {
                    return err(error::GPG_ERR_INV_ARG);
                }
                let Block8State::Eax(_) = &self.state else {
                    return err(error::GPG_ERR_INV_CIPHER_MODE);
                };
                unsafe {
                    *nbytes = BLOCK8_LEN;
                }
                0
            }
            _ => err(error::GPG_ERR_INV_OP),
        }
    }

    fn ctl(&mut self, cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
        let result = match cmd {
            GCRYCTL_RESET => {
                self.reset_runtime();
                Ok(())
            }
            GCRYCTL_FINALIZE => {
                if !buffer.is_null() || buflen != 0 {
                    Err(err(error::GPG_ERR_INV_ARG))
                } else {
                    Ok(())
                }
            }
            GCRYCTL_CFB_SYNC => self.cfb_sync(),
            GCRYCTL_SET_CBC_CTS => {
                if buflen != 0 {
                    if (self.flags & GCRY_CIPHER_CBC_MAC) != 0 {
                        Err(err(error::GPG_ERR_INV_FLAG))
                    } else {
                        self.flags |= GCRY_CIPHER_CBC_CTS;
                        Ok(())
                    }
                } else {
                    self.flags &= !GCRY_CIPHER_CBC_CTS;
                    Ok(())
                }
            }
            GCRYCTL_SET_CBC_MAC => {
                if buflen != 0 {
                    if (self.flags & GCRY_CIPHER_CBC_CTS) != 0 {
                        Err(err(error::GPG_ERR_INV_FLAG))
                    } else {
                        self.flags |= GCRY_CIPHER_CBC_MAC;
                        Ok(())
                    }
                } else {
                    self.flags &= !GCRY_CIPHER_CBC_MAC;
                    Ok(())
                }
            }
            GCRYCTL_SET_ALLOW_WEAK_KEY => {
                if !buffer.is_null() || buflen > 1 {
                    Err(err(error::GPG_ERR_CIPHER_ALGO))
                } else {
                    self.allow_weak_key = buflen != 0;
                    Ok(())
                }
            }
            _ => Err(err(error::GPG_ERR_INV_OP)),
        };

        match result {
            Ok(()) => 0,
            Err(code) => code,
        }
    }

    fn cfb_sync(&mut self) -> Result<(), u32> {
        if (self.flags & GCRY_CIPHER_ENABLE_SYNC) == 0 {
            return Ok(());
        }
        let Block8State::Cfb(state) = &mut self.state else {
            return Ok(());
        };
        if state.unused == 0 {
            return Ok(());
        }
        let unused = state.unused;
        let mut next = [0u8; BLOCK8_LEN];
        next[unused..].copy_from_slice(&state.iv[..BLOCK8_LEN - unused]);
        next[..unused].copy_from_slice(&state.lastiv[BLOCK8_LEN - unused..]);
        state.iv = next;
        state.unused = 0;
        Ok(())
    }

    fn authenticate(&mut self, aad: &[u8]) -> Result<(), u32> {
        let this = self as *const Self;
        match &mut self.state {
            Block8State::Eax(state) => {
                unsafe { (&*this).ensure_eax_nonce(state)? };
                if state.tag.is_some() {
                    return Err(err(error::GPG_ERR_INV_STATE));
                }
                state.aad.extend_from_slice(aad);
                Ok(())
            }
            _ => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
        }
    }

    fn encrypt(&mut self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        let this = self as *const Self;
        match &mut self.state {
            Block8State::None => {
                if out.len() < input.len() {
                    return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
                }
                out[..input.len()].copy_from_slice(input);
                Ok(())
            }
            Block8State::Ecb => unsafe { (&*this).ecb_encrypt(out, input) },
            Block8State::Cbc(state) => unsafe { (&*this).cbc_encrypt(state, out, input) },
            Block8State::Cfb(state) => unsafe { (&*this).cfb_encrypt(state, out, input) },
            Block8State::Cfb8(state) => unsafe { (&*this).cfb8_encrypt(state, out, input) },
            Block8State::Ofb(state) => unsafe { (&*this).ofb_crypt(state, out, input) },
            Block8State::Ctr(state) => unsafe { (&*this).ctr_crypt(state, out, input) },
            Block8State::Eax(state) => unsafe { (&*this).eax_encrypt(state, out, input) },
        }
    }

    fn decrypt(&mut self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        let this = self as *const Self;
        match &mut self.state {
            Block8State::None => {
                if out.len() < input.len() {
                    return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
                }
                out[..input.len()].copy_from_slice(input);
                Ok(())
            }
            Block8State::Ecb => unsafe { (&*this).ecb_decrypt(out, input) },
            Block8State::Cbc(state) => unsafe { (&*this).cbc_decrypt(state, out, input) },
            Block8State::Cfb(state) => unsafe { (&*this).cfb_decrypt(state, out, input) },
            Block8State::Cfb8(state) => unsafe { (&*this).cfb8_decrypt(state, out, input) },
            Block8State::Ofb(state) => unsafe { (&*this).ofb_crypt(state, out, input) },
            Block8State::Ctr(state) => unsafe { (&*this).ctr_crypt(state, out, input) },
            Block8State::Eax(state) => unsafe { (&*this).eax_decrypt(state, out, input) },
        }
    }

    fn gettag(&mut self, outtag: &mut [u8]) -> Result<usize, u32> {
        let this = self as *const Self;
        match &mut self.state {
            Block8State::Eax(state) => {
                let tag = unsafe { (&*this).finalize_eax_tag(state)? };
                let n = outtag.len().min(BLOCK8_LEN);
                outtag[..n].copy_from_slice(&tag[..n]);
                Ok(n)
            }
            _ => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
        }
    }

    fn checktag(&mut self, tag: &[u8]) -> Result<(), u32> {
        let this = self as *const Self;
        match &mut self.state {
            Block8State::Eax(state) => {
                let expected = unsafe { (&*this).finalize_eax_tag(state)? };
                if tag.len() <= BLOCK8_LEN && bool::from(expected[..tag.len()].ct_eq(tag)) {
                    Ok(())
                } else {
                    Err(err(error::GPG_ERR_CHECKSUM))
                }
            }
            _ => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
        }
    }

    fn eax_cmac(&self, domain: u8, data: &[u8]) -> Result<Block8, u32> {
        let cipher = self.base_cipher()?;
        let mut l = [0u8; BLOCK8_LEN];
        cipher.encrypt_block(&mut l);

        let mut k1 = l;
        double_cmac8(&mut k1);
        let mut k2 = k1;
        double_cmac8(&mut k2);

        let mut msg = Vec::with_capacity(BLOCK8_LEN + data.len());
        msg.extend_from_slice(&[0u8; BLOCK8_LEN - 1]);
        msg.push(domain);
        msg.extend_from_slice(data);

        let full_last = msg.len() % BLOCK8_LEN == 0;
        let split = if full_last {
            msg.len() - BLOCK8_LEN
        } else {
            msg.len() - (msg.len() % BLOCK8_LEN)
        };

        let mut mac = [0u8; BLOCK8_LEN];
        for chunk in msg[..split].chunks(BLOCK8_LEN) {
            let block: Block8 = chunk.try_into().unwrap();
            xor_block8_in_place(&mut mac, &block);
            cipher.encrypt_block(&mut mac);
        }

        let mut last = [0u8; BLOCK8_LEN];
        let tail = &msg[split..];
        if full_last {
            last.copy_from_slice(tail);
            xor_block8_in_place(&mut last, &k1);
        } else {
            last[..tail.len()].copy_from_slice(tail);
            last[tail.len()] = 0x80;
            xor_block8_in_place(&mut last, &k2);
        }
        xor_block8_in_place(&mut mac, &last);
        cipher.encrypt_block(&mut mac);
        Ok(mac)
    }

    fn compute_eax_tag(&self, state: &EaxState8) -> Result<Block8, u32> {
        if !state.nonce_set {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        let nonce_tag = self.eax_cmac(0, &state.nonce)?;
        let header_tag = self.eax_cmac(1, &state.aad)?;
        let cipher_tag = self.eax_cmac(2, &state.ciphertext)?;
        Ok(xor_block8(
            &xor_block8(&nonce_tag, &header_tag),
            &cipher_tag,
        ))
    }

    fn finalize_eax_tag(&self, state: &mut EaxState8) -> Result<Block8, u32> {
        self.ensure_eax_nonce(state)?;
        if let Some(tag) = state.tag {
            return Ok(tag);
        }
        let tag = self.compute_eax_tag(state)?;
        state.tag = Some(tag);
        Ok(tag)
    }

    fn ecb_encrypt(&self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK8_LEN != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        for (chunk_in, chunk_out) in input.chunks(BLOCK8_LEN).zip(out.chunks_mut(BLOCK8_LEN)) {
            let mut block: Block8 = chunk_in.try_into().unwrap();
            self.base_cipher()?.encrypt_block(&mut block);
            chunk_out.copy_from_slice(&block);
        }
        Ok(())
    }

    fn ecb_decrypt(&self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK8_LEN != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        for (chunk_in, chunk_out) in input.chunks(BLOCK8_LEN).zip(out.chunks_mut(BLOCK8_LEN)) {
            let mut block: Block8 = chunk_in.try_into().unwrap();
            self.base_cipher()?.decrypt_block(&mut block);
            chunk_out.copy_from_slice(&block);
        }
        Ok(())
    }

    fn cbc_encrypt(&self, state: &mut CbcState8, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        let cts_mode = (self.flags & GCRY_CIPHER_CBC_CTS) != 0;
        if cts_mode {
            return self.cbc_cts_encrypt(state, out, input);
        }
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK8_LEN != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let cipher = self.base_cipher()?;
        for (chunk_in, chunk_out) in input.chunks(BLOCK8_LEN).zip(out.chunks_mut(BLOCK8_LEN)) {
            let mut block = xor_block8(&state.iv, &chunk_in.try_into().unwrap());
            cipher.encrypt_block(&mut block);
            state.iv = block;
            chunk_out.copy_from_slice(&block);
        }
        Ok(())
    }

    fn cbc_cts_encrypt(
        &self,
        state: &mut CbcState8,
        out: &mut [u8],
        input: &[u8],
    ) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK8_LEN != 0 && input.len() <= BLOCK8_LEN {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let cipher = self.base_cipher()?;
        let mut iv = state.iv;
        let mut pos = 0usize;
        let mut full_blocks = input.len() / BLOCK8_LEN;
        if input.len() > BLOCK8_LEN && input.len() % BLOCK8_LEN == 0 {
            full_blocks -= 1;
        }
        while pos < full_blocks * BLOCK8_LEN {
            let mut block = xor_block8(&iv, &input[pos..pos + BLOCK8_LEN].try_into().unwrap());
            cipher.encrypt_block(&mut block);
            out[pos..pos + BLOCK8_LEN].copy_from_slice(&block);
            iv = block;
            pos += BLOCK8_LEN;
        }
        if input.len() > BLOCK8_LEN {
            let rest = if input.len() % BLOCK8_LEN == 0 {
                BLOCK8_LEN
            } else {
                input.len() % BLOCK8_LEN
            };
            let prev = pos - BLOCK8_LEN;
            let mut final_block = [0u8; BLOCK8_LEN];
            final_block[..rest].copy_from_slice(&input[pos..pos + rest]);
            for idx in 0..BLOCK8_LEN {
                final_block[idx] ^= iv[idx];
            }
            cipher.encrypt_block(&mut final_block);
            let stolen = out[prev..prev + rest].to_vec();
            out[pos..pos + rest].copy_from_slice(&stolen);
            out[prev..prev + BLOCK8_LEN].copy_from_slice(&final_block);
            iv = final_block;
        }
        state.iv = iv;
        Ok(())
    }

    fn cbc_decrypt(&self, state: &mut CbcState8, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if (self.flags & GCRY_CIPHER_CBC_CTS) != 0 {
            return self.cbc_cts_decrypt(state, out, input);
        }
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK8_LEN != 0 {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let cipher = self.base_cipher()?;
        for (chunk_in, chunk_out) in input.chunks(BLOCK8_LEN).zip(out.chunks_mut(BLOCK8_LEN)) {
            let current: Block8 = chunk_in.try_into().unwrap();
            let mut block = current;
            cipher.decrypt_block(&mut block);
            xor_block8_in_place(&mut block, &state.iv);
            state.iv = current;
            chunk_out.copy_from_slice(&block);
        }
        Ok(())
    }

    fn cbc_cts_decrypt(
        &self,
        state: &mut CbcState8,
        out: &mut [u8],
        input: &[u8],
    ) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if input.len() % BLOCK8_LEN != 0 && input.len() <= BLOCK8_LEN {
            return Err(err(error::GPG_ERR_INV_LENGTH));
        }
        let cipher = self.base_cipher()?;
        let mut iv = state.iv;
        let mut pos = 0usize;
        let mut nblocks = input.len() / BLOCK8_LEN;
        if input.len() > BLOCK8_LEN {
            nblocks -= 1;
            if input.len() % BLOCK8_LEN == 0 {
                nblocks -= 1;
            }
        }
        while pos < nblocks * BLOCK8_LEN {
            let current: Block8 = input[pos..pos + BLOCK8_LEN].try_into().unwrap();
            let mut block = current;
            cipher.decrypt_block(&mut block);
            xor_block8_in_place(&mut block, &iv);
            iv = current;
            out[pos..pos + BLOCK8_LEN].copy_from_slice(&block);
            pos += BLOCK8_LEN;
        }

        if input.len() > BLOCK8_LEN {
            let rest = if input.len() % BLOCK8_LEN == 0 {
                BLOCK8_LEN
            } else {
                input.len() % BLOCK8_LEN
            };
            let last_full = &input[pos..pos + BLOCK8_LEN];
            let tail = &input[pos + BLOCK8_LEN..];

            let mut tmp_iv = [0u8; BLOCK8_LEN];
            tmp_iv[..rest].copy_from_slice(tail);
            let mut decrypted = last_full.try_into().unwrap();
            cipher.decrypt_block(&mut decrypted);
            for idx in 0..rest {
                decrypted[idx] ^= tmp_iv[idx];
            }
            out[pos + BLOCK8_LEN..pos + BLOCK8_LEN + rest].copy_from_slice(&decrypted[..rest]);
            for idx in rest..BLOCK8_LEN {
                tmp_iv[idx] = decrypted[idx];
            }
            let mut block = tmp_iv;
            cipher.decrypt_block(&mut block);
            xor_block8_in_place(&mut block, &iv);
            out[pos..pos + BLOCK8_LEN].copy_from_slice(&block);
            iv = tmp_iv;
        }
        state.iv = iv;
        Ok(())
    }

    fn cfb_encrypt(&self, state: &mut CfbState8, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut inpos = 0usize;
        if input.len() <= state.unused {
            let start = BLOCK8_LEN - state.unused;
            for idx in 0..input.len() {
                let val = state.iv[start + idx] ^ input[idx];
                out[idx] = val;
                state.iv[start + idx] = val;
            }
            state.unused -= input.len();
            return Ok(());
        }
        if state.unused != 0 {
            let count = state.unused;
            let start = BLOCK8_LEN - count;
            for idx in 0..count {
                let val = state.iv[start + idx] ^ input[idx];
                out[idx] = val;
                state.iv[start + idx] = val;
            }
            inpos += count;
            state.unused = 0;
        }
        while input.len() - inpos >= BLOCK8_LEN {
            state.lastiv = state.iv;
            cipher.encrypt_block(&mut state.iv);
            for idx in 0..BLOCK8_LEN {
                let val = state.iv[idx] ^ input[inpos + idx];
                out[inpos + idx] = val;
                state.iv[idx] = val;
            }
            inpos += BLOCK8_LEN;
        }
        if inpos < input.len() {
            state.lastiv = state.iv;
            cipher.encrypt_block(&mut state.iv);
            let remaining = input.len() - inpos;
            for idx in 0..remaining {
                let val = state.iv[idx] ^ input[inpos + idx];
                out[inpos + idx] = val;
                state.iv[idx] = val;
            }
            state.unused = BLOCK8_LEN - remaining;
        }
        Ok(())
    }

    fn cfb_decrypt(&self, state: &mut CfbState8, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut inpos = 0usize;
        if input.len() <= state.unused {
            let start = BLOCK8_LEN - state.unused;
            for idx in 0..input.len() {
                let c = input[idx];
                out[idx] = state.iv[start + idx] ^ c;
                state.iv[start + idx] = c;
            }
            state.unused -= input.len();
            return Ok(());
        }
        if state.unused != 0 {
            let count = state.unused;
            let start = BLOCK8_LEN - count;
            for idx in 0..count {
                let c = input[idx];
                out[idx] = state.iv[start + idx] ^ c;
                state.iv[start + idx] = c;
            }
            inpos += count;
            state.unused = 0;
        }
        while input.len() - inpos >= BLOCK8_LEN {
            state.lastiv = state.iv;
            cipher.encrypt_block(&mut state.iv);
            for idx in 0..BLOCK8_LEN {
                let c = input[inpos + idx];
                out[inpos + idx] = state.iv[idx] ^ c;
                state.iv[idx] = c;
            }
            inpos += BLOCK8_LEN;
        }
        if inpos < input.len() {
            state.lastiv = state.iv;
            cipher.encrypt_block(&mut state.iv);
            let remaining = input.len() - inpos;
            for idx in 0..remaining {
                let c = input[inpos + idx];
                out[inpos + idx] = state.iv[idx] ^ c;
                state.iv[idx] = c;
            }
            state.unused = BLOCK8_LEN - remaining;
        }
        Ok(())
    }

    fn cfb8_encrypt(&self, state: &mut CbcState8, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        for idx in 0..input.len() {
            let mut tmp = state.iv;
            cipher.encrypt_block(&mut tmp);
            out[idx] = tmp[0] ^ input[idx];
            state.iv.copy_within(1.., 0);
            state.iv[BLOCK8_LEN - 1] = out[idx];
        }
        Ok(())
    }

    fn cfb8_decrypt(&self, state: &mut CbcState8, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        for idx in 0..input.len() {
            let mut tmp = state.iv;
            cipher.encrypt_block(&mut tmp);
            let c = input[idx];
            out[idx] = c ^ tmp[0];
            state.iv.copy_within(1.., 0);
            state.iv[BLOCK8_LEN - 1] = c;
        }
        Ok(())
    }

    fn ofb_crypt(&self, state: &mut OfbState8, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut pos = 0usize;
        if input.len() <= state.unused {
            let start = BLOCK8_LEN - state.unused;
            xor_slice(&mut out[..input.len()], input, &state.iv[start..start + input.len()]);
            state.unused -= input.len();
            return Ok(());
        }
        if state.unused != 0 {
            let start = BLOCK8_LEN - state.unused;
            let count = state.unused;
            xor_slice(&mut out[..count], &input[..count], &state.iv[start..]);
            pos += count;
            state.unused = 0;
        }
        while pos < input.len() {
            cipher.encrypt_block(&mut state.iv);
            let remaining = input.len() - pos;
            let take = remaining.min(BLOCK8_LEN);
            xor_slice(
                &mut out[pos..pos + take],
                &input[pos..pos + take],
                &state.iv[..take],
            );
            pos += take;
            if take < BLOCK8_LEN {
                state.unused = BLOCK8_LEN - take;
            }
        }
        Ok(())
    }

    fn ctr_crypt(&self, state: &mut CtrState8, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut pos = 0usize;
        if input.len() <= state.unused {
            let start = BLOCK8_LEN - state.unused;
            xor_slice(
                &mut out[..input.len()],
                input,
                &state.keystream[start..start + input.len()],
            );
            state.unused -= input.len();
            return Ok(());
        }
        if state.unused != 0 {
            let start = BLOCK8_LEN - state.unused;
            let count = state.unused;
            xor_slice(
                &mut out[..count],
                &input[..count],
                &state.keystream[start..],
            );
            pos += count;
            state.unused = 0;
        }
        while pos < input.len() {
            state.keystream = state.ctr;
            cipher.encrypt_block(&mut state.keystream);
            inc_be8(&mut state.ctr);
            let remaining = input.len() - pos;
            let take = remaining.min(BLOCK8_LEN);
            xor_slice(
                &mut out[pos..pos + take],
                &input[pos..pos + take],
                &state.keystream[..take],
            );
            pos += take;
            if take < BLOCK8_LEN {
                state.unused = BLOCK8_LEN - take;
            }
        }
        Ok(())
    }

    fn eax_encrypt(&self, state: &mut EaxState8, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        self.ensure_eax_nonce(state)?;
        if state.tag.is_some() {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        self.eax_crypt(state, out, input, true)
    }

    fn eax_decrypt(&self, state: &mut EaxState8, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        self.ensure_eax_nonce(state)?;
        if state.tag.is_some() {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        self.eax_crypt(state, out, input, false)
    }

    fn eax_crypt(
        &self,
        state: &mut EaxState8,
        out: &mut [u8],
        input: &[u8],
        encrypting: bool,
    ) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let cipher = self.base_cipher()?;
        let mut pos = 0usize;
        while pos < input.len() {
            if state.unused == 0 {
                state.keystream = state.ctr;
                cipher.encrypt_block(&mut state.keystream);
                inc_be8(&mut state.ctr);
            }
            let start = BLOCK8_LEN - state.unused;
            let available = if state.unused == 0 {
                BLOCK8_LEN
            } else {
                state.unused
            };
            let take = (input.len() - pos).min(available);
            let stream_start = if state.unused == 0 { 0 } else { start };
            xor_slice(
                &mut out[pos..pos + take],
                &input[pos..pos + take],
                &state.keystream[stream_start..stream_start + take],
            );
            if encrypting {
                state.ciphertext.extend_from_slice(&out[pos..pos + take]);
            } else {
                state.ciphertext.extend_from_slice(&input[pos..pos + take]);
            }
            pos += take;
            state.unused = available - take;
        }
        Ok(())
    }
}

const STREAM_BLOCK_LEN: usize = 64;
const POLY1305_TAG_LEN: usize = 16;
const CHACHA_SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
const CHACHA_TAU: [u32; 4] = [0x6170_7865, 0x3120_646e, 0x7962_2d36, 0x6b20_6574];
const SALSA_SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
const SALSA_TAU: [u32; 4] = [0x6170_7865, 0x3120_646e, 0x7962_2d36, 0x6b20_6574];

fn read_le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

fn salsa_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let (mut x0, mut x1, mut x2, mut x3) = (state[a], state[b], state[c], state[d]);
    x1 ^= x0.wrapping_add(x3).rotate_left(7);
    x2 ^= x1.wrapping_add(x0).rotate_left(9);
    x3 ^= x2.wrapping_add(x1).rotate_left(13);
    x0 ^= x3.wrapping_add(x2).rotate_left(18);
    state[a] = x0;
    state[b] = x1;
    state[c] = x2;
    state[d] = x3;
}

fn chacha_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let (mut x0, mut x1, mut x2, mut x3) = (state[a], state[b], state[c], state[d]);
    x0 = x0.wrapping_add(x1);
    x3 ^= x0;
    x3 = x3.rotate_left(16);
    x2 = x2.wrapping_add(x3);
    x1 ^= x2;
    x1 = x1.rotate_left(12);
    x0 = x0.wrapping_add(x1);
    x3 ^= x0;
    x3 = x3.rotate_left(8);
    x2 = x2.wrapping_add(x3);
    x1 ^= x2;
    x1 = x1.rotate_left(7);
    state[a] = x0;
    state[b] = x1;
    state[c] = x2;
    state[d] = x3;
}

#[derive(Clone)]
struct SalsaState {
    state: [u32; 16],
    rounds: usize,
    block: [u8; STREAM_BLOCK_LEN],
    unused: usize,
}

impl SalsaState {
    fn new(key: &[u8], iv: &[u8], rounds: usize) -> Result<Self, u32> {
        if !matches!(key.len(), 16 | 32) {
            return Err(err(error::GPG_ERR_INV_KEYLEN));
        }

        let mut state = [0u32; 16];
        let constants = if key.len() == 32 {
            SALSA_SIGMA
        } else {
            SALSA_TAU
        };
        state[0] = constants[0];
        state[5] = constants[1];
        state[10] = constants[2];
        state[15] = constants[3];
        for (idx, chunk) in key[..16].chunks_exact(4).enumerate() {
            state[1 + idx] = read_le_u32(chunk);
        }
        if key.len() == 32 {
            for (idx, chunk) in key[16..].chunks_exact(4).enumerate() {
                state[11 + idx] = read_le_u32(chunk);
            }
        } else {
            state[11] = state[1];
            state[12] = state[2];
            state[13] = state[3];
            state[14] = state[4];
        }
        state[6] = read_le_u32(&iv[..4]);
        state[7] = read_le_u32(&iv[4..8]);
        state[8] = 0;
        state[9] = 0;

        Ok(Self {
            state,
            rounds,
            block: [0u8; STREAM_BLOCK_LEN],
            unused: 0,
        })
    }

    fn generate_block(&mut self) -> [u8; STREAM_BLOCK_LEN] {
        let mut working = self.state;
        for _ in (0..self.rounds).step_by(2) {
            salsa_quarter_round(&mut working, 0, 4, 8, 12);
            salsa_quarter_round(&mut working, 5, 9, 13, 1);
            salsa_quarter_round(&mut working, 10, 14, 2, 6);
            salsa_quarter_round(&mut working, 15, 3, 7, 11);
            salsa_quarter_round(&mut working, 0, 1, 2, 3);
            salsa_quarter_round(&mut working, 5, 6, 7, 4);
            salsa_quarter_round(&mut working, 10, 11, 8, 9);
            salsa_quarter_round(&mut working, 15, 12, 13, 14);
        }

        let mut out = [0u8; STREAM_BLOCK_LEN];
        for (idx, word) in working.iter_mut().enumerate() {
            *word = word.wrapping_add(self.state[idx]);
            out[idx * 4..(idx + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }

        self.state[8] = self.state[8].wrapping_add(1);
        if self.state[8] == 0 {
            self.state[9] = self.state[9].wrapping_add(1);
        }
        out
    }

    fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut pos = 0;
        while pos < data.len() {
            if self.unused == 0 {
                self.block = self.generate_block();
                self.unused = STREAM_BLOCK_LEN;
            }
            let offset = STREAM_BLOCK_LEN - self.unused;
            let take = self.unused.min(data.len() - pos);
            for idx in 0..take {
                data[pos + idx] ^= self.block[offset + idx];
            }
            self.unused -= take;
            pos += take;
        }
    }
}

#[derive(Clone)]
struct ChaChaState {
    state: [u32; 16],
    block: [u8; STREAM_BLOCK_LEN],
    unused: usize,
}

impl ChaChaState {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self, u32> {
        if !matches!(key.len(), 16 | 32) {
            return Err(err(error::GPG_ERR_INV_KEYLEN));
        }

        let mut state = [0u32; 16];
        let constants = if key.len() == 32 {
            CHACHA_SIGMA
        } else {
            CHACHA_TAU
        };
        state[..4].copy_from_slice(&constants);
        for (idx, chunk) in key[..16].chunks_exact(4).enumerate() {
            state[4 + idx] = read_le_u32(chunk);
        }
        if key.len() == 32 {
            for (idx, chunk) in key[16..].chunks_exact(4).enumerate() {
                state[8 + idx] = read_le_u32(chunk);
            }
        } else {
            state[8] = state[4];
            state[9] = state[5];
            state[10] = state[6];
            state[11] = state[7];
        }

        match iv.len() {
            16 => {
                state[12] = read_le_u32(&iv[..4]);
                state[13] = read_le_u32(&iv[4..8]);
                state[14] = read_le_u32(&iv[8..12]);
                state[15] = read_le_u32(&iv[12..16]);
            }
            12 => {
                state[12] = 0;
                state[13] = read_le_u32(&iv[..4]);
                state[14] = read_le_u32(&iv[4..8]);
                state[15] = read_le_u32(&iv[8..12]);
            }
            8 => {
                state[12] = 0;
                state[13] = 0;
                state[14] = read_le_u32(&iv[..4]);
                state[15] = read_le_u32(&iv[4..8]);
            }
            _ => {}
        }

        Ok(Self {
            state,
            block: [0u8; STREAM_BLOCK_LEN],
            unused: 0,
        })
    }

    fn generate_block(&mut self) -> [u8; STREAM_BLOCK_LEN] {
        let mut working = self.state;
        for _ in 0..10 {
            chacha_quarter_round(&mut working, 0, 4, 8, 12);
            chacha_quarter_round(&mut working, 1, 5, 9, 13);
            chacha_quarter_round(&mut working, 2, 6, 10, 14);
            chacha_quarter_round(&mut working, 3, 7, 11, 15);
            chacha_quarter_round(&mut working, 0, 5, 10, 15);
            chacha_quarter_round(&mut working, 1, 6, 11, 12);
            chacha_quarter_round(&mut working, 2, 7, 8, 13);
            chacha_quarter_round(&mut working, 3, 4, 9, 14);
        }

        let mut out = [0u8; STREAM_BLOCK_LEN];
        for (idx, word) in working.iter_mut().enumerate() {
            *word = word.wrapping_add(self.state[idx]);
            out[idx * 4..(idx + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }

        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
        out
    }

    fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut pos = 0;
        while pos < data.len() {
            if self.unused == 0 {
                self.block = self.generate_block();
                self.unused = STREAM_BLOCK_LEN;
            }
            let offset = STREAM_BLOCK_LEN - self.unused;
            let take = self.unused.min(data.len() - pos);
            for idx in 0..take {
                data[pos + idx] ^= self.block[offset + idx];
            }
            self.unused -= take;
            pos += take;
        }
    }
}

fn normalize_salsa_iv(iv: Option<&[u8]>) -> Vec<u8> {
    let mut nonce = vec![0u8; 8];
    if let Some(iv) = iv.filter(|iv| iv.len() == 8) {
        nonce.copy_from_slice(iv);
    }
    nonce
}

fn normalize_chacha_iv(iv: Option<&[u8]>) -> Vec<u8> {
    match iv {
        Some(iv) if matches!(iv.len(), 8 | 12 | 16) => iv.to_vec(),
        _ => vec![0u8; 8],
    }
}

enum StreamCipherVariant {
    Arcfour(Rc4),
    Salsa20(SalsaState),
    Salsa12(SalsaState),
    ChaCha20(ChaChaState),
}

struct StreamHandle {
    algo: CipherAlgorithm,
    raw_key: Vec<u8>,
    iv: Vec<u8>,
    cipher: Option<StreamCipherVariant>,
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        self.raw_key.fill(0);
        self.iv.fill(0);
    }
}

impl StreamHandle {
    fn new(algo: CipherAlgorithm, mode: c_int, _flags: c_uint) -> Result<Self, u32> {
        if mode != GCRY_CIPHER_MODE_STREAM || !mode_supported_for_algorithm(mode, algo) {
            return Err(err(error::GPG_ERR_INV_CIPHER_MODE));
        }
        Ok(Self {
            algo,
            raw_key: Vec::new(),
            iv: Vec::new(),
            cipher: None,
        })
    }

    fn normalized_iv(&self, iv: Option<&[u8]>) -> Vec<u8> {
        match self.algo {
            CipherAlgorithm::Arcfour => Vec::new(),
            CipherAlgorithm::Salsa20 | CipherAlgorithm::Salsa20R12 => normalize_salsa_iv(iv),
            CipherAlgorithm::Chacha20 => normalize_chacha_iv(iv),
            _ => Vec::new(),
        }
    }

    fn rebuild_cipher(&mut self) -> Result<(), u32> {
        if self.raw_key.is_empty() {
            self.cipher = None;
            return Ok(());
        }

        self.cipher = Some(match self.algo {
            CipherAlgorithm::Arcfour => Rc4::new_from_slice(&self.raw_key)
                .map(StreamCipherVariant::Arcfour)
                .map_err(|_| err(error::GPG_ERR_INV_KEYLEN))?,
            CipherAlgorithm::Salsa20 => {
                StreamCipherVariant::Salsa20(SalsaState::new(&self.raw_key, &self.iv, 20)?)
            }
            CipherAlgorithm::Salsa20R12 => {
                StreamCipherVariant::Salsa12(SalsaState::new(&self.raw_key, &self.iv, 12)?)
            }
            CipherAlgorithm::Chacha20 => {
                StreamCipherVariant::ChaCha20(ChaChaState::new(&self.raw_key, &self.iv)?)
            }
            _ => return Err(err(error::GPG_ERR_CIPHER_ALGO)),
        });
        Ok(())
    }

    fn setkey(&mut self, key: &[u8]) -> Result<(), u32> {
        match self.algo {
            CipherAlgorithm::Salsa20 | CipherAlgorithm::Salsa20R12 | CipherAlgorithm::Chacha20 => {
                if !matches!(key.len(), 16 | 32) {
                    return Err(err(error::GPG_ERR_INV_KEYLEN));
                }
            }
            _ => {}
        }

        self.raw_key.clear();
        self.raw_key.extend_from_slice(key);
        if self.iv.is_empty() {
            self.iv = self.normalized_iv(None);
        }
        self.rebuild_cipher()
    }

    fn setiv(&mut self, iv: Option<&[u8]>) -> Result<(), u32> {
        self.iv = self.normalized_iv(iv);
        self.rebuild_cipher()
    }

    fn reset_runtime(&mut self) -> Result<(), u32> {
        self.rebuild_cipher()
    }

    fn ctl(&mut self, cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
        let result = match cmd {
            GCRYCTL_RESET => self.reset_runtime(),
            GCRYCTL_FINALIZE => {
                if !buffer.is_null() || buflen != 0 {
                    Err(err(error::GPG_ERR_INV_ARG))
                } else {
                    Ok(())
                }
            }
            GCRYCTL_SET_ALLOW_WEAK_KEY => {
                if !buffer.is_null() || buflen > 1 {
                    Err(err(error::GPG_ERR_CIPHER_ALGO))
                } else {
                    Ok(())
                }
            }
            _ => Err(err(error::GPG_ERR_INV_OP)),
        };

        match result {
            Ok(()) => 0,
            Err(code) => code,
        }
    }

    fn info(&self, _what: c_int, _buffer: *mut c_void, _nbytes: *mut usize) -> u32 {
        err(error::GPG_ERR_INV_OP)
    }

    fn crypt(&mut self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        out[..input.len()].copy_from_slice(input);
        let cipher = self
            .cipher
            .as_mut()
            .ok_or_else(|| err(error::GPG_ERR_MISSING_KEY))?;
        match cipher {
            StreamCipherVariant::Arcfour(cipher) => cipher.apply_keystream(&mut out[..input.len()]),
            StreamCipherVariant::Salsa20(cipher) | StreamCipherVariant::Salsa12(cipher) => {
                cipher.apply_keystream(&mut out[..input.len()])
            }
            StreamCipherVariant::ChaCha20(cipher) => cipher.apply_keystream(&mut out[..input.len()]),
        }
        Ok(())
    }
}

struct Poly1305Handle {
    raw_key: Vec<u8>,
    iv: Vec<u8>,
    poly_key: Option<[u8; 32]>,
    cipher: Option<ChaChaState>,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Option<[u8; POLY1305_TAG_LEN]>,
    aad_finalized: bool,
}

impl Drop for Poly1305Handle {
    fn drop(&mut self) {
        self.raw_key.fill(0);
        self.iv.fill(0);
        if let Some(poly_key) = &mut self.poly_key {
            poly_key.fill(0);
        }
    }
}

impl Poly1305Handle {
    fn new(algo: CipherAlgorithm, mode: c_int, _flags: c_uint) -> Result<Self, u32> {
        if algo != CipherAlgorithm::Chacha20 || mode != GCRY_CIPHER_MODE_POLY1305 {
            return Err(err(error::GPG_ERR_INV_CIPHER_MODE));
        }
        Ok(Self {
            raw_key: Vec::new(),
            iv: Vec::new(),
            poly_key: None,
            cipher: None,
            aad: Vec::new(),
            ciphertext: Vec::new(),
            tag: None,
            aad_finalized: false,
        })
    }

    fn clear_runtime(&mut self) {
        if let Some(poly_key) = &mut self.poly_key {
            poly_key.fill(0);
        }
        self.poly_key = None;
        self.cipher = None;
        self.aad.clear();
        self.ciphertext.clear();
        self.tag = None;
        self.aad_finalized = false;
    }

    fn setkey(&mut self, key: &[u8]) -> Result<(), u32> {
        if !matches!(key.len(), 16 | 32) {
            return Err(err(error::GPG_ERR_INV_KEYLEN));
        }
        self.raw_key.clear();
        self.raw_key.extend_from_slice(key);
        self.iv.clear();
        self.clear_runtime();
        Ok(())
    }

    fn build_runtime(&mut self) -> Result<(), u32> {
        if self.raw_key.is_empty() {
            return Err(err(error::GPG_ERR_MISSING_KEY));
        }
        if self.iv.is_empty() {
            self.iv = vec![0u8; 8];
        }
        let mut cipher = ChaChaState::new(&self.raw_key, &self.iv)?;
        let block = cipher.generate_block();
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&block[..32]);
        self.poly_key = Some(poly_key);
        self.cipher = Some(cipher);
        self.aad.clear();
        self.ciphertext.clear();
        self.tag = None;
        self.aad_finalized = false;
        Ok(())
    }

    fn ensure_runtime(&mut self) -> Result<(), u32> {
        if self.cipher.is_none() || self.poly_key.is_none() {
            self.build_runtime()?;
        }
        Ok(())
    }

    fn setiv(&mut self, iv: Option<&[u8]>, explicit_zero_length: bool) -> Result<(), u32> {
        if explicit_zero_length {
            return Err(err(error::GPG_ERR_INV_ARG));
        }
        self.iv = normalize_chacha_iv(iv);
        self.clear_runtime();
        if !self.raw_key.is_empty() {
            self.build_runtime()?;
        }
        Ok(())
    }

    fn reset_runtime(&mut self) {
        self.iv.clear();
        self.clear_runtime();
    }

    fn ctl(&mut self, cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
        let result = match cmd {
            GCRYCTL_RESET => {
                self.reset_runtime();
                Ok(())
            }
            GCRYCTL_FINALIZE => {
                if !buffer.is_null() || buflen != 0 {
                    Err(err(error::GPG_ERR_INV_ARG))
                } else {
                    Ok(())
                }
            }
            GCRYCTL_SET_ALLOW_WEAK_KEY => {
                if !buffer.is_null() || buflen > 1 {
                    Err(err(error::GPG_ERR_CIPHER_ALGO))
                } else {
                    Ok(())
                }
            }
            _ => Err(err(error::GPG_ERR_INV_OP)),
        };

        match result {
            Ok(()) => 0,
            Err(code) => code,
        }
    }

    fn info(&self, what: c_int, buffer: *mut c_void, nbytes: *mut usize) -> u32 {
        match what {
            GCRYCTL_GET_TAGLEN => {
                if !buffer.is_null() || nbytes.is_null() {
                    return err(error::GPG_ERR_INV_ARG);
                }
                unsafe {
                    *nbytes = POLY1305_TAG_LEN;
                }
                0
            }
            _ => err(error::GPG_ERR_INV_OP),
        }
    }

    fn authenticate(&mut self, aad: &[u8]) -> Result<(), u32> {
        self.ensure_runtime()?;
        if self.aad_finalized || self.tag.is_some() {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        self.aad.extend_from_slice(aad);
        Ok(())
    }

    fn crypt(&mut self, out: &mut [u8], input: &[u8], encrypting: bool) -> Result<(), u32> {
        if out.len() < input.len() {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        if self.tag.is_some() {
            return Err(err(error::GPG_ERR_INV_STATE));
        }
        self.ensure_runtime()?;
        if !self.aad_finalized {
            self.aad_finalized = true;
        }
        out[..input.len()].copy_from_slice(input);
        self.cipher
            .as_mut()
            .ok_or_else(|| err(error::GPG_ERR_MISSING_KEY))?
            .apply_keystream(&mut out[..input.len()]);
        if encrypting {
            self.ciphertext.extend_from_slice(&out[..input.len()]);
        } else {
            self.ciphertext.extend_from_slice(input);
        }
        Ok(())
    }

    fn append_padded(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(data);
        let remainder = data.len() % POLY1305_TAG_LEN;
        if remainder != 0 {
            out.resize(out.len() + (POLY1305_TAG_LEN - remainder), 0);
        }
    }

    fn finalize_tag(&mut self) -> Result<[u8; POLY1305_TAG_LEN], u32> {
        self.ensure_runtime()?;
        if let Some(tag) = self.tag {
            return Ok(tag);
        }

        self.aad_finalized = true;
        let mut message = Vec::with_capacity(
            self.aad.len() + self.ciphertext.len() + (POLY1305_TAG_LEN * 2),
        );
        Self::append_padded(&mut message, &self.aad);
        Self::append_padded(&mut message, &self.ciphertext);
        message.extend_from_slice(&(self.aad.len() as u64).to_le_bytes());
        message.extend_from_slice(&(self.ciphertext.len() as u64).to_le_bytes());

        let poly_key = self.poly_key.ok_or_else(|| err(error::GPG_ERR_INV_STATE))?;
        let tag = Poly1305::new((&poly_key).into()).compute_unpadded(&message);
        let mut out = [0u8; POLY1305_TAG_LEN];
        out.copy_from_slice(&tag);
        self.tag = Some(out);
        Ok(out)
    }

    fn gettag(&mut self, outtag: &mut [u8]) -> Result<usize, u32> {
        if outtag.len() < POLY1305_TAG_LEN {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let tag = self.finalize_tag()?;
        outtag[..POLY1305_TAG_LEN].copy_from_slice(&tag);
        Ok(POLY1305_TAG_LEN)
    }

    fn checktag(&mut self, tag: &[u8]) -> Result<(), u32> {
        if tag.len() < POLY1305_TAG_LEN {
            return Err(err(error::GPG_ERR_BUFFER_TOO_SHORT));
        }
        let expected = self.finalize_tag()?;
        if tag.len() != POLY1305_TAG_LEN || !bool::from(expected.ct_eq(tag.try_into().unwrap())) {
            Err(err(error::GPG_ERR_CHECKSUM))
        } else {
            Ok(())
        }
    }
}

enum CipherObject {
    Block16(CipherHandle),
    Block8(Block8Handle),
    Stream(StreamHandle),
    Poly1305(Poly1305Handle),
}

impl CipherObject {
    fn missing_key(&self) -> bool {
        match self {
            Self::Block16(handle) => handle.mode != GCRY_CIPHER_MODE_NONE && handle.raw_key.is_empty(),
            Self::Block8(handle) => handle.mode != GCRY_CIPHER_MODE_NONE && handle.raw_key.is_empty(),
            Self::Stream(handle) => handle.raw_key.is_empty(),
            Self::Poly1305(handle) => handle.raw_key.is_empty(),
        }
    }

    fn ctl(&mut self, cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
        match self {
            Self::Block16(handle) => handle.ctl(cmd, buffer, buflen),
            Self::Block8(handle) => handle.ctl(cmd, buffer, buflen),
            Self::Stream(handle) => handle.ctl(cmd, buffer, buflen),
            Self::Poly1305(handle) => handle.ctl(cmd, buffer, buflen),
        }
    }

    fn info(&self, what: c_int, buffer: *mut c_void, nbytes: *mut usize) -> u32 {
        match self {
            Self::Block16(handle) => handle.info(what, buffer, nbytes),
            Self::Block8(handle) => handle.info(what, buffer, nbytes),
            Self::Stream(handle) => handle.info(what, buffer, nbytes),
            Self::Poly1305(handle) => handle.info(what, buffer, nbytes),
        }
    }

    fn encrypt(&mut self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        match self {
            Self::Block16(handle) => handle.encrypt(out, input),
            Self::Block8(handle) => handle.encrypt(out, input),
            Self::Stream(handle) => handle.crypt(out, input),
            Self::Poly1305(handle) => handle.crypt(out, input, true),
        }
    }

    fn decrypt(&mut self, out: &mut [u8], input: &[u8]) -> Result<(), u32> {
        match self {
            Self::Block16(handle) => handle.decrypt(out, input),
            Self::Block8(handle) => handle.decrypt(out, input),
            Self::Stream(handle) => handle.crypt(out, input),
            Self::Poly1305(handle) => handle.crypt(out, input, false),
        }
    }

    fn setkey(&mut self, key: &[u8]) -> Result<(), u32> {
        match self {
            Self::Block16(handle) => handle.setkey(key),
            Self::Block8(handle) => handle.setkey(key),
            Self::Stream(handle) => handle.setkey(key),
            Self::Poly1305(handle) => handle.setkey(key),
        }
    }

    fn setiv(&mut self, iv: Option<&[u8]>, explicit_zero_length: bool) -> Result<(), u32> {
        match self {
            Self::Block16(handle) => handle.setiv(iv, explicit_zero_length),
            Self::Block8(handle) => handle.setiv(iv),
            Self::Stream(handle) => handle.setiv(iv),
            Self::Poly1305(handle) => handle.setiv(iv, explicit_zero_length),
        }
    }

    fn setctr(&mut self, ctr: Option<&[u8]>) -> Result<(), u32> {
        match self {
            Self::Block16(handle) => handle.setctr(ctr),
            Self::Block8(handle) => handle.setctr(ctr),
            Self::Stream(_) => Err(err(error::GPG_ERR_INV_ARG)),
            Self::Poly1305(_) => Err(err(error::GPG_ERR_INV_ARG)),
        }
    }

    fn authenticate(&mut self, aad: &[u8]) -> Result<(), u32> {
        match self {
            Self::Block16(handle) => handle.authenticate(aad),
            Self::Block8(handle) => handle.authenticate(aad),
            Self::Stream(_) => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
            Self::Poly1305(handle) => handle.authenticate(aad),
        }
    }

    fn gettag(&mut self, outtag: &mut [u8]) -> Result<usize, u32> {
        match self {
            Self::Block16(handle) => handle.gettag(outtag),
            Self::Block8(handle) => handle.gettag(outtag),
            Self::Stream(_) => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
            Self::Poly1305(handle) => handle.gettag(outtag),
        }
    }

    fn checktag(&mut self, intag: &[u8]) -> Result<(), u32> {
        match self {
            Self::Block16(handle) => handle.checktag(intag),
            Self::Block8(handle) => handle.checktag(intag),
            Self::Stream(_) => Err(err(error::GPG_ERR_INV_CIPHER_MODE)),
            Self::Poly1305(handle) => handle.checktag(intag),
        }
    }
}

fn handle_mut(handle: gcry_cipher_hd_t) -> Result<&'static mut CipherObject, u32> {
    if handle.is_null() {
        Err(err(error::GPG_ERR_INV_ARG))
    } else {
        Ok(unsafe { &mut *(handle.cast::<CipherObject>()) })
    }
}

pub(crate) fn open(handle: *mut gcry_cipher_hd_t, algo: c_int, mode: c_int, flags: c_uint) -> u32 {
    if handle.is_null() {
        return err(error::GPG_ERR_INV_ARG);
    }

    let Some(algo) = algorithm_from_id(algo) else {
        return err(error::GPG_ERR_CIPHER_ALGO);
    };
    if !algorithm_is_locally_supported(algo) {
        return err(error::GPG_ERR_CIPHER_ALGO);
    }

    let created = match if mode == GCRY_CIPHER_MODE_POLY1305 {
        Poly1305Handle::new(algo, mode, flags).map(CipherObject::Poly1305)
    } else if algo.is_stream_cipher() {
        StreamHandle::new(algo, mode, flags).map(CipherObject::Stream)
    } else if algo.is_block16() {
        CipherHandle::new(algo, mode, flags).map(CipherObject::Block16)
    } else if algo.is_block8() {
        Block8Handle::new(algo, mode, flags).map(CipherObject::Block8)
    } else {
        Err(err(error::GPG_ERR_CIPHER_ALGO))
    } {
        Ok(handle) => handle,
        Err(code) => return code,
    };

    unsafe {
        *handle = Box::into_raw(Box::new(created)).cast();
    }
    0
}

pub(crate) fn close(handle: gcry_cipher_hd_t) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle.cast::<CipherObject>()));
    }
}

pub(crate) fn ctl(handle: gcry_cipher_hd_t, cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32 {
    match handle_mut(handle) {
        Ok(handle) => handle.ctl(cmd, buffer, buflen),
        Err(code) => code,
    }
}

pub(crate) fn info(
    handle: gcry_cipher_hd_t,
    what: c_int,
    buffer: *mut c_void,
    nbytes: *mut usize,
) -> u32 {
    match handle_mut(handle) {
        Ok(handle) => handle.info(what, buffer, nbytes),
        Err(code) => code,
    }
}

pub(crate) fn mode_from_oid(string: *const i8) -> c_int {
    if string.is_null() {
        return 0;
    }
    let oid = unsafe { CStr::from_ptr(string) };
    mode_from_oid_str(oid)
}

pub(crate) fn crypt(
    handle: gcry_cipher_hd_t,
    out: *mut c_void,
    outsize: usize,
    input: *const c_void,
    inlen: usize,
    encrypting: bool,
) -> u32 {
    let handle = match handle_mut(handle) {
        Ok(handle) => handle,
        Err(code) => return code,
    };
    if handle.missing_key() {
        return err(error::GPG_ERR_MISSING_KEY);
    }

    let input = match copy_input(
        out,
        outsize,
        input,
        if input.is_null() { outsize } else { inlen },
    ) {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let output = match out_slice(out, outsize) {
        Ok(slice) => slice,
        Err(code) => return code,
    };

    let result = if encrypting {
        handle.encrypt(output, &input)
    } else {
        handle.decrypt(output, &input)
    };

    match result {
        Ok(()) => 0,
        Err(code) => {
            if encrypting && !output.is_empty() {
                output.fill(0x42);
            }
            code
        }
    }
}

pub(crate) fn setkey(handle: gcry_cipher_hd_t, key: *const c_void, keylen: usize) -> u32 {
    let handle = match handle_mut(handle) {
        Ok(handle) => handle,
        Err(code) => return code,
    };
    if keylen > 0 && key.is_null() {
        return err(error::GPG_ERR_INV_ARG);
    }
    let key = unsafe { slice::from_raw_parts(key.cast::<u8>(), keylen) };
    match handle.setkey(key) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

pub(crate) fn setiv(handle: gcry_cipher_hd_t, iv: *const c_void, ivlen: usize) -> u32 {
    let handle = match handle_mut(handle) {
        Ok(handle) => handle,
        Err(code) => return code,
    };
    if ivlen > 0 && iv.is_null() {
        return err(error::GPG_ERR_INV_ARG);
    }
    let iv = if ivlen == 0 {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(iv.cast::<u8>(), ivlen) })
    };
    match handle.setiv(iv, ivlen == 0) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

pub(crate) fn setctr(handle: gcry_cipher_hd_t, ctr: *const c_void, ctrlen: usize) -> u32 {
    let handle = match handle_mut(handle) {
        Ok(handle) => handle,
        Err(code) => return code,
    };
    let ctr = if ctr.is_null() || ctrlen == 0 {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(ctr.cast::<u8>(), ctrlen) })
    };
    match handle.setctr(ctr) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

pub(crate) fn authenticate(handle: gcry_cipher_hd_t, abuf: *const c_void, abuflen: usize) -> u32 {
    let handle = match handle_mut(handle) {
        Ok(handle) => handle,
        Err(code) => return code,
    };
    if abuflen > 0 && abuf.is_null() {
        return err(error::GPG_ERR_INV_ARG);
    }
    let aad = unsafe { slice::from_raw_parts(abuf.cast::<u8>(), abuflen) };
    match handle.authenticate(aad) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

pub(crate) fn gettag(handle: gcry_cipher_hd_t, outtag: *mut c_void, taglen: usize) -> u32 {
    let handle = match handle_mut(handle) {
        Ok(handle) => handle,
        Err(code) => return code,
    };
    let out = match out_slice(outtag, taglen) {
        Ok(slice) => slice,
        Err(code) => return code,
    };
    match handle.gettag(out) {
        Ok(_) => 0,
        Err(code) => code,
    }
}

pub(crate) fn checktag(handle: gcry_cipher_hd_t, intag: *const c_void, taglen: usize) -> u32 {
    let handle = match handle_mut(handle) {
        Ok(handle) => handle,
        Err(code) => return code,
    };
    if taglen > 0 && intag.is_null() {
        return err(error::GPG_ERR_INV_ARG);
    }
    let tag = unsafe { slice::from_raw_parts(intag.cast::<u8>(), taglen) };
    match handle.checktag(tag) {
        Ok(()) => 0,
        Err(code) => code,
    }
}
