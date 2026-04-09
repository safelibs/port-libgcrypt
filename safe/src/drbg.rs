use std::sync::{Mutex, OnceLock};

use crate::os_rng;

const CHACHA_BLOCK_BYTES: usize = 64;
const SEED_BYTES: usize = 48;
const RESEED_INTERVAL: u64 = 1024;

#[derive(Clone, Copy)]
pub(crate) struct EntropyPool {
    bytes: [u8; 64],
    cursor: usize,
    dirty: bool,
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self {
            bytes: [0u8; 64],
            cursor: 0,
            dirty: false,
        }
    }
}

impl EntropyPool {
    pub(crate) fn absorb(&mut self, input: &[u8]) {
        for (index, byte) in input.iter().copied().enumerate() {
            let slot = (self.cursor + index) % self.bytes.len();
            self.bytes[slot] ^= byte.rotate_left((slot % 7) as u32);
            let mirror = (slot * 13 + 11) % self.bytes.len();
            self.bytes[mirror] = self.bytes[mirror].wrapping_add(byte ^ (index as u8));
        }
        self.cursor = (self.cursor + input.len()) % self.bytes.len();
        self.dirty |= !input.is_empty();
    }

    pub(crate) fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub(crate) fn drain_into(&mut self, seed: &mut [u8]) {
        if !self.dirty {
            return;
        }

        for (index, byte) in seed.iter_mut().enumerate() {
            let a = self.bytes[index % self.bytes.len()];
            let b = self.bytes[(index * 9 + 5) % self.bytes.len()];
            *byte ^= a.rotate_left((index % 5) as u32) ^ b.wrapping_add(index as u8);
        }

        for (index, slot) in self.bytes.iter_mut().enumerate() {
            *slot = slot
                .wrapping_add((index as u8).wrapping_mul(17))
                .rotate_left(((index % 7) + 1) as u32);
        }
        self.dirty = false;
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DrbgStats {
    pub(crate) bytes_generated: u64,
    pub(crate) reseeds: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct DrbgState {
    key: [u32; 8],
    counter: u32,
    nonce: [u32; 3],
    last_pid: u32,
    seeded: bool,
    requests_since_reseed: u64,
    bytes_generated: u64,
    reseeds: u64,
    label: [u8; 8],
}

impl DrbgState {
    pub(crate) const fn new(label: [u8; 8]) -> Self {
        Self {
            key: [0; 8],
            counter: 0,
            nonce: [0; 3],
            last_pid: 0,
            seeded: false,
            requests_since_reseed: 0,
            bytes_generated: 0,
            reseeds: 0,
            label,
        }
    }

    fn apply_seed(&mut self, seed: &[u8; SEED_BYTES]) {
        for (index, word) in self.key.iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_le_bytes(seed[offset..offset + 4].try_into().unwrap());
        }
        self.counter = u32::from_le_bytes(seed[32..36].try_into().unwrap());
        if self.counter == 0 {
            self.counter = 1;
        }
        for (index, word) in self.nonce.iter_mut().enumerate() {
            let offset = 36 + index * 4;
            *word = u32::from_le_bytes(seed[offset..offset + 4].try_into().unwrap());
        }
        self.last_pid = os_rng::process_id();
        self.seeded = true;
        self.requests_since_reseed = 0;
        self.reseeds += 1;
    }

    fn stir_seed_material(&self, seed: &mut [u8; SEED_BYTES]) {
        let pid = os_rng::process_id().to_le_bytes();
        let time = os_rng::monotonic_nanos().to_le_bytes();

        for (index, byte) in seed.iter_mut().enumerate() {
            *byte ^= self.label[index % self.label.len()];
            *byte ^= pid[index % pid.len()].rotate_left((index % 7) as u32);
            *byte = byte.wrapping_add(time[index % time.len()]);
        }
    }

    fn reseed(&mut self, pool: &mut EntropyPool) {
        let mut seed = [0u8; SEED_BYTES];
        os_rng::fill_random(&mut seed);
        pool.drain_into(&mut seed);
        self.stir_seed_material(&mut seed);
        self.apply_seed(&seed);
    }

    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    fn block(&self, counter: u32) -> [u8; CHACHA_BLOCK_BYTES] {
        let constants = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&constants);
        state[4..12].copy_from_slice(&self.key);
        state[12] = counter;
        state[13..16].copy_from_slice(&self.nonce);

        let mut working = state;
        for _ in 0..10 {
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }

        for (word, base) in working.iter_mut().zip(state) {
            *word = word.wrapping_add(base);
        }

        let mut out = [0u8; CHACHA_BLOCK_BYTES];
        for (index, word) in working.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn generate_raw(&mut self, output: &mut [u8]) {
        let mut offset = 0usize;
        while offset < output.len() {
            let block = self.block(self.counter);
            self.counter = self.counter.wrapping_add(1);
            if self.counter == 0 {
                self.nonce[0] = self.nonce[0].wrapping_add(1);
            }
            let take = (output.len() - offset).min(CHACHA_BLOCK_BYTES);
            output[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
        }
        self.bytes_generated = self.bytes_generated.saturating_add(output.len() as u64);
    }

    fn rekey(&mut self, pool: &mut EntropyPool) {
        let mut seed = [0u8; SEED_BYTES];
        self.generate_raw(&mut seed);
        pool.drain_into(&mut seed);
        self.stir_seed_material(&mut seed);
        self.apply_seed(&seed);
    }

    pub(crate) fn generate(&mut self, output: &mut [u8], pool: &mut EntropyPool) {
        if !self.seeded
            || self.last_pid != os_rng::process_id()
            || self.requests_since_reseed >= RESEED_INTERVAL
            || pool.is_dirty()
        {
            self.reseed(pool);
        }

        self.generate_raw(output);
        self.requests_since_reseed = self.requests_since_reseed.saturating_add(1);
        self.rekey(pool);
    }

    pub(crate) fn stats(&self) -> DrbgStats {
        DrbgStats {
            bytes_generated: self.bytes_generated,
            reseeds: self.reseeds,
        }
    }
}

pub(crate) struct DrbgManager {
    pub(crate) random: DrbgState,
    pub(crate) nonce: DrbgState,
    pub(crate) random_pool: EntropyPool,
    pub(crate) nonce_pool: EntropyPool,
}

impl Default for DrbgManager {
    fn default() -> Self {
        Self {
            random: DrbgState::new(*b"random\0\0"),
            nonce: DrbgState::new(*b"nonce\0\0\0"),
            random_pool: EntropyPool::default(),
            nonce_pool: EntropyPool::default(),
        }
    }
}

impl DrbgManager {
    pub(crate) fn generate_random(&mut self, output: &mut [u8]) {
        let mut pool = std::mem::take(&mut self.random_pool);
        self.random.generate(output, &mut pool);
        self.random_pool = pool;
    }

    pub(crate) fn generate_nonce(&mut self, output: &mut [u8]) {
        let mut pool = std::mem::take(&mut self.nonce_pool);
        self.nonce.generate(output, &mut pool);
        self.nonce_pool = pool;
    }
}

pub(crate) fn manager() -> &'static Mutex<DrbgManager> {
    static MANAGER: OnceLock<Mutex<DrbgManager>> = OnceLock::new();
    MANAGER.get_or_init(|| Mutex::new(DrbgManager::default()))
}
