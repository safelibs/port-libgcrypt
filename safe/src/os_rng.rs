use std::fs::File;
use std::io::Read;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

fn fallback_state() -> &'static Mutex<u64> {
    static STATE: OnceLock<Mutex<u64>> = OnceLock::new();
    STATE.get_or_init(|| {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0x6d5a_56b7_c3dd_e41b);
        Mutex::new(seed ^ 0x9e37_79b9_7f4a_7c15)
    })
}

fn fill_with_fallback(buffer: &mut [u8]) {
    let mut state = match fallback_state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    for byte in buffer {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        *byte = (x & 0xff) as u8;
    }
}

pub(crate) fn fill_random(buffer: &mut [u8]) {
    if buffer.is_empty() {
        return;
    }

    match File::open("/dev/urandom").and_then(|mut file| file.read_exact(buffer)) {
        Ok(()) => {}
        Err(_) => fill_with_fallback(buffer),
    }
}
