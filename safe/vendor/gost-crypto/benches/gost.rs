#![allow(missing_docs, clippy::semicolon_if_nothing_returned)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use gost_crypto::{Gost28147, Gost341194, SBOX_CRYPTOPRO};
use digest::Update;

fn make_key()   -> [u8; 32] { [0x42u8; 32] }
fn make_block() -> [u8; 8]  { [1, 2, 3, 4, 5, 6, 7, 8] }

fn bench_cipher(c: &mut Criterion) {
    let key    = make_key();
    let block  = make_block();
    let cipher = Gost28147::with_sbox(&key, &SBOX_CRYPTOPRO);

    c.bench_function("cipher/encrypt_block", |b| {
        b.iter(|| cipher.encrypt_block_raw(black_box(block)));
    });
}

fn bench_hash(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash/gost341194");

    for size in [64usize, 1024, 16 * 1024, 64 * 1024] {
        let data = vec![0xABu8; size];
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| {
                let mut h = Gost341194::new_with_sbox(black_box(&SBOX_CRYPTOPRO));
                h.update(black_box(d));
                h.finalize_bytes()
            })
        });
    }

    g.finish();
}

criterion_group!(benches, bench_cipher, bench_hash);
criterion_main!(benches);
