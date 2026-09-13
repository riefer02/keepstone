//! Benchmarks for the cryptographic core.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use keepstone_crypto::{aead, shamir, stream, Identity, SealedKey};

fn aead_bench(c: &mut Criterion) {
    let key = [1u8; 32];
    let nonce = [2u8; 24];
    let message = vec![0u8; 4096];
    let ciphertext = aead::seal(&key, &nonce, b"", &message).unwrap();

    c.bench_function("aead_seal_4k", |b| {
        b.iter(|| aead::seal(black_box(&key), black_box(&nonce), b"", black_box(&message)).unwrap())
    });
    c.bench_function("aead_open_4k", |b| {
        b.iter(|| {
            aead::open(
                black_box(&key),
                black_box(&nonce),
                b"",
                black_box(&ciphertext),
            )
            .unwrap()
        })
    });
}

fn stream_bench(c: &mut Criterion) {
    let key = [1u8; 32];
    let data = vec![0u8; 1024 * 1024];
    let (framing, chunks) = stream::encrypt(&key, &data).unwrap();

    let mut group = c.benchmark_group("stream");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("encrypt_1m", |b| {
        b.iter(|| stream::encrypt(black_box(&key), black_box(&data)).unwrap())
    });
    group.bench_function("decrypt_1m", |b| {
        b.iter(|| {
            stream::decrypt(black_box(&key), black_box(&framing), black_box(&chunks)).unwrap()
        })
    });
    group.finish();
}

fn sealed_bench(c: &mut Criterion) {
    let recipient = Identity::generate();
    let key = [3u8; 32];
    let sealed = SealedKey::seal(&key, &recipient.ecdh_public()).unwrap();
    let secret = recipient.ecdh_secret_bytes();

    c.bench_function("sealed_box_seal", |b| {
        b.iter(|| SealedKey::seal(black_box(&key), black_box(&recipient.ecdh_public())).unwrap())
    });
    c.bench_function("sealed_box_open", |b| {
        b.iter(|| black_box(&sealed).open(black_box(&secret)).unwrap())
    });
}

fn shamir_bench(c: &mut Criterion) {
    let secret = [7u8; 32];
    let shares = shamir::split(&secret, 3, 5).unwrap();
    let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];

    c.bench_function("shamir_split_3of5", |b| {
        b.iter(|| shamir::split(black_box(&secret), 3, 5).unwrap())
    });
    c.bench_function("shamir_combine_3of5", |b| {
        b.iter(|| shamir::combine(black_box(&subset)).unwrap())
    });
}

criterion_group!(
    benches,
    aead_bench,
    stream_bench,
    sealed_bench,
    shamir_bench
);
criterion_main!(benches);
