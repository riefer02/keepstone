//! Benchmarks for the RFC 6962 Merkle log.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use keepstone_log::merkle::{
    consistency_proof, inclusion_proof, leaf_hash, mth, verify_consistency, verify_inclusion, Hash,
};

const N: usize = 10_000;
const M: usize = 5_000;

fn leaves(n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| leaf_hash(format!("entry-{i}").as_bytes()))
        .collect()
}

fn merkle_bench(c: &mut Criterion) {
    let all = leaves(N);
    let root = mth(&all);
    let proof = inclusion_proof(&all, M).unwrap();
    let consistency = consistency_proof(&all, M).unwrap();
    let old_root = mth(&all[..M]);

    c.bench_function("mth_10000", |b| b.iter(|| mth(black_box(&all))));
    c.bench_function("inclusion_proof_10000", |b| {
        b.iter(|| inclusion_proof(black_box(&all), M).unwrap())
    });
    c.bench_function("verify_inclusion_10000", |b| {
        b.iter(|| {
            verify_inclusion(
                black_box(&all[M]),
                M,
                all.len(),
                black_box(&proof),
                black_box(&root),
            )
        })
    });
    c.bench_function("consistency_proof_10000", |b| {
        b.iter(|| consistency_proof(black_box(&all), M).unwrap())
    });
    c.bench_function("verify_consistency_10000", |b| {
        b.iter(|| {
            verify_consistency(
                M,
                all.len(),
                black_box(&old_root),
                black_box(&root),
                black_box(&consistency),
            )
        })
    });
}

criterion_group!(benches, merkle_bench);
criterion_main!(benches);
