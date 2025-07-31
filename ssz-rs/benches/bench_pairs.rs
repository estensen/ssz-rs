use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ssz_rs::hash_pairs_bulk;

const N: usize = 1000;
const IN_LEN: usize = 64 * N;
const OUT_LEN: usize = 32 * N;

fn bench_pairs_bulk(c: &mut Criterion) {
    let input = vec![0u8; IN_LEN];
    let mut output = vec![0u8; OUT_LEN];

    c.bench_function("hash_pairs_bulk 1000 pairs", |b| {
        b.iter(|| {
            hash_pairs_bulk(black_box(&input), black_box(&mut output));
        });
    });
}

criterion_group!(benches, bench_pairs_bulk);
criterion_main!(benches);
