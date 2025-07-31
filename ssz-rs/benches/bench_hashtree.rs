use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ssz_rs::hash_pairs_bulk;

const N: usize = 1000; // number of (left, right) pairs
const IN_LEN: usize = 64 * N;
const OUT_LEN: usize = 32 * N;

fn bench_hashtree(c: &mut Criterion) {
    let input = vec![0u8; IN_LEN]; // simulate N (left, right) pairs
    let mut output = vec![0u8; OUT_LEN];

    hashtree::init(); // make sure SIMD setup is done

    c.bench_function("hashtree::hash bulk 1000 pairs", |b| {
        b.iter(|| {
            hashtree::hash(black_box(&mut output), black_box(&input), N);
        });
    });
}

criterion_group!(benches, bench_hashtree);
criterion_main!(benches);
