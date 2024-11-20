use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn bench_merkleization(c: &mut Criterion) {
    use ssz_rs::{HashTreeRoot, List};

    let inner: Vec<List<u8, 1073741824>> = vec![
        vec![0u8, 1u8, 2u8].try_into().unwrap(),
        vec![3u8, 4u8, 5u8].try_into().unwrap(),
        vec![6u8, 7u8, 8u8].try_into().unwrap(),
        vec![9u8, 10u8, 11u8].try_into().unwrap(),
    ];

    // Emulate a transactions tree
    let outer: List<List<u8, 1073741824>, 1048576> = List::try_from(inner).unwrap();

    c.bench_function("hash_tree_root", |b| {
        b.iter(|| {
            let _ = black_box(outer.hash_tree_root().unwrap());
        })
    });
}

criterion_group!(benches, bench_merkleization);
criterion_main!(benches);
