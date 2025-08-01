use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use once_cell::sync::Lazy;
use ssz_rs::{List, PathElement, Prove};
use std::{convert::TryFrom, fs::File, hint::black_box, io::BufReader, path::Path};

const MAX_BYTES_PER_TRANSACTION: usize = 1_073_741_824; // 1 GiB
const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1_048_576; // 2^20

type OuterList = List<List<u8, MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>;

static OUTER_247: Lazy<OuterList> = Lazy::new(|| load_transactions("benches/21315748.json"));
static OUTER_261: Lazy<OuterList> = Lazy::new(|| load_transactions("benches/21327802.json"));

fn load_transactions<P: AsRef<Path>>(file_path: P) -> OuterList {
    let file = File::open(&file_path).expect("open file");
    let reader = BufReader::new(file);
    let txs: Vec<String> = serde_json::from_reader(reader).expect("parse json");

    let inner: Vec<_> = txs
        .into_iter()
        .enumerate()
        .map(|(i, tx_hex)| {
            let hex = tx_hex.strip_prefix("0x").unwrap_or(&tx_hex);
            let bytes = hex::decode(hex).unwrap_or_else(|_| panic!("hex decode fail @ {i}"));
            List::<u8, MAX_BYTES_PER_TRANSACTION>::try_from(bytes)
                .unwrap_or_else(|_| panic!("List<u8> fail @ {i}"))
        })
        .collect();

    OuterList::try_from(inner).expect("outer list")
}

fn bench_outer_prove(c: &mut Criterion) {
    // Force-load the Lazy statics so all file I/O and allocations are done
    let _ = once_cell::sync::Lazy::force(&OUTER_247);
    let _ = once_cell::sync::Lazy::force(&OUTER_261);

    let mut group = c.benchmark_group("outer_prove");
    group.warm_up_time(std::time::Duration::from_secs(3));
    group.measurement_time(std::time::Duration::from_secs(10));
    group.sample_size(10);

    for (name, outer) in [("21315748", &*OUTER_247), ("21327802", &*OUTER_261)] {
        let index = outer.len() / 2;
        let path = vec![PathElement::from(index)];
        group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter(|| {
                let proof = outer.prove(black_box(&path)).expect("prove ok");
                black_box(proof);
            });
        });
    }

    group.finish();
}

/*
fn bench_manual_branch(c: &mut Criterion) {
    for (name, outer) in [("21315748", &*OUTER_247), ("21327802", &*OUTER_261)] {
        let size = outer.len();
        let index = size / 2;
        let packed = pack(outer).expect("pack");
        let chunk_count = packed.len() / BYTES_PER_CHUNK;
        let leaf_count = chunk_count.next_power_of_two();
        let node_count = 2 * leaf_count - 1;
        let leaf_start = leaf_count - 1;

        let mut group = c.benchmark_group(format!("manual_branch-{name}-size-{size}"));
        group.warm_up_time(Duration::from_secs(3));
        group.measurement_time(Duration::from_secs(30));
        group.sample_size(30);

        group.bench_with_input(
            BenchmarkId::new("tree_and_branch_extract", index),
            &index,
            |b, &leaf_index| {
                let mut tree_buffer = vec![0u8; node_count * BYTES_PER_CHUNK];

                b.iter(|| {
                    tree_buffer
                        [leaf_start * BYTES_PER_CHUNK..leaf_start * BYTES_PER_CHUNK + packed.len()]
                        .copy_from_slice(&packed);

                    ssz_rs::compute_merkle_tree_serial(&mut tree_buffer, leaf_count);

                    let branch_indexes = compute_proof_branch_indexes(leaf_count, leaf_index);
                    let mut tmp = [0u8; 32];
                    for &i in &branch_indexes {
                        tmp.copy_from_slice(
                            &tree_buffer[i * BYTES_PER_CHUNK..(i + 1) * BYTES_PER_CHUNK],
                        );
                        black_box(&tmp);
                    }
                });
            },
        );

        group.finish();
    }
}

fn bench_outer_prove_cached(c: &mut Criterion) {
    // Force-load the Lazy statics so all file I/O and allocations are done
    let _ = once_cell::sync::Lazy::force(&OUTER_247);
    let _ = once_cell::sync::Lazy::force(&OUTER_261);

    let mut group = c.benchmark_group("outer_prove_cached");
    group.warm_up_time(std::time::Duration::from_secs(3));
    group.measurement_time(std::time::Duration::from_secs(10));
    group.sample_size(10);

    for (name, outer) in [("21315748", &*OUTER_247), ("21327802", &*OUTER_261)] {
        let index = outer.len() / 2;
        let path = vec![PathElement::from(index)];

        group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter(|| {
                // Pre-compute the cached tree
                let cached_tree = outer.get_cached_tree().expect("can get cached tree");

                let proof =
                    outer.prove_cached(black_box(&path), Some(&cached_tree)).expect("prove ok");
                black_box(proof);
            });
        });
    }

    group.finish();
}
    */

criterion_group!(benches, bench_outer_prove);
//criterion_group!(benches, bench_outer_prove, bench_manual_branch);
criterion_main!(benches);
