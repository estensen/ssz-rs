use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ssz_rs::{proofs::compute_proof_branch_indexes, List, PathElement, Prove};
use std::{convert::TryFrom, env, fs::File, hint::black_box, io::BufReader, path::Path};

const BYTES_PER_CHUNK: usize = 32;

// https://github.com/ethereum/consensus-specs/blob/85b4d003668731cbad63d6b6ba53fcc7d042cba1/specs/bellatrix/beacon-chain.md?plain=1#L69-L76
const MAX_BYTES_PER_TRANSACTION: usize = 1_073_741_824; // 1 GiB
const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1_048_576; // 2^20

// Test blocks just above and below 256, a power of 2.
// 21315748.json contains 247 transactions.
// 21327802.json contains 261 transactions.
const TRANSACTIONS_JSON_PATHS: &[&str] = &["benches/21315748.json", "benches/21327802.json"];

/// Represents the structure of the JSON file.
/// Each transaction is a hex-encoded string prefixed with "0x".
type TransactionsJson = Vec<String>;

/// Reads transaction data from a local JSON file.
fn load_transactions<P: AsRef<Path>>(
    file_path: P,
) -> List<List<u8, MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD> {
    // Open the JSON file
    let current_dir = env::current_dir().expect("Failed to get current working directory");
    let file = File::open(&file_path).unwrap_or_else(|e| {
        panic!(
            "Failed to open JSON file at {:?}. Current working directory: {:?}. Error: {}",
            file_path.as_ref(),
            current_dir,
            e
        )
    });
    let reader = BufReader::new(file);

    // Deserialize the JSON into a Vec<String>
    let transactions_json: TransactionsJson =
        serde_json::from_reader(reader).expect("Failed to parse JSON");

    // Convert each hex string to Vec<u8> and then to List<u8, MAX_BYTES_PER_TRANSACTION>
    let mut inner: Vec<List<u8, MAX_BYTES_PER_TRANSACTION>> =
        Vec::with_capacity(transactions_json.len());

    for (i, tx_hex) in transactions_json.into_iter().enumerate() {
        // Remove "0x" prefix
        let tx_hex_trimmed = tx_hex.strip_prefix("0x").unwrap_or(&tx_hex);

        // Decode hex string to Vec<u8>
        let tx_bytes = hex::decode(tx_hex_trimmed)
            .unwrap_or_else(|_| panic!("Failed to decode hex string at index {}", i));

        // Convert Vec<u8> to List<u8, MAX_BYTES_PER_TRANSACTION>
        let tx_list = List::<u8, MAX_BYTES_PER_TRANSACTION>::try_from(tx_bytes).expect(&format!(
            "Failed to convert Vec<u8> to List<u8, {}> at index {}",
            MAX_BYTES_PER_TRANSACTION, i
        ));

        inner.push(tx_list);
    }

    let outer =
        List::<List<u8, MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>::try_from(inner)
            .expect("Failed to convert Vec<List<u8, MAX_BYTES_PER_TRANSACTION>> to outer List");

    outer
}

fn bench_prove(c: &mut Criterion) {
    for &file_path_str in TRANSACTIONS_JSON_PATHS {
        let file_path = Path::new(file_path_str);

        // Generate the nested List from the JSON file
        let outer = load_transactions(file_path);
        let size = outer.len();

        // Determine indices to benchmark (first, middle, last)
        let index = size / 2;

        let mut group =
            c.benchmark_group(format!("Prove Benchmark - File: {} - size {}", file_path_str, size));
        // Reduce sample size for larger benchmarks to ensure completion
        group.sample_size(10);

        let path = vec![PathElement::from(index)];

        group.bench_with_input(BenchmarkId::from_parameter(index), &path, |b, path| {
            b.iter(|| {
                let proof = outer.prove(black_box(path)).expect("Failed to generate proof");
                black_box(proof)
            })
        });

        group.bench_with_input(
            BenchmarkId::new("tree_and_branch_extract", index),
            &index,
            |b, &leaf_index| {
                // Packed data can be precomputed once
                let packed = ssz_rs::pack(&outer).expect("can pack values");
                let chunk_count = packed.len() / BYTES_PER_CHUNK;
                let leaf_count = chunk_count.next_power_of_two();
                let node_count = 2 * leaf_count - 1;
                let leaf_start = leaf_count - 1;

                b.iter(|| {
                    // 1. Copy leaves into a fresh buffer for each iteration
                    let mut tree_buffer = vec![0u8; node_count * BYTES_PER_CHUNK];
                    tree_buffer
                        [leaf_start * BYTES_PER_CHUNK..leaf_start * BYTES_PER_CHUNK + packed.len()]
                        .copy_from_slice(&packed);

                    // 2. Compute the Merkle tree in place
                    ssz_rs::compute_merkle_tree_serial(&mut tree_buffer, leaf_count);

                    // 3. Extract the proof branch from the buffer
                    let branch_indexes = compute_proof_branch_indexes(leaf_count, leaf_index);
                    let branch_hashes: Vec<[u8; 32]> = branch_indexes
                        .iter()
                        .map(|&i| {
                            let start = i * BYTES_PER_CHUNK;
                            let end = start + BYTES_PER_CHUNK;
                            tree_buffer[start..end].try_into().unwrap()
                        })
                        .collect();

                    black_box(branch_hashes)
                })
            },
        );

        group.finish();
    }
}

criterion_group!(benches, bench_prove);
criterion_main!(benches);
