use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ssz_rs::{compute_merkle_tree_parallel_8, compute_merkle_tree_serial, pack, List};
use std::{convert::TryFrom, env, fs::File, io::BufReader, path::Path};

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

fn bench_merkleize(c: &mut Criterion) {
    for &file_path_str in TRANSACTIONS_JSON_PATHS {
        let file_path = Path::new(file_path_str);

        // Load transaction data (List of Lists)
        let outer = load_transactions(file_path);

        // Convert to packed buffer of bytes
        let packed = pack(&outer).expect("can pack values");

        let mut group = c.benchmark_group(format!(
            "Merkle Root Benchmark - File: {} - size {}",
            file_path_str,
            outer.len()
        ));
        group.sample_size(10);

        let chunk_count = packed.len() / BYTES_PER_CHUNK;
        let leaf_count = chunk_count.next_power_of_two();
        let node_count = 2 * leaf_count - 1;
        let mut tree_buffer = vec![0u8; node_count * BYTES_PER_CHUNK];
        let leaf_start = leaf_count - 1;

        // Copy packed leaves into tree buffer at correct position
        tree_buffer[leaf_start * BYTES_PER_CHUNK..leaf_start * BYTES_PER_CHUNK + packed.len()]
            .copy_from_slice(&packed);

        group.bench_with_input(
            BenchmarkId::new("full_tree_serial", file_path_str),
            &packed,
            |b, input| {
                b.iter(|| {
                    let mut tree_buffer = vec![0u8; node_count * BYTES_PER_CHUNK];
                    tree_buffer
                        [leaf_start * BYTES_PER_CHUNK..leaf_start * BYTES_PER_CHUNK + packed.len()]
                        .copy_from_slice(input);
                    compute_merkle_tree_serial(&mut tree_buffer, leaf_count);
                    black_box(&tree_buffer[0..BYTES_PER_CHUNK]);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("full_tree_parallel_8", file_path_str),
            &packed,
            |b, input| {
                b.iter(|| {
                    let mut tree_buffer = vec![0u8; node_count * BYTES_PER_CHUNK];
                    tree_buffer
                        [leaf_start * BYTES_PER_CHUNK..leaf_start * BYTES_PER_CHUNK + packed.len()]
                        .copy_from_slice(input);
                    compute_merkle_tree_parallel_8(&mut tree_buffer, leaf_count);
                    black_box(&tree_buffer[0..BYTES_PER_CHUNK]);
                });
            },
        );

        group.finish();
    }
}

criterion_group!(benches, bench_merkleize);
criterion_main!(benches);
