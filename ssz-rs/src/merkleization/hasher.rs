#[cfg(feature = "hashtree")]
use std::sync::Once;

use super::BYTES_PER_CHUNK;

use rayon::prelude::*;

#[cfg(not(feature = "hashtree"))]
use ::sha2::{Digest, Sha256};

#[cfg(feature = "hashtree")]
static INIT: Once = Once::new();

#[inline]
#[cfg(feature = "hashtree")]
fn hash_chunks_hashtree(left: impl AsRef<[u8]>, right: impl AsRef<[u8]>) -> [u8; BYTES_PER_CHUNK] {
    INIT.call_once(|| {
        hashtree::init();
    });

    let mut out = [0u8; BYTES_PER_CHUNK];

    let mut chunks = [0u8; 2 * BYTES_PER_CHUNK];

    chunks[..BYTES_PER_CHUNK].copy_from_slice(left.as_ref());
    chunks[BYTES_PER_CHUNK..].copy_from_slice(right.as_ref());

    hashtree::hash(&mut out, &chunks, 1);

    out
}

#[inline]
#[cfg(not(feature = "hashtree"))]
fn hash_chunks_sha256(left: impl AsRef<[u8]>, right: impl AsRef<[u8]>) -> [u8; BYTES_PER_CHUNK] {
    let mut hasher = Sha256::new();
    hasher.update(left.as_ref());
    hasher.update(right.as_ref());
    hasher.finalize_reset().into()
}

/// Hash N consecutive (left,right) pairs.
/// `in_pairs.len()  == 64 * N`
/// `out_hashes.len() == 32 * N`
#[inline(always)]
pub fn hash_pairs_bulk(in_pairs: &[u8], out_hashes: &mut [u8]) {
    debug_assert!(in_pairs.len() % 64 == 0);
    debug_assert!(out_hashes.len() * 2 == in_pairs.len());

    let num_pairs = in_pairs.len() / 64;
    if num_pairs == 0 {
        return;
    }

    // Determine the number of chunks to split the work into.
    // This is a good heuristic, dividing the work among the available threads.
    let num_threads = rayon::current_num_threads();
    let pairs_per_chunk = (num_pairs + num_threads - 1) / num_threads; // Ceiling division

    // Calculate byte sizes for the chunks
    let in_chunk_size = pairs_per_chunk * 64;
    let out_chunk_size = pairs_per_chunk * 32;

    // Create parallel iterators over the large chunks
    out_hashes.par_chunks_mut(out_chunk_size).zip(in_pairs.par_chunks(in_chunk_size)).for_each(
        |(out_chunk, in_chunk)| {
            // This closure is executed in parallel on a large chunk of data.
            // Now we can use the original, efficient sequential logic inside.

            #[cfg(feature = "hashtree")]
            {
                // This assumes `hashtree::hash` is thread-safe after `init`.
                // The `INIT` call should be outside the parallel loop if possible,
                // or remain where it is, as `call_once` is thread-safe.
                INIT.call_once(|| {
                    hashtree::init();
                });

                let pairs_in_this_chunk = in_chunk.len() / 64;
                if pairs_in_this_chunk > 0 {
                    // Call the bulk function on the chunk
                    hashtree::hash(out_chunk, in_chunk, pairs_in_this_chunk);
                }
            }

            #[cfg(not(feature = "hashtree"))]
            {
                // Run the original sequential loop on the chunk assigned to this thread.
                for (blk, out) in in_chunk.chunks_exact(64).zip(out_chunk.chunks_exact_mut(32)) {
                    let mut h = Sha256::new();
                    h.update(blk);
                    out.copy_from_slice(&h.finalize_reset());
                }
            }
        },
    );
}

/// Function that hashes 2 [BYTES_PER_CHUNK] (32) len byte slices together. Depending on the feature
/// flags, this will either use:
/// - sha256 (default)
/// - sha256 with assembly support (with the "sha2-asm" feature flag)
/// - hashtree (with the "hashtree" feature flag)
#[inline]
pub fn hash_chunks(left: impl AsRef<[u8]>, right: impl AsRef<[u8]>) -> [u8; BYTES_PER_CHUNK] {
    debug_assert!(left.as_ref().len() == BYTES_PER_CHUNK);
    debug_assert!(right.as_ref().len() == BYTES_PER_CHUNK);

    #[cfg(feature = "hashtree")]
    return hash_chunks_hashtree(left, right);

    #[cfg(not(feature = "hashtree"))]
    return hash_chunks_sha256(left, right);
}
