#[cfg(feature = "hashtree")]
use std::sync::Once;

use super::BYTES_PER_CHUNK;

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

    #[cfg(feature = "hashtree")]
    {
        INIT.call_once(|| { hashtree::init(); });
        hashtree::hash(out_hashes, in_pairs, in_pairs.len() / 64);
        return;
    }

    #[cfg(not(feature = "hashtree"))]
    {
        use sha2::{Digest, Sha256};
        for (blk, out) in in_pairs.chunks_exact(64).zip(out_hashes.chunks_exact_mut(32)) {
            let mut h = Sha256::new();
            h.update(blk);
            out.copy_from_slice(&h.finalize_reset());
        }
    }
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
