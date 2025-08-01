//! Support for computing Merkle trees.
use crate::{
    lib::*,
    merkleization::{
        hasher::{hash_chunks, hash_pairs_bulk},
        MerkleizationError as Error, Node, BYTES_PER_CHUNK,
    },
    ser::Serialize,
    GeneralizedIndex,
};
#[cfg(feature = "serde")]
use alloy_primitives::hex::FromHex;

use rayon::{join, prelude::*};

// The generalized index for the root of the "decorated" type in any Merkleized type that supports
// decoration.
const INNER_ROOT_GENERALIZED_INDEX: GeneralizedIndex = 2;
// The generalized index for the "decoration" in any Merkleized type that supports decoration.
const DECORATION_GENERALIZED_INDEX: GeneralizedIndex = 3;

/// Types that can provide the root of their corresponding Merkle tree following the SSZ spec.
pub trait HashTreeRoot {
    /// Compute the "hash tree root" of `Self`.
    fn hash_tree_root(&self) -> Result<Node, Error>;

    /// Indicate the "composite" nature of `Self`.
    fn is_composite_type() -> bool {
        true
    }
}

// Ensures `buffer` can be exactly broken up into `BYTES_PER_CHUNK` chunks of bytes
// via padding any partial chunks at the end of `buffer`
pub fn pack_bytes(buffer: &mut Vec<u8>) {
    let incomplete_chunk_len = buffer.len() % BYTES_PER_CHUNK;
    if incomplete_chunk_len != 0 {
        let bytes_to_pad = BYTES_PER_CHUNK - incomplete_chunk_len;
        buffer.resize(buffer.len() + bytes_to_pad, 0);
    }
}

// Packs serializations of `values` into the return buffer with the
// guarantee that `buffer.len() % BYTES_PER_CHUNK == 0`
pub fn pack<T>(values: &[T]) -> Result<Vec<u8>, Error>
where
    T: Serialize,
{
    let mut buffer = vec![];
    for value in values {
        value.serialize(&mut buffer)?;
    }
    pack_bytes(&mut buffer);
    Ok(buffer)
}

#[inline(always)]
fn hash_nodes(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>, out: &mut [u8]) {
    out.copy_from_slice(&hash_chunks(a, b));
}

const MAX_MERKLE_TREE_DEPTH: usize = 64;

#[derive(Debug)]
struct Context {
    zero_hashes: [u8; MAX_MERKLE_TREE_DEPTH * BYTES_PER_CHUNK],
}

impl Index<usize> for Context {
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.zero_hashes[index * BYTES_PER_CHUNK..(index + 1) * BYTES_PER_CHUNK]
    }
}

// Grab the precomputed context from the build stage
include!(concat!(env!("OUT_DIR"), "/context.rs"));

/// Return the root of the root node of a binary tree formed from `chunks`.
///
/// `chunks` forms the bottom layer of this tree.
///
/// This implementation is memory efficient by relying on pre-computed subtrees of all
/// "zero" leaves stored in the `CONTEXT`. SSZ specifies that `chunks` is padded to the next power
/// of two and this can be quite large for some types. "Zero" subtrees are virtualized to avoid the
/// memory and computation cost of large trees with partially empty leaves.
///
/// The implementation uses an efficient two-buffer swapping approach to compute the root
/// level-by-level, minimizing memory allocations.
///
/// Invariant: `chunks.len() % BYTES_PER_CHUNK == 0`
/// Invariant: `leaf_count.next_power_of_two() == leaf_count`
/// Invariant: `leaf_count != 0`
/// Invariant: `leaf_count.trailing_zeros() < MAX_MERKLE_TREE_DEPTH`
fn merkleize_chunks_with_virtual_padding(chunks: &[u8], leaf_count: usize) -> Result<Node, Error> {
    debug_assert!(chunks.len() % BYTES_PER_CHUNK == 0);
    debug_assert!(leaf_count.is_power_of_two());
    let height = leaf_count.trailing_zeros() as usize;

    let chunk_count = chunks.len() / BYTES_PER_CHUNK;
    if chunk_count == 0 {
        return Ok(CONTEXT[height].try_into().unwrap());
    }

    // Allocate exactly twice and ping‑pong.
    let mut buf_a = chunks.to_vec();
    let mut buf_b: Vec<u8> = Vec::with_capacity(buf_a.len()); // grows downward each round
    let mut in_buf = &mut buf_a;
    let mut out_buf = &mut buf_b;

    for depth in 0..height {
        let mut nodes = in_buf.len() / BYTES_PER_CHUNK;
        if nodes <= 1 {
            break;
        }
        if nodes & 1 != 0 {
            in_buf.extend_from_slice(&CONTEXT[depth]);
            nodes += 1;
        }

        let parents = nodes / 2;
        out_buf.resize(parents * BYTES_PER_CHUNK, 0);
        hash_pairs_bulk(in_buf, out_buf);

        // Next round: swap buffers, keep their capacity.
        std::mem::swap(&mut in_buf, &mut out_buf);
    }

    Ok(in_buf[..BYTES_PER_CHUNK].try_into().unwrap())
}

// Return the root of the Merklization of a binary tree formed from `chunks`.
// Invariant: `chunks.len() % BYTES_PER_CHUNK == 0`
pub fn merkleize(chunks: &[u8], limit: Option<usize>) -> Result<Node, Error> {
    debug_assert!(chunks.len() % BYTES_PER_CHUNK == 0);
    let chunk_count = chunks.len() / BYTES_PER_CHUNK;
    let mut leaf_count = chunk_count.next_power_of_two();
    if let Some(limit) = limit {
        if limit < chunk_count {
            return Err(Error::InputExceedsLimit(limit));
        }
        leaf_count = limit.next_power_of_two();
    }
    merkleize_chunks_with_virtual_padding(chunks, leaf_count)
}

fn mix_in_decoration(root: Node, decoration: usize) -> Node {
    let decoration_data = decoration.hash_tree_root().expect("can merkleize usize");

    let mut output = vec![0u8; BYTES_PER_CHUNK];
    hash_nodes(root, decoration_data, &mut output);
    output.as_slice().try_into().expect("can extract root")
}

pub(crate) fn mix_in_length(root: Node, length: usize) -> Node {
    mix_in_decoration(root, length)
}

#[inline(always)]
pub fn mix_in_selector(root: Node, selector: usize) -> Node {
    mix_in_decoration(root, selector)
}

pub(crate) fn elements_to_chunks<'a, T: HashTreeRoot + 'a>(
    elements: impl Iterator<Item = (usize, &'a T)>,
    count: usize,
) -> Result<Vec<u8>, Error> {
    let total = count * BYTES_PER_CHUNK;
    let mut chunks: Vec<u8> = Vec::with_capacity(total);
    unsafe { chunks.set_len(total) };

    for (i, elem) in elements {
        let chunk = elem.hash_tree_root()?;
        let dst = &mut chunks[i * BYTES_PER_CHUNK..(i + 1) * BYTES_PER_CHUNK];
        dst.copy_from_slice(chunk.as_ref());
    }
    Ok(chunks)
}

// New parallel version for slice inputs
pub(crate) fn elements_to_chunks_parallel<T: HashTreeRoot + Sync>(
    elements: &[T],
) -> Result<Vec<u8>, Error> {
    let count = elements.len();
    let total = count * BYTES_PER_CHUNK;
    let mut chunks: Vec<u8> = vec![0u8; total];

    // Use rayon to compute the roots and fill the chunks buffer in parallel
    elements
        .par_iter()
        .zip(chunks.par_chunks_mut(BYTES_PER_CHUNK))
        .try_for_each(|(elem, chunk_buffer)| -> Result<(), Error> {
            let root = elem.hash_tree_root()?;
            chunk_buffer.copy_from_slice(root.as_ref());
            Ok(())
        })?;

    Ok(chunks)
}

pub struct Tree(Vec<u8>);

impl Tree {
    pub fn mix_in_decoration(&mut self, decoration: usize) -> Result<(), Error> {
        let target_node = &mut self[DECORATION_GENERALIZED_INDEX];
        let decoration_node = decoration.hash_tree_root()?;
        target_node.copy_from_slice(decoration_node.as_ref());
        let out =
            hash_chunks(&self[INNER_ROOT_GENERALIZED_INDEX], &self[DECORATION_GENERALIZED_INDEX]);
        self[1].copy_from_slice(&out);
        Ok(())
    }

    /// Get the raw bytes of the tree for caching purposes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a Tree from raw bytes (for caching purposes)
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Tree(bytes)
    }

    #[cfg(feature = "serde")]
    fn nodes(&self) -> impl Iterator<Item = Node> + '_ {
        self.0.chunks(BYTES_PER_CHUNK).map(|chunk| Node::from_hex(chunk).unwrap())
    }
}

impl Index<GeneralizedIndex> for Tree {
    type Output = [u8];

    fn index(&self, index: GeneralizedIndex) -> &Self::Output {
        // This layout is for a tree where root=1, left=2, right=3...
        // so we subtract 1 for 0-based indexing.
        let start = (index - 1) * BYTES_PER_CHUNK;
        let end = index * BYTES_PER_CHUNK;
        &self.0[start..end]
    }
}

impl IndexMut<GeneralizedIndex> for Tree {
    fn index_mut(&mut self, index: GeneralizedIndex) -> &mut Self::Output {
        let start = (index - 1) * BYTES_PER_CHUNK;
        let end = index * BYTES_PER_CHUNK;
        &mut self.0[start..end]
    }
}

#[cfg(feature = "serde")]
impl std::fmt::Debug for Tree {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.nodes()).finish()
    }
}

// Return the full Merkle tree of the `chunks`.
// Invariant: `chunks.len() % BYTES_PER_CHUNK == 0`
// Invariant: `leaf_count.next_power_of_two() == leaf_count`
pub fn compute_merkle_tree(chunks: &[u8], leaf_count: usize) -> Result<Tree, Error> {
    debug_assert!(chunks.len() % BYTES_PER_CHUNK == 0);
    debug_assert!(leaf_count.is_power_of_two());
    if leaf_count < 2 {
        return Ok(Tree(chunks.to_vec()));
    }

    let node_count = 2 * leaf_count - 1;
    let leaf_start = leaf_count - 1;
    let node_bytes = node_count * BYTES_PER_CHUNK;

    // Uninitialized buffer; we will fully write all bytes we ever read.
    let mut buffer: Vec<u8> = Vec::with_capacity(node_bytes);
    unsafe { buffer.set_len(node_bytes) };

    // Copy the actual chunks into leaf area.
    let leaf_start_bytes = leaf_start * BYTES_PER_CHUNK;
    buffer[leaf_start_bytes..leaf_start_bytes + chunks.len()].copy_from_slice(chunks);

    // If odd number of chunks, ensure the single extra child we will read is zeroed.
    let chunk_count = chunks.len() / BYTES_PER_CHUNK;
    if chunk_count & 1 == 1 {
        let off = leaf_start_bytes + chunk_count * BYTES_PER_CHUNK;
        // write exactly one zero-node; parents above will be filled from CONTEXT.
        buffer[off..off + BYTES_PER_CHUNK].fill(0);
    }

    compute_merkle_tree_inplace(&mut buffer, leaf_count, chunk_count);
    Ok(Tree(buffer))
}

// Compute the Merkle tree serially.
pub fn compute_merkle_tree_serial(buffer: &mut [u8], leaf_count: usize) {
    let tree_height = leaf_count.ilog2();

    for depth in (0..tree_height).rev() {
        let parent_level_start_node = (1 << depth) - 1;
        let num_parent_nodes = 1 << depth;
        let child_level_start_node = (1 << (depth + 1)) - 1;

        let child_start_byte = child_level_start_node * BYTES_PER_CHUNK;
        let (parent_half, child_half) = buffer.split_at_mut(child_start_byte);

        let parent_start_byte = parent_level_start_node * BYTES_PER_CHUNK;
        let parent_layer = &mut parent_half[parent_start_byte..];

        let child_layer = &child_half[..num_parent_nodes * 2 * BYTES_PER_CHUNK];
        hash_pairs_bulk(child_layer, &mut parent_layer[..num_parent_nodes * BYTES_PER_CHUNK]);
    }
}

pub fn compute_merkle_tree_inplace(buffer: &mut [u8], leaf_count: usize, chunk_count: usize) {
    debug_assert!(leaf_count.is_power_of_two());
    if leaf_count < 2 {
        return;
    }

    let h = leaf_count.ilog2() as usize;
    let mut real = chunk_count; // number of child nodes at this level that are “real”

    for depth in (0..h).rev() {
        let parents = 1usize << depth;
        let num_parent_nodes = parents;

        let child_level_start_node = (1 << (depth + 1)) - 1;
        let parent_level_start_node = (1 << depth) - 1;

        let child_start_byte = child_level_start_node * BYTES_PER_CHUNK;
        let parent_start_byte = parent_level_start_node * BYTES_PER_CHUNK;

        // Split once so the two borrows are disjoint
        let (prefix, child_and_rest) = buffer.split_at_mut(child_start_byte);

        // Parent layer lives entirely in `prefix`
        let parent_layer =
            &mut prefix[parent_start_byte..parent_start_byte + num_parent_nodes * BYTES_PER_CHUNK];

        // Child layer lives at the beginning of `child_and_rest`
        let child_layer = &child_and_rest[..num_parent_nodes * 2 * BYTES_PER_CHUNK];

        // How many parents actually depend on data at this level
        let need = (real + 1) / 2;

        // Use bulk hashing for maximum SIMD efficiency
        if need > 0 {
            // The children that are inputs to our real parent nodes
            let child_pairs_to_hash = &child_layer[..need * 2 * BYTES_PER_CHUNK];
            // The parents that will be the output of the hash
            let parent_hashes_to_fill = &mut parent_layer[..need * BYTES_PER_CHUNK];
            
            // Use the bulk hash function to process the entire layer at once
            hash_pairs_bulk(child_pairs_to_hash, parent_hashes_to_fill);
        }

        // Fill the tail with the correct zero-subtree hash for this level
        if need < parents {
            // subtree height at this level = h - depth
            let zero = &CONTEXT[h - depth];
            for dst in parent_layer[need * BYTES_PER_CHUNK..].chunks_mut(BYTES_PER_CHUNK) {
                dst.copy_from_slice(zero);
            }
        }

        real = need;
    }
}

pub fn merkleize_parallel(chunks: &[u8], limit: Option<usize>) -> Result<Node, Error> {
    debug_assert!(chunks.len() % BYTES_PER_CHUNK == 0);
    let chunk_count = chunks.len() / BYTES_PER_CHUNK;
    let mut leaf_count = chunk_count.next_power_of_two();
    if let Some(limit) = limit {
        if limit < chunk_count {
            return Err(Error::InputExceedsLimit(limit));
        }
        leaf_count = limit.next_power_of_two();
    }
    Ok(merkleize_chunks_parallel(chunks, 0, leaf_count))
}

/// Divide and conquer, recursive, parallel Merkle calculation.
/// `chunks` may be shorter than `leaf_count * BYTES_PER_CHUNK` and is zero-padded virtually.
/// `depth` is how deep in the tree we are (0 = root), used for zero hash.
fn merkleize_chunks_parallel(chunks: &[u8], depth: usize, leaf_count: usize) -> Node {
    // Base case: this subtree is all virtual padding
    if chunks.is_empty() {
        // Use precomputed zero hash for this depth
        return CONTEXT[depth].try_into().unwrap();
    }
    // Base case: only one chunk (or less, but not empty)
    if leaf_count == 1 {
        let mut out = [0u8; BYTES_PER_CHUNK];
        out[..chunks.len()].copy_from_slice(chunks);
        if chunks.len() < BYTES_PER_CHUNK {
            // Zero pad
            for i in chunks.len()..BYTES_PER_CHUNK {
                out[i] = 0;
            }
        }
        return alloy_primitives::FixedBytes(out);
    }

    let half = leaf_count / 2;
    let chunk_half = std::cmp::min(half * BYTES_PER_CHUNK, chunks.len());
    let (left, right) = chunks.split_at(chunk_half);

    let (left_hash, right_hash) = join(
        || merkleize_chunks_parallel(left, depth + 1, half),
        || merkleize_chunks_parallel(right, depth + 1, half),
    );

    let mut out = [0u8; BYTES_PER_CHUNK];
    hash_nodes(left_hash, right_hash, &mut out);
    alloy_primitives::FixedBytes(out)
}

pub fn compute_node_count(leaf_count: usize) -> usize {
    2 * leaf_count - 1
}

// Copies data for a list of node indices between buffers
fn copy_nodes_to_buffer(src: &[u8], node_indices: &[usize], dst: &mut [u8]) {
    for (i, &node_idx) in node_indices.iter().enumerate() {
        let src_start = node_idx * BYTES_PER_CHUNK;
        let src_end = src_start + BYTES_PER_CHUNK;
        let dst_start = i * BYTES_PER_CHUNK;
        let dst_end = dst_start + BYTES_PER_CHUNK;
        dst[dst_start..dst_end].copy_from_slice(&src[src_start..src_end]);
    }
}

fn copy_buffer_to_nodes(src: &[u8], node_indices: &[usize], dst: &mut [u8]) {
    for (i, &node_idx) in node_indices.iter().enumerate() {
        let dst_start = node_idx * BYTES_PER_CHUNK;
        let dst_end = dst_start + BYTES_PER_CHUNK;
        let src_start = i * BYTES_PER_CHUNK;
        let src_end = src_start + BYTES_PER_CHUNK;
        dst[dst_start..dst_end].copy_from_slice(&src[src_start..src_end]);
    }
}

fn process_subtree(buffer: &mut [u8], node_count: usize) {
    // (Nearly identical to compute_merkle_tree_serial, but just for this buffer)
    let tree_height = node_count.ilog2();

    for depth in (0..tree_height).rev() {
        let parent_level_start_node = (1 << depth) - 1;
        let num_parent_nodes = 1 << depth;
        let child_level_start_node = (1 << (depth + 1)) - 1;

        let child_start_byte = child_level_start_node * BYTES_PER_CHUNK;
        let (parent_half, child_half) = buffer.split_at_mut(child_start_byte);
        let parent_start_byte = parent_level_start_node * BYTES_PER_CHUNK;
        let parent_layer = &mut parent_half[parent_start_byte..];

        let child_layer = &child_half[..num_parent_nodes * 2 * BYTES_PER_CHUNK];
        hash_pairs_bulk(child_layer, &mut parent_layer[..num_parent_nodes * BYTES_PER_CHUNK]);
    }
}

pub fn compute_merkle_tree_parallel_8(buffer: &mut [u8], leaf_count: usize) {
    let node_count = compute_node_count(leaf_count);
    let nodes = split_merkle_tree_nodes8(node_count);

    let mut subtree_buffers = vec![
        vec![0u8; nodes.subtree0.len() * BYTES_PER_CHUNK],
        vec![0u8; nodes.subtree1.len() * BYTES_PER_CHUNK],
        vec![0u8; nodes.subtree2.len() * BYTES_PER_CHUNK],
        vec![0u8; nodes.subtree3.len() * BYTES_PER_CHUNK],
        vec![0u8; nodes.subtree4.len() * BYTES_PER_CHUNK],
        vec![0u8; nodes.subtree5.len() * BYTES_PER_CHUNK],
        vec![0u8; nodes.subtree6.len() * BYTES_PER_CHUNK],
        vec![0u8; nodes.subtree7.len() * BYTES_PER_CHUNK],
    ];

    copy_nodes_to_buffer(buffer, &nodes.subtree0, &mut subtree_buffers[0]);
    copy_nodes_to_buffer(buffer, &nodes.subtree1, &mut subtree_buffers[1]);
    copy_nodes_to_buffer(buffer, &nodes.subtree2, &mut subtree_buffers[2]);
    copy_nodes_to_buffer(buffer, &nodes.subtree3, &mut subtree_buffers[3]);
    copy_nodes_to_buffer(buffer, &nodes.subtree4, &mut subtree_buffers[4]);
    copy_nodes_to_buffer(buffer, &nodes.subtree5, &mut subtree_buffers[5]);
    copy_nodes_to_buffer(buffer, &nodes.subtree6, &mut subtree_buffers[6]);
    copy_nodes_to_buffer(buffer, &nodes.subtree7, &mut subtree_buffers[7]);

    let subtree_lens: Vec<_> = subtree_buffers.iter().map(|b| b.len() / BYTES_PER_CHUNK).collect();

    rayon::scope(|s| {
        for (buf, &len) in subtree_buffers.iter_mut().zip(subtree_lens.iter()) {
            s.spawn(move |_| process_subtree(buf, len));
        }
    });

    copy_buffer_to_nodes(&subtree_buffers[0], &nodes.subtree0, buffer);
    copy_buffer_to_nodes(&subtree_buffers[1], &nodes.subtree1, buffer);
    copy_buffer_to_nodes(&subtree_buffers[2], &nodes.subtree2, buffer);
    copy_buffer_to_nodes(&subtree_buffers[3], &nodes.subtree3, buffer);
    copy_buffer_to_nodes(&subtree_buffers[4], &nodes.subtree4, buffer);
    copy_buffer_to_nodes(&subtree_buffers[5], &nodes.subtree5, buffer);
    copy_buffer_to_nodes(&subtree_buffers[6], &nodes.subtree6, buffer);
    copy_buffer_to_nodes(&subtree_buffers[7], &nodes.subtree7, buffer);

    // Compute parent nodes above level 3
    let mut level = 3;
    while level > 0 {
        let start_idx = (1 << level) - 1;
        let end_idx = (1 << (level + 1)) - 1;
        for parent in (start_idx..end_idx).step_by(2) {
            if parent + 1 >= node_count {
                continue;
            }
            let hash = hash_chunks(
                &buffer[parent * BYTES_PER_CHUNK..(parent + 1) * BYTES_PER_CHUNK],
                &buffer[(parent + 1) * BYTES_PER_CHUNK..(parent + 2) * BYTES_PER_CHUNK],
            );
            let parent_idx = (parent - 1) / 2;
            buffer[parent_idx * BYTES_PER_CHUNK..(parent_idx + 1) * BYTES_PER_CHUNK]
                .copy_from_slice(&hash);
        }
        if level == 0 {
            break;
        }
        level -= 1;
    }
}

#[derive(Debug, PartialEq)]
struct SubtreeNodes8 {
    subtree0: Vec<usize>,
    subtree1: Vec<usize>,
    subtree2: Vec<usize>,
    subtree3: Vec<usize>,
    subtree4: Vec<usize>,
    subtree5: Vec<usize>,
    subtree6: Vec<usize>,
    subtree7: Vec<usize>,
}

fn split_merkle_tree_nodes8(node_count: usize) -> SubtreeNodes8 {
    let mut subtrees = SubtreeNodes8 {
        subtree0: Vec::new(),
        subtree1: Vec::new(),
        subtree2: Vec::new(),
        subtree3: Vec::new(),
        subtree4: Vec::new(),
        subtree5: Vec::new(),
        subtree6: Vec::new(),
        subtree7: Vec::new(),
    };

    // Skip root node (index 0) and level 1-2 nodes (1-6)
    for i in 7..node_count {
        // Determine the level of the current node (0-based)
        let level = (i + 1).ilog2() as usize;
        // Position within the current level
        let pos_in_level = i - ((1 << level) - 1);

        // For level 3 nodes (indices 7-14), they become the start of our subtrees
        if level == 3 {
            match i {
                7 => subtrees.subtree0.push(i),
                8 => subtrees.subtree1.push(i),
                9 => subtrees.subtree2.push(i),
                10 => subtrees.subtree3.push(i),
                11 => subtrees.subtree4.push(i),
                12 => subtrees.subtree5.push(i),
                13 => subtrees.subtree6.push(i),
                14 => subtrees.subtree7.push(i),
                _ => unreachable!("Invalid level 3 index"),
            }
            continue;
        }

        // For deeper levels, assign based on their ancestor at level 3
        if level > 3 {
            let ancestor_at_level3 = {
                let steps_up = level - 3;
                let parent_pos = pos_in_level >> steps_up;
                parent_pos + 7 // +7 because level 3 starts at index 7
            };

            match ancestor_at_level3 {
                7 => subtrees.subtree0.push(i),
                8 => subtrees.subtree1.push(i),
                9 => subtrees.subtree2.push(i),
                10 => subtrees.subtree3.push(i),
                11 => subtrees.subtree4.push(i),
                12 => subtrees.subtree5.push(i),
                13 => subtrees.subtree6.push(i),
                14 => subtrees.subtree7.push(i),
                _ => unreachable!("Invalid ancestor index at level 3"),
            }
        }
    }

    subtrees
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{merkleization::proofs::tests::decode_node_from_hex, prelude::*};

    // Return the root of the Merklization of a binary tree formed from `chunks`.
    fn merkleize_chunks(chunks: &[u8], leaf_count: usize) -> Result<Node, Error> {
        let tree = compute_merkle_tree(chunks, leaf_count)?;
        let root_index = default_generalized_index();
        Ok(tree[root_index].try_into().expect("can produce a single root chunk"))
    }

    #[test]
    fn test_packing_basic_types_simple() {
        let b = true;
        let mut expected = vec![0u8; BYTES_PER_CHUNK];
        expected[0] = 1u8;
        let input = &[b];
        let result = pack(input).expect("can pack values");
        assert!(result.len() == BYTES_PER_CHUNK);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_packing_basic_types_extended() {
        let b = true;
        let input = &[b, !b, !b, b];
        let result = pack(input).expect("can pack values");

        let mut expected = vec![0u8; BYTES_PER_CHUNK];
        expected[0] = 1u8;
        expected[3] = 1u8;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_packing_basic_types_multiple() {
        let data = U256::from_le_bytes([1u8; 32]);
        let input = &[data, data, data];
        let result = pack(input).expect("can pack values");

        let expected = vec![1u8; 3 * 32];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_merkleize_basic() {
        let input = &[];
        let result = merkleize(input, None).expect("can merkle");
        assert_eq!(result, Node::default());

        let b = true;
        let input = &[b];
        let input = pack(input).expect("can pack");
        let result = merkleize(&input, None).expect("can merkle");
        let mut expected = Node::default();
        expected[0] = 1u8;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_naive_merkleize_chunks() {
        let chunks = vec![0u8; 2 * BYTES_PER_CHUNK];
        let root = merkleize_chunks(&chunks, 2).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
            )
        );

        let chunks = vec![1u8; 2 * BYTES_PER_CHUNK];
        let root = merkleize_chunks(&chunks, 2).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "7c8975e1e60a5c8337f28edf8c33c3b180360b7279644a9bc1af3c51e6220bf5"
            )
        );

        let chunks = vec![0u8; BYTES_PER_CHUNK];
        let root = merkleize_chunks(&chunks, 4).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"
            )
        );

        let chunks = vec![1u8; BYTES_PER_CHUNK];
        let root = merkleize_chunks(&chunks, 4).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "29797eded0e83376b70f2bf034cc0811ae7f1414653b1d720dfd18f74cf13309"
            )
        );

        let chunks = vec![2u8; BYTES_PER_CHUNK];
        let root = merkleize_chunks(&chunks, 8).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "fa4cf775712aa8a2fe5dcb5a517d19b2e9effcf58ff311b9fd8e4a7d308e6d00"
            )
        );

        let chunks = vec![1u8; 5 * BYTES_PER_CHUNK];
        let root = merkleize_chunks(&chunks, 8).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "0ae67e34cba4ad2bbfea5dc39e6679b444021522d861fab00f05063c54341289"
            )
        );
    }

    #[test]
    fn test_merkleize_chunks() {
        let chunks = vec![1u8; 3 * BYTES_PER_CHUNK];
        let root = merkleize_chunks_with_virtual_padding(&chunks, 4).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "65aa94f2b59e517abd400cab655f42821374e433e41b8fe599f6bb15484adcec"
            )
        );

        let chunks = vec![1u8; 5 * BYTES_PER_CHUNK];
        let root = merkleize_chunks_with_virtual_padding(&chunks, 8).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "0ae67e34cba4ad2bbfea5dc39e6679b444021522d861fab00f05063c54341289"
            )
        );

        let chunks = vec![1u8; 6 * BYTES_PER_CHUNK];
        let root = merkleize_chunks_with_virtual_padding(&chunks, 8).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "0ef7df63c204ef203d76145627b8083c49aa7c55ebdee2967556f55a4f65a238"
            )
        );
    }

    #[test]
    fn test_merkleize_chunks_with_many_virtual_nodes() {
        let chunks = vec![1u8; 5 * BYTES_PER_CHUNK];
        let root =
            merkleize_chunks_with_virtual_padding(&chunks, 2usize.pow(10)).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "2647cb9e26bd83eeb0982814b2ac4d6cc4a65d0d98637f1a73a4c06d3db0e6ce"
            )
        );

        let chunks = vec![1u8; 70 * BYTES_PER_CHUNK];
        let root =
            merkleize_chunks_with_virtual_padding(&chunks, 2usize.pow(63)).expect("can merkleize");
        assert_eq!(
            root,
            decode_node_from_hex(
                "9317695d95b5a3b46e976b5a9cbfcfccb600accaddeda9ac867cc9669b862979"
            )
        );
    }

    #[test]
    fn test_hash_tree_root_of_list() {
        let a_list = List::<u16, 1024>::try_from(vec![
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            65535, 65535, 65535, 65535,
        ])
        .unwrap();
        let root = a_list.hash_tree_root().expect("can compute root");
        assert_eq!(
            root,
            decode_node_from_hex(
                "d20d2246e1438d88de46f6f41c7b041f92b673845e51f2de93b944bf599e63b1"
            )
        );
    }

    #[test]
    fn test_hash_tree_root_of_empty_list() {
        let a_list = List::<u16, 1024>::try_from(vec![]).unwrap();
        let root = a_list.hash_tree_root().expect("can compute root");
        assert_eq!(
            root,
            decode_node_from_hex(
                "c9eece3e14d3c3db45c38bbf69a4cb7464981e2506d8424a0ba450dad9b9af30"
            )
        );
    }

    #[test]
    fn test_hash_tree_root() {
        #[derive(PartialEq, Eq, Debug, SimpleSerialize, Clone)]
        enum Bar {
            A(u32),
            B(List<bool, 32>),
        }

        impl Default for Bar {
            fn default() -> Self {
                Self::A(Default::default())
            }
        }

        #[derive(PartialEq, Eq, Debug, Default, SimpleSerialize, Clone)]
        struct Foo {
            a: u32,
            b: Vector<u32, 4>,
            c: bool,
            d: Bitlist<27>,
            e: Bar,
            f: Bitvector<4>,
            g: List<u16, 7>,
        }

        let mut foo = Foo {
            a: 16u32,
            b: Vector::try_from(vec![3u32, 2u32, 1u32, 10u32]).unwrap(),
            c: true,
            d: Bitlist::try_from(
                [
                    true, false, false, true, true, false, true, false, true, true, false, false,
                    true, true, false, true, false, true, true, false, false, true, true, false,
                    true, false, true,
                ]
                .as_ref(),
            )
            .unwrap(),
            e: Bar::B(List::try_from(vec![true, true, false, false, false, true]).unwrap()),
            f: Bitvector::try_from([false, true, false, true].as_ref()).unwrap(),
            g: List::try_from(vec![1, 2]).unwrap(),
        };

        let root = foo.hash_tree_root().expect("can make root");
        assert_eq!(
            root,
            decode_node_from_hex(
                "7078155bf8f0dc42d8afccec8d9b5aeb54f0a2e8e58fcef3e723f6a867232ce7"
            )
        );

        let original_foo = foo.clone();

        foo.b[2] = 44u32;
        foo.d.pop();
        foo.e = Bar::A(33);

        let root = original_foo.hash_tree_root().expect("can make root");
        assert_eq!(
            root,
            decode_node_from_hex(
                "7078155bf8f0dc42d8afccec8d9b5aeb54f0a2e8e58fcef3e723f6a867232ce7"
            )
        );

        let root = foo.hash_tree_root().expect("can make root");
        assert_eq!(
            root,
            decode_node_from_hex(
                "0063bfcfabbca567483a2ee859fcfafb958329489eb328ac7f07790c7df1b231"
            )
        );

        let encoding = serialize(&original_foo).expect("can serialize");

        let mut restored_foo = Foo::deserialize(&encoding).expect("can deserialize");

        let root = restored_foo.hash_tree_root().expect("can make root");
        assert_eq!(
            root,
            decode_node_from_hex(
                "7078155bf8f0dc42d8afccec8d9b5aeb54f0a2e8e58fcef3e723f6a867232ce7"
            )
        );

        restored_foo.b[2] = 44u32;
        restored_foo.d.pop();
        restored_foo.e = Bar::A(33);

        let root = foo.hash_tree_root().expect("can make root");
        assert_eq!(
            root,
            decode_node_from_hex(
                "0063bfcfabbca567483a2ee859fcfafb958329489eb328ac7f07790c7df1b231"
            )
        );
    }

    #[test]
    fn test_simple_serialize_of_root() {
        let root = Node::default();
        let mut result = vec![];
        let _ = root.serialize(&mut result).expect("can encode");
        let expected_encoding = vec![0; 32];
        assert_eq!(result, expected_encoding);

        let recovered_root = Node::deserialize(&result).expect("can decode");
        assert_eq!(recovered_root, Node::default());

        let hash_tree_root = root.hash_tree_root().expect("can find root");
        assert_eq!(hash_tree_root, Node::default());
    }

    #[test]
    fn test_derive_hash_tree_root() {
        #[derive(Debug, HashTreeRoot)]
        struct Foo {
            a: U256,
        }

        let foo = Foo { a: U256::from(68) };
        let foo_root = foo.hash_tree_root().unwrap();
        let expected_root = decode_node_from_hex(
            "4400000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(foo_root, expected_root);
    }
}
