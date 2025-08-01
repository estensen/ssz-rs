//! Support for constructing and verifying Merkle proofs.
pub use crate::merkleization::generalized_index::log_2;
use crate::{
    lib::*,
    merkleization::{
        compute_merkle_tree, GeneralizedIndex, GeneralizedIndexable, MerkleizationError as Error,
        Node, Path, Tree,
    },
};
use sha2::{Digest, Sha256};

/// Convenience type for a Merkle proof and the root of the Merkle tree, which serves as
/// "witness" that the proof is valid.
pub type ProofAndWitness = (Proof, Node);

fn get_depth(i: GeneralizedIndex) -> Result<u32, Error> {
    log_2(i).ok_or(Error::InvalidGeneralizedIndex)
}

fn get_index(i: GeneralizedIndex, depth: u32) -> usize {
    i % 2usize.pow(depth)
}

/// Return the index in the layer of the Merkle tree a node with generalized index `index` occupies.
pub fn get_subtree_index(i: GeneralizedIndex) -> Result<usize, Error> {
    let depth = get_depth(i)?;
    Ok(get_index(i, depth))
}

// Identify the generalized index that is the largest parent of `i` that fits in a perfect binary
// tree with `leaf_count` leaves. Return this index along with its depth in the tree
// and its index in the leaf layer.
pub(crate) fn compute_local_merkle_coordinates(
    mut i: GeneralizedIndex,
    leaf_count: usize,
) -> Result<(u32, usize, GeneralizedIndex), Error> {
    let node_count = 2 * leaf_count - 1;
    while i > node_count {
        i /= 2;
    }
    let depth = get_depth(i)?;
    Ok((depth, get_index(i, depth), i))
}

/// A type that knows how to compute Merkle proofs assuming a target type is `Prove`.
#[derive(Debug)]
pub struct Prover {
    proof: Proof,
    witness: Node,
}

impl Prover {
    fn set_leaf(&mut self, leaf: &[u8]) {
        self.proof.leaf = leaf.try_into().expect("is correct size");
    }

    // Adds a node to the Merkle proof's branch.
    // Assumes nodes are provided going from the bottom of the tree to the top.
    fn extend_branch(&mut self, node: &[u8]) {
        self.proof.branch.push(node.try_into().expect("is correct size"))
    }

    fn set_witness(&mut self, witness: &[u8]) {
        self.witness = witness.try_into().expect("is correct size");
    }

    /// Derive a Merkle proof relative to `data` given the parameters in `self`.
    pub fn compute_proof<T: Prove + ?Sized>(&mut self, data: &T) -> Result<(), Error> {
        let chunk_count = T::chunk_count();
        let mut leaf_count = chunk_count.next_power_of_two();
        let parent_index = self.proof.index;
        let decoration = data.decoration();
        if decoration.is_some() {
            // double to account for decoration layer
            leaf_count *= 2;
        }

        let (local_depth, local_index, local_generalized_index) =
            compute_local_merkle_coordinates(parent_index, leaf_count)?;

        let mut is_leaf_local = false;
        if local_generalized_index < parent_index {
            // NOTE: need to recurse to children to find ultimate leaf
            let parent_depth = get_depth(parent_index)?;
            let child_depth = parent_depth - local_depth;
            let node_count = 2usize.pow(child_depth);
            let child_index = node_count + parent_index % node_count;
            self.proof.index = child_index;
            data.prove_element(local_index, self)?;
            self.proof.index = parent_index;
        } else {
            // NOTE: leaf is within the current object, set a flag to grab from merkle tree later
            is_leaf_local = true;
        }
        let chunks = data.chunks()?;
        let mut tree = compute_merkle_tree(&chunks, leaf_count)?;
        if let Some(decoration) = decoration {
            tree.mix_in_decoration(decoration)?;
        }

        if is_leaf_local {
            self.set_leaf(&tree[parent_index]);
        }

        let mut target = local_generalized_index;
        for _ in 0..local_depth {
            let sibling = if target % 2 != 0 { &tree[target - 1] } else { &tree[target + 1] };
            self.extend_branch(sibling);
            target /= 2;
        }

        let root = &tree[1];
        self.set_witness(root);

        Ok(())
    }

    /// Optimized version of compute_proof that caches the Merkle tree
    pub fn compute_proof_cached<T: Prove + ?Sized>(
        &mut self,
        data: &T,
        cached_tree: Option<&[u8]>,
    ) -> Result<(), Error> {
        let chunk_count = T::chunk_count();
        let mut leaf_count = chunk_count.next_power_of_two();
        let parent_index = self.proof.index;
        let decoration = data.decoration();
        if decoration.is_some() {
            leaf_count *= 2;
        }

        let (local_depth, local_index, local_generalized_index) =
            compute_local_merkle_coordinates(parent_index, leaf_count)?;

        let mut is_leaf_local = false;
        if local_generalized_index < parent_index {
            let parent_depth = get_depth(parent_index)?;
            let child_depth = parent_depth - local_depth;
            let node_count = 2usize.pow(child_depth);
            let child_index = node_count + parent_index % node_count;
            self.proof.index = child_index;
            data.prove_element(local_index, self)?;
            self.proof.index = parent_index;
        } else {
            is_leaf_local = true;
        }

        // Use cached tree if provided, otherwise compute
        let tree = if let Some(cached) = cached_tree {
            // Reconstruct Tree from cached bytes
            let mut tree = Tree::from_bytes(cached.to_vec());
            if let Some(decoration) = decoration {
                tree.mix_in_decoration(decoration)?;
            }
            tree
        } else {
            let chunks = data.chunks()?;
            let mut tree = compute_merkle_tree(&chunks, leaf_count)?;
            if let Some(decoration) = decoration {
                tree.mix_in_decoration(decoration)?;
            }
            tree
        };

        if is_leaf_local {
            self.set_leaf(&tree[parent_index]);
        }

        let mut target = local_generalized_index;
        for _ in 0..local_depth {
            let sibling = if target % 2 != 0 { &tree[target - 1] } else { &tree[target + 1] };
            self.extend_branch(sibling);
            target /= 2;
        }

        let root = &tree[1];
        self.set_witness(root);

        Ok(())
    }
}

impl From<Prover> for ProofAndWitness {
    fn from(value: Prover) -> Self {
        (value.proof, value.witness)
    }
}

impl From<GeneralizedIndex> for Prover {
    fn from(index: GeneralizedIndex) -> Self {
        Self {
            proof: Proof { leaf: Default::default(), branch: vec![], index },
            witness: Default::default(),
        }
    }
}

/// Required functionality to support computing Merkle proofs.
pub trait Prove: GeneralizedIndexable {
    /// Compute the "chunks" of this type as required for the SSZ merkle tree computation.
    /// Default implementation signals an error. Implementing types should override
    /// to provide the correct behavior.
    fn chunks(&self) -> Result<Vec<u8>, Error> {
        Err(Error::NotChunkable)
    }

    /// Construct a proof of the member element located at the type-specific `index` assuming the
    /// context in `prover`.
    #[allow(unused)]
    fn prove_element(&self, index: usize, prover: &mut Prover) -> Result<(), Error> {
        Err(Error::NoInnerElement)
    }

    /// Returns the "decoration" if this type has any in the Merkle tree.
    /// For `List`s, the length of the list is hashed into the root of the Merkle tree.
    /// For unions, the type of the currently occupied variant is hashed into the root of the Merkle
    /// tree.
    fn decoration(&self) -> Option<usize> {
        None
    }

    /// Compute a Merkle proof of `Self` at the type's `path`, along with the root of the Merkle
    /// tree as a witness value.
    fn prove(&self, path: Path) -> Result<ProofAndWitness, Error> {
        let index = Self::generalized_index(path)?;
        let mut prover = Prover::from(index);
        prover.compute_proof(self)?;
        Ok(prover.into())
    }

    /// Compute a Merkle proof of `Self` at the type's `path`, along with the root of the Merkle
    /// tree as a witness value, using an optional cached tree.
    fn prove_cached(
        &self,
        path: Path,
        cached_tree: Option<&[u8]>,
    ) -> Result<ProofAndWitness, Error> {
        let index = Self::generalized_index(path)?;
        let mut prover = Prover::from(index);
        prover.compute_proof_cached(self, cached_tree)?;
        Ok(prover.into())
    }

    /// Get the cached tree for this type. This can be used to avoid recomputing the tree
    /// for multiple proofs on the same data.
    fn get_cached_tree(&self) -> Result<Vec<u8>, Error> {
        let chunks = self.chunks()?;
        let chunk_count = Self::chunk_count();
        let mut leaf_count = chunk_count.next_power_of_two();
        let decoration = self.decoration();
        if decoration.is_some() {
            leaf_count *= 2;
        }
        let mut tree = compute_merkle_tree(&chunks, leaf_count)?;
        if let Some(decoration) = decoration {
            tree.mix_in_decoration(decoration)?;
        }
        // Return the raw bytes from the Tree
        Ok(tree.as_bytes().to_vec())
    }
}

/// Contains data necessary to verify `leaf` was included under some witness "root" node
/// at the generalized position `index`.
#[derive(Debug, PartialEq, Eq)]
pub struct Proof {
    pub leaf: Node,
    pub branch: Vec<Node>,
    pub index: GeneralizedIndex,
}

impl Proof {
    /// Verify `self` against the provided `root` witness node.
    /// This `root` is the hash tree root of the SSZ object that produced the proof.
    /// See `Prover` for further information.
    pub fn verify(&self, root: Node) -> Result<(), Error> {
        is_valid_merkle_branch_for_generalized_index(self.leaf, &self.branch, self.index, root)
    }
}

/// Verifies the Merkle proof against the `root` given the other metadata, assuming `leaf` occupies
/// the `generalized_index` in the tree.
pub fn is_valid_merkle_branch_for_generalized_index(
    leaf: Node,
    branch: &[Node],
    generalized_index: GeneralizedIndex,
    root: Node,
) -> Result<(), Error> {
    let depth = log_2(generalized_index).ok_or(Error::InvalidGeneralizedIndex)? as usize;
    let index = get_subtree_index(generalized_index)?;
    is_valid_merkle_branch(leaf, branch, depth, index, root)
}

/// `is_valid_merkle_branch` verifies the Merkle proof against the `root` given the other metadata.
pub fn is_valid_merkle_branch(
    leaf: Node,
    branch: &[Node],
    depth: usize,
    index: usize,
    root: Node,
) -> Result<(), Error> {
    if branch.len() != depth {
        return Err(Error::InvalidProof)
    }

    let mut derived_root = leaf;
    let mut hasher = Sha256::new();

    for (i, node) in branch.iter().enumerate() {
        if (index / 2usize.pow(i as u32)) % 2 != 0 {
            hasher.update(node);
            hasher.update(derived_root);
        } else {
            hasher.update(derived_root);
            hasher.update(node);
        }
        derived_root.copy_from_slice(&hasher.finalize_reset());
    }

    if derived_root == root {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}

/// Returns the buffer indices for the proof path, given the number of leaves and a leaf index.
pub fn compute_proof_branch_indexes(leaf_count: usize, leaf_index: usize) -> Vec<usize> {
    let leaf_start = leaf_count - 1;
    let mut idx = leaf_start + leaf_index;
    let mut branch = Vec::new();

    while idx > 0 {
        let sibling = if idx % 2 == 0 { idx - 1 } else { idx + 1 };
        branch.push(sibling);
        idx = (idx - 1) / 2;
    }
    branch
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::prelude::*;
    use alloy_primitives::hex::FromHex;

    pub(crate) fn decode_node_from_hex(hex: &str) -> Node {
        Node::from_hex(hex).unwrap()
    }

    pub(crate) fn compute_and_verify_proof_for_path<T: SimpleSerialize>(data: &T, path: Path) {
        let (proof, witness) = data.prove(path).unwrap();
        assert_eq!(witness, data.hash_tree_root().unwrap());
        let result = proof.verify(witness);
        if let Err(err) = result {
            panic!("{err} for {proof:?} with witness {witness}")
        }
    }

    /// Helper function to verify that `prove_cached` yields identical results to `prove`
    pub(crate) fn verify_prove_cached_equivalence<T: SimpleSerialize>(data: &T, path: Path) {
        // Get proof using regular prove method
        let (proof_regular, witness_regular) = data.prove(path).unwrap();

        // Get proof using prove_cached with None (should be equivalent to prove)
        let (proof_cached_none, witness_cached_none) = data.prove_cached(path, None).unwrap();

        // Get cached tree and use it for prove_cached
        let cached_tree = data.get_cached_tree().unwrap();
        let (proof_cached_with_tree, witness_cached_with_tree) =
            data.prove_cached(path, Some(&cached_tree)).unwrap();

        // All three methods should produce identical results
        assert_eq!(
            proof_regular.leaf, proof_cached_none.leaf,
            "Leaf mismatch between prove and prove_cached(None)"
        );
        assert_eq!(
            proof_regular.branch, proof_cached_none.branch,
            "Branch mismatch between prove and prove_cached(None)"
        );
        assert_eq!(
            proof_regular.index, proof_cached_none.index,
            "Index mismatch between prove and prove_cached(None)"
        );
        assert_eq!(
            witness_regular, witness_cached_none,
            "Witness mismatch between prove and prove_cached(None)"
        );

        assert_eq!(
            proof_regular.leaf, proof_cached_with_tree.leaf,
            "Leaf mismatch between prove and prove_cached(Some)"
        );
        assert_eq!(
            proof_regular.branch, proof_cached_with_tree.branch,
            "Branch mismatch between prove and prove_cached(Some)"
        );
        assert_eq!(
            proof_regular.index, proof_cached_with_tree.index,
            "Index mismatch between prove and prove_cached(Some)"
        );
        assert_eq!(
            witness_regular, witness_cached_with_tree,
            "Witness mismatch between prove and prove_cached(Some)"
        );

        // Verify all proofs are valid
        assert!(proof_regular.verify(witness_regular).is_ok(), "Regular proof verification failed");
        assert!(
            proof_cached_none.verify(witness_cached_none).is_ok(),
            "Cached proof (None) verification failed"
        );
        assert!(
            proof_cached_with_tree.verify(witness_cached_with_tree).is_ok(),
            "Cached proof (Some) verification failed"
        );

        // Verify witnesses match hash tree root
        let expected_root = data.hash_tree_root().unwrap();
        assert_eq!(witness_regular, expected_root, "Regular witness doesn't match hash tree root");
        assert_eq!(
            witness_cached_none, expected_root,
            "Cached witness (None) doesn't match hash tree root"
        );
        assert_eq!(
            witness_cached_with_tree, expected_root,
            "Cached witness (Some) doesn't match hash tree root"
        );
    }

    #[test]
    fn test_is_valid_merkle_branch() {
        let leaf = decode_node_from_hex(
            "94159da973dfa9e40ed02535ee57023ba2d06bad1017e451055470967eb71cd5",
        );
        let branch = [
            "8f594dbb4f4219ad4967f86b9cccdb26e37e44995a291582a431eef36ecba45c",
            "f8c2ed25e9c31399d4149dcaa48c51f394043a6a1297e65780a5979e3d7bb77c",
            "382ba9638ce263e802593b387538faefbaed106e9f51ce793d405f161b105ee6",
        ]
        .into_iter()
        .map(decode_node_from_hex)
        .collect::<Vec<_>>();
        let depth = 3;
        let index = 2;
        let root = decode_node_from_hex(
            "27097c728aade54ff1376d5954681f6d45c282a81596ef19183148441b754abb",
        );

        assert!(is_valid_merkle_branch(leaf, &branch, depth, index, root).is_ok());
    }

    #[test]
    fn test_simple_proof() {
        let leaf = decode_node_from_hex(
            "94159da973dfa9e40ed02535ee57023ba2d06bad1017e451055470967eb71cd5",
        );
        let branch = [
            "8f594dbb4f4219ad4967f86b9cccdb26e37e44995a291582a431eef36ecba45c",
            "f8c2ed25e9c31399d4149dcaa48c51f394043a6a1297e65780a5979e3d7bb77c",
            "382ba9638ce263e802593b387538faefbaed106e9f51ce793d405f161b105ee6",
        ]
        .into_iter()
        .map(decode_node_from_hex)
        .collect::<Vec<_>>();
        let depth = 3;
        let index = 2;
        let proof = Proof { leaf, branch, index: 2usize.pow(depth) + index };
        let root = decode_node_from_hex(
            "27097c728aade54ff1376d5954681f6d45c282a81596ef19183148441b754abb",
        );
        let result = proof.verify(root);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_proving() {
        let inner: Vec<List<u8, 1073741824>> = vec![
            vec![0u8, 1u8, 2u8].try_into().unwrap(),
            vec![3u8, 4u8, 5u8].try_into().unwrap(),
            vec![6u8, 7u8, 8u8].try_into().unwrap(),
            vec![9u8, 10u8, 11u8].try_into().unwrap(),
        ];

        // Emulate a transactions tree
        let outer: List<List<u8, 1073741824>, 1048576> = List::try_from(inner).unwrap();

        let root = outer.hash_tree_root().unwrap();

        let index = PathElement::from(1);

        let start_proof = std::time::Instant::now();
        let (proof, witness) = outer.prove(&[index]).unwrap();
        println!("Generated proof in {:?}", start_proof.elapsed());

        // Root and witness must be the same
        assert_eq!(root, witness);

        let start_verify = std::time::Instant::now();
        assert!(proof.verify(witness).is_ok());
        println!("Verified proof in {:?}", start_verify.elapsed());
    }

    #[test]
    fn test_proving_primitives_fails_with_bad_path() {
        let data = 8u8;
        let result = data.prove(&[PathElement::Length]);
        assert!(result.is_err());

        let data = true;
        let result = data.prove(&[234.into()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_prove_primitives() {
        let data = 8u8;
        compute_and_verify_proof_for_path(&data, &[]);

        let data = 0u8;
        compute_and_verify_proof_for_path(&data, &[]);

        let data = 234238u64;
        compute_and_verify_proof_for_path(&data, &[]);

        let data = 0u128;
        compute_and_verify_proof_for_path(&data, &[]);

        let data = u128::MAX;
        compute_and_verify_proof_for_path(&data, &[]);

        let data = U256::from_str_radix(
            "f8c2ed25e9c31399d4149dcaa48c51f394043a6a1297e65780a5979e3d7bb77c",
            16,
        )
        .unwrap();
        compute_and_verify_proof_for_path(&data, &[]);

        let data = true;
        compute_and_verify_proof_for_path(&data, &[]);

        let data = false;
        compute_and_verify_proof_for_path(&data, &[]);
    }

    #[test]
    fn test_prove_cached_equivalence_primitives() {
        // Test various primitive types to ensure prove_cached yields same results as prove
        let data = 8u8;
        verify_prove_cached_equivalence(&data, &[]);

        let data = 0u8;
        verify_prove_cached_equivalence(&data, &[]);

        let data = 234238u64;
        verify_prove_cached_equivalence(&data, &[]);

        let data = 0u128;
        verify_prove_cached_equivalence(&data, &[]);

        let data = u128::MAX;
        verify_prove_cached_equivalence(&data, &[]);

        let data = U256::from_str_radix(
            "f8c2ed25e9c31399d4149dcaa48c51f394043a6a1297e65780a5979e3d7bb77c",
            16,
        )
        .unwrap();
        verify_prove_cached_equivalence(&data, &[]);

        let data = true;
        verify_prove_cached_equivalence(&data, &[]);

        let data = false;
        verify_prove_cached_equivalence(&data, &[]);
    }

    #[test]
    fn test_prove_cached_equivalence_lists() {
        // Test List with various paths
        let inner: Vec<List<u8, 1073741824>> = vec![
            vec![0u8, 1u8, 2u8].try_into().unwrap(),
            vec![3u8, 4u8, 5u8].try_into().unwrap(),
            vec![6u8, 7u8, 8u8].try_into().unwrap(),
            vec![9u8, 10u8, 11u8].try_into().unwrap(),
        ];

        let outer: List<List<u8, 1073741824>, 1048576> = List::try_from(inner).unwrap();

        // Test different paths
        verify_prove_cached_equivalence(&outer, &[PathElement::from(0)]);
        verify_prove_cached_equivalence(&outer, &[PathElement::from(1)]);
        verify_prove_cached_equivalence(&outer, &[PathElement::from(2)]);
        verify_prove_cached_equivalence(&outer, &[PathElement::from(3)]);
        verify_prove_cached_equivalence(&outer, &[PathElement::Length]);
    }

    #[test]
    fn test_prove_cached_equivalent_to_prove_for_lists() {
        // Create the same type of list as in the benchmark
        let inner: Vec<List<u8, 1073741824>> = vec![
            vec![0u8, 1u8, 2u8].try_into().unwrap(),
            vec![3u8, 4u8, 5u8].try_into().unwrap(),
            vec![6u8, 7u8, 8u8].try_into().unwrap(),
            vec![9u8, 10u8, 11u8].try_into().unwrap(),
        ];
        let outer: List<List<u8, 1073741824>, 1048576> = List::try_from(inner).unwrap();

        // Use the same path as the benchmark
        let index = outer.len() / 2; // This is 2
        let path = vec![PathElement::from(index)];

        println!("Testing list prove vs prove_cached with index {}", index);

        // Test prove
        let (proof_regular, witness_regular) = outer.prove(&path).unwrap();

        // Test prove_cached with None
        let (proof_cached_none, witness_cached_none) = outer.prove_cached(&path, None).unwrap();

        // Test prove_cached with cached tree
        let cached_tree = outer.get_cached_tree().unwrap();
        let (proof_cached_with_tree, witness_cached_with_tree) =
            outer.prove_cached(&path, Some(&cached_tree)).unwrap();

        println!(
            "Regular proof: leaf={:?}, index={}, branch_len={}",
            proof_regular.leaf,
            proof_regular.index,
            proof_regular.branch.len()
        );
        println!(
            "Cached proof (None): leaf={:?}, index={}, branch_len={}",
            proof_cached_none.leaf,
            proof_cached_none.index,
            proof_cached_none.branch.len()
        );
        println!(
            "Cached proof (Some): leaf={:?}, index={}, branch_len={}",
            proof_cached_with_tree.leaf,
            proof_cached_with_tree.index,
            proof_cached_with_tree.branch.len()
        );

        // Verify all proofs are identical
        assert_eq!(proof_regular.leaf, proof_cached_none.leaf, "Leaf mismatch (None)");
        assert_eq!(proof_regular.branch, proof_cached_none.branch, "Branch mismatch (None)");
        assert_eq!(proof_regular.index, proof_cached_none.index, "Index mismatch (None)");
        assert_eq!(witness_regular, witness_cached_none, "Witness mismatch (None)");

        assert_eq!(proof_regular.leaf, proof_cached_with_tree.leaf, "Leaf mismatch (Some)");
        assert_eq!(proof_regular.branch, proof_cached_with_tree.branch, "Branch mismatch (Some)");
        assert_eq!(proof_regular.index, proof_cached_with_tree.index, "Index mismatch (Some)");
        assert_eq!(witness_regular, witness_cached_with_tree, "Witness mismatch (Some)");

        // Verify proofs can be verified
        assert!(proof_regular.verify(witness_regular).is_ok(), "Regular proof verification failed");
        assert!(
            proof_cached_none.verify(witness_cached_none).is_ok(),
            "Cached proof (None) verification failed"
        );
        assert!(
            proof_cached_with_tree.verify(witness_cached_with_tree).is_ok(),
            "Cached proof (Some) verification failed"
        );

        println!("✅ All proofs are equivalent and verify successfully!");
    }

    #[test]
    fn test_prove_cached_various_list_sizes() {
        // Test different list sizes to ensure prove_cached works consistently
        for size in [1, 2, 4, 8, 16, 32] {
            let data: List<u64, 128> =
                (0..size).map(|i| i as u64).collect::<Vec<_>>().try_into().unwrap();

            // Test middle element
            let index = size / 2;
            let path = vec![PathElement::from(index)];

            let (proof_regular, witness_regular) = data.prove(&path).unwrap();
            let (proof_cached_none, witness_cached_none) = data.prove_cached(&path, None).unwrap();

            let cached_tree = data.get_cached_tree().unwrap();
            let (proof_cached_with_tree, witness_cached_with_tree) =
                data.prove_cached(&path, Some(&cached_tree)).unwrap();

            // All should be identical
            assert_eq!(
                proof_regular.leaf, proof_cached_none.leaf,
                "Size {} - Leaf mismatch (None)",
                size
            );
            assert_eq!(
                proof_regular.branch, proof_cached_none.branch,
                "Size {} - Branch mismatch (None)",
                size
            );
            assert_eq!(
                proof_regular.index, proof_cached_none.index,
                "Size {} - Index mismatch (None)",
                size
            );
            assert_eq!(
                witness_regular, witness_cached_none,
                "Size {} - Witness mismatch (None)",
                size
            );

            assert_eq!(
                proof_regular.leaf, proof_cached_with_tree.leaf,
                "Size {} - Leaf mismatch (Some)",
                size
            );
            assert_eq!(
                proof_regular.branch, proof_cached_with_tree.branch,
                "Size {} - Branch mismatch (Some)",
                size
            );
            assert_eq!(
                proof_regular.index, proof_cached_with_tree.index,
                "Size {} - Index mismatch (Some)",
                size
            );
            assert_eq!(
                witness_regular, witness_cached_with_tree,
                "Size {} - Witness mismatch (Some)",
                size
            );

            // Verify proofs
            assert!(
                proof_regular.verify(witness_regular).is_ok(),
                "Size {} - Regular proof verification failed",
                size
            );
            assert!(
                proof_cached_none.verify(witness_cached_none).is_ok(),
                "Size {} - Cached proof (None) verification failed",
                size
            );
            assert!(
                proof_cached_with_tree.verify(witness_cached_with_tree).is_ok(),
                "Size {} - Cached proof (Some) verification failed",
                size
            );
        }
    }

    #[test]
    fn test_prove_cached_list_length_proof() {
        // Test proving the length of a list
        let data: List<u32, 256> =
            (0..10).map(|i| i as u32).collect::<Vec<_>>().try_into().unwrap();
        let path = vec![PathElement::Length];

        let (proof_regular, witness_regular) = data.prove(&path).unwrap();
        let (proof_cached_none, witness_cached_none) = data.prove_cached(&path, None).unwrap();

        let cached_tree = data.get_cached_tree().unwrap();
        let (proof_cached_with_tree, witness_cached_with_tree) =
            data.prove_cached(&path, Some(&cached_tree)).unwrap();

        // All should be identical
        assert_eq!(
            proof_regular.leaf, proof_cached_none.leaf,
            "Length proof - Leaf mismatch (None)"
        );
        assert_eq!(
            proof_regular.branch, proof_cached_none.branch,
            "Length proof - Branch mismatch (None)"
        );
        assert_eq!(
            proof_regular.index, proof_cached_none.index,
            "Length proof - Index mismatch (None)"
        );
        assert_eq!(witness_regular, witness_cached_none, "Length proof - Witness mismatch (None)");

        assert_eq!(
            proof_regular.leaf, proof_cached_with_tree.leaf,
            "Length proof - Leaf mismatch (Some)"
        );
        assert_eq!(
            proof_regular.branch, proof_cached_with_tree.branch,
            "Length proof - Branch mismatch (Some)"
        );
        assert_eq!(
            proof_regular.index, proof_cached_with_tree.index,
            "Length proof - Index mismatch (Some)"
        );
        assert_eq!(
            witness_regular, witness_cached_with_tree,
            "Length proof - Witness mismatch (Some)"
        );

        // Verify proofs
        assert!(
            proof_regular.verify(witness_regular).is_ok(),
            "Length proof - Regular verification failed"
        );
        assert!(
            proof_cached_none.verify(witness_cached_none).is_ok(),
            "Length proof - Cached (None) verification failed"
        );
        assert!(
            proof_cached_with_tree.verify(witness_cached_with_tree).is_ok(),
            "Length proof - Cached (Some) verification failed"
        );
    }

    #[test]
    fn test_prove_cached_equivalence_vectors() {
        // Test Vector types
        let data: Vector<u32, 8> = vec![1u32, 2, 3, 4, 5, 6, 7, 8].try_into().unwrap();

        // Test different indices
        for i in 0..8 {
            verify_prove_cached_equivalence(&data, &[PathElement::from(i)]);
        }
    }

    #[test]
    fn test_prove_cached_equivalence_containers() {
        // Test container types
        #[derive(Debug, Default, PartialEq, Eq, SimpleSerialize)]
        struct TestContainer {
            a: u64,
            b: Vector<u8, 32>,
            c: List<u16, 128>,
        }

        let container = TestContainer {
            a: 42,
            b: vec![1u8; 32].try_into().unwrap(),
            c: vec![10u16, 20, 30].try_into().unwrap(),
        };

        // Test proving different fields
        verify_prove_cached_equivalence(&container, &[PathElement::from(0)]); // field a
        verify_prove_cached_equivalence(&container, &[PathElement::from(1)]); // field b
        verify_prove_cached_equivalence(&container, &[PathElement::from(2)]); // field c

        // Test nested paths
        verify_prove_cached_equivalence(&container, &[PathElement::from(1), PathElement::from(0)]); // b[0]
        verify_prove_cached_equivalence(&container, &[PathElement::from(2), PathElement::from(1)]); // c[1]
        verify_prove_cached_equivalence(&container, &[PathElement::from(2), PathElement::Length]); // c.len()
    }

    #[test]
    fn test_prove_cached_equivalence_bitvector() {
        // Test Bitvector
        let mut bitvector = Bitvector::<64>::default();
        bitvector.set(5, true).unwrap();
        bitvector.set(13, true).unwrap();
        bitvector.set(42, true).unwrap();

        // Test different bit indices
        verify_prove_cached_equivalence(&bitvector, &[PathElement::from(5)]);
        verify_prove_cached_equivalence(&bitvector, &[PathElement::from(13)]);
        verify_prove_cached_equivalence(&bitvector, &[PathElement::from(42)]);
    }

    #[test]
    fn test_prove_cached_equivalence_bitlist() {
        // Test Bitlist
        let mut bit_array = vec![false; 20];
        bit_array[3] = true;
        bit_array[7] = true;
        bit_array[15] = true;
        let bitlist = Bitlist::<64>::try_from(bit_array.as_slice()).unwrap();

        // Test different paths
        verify_prove_cached_equivalence(&bitlist, &[PathElement::from(3)]);
        verify_prove_cached_equivalence(&bitlist, &[PathElement::from(7)]);
        verify_prove_cached_equivalence(&bitlist, &[PathElement::from(15)]);
        verify_prove_cached_equivalence(&bitlist, &[PathElement::Length]);
    }

    #[test]
    fn test_prove_cached_equivalence_edge_cases() {
        // Test empty list
        let empty_list: List<u8, 128> = List::default();
        verify_prove_cached_equivalence(&empty_list, &[PathElement::Length]);

        // Test single element list
        let single_list: List<u64, 128> = vec![42u64].try_into().unwrap();
        verify_prove_cached_equivalence(&single_list, &[PathElement::from(0)]);
        verify_prove_cached_equivalence(&single_list, &[PathElement::Length]);

        // Test maximum values
        let max_u8 = u8::MAX;
        verify_prove_cached_equivalence(&max_u8, &[]);

        let max_u64 = u64::MAX;
        verify_prove_cached_equivalence(&max_u64, &[]);
    }

    #[test]
    fn test_prove_cached_equivalence_property_based_lists() {
        // Property-based testing with different list sizes and contents
        for size in [1, 2, 3, 5, 8, 13, 21, 34, 55, 89] {
            let data: List<u64, 128> =
                (0..size).map(|i| (i * 7) as u64).collect::<Vec<_>>().try_into().unwrap();

            // Test accessing different indices
            for i in 0..size {
                verify_prove_cached_equivalence(&data, &[PathElement::from(i)]);
            }

            // Always test length
            verify_prove_cached_equivalence(&data, &[PathElement::Length]);
        }
    }

    #[test]
    fn test_prove_cached_equivalence_property_based_vectors() {
        // Property-based testing with vectors of different patterns
        let patterns = [
            vec![0u32; 16],
            (0..16).collect::<Vec<u32>>(),
            (0..16).map(|x| x * x).collect::<Vec<u32>>(),
            vec![u32::MAX; 16],
            (0..16).map(|x| 1u32 << (x % 32)).collect::<Vec<u32>>(),
        ];

        for pattern in patterns {
            let data: Vector<u32, 16> = pattern.try_into().unwrap();

            // Test random indices
            for i in [0, 1, 7, 8, 15] {
                verify_prove_cached_equivalence(&data, &[PathElement::from(i)]);
            }
        }
    }

    #[test]
    fn test_prove_cached_equivalence_nested_containers() {
        // Test deeply nested structures
        #[derive(Debug, Default, PartialEq, Eq, SimpleSerialize)]
        struct InnerContainer {
            x: u32,
            y: Vector<u8, 4>,
        }

        #[derive(Debug, Default, PartialEq, Eq, SimpleSerialize)]
        struct OuterContainer {
            inner: InnerContainer,
            data: List<u16, 8>,
        }

        let container = OuterContainer {
            inner: InnerContainer { x: 42, y: vec![1, 2, 3, 4].try_into().unwrap() },
            data: vec![100, 200, 300].try_into().unwrap(),
        };

        // Test various nested paths
        verify_prove_cached_equivalence(&container, &[PathElement::from(0)]); // inner
        verify_prove_cached_equivalence(&container, &[PathElement::from(1)]); // data
        verify_prove_cached_equivalence(&container, &[PathElement::from(0), PathElement::from(0)]); // inner.x
        verify_prove_cached_equivalence(&container, &[PathElement::from(0), PathElement::from(1)]); // inner.y
        verify_prove_cached_equivalence(
            &container,
            &[PathElement::from(0), PathElement::from(1), PathElement::from(2)],
        ); // inner.y[2]
        verify_prove_cached_equivalence(&container, &[PathElement::from(1), PathElement::from(1)]); // data[1]
        verify_prove_cached_equivalence(&container, &[PathElement::from(1), PathElement::Length]); // data.len()
    }
}
