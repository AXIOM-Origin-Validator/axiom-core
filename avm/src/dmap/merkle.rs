//! Merkle Tree for DMAP Checkpoints
//!
//! Simple binary Merkle tree over checkpoint hashes.
//! Supports proof generation and verification for revealed checkpoints.

use alloc::vec::Vec;

/// Domain prefix for leaf nodes (prevents second-preimage attacks)
const LEAF_PREFIX: u8 = 0x00;
/// Domain prefix for internal nodes
const INTERNAL_PREFIX: u8 = 0x01;

/// Empty leaf hash (BLAKE3 of leaf-domain-tagged empty)
fn empty_hash() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    *hasher.finalize().as_bytes()
}

/// Hash two children to produce internal node
///
/// Uses INTERNAL_PREFIX domain tag to distinguish internal nodes from leaves.
/// This prevents second-preimage attacks where a 64-byte leaf could be
/// reinterpreted as an internal node (or vice versa).
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[INTERNAL_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Compute Merkle root from a list of leaf hashes
///
/// Pads to next power of 2 with empty hashes.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Pad to power of 2
    let n = leaves.len().next_power_of_two();
    let empty = empty_hash();
    let mut current: Vec<[u8; 32]> = Vec::with_capacity(n);
    current.extend_from_slice(leaves);
    while current.len() < n {
        current.push(empty);
    }

    // Build tree bottom-up
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        current = next;
    }

    current[0]
}

/// Generate a Merkle proof for the leaf at `index`
///
/// Returns sibling hashes from leaf to root.
pub fn generate_merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let n = leaves.len().next_power_of_two();
    let empty = empty_hash();
    let mut current: Vec<[u8; 32]> = Vec::with_capacity(n);
    current.extend_from_slice(leaves);
    while current.len() < n {
        current.push(empty);
    }

    let mut proof = Vec::new();
    let mut idx = index;

    while current.len() > 1 {
        // Sibling index
        let sibling = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
        if sibling < current.len() {
            proof.push(current[sibling]);
        } else {
            proof.push(empty);
        }

        // Move up
        let mut next = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        current = next;
        idx /= 2;
    }

    proof
}

/// Verify a Merkle proof for a leaf hash against a known root
pub fn verify_merkle_proof(
    leaf_hash: &[u8; 32],
    proof: &[[u8; 32]],
    index: usize,
    root: &[u8; 32],
) -> bool {
    let mut current = *leaf_hash;
    let mut idx = index;

    for sibling in proof {
        if idx.is_multiple_of(2) {
            current = hash_pair(&current, sibling);
        } else {
            current = hash_pair(sibling, &current);
        }
        idx /= 2;
    }

    current == *root
}

/// A pre-built Merkle tree (stores all levels for efficient proof generation)
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        let root = compute_merkle_root(&leaves);
        MerkleTree { leaves, root }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn proof(&self, index: usize) -> Vec<[u8; 32]> {
        generate_merkle_proof(&self.leaves, index)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let leaf = [0xAB; 32];
        let root = compute_merkle_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_two_leaves() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let root = compute_merkle_root(&[a, b]);
        let expected = hash_pair(&a, &b);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_proof_verification() {
        let leaves: Vec<[u8; 32]> = (0..8u8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                h
            })
            .collect();

        let root = compute_merkle_root(&leaves);

        // Verify proof for each leaf
        for i in 0..leaves.len() {
            let proof = generate_merkle_proof(&leaves, i);
            assert!(
                verify_merkle_proof(&leaves[i], &proof, i, &root),
                "Proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_wrong_proof_rejected() {
        let leaves: Vec<[u8; 32]> = (0..4u8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                h
            })
            .collect();

        let root = compute_merkle_root(&leaves);
        let proof = generate_merkle_proof(&leaves, 0);

        // Wrong leaf should fail
        let wrong_leaf = [0xFF; 32];
        assert!(!verify_merkle_proof(&wrong_leaf, &proof, 0, &root));
    }

    #[test]
    fn test_non_power_of_two() {
        let leaves: Vec<[u8; 32]> = (0..5u8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                h
            })
            .collect();

        let root = compute_merkle_root(&leaves);

        for i in 0..leaves.len() {
            let proof = generate_merkle_proof(&leaves, i);
            assert!(verify_merkle_proof(&leaves[i], &proof, i, &root));
        }
    }

    #[test]
    fn test_merkle_tree_struct() {
        let leaves: Vec<[u8; 32]> = (0..4u8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                h
            })
            .collect();

        let tree = MerkleTree::new(leaves.clone());
        assert_eq!(tree.len(), 4);

        for i in 0..4 {
            let proof = tree.proof(i);
            assert!(verify_merkle_proof(&leaves[i], &proof, i, &tree.root()));
        }
    }

    #[test]
    fn test_domain_separation_leaf_vs_internal() {
        // A raw BLAKE3(left || right) must NOT equal hash_pair(left, right)
        // because hash_pair prepends INTERNAL_PREFIX
        let left = [1u8; 32];
        let right = [2u8; 32];

        let naive = {
            let mut h = blake3::Hasher::new();
            h.update(&left);
            h.update(&right);
            *h.finalize().as_bytes()
        };

        let domain_tagged = hash_pair(&left, &right);
        assert_ne!(naive, domain_tagged,
            "Internal node hash must differ from naive concatenation (domain separation)");
    }
}
