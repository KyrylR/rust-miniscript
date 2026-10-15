// SPDX-License-Identifier: CC0-1.0

//! Taproot Spending Information
//!
//! Provides a structure which can be used to obtain control blocks and other information
//! needed for Taproot spends.
//!

use elements::hashes::{sha256t, HashEngine};
use elements::schnorr::{TapTweak as _, TweakedPublicKey, UntweakedPublicKey};
use elements::secp256k1_zkp::{Parity, Secp256k1};
use elements::taproot::{
    ControlBlock, LeafVersion, TapBranchTag, TapLeafHash, TapNodeHash, TaprootBuilder,
    TaprootMerkleBranch, TAPROOT_CONTROL_MAX_NODE_COUNT,
};
use elements::{pset, Script};

use super::taptree::TapLeaf;
use crate::extensions::{CovExtArgs, CovenantExt, Extension, ParseableExt};
use crate::miniscript::context::Tap;
use crate::prelude::Vec;
#[cfg(feature = "simplicity")]
use crate::simplicity::SimplicityLeaf;
use crate::sync::Arc;
use crate::{Miniscript, MiniscriptKey, ToPublicKey};

/// Utility structure which maintains a stack of bits (at most 128) using a u128.
///
/// Will panic if the user attempts to push more than 128 bits; we assume in this
/// module that we are starting with a validated [`super::TapTree`] and therefore
/// that this can't happen.
#[derive(Default)]
struct BitStack128 {
    inner: u128,
    height: u8,
}

impl BitStack128 {
    fn push(&mut self, bit: bool) {
        if bit {
            self.inner |= 1u128 << self.height;
        } else {
            self.inner &= !(1u128 << self.height);
        }
        self.height += 1;
    }

    fn pop(&mut self) -> Option<bool> {
        if self.height > 0 {
            self.height -= 1;
            Some(self.inner & (1u128 << self.height) != 0)
        } else {
            None
        }
    }
}

/// Stack of `(bool, usize)` elements, with a maximum capacity of `TAPROOT_CONTROL_MAX_NODE_COUNT`.
///
/// Avoids heap allocation. Flags and indices are kept apart because a pair would be
/// padded to 16 bytes, twice what an index needs.
struct ParentStack {
    done_left: BitStack128,
    indices: [usize; TAPROOT_CONTROL_MAX_NODE_COUNT],
}

impl ParentStack {
    fn new() -> Self {
        Self { done_left: BitStack128::default(), indices: [0; TAPROOT_CONTROL_MAX_NODE_COUNT] }
    }

    fn push(&mut self, val: (bool, usize)) {
        // The stack never grows past the depth of a leaf, and a `TapTree` cannot be built with
        // leaves deeper than `TAPROOT_CONTROL_MAX_NODE_COUNT`, so the last index written is
        // `TAPROOT_CONTROL_MAX_NODE_COUNT - 1` and `indices` is exactly big enough.
        let (done_left_child, index) = val;

        // Written first: the bounds check is active in release, the shift in `BitStack128` is not.
        self.indices[self.len()] = index;
        self.done_left.push(done_left_child);
    }

    fn pop(&mut self) -> Option<(bool, usize)> {
        let done_left_child = self.done_left.pop()?;
        Some((done_left_child, self.indices[self.len()]))
    }

    fn len(&self) -> usize { usize::from(self.done_left.height) }
}

/// Computes the hash of a branch node from the hashes of its children, with the
/// Elements `TapBranch/elements` tag.
fn branch_hash(a: TapNodeHash, b: TapNodeHash) -> TapNodeHash {
    let (a, b) = if a < b { (a, b) } else { (b, a) };
    let mut eng = sha256t::Hash::<TapBranchTag>::engine();
    eng.input(a.as_byte_array());
    eng.input(b.as_byte_array());
    TapNodeHash::from_byte_array(eng.finalize().to_byte_array())
}

/// A structure which can be used to obtain control blocks and other information
/// needed for Taproot spends.
///
/// Conceptually, this object is a copy of the Taproot tree with each leave annotated
/// with extra information that can be used to compute its control block.
pub struct TrSpendInfo<Pk: MiniscriptKey, Ext: Extension = CovenantExt<CovExtArgs>> {
    internal_key: UntweakedPublicKey,
    output_key: TweakedPublicKey,
    output_key_parity: Parity,
    /// The nodes of the tree, in pre-order, i.e. left-to-right depth-first order.
    nodes: Vec<TrSpendInfoNode<Pk, Ext>>,
}

impl<Pk: ToPublicKey, Ext: ParseableExt> TrSpendInfo<Pk, Ext> {
    fn nodes_from_tap_tree(tree: &super::TapTree<Pk, Ext>) -> Vec<TrSpendInfoNode<Pk, Ext>> {
        let mut nodes = vec![];
        let mut parent_stack = ParentStack::new();
        for leaf in tree.leaves() {
            let depth = usize::from(leaf.depth());
            let script = leaf.compute_script();

            let leaf_hash = TapLeafHash::from_script(&script, leaf.leaf_version());
            let mut current_hash = TapNodeHash::from_byte_array(leaf_hash.to_byte_array());

            // 1. If this node increases our depth, add parents.
            while parent_stack.len() < depth {
                // When we encounter a leaf we put all of its parent nodes into the
                // result. We set the "sibling hash" to a dummy value (specifically,
                // `current_hash`, because it's convenient and the right type).
                parent_stack.push((false, nodes.len()));
                nodes.push(TrSpendInfoNode { sibling_hash: current_hash, leaf_data: None });
            }
            // If parent_stack.len() < depth then we pushed things onto the stack in
            // the previous step so that we now have equality. Meanwhile, it is
            // impossible for parent_stack.len() > depth because we pop things off
            // the stack in step 3 below.
            assert_eq!(depth, parent_stack.len());

            // 2. Add the node.
            //
            // Again, we don't know the sibling hash yet so we use the current hash.
            // But this time the current hash isn't an arbitrary dummy value -- in the
            // next step we will have an invariant that incomplete nodes' "sibling hashes"
            // are set to the nodes' own hashes.
            //
            // We will use this hash to compute the parent's hash then replace it with
            // the actual sibling hash. We do this for every node EXCEPT the root node,
            // whose "sibling hash" will then wind up being equal to the Merkle root
            // of the whole tree.
            nodes.push(TrSpendInfoNode {
                sibling_hash: current_hash,
                leaf_data: Some(LeafData { script, leaf: leaf.leaf.clone(), leaf_hash }),
            });

            // 3. Recursively complete nodes as long as we are on a right branch.
            //
            // As described above, for each parent node, we compute its hash and store it
            // in `sibling_hash`. At that point we're done with the childrens' hashes so
            // we finally replace those with their sibling hashes.
            let mut cur_index = nodes.len() - 1;
            while let Some((done_left_child, parent_idx)) = parent_stack.pop() {
                if done_left_child {
                    let lchild_hash = nodes[parent_idx + 1].sibling_hash;
                    // Set current node's "sibling hash" to its own hash.
                    let new_merkle_root = branch_hash(lchild_hash, current_hash);
                    nodes[parent_idx].sibling_hash = new_merkle_root;
                    // Set the children's sibling hashes to each others' hashes.
                    nodes[parent_idx + 1].sibling_hash = current_hash;
                    nodes[cur_index].sibling_hash = lchild_hash;
                    // Recurse.
                    current_hash = new_merkle_root;
                    cur_index = parent_idx;
                } else {
                    // Once we hit a left branch we can't do anything until we see the next leaf.
                    parent_stack.push((true, parent_idx));
                    break;
                }
            }
        }
        debug_assert_eq!(parent_stack.len(), 0);
        debug_assert_ne!(nodes.len(), 0);

        nodes
    }

    /// Constructs a [`TrSpendInfo`] for a [`super::Tr`].
    pub fn from_tr(tr: &super::Tr<Pk, Ext>) -> Self {
        let internal_key = tr.internal_key().to_x_only_pubkey();

        let nodes = match tr.tap_tree() {
            Some(tree) => Self::nodes_from_tap_tree(tree),
            None => vec![],
        };

        let secp = Secp256k1::verification_only();
        let (output_key, output_key_parity) =
            internal_key.tap_tweak(&secp, nodes.first().map(|node| node.sibling_hash));

        Self { internal_key, output_key, output_key_parity, nodes }
    }

    /// If this [`TrSpendInfo`] has an associated Taproot tree, return its Merkle root.
    pub fn merkle_root(&self) -> Option<TapNodeHash> {
        // As described in `nodes_from_tap_tree`, the "sibling hash" of the root node
        // is actually the Merkle root of the whole tree.
        self.nodes.first().map(|node| node.sibling_hash)
    }

    /// The internal key of the Taproot output.
    ///
    /// This returns the x-only public key which appears on-chain. For the abstroct
    /// public key, use the `internal_key` method on the original [`super::Tr`] used to
    /// create this object.
    pub fn internal_key(&self) -> UntweakedPublicKey { self.internal_key }

    // I don't really like these names, but they're used in rust-bitcoin so we'll stick
    // with them and just doc-alias them to better names so they show up in search results.
    /// The external key of the Taproot output.
    #[doc(alias = "external_key")]
    pub fn output_key(&self) -> TweakedPublicKey { self.output_key }

    /// The parity of the external key of the Taproot output.
    #[doc(alias = "external_key_parity")]
    pub fn output_key_parity(&self) -> Parity { self.output_key_parity }

    /// An iterator over the leaves of the Taptree.
    ///
    /// This yields the same leaves in the same order as [`super::Tr::leaves`] on the original
    /// [`super::Tr`]. However, in addition to yielding the leaves and their depths, it also
    /// yields their scripts, leafhashes, and control blocks.
    pub fn leaves(&self) -> TrSpendInfoIter<'_, Pk, Ext> {
        TrSpendInfoIter {
            spend_info: self,
            index: 0,
            merkle_stack: Vec::with_capacity(TAPROOT_CONTROL_MAX_NODE_COUNT),
            done_left_stack: BitStack128::default(),
        }
    }

    /// If the Taproot tree is not keyspend-only, converts it to a [`pset::TapTree`] structure.
    ///
    /// This conversion is not particularly efficient but the resulting data structure is
    /// useful for interacting with PSETs.
    pub fn to_tap_tree(&self) -> Option<pset::TapTree> {
        if self.nodes.is_empty() {
            return None;
        }

        let mut builder = TaprootBuilder::new();
        for leaf in self.leaves() {
            builder = builder
                .add_leaf_with_ver(
                    usize::from(leaf.depth()),
                    leaf.script().clone(),
                    leaf.leaf_version(),
                )
                .expect("iterating through tree in correct DFS order")
        }
        Some(pset::TapTree::from_inner(builder).expect("tree is complete"))
    }
}

/// An internal node of the spend
#[derive(Debug)]
struct TrSpendInfoNode<Pk: MiniscriptKey, Ext: Extension> {
    sibling_hash: TapNodeHash,
    leaf_data: Option<LeafData<Pk, Ext>>,
}

#[derive(Debug)]
struct LeafData<Pk: MiniscriptKey, Ext: Extension> {
    script: Script,
    leaf: TapLeaf<Pk, Ext>,
    leaf_hash: TapLeafHash,
}

/// An iterator over the leaves of a Taproot tree. Produced by [`TrSpendInfo::leaves`].
///
/// This is conceptually similar to [`super::TapTreeIter`], which can be obtained by
/// calling [`super::TapTree::leaves`]. That iterator goes over the leaves of the tree,
/// yielding the Miniscripts of the leaves and their depth.
///
/// This iterator goes over the leaves in the same order, yielding the data that actually
/// goes on chain: their scripts, control blocks, etc.
pub struct TrSpendInfoIter<'sp, Pk: MiniscriptKey, Ext: Extension = CovenantExt<CovExtArgs>> {
    spend_info: &'sp TrSpendInfo<Pk, Ext>,
    index: usize,
    merkle_stack: Vec<TapNodeHash>,
    done_left_stack: BitStack128,
}

impl<'sp, Pk: MiniscriptKey, Ext: Extension> Iterator for TrSpendInfoIter<'sp, Pk, Ext> {
    type Item = TrSpendInfoIterItem<'sp, Pk, Ext>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.spend_info.nodes.len() {
            let current_node = &self.spend_info.nodes[self.index];
            if self.index > 0 {
                self.merkle_stack.push(current_node.sibling_hash);
            }
            self.index += 1;

            if let Some(ref leaf) = current_node.leaf_data {
                // leaf
                let mut merkle_stack = self.merkle_stack.clone();
                merkle_stack.reverse();
                self.merkle_stack.pop();

                loop {
                    match self.done_left_stack.pop() {
                        None => break, // this leaf is the root node
                        Some(false) => {
                            self.done_left_stack.push(true);
                            break;
                        }
                        Some(true) => {
                            self.merkle_stack.pop();
                        }
                    }
                }

                return Some(TrSpendInfoIterItem {
                    script: &leaf.script,
                    leaf: &leaf.leaf,
                    leaf_hash: leaf.leaf_hash,
                    control_block: ControlBlock {
                        leaf_version: leaf.leaf.leaf_version(),
                        output_key_parity: self.spend_info.output_key_parity,
                        internal_key: self.spend_info.internal_key,
                        merkle_branch: TaprootMerkleBranch::from_inner(merkle_stack)
                            .expect("merkle stack guaranteed to be within allowable length"),
                    },
                });
            } else {
                // internal node
                self.done_left_stack.push(false);
            }
        }
        None
    }
}

/// Item yielded from a [`TrSpendInfoIter`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TrSpendInfoIterItem<'tr, Pk: MiniscriptKey, Ext: Extension = CovenantExt<CovExtArgs>> {
    script: &'tr Script,
    leaf: &'tr TapLeaf<Pk, Ext>,
    leaf_hash: TapLeafHash,
    control_block: ControlBlock,
}

impl<'sp, Pk: MiniscriptKey, Ext: Extension> TrSpendInfoIterItem<'sp, Pk, Ext> {
    /// The script of this leaf: a Tapscript, or the commitment of a Simplicity leaf.
    #[inline]
    pub fn script(&self) -> &'sp Script { self.script }

    /// The Tapscript of this leaf, in Miniscript form, or `None` for a Simplicity leaf.
    #[inline]
    pub fn miniscript(&self) -> Option<&'sp Arc<Miniscript<Pk, Tap, Ext>>> {
        self.leaf.miniscript()
    }

    /// The program commitment of this leaf, or `None` for a Tapscript leaf.
    #[cfg(feature = "simplicity")]
    #[inline]
    pub fn simplicity(&self) -> Option<&'sp SimplicityLeaf> { self.leaf.simplicity() }

    /// The depth of the leaf in the tree.
    ///
    /// This value is returned as `u8` since it is guaranteed to be <= 128 by the Taproot
    /// consensus rules.
    #[inline]
    pub fn depth(&self) -> u8 {
        self.control_block.merkle_branch.as_inner().len() as u8 // cast ok, length limited to 128
    }

    /// The Tapleaf version of this leaf: the Elements Tapscript leaf version, or `0xbe` for
    /// a Simplicity leaf.
    #[inline]
    pub fn leaf_version(&self) -> LeafVersion { self.control_block.leaf_version }

    /// The hash of this leaf.
    ///
    /// This hash, prefixed with the leaf's [`Self::leaf_version`], is what is directly
    /// committed in the Taproot tree.
    #[inline]
    pub fn leaf_hash(&self) -> TapLeafHash { self.leaf_hash }

    /// The control block of this leaf.
    ///
    /// Unlike the other data obtainable from [`TrSpendInfoIterItem`], this one is computed
    /// dynamically during iteration and therefore will not outlive the iterator item. See
    /// [`Self::into_control_block`], which consumes the iterator item but will give you an
    /// owned copy of the control block.
    ///
    /// If you need access to multiple control blocks at once, you may need to `clone` the
    /// return value of this method, or call [`Self::into_control_block`], and store the
    /// result in a separate container.
    #[inline]
    pub fn control_block(&self) -> &ControlBlock { &self.control_block }

    /// Extract the control block of this leaf, consuming `self`.
    #[inline]
    pub fn into_control_block(self) -> ControlBlock { self.control_block }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::descriptor::{TapTree, Tr};

    fn tree(s: &str) -> TapTree<bitcoin::PublicKey> {
        let desc =
            format!("eltr(03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,{s})");
        Tr::<bitcoin::PublicKey>::from_str(&desc)
            .unwrap()
            .tap_tree()
            .unwrap()
            .clone()
    }

    fn test_trees() -> Vec<Option<TapTree<bitcoin::PublicKey>>> {
        let mut trees: Vec<_> = [
            // Key spend only
            None,
            // Single leaf
            Some("0"),
            Some("pk(03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115)"),
            // Two leaves, repeated and distinct
            Some("{0,0}"),
            Some("{0,1}"),
            // Shapes of the rust-miniscript fuzz test vectors
            Some("{0,{0,tv:0}}"),
            Some("{uuu:0,{0,uu:0}}"),
            Some("{{0,{uuu:0,0}},{0,uu:0}}"),
            // Unbalanced trees in both directions, and repeated leaves at different depths
            Some("{{{0,1},uu:0},{tv:0,0}}"),
            Some("{1,{1,{1,{1,0}}}}"),
            Some("{{{{0,1},1},1},1}"),
        ]
        .into_iter()
        .map(|desc| desc.map(tree))
        .collect();

        // Combs in both directions, whose two deepest leaves are at depth 128.
        let (mut left, mut right) = (tree("0"), tree("0"));
        for i in 0..TAPROOT_CONTROL_MAX_NODE_COUNT {
            let leaf = tree(["0", "1"][i % 2]);
            left = TapTree::combine(left, leaf.clone()).unwrap();
            right = TapTree::combine(leaf, right).unwrap();
        }
        for comb in [&left, &right] {
            assert_eq!(comb.leaves().map(|leaf| leaf.depth()).max(), Some(128));
        }
        trees.push(Some(left));
        trees.push(Some(right));
        trees
    }

    // Checks the spend info against the independent `TaprootBuilder` implementation
    // in rust-elements, and checks each control block with
    // `ControlBlock::verify_taproot_commitment`.
    #[test]
    fn spend_info_matches_elements_taproot_builder() {
        let secp = Secp256k1::verification_only();
        let pk = bitcoin::PublicKey::from_str(
            "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();

        for tap_tree in test_trees() {
            let tr = Tr::new(pk, tap_tree.clone()).unwrap();
            let spend_info = tr.spend_info();

            let expected = match tap_tree {
                Some(ref tap_tree) => {
                    let mut builder = TaprootBuilder::new();
                    for leaf in tap_tree.leaves() {
                        builder = builder
                            .add_leaf(usize::from(leaf.depth()), leaf.compute_script())
                            .unwrap();
                    }
                    builder.finalize(&secp, pk.to_x_only_pubkey()).unwrap()
                }
                None => elements::taproot::TaprootSpendInfo::new_key_spend(
                    &secp,
                    pk.to_x_only_pubkey(),
                    None,
                ),
            };

            assert_eq!(spend_info.internal_key(), expected.internal_key(), "{}", tr);
            assert_eq!(spend_info.merkle_root(), expected.merkle_root(), "{}", tr);
            assert_eq!(spend_info.output_key(), expected.output_key(), "{}", tr);
            assert_eq!(spend_info.output_key_parity(), expected.output_key_parity(), "{}", tr);

            let leaves: Vec<_> = spend_info.leaves().collect();
            let tree_leaves: Vec<_> = tap_tree.iter().flat_map(TapTree::leaves).collect();
            assert_eq!(leaves.len(), tree_leaves.len(), "{}", tr);
            for (leaf, tree_leaf) in leaves.iter().zip(tree_leaves.iter()) {
                assert_eq!(leaf.depth(), tree_leaf.depth(), "{}", tr);
                assert_eq!(leaf.miniscript(), tree_leaf.miniscript(), "{}", tr);
                assert_eq!(leaf.script(), &tree_leaf.compute_script(), "{}", tr);
                assert_eq!(leaf.leaf_hash(), tree_leaf.compute_tap_leaf_hash(), "{}", tr);
                assert_eq!(leaf.leaf_version(), LeafVersion::default(), "{}", tr);

                let script_ver = (leaf.script().clone(), leaf.leaf_version());
                let branches = expected.as_script_map().get(&script_ver).unwrap();
                assert!(branches.contains(&leaf.control_block().merkle_branch), "{}", tr);
                assert!(leaf.control_block().verify_taproot_commitment(
                    &secp,
                    &spend_info.output_key(),
                    leaf.script(),
                ));
            }

            match (spend_info.to_tap_tree(), tap_tree) {
                (None, None) => {}
                (Some(pset_tree), Some(_)) => {
                    let from_pset = pset_tree
                        .into_inner()
                        .finalize(&secp, pk.to_x_only_pubkey())
                        .unwrap();
                    assert_eq!(from_pset.merkle_root(), spend_info.merkle_root(), "{}", tr);
                }
                _ => panic!("tap tree mismatch for {}", tr),
            }
        }
    }
}
