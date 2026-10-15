// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use elements::taproot::{LeafVersion, TapLeafHash, TAPROOT_CONTROL_MAX_NODE_COUNT};

use crate::extensions::{CovExtArgs, CovenantExt, ExtTranslator, Extension, ParseableExt};
use crate::miniscript::context::Tap;
use crate::policy::{Liftable, Semantic};
use crate::prelude::Vec;
use crate::sync::Arc;
use crate::{Miniscript, MiniscriptKey, Threshold, ToPublicKey, TranslateErr, Translator};

type LeafDepth<Pk, Ext> = (u8, Arc<Miniscript<Pk, Tap, Ext>>);

/// Tried to construct Taproot tree which was too deep.
#[derive(PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct TapTreeDepthError;

impl fmt::Display for TapTreeDepthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("maximum Taproot tree depth (128) exceeded")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TapTreeDepthError {}

/// A Taproot Tree representation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TapTree<Pk: MiniscriptKey, Ext: Extension = CovenantExt<CovExtArgs>> {
    depths_leaves: Vec<LeafDepth<Pk, Ext>>,
}

impl<Pk: MiniscriptKey, Ext: Extension> TapTree<Pk, Ext> {
    /// Creates a `TapTree` leaf from a Miniscript.
    pub fn leaf<A: Into<Arc<Miniscript<Pk, Tap, Ext>>>>(ms: A) -> Self {
        Self { depths_leaves: vec![(0, ms.into())] }
    }

    /// Creates a `TapTree` by combining `left` and `right` tree nodes.
    pub fn combine(left: Self, right: Self) -> Result<Self, TapTreeDepthError> {
        let mut depths_leaves =
            Vec::with_capacity(left.depths_leaves.len() + right.depths_leaves.len());
        for (depth, leaf) in left.depths_leaves.iter().chain(right.depths_leaves.iter()) {
            if usize::from(*depth) > TAPROOT_CONTROL_MAX_NODE_COUNT - 1 {
                return Err(TapTreeDepthError);
            }
            depths_leaves.push((*depth + 1, Arc::clone(leaf)));
        }
        Ok(Self { depths_leaves })
    }

    /// Iterates over all the leaves of the tree in depth-first preorder.
    ///
    /// The yielded elements include the Miniscript for each leave as well as its depth
    /// in the tree, which is the data required by PSBT (BIP 371).
    pub fn leaves(&self) -> TapTreeIter<'_, Pk, Ext> { TapTreeIter::from_tree(self) }

    /// Converts keys from one type of public key to another.
    pub fn translate_pk<T>(
        &self,
        translate: &mut T,
    ) -> Result<TapTree<T::TargetPk, Ext>, TranslateErr<T::Error>>
    where
        T: Translator<Pk>,
    {
        self.translate_leaves(|leaf| leaf.translate_pk(translate))
    }

    /// Converts the extensions from one type to another.
    pub fn translate_ext<T>(
        &self,
        translate: &mut T,
    ) -> Result<TapTree<Pk, T::TargetExt>, TranslateErr<T::Error>>
    where
        T: ExtTranslator<Ext>,
    {
        self.translate_leaves(|leaf| leaf.translate_ext(translate))
    }

    fn translate_leaves<QPk: MiniscriptKey, QExt: Extension, E>(
        &self,
        mut translate: impl FnMut(&Miniscript<Pk, Tap, Ext>) -> Result<Miniscript<QPk, Tap, QExt>, E>,
    ) -> Result<TapTree<QPk, QExt>, E> {
        let mut ret = TapTree { depths_leaves: Vec::with_capacity(self.depths_leaves.len()) };
        for (depth, leaf) in &self.depths_leaves {
            let leaf = Arc::new(translate(leaf)?);
            ret.depths_leaves.push((*depth, leaf));
        }

        Ok(ret)
    }
}

impl<Pk: MiniscriptKey, Ext: Extension> Liftable<Pk> for TapTree<Pk, Ext> {
    fn lift(&self) -> Result<Semantic<Pk>, crate::Error> {
        let thresh_vec = self
            .leaves()
            .map(|item| item.miniscript().lift().map(Arc::new))
            .collect::<Result<Vec<_>, _>>()?;
        let thresh = Threshold::new(1, thresh_vec).expect("no size limit on Semantic threshold");
        Ok(Semantic::Thresh(thresh).normalized())
    }
}

fn fmt_helper<Pk: MiniscriptKey, Ext: Extension>(
    view: &TapTree<Pk, Ext>,
    f: &mut fmt::Formatter,
    mut fmt_ms: impl FnMut(&mut fmt::Formatter, &Miniscript<Pk, Tap, Ext>) -> fmt::Result,
) -> fmt::Result {
    let mut child_counts = Vec::<u8>::with_capacity(TAPROOT_CONTROL_MAX_NODE_COUNT);

    for item in view.leaves() {
        let depth = usize::from(item.depth());

        if !child_counts.is_empty() {
            f.write_str(",")?;
        }

        while child_counts.len() < depth {
            f.write_str("{")?;
            child_counts.push(0);
        }

        fmt_ms(f, item.miniscript())?;

        if let Some(child_count) = child_counts.last_mut() {
            *child_count += 1;
        }
        while let Some(2) = child_counts.last() {
            f.write_str("}")?;
            child_counts.pop();
            if let Some(child_count) = child_counts.last_mut() {
                *child_count += 1;
            }
        }
    }

    Ok(())
}

impl<Pk: MiniscriptKey, Ext: Extension> fmt::Display for TapTree<Pk, Ext> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt_helper(self, f, |f, ms| write!(f, "{}", ms))
    }
}

impl<Pk: MiniscriptKey, Ext: Extension> fmt::Debug for TapTree<Pk, Ext> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt_helper(self, f, |f, ms| write!(f, "{:?}", ms))
    }
}

/// Iterator over the leaves of a Taptree.
///
/// Yields a pair of (depth, miniscript) in a depth first walk
/// For example, this tree:
///                                     - N0 -
///                                    /     \\
///                                   N1      N2
///                                  /  \    /  \\
///                                 A    B  C   N3
///                                            /  \\
///                                           D    E
/// would yield (2, A), (2, B), (2,C), (3, D), (3, E).
///
#[derive(Debug, Clone)]
pub struct TapTreeIter<'tr, Pk: MiniscriptKey, Ext: Extension = CovenantExt<CovExtArgs>> {
    inner: core::slice::Iter<'tr, LeafDepth<Pk, Ext>>,
}

impl<'tr, Pk: MiniscriptKey, Ext: Extension> TapTreeIter<'tr, Pk, Ext> {
    /// An empty iterator.
    pub fn empty() -> Self { Self { inner: [].iter() } }

    /// An iterator over a given tree.
    fn from_tree(tree: &'tr TapTree<Pk, Ext>) -> Self { Self { inner: tree.depths_leaves.iter() } }
}

impl<'tr, Pk: MiniscriptKey, Ext: Extension> Iterator for TapTreeIter<'tr, Pk, Ext> {
    type Item = TapTreeIterItem<'tr, Pk, Ext>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|&(depth, ref node)| TapTreeIterItem { depth, node })
    }
}

impl<'tr, Pk: MiniscriptKey, Ext: Extension> DoubleEndedIterator for TapTreeIter<'tr, Pk, Ext> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner
            .next_back()
            .map(|&(depth, ref node)| TapTreeIterItem { depth, node })
    }
}

impl<'tr, Pk: MiniscriptKey, Ext: Extension> ExactSizeIterator for TapTreeIter<'tr, Pk, Ext> {
    fn len(&self) -> usize { self.inner.len() }
}

impl<'tr, Pk: MiniscriptKey, Ext: Extension> core::iter::FusedIterator
    for TapTreeIter<'tr, Pk, Ext>
{
}

/// Iterator over all of the leaves of a Taproot tree.
///
/// If there is no tree (i.e. this is a keyspend-only Taproot descriptor)
/// then the iterator will yield nothing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TapTreeIterItem<'tr, Pk: MiniscriptKey, Ext: Extension = CovenantExt<CovExtArgs>> {
    node: &'tr Arc<Miniscript<Pk, Tap, Ext>>,
    depth: u8,
}

impl<'tr, Pk: MiniscriptKey, Ext: Extension> TapTreeIterItem<'tr, Pk, Ext> {
    /// The Tapscript in the leaf.
    ///
    /// To obtain an [`elements::Script`] from this node, call [`Miniscript::encode`]
    /// on the returned value.
    #[inline]
    pub fn miniscript(&self) -> &'tr Arc<Miniscript<Pk, Tap, Ext>> { self.node }

    /// The depth of this leaf.
    ///
    /// This is useful for reconstructing the shape of the tree.
    #[inline]
    pub fn depth(&self) -> u8 { self.depth }

    /// The Tapleaf version of this leaf.
    ///
    /// This function returns a constant value, the Elements Tapscript leaf
    /// version, which is the only version Miniscript leaves use.
    #[inline]
    pub fn leaf_version(&self) -> LeafVersion { LeafVersion::default() }
}

impl<Pk: ToPublicKey, Ext: ParseableExt> TapTreeIterItem<'_, Pk, Ext> {
    /// Computes the Elements Script of the leaf.
    ///
    /// This function is potentially expensive. If you are calling this method on
    /// all (or many) of the leaves of the tree, you may instead want to call
    /// [`super::Tr::spend_info`] and use the [`super::TrSpendInfo::leaves`] iterator instead.
    #[inline]
    pub fn compute_script(&self) -> elements::Script { self.node.encode() }

    /// Computes the [`TapLeafHash`] of the leaf.
    ///
    /// This function is potentially expensive, since it serializes the full Elements
    /// Script of the leaf and hashes this data. If you are calling this method on
    /// all (or many) of the leaves of the tree, you may instead want to call
    /// [`super::Tr::spend_info`] and use the [`super::TrSpendInfo::leaves`] iterator instead.
    #[inline]
    pub fn compute_tap_leaf_hash(&self) -> TapLeafHash {
        TapLeafHash::from_script(&self.compute_script(), self.leaf_version())
    }
}

pub(super) struct TapTreeBuilder<Pk: MiniscriptKey, Ext: Extension> {
    depths_leaves: Vec<LeafDepth<Pk, Ext>>,
    complete_heights: u128, // ArrayVec<bool, 129> represented as a bitmap...and a bool.
    complete_128: bool,     // BIP341 says depths are in [0,128] *inclusive* so 129 possibilities.
    current_height: u8,
}

impl<Pk: MiniscriptKey, Ext: Extension> TapTreeBuilder<Pk, Ext> {
    pub(super) fn new() -> Self {
        Self {
            depths_leaves: vec![],
            complete_heights: 0,
            complete_128: false,
            current_height: 0,
        }
    }

    #[inline]
    pub(super) fn push_inner_node(&mut self) -> Result<(), TapTreeDepthError> {
        self.current_height += 1;
        if usize::from(self.current_height) > TAPROOT_CONTROL_MAX_NODE_COUNT {
            return Err(TapTreeDepthError);
        }
        Ok(())
    }

    #[inline]
    pub(super) fn push_leaf<A: Into<Arc<Miniscript<Pk, Tap, Ext>>>>(&mut self, ms: A) {
        self.depths_leaves.push((self.current_height, ms.into()));

        // Special-case 128 which doesn't fit into the `complete_heights` bitmap
        if usize::from(self.current_height) == TAPROOT_CONTROL_MAX_NODE_COUNT {
            if self.complete_128 {
                self.complete_128 = false;
                self.current_height -= 1;
            } else {
                self.complete_128 = true;
                return;
            }
        }
        // Then deal with all other nonzero heights
        while self.current_height > 0 {
            if self.complete_heights & (1 << self.current_height) == 0 {
                self.complete_heights |= 1 << self.current_height;
                break;
            }
            self.complete_heights &= !(1 << self.current_height);
            self.current_height -= 1;
        }
    }

    #[inline]
    pub(super) fn finalize(self) -> TapTree<Pk, Ext> {
        assert!(!self.depths_leaves.is_empty(), "TapTreeBuilder must not finalize an empty tree");
        TapTree { depths_leaves: self.depths_leaves }
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::NoExt;

    fn leaf(ms: &str) -> TapTree<String, NoExt> {
        TapTree::leaf(Arc::new(Miniscript::<String, Tap>::from_str(ms).unwrap()))
    }

    #[test]
    fn display_single_leaf_taptree() {
        let tree = leaf("pk(A)");

        assert_eq!(format!("{}", tree), "pk(A)");
    }

    #[test]
    fn debug_binary_taptree() {
        let tree = TapTree::combine(leaf("pk(A)"), leaf("pk(B)")).unwrap();

        assert_eq!(format!("{:?}", tree), "{[B/onduesm]pk(\"A\"),[B/onduesm]pk(\"B\")}");
    }
}
