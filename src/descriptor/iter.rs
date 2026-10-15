// SPDX-License-Identifier: CC0-1.0

//! Iterators over descriptors

use crate::descriptor::csfs_cov::{LegacyCSFSCov, LegacyCovExt};
use crate::descriptor::{TapTreeIter, Tr};
use crate::extensions::{CovExtArgs, CovenantExt, Extension};
use crate::miniscript::context::{BareCtx, Legacy, Segwitv0, Tap};
use crate::{miniscript, Miniscript, MiniscriptKey};

/// Iterator over all the keys in a descriptor.
pub struct PkIter<'desc, Pk: MiniscriptKey, Ext: Extension = CovenantExt<CovExtArgs>> {
    single_key: Option<Pk>,
    taptree_iter: Option<TapTreeIter<'desc, Pk, Ext>>,
    ms_iter_bare: Option<miniscript::iter::PkIter<'desc, Pk, BareCtx>>,
    ms_iter_legacy: Option<miniscript::iter::PkIter<'desc, Pk, Legacy>>,
    ms_iter_segwit: Option<miniscript::iter::PkIter<'desc, Pk, Segwitv0>>,
    ms_iter_cov: Option<miniscript::iter::PkIter<'desc, Pk, Segwitv0, LegacyCovExt>>,
    ms_iter_taproot: Option<miniscript::iter::PkIter<'desc, Pk, Tap, Ext>>,
}

impl<'desc, Pk: MiniscriptKey, Ext: Extension> PkIter<'desc, Pk, Ext> {
    fn empty() -> Self {
        Self {
            single_key: None,
            taptree_iter: None,
            ms_iter_bare: None,
            ms_iter_legacy: None,
            ms_iter_segwit: None,
            ms_iter_cov: None,
            ms_iter_taproot: None,
        }
    }

    pub(super) fn from_key(pk: Pk) -> Self { Self { single_key: Some(pk), ..Self::empty() } }

    pub(super) fn from_miniscript_bare(ms: &'desc Miniscript<Pk, BareCtx>) -> Self {
        Self { ms_iter_bare: Some(ms.iter_pk()), ..Self::empty() }
    }

    pub(super) fn from_miniscript_legacy(ms: &'desc Miniscript<Pk, Legacy>) -> Self {
        Self { ms_iter_legacy: Some(ms.iter_pk()), ..Self::empty() }
    }

    pub(super) fn from_miniscript_segwit(ms: &'desc Miniscript<Pk, Segwitv0>) -> Self {
        Self { ms_iter_segwit: Some(ms.iter_pk()), ..Self::empty() }
    }

    pub(super) fn from_legacy_cov(cov: &'desc LegacyCSFSCov<Pk>) -> Self {
        Self {
            single_key: Some(cov.pk().clone()),
            ms_iter_cov: Some(cov.as_inner().iter_pk()),
            ..Self::empty()
        }
    }

    pub(super) fn from_tr(tr: &'desc Tr<Pk, Ext>) -> Self {
        Self {
            single_key: Some(tr.internal_key().clone()),
            taptree_iter: Some(tr.leaves()),
            ..Self::empty()
        }
    }
}

impl<'desc, Pk: MiniscriptKey, Ext: Extension> Iterator for PkIter<'desc, Pk, Ext> {
    type Item = Pk;

    #[rustfmt::skip] // the tower of .or_elses looks good as is
    fn next(&mut self) -> Option<Self::Item> {
        // If there is a single key, return it first. (This will be the case
        // for all single-key-only iterators but also for Taproot, where the
        // single key is the root key.)
        if let Some(k) = self.single_key.take() {
            return Some(k.clone());
        }

        // Then attempt to yield something from the Taptree iterator.
        loop {
            if let Some(item) = self.ms_iter_taproot.as_mut().and_then(Iterator::next) {
                return Some(item);
            }
            if let Some(iter) = self.taptree_iter.as_mut().and_then(Iterator::next) {
                // Simplicity leaves hide the keys of their programs.
                self.ms_iter_taproot = iter.miniscript().map(|ms| ms.iter_pk());
            } else {
                break;
            }
        }

        // Finally run through the train of other iterators.
        self.ms_iter_bare.as_mut().and_then(Iterator::next).or_else(
            || self.ms_iter_legacy.as_mut().and_then(Iterator::next).or_else(
                || self.ms_iter_segwit.as_mut().and_then(Iterator::next).or_else(
                    || self.ms_iter_cov.as_mut().and_then(Iterator::next)
                )
            )
        )
    }
}
