// SPDX-License-Identifier: CC0-1.0

//! Simplicity program commitments as Taproot leaves
//!
//! A leaf `sim{asm(CMR)}` holds only the commitment Merkle root (CMR) of a Simplicity program:
//! its leaf script is the 32-byte CMR, with leaf version `0xbe`. The CMR exposes neither the
//! program, nor its keys, nor its spending conditions, so callers must keep the program
//! themselves. Nothing here decodes, checks or runs a program, and a Taproot tree with a
//! Simplicity leaf has no witness size bound or semantic policy.

use core::fmt;
use core::str::FromStr;

use bitcoin::hex::{DisplayHex, FromHex};
use elements::taproot::LeafVersion;
use elements::Script;

use crate::expression::{FromTree, Parens, Tree, TreeIterItem};
use crate::prelude::*;
use crate::{Error, ParseError};

/// A Taproot leaf committing to a Simplicity program, `sim{asm(CMR)}`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimplicityLeaf([u8; 32]);

impl SimplicityLeaf {
    /// Creates the leaf of the program with commitment Merkle root `cmr`.
    pub fn from_cmr(cmr: [u8; 32]) -> Self { Self(cmr) }

    /// The commitment Merkle root of the program.
    pub fn cmr(&self) -> [u8; 32] { self.0 }

    /// The leaf script, the 32 bytes of the commitment Merkle root.
    pub(crate) fn script(&self) -> Script { Script::from(self.0.to_vec()) }

    /// The Taproot leaf version of Simplicity programs, `0xbe`.
    pub(crate) fn leaf_version() -> LeafVersion {
        LeafVersion::from_u8(0xbe).expect("0xbe is even and not the annex prefix")
    }
}

impl fmt::Display for SimplicityLeaf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "sim{{asm({})}}", self.0.as_hex())
    }
}

impl FromTree for SimplicityLeaf {
    fn from_tree(root: TreeIterItem) -> Result<Self, Error> {
        match (root.name(), root.parens(), root.first_child()) {
            ("sim", Parens::Curly, Some(asm)) if root.n_children() == 1 => {
                let cmr = asm
                    .verify_toplevel("asm", 1..=1)
                    .map_err(|e| Error::Parse(ParseError::Tree(e)))?;
                cmr.verify_n_children("CMR", 0..=0)
                    .map_err(|e| Error::Parse(ParseError::Tree(e)))?;
                <[u8; 32]>::from_hex(cmr.name())
                    .map(Self)
                    .map_err(|e| Error::Parse(ParseError::box_from_str(e)))
            }
            _ => Err(Error::Unexpected("expected sim{asm(CMR)}".to_owned())),
        }
    }
}

impl FromStr for SimplicityLeaf {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let tree = Tree::from_str(s)?;
        Self::from_tree(tree.root())
    }
}
