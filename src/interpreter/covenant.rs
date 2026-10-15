// SPDX-License-Identifier: CC0-1.0

//! Covenant fragments, and the covenant check of `elcovwsh` spends

use core::fmt;

use bitcoin::hashes::{sha256d, Hash, HashEngine};
use elements::secp256k1_zkp::{Message, Secp256k1};

use super::{Element, Error, KeySigPair, Stack};
use crate::descriptor::csfs_cov::script::ITEM_SIZES;
use crate::descriptor::csfs_cov::LegacyCovExt;
use crate::elementssig_from_rawsig;
use crate::expression::TreeIterItem;
use crate::extensions::{CovExtArgs, CovenantExt, Extension, NoExt, ParseableExt as _, TxEnv};
use crate::miniscript::types::{ExtData, Type};
use crate::prelude::*;

/// The extension fragments of the scripts that the interpreter evaluates.
///
/// The interpreter decodes each script in its own context, with the fragments of that context,
/// and only then converts it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub(super) enum InterpreterExt {
    /// A fragment of a Tapscript
    Tap(CovenantExt<CovExtArgs>),
    /// A fragment of the Miniscript of an `elcovwsh` witness script
    Legacy(LegacyCovExt),
}

impl InterpreterExt {
    /// Whether the fragment reads the transaction. Only Tapscript arithmetic and introspection
    /// fragments do: `csfs` checks a message signature, and the legacy fragments read witness
    /// items.
    pub(super) fn needs_tx_env(&self) -> bool {
        matches!(self, Self::Tap(CovenantExt::Arith(_) | CovenantExt::Introspect(_)))
    }

    /// Executes the fragment on `stack`, consuming its witness, and returns whether it was
    /// satisfied.
    pub(super) fn evaluate(&self, stack: &mut Stack, env: Option<&TxEnv>) -> Result<bool, Error> {
        match self {
            Self::Tap(ext) => ext.evaluate(stack, env),
            Self::Legacy(ext) => ext.evaluate(stack, env),
        }
    }
}

impl fmt::Display for InterpreterExt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tap(ext) => fmt::Display::fmt(ext, f),
            Self::Legacy(ext) => fmt::Display::fmt(ext, f),
        }
    }
}

impl Extension for InterpreterExt {
    fn ty(&self) -> Type {
        match self {
            Self::Tap(ext) => ext.ty(),
            Self::Legacy(ext) => ext.ty(),
        }
    }

    fn ext_data(&self) -> ExtData {
        match self {
            Self::Tap(ext) => ext.ext_data(),
            Self::Legacy(ext) => ext.ext_data(),
        }
    }

    fn segwit_v0_allowed(&self) -> bool {
        match self {
            Self::Tap(ext) => ext.segwit_v0_allowed(),
            Self::Legacy(ext) => ext.segwit_v0_allowed(),
        }
    }

    fn tap_allowed(&self) -> bool {
        match self {
            Self::Tap(ext) => ext.tap_allowed(),
            Self::Legacy(ext) => ext.tap_allowed(),
        }
    }

    // The interpreter only converts decoded scripts.
    fn from_tree(_: &str, _: TreeIterItem) -> Option<Result<Self, crate::Error>> { None }
}

impl From<NoExt> for InterpreterExt {
    fn from(ext: NoExt) -> Self { match ext {} }
}

impl From<CovenantExt<CovExtArgs>> for InterpreterExt {
    fn from(ext: CovenantExt<CovExtArgs>) -> Self { Self::Tap(ext) }
}

impl From<LegacyCovExt> for InterpreterExt {
    fn from(ext: LegacyCovExt) -> Self { Self::Legacy(ext) }
}

/// Checks the covenant of an `elcovwsh` spend on the witness items below the result of its
/// Miniscript, and returns the covenant signature.
///
/// The items must be the covenant signature in DER, then the items of the Segwit v0 signature
/// hash preimage from the sighash type to the version, with the sizes that the witness script
/// checks. The signature by `key` must sign the double SHA256 of the items, as
/// `OP_CHECKSIGFROMSTACK` verifies, and the transaction, as `OP_CHECKSIGVERIFY` verifies with
/// `verify_sig`.
pub(super) fn check(
    key: bitcoin::PublicKey,
    items: &[Element],
    verify_sig: &mut Box<dyn FnMut(&KeySigPair) -> bool + '_>,
) -> Result<KeySigPair, Error> {
    let (der_sig, hash_type) = match items {
        [Element::Push(der_sig), Element::Push(hash_type), ..]
            if items.len() == ITEM_SIZES.len() + 1 =>
        {
            (*der_sig, *hash_type)
        }
        _ => return Err(Error::IncorrectCovenantWitness),
    };
    let mut engine = sha256d::Hash::engine();
    for (item, size) in items.iter().skip(1).rev().zip(ITEM_SIZES) {
        match *item {
            Element::Push(item) if has_size(item, size) => engine.input(item),
            _ => return Err(Error::IncorrectCovenantWitness),
        }
    }

    // The transaction signature has the first byte of the sighash type.
    let mut raw_sig = der_sig.to_vec();
    raw_sig.extend(hash_type.first());
    let sig = elementssig_from_rawsig(&raw_sig)?;

    let msg = Message::from_digest(sha256d::Hash::from_engine(engine).to_byte_array());
    let secp = Secp256k1::verification_only();
    if secp.verify_ecdsa(&msg, &sig.0, &key.inner).is_err() {
        return Err(Error::InvalidCovenantPreimage(key));
    }
    let key_sig = KeySigPair::Ecdsa(key, sig);
    if verify_sig(&key_sig) {
        Ok(key_sig)
    } else {
        Err(Error::InvalidEcdsaSignature(key))
    }
}

// Whether `item` has `size`. The spent amount has no fixed size: it is explicit, a 1 then 8
// bytes, or a 33-byte commitment.
fn has_size(item: &[u8], size: Option<u8>) -> bool {
    let size = size.unwrap_or(if item.first() == Some(&1) { 9 } else { 33 });
    item.len() == usize::from(size)
}
