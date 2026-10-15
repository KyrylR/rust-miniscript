// Written in 2018 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Pegin Descriptors
//!
//! A pegin pays bitcoin to a federation script on the Bitcoin chain. Elements tweaks the
//! federation script with the claim script, which is the scriptPubKey of the Elements descriptor
//! that claims the coins. Its `calculate_contract` replaces each 33-byte push `P` of the script
//! by `P + HMAC-SHA256(P, claim script)G`, keying the HMAC with the pushed key. Elements only
//! accepts claim scripts of at most 100 bytes.
//!
//! The federation side uses the upstream Bitcoin Miniscript library, [`bitcoin_miniscript`].
//! The descriptors are written `pegin(FEDERATION,CLAIM)` and `legacy_pegin(FEDERATION,CLAIM)`.

mod dynafed_pegin;
mod legacy_pegin;

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use bitcoin::hashes::{hash160, sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::{secp256k1, PublicKey};
use bitcoin_miniscript::descriptor::DescriptorType;
use bitcoin_miniscript::{Miniscript, Segwitv0, TranslateErr};
use elements::secp256k1_zkp::{Scalar, Secp256k1, Verification};

pub use self::dynafed_pegin::Pegin;
pub use self::legacy_pegin::{LegacyPegin, LegacyPeginKey, LegacyPeginKeyError};
use crate::descriptor::checksum::verify_checksum;
use crate::expression::{self, Parens, TreeIterItem};
use crate::prelude::*;
use crate::{MiniscriptKey, ParseError, ParseTreeError, ToPublicKey};

/// Elements `IsValidPeginWitness` rejects a pegin whose claim script is longer than this.
const MAX_CLAIM_SCRIPT_SIZE: usize = 100;

/// An error parsing or using a pegin descriptor
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The pegin expression or its Elements claim descriptor is invalid.
    Elements(crate::Error),
    /// The Bitcoin federation descriptor or Miniscript is invalid, a federation key cannot be
    /// tweaked, or the Bitcoin script cannot be satisfied.
    Bitcoin(bitcoin_miniscript::Error),
    /// The federation descriptor is neither `wsh()` nor `sh(wsh())`, the forms that Elements
    /// accepts for pegins.
    UnsupportedFederation(DescriptorType),
    /// The federation Miniscript of a legacy pegin is not
    /// `or_d(multi(...),and_v(v:older(...),multi(...)))`.
    UnexpectedLegacyMiniscript,
    /// The federation and emergency thresholds of a legacy pegin have the same `k`. The depth
    /// check of the watchman script could never select the emergency branch, and Elements
    /// `MatchLiquidWatchman` rejects the script, so Elements would tweak the emergency keys too.
    EqualLegacyThresholds(usize),
    /// The claim script has the given length, which is more than the 100 bytes Elements
    /// accepts in a pegin witness, so a pegin to this descriptor could not be claimed.
    ClaimScriptTooLarge(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Elements(e) => fmt::Display::fmt(e, f),
            Self::Bitcoin(e) => fmt::Display::fmt(e, f),
            Self::UnsupportedFederation(ty) => {
                write!(f, "federation descriptor of type {:?} is not wsh() or sh(wsh())", ty)
            }
            Self::UnexpectedLegacyMiniscript => f.write_str(
                "legacy pegin Miniscript is not or_d(multi(...),and_v(v:older(...),multi(...)))",
            ),
            Self::EqualLegacyThresholds(k) => write!(
                f,
                "legacy pegin federation and emergency thresholds both need {} signatures, which \
                 Elements does not accept as a watchman script",
                k
            ),
            Self::ClaimScriptTooLarge(len) => write!(
                f,
                "claim script of {} bytes is longer than the {} bytes Elements accepts in a pegin",
                len, MAX_CLAIM_SCRIPT_SIZE
            ),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Elements(e) => Some(e),
            Self::Bitcoin(e) => Some(e),
            Self::UnsupportedFederation(_)
            | Self::UnexpectedLegacyMiniscript
            | Self::EqualLegacyThresholds(_)
            | Self::ClaimScriptTooLarge(_) => None,
        }
    }
}

impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self { Self::Elements(e) }
}

impl From<bitcoin_miniscript::Error> for Error {
    fn from(e: bitcoin_miniscript::Error) -> Self { Self::Bitcoin(e) }
}

/// Splits `name(FIRST,SECOND)`, after verifying any checksum, into the text of its two
/// arguments, so that each can be parsed by the library it belongs to.
///
/// The first argument is Bitcoin text and the second an Elements descriptor. Curly braces are
/// only accepted around the script trees of `tr` and `eltr` respectively.
fn split_args<'s>(s: &'s str, name: &'static str) -> Result<(&'s str, &'s str), crate::Error> {
    let tree_error = |e: ParseTreeError| crate::Error::Parse(ParseError::Tree(e));
    let s = verify_checksum(s).map_err(|e| tree_error(e.into()))?;
    let tree = expression::Tree::from_str(s)?;
    let top = tree.root();
    top.verify_toplevel(name, 2..=2).map_err(tree_error)?;
    let (first, second) = top.verify_binary(name).map_err(tree_error)?;
    verify_bitcoin_curly_braces(first).map_err(tree_error)?;
    Ok((&s[first.name_pos()..second.name_pos() - 1], &s[second.name_pos()..s.len() - 1]))
}

/// Checks that curly braces in Bitcoin text only surround script tree branches, which have no
/// name and are the second argument of `tr` or nested in it.
///
/// The Bitcoin library reads the key of `wpkh` and `pkh` without checking its brackets, so it
/// would accept a text such as `wpkh{K}`.
fn verify_bitcoin_curly_braces(node: TreeIterItem) -> Result<(), ParseTreeError> {
    for node in node.pre_order_iter() {
        if node.parens() != Parens::Curly {
            continue;
        }
        let mut branch = node;
        while let Some(parent) = branch.parent().filter(|p| p.parens() == Parens::Curly) {
            branch = parent;
        }
        let in_script_tree = node.name().is_empty()
            && !branch.is_first_child()
            && branch.parent().is_some_and(|p| p.name() == "tr");
        if !in_script_tree {
            return Err(ParseTreeError::IllegalCurlyBrace { pos: node.children_pos() });
        }
    }
    Ok(())
}

/// Tweaks a federation key with the claim script, as Elements `calculate_contract` does.
///
/// Elements only tweaks 33-byte keys, so an uncompressed key is returned unchanged. The tweak
/// fails if the HMAC is not below the curve order or gives the point at infinity.
fn tweak_key<C: Verification>(
    secp: &Secp256k1<C>,
    key: &PublicKey,
    claim_script: &[u8],
) -> Result<PublicKey, Error> {
    if !key.compressed {
        return Ok(*key);
    }
    let secp_error = |e| Error::Bitcoin(bitcoin_miniscript::Error::Secp(e));
    let mut engine = HmacEngine::<sha256::Hash>::new(&key.inner.serialize());
    engine.input(claim_script);
    let tweak = Scalar::from_be_bytes(Hmac::from_engine(engine).to_byte_array())
        .map_err(|_| secp_error(secp256k1::Error::InvalidTweak))?;
    Ok(PublicKey::new(key.inner.add_exp_tweak(secp, &tweak).map_err(secp_error)?))
}

/// The scriptPubKey of a claim descriptor, if Elements accepts it as a claim script.
fn claim_script<Pk: MiniscriptKey + ToPublicKey>(
    desc: &crate::Descriptor<Pk>,
) -> Result<elements::Script, Error> {
    let script = desc.script_pubkey();
    if script.len() > MAX_CLAIM_SCRIPT_SIZE {
        return Err(Error::ClaimScriptTooLarge(script.len()));
    }
    Ok(script)
}

/// Whether a federation descriptor is `sh(wsh())` rather than `wsh()`, the two forms that
/// Elements accepts for pegins.
fn federation_is_sh(fed: &bitcoin_miniscript::Descriptor<PublicKey>) -> Result<bool, Error> {
    match fed.desc_type() {
        DescriptorType::Wsh => Ok(false),
        DescriptorType::ShWsh => Ok(true),
        other => Err(Error::UnsupportedFederation(other)),
    }
}

/// Tweaks a federation descriptor with the claim script, as Elements `calculate_contract`
/// tweaks the 33-byte pushes of its witness script.
///
/// Decoding the witness script reads each `pk_h` as the key hash it pushes, so only the keys
/// of `pk_k` and `multi` are tweaked. The key hashes are then mapped back to their untweaked
/// keys, so that a satisfier can look up `pk_h` signatures by key.
fn tweak_federation<C: Verification>(
    fed: &bitcoin_miniscript::Descriptor<PublicKey>,
    claim_script: &[u8],
    secp: &Secp256k1<C>,
) -> Result<bitcoin_miniscript::Descriptor<PublicKey>, Error> {
    struct Tweak<'a, C: Verification>(&'a Secp256k1<C>, &'a [u8]);

    impl<C: Verification> bitcoin_miniscript::Translator<PublicKey> for Tweak<'_, C> {
        type TargetPk = PublicKey;
        type Error = Error;

        fn pk(&mut self, pk: &PublicKey) -> Result<PublicKey, Error> {
            tweak_key(self.0, pk, self.1)
        }

        bitcoin_miniscript::translate_hash_clone!(PublicKey, PublicKey, Error);
    }

    let is_sh = federation_is_sh(fed)?;
    let pushed = Miniscript::<PublicKey, Segwitv0>::decode_consensus(&fed.explicit_script()?)?;
    let tweaked = pushed
        .translate_pk(&mut Tweak(secp, claim_script))
        .map_err(|e| match e {
            TranslateErr::TranslatorErr(e) => e,
            TranslateErr::OuterError(e) => Error::Bitcoin(e),
        })?;
    let keys: BTreeMap<_, _> = fed
        .iter_pk()
        .map(|key| (hash160::Hash::hash(&key.to_bytes()), key))
        .collect();
    let tweaked = tweaked.substitute_raw_pkh(&keys);
    if is_sh {
        Ok(bitcoin_miniscript::Descriptor::new_sh_wsh(tweaked)?)
    } else {
        Ok(bitcoin_miniscript::Descriptor::new_wsh(tweaked)?)
    }
}
