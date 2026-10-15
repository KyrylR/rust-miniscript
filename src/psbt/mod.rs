// SPDX-License-Identifier: CC0-1.0

//! # Partially-Signed Elements Transactions
//!
//! This module implements the Finalizer and Extractor roles defined in
//! BIP 174, PSBT, described at
//! `https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki`,
//! for the Elements PSET format.
//!

use core::convert::TryFrom;
use core::fmt;
use core::ops::Deref;
#[cfg(feature = "std")]
use std::error;

use bitcoin::hashes::{hash160, Hash};
use bitcoin::{absolute, bip32, relative};
use elements::pset::{self as psbt, PartiallySignedTransaction as Psbt};
use elements::secp256k1_zkp::{self as secp256k1, Secp256k1, VerifyOnly};
use elements::sighash::SighashCache;
use elements::taproot::{self, ControlBlock, LeafVersion, TapLeafHash};
use elements::{hashes as el_hashes, EcdsaSighashType, Script};

use crate::miniscript::context::SigType;
use crate::prelude::*;
use crate::{
    descriptor, elementssig_from_rawsig, interpreter, DefiniteDescriptorKey, Descriptor,
    DescriptorPublicKey, ElementsSig, MiniscriptKey, Preimage32, Satisfier, ToPublicKey,
    Translator,
};

mod finalizer;

#[allow(deprecated)]
pub use self::finalizer::{finalize, finalize_mall, interpreter_check};

/// Error type for entire Psbt
#[derive(Debug)]
pub enum Error {
    /// Error from the underlying PSET, e.g. while extracting its transaction
    PsbtError(elements::pset::Error),
    /// Input Error type
    InputError(InputError, usize),
    /// Wrong Input Count
    WrongInputCount {
        /// Input count in tx
        in_tx: usize,
        /// Input count in psbt
        in_map: usize,
    },
    /// Psbt Input index out of bounds
    InputIdxOutofBounds {
        /// Inputs in pbst
        psbt_inp: usize,
        /// requested index
        index: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::PsbtError(ref e) => write!(f, "PSET error: {}", e),
            Self::InputError(ref inp_err, index) => write!(f, "{} at index {}", inp_err, index),
            Self::WrongInputCount { in_tx, in_map } => {
                write!(f, "PSBT had {} inputs in transaction but {} inputs in map", in_tx, in_map)
            }
            Self::InputIdxOutofBounds { psbt_inp, index } => write!(
                f,
                "psbt input index {} out of bounds: psbt.inputs.len() {}",
                index, psbt_inp
            ),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::Error::*;

        match self {
            PsbtError(e) => Some(e),
            InputError(e, _) => Some(e),
            WrongInputCount { .. } | InputIdxOutofBounds { .. } => None,
        }
    }
}

#[doc(hidden)]
impl From<elements::pset::Error> for Error {
    fn from(e: elements::pset::Error) -> Self { Self::PsbtError(e) }
}

/// Error type for Pbst Input
#[derive(Debug)]
pub enum InputError {
    /// Get the secp Errors directly
    SecpErr(bitcoin::secp256k1::Error),
    /// Key errors
    KeyErr(bitcoin::key::FromSliceError),
    /// Could not satisfy taproot descriptor
    /// This error is returned when both script path and key paths could not be
    /// satisfied. We cannot return a detailed error because we try all miniscripts
    /// in script spend path, we cannot know which miniscript failed.
    CouldNotSatisfyTr,
    /// Error doing an interpreter-check on a finalized psbt
    Interpreter(interpreter::Error),
    /// Redeem script does not match the p2sh hash
    InvalidRedeemScript {
        /// Redeem script
        redeem: Script,
        /// Expected p2sh Script
        p2sh_expected: Script,
    },
    /// Witness script does not match the p2wsh hash
    InvalidWitnessScript {
        /// Witness Script
        witness_script: Script,
        /// Expected p2wsh script
        p2wsh_expected: Script,
    },
    /// Invalid sig
    InvalidSignature {
        /// The bitcoin public key
        pubkey: bitcoin::PublicKey,
        /// The (incorrect) signature
        sig: Vec<u8>,
    },
    /// Pass through the underlying errors in miniscript
    MiniscriptError(super::Error),
    /// Missing redeem script for p2sh
    MissingRedeemScript,
    /// Missing witness
    MissingWitness,
    /// used for public key corresponding to pkh/wpkh
    MissingPubkey,
    /// Missing witness script for segwit descriptors
    MissingWitnessScript,
    /// Missing the utxo spent by the input
    MissingUtxo,
    /// Non empty Witness script for p2sh
    NonEmptyWitnessScript,
    /// Non empty Redeem script
    NonEmptyRedeemScript,
    /// Non Standard sighash type
    NonStandardSighashType(psbt::PsbtSighashType),
    /// Sighash did not match
    WrongSighashFlag {
        /// required sighash type
        required: EcdsaSighashType,
        /// the sighash type we got
        got: EcdsaSighashType,
        /// the corresponding publickey
        pubkey: bitcoin::PublicKey,
    },
}

#[cfg(feature = "std")]
impl error::Error for InputError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::InputError::*;

        match self {
            CouldNotSatisfyTr
            | InvalidRedeemScript { .. }
            | InvalidWitnessScript { .. }
            | InvalidSignature { .. }
            | MissingRedeemScript
            | MissingWitness
            | MissingPubkey
            | MissingWitnessScript
            | MissingUtxo
            | NonEmptyWitnessScript
            | NonEmptyRedeemScript
            | NonStandardSighashType(_)
            | WrongSighashFlag { .. } => None,
            SecpErr(e) => Some(e),
            KeyErr(e) => Some(e),
            Interpreter(e) => Some(e),
            MiniscriptError(e) => Some(e),
        }
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::InvalidSignature { ref pubkey, ref sig } => {
                write!(f, "PSBT: bad signature {} for key {:?}", pubkey, sig)
            }
            Self::KeyErr(ref e) => write!(f, "Key Err: {}", e),
            Self::Interpreter(ref e) => write!(f, "Interpreter: {}", e),
            Self::SecpErr(ref e) => write!(f, "Secp Err: {}", e),
            Self::InvalidRedeemScript { ref redeem, ref p2sh_expected } => write!(
                f,
                "Redeem script {} does not match the p2sh script {}",
                redeem, p2sh_expected
            ),
            Self::InvalidWitnessScript { ref witness_script, ref p2wsh_expected } => write!(
                f,
                "Witness script {} does not match the p2wsh script {}",
                witness_script, p2wsh_expected
            ),
            Self::MiniscriptError(ref e) => write!(f, "Miniscript Error: {}", e),
            Self::MissingWitness => write!(f, "PSBT is missing witness"),
            Self::MissingRedeemScript => write!(f, "PSBT is Redeem script"),
            Self::MissingUtxo => write!(f, "PSBT is missing the spent UTXO"),
            Self::MissingWitnessScript => write!(f, "PSBT is missing witness script"),
            Self::MissingPubkey => write!(f, "Missing pubkey for a pkh/wpkh"),
            Self::NonEmptyRedeemScript => {
                write!(f, "PSBT has non-empty redeem script at for legacy transactions")
            }
            Self::NonEmptyWitnessScript => {
                write!(f, "PSBT has non-empty witness script at for legacy input")
            }
            Self::WrongSighashFlag { required, got, pubkey } => write!(
                f,
                "PSBT: signature with key {:?} had \
                 sighashflag {:?} rather than required {:?}",
                pubkey, got, required
            ),
            Self::CouldNotSatisfyTr => write!(f, "Could not satisfy Tr descriptor"),
            Self::NonStandardSighashType(ref e) => {
                write!(f, "Non-standard sighash type {}", e)
            }
        }
    }
}

#[doc(hidden)]
impl From<super::Error> for InputError {
    fn from(e: super::Error) -> Self { Self::MiniscriptError(e) }
}

#[doc(hidden)]
impl From<bitcoin::secp256k1::Error> for InputError {
    fn from(e: bitcoin::secp256k1::Error) -> Self { Self::SecpErr(e) }
}

#[doc(hidden)]
impl From<bitcoin::key::FromSliceError> for InputError {
    fn from(e: bitcoin::key::FromSliceError) -> Self { Self::KeyErr(e) }
}

/// Psbt satisfier for inputs at a particular index.
///
/// Holds a `&psbt` because multiple inputs may share
/// the same psbt structure
/// All operations on this structure will panic if index
/// is more than number of inputs in pbst
pub struct PsbtInputSatisfier<'psbt> {
    /// pbst
    psbt: &'psbt Psbt,
    /// input index
    index: usize,
}

impl<'psbt> PsbtInputSatisfier<'psbt> {
    /// create a new PsbtInputsatisfier from
    /// psbt and index
    pub fn new(psbt: &'psbt Psbt, index: usize) -> Self { Self { psbt, index } }

    /// Accessor for the PSBT this satisfier is associated with.
    pub fn psbt(&self) -> &'psbt Psbt { self.psbt }

    /// Accessor for the input this satisfier is associated with.
    pub fn psbt_input(&self) -> &psbt::Input { &self.psbt.inputs()[self.index] }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for PsbtInputSatisfier<'_> {
    fn lookup_tap_key_spend_sig(&self, pk: &Pk) -> Option<elements::SchnorrSig> {
        if let Some(key) = self.psbt_input().tap_internal_key {
            if pk.to_x_only_pubkey() == key {
                return self.psbt_input().tap_key_sig;
            }
        }
        None
    }

    fn lookup_tap_leaf_script_sig(
        &self,
        pk: &Pk,
        lh: &TapLeafHash,
    ) -> Option<elements::SchnorrSig> {
        self.psbt_input()
            .tap_script_sigs
            .get(&(pk.to_x_only_pubkey(), *lh))
            .copied()
    }

    fn lookup_raw_pkh_pk(&self, pkh: &hash160::Hash) -> Option<bitcoin::PublicKey> {
        self.psbt_input()
            .bip32_derivation
            .iter()
            .find_map(|(&pk, _)| (pk.to_pubkeyhash(SigType::Ecdsa) == *pkh).then_some(pk))
    }

    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (Script, LeafVersion)>> {
        Some(&self.psbt_input().tap_scripts)
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        pkh: &(hash160::Hash, TapLeafHash),
    ) -> Option<(bitcoin::key::XOnlyPublicKey, elements::SchnorrSig)> {
        self.psbt_input()
            .tap_script_sigs
            .iter()
            .find_map(|(&(pk, lh), &sig)| {
                (pk.to_pubkeyhash(SigType::Schnorr) == pkh.0 && lh == pkh.1).then_some((pk, sig))
            })
    }

    fn lookup_ecdsa_sig(&self, pk: &Pk) -> Option<ElementsSig> {
        // The finalizer rejects a partial signature that does not parse before satisfying its
        // input. Other users of this satisfier see such a signature as missing.
        self.psbt_input()
            .partial_sigs
            .get(&pk.to_public_key())
            .and_then(|sig| elementssig_from_rawsig(sig).ok())
    }

    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        pkh: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, ElementsSig)> {
        self.psbt_input()
            .partial_sigs
            .iter()
            .find(|&(pk, _)| pk.to_pubkeyhash(SigType::Ecdsa) == *pkh)
            .and_then(|(&pk, sig)| elementssig_from_rawsig(sig).ok().map(|sig| (pk, sig)))
    }

    fn check_after(&self, n: absolute::LockTime) -> bool {
        let seq = self
            .psbt_input()
            .sequence
            .unwrap_or(elements::Sequence::MAX);
        if !seq.enables_absolute_lock_time() {
            return false;
        }

        // The PSET locktime is derived from the inputs' required locktimes
        // and the global fallback locktime.
        let lock_time = match self.psbt.locktime() {
            Ok(lock_time) => lock_time,
            Err(_) => return false,
        };

        <dyn Satisfier<Pk>>::check_after(&lock_time, n)
    }

    fn check_older(&self, n: relative::LockTime) -> bool {
        let seq = self
            .psbt_input()
            .sequence
            .unwrap_or(elements::Sequence::MAX);

        if self.psbt.global.tx_data.version < 2 || !seq.is_relative_lock_time() {
            return false;
        }

        <dyn Satisfier<Pk>>::check_older(&seq, n)
    }

    // PSET preimage maps are keyed by Elements' `bitcoin_hashes` types.
    fn lookup_hash160(&self, h: &Pk::Hash160) -> Option<Preimage32> {
        self.psbt_input()
            .hash160_preimages
            .get(&el_hashes::hash160::Hash::from_byte_array(Pk::to_hash160(h).to_byte_array()))
            .and_then(|x: &Vec<u8>| <[u8; 32]>::try_from(&x[..]).ok())
    }

    fn lookup_sha256(&self, h: &Pk::Sha256) -> Option<Preimage32> {
        self.psbt_input()
            .sha256_preimages
            .get(&el_hashes::sha256::Hash::from_byte_array(Pk::to_sha256(h).to_byte_array()))
            .and_then(|x: &Vec<u8>| <[u8; 32]>::try_from(&x[..]).ok())
    }

    fn lookup_hash256(&self, h: &Pk::Hash256) -> Option<Preimage32> {
        self.psbt_input()
            .hash256_preimages
            .get(&el_hashes::sha256d::Hash::from_byte_array(Pk::to_hash256(h).to_byte_array()))
            .and_then(|x: &Vec<u8>| <[u8; 32]>::try_from(&x[..]).ok())
    }

    fn lookup_ripemd160(&self, h: &Pk::Ripemd160) -> Option<Preimage32> {
        self.psbt_input()
            .ripemd160_preimages
            .get(&el_hashes::ripemd160::Hash::from_byte_array(
                Pk::to_ripemd160(h).to_byte_array(),
            ))
            .and_then(|x: &Vec<u8>| <[u8; 32]>::try_from(&x[..]).ok())
    }
}

// Basic sanity checks on psbts.
// rust-bitcoin TODO: (Long term)
// Brainstorm about how we can enforce these in type system while having a nice API
fn sanity_check(psbt: &Psbt) -> Result<(), Error> {
    if psbt.n_inputs() != psbt.inputs().len() {
        return Err(Error::WrongInputCount { in_tx: psbt.n_inputs(), in_map: psbt.inputs().len() });
    }

    // Check well-formedness of input data
    for (index, input) in psbt.inputs().iter().enumerate() {
        let target_ecdsa_sighash_ty = match input.sighash_type {
            Some(ty) => ty
                .ecdsa_hash_ty()
                .ok_or(Error::InputError(InputError::NonStandardSighashType(ty), index))?,
            None => EcdsaSighashType::All,
        };
        for sig in partial_sigs(input, index) {
            let (key, (_, flag)) = sig?;
            if target_ecdsa_sighash_ty != flag {
                return Err(Error::InputError(
                    InputError::WrongSighashFlag {
                        required: target_ecdsa_sighash_ty,
                        got: flag,
                        pubkey: *key,
                    },
                    index,
                ));
            }
        }
    }

    Ok(())
}

// The partial signatures of input `index`, which PSETs store raw: DER followed by the sighash
// byte.
fn partial_sigs(
    input: &psbt::Input,
    index: usize,
) -> impl Iterator<Item = Result<(&bitcoin::PublicKey, ElementsSig), Error>> + '_ {
    input.partial_sigs.iter().map(move |(key, raw)| {
        elementssig_from_rawsig(raw)
            .map(|sig| (key, sig))
            .map_err(|e| Error::InputError(InputError::Interpreter(e), index))
    })
}

/// Additional operations for miniscript descriptors for various psbt roles.
/// Note that these APIs would generally error when used on scripts that are not
/// miniscripts.
pub trait PsbtExt {
    /// Finalize the psbt. This function takes in a mutable reference to psbt
    /// and populates the final_witness and final_scriptsig
    /// for all miniscript inputs.
    ///
    /// Finalizes all inputs that it can finalize, and returns an error for each input
    /// that it cannot finalize. Also performs a sanity interpreter check on the
    /// finalized psbt which involves checking the signatures/ preimages/timelocks.
    ///
    /// Inputs with a nonempty final scriptSig or witness are left as they are. Empty final
    /// fields, which `PartiallySignedTransaction::from_tx` records, do not count as final.
    ///
    /// Input finalization also fails if it is not possible to satisfy any of the inputs non-malleably
    /// See [finalizer::finalize_mall] if you want to allow malleable satisfactions
    ///
    /// For finalizing individual inputs, see also [`PsbtExt::finalize_inp`]
    ///
    /// The `genesis_hash` of the chain is required to check Taproot signatures.
    ///
    /// # Errors:
    ///
    /// - A vector of errors, one of each of failed finalized input
    fn finalize_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Vec<Error>>;

    /// Same as [`PsbtExt::finalize_mut`], but does not mutate the input psbt and
    /// returns a new psbt
    ///
    /// # Errors:
    ///
    /// - Returns a mutated psbt with all inputs `finalize_mut` could finalize
    /// - A vector of input errors, one of each of failed finalized input
    #[allow(clippy::result_large_err)]
    fn finalize<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Vec<Error>)>;

    /// Same as [PsbtExt::finalize_mut], but allows for malleable satisfactions
    fn finalize_mall_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Vec<Error>>;

    /// Same as [PsbtExt::finalize], but allows for malleable satisfactions
    #[allow(clippy::result_large_err)]
    fn finalize_mall<C: secp256k1::Verification>(
        self,
        secp: &Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Vec<Error>)>;

    /// Same as [`PsbtExt::finalize_mut`], but only tries to finalize a single input leaving other
    /// inputs as is. Use this when not all of inputs that you are trying to
    /// satisfy are miniscripts
    ///
    /// # Errors:
    ///
    /// - Input error detailing why the finalization failed. The psbt is not mutated when the finalization fails
    fn finalize_inp_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Error>;

    /// Same as [`PsbtExt::finalize_inp_mut`], but does not mutate the psbt and returns a new one
    ///
    /// # Errors:
    ///  Returns a tuple containing
    /// - Original psbt
    /// - Input Error detailing why the input finalization failed
    #[allow(clippy::result_large_err)] // our "error type" includes the original PSBT
    fn finalize_inp<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Error)>;

    /// Same as [`PsbtExt::finalize_inp_mut`], but allows for malleable satisfactions
    fn finalize_inp_mall_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Error>;

    /// Same as [`PsbtExt::finalize_inp`], but allows for malleable satisfactions
    #[allow(clippy::result_large_err)] // our "error type" includes the original PSBT
    fn finalize_inp_mall<C: secp256k1::Verification>(
        self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Error)>;

    /// Psbt extractor as defined in BIP174 that takes in a psbt reference
    /// and outputs a extracted [`elements::Transaction`].
    ///
    /// Also does the interpreter sanity check.
    ///
    /// Will error if the final ScriptSig or final Witness are missing
    /// or the interpreter check fails.
    fn extract<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<elements::Transaction, Error>;

    /// Update PSBT input with a descriptor and check consistency of `*_utxo` fields.
    ///
    /// This is the checked version of [`update_with_descriptor_unchecked`]. It checks that the
    /// `witness_utxo` and `non_witness_utxo` are sane and have a `script_pubkey` that matches the
    /// descriptor. In particular, it makes sure pre-segwit descriptors always have `non_witness_utxo`
    /// present (and the txid matches). If both `witness_utxo` and `non_witness_utxo` are present
    /// then it also checks they are consistent with each other.
    ///
    /// Hint: because of the *[segwit bug]* some PSBT signers require that `non_witness_utxo` is
    /// present on segwitv0 inputs regardless but this function doesn't enforce this so you will
    /// have to do this check its presence manually (if it is present this *will* check its
    /// validity).
    ///
    /// The `descriptor` **must not have any wildcards** in it
    /// otherwise an error will be returned however it can (and should) have extended keys in it.
    ///
    /// [`update_with_descriptor_unchecked`]: PsbtInputExt::update_with_descriptor_unchecked
    /// [segwit bug]: https://bitcoinhackers.org/@lukedashjr/104287698361196952
    fn update_input_with_descriptor(
        &mut self,
        input_index: usize,
        descriptor: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<(), UtxoUpdateError>;

    /// Update PSBT output with a descriptor and check consistency of the output's `script_pubkey`
    ///
    /// This is the checked version of [`update_with_descriptor_unchecked`]. It checks that the
    /// output's `script_pubkey` matches the descriptor.
    ///
    /// The `descriptor` **must not have any wildcards** in it
    /// otherwise an error will be returned however it can (and should) have extended keys in it.
    ///
    /// [`update_with_descriptor_unchecked`]: PsbtOutputExt::update_with_descriptor_unchecked
    fn update_output_with_descriptor(
        &mut self,
        output_index: usize,
        descriptor: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<(), OutputUpdateError>;

    /// Get the sighash message(data to sign) at input index `idx`.
    ///
    /// Based on the sighash
    /// flag specified in the [`Psbt`] sighash field. If the input sighash flag psbt field is `None`
    /// the [`SchnorrSighashType::Default`](elements::SchnorrSighashType::Default) is chosen
    /// for for taproot spends, otherwise [`EcdsaSighashType::All`] is chosen.
    /// If the utxo at `idx` is a taproot output, returns a [`PsbtSighashMsg::TapSighash`] variant.
    /// If the utxo at `idx` is a pre-taproot segwit output, returns a [`PsbtSighashMsg::SegwitV0Sighash`] variant.
    /// For legacy outputs, returns a [`PsbtSighashMsg::LegacySighash`] variant.
    /// The `tapleaf_hash` parameter can be used to specify which tapleaf script hash has to be computed. If
    /// `tapleaf_hash` is [`None`], and the output is taproot output, the key spend hash is computed. This parameter must be
    /// set to [`None`] while computing sighash for pre-taproot outputs.
    /// The function also updates the sighash cache with transaction computed during sighash computation of this input
    ///
    /// `cache` must be built from the transaction extracted from this PSET, with matching
    /// sighash-relevant transaction fields. This method does not verify that correspondence.
    ///
    /// # Panics
    ///
    /// For legacy and Segwit v0 inputs, panics if `idx` is a valid PSET input index but is
    /// outside the transaction used to construct `cache`.
    ///
    /// # Arguments:
    ///
    /// * `idx`: The input index of psbt to sign
    /// * `cache`: The [`SighashCache`] for used to cache/read previously cached computations
    /// * `tapleaf_hash`: If the output is taproot, compute the sighash for this particular leaf.
    /// * `genesis_hash`: The genesis block hash of the chain, committed to by Taproot sighashes.
    ///
    /// [`SighashCache`]: elements::sighash::SighashCache
    fn sighash_msg<T: Deref<Target = elements::Transaction>>(
        &self,
        idx: usize,
        cache: &mut SighashCache<T>,
        tapleaf_hash: Option<TapLeafHash>,
        genesis_hash: elements::BlockHash,
    ) -> Result<PsbtSighashMsg, SighashError>;
}

impl PsbtExt for Psbt {
    fn finalize_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Vec<Error>> {
        let mut tx = None;
        let errors = (0..self.inputs().len())
            .filter_map(|i| {
                finalizer::finalize_input(
                    self,
                    i,
                    secp,
                    /*allow_mall*/ false,
                    genesis_hash,
                    &mut tx,
                )
                .err()
            })
            .collect::<Vec<Error>>();
        errors.is_empty().then_some(()).ok_or(errors)
    }

    fn finalize<C: secp256k1::Verification>(
        mut self,
        secp: &secp256k1::Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Vec<Error>)> {
        match self.finalize_mut(secp, genesis_hash) {
            Ok(..) => Ok(self),
            Err(e) => Err((self, e)),
        }
    }

    fn finalize_mall_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Vec<Error>> {
        let mut tx = None;
        let errors = (0..self.inputs().len())
            .filter_map(|i| {
                finalizer::finalize_input(
                    self,
                    i,
                    secp,
                    /*allow_mall*/ true,
                    genesis_hash,
                    &mut tx,
                )
                .err()
            })
            .collect::<Vec<Error>>();
        errors.is_empty().then_some(()).ok_or(errors)
    }

    fn finalize_mall<C: secp256k1::Verification>(
        mut self,
        secp: &Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Vec<Error>)> {
        match self.finalize_mall_mut(secp, genesis_hash) {
            Ok(..) => Ok(self),
            Err(e) => Err((self, e)),
        }
    }

    fn finalize_inp_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Error> {
        if index >= self.inputs().len() {
            return Err(Error::InputIdxOutofBounds { psbt_inp: self.inputs().len(), index });
        }
        finalizer::finalize_input(
            self,
            index,
            secp,
            /*allow_mall*/ false,
            genesis_hash,
            &mut None,
        )
    }

    fn finalize_inp<C: secp256k1::Verification>(
        mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Error)> {
        match self.finalize_inp_mut(secp, index, genesis_hash) {
            Ok(..) => Ok(self),
            Err(e) => Err((self, e)),
        }
    }

    fn finalize_inp_mall_mut<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<(), Error> {
        if index >= self.inputs().len() {
            return Err(Error::InputIdxOutofBounds { psbt_inp: self.inputs().len(), index });
        }
        finalizer::finalize_input(
            self,
            index,
            secp,
            /*allow_mall*/ true,
            genesis_hash,
            &mut None,
        )
    }

    fn finalize_inp_mall<C: secp256k1::Verification>(
        mut self,
        secp: &secp256k1::Secp256k1<C>,
        index: usize,
        genesis_hash: elements::BlockHash,
    ) -> Result<Psbt, (Psbt, Error)> {
        match self.finalize_inp_mall_mut(secp, index, genesis_hash) {
            Ok(..) => Ok(self),
            Err(e) => Err((self, e)),
        }
    }

    fn extract<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        genesis_hash: elements::BlockHash,
    ) -> Result<elements::Transaction, Error> {
        sanity_check(self)?;

        for (n, input) in self.inputs().iter().enumerate() {
            if !finalizer::has_final_scripts(input) {
                return Err(Error::InputError(InputError::MissingWitness, n));
            }
        }
        // The PSET extractor fills in the final scriptSigs and witnesses.
        let ret = self.extract_tx()?;
        finalizer::interpreter_check_tx(self, secp, genesis_hash, &ret)?;
        Ok(ret)
    }

    fn update_input_with_descriptor(
        &mut self,
        input_index: usize,
        desc: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<(), UtxoUpdateError> {
        let n_inputs = self.inputs().len();
        let input = self
            .inputs_mut()
            .get_mut(input_index)
            .ok_or(UtxoUpdateError::IndexOutOfBounds(input_index, n_inputs))?;
        // PSET inputs carry their own prevout.
        let prevout = input.previous_outpoint();

        let desc_type = desc.desc_type();

        if let Some(non_witness_utxo) = &input.non_witness_utxo {
            if prevout.txid != non_witness_utxo.txid() {
                return Err(UtxoUpdateError::UtxoCheck);
            }
        }

        let expected_spk = {
            match (&input.witness_utxo, &input.non_witness_utxo) {
                (Some(witness_utxo), None) => {
                    if desc_type.segwit_version().is_some() {
                        witness_utxo.script_pubkey.clone()
                    } else {
                        return Err(UtxoUpdateError::UtxoCheck);
                    }
                }
                (None, Some(non_witness_utxo)) => non_witness_utxo
                    .output
                    .get(prevout.vout as usize)
                    .ok_or(UtxoUpdateError::UtxoCheck)?
                    .script_pubkey
                    .clone(),
                (Some(witness_utxo), Some(non_witness_utxo)) => {
                    if witness_utxo
                        != non_witness_utxo
                            .output
                            .get(prevout.vout as usize)
                            .ok_or(UtxoUpdateError::UtxoCheck)?
                    {
                        return Err(UtxoUpdateError::UtxoCheck);
                    }

                    witness_utxo.script_pubkey.clone()
                }
                (None, None) => return Err(UtxoUpdateError::UtxoCheck),
            }
        };

        let (_, spk_check_passed) =
            update_item_with_descriptor_helper(input, desc, Some(&expected_spk))
                .map_err(UtxoUpdateError::DerivationError)?;

        if !spk_check_passed {
            return Err(UtxoUpdateError::MismatchedScriptPubkey);
        }

        Ok(())
    }

    fn update_output_with_descriptor(
        &mut self,
        output_index: usize,
        desc: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<(), OutputUpdateError> {
        let n_outputs = self.outputs().len();
        let output = self
            .outputs_mut()
            .get_mut(output_index)
            .ok_or(OutputUpdateError::IndexOutOfBounds(output_index, n_outputs))?;
        // PSET outputs carry their own script_pubkey; clone it to release the borrow.
        let txout_spk = output.script_pubkey.clone();

        let (_, spk_check_passed) =
            update_item_with_descriptor_helper(output, desc, Some(&txout_spk))
                .map_err(OutputUpdateError::DerivationError)?;

        if !spk_check_passed {
            return Err(OutputUpdateError::MismatchedScriptPubkey);
        }

        Ok(())
    }

    fn sighash_msg<T: Deref<Target = elements::Transaction>>(
        &self,
        idx: usize,
        cache: &mut SighashCache<T>,
        tapleaf_hash: Option<TapLeafHash>,
        genesis_hash: elements::BlockHash,
    ) -> Result<PsbtSighashMsg, SighashError> {
        // Infer a descriptor at idx
        if idx >= self.inputs().len() {
            return Err(SighashError::IndexOutOfBounds(idx, self.inputs().len()));
        }
        let inp = &self.inputs()[idx];
        let prevouts = finalizer::prevouts(self).map_err(|_e| SighashError::MissingSpendUtxos)?;
        // Note that as per Psbt spec we should have access to spent_utxos for the transaction
        // Even if the transaction does not require SighashAll, we create `Prevouts::All` for code simplicity
        let prevouts = elements::sighash::Prevouts::All(&prevouts);
        let inp_spk =
            finalizer::get_scriptpubkey(self, idx).map_err(|_e| SighashError::MissingInputUtxo)?;
        if inp_spk.is_v1_p2tr() {
            let hash_ty = inp
                .schnorr_hash_ty()
                .ok_or(SighashError::InvalidSighashType)?;
            match tapleaf_hash {
                Some(leaf_hash) => {
                    let tap_sighash_msg = cache.taproot_script_spend_signature_hash(
                        idx,
                        &prevouts,
                        leaf_hash,
                        hash_ty,
                        genesis_hash,
                    )?;
                    Ok(PsbtSighashMsg::TapSighash(tap_sighash_msg))
                }
                None => {
                    let tap_sighash_msg = cache.taproot_key_spend_signature_hash(
                        idx,
                        &prevouts,
                        hash_ty,
                        genesis_hash,
                    )?;
                    Ok(PsbtSighashMsg::TapSighash(tap_sighash_msg))
                }
            }
        } else {
            let hash_ty = inp
                .ecdsa_hash_ty()
                .ok_or(SighashError::InvalidSighashType)?;
            let amt = finalizer::get_utxo(self, idx)
                .map_err(|_e| SighashError::MissingInputUtxo)?
                .value;
            let is_nested_wpkh = inp_spk.is_p2sh()
                && inp
                    .redeem_script
                    .as_ref()
                    .map(|x| x.is_v0_p2wpkh())
                    .unwrap_or(false);
            let is_nested_wsh = inp_spk.is_p2sh()
                && inp
                    .redeem_script
                    .as_ref()
                    .map(|x| x.is_v0_p2wsh())
                    .unwrap_or(false);
            if inp_spk.is_v0_p2wpkh() || inp_spk.is_v0_p2wsh() || is_nested_wpkh || is_nested_wsh {
                let msg = if inp_spk.is_v0_p2wpkh() {
                    cache.segwitv0_sighash(idx, &script_code_wpkh(&inp_spk), amt, hash_ty)
                } else if is_nested_wpkh {
                    let script_code = inp
                        .redeem_script
                        .as_ref()
                        .expect("redeem script non-empty checked earlier");
                    cache.segwitv0_sighash(idx, &script_code_wpkh(script_code), amt, hash_ty)
                } else {
                    let witness_script = inp
                        .witness_script
                        .as_ref()
                        .ok_or(SighashError::MissingWitnessScript)?;
                    cache.segwitv0_sighash(idx, witness_script, amt, hash_ty)
                };
                Ok(PsbtSighashMsg::SegwitV0Sighash(msg))
            } else {
                // legacy sighash case
                let script_code = if inp_spk.is_p2sh() {
                    inp.redeem_script
                        .as_ref()
                        .ok_or(SighashError::MissingRedeemScript)?
                } else {
                    &inp_spk
                };
                let msg = cache.legacy_sighash(idx, script_code, hash_ty);
                Ok(PsbtSighashMsg::LegacySighash(msg))
            }
        }
    }
}

// The BIP143 script code of a P2WPKH output, `DUP HASH160 <pkh> EQUALVERIFY CHECKSIG`,
// which Elements shares with Bitcoin.
fn script_code_wpkh(spk: &Script) -> Script {
    let mut script_code = vec![0x76u8, 0xa9, 0x14];
    script_code.extend(&spk.as_bytes()[2..]);
    script_code.push(0x88);
    script_code.push(0xac);
    Script::from(script_code)
}

/// Extension trait for PSBT inputs
pub trait PsbtInputExt {
    /// Given the descriptor for a utxo being spent populate the PSBT input's fields so it can be signed.
    ///
    /// If the descriptor contains wildcards or otherwise cannot be transformed into a concrete
    /// descriptor an error will be returned. The descriptor *can* (and should) have extended keys in
    /// it so PSBT fields like `bip32_derivation` and `tap_key_origins` can be populated.
    ///
    /// Every key in the descriptor gets an entry in `bip32_derivation` (or `tap_key_origins` for
    /// Taproot descriptors). Keys without origin information are recorded as their own master
    /// key: the fingerprint is [`DefiniteDescriptorKey::master_fingerprint`] and the derivation
    /// path is empty.
    ///
    /// Note that his method doesn't check that the `witness_utxo` or `non_witness_utxo` is
    /// consistent with the descriptor. To do that see [`update_input_with_descriptor`].
    ///
    /// ## Return value
    ///
    /// For convenience, this returns the concrete descriptor that is computed internally to fill
    /// out the PSBT input fields. This can be used to manually check that the `script_pubkey` in
    /// `witness_utxo` and/or `non_witness_utxo` is consistent with the descriptor.
    ///
    /// [`update_input_with_descriptor`]: PsbtExt::update_input_with_descriptor
    fn update_with_descriptor_unchecked(
        &mut self,
        descriptor: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<Descriptor<bitcoin::PublicKey>, descriptor::NonDefiniteKeyError>;
}

impl PsbtInputExt for psbt::Input {
    fn update_with_descriptor_unchecked(
        &mut self,
        descriptor: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<Descriptor<bitcoin::PublicKey>, descriptor::NonDefiniteKeyError> {
        let (derived, _) = update_item_with_descriptor_helper(self, descriptor, None)?;
        Ok(derived)
    }
}

/// Extension trait for PSBT outputs
pub trait PsbtOutputExt {
    /// Given the descriptor of a PSBT output populate the relevant metadata
    ///
    /// If the descriptor contains wildcards or otherwise cannot be transformed into a concrete
    /// descriptor an error will be returned. The descriptor *can* (and should) have extended keys in
    /// it so PSBT fields like `bip32_derivation` and `tap_key_origins` can be populated.
    ///
    /// Every key in the descriptor gets an entry in `bip32_derivation` (or `tap_key_origins` for
    /// Taproot descriptors). Keys without origin information are recorded as their own master
    /// key: the fingerprint is [`DefiniteDescriptorKey::master_fingerprint`] and the derivation
    /// path is empty.
    ///
    /// Note that this method doesn't check that the `script_pubkey` of the output being
    /// updated matches the descriptor. To do that see [`update_output_with_descriptor`].
    ///
    /// ## Return value
    ///
    /// For convenience, this returns the concrete descriptor that is computed internally to fill
    /// out the PSBT output fields. This can be used to manually check that the `script_pubkey` is
    /// consistent with the descriptor.
    ///
    /// [`update_output_with_descriptor`]: PsbtExt::update_output_with_descriptor
    fn update_with_descriptor_unchecked(
        &mut self,
        descriptor: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<Descriptor<bitcoin::PublicKey>, descriptor::NonDefiniteKeyError>;
}

impl PsbtOutputExt for psbt::Output {
    fn update_with_descriptor_unchecked(
        &mut self,
        descriptor: &Descriptor<DefiniteDescriptorKey>,
    ) -> Result<Descriptor<bitcoin::PublicKey>, descriptor::NonDefiniteKeyError> {
        let (derived, _) = update_item_with_descriptor_helper(self, descriptor, None)?;
        Ok(derived)
    }
}

// Traverse the pkh lookup while maintaining a reverse map for storing the map
// hash160 -> (XonlyPublicKey)/PublicKey
struct KeySourceLookUp(
    pub BTreeMap<bitcoin::PublicKey, bip32::KeySource>,
    pub secp256k1::Secp256k1<VerifyOnly>,
);

impl Translator<DefiniteDescriptorKey> for KeySourceLookUp {
    type TargetPk = bitcoin::PublicKey;
    type Error = core::convert::Infallible;

    fn pk(&mut self, xpk: &DefiniteDescriptorKey) -> Result<Self::TargetPk, Self::Error> {
        let derived = xpk.derive_public_key(&self.1);
        self.0.insert(
            derived.to_public_key(),
            (
                xpk.master_fingerprint(),
                xpk.full_derivation_path()
                    .expect("definite keys cannot be multikeys"),
            ),
        );
        Ok(derived)
    }

    translate_hash_clone!(DescriptorPublicKey);
}

// Provides generalized access to PSBT fields common to inputs and outputs
trait PsbtFields {
    // Common fields are returned as a mutable ref of the same type
    fn redeem_script(&mut self) -> &mut Option<Script>;
    fn witness_script(&mut self) -> &mut Option<Script>;
    fn bip32_derivation(&mut self) -> &mut BTreeMap<bitcoin::PublicKey, bip32::KeySource>;
    fn tap_internal_key(&mut self) -> &mut Option<bitcoin::key::XOnlyPublicKey>;
    fn tap_key_origins(
        &mut self,
    ) -> &mut BTreeMap<bitcoin::key::XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)>;
    #[allow(dead_code)]
    fn proprietary(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>>;
    #[allow(dead_code)]
    fn unknown(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>>;

    // `tap_tree` only appears in psbt::Output, so it's returned as an option of a mutable ref
    fn tap_tree(&mut self) -> Option<&mut Option<psbt::TapTree>> { None }

    // `tap_scripts` and `tap_merkle_root` only appear in psbt::Input
    fn tap_scripts(&mut self) -> Option<&mut BTreeMap<ControlBlock, (Script, LeafVersion)>> { None }
    fn tap_merkle_root(&mut self) -> Option<&mut Option<taproot::TapNodeHash>> { None }
}

impl PsbtFields for psbt::Input {
    fn redeem_script(&mut self) -> &mut Option<Script> { &mut self.redeem_script }
    fn witness_script(&mut self) -> &mut Option<Script> { &mut self.witness_script }
    fn bip32_derivation(&mut self) -> &mut BTreeMap<bitcoin::PublicKey, bip32::KeySource> {
        &mut self.bip32_derivation
    }
    fn tap_internal_key(&mut self) -> &mut Option<bitcoin::key::XOnlyPublicKey> {
        &mut self.tap_internal_key
    }
    fn tap_key_origins(
        &mut self,
    ) -> &mut BTreeMap<bitcoin::key::XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)> {
        &mut self.tap_key_origins
    }
    #[allow(dead_code)]
    fn proprietary(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>> {
        &mut self.proprietary
    }
    #[allow(dead_code)]
    fn unknown(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>> { &mut self.unknown }

    fn tap_scripts(&mut self) -> Option<&mut BTreeMap<ControlBlock, (Script, LeafVersion)>> {
        Some(&mut self.tap_scripts)
    }
    fn tap_merkle_root(&mut self) -> Option<&mut Option<taproot::TapNodeHash>> {
        Some(&mut self.tap_merkle_root)
    }
}

impl PsbtFields for psbt::Output {
    fn redeem_script(&mut self) -> &mut Option<Script> { &mut self.redeem_script }
    fn witness_script(&mut self) -> &mut Option<Script> { &mut self.witness_script }
    fn bip32_derivation(&mut self) -> &mut BTreeMap<bitcoin::PublicKey, bip32::KeySource> {
        &mut self.bip32_derivation
    }
    fn tap_internal_key(&mut self) -> &mut Option<bitcoin::key::XOnlyPublicKey> {
        &mut self.tap_internal_key
    }
    fn tap_key_origins(
        &mut self,
    ) -> &mut BTreeMap<bitcoin::key::XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)> {
        &mut self.tap_key_origins
    }
    #[allow(dead_code)]
    fn proprietary(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>> {
        &mut self.proprietary
    }
    #[allow(dead_code)]
    fn unknown(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>> { &mut self.unknown }

    fn tap_tree(&mut self) -> Option<&mut Option<psbt::TapTree>> { Some(&mut self.tap_tree) }
}

fn update_item_with_descriptor_helper<F: PsbtFields>(
    item: &mut F,
    descriptor: &Descriptor<DefiniteDescriptorKey>,
    check_script: Option<&Script>,
    // We return an extra boolean here to indicate an error with `check_script`. We do this
    // because the error is "morally" a UtxoUpdateError::MismatchedScriptPubkey, but some
    // callers expect a `descriptor::NonDefiniteKeyError`, which cannot be produced from a
    // `UtxoUpdateError`, and those callers can't get this error anyway because they pass
    // `None` for `check_script`.
) -> Result<(Descriptor<bitcoin::PublicKey>, bool), descriptor::NonDefiniteKeyError> {
    let secp = Secp256k1::verification_only();

    // 1. Derive the descriptor, recording each key derivation in a map from xpubs
    //    the keysource used to derive the key.
    let mut bip32_derivation = KeySourceLookUp(BTreeMap::new(), secp);
    let derived = descriptor
        .translate_pk(&mut bip32_derivation)
        .map_err(crate::TranslateErr::into_outer_err)
        .expect("No Context errors while translating");

    // 2. If we have a specific scriptpubkey we are targeting, bail out.
    if let Some(check_script) = check_script {
        if check_script != &derived.script_pubkey() {
            return Ok((derived, false));
        }
    }

    // 3. Update the PSBT fields using the derived key map.
    if let Descriptor::Tr(ref tr_derived) = &derived {
        let spend_info = tr_derived.spend_info();
        let KeySourceLookUp(xpub_map, _) = bip32_derivation;

        *item.tap_internal_key() = Some(spend_info.internal_key());
        for (derived_key, key_source) in xpub_map {
            item.tap_key_origins()
                .insert(derived_key.to_x_only_pubkey(), (vec![], key_source));
        }
        if let Some(merkle_root) = item.tap_merkle_root() {
            *merkle_root = spend_info.merkle_root();
        }

        for leaf_derived in spend_info.leaves() {
            let leaf_script = (leaf_derived.script().clone(), leaf_derived.leaf_version());
            let tapleaf_hash = leaf_derived.leaf_hash();
            if let Some(tap_scripts) = item.tap_scripts() {
                let control_block = leaf_derived.control_block().clone();
                tap_scripts.insert(control_block, leaf_script);
            }

            for leaf_pk in leaf_derived.miniscript().iter_pk() {
                let tapleaf_hashes = &mut item
                    .tap_key_origins()
                    .get_mut(&leaf_pk.to_x_only_pubkey())
                    .expect("inserted all keys above")
                    .0;
                if tapleaf_hashes.last() != Some(&tapleaf_hash) {
                    tapleaf_hashes.push(tapleaf_hash);
                }
            }
        }

        // Ensure there are no duplicated leaf hashes. This can happen if some of them were
        // already present in the map when this function is called, since this only appends new
        // data to the psbt without checking what's already present.
        for (tapleaf_hashes, _) in item.tap_key_origins().values_mut() {
            tapleaf_hashes.sort();
            tapleaf_hashes.dedup();
        }

        // Only set the tap_tree if the item supports it (it's an output) and the descriptor actually
        // contains one, otherwise it'll just be empty
        if let Some(tap_tree) = item.tap_tree() {
            *tap_tree = spend_info.to_tap_tree();
        }
    } else {
        item.bip32_derivation().append(&mut bip32_derivation.0);

        match &derived {
            Descriptor::Bare(_) | Descriptor::Pkh(_) | Descriptor::Wpkh(_) => {}
            Descriptor::Sh(sh) => match sh.as_inner() {
                descriptor::ShInner::Wsh(wsh) => {
                    *item.witness_script() = Some(wsh.inner_script());
                    *item.redeem_script() = Some(wsh.inner_script().to_v0_p2wsh());
                }
                descriptor::ShInner::Wpkh(..) => *item.redeem_script() = Some(sh.inner_script()),
                descriptor::ShInner::Ms(_) => *item.redeem_script() = Some(sh.inner_script()),
            },
            Descriptor::Wsh(wsh) => *item.witness_script() = Some(wsh.inner_script()),
            Descriptor::Tr(_) => unreachable!("Tr is dealt with separately"),
        }
    };

    Ok((derived, true))
}

/// Return error type for [`PsbtExt::update_input_with_descriptor`]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UtxoUpdateError {
    /// Index out of bounds
    IndexOutOfBounds(usize, usize),
    /// The unsigned transaction didn't have an input at that index
    MissingInputUtxo,
    /// Derivation error
    DerivationError(descriptor::NonDefiniteKeyError),
    /// The PSBT's `witness_utxo` and/or `non_witness_utxo` were invalid or missing
    UtxoCheck,
    /// The PSBT's `witness_utxo` and/or `non_witness_utxo` had a script_pubkey that did not match
    /// the descriptor
    MismatchedScriptPubkey,
}

impl fmt::Display for UtxoUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfBounds(ind, len) => {
                write!(f, "index {}, psbt input len: {}", ind, len)
            }
            Self::MissingInputUtxo => {
                write!(f, "Missing input in unsigned transaction")
            }
            Self::DerivationError(e) => write!(f, "Key derivation error {}", e),
            Self::UtxoCheck => write!(
                f,
                "The input's witness_utxo and/or non_witness_utxo were invalid or missing"
            ),
            Self::MismatchedScriptPubkey => {
                write!(f, "The input's witness_utxo and/or non_witness_utxo had a script pubkey that didn't match the descriptor")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for UtxoUpdateError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::UtxoUpdateError::*;

        match self {
            IndexOutOfBounds(_, _) | MissingInputUtxo | UtxoCheck | MismatchedScriptPubkey => None,
            DerivationError(e) => Some(e),
        }
    }
}

/// Return error type for [`PsbtExt::update_output_with_descriptor`]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OutputUpdateError {
    /// Index out of bounds
    IndexOutOfBounds(usize, usize),
    /// The raw unsigned transaction didn't have an output at that index
    MissingTxOut,
    /// Derivation error
    DerivationError(descriptor::NonDefiniteKeyError),
    /// The output's script_pubkey did not match the descriptor
    MismatchedScriptPubkey,
}

impl fmt::Display for OutputUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfBounds(ind, len) => {
                write!(f, "index {}, psbt output len: {}", ind, len)
            }
            Self::MissingTxOut => {
                write!(f, "Missing txout in the unsigned transaction")
            }
            Self::DerivationError(e) => write!(f, "Key derivation error {}", e),
            Self::MismatchedScriptPubkey => {
                write!(f, "The output's script pubkey didn't match the descriptor")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for OutputUpdateError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::OutputUpdateError::*;

        match self {
            IndexOutOfBounds(_, _) | MissingTxOut | MismatchedScriptPubkey => None,
            DerivationError(e) => Some(e),
        }
    }
}

/// Return error type for [`PsbtExt::sighash_msg`]
#[derive(Debug)]
pub enum SighashError {
    /// Index out of bounds
    IndexOutOfBounds(usize, usize),
    /// Missing input utxo
    MissingInputUtxo,
    /// Missing Prevouts
    MissingSpendUtxos,
    /// Invalid Sighash type
    InvalidSighashType,
    /// Computation error for taproot sighash.
    SighashTaproot(elements::sighash::Error),
    /// Missing Witness script
    MissingWitnessScript,
    /// Missing Redeem script,
    MissingRedeemScript,
}

impl fmt::Display for SighashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfBounds(ind, len) => {
                write!(f, "index {}, psbt input len: {}", ind, len)
            }
            Self::MissingInputUtxo => write!(f, "Missing input utxo in pbst"),
            Self::MissingSpendUtxos => write!(f, "Missing Psbt spend utxos"),
            Self::InvalidSighashType => write!(f, "Invalid Sighash type"),
            Self::MissingWitnessScript => write!(f, "Missing Witness Script"),
            Self::MissingRedeemScript => write!(f, "Missing Redeem Script"),
            Self::SighashTaproot(ref e) => write!(f, "sighash taproot: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for SighashError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::SighashError::*;

        match self {
            IndexOutOfBounds(_, _)
            | MissingInputUtxo
            | MissingSpendUtxos
            | InvalidSighashType
            | MissingWitnessScript
            | MissingRedeemScript => None,
            SighashTaproot(ref e) => Some(e),
        }
    }
}

impl From<elements::sighash::Error> for SighashError {
    fn from(e: elements::sighash::Error) -> Self { Self::SighashTaproot(e) }
}

/// Sighash message(signing data) for a given psbt transaction input.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum PsbtSighashMsg {
    /// Taproot Signature hash
    TapSighash(taproot::TapSighashHash),
    /// Legacy ECDSA sighash message.
    LegacySighash(elements::Sighash),
    /// Segwit v0 ECDSA sighash message.
    SegwitV0Sighash(elements::Sighash),
}

impl PsbtSighashMsg {
    /// Convert the message to a [`secp256k1::Message`].
    pub fn to_secp_msg(&self) -> secp256k1::Message {
        match *self {
            Self::TapSighash(msg) => secp256k1::Message::from_digest(msg.to_byte_array()),
            Self::LegacySighash(msg) => secp256k1::Message::from_digest(msg.to_byte_array()),
            Self::SegwitV0Sighash(msg) => secp256k1::Message::from_digest(msg.to_byte_array()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::bip32::{DerivationPath, Xpub};
    use bitcoin::key::XOnlyPublicKey;
    use bitcoin::PublicKey;
    use elements::confidential;

    use super::*;
    use crate::{elementssig_to_rawsig, Miniscript};

    // Taproot sighashes commit to the genesis hash of the chain.
    pub(super) fn genesis_hash() -> elements::BlockHash {
        elements::BlockHash::from_byte_array([0x42; 32])
    }

    // An explicit L-BTC output.
    pub(super) fn explicit_txout(script_pubkey: Script, amount: u64) -> elements::TxOut {
        elements::TxOut {
            asset: confidential::Asset::Explicit(elements::AssetId::LIQUID_BTC),
            value: confidential::Value::Explicit(amount),
            script_pubkey,
            ..Default::default()
        }
    }

    // A PSET with one input per script pubkey, each spending an explicit
    // 100_000 sat output, paying to the first script pubkey with a fee output.
    pub(super) fn pset_spending(script_pubkeys: &[Script]) -> Psbt {
        let mut psbt = Psbt::new_v2();
        for (vout, spk) in script_pubkeys.iter().enumerate() {
            let txid = elements::Txid::from_byte_array([1; 32]);
            let mut input = psbt::Input::from_prevout(elements::OutPoint::new(txid, vout as u32));
            input.witness_utxo = Some(explicit_txout(spk.clone(), 100_000));
            psbt.add_input(input);
        }
        let n = script_pubkeys.len() as u64;
        let asset = elements::AssetId::LIQUID_BTC;
        psbt.add_output(psbt::Output::new_explicit(
            script_pubkeys[0].clone(),
            90_000 * n,
            asset,
            None,
        ));
        // An empty script pubkey marks the Elements fee output.
        psbt.add_output(psbt::Output::new_explicit(Script::new(), 10_000 * n, asset, None));
        psbt
    }

    // A secret key filled with `sk` bytes and its public key.
    pub(super) fn wpkh_key(
        secp: &Secp256k1<secp256k1::All>,
        sk: u8,
    ) -> (secp256k1::SecretKey, PublicKey) {
        let sk = secp256k1::SecretKey::from_slice(&[sk; 32]).unwrap();
        (sk, PublicKey::new(secp256k1::PublicKey::from_secret_key(secp, &sk)))
    }

    #[test]
    fn test_extract_finalized_pset() {
        // Sign an `elwpkh` input, finalize it and extract the transaction; both
        // finalizing and extracting run the interpreter over the Elements sighash.
        let secp = Secp256k1::new();
        let (sk, pk) = wpkh_key(&secp, 1);
        let desc = Descriptor::new_wpkh(pk).unwrap();
        let mut psbt = pset_spending(&[desc.script_pubkey()]);

        let unsigned_tx = psbt.extract_tx().unwrap();
        let msg = psbt
            .sighash_msg(0, &mut SighashCache::new(&unsigned_tx), None, genesis_hash())
            .unwrap();
        assert!(matches!(msg, PsbtSighashMsg::SegwitV0Sighash(_)));
        let sig = (secp.sign_ecdsa(&msg.to_secp_msg(), &sk), EcdsaSighashType::All);
        psbt.inputs_mut()[0]
            .partial_sigs
            .insert(pk, elementssig_to_rawsig(&sig));

        psbt.finalize_mut(&secp, genesis_hash()).unwrap();
        assert!(psbt.inputs()[0].partial_sigs.is_empty());
        let tx = psbt.extract(&secp, genesis_hash()).unwrap();

        assert!(tx.input[0].script_sig.is_empty());
        assert_eq!(
            tx.input[0].witness.script_witness.to_vec(),
            vec![elementssig_to_rawsig(&sig), pk.to_bytes()]
        );
        assert_eq!(tx.input[0].previous_output, psbt.inputs()[0].previous_outpoint());
        assert_eq!(tx.output, unsigned_tx.output);
    }

    #[test]
    fn finalize_pset_from_unsigned_transaction() {
        let secp = Secp256k1::new();
        let (sk, pk) = wpkh_key(&secp, 1);
        let desc = Descriptor::new_wpkh(pk).unwrap();
        let original = pset_spending(&[desc.script_pubkey()]);
        let unsigned_tx = original.extract_tx().unwrap();
        let mut psbt = Psbt::from_tx(unsigned_tx.clone());
        psbt.inputs_mut()[0].witness_utxo = original.inputs()[0].witness_utxo.clone();

        // from_tx records the unsigned transaction's empty final fields as Some.
        assert!(psbt.inputs()[0]
            .final_script_sig
            .as_ref()
            .unwrap()
            .is_empty());
        assert!(psbt.inputs()[0]
            .final_script_witness
            .as_ref()
            .unwrap()
            .is_empty());
        assert!(psbt.finalize_mut(&secp, genesis_hash()).is_err());
        assert!(matches!(
            psbt.extract(&secp, genesis_hash()),
            Err(Error::InputError(InputError::MissingWitness, 0))
        ));

        let msg = psbt
            .sighash_msg(0, &mut SighashCache::new(&unsigned_tx), None, genesis_hash())
            .unwrap();
        let sig = (secp.sign_ecdsa(&msg.to_secp_msg(), &sk), EcdsaSighashType::All);
        psbt.inputs_mut()[0]
            .partial_sigs
            .insert(pk, elementssig_to_rawsig(&sig));
        psbt.finalize_mut(&secp, genesis_hash()).unwrap();
        let tx = psbt.extract(&secp, genesis_hash()).unwrap();
        assert_eq!(
            tx.input[0].witness.script_witness.to_vec(),
            vec![elementssig_to_rawsig(&sig), pk.to_bytes()]
        );
        assert_eq!(tx.output, unsigned_tx.output);
    }

    #[test]
    fn test_extract_finalized_pset_taproot_key_spend() {
        use elements::schnorr::TapTweak as _;

        let secp = Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[2; 32]).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (internal_key, _) = keypair.x_only_public_key();
        let desc = Descriptor::new_tr(PublicKey::new(keypair.public_key()), None).unwrap();
        let mut psbt = pset_spending(&[desc.script_pubkey()]);
        psbt.inputs_mut()[0].tap_internal_key = Some(internal_key);

        let unsigned_tx = psbt.extract_tx().unwrap();
        let msg = psbt
            .sighash_msg(0, &mut SighashCache::new(&unsigned_tx), None, genesis_hash())
            .unwrap();
        assert!(matches!(msg, PsbtSighashMsg::TapSighash(_)));
        let tweaked = keypair.tap_tweak(&secp, None).to_inner();
        let sig = elements::SchnorrSig {
            sig: secp.sign_schnorr_with_aux_rand(&msg.to_secp_msg(), &tweaked, &[0; 32]),
            hash_ty: elements::SchnorrSighashType::Default,
        };
        psbt.inputs_mut()[0].tap_key_sig = Some(sig);

        psbt.finalize_mut(&secp, genesis_hash()).unwrap();
        // The signature commits to the genesis hash, so another chain rejects it.
        let other_chain = elements::BlockHash::from_byte_array([0x43; 32]);
        assert!(interpreter_check(&psbt, &secp, other_chain).is_err());
        let tx = psbt.extract(&secp, genesis_hash()).unwrap();
        assert_eq!(tx.input[0].witness.script_witness.to_vec(), vec![sig.to_vec()]);
    }

    // A partial signature that is not DER followed by a sighash byte is an error, rather than a
    // missing signature.
    #[test]
    fn malformed_partial_signature() {
        let secp = Secp256k1::new();
        let (_, pk) = wpkh_key(&secp, 1);
        let mut psbt = pset_spending(&[Descriptor::new_wpkh(pk).unwrap().script_pubkey()]);
        psbt.inputs_mut()[0]
            .partial_sigs
            .insert(pk, vec![0x30, 0x00, 0x01]);
        let malformed = |err: Error| {
            matches!(
                err,
                Error::InputError(InputError::Interpreter(interpreter::Error::Secp(_)), 0)
            )
        };

        let finalized = psbt.clone().finalize_inp_mut(&secp, 0, genesis_hash());
        assert!(malformed(finalized.unwrap_err()));
        let extracted = psbt.extract(&secp, genesis_hash());
        assert!(malformed(extracted.unwrap_err()));
    }

    #[test]
    fn sighash_msg_index_out_of_bounds() {
        let secp = Secp256k1::new();
        let spks: Vec<Script> = (1..=2)
            .map(|sk| {
                Descriptor::new_wpkh(wpkh_key(&secp, sk).1)
                    .unwrap()
                    .script_pubkey()
            })
            .collect();
        let psbt = pset_spending(&spks);
        let tx = psbt.extract_tx().unwrap();
        let msg = psbt.sighash_msg(1, &mut SighashCache::new(&tx), None, genesis_hash());
        assert!(matches!(msg, Ok(PsbtSighashMsg::SegwitV0Sighash(_))));

        let err = psbt
            .sighash_msg(2, &mut SighashCache::new(&tx), None, genesis_hash())
            .unwrap_err();
        assert!(matches!(err, SighashError::IndexOutOfBounds(2, 2)), "{}", err);
    }

    #[test]
    fn missing_non_witness_utxo_output() {
        let secp = Secp256k1::new();
        let previous = pset_spending(&[Script::new()]).extract_tx().unwrap();
        let vout = previous.output.len() as u32;
        let mut psbt = Psbt::new_v2();
        let mut input = psbt::Input::from_prevout(elements::OutPoint::new(previous.txid(), vout));
        input.non_witness_utxo = Some(previous);
        psbt.add_input(input);

        let tx = psbt.extract_tx().unwrap();
        let err = psbt
            .sighash_msg(0, &mut SighashCache::new(&tx), None, genesis_hash())
            .unwrap_err();
        assert!(matches!(err, SighashError::MissingSpendUtxos), "{}", err);
        let err = psbt.finalize_inp_mut(&secp, 0, genesis_hash()).unwrap_err();
        assert!(matches!(err, Error::InputError(InputError::MissingUtxo, 0)), "{}", err);
    }

    #[test]
    fn finalize_inp_mall_allows_malleable_satisfaction() {
        use bitcoin::hashes::sha256;

        // Neither branch requires a signature, so only a malleable satisfaction exists.
        let secp = Secp256k1::new();
        let preimage = [1u8; 32];
        let hash = sha256::Hash::hash(&preimage);
        let ms = Miniscript::<PublicKey, crate::Segwitv0>::from_str_insane(&format!(
            "or_i(sha256({}),sha256({}))",
            hash,
            sha256::Hash::hash(&[2u8; 32]),
        ))
        .unwrap();
        let mut psbt = pset_spending(&[ms.encode().to_v0_p2wsh()]);
        let input = &mut psbt.inputs_mut()[0];
        input.witness_script = Some(ms.encode());
        input.sha256_preimages.insert(
            el_hashes::sha256::Hash::from_byte_array(hash.to_byte_array()),
            preimage.to_vec(),
        );

        let err = psbt
            .clone()
            .finalize_inp_mut(&secp, 0, genesis_hash())
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::InputError(InputError::MiniscriptError(crate::Error::CouldNotSatisfy), 0)
            ),
            "{}",
            err
        );
        psbt.finalize_inp_mall_mut(&secp, 0, genesis_hash())
            .unwrap();
        assert!(psbt.inputs()[0].final_script_witness.is_some());
    }

    #[test]
    fn test_update_item_no_origin_single_key() {
        // A single key without origin is recorded as its own master key: its own
        // fingerprint (first four bytes of HASH160) with an empty derivation path.
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(
            "elwpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        )
        .unwrap();
        let pk = PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let mut psbt_input = psbt::Input::default();
        psbt_input.update_with_descriptor_unchecked(&desc).unwrap();
        assert_eq!(psbt_input.bip32_derivation.len(), 1);
        let (fingerprint, path) = &psbt_input.bip32_derivation[&pk];
        assert_eq!(*fingerprint, bip32::Fingerprint::from_str("751e76e8").unwrap());
        assert_eq!(*path, DerivationPath::master());

        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(
            "eltr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        )
        .unwrap();
        let xonly = XOnlyPublicKey::from_str(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let mut psbt_output = psbt::Output::default();
        psbt_output.update_with_descriptor_unchecked(&desc).unwrap();
        assert_eq!(psbt_output.tap_key_origins.len(), 1);
        let (leaf_hashes, (fingerprint, path)) = &psbt_output.tap_key_origins[&xonly];
        assert!(leaf_hashes.is_empty());
        assert_eq!(*fingerprint, bip32::Fingerprint::from_str("f678d9b7").unwrap());
        assert_eq!(*path, DerivationPath::master());
    }

    #[test]
    fn test_update_item_tr_no_script() {
        // keys taken from: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#Specifications
        let root_xpub = Xpub::from_str("xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8").unwrap();
        let fingerprint = root_xpub.fingerprint();
        let desc = format!("eltr([{}/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/0)", fingerprint);
        let desc = Descriptor::from_str(&desc).unwrap();
        let mut psbt_input = psbt::Input::default();
        psbt_input.update_with_descriptor_unchecked(&desc).unwrap();
        let mut psbt_output = psbt::Output::default();
        psbt_output.update_with_descriptor_unchecked(&desc).unwrap();
        let internal_key = XOnlyPublicKey::from_str(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();
        assert_eq!(psbt_input.tap_internal_key, Some(internal_key));
        assert_eq!(
            psbt_input.tap_key_origins.get(&internal_key),
            Some(&(vec![], (fingerprint, DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap())))
        );
        assert_eq!(psbt_input.tap_key_origins.len(), 1);
        assert_eq!(psbt_input.tap_scripts.len(), 0);
        assert_eq!(psbt_input.tap_merkle_root, None);

        assert_eq!(psbt_output.tap_internal_key, psbt_input.tap_internal_key);
        assert_eq!(psbt_output.tap_key_origins, psbt_input.tap_key_origins);
        assert_eq!(psbt_output.tap_tree, None);
    }

    #[test]
    fn test_update_item_tr_with_tapscript() {
        use crate::Tap;
        // keys taken from: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#Specifications
        let root_xpub = Xpub::from_str("xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8").unwrap();
        let fingerprint = root_xpub.fingerprint();
        let xpub = format!("[{}/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ", fingerprint);
        let desc = format!(
            "eltr({}/0/0,{{pkh({}/0/1),multi_a(2,{}/0/1,{}/1/0)}})",
            xpub, xpub, xpub, xpub
        );

        let desc = Descriptor::from_str(&desc).unwrap();
        let internal_key = XOnlyPublicKey::from_str(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();
        let mut psbt_input = psbt::Input::default();
        psbt_input.update_with_descriptor_unchecked(&desc).unwrap();
        let mut psbt_output = psbt::Output::default();
        psbt_output.update_with_descriptor_unchecked(&desc).unwrap();
        assert_eq!(psbt_input.tap_internal_key, Some(internal_key));
        assert_eq!(
            psbt_input.tap_key_origins.get(&internal_key),
            Some(&(vec![], (fingerprint, DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap())))
        );
        assert_eq!(psbt_input.tap_key_origins.len(), 3);
        assert_eq!(psbt_input.tap_scripts.len(), 2);
        assert!(psbt_input.tap_merkle_root.is_some());

        assert_eq!(psbt_output.tap_internal_key, psbt_input.tap_internal_key);
        assert_eq!(psbt_output.tap_key_origins, psbt_input.tap_key_origins);
        assert!(psbt_output.tap_tree.is_some());

        let key_0_1 = XOnlyPublicKey::from_str(
            "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
        )
        .unwrap();
        let first_leaf_hash = {
            let ms =
                Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!("pkh({})", key_0_1)).unwrap();
            let first_script = ms.encode();
            assert!(psbt_input
                .tap_scripts
                .values()
                .any(|value| *value == (first_script.clone(), LeafVersion::default())));
            TapLeafHash::from_script(&first_script, LeafVersion::default())
        };

        {
            // check 0/1
            let (leaf_hashes, (key_fingerprint, deriv_path)) =
                psbt_input.tap_key_origins.get(&key_0_1).unwrap();
            assert_eq!(key_fingerprint, &fingerprint);
            assert_eq!(&deriv_path.to_string(), "86'/0'/0'/0/1");
            assert_eq!(leaf_hashes.len(), 2);
            assert!(leaf_hashes.contains(&first_leaf_hash));
        }

        {
            // check 1/0
            let key_1_0 = XOnlyPublicKey::from_str(
                "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
            )
            .unwrap();
            let (leaf_hashes, (key_fingerprint, deriv_path)) =
                psbt_input.tap_key_origins.get(&key_1_0).unwrap();
            assert_eq!(key_fingerprint, &fingerprint);
            assert_eq!(&deriv_path.to_string(), "86'/0'/0'/1/0");
            assert_eq!(leaf_hashes.len(), 1);
            assert!(!leaf_hashes.contains(&first_leaf_hash));
        }
    }

    #[test]
    fn test_update_item_non_tr_multi() {
        // values taken from https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki (after removing zpub thingy)
        let root_xpub = Xpub::from_str("xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8").unwrap();
        let fingerprint = root_xpub.fingerprint();
        let xpub = format!("[{}/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V", fingerprint);
        let pubkeys = [
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
            "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
            "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6",
        ];

        let expected_bip32 = pubkeys
            .iter()
            .zip(["0/0", "0/1", "1/0"].iter())
            .map(|(pubkey, path)| {
                (
                    PublicKey::from_str(pubkey).unwrap(),
                    (
                        fingerprint,
                        DerivationPath::from_str(&format!("m/84'/0'/0'/{}", path)).unwrap(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();

        {
            // test segwit
            let desc = format!("elwsh(multi(2,{}/0/0,{}/0/1,{}/1/0))", xpub, xpub, xpub);
            let desc = Descriptor::from_str(&desc).unwrap();
            let derived = format!("elwsh(multi(2,{}))", pubkeys.join(","));
            let derived = Descriptor::<bitcoin::PublicKey>::from_str(&derived).unwrap();

            let mut psbt_input = psbt::Input::default();
            psbt_input.update_with_descriptor_unchecked(&desc).unwrap();

            let mut psbt_output = psbt::Output::default();
            psbt_output.update_with_descriptor_unchecked(&desc).unwrap();

            assert_eq!(expected_bip32, psbt_input.bip32_derivation);
            assert_eq!(psbt_input.witness_script, Some(derived.explicit_script().unwrap()));

            assert_eq!(psbt_output.bip32_derivation, psbt_input.bip32_derivation);
            assert_eq!(psbt_output.witness_script, psbt_input.witness_script);
        }

        {
            // test non-segwit
            let desc = format!("elsh(multi(2,{}/0/0,{}/0/1,{}/1/0))", xpub, xpub, xpub);
            let desc = Descriptor::from_str(&desc).unwrap();
            let derived = format!("elsh(multi(2,{}))", pubkeys.join(","));
            let derived = Descriptor::<bitcoin::PublicKey>::from_str(&derived).unwrap();

            let mut psbt_input = psbt::Input::default();
            psbt_input.update_with_descriptor_unchecked(&desc).unwrap();

            let mut psbt_output = psbt::Output::default();
            psbt_output.update_with_descriptor_unchecked(&desc).unwrap();

            assert_eq!(psbt_input.bip32_derivation, expected_bip32);
            assert_eq!(psbt_input.witness_script, None);
            assert_eq!(psbt_input.redeem_script, Some(derived.explicit_script().unwrap()));

            assert_eq!(psbt_output.bip32_derivation, psbt_input.bip32_derivation);
            assert_eq!(psbt_output.witness_script, psbt_input.witness_script);
            assert_eq!(psbt_output.redeem_script, psbt_input.redeem_script);
        }
    }

    #[test]
    fn test_update_input_checks() {
        let desc = "eltr([73c5da0a/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/0)";
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(desc).unwrap();

        // Elements Taproot outputs use Elements-tagged hashes, so the BIP 86 output
        // script does not apply; take the one the descriptor commits to.
        let mut non_witness_utxo = elements::Transaction {
            version: 1,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![explicit_txout(desc.script_pubkey(), 1_000)],
        };

        let mut psbt = Psbt::new_v2();
        psbt.add_input(psbt::Input::from_prevout(elements::OutPoint::new(
            non_witness_utxo.txid(),
            0,
        )));
        assert_eq!(
            psbt.update_input_with_descriptor(0, &desc),
            Err(UtxoUpdateError::UtxoCheck),
            "neither *_utxo are not set"
        );
        psbt.inputs_mut()[0].witness_utxo = Some(non_witness_utxo.output[0].clone());
        assert_eq!(
            psbt.update_input_with_descriptor(0, &desc),
            Ok(()),
            "witness_utxo is set which is ok"
        );
        psbt.inputs_mut()[0].non_witness_utxo = Some(non_witness_utxo.clone());
        assert_eq!(
            psbt.update_input_with_descriptor(0, &desc),
            Ok(()),
            "matching non_witness_utxo"
        );
        non_witness_utxo.version = 0;
        psbt.inputs_mut()[0].non_witness_utxo = Some(non_witness_utxo);
        assert_eq!(
            psbt.update_input_with_descriptor(0, &desc),
            Err(UtxoUpdateError::UtxoCheck),
            "non_witness_utxo no longer matches"
        );
        psbt.inputs_mut()[0].non_witness_utxo = None;
        psbt.inputs_mut()[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = Script::default();
        assert_eq!(
            psbt.update_input_with_descriptor(0, &desc),
            Err(UtxoUpdateError::MismatchedScriptPubkey),
            "non_witness_utxo no longer matches"
        );
    }

    #[test]
    fn test_update_output_checks() {
        let desc = "eltr([73c5da0a/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/0)";
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(desc).unwrap();

        let mut psbt = Psbt::new_v2();
        psbt.add_output(psbt::Output::new_explicit(
            desc.script_pubkey(),
            1_000,
            elements::AssetId::LIQUID_BTC,
            None,
        ));
        assert_eq!(
            psbt.update_output_with_descriptor(1, &desc),
            Err(OutputUpdateError::IndexOutOfBounds(1, 1)),
            "output index doesn't exist"
        );
        assert_eq!(
            psbt.update_output_with_descriptor(0, &desc),
            Ok(()),
            "script_pubkey should match"
        );
        psbt.outputs_mut()[0].script_pubkey = Script::default();
        assert_eq!(
            psbt.update_output_with_descriptor(0, &desc),
            Err(OutputUpdateError::MismatchedScriptPubkey),
            "output script_pubkey no longer matches"
        );
    }
}
