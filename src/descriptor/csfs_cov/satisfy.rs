// SPDX-License-Identifier: CC0-1.0

//! The transaction data in an `elcovwsh` witness

use bitcoin::hashes::{sha256d, Hash, HashEngine};
use elements::encode::serialize;
use elements::{EcdsaSighashType, Sighash, TxIn};

use super::{script, Error};
use crate::extensions::TxEnv;
use crate::prelude::*;
use crate::{MiniscriptKey, Satisfier, ToPublicKey};

/// The items of the Elements Segwit v0 signature hash preimage that an `elcovwsh` witness
/// supplies for an input, and that the covenant key signs.
///
/// As a [`Satisfier`], it provides the transaction to `ver_eq` and `outputs_pref`.
#[derive(Clone, Debug)]
pub struct LegacyCovSatisfier<'tx, 'ptx> {
    env: TxEnv<'tx, 'ptx>,
    hash_type: EcdsaSighashType,
    items: Vec<Vec<u8>>,
}

impl<'tx, 'ptx> LegacyCovSatisfier<'tx, 'ptx> {
    /// Computes the items for the input of `env`, for a signature with `hash_type`.
    ///
    /// Fails if the input has an issuance or spends a null amount, which the covenant check
    /// rejects.
    pub fn new(env: TxEnv<'tx, 'ptx>, hash_type: EcdsaSighashType) -> Result<Self, Error> {
        let (tx, idx) = (env.tx(), env.idx());
        // `TxEnv` holds an input and a spent output at `idx`.
        let input = &tx.input[idx];
        let value = env.spent_utxo(idx).expect("checked by TxEnv").value;
        if input.has_issuance() {
            return Err(Error::IssuanceInput);
        }
        if value.is_null() {
            return Err(Error::NullAmount);
        }

        let hash_inputs =
            |item: fn(&TxIn) -> Vec<u8>| hash_items(tx.input.iter().map(item)).to_vec();
        let zero = vec![0; 32];
        let anyone_can_pay = matches!(
            hash_type,
            EcdsaSighashType::AllPlusAnyoneCanPay
                | EcdsaSighashType::NonePlusAnyoneCanPay
                | EcdsaSighashType::SinglePlusAnyoneCanPay
        );
        let (hash_prevouts, hash_issuances) = if anyone_can_pay {
            (zero.clone(), zero.clone())
        } else {
            let issuance = |input: &TxIn| {
                if input.has_issuance() {
                    serialize(&input.asset_issuance)
                } else {
                    vec![0]
                }
            };
            (hash_inputs(|input| serialize(&input.previous_output)), hash_inputs(issuance))
        };
        let hash_sequence = match hash_type {
            EcdsaSighashType::All => hash_inputs(|input| serialize(&input.sequence)),
            _ => zero.clone(),
        };
        let hash_outputs = match hash_type {
            EcdsaSighashType::All | EcdsaSighashType::AllPlusAnyoneCanPay => {
                hash_items(tx.output.iter().map(serialize)).to_vec()
            }
            EcdsaSighashType::Single | EcdsaSighashType::SinglePlusAnyoneCanPay => {
                tx.output.get(idx).map_or(zero, |output| {
                    sha256d::Hash::hash(&serialize(output))
                        .to_byte_array()
                        .to_vec()
                })
            }
            EcdsaSighashType::None | EcdsaSighashType::NonePlusAnyoneCanPay => zero,
        };
        let items = vec![
            serialize(&tx.version),
            hash_prevouts,
            hash_sequence,
            hash_issuances,
            serialize(&input.previous_output),
            serialize(&script::script_code()),
            serialize(&value),
            serialize(&input.sequence),
            hash_outputs,
            serialize(&tx.lock_time),
            serialize(&hash_type.as_u32()),
        ];
        Ok(Self { env, hash_type, items })
    }

    /// The signature hash that the covenant key signs.
    pub fn sighash(&self) -> Sighash { Sighash::from_byte_array(hash_items(&self.items)) }

    /// The sighash type of the covenant signature.
    pub fn hash_type(&self) -> EcdsaSighashType { self.hash_type }

    /// The preimage items, from the version to the sighash type.
    pub(super) fn items(&self) -> &[Vec<u8>] { &self.items }

    /// Whether hashOutputs commits to all outputs, which `outputs_pref` constrains.
    pub(super) fn commits_to_outputs(&self) -> bool {
        matches!(self.hash_type, EcdsaSighashType::All | EcdsaSighashType::AllPlusAnyoneCanPay)
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for LegacyCovSatisfier<'_, '_> {
    fn lookup_tx_env(&self) -> Option<&TxEnv<'_, '_>> { Some(&self.env) }
}

fn hash_items<T: AsRef<[u8]>>(items: impl IntoIterator<Item = T>) -> [u8; 32] {
    let mut engine = sha256d::Hash::engine();
    for item in items {
        engine.input(item.as_ref());
    }
    sha256d::Hash::from_engine(engine).to_byte_array()
}

/// A signature for the `elcovwsh` covenant suffix, separate from inner-script signatures.
///
/// Combine it with other satisfiers in a tuple. The signature signs
/// [`LegacyCovSatisfier::sighash`], while ordinary ECDSA signatures sign the full witness script.
#[derive(Clone, Copy, Debug)]
pub struct CovenantSignature<Pk> {
    /// The covenant key.
    pub key: Pk,
    /// The signature and its sighash type.
    pub signature: crate::ElementsSig,
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for CovenantSignature<Pk> {
    fn lookup_legacy_covenant_sig(&self, pk: &Pk) -> Option<crate::ElementsSig> {
        (*pk == self.key).then_some(self.signature)
    }
}
