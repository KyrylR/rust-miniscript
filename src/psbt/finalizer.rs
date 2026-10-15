// Written in 2020 by Sanket Kanjalkar <sanket1729@gmail.com>
// SPDX-License-Identifier: CC0-1.0

//! Partially-Signed Elements Transactions
//!
//! This module implements the Finalizer and Extractor roles defined in
//! BIP 174, PSBT, described at
//! `https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki`,
//! for the Elements PSET format.
//!

use core::convert::TryFrom;

use bitcoin::hashes::hash160;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::PublicKey;
use elements::secp256k1_zkp::{self as secp256k1, Secp256k1};
use elements::sighash::Prevouts;
use elements::taproot::LeafVersion;
use elements::{Script, TxOut, Witness};

use super::{partial_sigs, sanity_check, Error, InputError, Psbt, PsbtInputSatisfier};
use crate::extensions::{CovExtArgs, CovenantExt, TxEnv};
use crate::prelude::*;
use crate::util::witness_size;
use crate::{
    interpreter, BareCtx, Descriptor, Legacy, Miniscript, Satisfier, Segwitv0, SigType, Tap,
    ToPublicKey,
};

// Satisfy the taproot descriptor. It is not possible to infer the complete
// descriptor from psbt because the information about all the scripts might not
// be present. Also, currently the spec does not support hidden branches, so
// inferring a descriptor is not possible
fn construct_tap_witness(
    sat: &PsbtInputSatisfier,
    env: &TxEnv,
    allow_mall: bool,
) -> Result<Vec<Vec<u8>>, InputError> {
    // When miniscript tries to finalize the PSBT, it doesn't have the full descriptor (which contained a pkh() fragment)
    // and instead resorts to parsing the raw script sig, which is translated into a "expr_raw_pkh" internally.
    let mut map: BTreeMap<hash160::Hash, bitcoin::key::XOnlyPublicKey> = BTreeMap::new();
    sat.psbt.inputs().iter().for_each(|input| {
        // We need to satisfy or dissatisfy any given key. `tap_key_origin` is the only field of PSBT Input which consist of
        // all the keys added on a descriptor and thus we get keys from it.
        input.tap_key_origins.keys().for_each(|key| {
            map.insert(key.to_pubkeyhash(SigType::Schnorr), *key);
        })
    });
    // Try the key spend path first
    if let Some(sig) = sat.psbt_input().tap_internal_key.as_ref().and_then(|key| {
        <PsbtInputSatisfier as Satisfier<XOnlyPublicKey>>::lookup_tap_key_spend_sig(sat, key)
    }) {
        return Ok(vec![sig.to_vec()]);
    }
    // Next script spends
    let (mut min_wit, mut min_wit_len) = (None, None);
    if let Some(block_map) =
        <PsbtInputSatisfier as Satisfier<XOnlyPublicKey>>::lookup_tap_control_block_map(sat)
    {
        for (control_block, (script, ver)) in block_map {
            if *ver != LeafVersion::default() {
                // We don't know how to satisfy non default version scripts yet
                continue;
            }
            let ms =
                match Miniscript::<XOnlyPublicKey, Tap, CovenantExt<CovExtArgs>>::decode_consensus(
                    script,
                ) {
                    Ok(ms) => ms.substitute_raw_pkh(&map),
                    Err(..) => continue, // try another script
                };
            let mut wit = if allow_mall {
                match ms.satisfy_malleable((sat, env)) {
                    Ok(ms) => ms,
                    Err(..) => continue,
                }
            } else {
                match ms.satisfy((sat, env)) {
                    Ok(ms) => ms,
                    Err(..) => continue,
                }
            };
            wit.push(ms.encode().into_bytes());
            wit.push(control_block.serialize());
            let wit_len = Some(witness_size(&wit));
            if min_wit_len.is_some() && wit_len > min_wit_len {
                continue;
            } else {
                // store the minimum
                min_wit = Some(wit);
                min_wit_len = wit_len;
            }
        }
        min_wit.ok_or(InputError::CouldNotSatisfyTr)
    } else {
        // No control blocks found
        Err(InputError::CouldNotSatisfyTr)
    }
}

// Get the scriptpubkey for the psbt input
pub(super) fn get_scriptpubkey(psbt: &Psbt, index: usize) -> Result<Script, InputError> {
    get_utxo(psbt, index).map(|utxo| utxo.script_pubkey.clone())
}

// Get the spending utxo for this psbt input
pub(super) fn get_utxo(psbt: &Psbt, index: usize) -> Result<&TxOut, InputError> {
    let inp = &psbt.inputs()[index];
    let utxo = if let Some(ref witness_utxo) = inp.witness_utxo {
        witness_utxo
    } else if let Some(ref non_witness_utxo) = inp.non_witness_utxo {
        let vout = inp.previous_outpoint().vout;
        non_witness_utxo
            .output
            .get(vout as usize)
            .ok_or(InputError::MissingUtxo)?
    } else {
        return Err(InputError::MissingUtxo);
    };
    Ok(utxo)
}

/// Get the Prevouts for the psbt
pub(super) fn prevouts(psbt: &Psbt) -> Result<Vec<&TxOut>, super::Error> {
    let mut utxos = vec![];
    for i in 0..psbt.inputs().len() {
        let utxo_ref = get_utxo(psbt, i).map_err(|e| Error::InputError(e, i))?;
        utxos.push(utxo_ref);
    }
    Ok(utxos)
}

// Create a descriptor from unfinalized PSBT input.
// Panics on out of bound input index for psbt
// Also sanity checks that the witness script and
// redeem script are consistent with the script pubkey.
// Does *not* check signatures
// We parse the insane version while satisfying because
// we want to move the script is probably already created
// and we want to satisfy it in any way possible.
fn get_descriptor(psbt: &Psbt, index: usize) -> Result<Descriptor<PublicKey>, InputError> {
    let mut map: BTreeMap<hash160::Hash, PublicKey> = BTreeMap::new();
    let psbt_inputs = psbt.inputs();
    for psbt_input in psbt_inputs {
        // Use BIP32 Derviation to get set of all possible keys.
        let public_keys = psbt_input.bip32_derivation.keys();
        for key in public_keys {
            let bitcoin_key = *key;
            let hash = bitcoin_key.pubkey_hash().to_raw_hash();
            map.insert(hash, bitcoin_key);
        }
    }

    // Figure out Scriptpubkey
    let script_pubkey = get_scriptpubkey(psbt, index)?;
    let inp = &psbt.inputs()[index];
    // 1. `PK`: creates a `Pk` descriptor(does not check if partial sig is given)
    if script_pubkey.is_p2pk() {
        let script_pubkey_len = script_pubkey.len();
        let pk_bytes = &script_pubkey.to_bytes();
        match bitcoin::PublicKey::from_slice(&pk_bytes[1..script_pubkey_len - 1]) {
            Ok(pk) => Ok(Descriptor::new_pk(pk)),
            Err(e) => Err(InputError::from(e)),
        }
    } else if script_pubkey.is_p2pkh() {
        // 2. `Pkh`: creates a `PkH` descriptor if partial_sigs has the corresponding pk
        let (pk, _) = inp
            .partial_sigs
            .iter()
            .find(|&(pk, _sig)| script_pubkey.as_bytes()[3..23] == pk.pubkey_hash()[..])
            .ok_or(InputError::MissingPubkey)?;
        Descriptor::new_pkh(*pk).map_err(InputError::from)
    } else if script_pubkey.is_v0_p2wpkh() {
        // 3. `Wpkh`: creates a `wpkh` descriptor if the partial sig has corresponding pk.
        let (pk, _) = inp
            .partial_sigs
            .iter()
            .find(|&(pk, _)| {
                bitcoin::key::CompressedPublicKey::try_from(*pk)
                    .map(|compressed| {
                        compressed.pubkey_hash()[..] == script_pubkey.as_bytes()[2..22]
                    })
                    .unwrap_or(false)
            })
            .ok_or(InputError::MissingPubkey)?;
        Descriptor::new_wpkh(*pk).map_err(InputError::from)
    } else if script_pubkey.is_v0_p2wsh() {
        // 4. `Wsh`: creates a `Wsh` descriptor
        if inp.redeem_script.is_some() {
            return Err(InputError::NonEmptyRedeemScript);
        }
        if let Some(ref witness_script) = inp.witness_script {
            if witness_script.to_v0_p2wsh() != script_pubkey {
                return Err(InputError::InvalidWitnessScript {
                    witness_script: witness_script.clone(),
                    p2wsh_expected: script_pubkey.clone(),
                });
            }
            if let Ok(cov) =
                crate::descriptor::csfs_cov::LegacyCSFSCov::decode_consensus(witness_script)
            {
                return Ok(Descriptor::LegacyCSFSCov(cov));
            }
            let ms = Miniscript::<bitcoin::PublicKey, Segwitv0>::decode_consensus(witness_script)?;
            Ok(Descriptor::new_wsh(ms.substitute_raw_pkh(&map))?)
        } else {
            Err(InputError::MissingWitnessScript)
        }
    } else if script_pubkey.is_p2sh() {
        match inp.redeem_script {
            None => Err(InputError::MissingRedeemScript),
            Some(ref redeem_script) => {
                if redeem_script.to_p2sh() != script_pubkey {
                    return Err(InputError::InvalidRedeemScript {
                        redeem: redeem_script.clone(),
                        p2sh_expected: script_pubkey.clone(),
                    });
                }
                if redeem_script.is_v0_p2wsh() {
                    // 5. `ShWsh` case
                    if let Some(ref witness_script) = inp.witness_script {
                        if witness_script.to_v0_p2wsh() != *redeem_script {
                            return Err(InputError::InvalidWitnessScript {
                                witness_script: witness_script.clone(),
                                p2wsh_expected: redeem_script.clone(),
                            });
                        }
                        let ms = Miniscript::<bitcoin::PublicKey, Segwitv0>::decode_consensus(
                            witness_script,
                        )?;
                        Ok(Descriptor::new_sh_wsh(ms.substitute_raw_pkh(&map))?)
                    } else {
                        Err(InputError::MissingWitnessScript)
                    }
                } else if redeem_script.is_v0_p2wpkh() {
                    // 6. `ShWpkh` case
                    let (pk, _) = inp
                        .partial_sigs
                        .iter()
                        .find(|&(&pk, _sig)| {
                            bitcoin::key::CompressedPublicKey::try_from(pk)
                                .map(|compressed| {
                                    compressed.pubkey_hash()[..] == redeem_script.as_bytes()[2..22]
                                })
                                .unwrap_or(false)
                        })
                        .ok_or(InputError::MissingPubkey)?;
                    Ok(Descriptor::new_sh_wpkh(*pk)?)
                } else {
                    //7. regular p2sh
                    if inp.witness_script.is_some() {
                        return Err(InputError::NonEmptyWitnessScript);
                    }
                    if let Some(ref redeem_script) = inp.redeem_script {
                        let ms = Miniscript::<bitcoin::PublicKey, Legacy>::decode_consensus(
                            redeem_script,
                        )?;
                        Ok(Descriptor::new_sh(ms)?)
                    } else {
                        Err(InputError::MissingWitnessScript)
                    }
                }
            }
        }
    } else {
        // 8. Bare case
        if inp.witness_script.is_some() {
            return Err(InputError::NonEmptyWitnessScript);
        }
        if inp.redeem_script.is_some() {
            return Err(InputError::NonEmptyRedeemScript);
        }
        let ms = Miniscript::<bitcoin::PublicKey, BareCtx>::decode_consensus(&script_pubkey)?;
        Ok(Descriptor::new_bare(ms.substitute_raw_pkh(&map))?)
    }
}

/// Interprets all psbt inputs and checks whether the
/// script is correctly interpreted according to the context.
///
/// The psbt must have included final script sig and final witness.
/// In other words, this checks whether the finalized psbt interprets
/// correctly
pub fn interpreter_check<C: secp256k1::Verification>(
    psbt: &Psbt,
    secp: &Secp256k1<C>,
    genesis_hash: elements::BlockHash,
) -> Result<(), Error> {
    let tx = psbt.extract_tx()?;
    interpreter_check_tx(psbt, secp, genesis_hash, &tx)
}

pub(super) fn interpreter_check_tx<C: secp256k1::Verification>(
    psbt: &Psbt,
    secp: &Secp256k1<C>,
    genesis_hash: elements::BlockHash,
    tx: &elements::Transaction,
) -> Result<(), Error> {
    let utxos = prevouts(psbt)?;
    let utxos = &Prevouts::All(&utxos);
    let empty_script_sig = Script::new();
    let empty_witness = Witness::default();
    for (index, input) in psbt.inputs().iter().enumerate() {
        let script_sig = input.final_script_sig.as_ref().unwrap_or(&empty_script_sig);
        let witness = input
            .final_script_witness
            .as_ref()
            .unwrap_or(&empty_witness);

        interpreter_inp_check(psbt, secp, index, utxos, witness, script_sig, tx, genesis_hash)?;
    }
    Ok(())
}

// Run the miniscript interpreter on a single psbt input
#[allow(clippy::too_many_arguments)]
fn interpreter_inp_check<C: secp256k1::Verification, T: Borrow<TxOut>>(
    psbt: &Psbt,
    secp: &Secp256k1<C>,
    index: usize,
    utxos: &Prevouts<T>,
    witness: &Witness,
    script_sig: &Script,
    tx: &elements::Transaction,
    genesis_hash: elements::BlockHash,
) -> Result<(), Error> {
    let spk = get_scriptpubkey(psbt, index).map_err(|e| Error::InputError(e, index))?;

    // Now look at all the satisfied constraints. If everything is filled in
    // corrected, there should be no errors
    // Interpreter check
    {
        let cltv = tx.lock_time;
        let csv = tx.input[index].sequence;
        let interpreter =
            interpreter::Interpreter::from_txdata(&spk, script_sig, witness, csv, cltv)
                .map_err(|e| Error::InputError(InputError::Interpreter(e), index))?;
        let iter = interpreter.iter(secp, tx, index, utxos, genesis_hash);
        if let Some(error) = iter.filter_map(Result::err).next() {
            return Err(Error::InputError(InputError::Interpreter(error), index));
        };
    }
    Ok(())
}

/// Finalize the psbt.
///
/// This function takes in a mutable reference to psbt
/// and populates the final_witness and final_scriptsig
/// of the psbt assuming all of the inputs are miniscript as per BIP174.
/// If any of the inputs is not miniscript, this returns a parsing error
/// For satisfaction of individual inputs, use the satisfy API.
/// This function also performs a sanity interpreter check on the
/// finalized psbt which involves checking the signatures/ preimages/timelocks.
/// The functions fails it is not possible to satisfy any of the inputs non-malleably
/// See [finalize_mall] if you want to allow malleable satisfactions
#[deprecated(since = "7.0.0", note = "Please use PsbtExt::finalize instead")]
pub fn finalize<C: secp256k1::Verification>(
    psbt: &mut Psbt,
    secp: &Secp256k1<C>,
    genesis_hash: elements::BlockHash,
) -> Result<(), super::Error> {
    finalize_helper(psbt, secp, false, genesis_hash)
}

/// Same as [finalize], but allows for malleable satisfactions
pub fn finalize_mall<C: secp256k1::Verification>(
    psbt: &mut Psbt,
    secp: &Secp256k1<C>,
    genesis_hash: elements::BlockHash,
) -> Result<(), super::Error> {
    finalize_helper(psbt, secp, true, genesis_hash)
}

pub fn finalize_helper<C: secp256k1::Verification>(
    psbt: &mut Psbt,
    secp: &Secp256k1<C>,
    allow_mall: bool,
    genesis_hash: elements::BlockHash,
) -> Result<(), super::Error> {
    sanity_check(psbt)?;

    let mut tx = None;
    for index in 0..psbt.inputs().len() {
        finalize_input(psbt, index, secp, allow_mall, genesis_hash, &mut tx)?;
    }
    // Interpreter is already run inside finalize_input for each input
    Ok(())
}

// Helper function to obtain psbt final_witness/final_script_sig.
// Does not add fields to the psbt, only returns the values.
fn finalize_input_helper<C: secp256k1::Verification>(
    psbt: &Psbt,
    index: usize,
    secp: &Secp256k1<C>,
    allow_mall: bool,
    genesis_hash: elements::BlockHash,
    tx: &elements::Transaction,
) -> Result<(Witness, Script), super::Error> {
    let utxos = prevouts(psbt)?;
    let env = TxEnv::from_refs(tx, &utxos, index)
        .ok_or(Error::InputError(InputError::MissingUtxo, index))?;
    let (witness, script_sig) = {
        let spk = get_scriptpubkey(psbt, index).map_err(|e| Error::InputError(e, index))?;
        if spk.is_v1_p2tr() {
            let sat = PsbtInputSatisfier { psbt, index, legacy_covenant_key: None };
            // Deal with tr case separately, unfortunately we cannot infer the full descriptor for Tr
            let wit = construct_tap_witness(&sat, &env, allow_mall)
                .map_err(|e| Error::InputError(e, index))?;
            (wit, Script::new())
        } else {
            // Get a descriptor for this input.
            let desc = get_descriptor(psbt, index).map_err(|e| Error::InputError(e, index))?;
            let legacy_covenant_key = match &desc {
                Descriptor::LegacyCSFSCov(cov) => Some(*cov.pk()),
                _ => None,
            };
            let sat = PsbtInputSatisfier { psbt, index, legacy_covenant_key };

            //generate the satisfaction witness and scriptsig
            if !allow_mall {
                desc.get_satisfaction((sat, &env))
            } else {
                desc.get_satisfaction_mall((sat, &env))
            }
            .map_err(|e| Error::InputError(InputError::MiniscriptError(e), index))?
        }
    };

    let witness = Witness::from_slice(&witness);
    let utxos = &Prevouts::All(&utxos);
    interpreter_inp_check(psbt, secp, index, utxos, &witness, &script_sig, tx, genesis_hash)?;

    Ok((witness, script_sig))
}

pub(super) fn has_final_scripts(input: &elements::pset::Input) -> bool {
    input
        .final_script_sig
        .as_ref()
        .is_some_and(|script| !script.is_empty())
        || input
            .final_script_witness
            .as_ref()
            .is_some_and(|witness| !witness.is_empty())
}

pub(super) fn finalize_input<C: secp256k1::Verification>(
    psbt: &mut Psbt,
    index: usize,
    secp: &Secp256k1<C>,
    allow_mall: bool,
    genesis_hash: elements::BlockHash,
    tx: &mut Option<elements::Transaction>,
) -> Result<(), super::Error> {
    // Preserve previously finalized inputs
    if has_final_scripts(&psbt.inputs()[index]) {
        return Ok(());
    }
    // The satisfier would treat a partial signature that does not parse as missing.
    for sig in partial_sigs(&psbt.inputs()[index], index) {
        sig?;
    }

    // Finalization changes only scriptSigs and witnesses, which sighashes do not
    // commit to. Extract lazily so already-finalized inputs need no other data.
    let tx = match tx {
        Some(tx) => tx,
        None => tx.insert(psbt.extract_tx()?),
    };
    let (witness, script_sig) =
        finalize_input_helper(psbt, index, secp, allow_mall, genesis_hash, tx)?;

    // Now mutate the psbt input. Note that we cannot error after this point.
    // If the input is mutated, it means that the finalization succeeded.
    {
        // Clear the signing data as BIP 174 requires of the Finalizer. Unlike a
        // v0 PSBT input, a PSET input also holds its prevout, sequence, locktime,
        // issuance, pegin and blinding data, which the extractor still needs.
        let input = &mut psbt.inputs_mut()[index];
        input.partial_sigs.clear();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation.clear();
        input.ripemd160_preimages.clear();
        input.sha256_preimages.clear();
        input.hash160_preimages.clear();
        input.hash256_preimages.clear();
        input.tap_key_sig = None;
        input.tap_script_sigs.clear();
        input.tap_scripts.clear();
        input.tap_key_origins.clear();
        input.tap_internal_key = None;
        input.tap_merkle_root = None;
        input.final_script_sig = (!script_sig.is_empty()).then_some(script_sig);
        input.final_script_witness = (!witness.is_empty()).then_some(witness);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use elements::script::Builder;
    use elements::sighash::SighashCache;
    use elements::EcdsaSighashType;

    use super::*;
    use crate::psbt::tests::{genesis_hash, pset_spending, wpkh_key};
    use crate::psbt::{PsbtExt, PsbtInputExt, PsbtSighashMsg};
    use crate::{elementssig_to_rawsig, DefiniteDescriptorKey, Descriptor};

    #[test]
    fn tests_from_bip174() {
        // The Elements counterpart of the BIP 174 finalizer vector: a P2SH multisig
        // input and a P2SH-wrapped P2WSH multisig input.
        let secp = Secp256k1::new();
        let keys: Vec<_> = (1..=4).map(|sk| wpkh_key(&secp, sk)).collect();
        let descs = [
            format!("elsh(multi(2,{},{}))", keys[0].1, keys[1].1),
            format!("elsh(wsh(multi(2,{},{})))", keys[2].1, keys[3].1),
        ];
        let descs: Vec<Descriptor<DefiniteDescriptorKey>> = descs
            .iter()
            .map(|d| Descriptor::from_str(d).unwrap())
            .collect();
        let spks: Vec<Script> = descs.iter().map(|d| d.script_pubkey()).collect();
        let mut psbt = pset_spending(&spks);
        for (input, desc) in psbt.inputs_mut().iter_mut().zip(&descs) {
            input.update_with_descriptor_unchecked(desc).unwrap();
        }

        let unsigned_tx = psbt.extract_tx().unwrap();
        let mut cache = SighashCache::new(&unsigned_tx);
        let mut sigs = vec![];
        for (idx, signers) in [&keys[0..2], &keys[2..4]].iter().enumerate() {
            let msg = psbt
                .sighash_msg(idx, &mut cache, None, genesis_hash())
                .unwrap();
            assert_eq!(matches!(msg, PsbtSighashMsg::LegacySighash(_)), idx == 0);
            for (sk, pk) in signers.iter() {
                let sig = (secp.sign_ecdsa(&msg.to_secp_msg(), sk), EcdsaSighashType::All);
                let sig = elementssig_to_rawsig(&sig);
                psbt.inputs_mut()[idx].partial_sigs.insert(*pk, sig.clone());
                sigs.push(sig);
            }
        }
        let redeem_script = psbt.inputs()[0].redeem_script.clone().unwrap();
        let nested_redeem_script = psbt.inputs()[1].redeem_script.clone().unwrap();
        let witness_script = psbt.inputs()[1].witness_script.clone().unwrap();

        psbt.finalize_mut(&secp, genesis_hash()).unwrap();

        let expected_script_sig = Builder::new()
            .push_int(0)
            .push_slice(&sigs[0])
            .push_slice(&sigs[1])
            .push_slice(redeem_script.as_bytes())
            .into_script();
        assert_eq!(psbt.inputs()[0].final_script_sig, Some(expected_script_sig));
        assert_eq!(psbt.inputs()[0].final_script_witness, None);
        assert_eq!(
            psbt.inputs()[1].final_script_sig,
            Some(
                Builder::new()
                    .push_slice(nested_redeem_script.as_bytes())
                    .into_script()
            )
        );
        assert_eq!(
            psbt.inputs()[1].final_script_witness,
            Some(Witness::from_slice(&[
                vec![],
                sigs[2].clone(),
                sigs[3].clone(),
                witness_script.to_bytes()
            ]))
        );
        // The signing data is cleared, but the data the extractor needs is kept.
        for (input, original) in psbt.inputs().iter().zip(pset_spending(&spks).inputs()) {
            assert!(input.partial_sigs.is_empty());
            assert!(input.bip32_derivation.is_empty());
            assert_eq!(input.redeem_script, None);
            assert_eq!(input.witness_script, None);
            assert_eq!(input.witness_utxo, original.witness_utxo);
            assert_eq!(input.previous_outpoint(), original.previous_outpoint());
        }
        psbt.extract(&secp, genesis_hash()).unwrap();
    }

    #[test]
    fn finalize_skips_already_finalized_input() {
        let mut psbt = Psbt::new_v2();
        psbt.add_input(elements::pset::Input::default());
        psbt.inputs_mut()[0].final_script_witness = Some(Witness::from_slice(&[vec![1]]));

        let expected_input = psbt.inputs()[0].clone();
        let secp = Secp256k1::verification_only();

        psbt.finalize_mut(&secp, genesis_hash()).unwrap();

        assert_eq!(psbt.inputs()[0], expected_input);
    }
}
