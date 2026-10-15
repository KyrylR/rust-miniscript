// SPDX-License-Identifier: CC0-1.0

//! The BIP 174 finalizer and extractor flow over an Elements PSET.
//!
//! BIP 174's test vectors are Bitcoin PSBTs, which this Elements crate does not
//! handle. This runs the same flow as those vectors, a P2SH multisig input and a
//! P2SH-wrapped P2WSH multisig input that are finalized and then extracted, on a
//! PSET whose keys, signatures and transaction are built here.

use std::str::FromStr;

use elements_miniscript::bitcoin::secp256k1::{Secp256k1, SecretKey};
use elements_miniscript::bitcoin::PublicKey;
use elements_miniscript::elements::pset::{Input, Output, PartiallySignedTransaction as Psbt};
use elements_miniscript::elements::sighash::SighashCache;
use elements_miniscript::elements::{
    confidential, AssetId, BlockHash, EcdsaSighashType, OutPoint, Script, TxOut, Txid,
};
use elements_miniscript::psbt::{PsbtExt, PsbtInputExt};
use elements_miniscript::{elementssig_to_rawsig, DefiniteDescriptorKey, Descriptor};

#[test]
fn finalize_and_extract() {
    let secp = Secp256k1::new();
    // Taproot sighashes commit to the chain; these inputs only need a fixed value.
    let genesis_hash = BlockHash::from_byte_array([0x42; 32]);
    let keys: Vec<(SecretKey, PublicKey)> = (1..=4u8)
        .map(|i| {
            let sk = SecretKey::from_slice(&[i; 32]).unwrap();
            (sk, PublicKey::new(sk.public_key(&secp)))
        })
        .collect();
    let descs: Vec<Descriptor<DefiniteDescriptorKey>> = [
        format!("elsh(multi(2,{},{}))", keys[0].1, keys[1].1),
        format!("elsh(wsh(multi(2,{},{})))", keys[2].1, keys[3].1),
    ]
    .iter()
    .map(|d| Descriptor::from_str(d).unwrap())
    .collect();

    let mut psbt = Psbt::new_v2();
    for (vout, desc) in descs.iter().enumerate() {
        let prevout = OutPoint::new(Txid::from_byte_array([1; 32]), vout as u32);
        let mut input = Input::from_prevout(prevout);
        input.witness_utxo = Some(TxOut {
            asset: confidential::Asset::Explicit(AssetId::LIQUID_BTC),
            value: confidential::Value::Explicit(100_000),
            script_pubkey: desc.script_pubkey(),
            ..Default::default()
        });
        input.update_with_descriptor_unchecked(desc).unwrap();
        psbt.add_input(input);
    }
    let asset = AssetId::LIQUID_BTC;
    psbt.add_output(Output::new_explicit(descs[0].script_pubkey(), 190_000, asset, None));
    // An empty script pubkey marks the Elements fee output.
    psbt.add_output(Output::new_explicit(Script::new(), 10_000, asset, None));

    // Each input is signed by both of its keys.
    let unsigned_tx = psbt.extract_tx().unwrap();
    let mut cache = SighashCache::new(&unsigned_tx);
    for (idx, signers) in [&keys[0..2], &keys[2..4]].iter().enumerate() {
        let msg = psbt
            .sighash_msg(idx, &mut cache, None, genesis_hash)
            .unwrap()
            .to_secp_msg();
        for (sk, pk) in signers.iter() {
            let sig = (secp.sign_ecdsa(&msg, sk), EcdsaSighashType::All);
            psbt.inputs_mut()[idx]
                .partial_sigs
                .insert(*pk, elementssig_to_rawsig(&sig));
        }
    }

    // Finalizing runs the interpreter over every input.
    psbt.finalize_mut(&secp, genesis_hash).unwrap();
    for input in psbt.inputs() {
        assert!(input.partial_sigs.is_empty());
        assert!(input.final_script_sig.is_some());
    }
    assert!(psbt.inputs()[0].final_script_witness.is_none());
    // Nested P2WSH multisig: the CHECKMULTISIG dummy, two signatures and the witness script.
    assert_eq!(
        psbt.inputs()[1]
            .final_script_witness
            .as_ref()
            .unwrap()
            .len(),
        4
    );

    // Extracting checks the finalized inputs with the interpreter again.
    let tx = psbt.extract(&secp, genesis_hash).unwrap();
    assert_eq!(tx.output, unsigned_tx.output);
    assert_eq!(tx.input.len(), 2);
    for (txin, input) in tx.input.iter().zip(psbt.inputs()) {
        assert_eq!(Some(&txin.script_sig), input.final_script_sig.as_ref());
        assert_eq!(txin.previous_output, input.previous_outpoint());
    }
}
