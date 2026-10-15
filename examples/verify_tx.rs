// SPDX-License-Identifier: CC0-1.0

//! Example: Verifying a signed transaction.

use std::collections::HashMap;
use std::str::FromStr;

use elements_miniscript::bitcoin::secp256k1::{Message, Secp256k1, SecretKey, Signing};
use elements_miniscript::bitcoin::PublicKey;
use elements_miniscript::elements::sighash::{Prevouts, SighashCache};
use elements_miniscript::elements::{
    confidential, AssetId, BlockHash, EcdsaSighashType, LockTime, OutPoint, Script, Sequence,
    Transaction, TxIn, TxOut, Txid,
};
use elements_miniscript::interpreter::KeySigPair;
use elements_miniscript::{Descriptor, ElementsSig};

fn main() {
    //
    // Setup
    //

    let secp = Secp256k1::new();
    let (tx, spk_input_1) = signed_transaction(&secp);

    let interpreter = elements_miniscript::Interpreter::from_txdata(
        &spk_input_1,
        &tx.input[0].script_sig,
        &tx.input[0].witness.script_witness,
        Sequence::ZERO,
        LockTime::ZERO,
    )
    .unwrap();

    let desc_string = interpreter.inferred_descriptor_string();
    println!("Descriptor: {}", desc_string);

    // To do sanity checks on the transaction using the interpreter parse the
    // descriptor with `from_str`.
    let _ = elements_miniscript::Descriptor::<bitcoin::PublicKey>::from_str(&desc_string)
        .expect("sanity checks to pass");
    // Alternately, use `inferred_descriptor` which does sanity checks for us also.
    let _ = interpreter.inferred_descriptor().expect("same as from_str");

    // Example one
    //
    // Learn which keys were used, not bothering to verify the signatures
    // (trusting that if they're on the blockchain, standardness would've
    // required they be either valid or 0-length.

    println!("\n\nExample one:\n");

    for elem in interpreter.iter_assume_sigs() {
        // Don't bother checking signatures.
        if let elements_miniscript::interpreter::SatisfiedConstraint::PublicKey { key_sig } =
            elem.expect("no evaluation error")
        {
            let (key, sig) = key_sig
                .as_ecdsa()
                .expect("expected ecdsa sig, found schnorr sig");

            println!("Signed with:\n key: {}\n sig: {} {}", key, sig.0, sig.1);
        }
    }

    // Example two
    //
    // Verify the signatures to ensure that invalid signatures are not treated
    // as having participated in the script

    println!("\n\nExample two:\n");

    // We can set prevouts to be empty list because this is a legacy transaction
    // and this information is not required for sighash computation. Only Taproot
    // sighashes commit to the genesis hash, so any value will do here.
    let prevouts = Prevouts::All::<TxOut>(&[]);
    let genesis_hash = BlockHash::from_byte_array([0; 32]);

    let mut n_verified = 0;
    for elem in interpreter.iter(&secp, &tx, 0, &prevouts, genesis_hash) {
        if let elements_miniscript::interpreter::SatisfiedConstraint::PublicKey { key_sig } =
            elem.expect("no evaluation error")
        {
            let (key, sig) = key_sig.as_ecdsa().unwrap();
            println!("Signed with:\n key: {}\n sig: {} {}", key, sig.0, sig.1);
            n_verified += 1;
        }
    }
    assert_eq!(n_verified, 2);

    // Example three
    //
    // Same, but with the wrong signature hash, to demonstrate what happens
    // given an apparently invalid script.
    let message = Message::from_digest([0x01; 32]);

    let iter = interpreter.iter_custom(Box::new(|key_sig: &KeySigPair| {
        let (pk, ecdsa_sig) = key_sig.as_ecdsa().expect("Ecdsa Sig");
        ecdsa_sig.1 == EcdsaSighashType::All
            && secp.verify_ecdsa(&message, &ecdsa_sig.0, &pk.inner).is_ok()
    }));

    println!("\n\nExample three:\n");

    for elem in iter {
        let error = elem.expect_err("evaluation error");
        println!("Evaluation error: {}", error);
    }
}

/// Returns an Elements transaction whose first input spends a 2-of-2 multisig
/// P2SH output, signed with fixed keys, along with that output's script pubkey.
fn signed_transaction<C: Signing>(secp: &Secp256k1<C>) -> (Transaction, Script) {
    let sks: Vec<SecretKey> = (1..=2u8)
        .map(|i| SecretKey::from_slice(&[i; 32]).expect("secret key"))
        .collect();
    let pks: Vec<PublicKey> = sks
        .iter()
        .map(|sk| PublicKey::new(sk.public_key(secp)))
        .collect();
    let descriptor =
        Descriptor::<PublicKey>::from_str(&format!("elsh(multi(2,{},{}))", pks[0], pks[1]))
            .unwrap();
    let redeem_script = descriptor.explicit_script().unwrap();

    let asset = confidential::Asset::Explicit(AssetId::LIQUID_BTC);
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            asset_issuance: Default::default(),
            witness: Default::default(),
        }],
        output: vec![
            TxOut {
                asset,
                value: confidential::Value::Explicit(99_000),
                script_pubkey: descriptor.script_pubkey(),
                ..Default::default()
            },
            // An empty script pubkey marks the Elements fee output.
            TxOut {
                asset,
                value: confidential::Value::Explicit(1_000),
                script_pubkey: Script::new(),
                ..Default::default()
            },
        ],
    };

    let sighash = SighashCache::new(&tx).legacy_sighash(0, &redeem_script, EcdsaSighashType::All);
    let message = Message::from_digest(sighash.to_byte_array());
    let sigs: HashMap<PublicKey, ElementsSig> = sks
        .iter()
        .zip(&pks)
        .map(|(sk, pk)| (*pk, (secp.sign_ecdsa(&message, sk), EcdsaSighashType::All)))
        .collect();
    descriptor.satisfy(&mut tx.input[0], &sigs).unwrap();

    (tx, descriptor.script_pubkey())
}
