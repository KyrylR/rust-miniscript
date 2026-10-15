// SPDX-License-Identifier: CC0-1.0

use std::str::FromStr;

use elements_miniscript::bitcoin::{secp256k1, PrivateKey};
use elements_miniscript::elements::encode::serialize_hex;
use elements_miniscript::elements::pset::{self, PartiallySignedTransaction as Psbt};
use elements_miniscript::elements::sighash::SighashCache;
use elements_miniscript::elements::{
    confidential, Address, AddressParams, AssetId, BlockHash, EcdsaSighashType, LockTime, OutPoint,
    Script, Sequence, Transaction, TxIn, TxOut, Txid,
};
use elements_miniscript::psbt::{PsbtExt, PsbtInputExt};
use elements_miniscript::{elementssig_to_rawsig, Descriptor};

fn main() {
    let secp256k1 = secp256k1::Secp256k1::new();

    let s = "elwsh(t:or_c(pk(027a3565454fe1b749bccaef22aff72843a9c3efefd7b16ac54537a0c23f0ec0de),v:thresh(1,pkh(032d672a1a91cc39d154d366cd231983661b0785c7f27bc338447565844f4a6813),a:pkh(03417129311ed34c242c012cd0a3e0b9bca0065f742d0dfb63c78083ea6a02d4d9),a:pkh(025a687659658baeabdfc415164528065be7bcaade19342241941e556557f01e28))))#tdp6ld3e";
    let bridge_descriptor = Descriptor::from_str(s).unwrap();
    //let bridge_descriptor = Descriptor::<bitcoin::PublicKey>::from_str(&s).expect("parse descriptor string");
    println!("Bridge pubkey script: {}", bridge_descriptor.script_pubkey());
    println!(
        "Bridge address: {}",
        bridge_descriptor.address(&AddressParams::ELEMENTS).unwrap()
    );
    println!(
        "Weight for witness satisfaction cost {}",
        bridge_descriptor.max_weight_to_satisfy().unwrap()
    );

    let master_private_key_str = "cQhdvB3McbBJdx78VSSumqoHQiSXs75qwLptqwxSQBNBMDxafvaw";
    let _master_private_key =
        PrivateKey::from_str(master_private_key_str).expect("Can't create private key");
    println!("Master public key: {}", _master_private_key.public_key(&secp256k1));

    let backup1_private_key_str = "cWA34TkfWyHa3d4Vb2jNQvsWJGAHdCTNH73Rht7kAz6vQJcassky";
    let backup1_private =
        PrivateKey::from_str(backup1_private_key_str).expect("Can't create private key");

    println!("Backup1 public key: {}", backup1_private.public_key(&secp256k1));

    let backup2_private_key_str = "cPJFWUKk8sdL7pcDKrmNiWUyqgovimmhaaZ8WwsByDaJ45qLREkh";
    let backup2_private =
        PrivateKey::from_str(backup2_private_key_str).expect("Can't create private key");

    println!("Backup2 public key: {}", backup2_private.public_key(&secp256k1));

    let backup3_private_key_str = "cT5cH9UVm81W5QAf5KABXb23RKNSMbMzMx85y6R2mF42L94YwKX6";
    let _backup3_private =
        PrivateKey::from_str(backup3_private_key_str).expect("Can't create private key");

    println!("Backup3 public key: {}", _backup3_private.public_key(&secp256k1));

    let spend_tx = Transaction {
        version: 2,
        lock_time: LockTime::from_height(5000).unwrap(),
        input: vec![],
        output: vec![],
    };

    // Spend one input and spend one output for simplicity.
    let mut psbt = Psbt::from_tx(spend_tx);

    let amount = 100000000;

    // In practice the deposit transaction comes from the chain; here it pays the
    // bridge from an arbitrary outpoint.
    let depo_tx = deposit_transaction(bridge_descriptor.script_pubkey(), amount);

    let receiver =
        Address::from_str("ert1qpq2cfgz5lktxzr5zqv7nrzz46hsvq3492ump9pz8rzcl8wqtwqcs2yqnuv")
            .unwrap();

    let (outpoint, witness_utxo) = get_vout(&depo_tx, &bridge_descriptor.script_pubkey());

    let mut input = pset::Input::from_prevout(outpoint);
    input.sequence = Some(Sequence::from_height(26));
    psbt.add_input(input);

    psbt.add_output(pset::Output::new_explicit(
        receiver.script_pubkey(),
        amount / 5 - 500,
        bitcoin_asset(),
        None,
    ));

    psbt.add_output(pset::Output::new_explicit(
        bridge_descriptor.script_pubkey(),
        amount * 4 / 5,
        bitcoin_asset(),
        None,
    ));

    // Elements transactions pay their fee in an explicit output with an empty script pubkey.
    psbt.add_output(pset::Output::new_explicit(Script::new(), 500, bitcoin_asset(), None));

    // Generating signatures & witness data

    psbt.inputs_mut()[0]
        .update_with_descriptor_unchecked(&bridge_descriptor)
        .unwrap();

    psbt.inputs_mut()[0].witness_utxo = Some(witness_utxo.clone());

    let unsigned_tx = psbt.extract_tx().expect("failed to extract unsigned tx");
    let mut sighash_cache = SighashCache::new(&unsigned_tx);

    // Only Taproot sighashes commit to the chain's genesis hash, so any value will do here.
    let genesis_hash = BlockHash::from_byte_array([0; 32]);

    let msg = psbt
        .sighash_msg(0, &mut sighash_cache, None, genesis_hash)
        .unwrap()
        .to_secp_msg();

    // Fixme: Take a parameter
    let hash_ty = EcdsaSighashType::All;

    let sk1 = backup1_private.inner;
    let sk2 = backup2_private.inner;

    // Finally construct the signature and add to psbt
    let sig1 = secp256k1.sign_ecdsa(&msg, &sk1);
    let pk1 = backup1_private.public_key(&secp256k1);
    assert!(secp256k1.verify_ecdsa(&msg, &sig1, &pk1.inner).is_ok());

    // Second key just in case
    let sig2 = secp256k1.sign_ecdsa(&msg, &sk2);
    let pk2 = backup2_private.public_key(&secp256k1);
    assert!(secp256k1.verify_ecdsa(&msg, &sig2, &pk2.inner).is_ok());

    psbt.inputs_mut()[0]
        .partial_sigs
        .insert(pk1, elementssig_to_rawsig(&(sig1, hash_ty)));

    println!("{:#?}", psbt);
    println!("{}", psbt);

    psbt.finalize_mut(&secp256k1, genesis_hash).unwrap();
    println!("{:#?}", psbt);

    let tx = psbt.extract_tx().expect("failed to extract tx");
    println!("{}", serialize_hex(&tx));
}

// Find the Outpoint by spk
fn get_vout(tx: &Transaction, spk: &Script) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == &txout.script_pubkey {
            return (OutPoint::new(tx.txid(), i as u32), txout);
        }
    }
    panic!("Only call get vout on functions which have the expected outpoint");
}

// An arbitrary asset standing in for the chain's policy asset.
fn bitcoin_asset() -> AssetId { AssetId::LIQUID_BTC }

// A transaction paying `amount` to `spk` from an arbitrary outpoint.
fn deposit_transaction(spk: Script, amount: u64) -> Transaction {
    let explicit_txout = |script_pubkey, value| TxOut {
        asset: confidential::Asset::Explicit(bitcoin_asset()),
        value: confidential::Value::Explicit(value),
        script_pubkey,
        ..Default::default()
    };
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0x3c; 32]), 0),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: Default::default(),
            witness: Default::default(),
        }],
        output: vec![
            explicit_txout(spk, amount),
            explicit_txout(Script::new(), 1_000),
        ],
    }
}
