//! Legacy covenant spends accepted by Elements consensus and policy.

use std::collections::BTreeMap;
use std::str::FromStr;

use elements_miniscript::bitcoin::hex::DisplayHex;
use elements_miniscript::bitcoin::{secp256k1, PublicKey};
use elements_miniscript::descriptor::csfs_cov::{LegacyCSFSCov, LegacyCovSatisfier};
use elements_miniscript::elements::pset::PartiallySignedTransaction;
use elements_miniscript::elements::sighash::SighashCache;
use elements_miniscript::elements::{
    confidential, encode, AssetId, EcdsaSighashType, LockTime, OutPoint, Sequence, Transaction,
    TxIn, TxOut,
};
use elements_miniscript::psbt::{PsbtExt, PsbtInputExt};
use elements_miniscript::{DefiniteDescriptorKey, Descriptor, TxEnv};

mod setup;
use setup::Call;

#[test]
fn legacy_covenant_spends() {
    let (node, genesis_hash) = setup::setup();
    let secp = secp256k1::Secp256k1::new();
    let covenant_sk = secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
    let spend_sk = secp256k1::SecretKey::from_slice(&[2; 32]).unwrap();
    let covenant_pk = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &covenant_sk));
    let spend_pk = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &spend_sk));
    let info = node.call("getsidechaininfo", &[]);
    let asset = AssetId::from_str(info["pegged_asset"].as_str().unwrap()).unwrap();
    let prefix = encode::serialize(&confidential::Asset::Explicit(asset)).to_lower_hex_string();
    let scripts = [
        "1".to_owned(),
        "ver_eq(2)".to_owned(),
        format!("and_v(v:pk({}),and_v(v:ver_eq(2),outputs_pref({})))", spend_pk, prefix),
        format!("pk({})", covenant_pk),
    ];
    for (case, script) in scripts.iter().enumerate() {
        let cov =
            LegacyCSFSCov::<PublicKey>::from_str(&format!("elcovwsh({},{})", covenant_pk, script,))
                .unwrap();
        cov.sanity_check().unwrap();
        for hash_type in [
            EcdsaSighashType::All,
            EcdsaSighashType::None,
            EcdsaSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        ] {
            // outputs_pref needs a signature committing to every output.
            if case == 2
                && !matches!(
                    hash_type,
                    EcdsaSighashType::All | EcdsaSighashType::AllPlusAnyoneCanPay
                )
            {
                continue;
            }
            let funding_txid = node.send_to_address(
                &cov.address(None, &elements_miniscript::elements::AddressParams::ELEMENTS),
                "1",
            );
            node.generate(1);
            let funding = Call::get_transaction(&node, &funding_txid);
            let (vout, prevout) = funding
                .output
                .iter()
                .enumerate()
                .find(|(_, output)| {
                    output.script_pubkey == cov.script_pubkey()
                        && output.value == confidential::Value::Explicit(100_000_000)
                })
                .unwrap();
            let mut tx = Transaction {
                version: 2,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(funding_txid, vout as u32),
                    sequence: Sequence::MAX,
                    ..Default::default()
                }],
                output: vec![
                    TxOut {
                        asset: prevout.asset,
                        value: confidential::Value::Explicit(99_997_000),
                        script_pubkey: node.get_new_address().script_pubkey(),
                        ..Default::default()
                    },
                    TxOut::new_fee(3_000, asset),
                ],
            };
            let prevouts = [prevout.clone()];
            let env = TxEnv::new(&tx, &prevouts, 0).unwrap();
            let cov_sat = LegacyCovSatisfier::new(env, hash_type).unwrap();
            let covenant_msg = secp256k1::Message::from_digest(cov_sat.sighash().to_byte_array());
            let covenant_signature = (secp.sign_ecdsa(&covenant_msg, &covenant_sk), hash_type);
            let mut signatures = BTreeMap::from([(covenant_pk, covenant_signature)]);
            let spend_hash = SighashCache::new(&tx).segwitv0_sighash(
                0,
                &cov.ecdsa_sighash_script_code(),
                prevout.value,
                hash_type,
            );
            let spend_msg = secp256k1::Message::from_digest(spend_hash.to_byte_array());
            signatures.insert(spend_pk, (secp.sign_ecdsa(&spend_msg, &spend_sk), hash_type));
            let desc = Descriptor::<DefiniteDescriptorKey>::from_str(&cov.to_string()).unwrap();
            let mut pset = PartiallySignedTransaction::from_tx(tx.clone());
            pset.inputs_mut()[0].witness_utxo = Some(prevout.clone());
            pset.inputs_mut()[0]
                .update_with_descriptor_unchecked(&desc)
                .unwrap();
            pset.inputs_mut()[0].sighash_type = Some(hash_type.into());
            pset.inputs_mut()[0].partial_sigs.extend(
                signatures
                    .iter()
                    .map(|(pk, sig)| (*pk, elements_miniscript::elementssig_to_rawsig(sig))),
            );
            let finalized = if case == 3 {
                let before = pset.clone();
                assert!(pset.finalize_mut(&secp, genesis_hash).is_err());
                assert_eq!(pset, before);
                signatures
                    .insert(covenant_pk, (secp.sign_ecdsa(&spend_msg, &covenant_sk), hash_type));
                None
            } else {
                pset.finalize_mut(&secp, genesis_hash).unwrap();
                Some(pset.extract(&secp, genesis_hash).unwrap())
            };
            let (witness, script_sig) = cov
                .get_satisfaction(
                    &cov_sat,
                    (
                        elements_miniscript::descriptor::csfs_cov::CovenantSignature {
                            key: *cov.pk(),
                            signature: covenant_signature,
                        },
                        &signatures,
                    ),
                )
                .unwrap();
            tx.input[0].script_sig = script_sig;
            tx.input[0].witness.script_witness = witness.into();
            if let Some(finalized) = finalized {
                assert_eq!(finalized, tx);
            }

            let mut tampered = tx.clone();
            // Item 11 holds the version at the top of the authenticated preimage items.
            let mut tampered_witness = tampered.input[0].witness.script_witness.to_vec();
            tampered_witness[11][0] ^= 1;
            tampered.input[0].witness.script_witness = tampered_witness.into();
            assert!(!node.test_mempool_accept(&tampered), "{} {:?}", script, hash_type);
            assert!(node.test_mempool_accept(&tx), "{} {:?}", script, hash_type);
            let txid = node.send_raw_transaction(&tx);
            node.generate(1);
            assert_eq!(Call::get_transaction(&node, &txid), tx);
        }
    }
}
