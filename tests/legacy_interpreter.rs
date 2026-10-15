//! Interpreting `elcovwsh` spends
//!
//! The witness holds, from the bottom, the covenant signature in DER, the 11 Segwit v0 signature
//! hash preimage items from the sighash type to the version, the Miniscript satisfaction and the
//! witness script.

use std::collections::BTreeMap;
use std::slice;
use std::str::FromStr;

use elements_miniscript::bitcoin::hex::DisplayHex as _;
use elements_miniscript::descriptor::csfs_cov::{LegacyCSFSCov, LegacyCovSatisfier};
use elements_miniscript::elements::encode::serialize;
use elements_miniscript::elements::secp256k1_zkp::{Message, Secp256k1, SecretKey};
use elements_miniscript::elements::sighash::{Prevouts, SighashCache};
use elements_miniscript::elements::{
    confidential, AssetId, BlockHash, EcdsaSighashType, LockTime, OutPoint, Script, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use elements_miniscript::interpreter::{Error, KeySigPair, SatisfiedConstraint};
use elements_miniscript::{
    bitcoin, elementssig_to_rawsig, Descriptor, ElementsSig, Interpreter, TxEnv,
};

type Cov = LegacyCSFSCov<bitcoin::PublicKey>;

const ALL: EcdsaSighashType = EcdsaSighashType::All;

// Key 1 is the covenant key.
fn key(i: u8) -> (bitcoin::PublicKey, SecretKey) {
    let mut sk = [0; 32];
    sk[0] = i;
    let sk = SecretKey::from_slice(&sk).unwrap();
    (bitcoin::PublicKey::new(sk.public_key(&Secp256k1::signing_only())), sk)
}

fn cov(ms: &str) -> Cov { Cov::from_str(&format!("elcovwsh({},{})", key(1).0, ms)).unwrap() }

fn asset() -> confidential::Asset {
    confidential::Asset::Explicit(AssetId::from_byte_array([1; 32]))
}

fn transaction() -> Transaction {
    let txid = "141f79c7c254ee3a9a9bc76b4f60564385b784bdfc1882b25154617801fe2237";
    let output = |value| TxOut {
        value: confidential::Value::Explicit(value),
        asset: asset(),
        ..Default::default()
    };
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_str(txid).unwrap(), vout: 1 },
            ..Default::default()
        }],
        output: vec![output(150_000), output(48_000)],
    }
}

fn spent(cov: &Cov) -> TxOut {
    TxOut {
        script_pubkey: cov.script_pubkey(),
        value: confidential::Value::Explicit(200_000),
        asset: asset(),
        ..Default::default()
    }
}

fn sign(sighash: [u8; 32], sk: &SecretKey) -> ElementsSig {
    (Secp256k1::signing_only().sign_ecdsa(&Message::from_digest(sighash), sk), ALL)
}

// The signature hash of Miniscript signatures, which sign the whole witness script.
fn ms_sighash(cov: &Cov, tx: &Transaction, spent: &TxOut) -> [u8; 32] {
    SighashCache::new(tx)
        .segwitv0_sighash(0, &cov.ecdsa_sighash_script_code(), spent.value, ALL)
        .to_byte_array()
}

fn witness(cov: &Cov, tx: &Transaction, spent: &TxOut) -> Vec<Vec<u8>> {
    let env = TxEnv::new(tx, slice::from_ref(spent), 0).unwrap();
    let data = LegacyCovSatisfier::new(env, ALL).unwrap();
    let covenant = elements_miniscript::descriptor::csfs_cov::CovenantSignature {
        key: key(1).0,
        signature: sign(data.sighash().to_byte_array(), &key(1).1),
    };
    let sigs = BTreeMap::from([
        (key(1).0, sign(ms_sighash(cov, tx, spent), &key(1).1)),
        (key(2).0, sign(ms_sighash(cov, tx, spent), &key(2).1)),
    ]);
    cov.get_satisfaction(&data, (&covenant, &sigs)).unwrap().0
}

fn genesis_hash() -> BlockHash {
    BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap()
}

fn interpreter<'txin>(
    spk: &Script,
    script_sig: &'txin Script,
    witness: &'txin Witness,
    tx: &Transaction,
) -> Result<Interpreter<'txin>, Error> {
    Interpreter::from_txdata(spk, script_sig, witness, tx.input[0].sequence, tx.lock_time)
}

fn interpret(
    spk: &Script,
    witness: &[Vec<u8>],
    tx: &Transaction,
    spent: &TxOut,
) -> Result<Vec<SatisfiedConstraint>, Error> {
    let (script_sig, witness) = (Script::new(), Witness::from_slice(witness));
    let interpreter = interpreter(spk, &script_sig, &witness, tx)?;
    let secp = Secp256k1::verification_only();
    let prevouts = [spent.clone()];
    let prevouts = Prevouts::All(&prevouts);
    interpreter
        .iter(&secp, tx, 0, &prevouts, genesis_hash())
        .collect()
}

fn is_covenant_sig(constraint: Option<&SatisfiedConstraint>) -> bool {
    match constraint {
        Some(SatisfiedConstraint::PublicKey { key_sig }) => {
            key_sig.as_ecdsa().map(|(pk, _)| pk) == Some(key(1).0)
        }
        _ => false,
    }
}

#[test]
fn spends() {
    let tx = transaction();
    let b = key(2).0;
    let pref = serialize(&tx.output[0]).as_hex().to_string();
    for ms in [
        "1".to_owned(),
        format!("pk({})", b),
        format!("and_v(v:pk({}),ver_eq(2))", b),
        format!("and_v(v:pk({}),outputs_pref({}))", b, pref),
    ] {
        let cov = cov(&ms);
        let spent = spent(&cov);
        let witness = witness(&cov, &tx, &spent);
        let constraints = interpret(&cov.script_pubkey(), &witness, &tx, &spent).unwrap();
        assert!(is_covenant_sig(constraints.last()), "{}", ms);

        let (script_sig, witness) = (Script::new(), Witness::from_slice(&witness));
        let interpreter = interpreter(&cov.script_pubkey(), &script_sig, &witness, &tx).unwrap();
        assert!(interpreter.is_segwit_v0());
        assert_eq!(interpreter.inferred_descriptor().unwrap(), Descriptor::from(cov));
    }
}

#[test]
fn wrong_witness_script() {
    let tx = transaction();
    let (cov_b, cov_c) = (cov(&format!("pk({})", key(2).0)), cov(&format!("pk({})", key(3).0)));
    let witness = witness(&cov_b, &tx, &spent(&cov_b));
    assert!(matches!(
        interpret(&cov_c.script_pubkey(), &witness, &tx, &spent(&cov_c)),
        Err(Error::IncorrectWScriptHash)
    ));
}

#[test]
fn reused_covenant_key() {
    let tx = transaction();
    let k = key(1).0;
    let cov = cov(&format!("pk({})", k));
    let (spk, spent) = (cov.script_pubkey(), spent(&cov));
    let mut witness = witness(&cov, &tx, &spent);
    let constraints = interpret(&spk, &witness, &tx, &spent).unwrap();
    assert_eq!(constraints.len(), 2);
    assert!(is_covenant_sig(constraints.last()));

    let ms_sig = witness.len() - 2;
    let mut covenant_sig = witness[0].clone();
    covenant_sig.push(ALL as u8);
    assert_ne!(witness[ms_sig], covenant_sig);
    witness[ms_sig] = covenant_sig;
    assert!(matches!(
        interpret(&spk, &witness, &tx, &spent),
        Err(Error::InvalidEcdsaSignature(pk)) if pk == k
    ));
}

#[test]
fn pset_keeps_covenant_signature_out_of_the_inner_script() {
    use elements_miniscript::psbt::PsbtExt;
    let tx = transaction();
    let k = key(1).0;
    for (ms, succeeds) in [
        (format!("pk({})", k), false),
        (format!("or_i(pk({}),pk({}))", k, key(2).0), true),
    ] {
        let cov = cov(&ms);
        let spent = spent(&cov);
        let data =
            LegacyCovSatisfier::new(TxEnv::new(&tx, slice::from_ref(&spent), 0).unwrap(), ALL)
                .unwrap();
        let mut pset =
            elements_miniscript::elements::pset::PartiallySignedTransaction::from_tx(tx.clone());
        let input = &mut pset.inputs_mut()[0];
        input.witness_utxo = Some(spent.clone());
        input.witness_script = Some(cov.inner_script());
        input
            .partial_sigs
            .insert(k, elementssig_to_rawsig(&sign(data.sighash().to_byte_array(), &key(1).1)));
        input.partial_sigs.insert(
            key(2).0,
            elementssig_to_rawsig(&sign(ms_sighash(&cov, &tx, &spent), &key(2).1)),
        );
        let before = pset.clone();
        let result = pset.finalize_mut(&Secp256k1::verification_only(), genesis_hash());
        if succeeds {
            result.unwrap();
            pset.extract(&Secp256k1::verification_only(), genesis_hash())
                .unwrap();
        } else {
            assert!(result.is_err());
            assert_eq!(pset, before);
        }
    }
}

// The covenant signature and the Miniscript signatures sign different scriptCodes, so one
// function cannot check both.
#[test]
fn custom_verification() {
    let tx = transaction();
    let cov = cov(&format!("pk({})", key(2).0));
    let spent = spent(&cov);
    let witness = Witness::from_slice(&witness(&cov, &tx, &spent));
    let script_sig = Script::new();
    let interpreter = interpreter(&cov.script_pubkey(), &script_sig, &witness, &tx).unwrap();
    let secp = Secp256k1::verification_only();
    let env = TxEnv::new(&tx, slice::from_ref(&spent), 0).unwrap();
    let covenant_sighash = LegacyCovSatisfier::new(env, ALL)
        .unwrap()
        .sighash()
        .to_byte_array();
    let prevouts = [spent.clone()];
    let prevouts = Prevouts::All(&prevouts);
    let whole_script =
        |sig: &KeySigPair| interpreter.verify_sig(&secp, &tx, 0, &prevouts, genesis_hash(), sig);
    let after_codeseparator = |sig: &KeySigPair| {
        let msg = Message::from_digest(covenant_sighash);
        sig.as_ecdsa()
            .is_some_and(|(pk, (sig, _))| secp.verify_ecdsa(&msg, &sig, &pk.inner).is_ok())
    };

    let mut iter = interpreter.iter_custom(Box::new(whole_script));
    assert!(matches!(iter.next(), Some(Err(Error::MissingCovenantVerifier))));

    let constraints = interpreter
        .iter_custom_with_covenant(Box::new(whole_script), Box::new(after_codeseparator))
        .collect::<Result<Vec<_>, _>>();
    assert!(is_covenant_sig(constraints.unwrap().last()));

    let constraints = interpreter
        .iter_custom_with_covenant(Box::new(after_codeseparator), Box::new(after_codeseparator))
        .collect::<Result<Vec<_>, _>>();
    assert!(matches!(constraints, Err(Error::InvalidEcdsaSignature(pk)) if pk == key(2).0));
    let constraints = interpreter
        .iter_custom_with_covenant(Box::new(whole_script), Box::new(whole_script))
        .collect::<Result<Vec<_>, _>>();
    assert!(matches!(constraints, Err(Error::InvalidEcdsaSignature(pk)) if pk == key(1).0));
}

// `ver_eq` reads the version item, which only the covenant check authenticates.
#[test]
fn forged_preimage_item() {
    let tx = transaction();
    let (honest, forged) = (cov("ver_eq(2)"), cov("ver_eq(3)"));
    let (spk, spent) = (forged.script_pubkey(), spent(&forged));
    let mut witness = witness(&honest, &tx, &spent);
    *witness.last_mut().unwrap() = forged.inner_script().into_bytes();
    assert!(matches!(
        interpret(&spk, &witness, &tx, &spent),
        Err(Error::ScriptSatisfactionError)
    ));

    witness[11] = 3u32.to_le_bytes().to_vec();
    assert!(matches!(
        interpret(&spk, &witness, &tx, &spent),
        Err(Error::InvalidCovenantPreimage(pk)) if pk == key(1).0
    ));
    let (script_sig, witness) = (Script::new(), Witness::from_slice(&witness));
    let interpreter = interpreter(&spk, &script_sig, &witness, &tx).unwrap();
    assert!(matches!(
        interpreter
            .iter_assume_sigs()
            .collect::<Result<Vec<_>, _>>(),
        Err(Error::InvalidCovenantPreimage(_))
    ));
}

// The items are the signature hash preimage of another transaction.
#[test]
fn other_transaction() {
    let tx = transaction();
    let cov = cov("1");
    let spent = spent(&cov);
    let witness = witness(&cov, &tx, &spent);
    let mut other = tx.clone();
    other.lock_time = LockTime::from_consensus(1);
    assert!(matches!(
        interpret(&cov.script_pubkey(), &witness, &other, &spent),
        Err(Error::InvalidEcdsaSignature(pk)) if pk == key(1).0
    ));

    let (script_sig, witness) = (Script::new(), Witness::from_slice(&witness));
    let interpreter = interpreter(&cov.script_pubkey(), &script_sig, &witness, &other).unwrap();
    let constraints = interpreter
        .iter_assume_sigs()
        .collect::<Result<Vec<_>, _>>();
    assert!(is_covenant_sig(constraints.unwrap().last()));
}

#[test]
fn malformed_items() {
    let tx = transaction();
    let cov = cov("1");
    let (spk, spent) = (cov.script_pubkey(), spent(&cov));
    let witness = witness(&cov, &tx, &spent);
    interpret(&spk, &witness, &tx, &spent).unwrap();

    let mut malformed = vec![];
    // hashOutputs and the locktime with a byte moved across, which keeps the signed preimage
    let mut shifted = witness.clone();
    let byte = shifted[3].pop().unwrap();
    shifted[2].insert(0, byte);
    malformed.push(shifted);
    // an explicit amount without its prefix
    let mut amount = witness.clone();
    amount[5][0] = 8;
    malformed.push(amount);
    let mut no_hash_type = witness.clone();
    no_hash_type.remove(1);
    malformed.push(no_hash_type);
    let mut extra = witness.clone();
    extra.insert(1, vec![2]);
    malformed.push(extra);
    for witness in malformed {
        assert!(matches!(
            interpret(&spk, &witness, &tx, &spent),
            Err(Error::IncorrectCovenantWitness)
        ));
    }

    let mut forged = vec![];
    // the sighash type with the same first byte, which the transaction signature takes
    let mut hash_type = witness.clone();
    hash_type[1][3] = 1;
    forged.push(hash_type);
    let mut hash_prevouts = witness.clone();
    hash_prevouts[10][0] ^= 1;
    forged.push(hash_prevouts);
    for witness in forged {
        assert!(matches!(
            interpret(&spk, &witness, &tx, &spent),
            Err(Error::InvalidCovenantPreimage(_))
        ));
    }
}
