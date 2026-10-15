// SPDX-License-Identifier: CC0-1.0

use std::collections::BTreeMap;
use std::str::FromStr;

use elements_miniscript::bitcoin::key::XOnlyPublicKey;
use elements_miniscript::bitcoin::{bip32, Network, WitnessVersion};
use elements_miniscript::descriptor::csfs_cov::LegacyCovSatisfier;
use elements_miniscript::descriptor::{Bare, DescriptorType};
use elements_miniscript::elements::secp256k1_zkp::{Message, Secp256k1, SecretKey};
use elements_miniscript::elements::{
    confidential, EcdsaSighashType, LockTime, Transaction, TxIn, TxOut,
};
use elements_miniscript::expression::{FromTree as _, Tree};
use elements_miniscript::extensions::{CovExtArgs, ExtParamTranslator};
use elements_miniscript::{
    bitcoin, translate_hash_fail, CovenantExt, Descriptor, DescriptorPublicKey, ElementsSig, Error,
    NoExt, Translator, TxEnv,
};

type StdDescriptor = Descriptor<bitcoin::PublicKey>;

const K0: &str = "02e20e746af365e86647826397ba1c0e0d5cb685752976fe2f326ab76bdc4d6ee9";
const K1: &str = "02937402303919b3a2ee5edd5009f4236f069bf75667b8e6ecf8e5464e20116a0e";
const K2: &str = "02eb64639a17f7334bb5a1a3aad857d6fec65faef439db3de72f85c88bc2906ad3";
const X: &str = "e20e746af365e86647826397ba1c0e0d5cb685752976fe2f326ab76bdc4d6ee9";
const MSG: &str = "0101010101010101010101010101010101010101010101010101010101010101";

#[test]
fn covenant_leaves_parse_alongside_ordinary_leaves() {
    let s = format!("eltr({K0},{{pk({K1}),and_v(v:pk({K2}),curr_idx_eq(3))}})");
    let desc = StdDescriptor::from_str(&s).unwrap();
    assert_eq!(desc.desc_type(), DescriptorType::Tr);
    assert_eq!(desc.tap_tree_iter().count(), 2);
    assert_eq!(StdDescriptor::from_str(&desc.to_string()).unwrap(), desc);
    desc.address(&elements_miniscript::elements::AddressParams::ELEMENTS)
        .unwrap();

    assert!(Descriptor::<bitcoin::PublicKey, NoExt>::from_str(&s).is_err());
}

#[cfg(not(feature = "simplicity"))]
#[test]
fn simplicity_leaves_need_their_feature() {
    let cmr = "0526eb603a8936dba018b14794dee96a87a6fd76987dd867c3e5a1773932fdfe";
    assert!(StdDescriptor::from_str(&format!("eltr({K0},sim{{asm({cmr})}})")).is_err());
}

struct Keys;

impl Translator<String> for Keys {
    type TargetPk = bitcoin::PublicKey;
    type Error = ();

    fn pk(&mut self, pk: &String) -> Result<bitcoin::PublicKey, ()> {
        let key = match pk.as_str() {
            "A" => K0,
            "B" => K1,
            "C" => K2,
            _ => return Err(()),
        };
        bitcoin::PublicKey::from_str(key).map_err(|_| ())
    }

    translate_hash_fail!(String, bitcoin::PublicKey, ());
}

struct Args;

impl ExtParamTranslator<String> for Args {
    type TargetArg = CovExtArgs;
    type Error = ();

    fn ext(&mut self, arg: &String) -> Result<CovExtArgs, ()> {
        match arg.as_str() {
            "X" => Ok(CovExtArgs::csfs_key(XOnlyPublicKey::from_str(X).unwrap())),
            "M" => Ok(CovExtArgs::csfs_msg(Message::from_digest([1; 32]))),
            _ => Err(()),
        }
    }
}

#[test]
fn abstract_descriptor_translates_keys_and_arguments() {
    let abstract_desc = Descriptor::<String, CovenantExt<String>>::from_str(
        "eltr(A,{pk(B),and_v(v:csfs(X,M),pk(C))})",
    )
    .unwrap();
    let keys = abstract_desc.translate_pk(&mut Keys).unwrap();
    let desc = keys.translate_ext(&mut Args).unwrap();

    let s = format!("eltr({K0},{{pk({K1}),and_v(v:csfs({X},{MSG}),pk({K2}))}})");
    assert_eq!(desc, StdDescriptor::from_str(&s).unwrap());
}

fn bare_from_tree(s: &str) -> Result<Bare<bitcoin::PublicKey>, Error> {
    let tree = Tree::from_str(s).unwrap();
    Bare::from_tree(tree.root())
}

#[test]
fn bare_descriptors_parse_from_their_tree() {
    for s in [
        format!("elpk({K1})"),
        format!("elmulti(1,{K1},{K2})"),
        format!("elc:pk_k({K1})"),
    ] {
        let bare = bare_from_tree(&s).unwrap();
        assert_eq!(Bare::<bitcoin::PublicKey>::from_str(&s).unwrap(), bare);

        let desc = StdDescriptor::from_str(&s).unwrap();
        assert_eq!(desc, Descriptor::Bare(bare));
        // The checksum is verified with the rest of the string, once.
        assert_eq!(StdDescriptor::from_str(&desc.to_string()).unwrap(), desc);
    }

    let err = bare_from_tree(&format!("pk({K1})")).unwrap_err();
    assert!(err
        .to_string()
        .contains("missing Elements descriptor prefix"));
    assert!(StdDescriptor::from_str(&format!("elpk({K1})#aaaaaaaa")).is_err());
}

#[test]
fn bare_key_errors_do_not_expose_private_keys() {
    let secp = Secp256k1::new();
    let private = bip32::Xpriv::new_master(Network::Bitcoin, &[42; 32]).unwrap();
    for text in [private.to_string(), format!("{}/0/*", private)] {
        let err = Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &text).unwrap_err();
        assert!(!err.to_string().contains(&private.to_string()), "{}", err);
    }
}

fn key(i: u8) -> (bitcoin::PublicKey, SecretKey) {
    let mut sk = [0; 32];
    sk[0] = i;
    let sk = SecretKey::from_slice(&sk).unwrap();
    (bitcoin::PublicKey::new(sk.public_key(&Secp256k1::signing_only())), sk)
}

#[test]
fn legacy_covenant_delegates() {
    let ((cov_pk, cov_sk), (pk, _)) = (key(1), key(2));
    let desc = StdDescriptor::from_str(&format!("elcovwsh({},pk({}))", cov_pk, pk)).unwrap();
    let cov = match desc {
        Descriptor::LegacyCSFSCov(ref cov) => cov,
        _ => panic!("{} is not a legacy covenant", desc),
    };
    assert_eq!(desc.desc_type(), DescriptorType::Cov);
    assert_eq!(desc.desc_type().segwit_version(), Some(WitnessVersion::V0));
    assert_eq!(desc.iter_pk().collect::<Vec<_>>(), [cov_pk, pk]);
    assert_eq!(desc.explicit_script().unwrap(), cov.inner_script());
    assert_eq!(desc.script_pubkey(), cov.script_pubkey());
    assert_eq!(desc.max_weight_to_satisfy().unwrap(), cov.max_weight_to_satisfy().unwrap());
    assert_eq!(StdDescriptor::from_str(&desc.to_string()).unwrap(), desc);

    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut { value: confidential::Value::Explicit(1_000), ..Default::default() }],
    };
    let spent = [TxOut { value: confidential::Value::Explicit(2_000), ..Default::default() }];
    let env = TxEnv::new(&tx, &spent, 0).unwrap();
    let cov_satisfier = LegacyCovSatisfier::new(env.clone(), EcdsaSighashType::All).unwrap();
    let msg = Message::from_digest(cov_satisfier.sighash().to_byte_array());
    let sig = Secp256k1::signing_only().sign_ecdsa(&msg, &cov_sk);
    let sig: ElementsSig = (sig, EcdsaSighashType::All);
    let sigs = BTreeMap::from([(cov_pk, sig), (pk, sig)]);

    // Without the transaction, there is no witness and no plan; a plain `elwsh` plans.
    assert!(matches!(desc.get_satisfaction(&sigs), Err(Error::CouldNotSatisfy)));
    assert_eq!(desc.clone().into_plan(&sigs).unwrap_err(), desc);
    let wsh = StdDescriptor::from_str(&format!("elwsh(pk({}))", pk)).unwrap();
    assert!(wsh.into_plan(&sigs).is_ok());

    let covenant = elements_miniscript::descriptor::csfs_cov::CovenantSignature {
        key: cov_pk,
        signature: sig,
    };
    let witness = desc.get_satisfaction((env, &covenant, &sigs)).unwrap();
    assert_eq!(
        witness,
        cov.get_satisfaction(&cov_satisfier, (&covenant, &sigs))
            .unwrap()
    );
}
