// SPDX-License-Identifier: CC0-1.0

#![cfg(feature = "simplicity")]

use std::collections::BTreeMap;
use std::str::FromStr;

use elements_miniscript::bitcoin::hex::FromHex;
use elements_miniscript::bitcoin::key::XOnlyPublicKey;
use elements_miniscript::descriptor::Tr;
use elements_miniscript::elements::pset::{self, PartiallySignedTransaction};
use elements_miniscript::elements::secp256k1_zkp::{schnorr, Secp256k1};
use elements_miniscript::elements::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use elements_miniscript::elements::{self, confidential, AddressParams, Script};
use elements_miniscript::policy::{LiftError, Liftable};
use elements_miniscript::psbt::{InputError, PsbtExt, PsbtInputExt, PsbtOutputExt};
use elements_miniscript::simplicity::SimplicityLeaf;
use elements_miniscript::{Descriptor, DescriptorPublicKey, Error, Miniscript, Tap};

const KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const XPUB: &str = "[78412e3a/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*";
const CMR: &str = "0526eb603a8936dba018b14794dee96a87a6fd76987dd867c3e5a1773932fdfe";

fn sim_version() -> LeafVersion { LeafVersion::from_u8(0xbe).unwrap() }

fn cmr_script() -> Script { Script::from(<[u8; 32]>::from_hex(CMR).unwrap().to_vec()) }

fn key() -> XOnlyPublicKey { XOnlyPublicKey::from_str(KEY).unwrap() }

#[test]
fn commitment_grammar() {
    let text = format!("sim{{asm({CMR})}}");
    let leaf = SimplicityLeaf::from_str(&text).unwrap();
    assert_eq!(leaf.to_string(), text);
    assert_eq!(leaf.cmr(), <[u8; 32]>::from_hex(CMR).unwrap());
    let upper = format!("sim{{asm({})}}", CMR.to_uppercase());
    assert_eq!(SimplicityLeaf::from_str(&upper).unwrap(), leaf);

    for bad in [
        "sim{pk(a)}".to_owned(),
        "sim{TRIVIAL}".to_owned(),
        "sim_v0_9_0{TRIVIAL}".to_owned(),
        "sim{asm(00)}".to_owned(),
        "sim{asm()}".to_owned(),
        "sim{asm(zz)}".to_owned(),
        "sim{asm(00),asm(00)}".to_owned(),
        format!("sim(asm({CMR}))"),
        format!("sim{{asm{{{CMR}}}}}"),
        format!("sim{{asm({CMR}){{x,y}}}}"),
        "sim{pk(a){pk(b),pk(c)}}".to_owned(),
    ] {
        assert!(SimplicityLeaf::from_str(&bad).is_err(), "{}", bad);
        assert!(Tr::<String>::from_str(&format!("eltr(internal,{})", bad)).is_err(), "{}", bad);
    }
}

#[test]
fn commitment_vectors() {
    let secp = Secp256k1::verification_only();
    let tr = Tr::<XOnlyPublicKey>::from_str(&format!("eltr({KEY},sim{{asm({CMR})}})")).unwrap();
    assert_eq!(Tr::from_str(&tr.to_string()).unwrap(), tr);

    let leaf = tr.leaves().next().unwrap();
    assert!(leaf.miniscript().is_none());
    assert_eq!(leaf.simplicity().unwrap().cmr(), <[u8; 32]>::from_hex(CMR).unwrap());
    assert_eq!(leaf.leaf_version(), sim_version());
    assert_eq!(leaf.compute_script(), cmr_script());

    let independent = TaprootBuilder::new()
        .add_leaf_with_ver(0, cmr_script(), sim_version())
        .unwrap()
        .finalize(&secp, key())
        .unwrap();
    let spend_info = tr.spend_info();
    assert_eq!(spend_info.merkle_root(), independent.merkle_root());
    assert_eq!(spend_info.output_key(), independent.output_key());
    let control = independent
        .control_block(&(cmr_script(), sim_version()))
        .unwrap();
    assert_eq!(spend_info.leaves().next().unwrap().control_block(), &control);
    assert_eq!(control.serialize(), [&[0xbe][..], &key().serialize()[..]].concat());
    assert_eq!(
        tr.address(None, &AddressParams::ELEMENTS).to_string(),
        "ert1psmpfd2fj6zwpw9ugf5f6al8wg7urum6vv3ednhwnskxf6mplz5nst39pkg"
    );
}

#[test]
#[allow(deprecated)]
fn bounds_and_policies_are_unavailable() {
    for tree in [
        format!("sim{{asm({CMR})}}"),
        format!("{{pk({KEY}),sim{{asm({CMR})}}}}"),
    ] {
        let tr = Tr::<XOnlyPublicKey>::from_str(&format!("eltr({KEY},{tree})")).unwrap();
        assert!(matches!(tr.max_weight_to_satisfy(), Err(Error::UnboundedSimplicityLeaf)));
        assert!(matches!(tr.max_satisfaction_weight(), Err(Error::UnboundedSimplicityLeaf)));
        assert!(matches!(tr.lift(), Err(Error::LiftError(LiftError::SimplicityLift))));
        assert!(matches!(tr.get_satisfaction(&()), Err(Error::CouldNotSatisfy)));
    }
}

#[test]
fn mixed_tree_spends_its_tapscript_leaf() {
    let secp = Secp256k1::verification_only();
    let script = Miniscript::<XOnlyPublicKey, Tap>::from_str(&format!("pk({KEY})"))
        .unwrap()
        .encode();
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::default());
    let sig = elements::SchnorrSig {
        sig: schnorr::Signature::from_slice(&[1; 64]).unwrap(),
        hash_ty: elements::SchnorrSighashType::Default,
    };
    let satisfier = BTreeMap::from([((key(), leaf_hash), sig)]);

    for tree in [
        format!("{{pk({KEY}),sim{{asm({CMR})}}}}"),
        format!("{{sim{{asm({CMR})}},pk({KEY})}}"),
    ] {
        let desc = Descriptor::<XOnlyPublicKey>::from_str(&format!("eltr({KEY},{tree})")).unwrap();
        let tr = match desc {
            Descriptor::Tr(ref tr) => tr,
            _ => panic!("{} is not a Taproot descriptor", desc),
        };

        let mut builder = TaprootBuilder::new();
        for leaf in tr.leaves() {
            let version = match leaf.miniscript() {
                Some(_) => LeafVersion::default(),
                None => sim_version(),
            };
            assert_eq!(leaf.leaf_version(), version);
            builder = builder
                .add_leaf_with_ver(usize::from(leaf.depth()), leaf.compute_script(), version)
                .unwrap();
        }
        let independent = builder.finalize(&secp, key()).unwrap();
        let spend_info = tr.spend_info();
        assert_eq!(spend_info.merkle_root(), independent.merkle_root());
        assert_eq!(spend_info.output_key(), independent.output_key());
        for leaf in spend_info.leaves() {
            let script_ver = (leaf.script().clone(), leaf.leaf_version());
            assert_eq!(Some(leaf.control_block()), independent.control_block(&script_ver).as_ref());
        }

        let control_block = independent
            .control_block(&(script.clone(), LeafVersion::default()))
            .unwrap();
        let witness = vec![sig.to_vec(), script.to_bytes(), control_block.serialize()];
        assert_eq!(desc.get_satisfaction(&satisfier).unwrap(), (witness.clone(), Script::new()));
        assert_eq!(desc.get_satisfaction_mall(&satisfier).unwrap().0, witness);
        let plan = desc.clone().into_plan(&satisfier).unwrap();
        assert_eq!(plan.satisfy(&satisfier).unwrap().0, witness);
        assert!(matches!(desc.get_satisfaction(()), Err(Error::CouldNotSatisfy)));
    }
}

#[test]
fn derivation_keeps_commitments() {
    let secp = Secp256k1::verification_only();
    let desc =
        Descriptor::<DescriptorPublicKey>::from_str(&format!("eltr({XPUB},sim{{asm({CMR})}})"))
            .unwrap();
    // Only the internal key: the commitment hides the keys of the program.
    assert_eq!(desc.iter_pk().count(), 1);

    let derived: Vec<_> = (0..2)
        .map(|i| desc.derive_at_index(i).unwrap().derived_descriptor(&secp))
        .collect();
    assert_ne!(derived[0].script_pubkey(), derived[1].script_pubkey());
    for desc in &derived {
        let leaf = desc.tap_tree_iter().next().unwrap();
        assert_eq!(leaf.compute_script(), cmr_script());
        assert_eq!(leaf.leaf_version(), sim_version());
    }
}

#[test]
fn pset_keeps_commitment_leaves() {
    let secp = Secp256k1::verification_only();
    let desc =
        Descriptor::<DescriptorPublicKey>::from_str(&format!("eltr({XPUB},sim{{asm({CMR})}})"))
            .unwrap()
            .derive_at_index(0)
            .unwrap();
    let derived = desc.derived_descriptor(&secp);
    let mut input = pset::Input::default();
    let mut output = pset::Output::default();
    input.update_with_descriptor_unchecked(&desc).unwrap();
    output.update_with_descriptor_unchecked(&desc).unwrap();

    let (control, (script, version)) = input.tap_scripts.iter().next().unwrap();
    assert_eq!(*script, cmr_script());
    assert_eq!(*version, sim_version());
    assert_eq!(control.leaf_version, sim_version());
    match derived {
        Descriptor::Tr(ref tr) => assert_eq!(input.tap_merkle_root, tr.spend_info().merkle_root()),
        _ => panic!("{} is not a Taproot descriptor", derived),
    }
    let tree = TaprootBuilder::new()
        .add_leaf_with_ver(0, cmr_script(), sim_version())
        .unwrap();
    assert_eq!(output.tap_tree, Some(pset::TapTree::from_inner(tree).unwrap()));
}

#[test]
fn finalizer_cannot_spend_commitment_leaves() {
    let secp = Secp256k1::verification_only();
    let desc =
        Descriptor::<DescriptorPublicKey>::from_str(&format!("eltr({KEY},sim{{asm({CMR})}})"))
            .unwrap()
            .into_definite()
            .unwrap();
    let tx = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn::default()],
        output: vec![],
    };
    let mut pset = PartiallySignedTransaction::from_tx(tx);
    pset.inputs_mut()[0].witness_utxo = Some(elements::TxOut {
        script_pubkey: desc.derived_descriptor(&secp).script_pubkey(),
        asset: confidential::Asset::Explicit(elements::AssetId::LIQUID_BTC),
        value: confidential::Value::Explicit(1000),
        ..elements::TxOut::default()
    });
    pset.inputs_mut()[0]
        .update_with_descriptor_unchecked(&desc)
        .unwrap();

    let before = pset.inputs()[0].final_script_witness.clone();
    let genesis_hash = elements::BlockHash::from_byte_array([0; 32]);
    assert!(matches!(
        pset.finalize_inp_mut(&secp, 0, genesis_hash),
        Err(elements_miniscript::psbt::Error::InputError(InputError::CouldNotSatisfyTr, 0))
    ));
    assert_eq!(pset.inputs()[0].final_script_witness, before);
}

#[test]
fn wrapped_commitment_descriptors() {
    use elements_miniscript::confidential;
    use elements_miniscript::descriptor::pegin::Pegin;

    let pk = format!("02{KEY}");
    for tree in [
        format!("sim{{asm({CMR})}}"),
        format!("{{pk({pk}),sim{{asm({CMR})}}}}"),
        format!("{{sim{{asm({CMR})}},pk({pk})}}"),
    ] {
        let plain = format!("eltr({pk},{tree})");
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&plain)
            .unwrap()
            .into_definite()
            .unwrap();
        let ct_text = format!("ct({pk},{plain})");
        let ct = confidential::Descriptor::<DescriptorPublicKey>::from_str(&ct_text).unwrap();
        assert_eq!(
            ct.to_string()
                .parse::<confidential::Descriptor<DescriptorPublicKey>>()
                .unwrap(),
            ct
        );
        let ct = ct.at_derivation_index(0).unwrap();
        assert_eq!(ct.descriptor.script_pubkey(), desc.script_pubkey());
        assert_eq!(
            ct.unconfidential_address(&AddressParams::ELEMENTS).unwrap(),
            desc.address(&AddressParams::ELEMENTS).unwrap()
        );
        let pegin =
            Pegin::<DescriptorPublicKey>::from_str(&format!("pegin(wsh(pk({pk})),{plain})"))
                .unwrap();
        assert_eq!(
            pegin
                .to_string()
                .parse::<Pegin<DescriptorPublicKey>>()
                .unwrap(),
            pegin
        );
    }
    for bad in [
        format!("ct({pk},eltr({pk},sim{{asm{{{CMR}}}}}))"),
        format!("ct({pk},elwsh(sim{{asm({CMR})}}))"),
    ] {
        assert!(bad
            .parse::<confidential::Descriptor<DescriptorPublicKey>>()
            .is_err());
    }
    assert!(format!("pegin(wsh(pk({pk})),eltr{{{pk},sim{{asm({CMR})}}}})")
        .parse::<Pegin<DescriptorPublicKey>>()
        .is_err());
}
