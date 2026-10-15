// SPDX-License-Identifier: CC0-1.0

use std::str::FromStr;

use elements_miniscript::elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use elements_miniscript::elements::taproot::{LeafVersion, TaprootBuilder};
use elements_miniscript::elements::{Address, AddressParams, LockTime, Script, Sequence, Witness};
use elements_miniscript::interpreter::{Error, Interpreter};

#[test]
fn interpreter_rejects_other_leaf_versions_before_script_decoding() {
    let secp = Secp256k1::verification_only();
    let key = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .unwrap();
    for version in [0xbe, 0xc0, 0xc6] {
        let script = Script::from(vec![0x51]);
        let version = LeafVersion::from_u8(version).unwrap();
        let spend = TaprootBuilder::new()
            .add_leaf_with_ver(0, script.clone(), version)
            .unwrap()
            .finalize(&secp, key)
            .unwrap();
        let control = spend.control_block(&(script.clone(), version)).unwrap();
        let spk = Address::p2tr_tweaked(spend.output_key(), None, &AddressParams::ELEMENTS)
            .script_pubkey();
        let witness = Witness::from_slice(&[script.into_bytes(), control.serialize()]);
        let script_sig = Script::new();
        assert!(matches!(
            Interpreter::from_txdata(&spk, &script_sig, &witness, Sequence::ZERO, LockTime::ZERO),
            Err(Error::UnsupportedTapLeafVersion(v)) if v == version.as_u8()
        ));
    }
}
