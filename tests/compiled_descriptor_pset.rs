// SPDX-License-Identifier: CC0-1.0

#![cfg(feature = "compiler")]

use std::str::FromStr;

use elements_miniscript::elements::pset::{Input, Output};
use elements_miniscript::policy::Concrete;
use elements_miniscript::psbt::{PsbtInputExt, PsbtOutputExt};
use elements_miniscript::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, NoExt};

#[test]
fn compiled_taproot_updates_pset_without_extension_conversion() {
    let a = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let b = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let policy =
        Concrete::<DescriptorPublicKey>::from_str(&format!("and(pk({a}),pk({b}))")).unwrap();
    let compiled: Descriptor<DescriptorPublicKey, NoExt> = policy
        .compile_tr(Some(DescriptorPublicKey::from_str(a).unwrap()))
        .unwrap();
    let compiled = compiled.into_definite().unwrap();
    let parsed = Descriptor::<DefiniteDescriptorKey>::from_str(&compiled.to_string()).unwrap();
    let mut compiled_input = Input::default();
    let mut parsed_input = Input::default();
    let mut compiled_output = Output::default();
    let mut parsed_output = Output::default();
    let derived = compiled_input
        .update_with_descriptor_unchecked(&compiled)
        .unwrap();
    parsed_input
        .update_with_descriptor_unchecked(&parsed)
        .unwrap();
    compiled_output
        .update_with_descriptor_unchecked(&compiled)
        .unwrap();
    parsed_output
        .update_with_descriptor_unchecked(&parsed)
        .unwrap();
    assert_eq!(derived.script_pubkey(), compiled.script_pubkey());
    assert_eq!(compiled_input, parsed_input);
    assert_eq!(compiled_output, parsed_output);
}
