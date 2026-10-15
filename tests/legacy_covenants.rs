//! Legacy covenant fragments outside `elcovwsh`
//!
//! `ver_eq` and `outputs_pref` read signature hash items that only the witness of an `elcovwsh`
//! covenant supplies and authenticates, so Tapscript and plain Segwit v0 Miniscript reject them
//! in both text and Script.

use std::str::FromStr;

use elements_miniscript::bitcoin::key::XOnlyPublicKey;
use elements_miniscript::elements::opcodes::all::{
    OP_CAT, OP_DEPTH, OP_EQUAL, OP_HASH256, OP_PICK, OP_SUB, OP_SWAP,
};
use elements_miniscript::elements::script::Builder;
use elements_miniscript::extensions::CovExtArgs;
use elements_miniscript::{bitcoin, CovenantExt, Miniscript, Segwitv0, Tap};

type TapCovenant = Miniscript<XOnlyPublicKey, Tap, CovenantExt<CovExtArgs>>;
type Segwit = Miniscript<bitcoin::PublicKey, Segwitv0>;

#[test]
fn legacy_fragments_do_not_parse() {
    for s in [
        "ver_eq(2)",
        "outputs_pref(0102)",
        "and_v(v:ver_eq(2),1)",
        "l:outputs_pref(0102)",
    ] {
        assert!(TapCovenant::from_str_insane(s).is_err(), "{}", s);
        assert!(Segwit::from_str_insane(s).is_err(), "{}", s);
        assert!(TapCovenant::from_str(s).is_err(), "{}", s);
        assert!(Segwit::from_str(s).is_err(), "{}", s);
    }
}

#[test]
fn legacy_scripts_do_not_decode() {
    // `ver_eq(2)` and `outputs_pref(0102)`, encoded as inside `elcovwsh`.
    let ver_eq = Builder::new()
        .push_opcode(OP_DEPTH)
        .push_int(12)
        .push_opcode(OP_SUB)
        .push_opcode(OP_PICK)
        .push_slice(&2u32.to_le_bytes())
        .push_opcode(OP_EQUAL)
        .into_script();
    let outputs_pref = (0..6)
        .fold(Builder::new(), |builder, _| builder.push_opcode(OP_CAT))
        .push_slice(&[1, 2])
        .push_opcode(OP_SWAP)
        .push_opcode(OP_CAT)
        .push_opcode(OP_HASH256)
        .push_opcode(OP_DEPTH)
        .push_int(4)
        .push_opcode(OP_SUB)
        .push_opcode(OP_PICK)
        .push_opcode(OP_EQUAL)
        .into_script();
    for script in [ver_eq, outputs_pref] {
        assert!(TapCovenant::decode_consensus(&script).is_err(), "{}", script);
        assert!(Segwit::decode_consensus(&script).is_err(), "{}", script);
    }
}
