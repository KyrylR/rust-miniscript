#![allow(unexpected_cfgs)]

use honggfuzz::fuzz;
use miniscript::bitcoin::key::XOnlyPublicKey;
use miniscript::elements::Script;
use miniscript::extensions::CovExtArgs;
use miniscript::{CovenantExt, Miniscript, Tap};

type CovenantMs = Miniscript<XOnlyPublicKey, Tap, CovenantExt<CovExtArgs>>;

fn do_test(data: &[u8]) {
    let script = Script::from(data.to_vec());

    if let Ok(ms) = CovenantMs::decode_consensus(&script) {
        let output = ms.encode();
        // Constant introspection operands are sized at their largest.
        assert!(ms.script_size() >= output.len());
        assert_eq!(output, script);
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
