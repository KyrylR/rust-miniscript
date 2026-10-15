#![allow(unexpected_cfgs)]

use honggfuzz::fuzz;
use miniscript::bitcoin::PublicKey;
use miniscript::descriptor::csfs_cov::LegacyCSFSCov;
use miniscript::elements::Script;

fn do_test(data: &[u8]) {
    let script = Script::from(data.to_vec());

    if let Ok(cov) = LegacyCSFSCov::<PublicKey>::decode_consensus(&script) {
        assert_eq!(cov.inner_script(), script);
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
