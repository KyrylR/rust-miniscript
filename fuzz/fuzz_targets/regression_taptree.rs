use descriptor_fuzz::FuzzPk;
use honggfuzz::fuzz;
use miniscript::descriptor::Tr;
use miniscript::elements::secp256k1_zkp::Secp256k1;
use miniscript::elements::taproot::TaprootBuilder;
use miniscript::ToPublicKey;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    let Ok(tr) = data_str.parse::<Tr<FuzzPk>>() else {
        return;
    };
    let secp = Secp256k1::verification_only();
    let spend_info = tr.spend_info();
    let internal_key = tr.internal_key().to_x_only_pubkey();
    let expected = match tr.tap_tree() {
        Some(tree) => {
            let mut builder = TaprootBuilder::new();
            for leaf in tree.leaves() {
                builder = builder
                    .add_leaf_with_ver(
                        usize::from(leaf.depth()),
                        leaf.compute_script(),
                        leaf.leaf_version(),
                    )
                    .unwrap();
            }
            builder.finalize(&secp, internal_key).unwrap()
        }
        None => miniscript::elements::taproot::TaprootSpendInfo::new_key_spend(
            &secp,
            internal_key,
            None,
        ),
    };
    assert_eq!(spend_info.merkle_root(), expected.merkle_root());
    assert_eq!(spend_info.output_key(), expected.output_key());
    for leaf in spend_info.leaves() {
        let key = (leaf.script().clone(), leaf.leaf_version());
        assert!(expected.as_script_map()[&key].contains(&leaf.control_block().merkle_branch));
        assert!(leaf.control_block().verify_taproot_commitment(
            &secp,
            &spend_info.output_key(),
            leaf.script()
        ));
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn duplicate_crash() { crate::do_test(b"eltr(0,{0,0})"); }
}
