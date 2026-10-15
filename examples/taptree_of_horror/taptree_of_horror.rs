use std::str::FromStr;

use bitcoin::bip32::Xpriv;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::PublicKey;
use elements_miniscript::descriptor::DescriptorSecretKey;
use elements_miniscript::elements::encode::serialize_hex;
use elements_miniscript::elements::pset::{self, PartiallySignedTransaction as Psbt};
use elements_miniscript::elements::sighash::SighashCache;
use elements_miniscript::elements::{
    confidential, hashes, Address, AddressParams, AssetId, BlockHash, LockTime, OutPoint,
    SchnorrSig, SchnorrSighashType, Script, Sequence,
};
use elements_miniscript::policy::Concrete;
use elements_miniscript::psbt::PsbtExt;
use elements_miniscript::{Descriptor, DescriptorPublicKey};
use helper_fns::{produce_grim_hash, produce_kelly_hash, produce_key_pairs};
mod helper_fns;

pub const KEYS_PER_PERSONA: usize = 9;

fn main() {
    let secp: &secp256k1::Secp256k1<secp256k1::All> = &secp256k1::Secp256k1::new();

    // ====== 1. Setup Hardcoded Values for all of the Personas ======

    // Define derivation paths that will be used
    let normal_path = "86'/1'/0'/0";
    let unhardened_path = "86/1/0/0";
    let weird_path = "69'/420'/999999999'/8008135'";

    // Hard coded regtest tprvs that will be used.
    let internal = format!("tprv8ZgxMBicQKsPfBJTWzMTQfRzcE3HCNKg6TUBpGBfigcFbqTXNBw6SuGPqBpD6D9pjLLASwq8bE7oZXCtMFPDKRizLy14xNqw4uz1zwrfo2c/{normal_path}/*");
    let alice = format!("tprv8ZgxMBicQKsPeZjVFDhZR5wjfCvFNev9qKGPDPC77p5cAEgEMUCR8Cecaf8pYfY7NTz8QcjVnP8uR8NedPz8o7iG7qWgnFMyQy9BAhMVZgb/{normal_path}/*");
    let bob = format!("tprv8ZgxMBicQKsPeHy2kPPVzYpbUqwTVBjSthMJUcGyqUiXk8eZTQ6xrJKEmdX8NYJKLLGCHGjuByqz2ahJXp52E8zCUV7njziJzwN7V7zfrKZ/{normal_path}/*");
    let charlie = format!("tprv8ZgxMBicQKsPdYaiWLUQCprj7Ej9Ka5GEq6giWHgTnbJvdLWnSuYnsF5sonVh6iy2HzvfkfxRDAmWEXNo3SJWTHCXM6XuxVZvqxtEyjdC29/{normal_path}/*");
    let dave = format!("tprv8ZgxMBicQKsPfCRUoMSWthoE8aJKr7De5YkxS1y55PuiSoi5ACyYUbas8Kv4vVtDzhKnBgY7cVSuogg2QLqtFcSZVv4ZTeBEzkzSnF9cSUT/{weird_path}/*");
    let eve = format!("tprv8ZgxMBicQKsPdYD5umCPZeh6tMqKfQATctqJbycgJ5N1rrJ15cHMgxds5iYENHZHmkMiXccAqUFx2k3ZNwU9qxPMjrKvTbCtgLFxk7mjMWD/{normal_path}/*");
    let frank = format!("tprv8ZgxMBicQKsPemyPyxqZ85T1UjpToCbLQ7uSn4JpbtwMBCodjvrLbgjBZeGgT4tMHdHCqyieDwCNzE7RrtRMVCQjPKQbGJzrg5vfn4eT7og/{normal_path}/*");
    let heather = format!("tprv8ZgxMBicQKsPefp99xLkwnQbU9LEEb8v4Aig3o4hwnjbaYotixkbJv3Ssmog68ptHij2LgExefNU96DYJKtFbDazTr1jm48twYhQLG775qw/{normal_path}/*");
    let ian = format!("tprv8ZgxMBicQKsPfGsuwfAdg3xPP452wreLk7ZEgusb8zdMqh1fyKGKnzFbxyxeHY3qhg8ESDRp5F6RgWiQGcvkmLyERcMys5V8DuT4gvxMDmS/{unhardened_path}/*");
    let judy = format!("tprv8ZgxMBicQKsPcz4VcN87e2e9k1LHDBLLajbVSAKAedpm1qakjtRT5xrdnmsQARWAfwg3REr6sNd5YHeWuWkHVvyey3rYmq9xYorMvwY3XAB/{normal_path}/*");
    let liam = format!("tprv8ZgxMBicQKsPcycCJ2v7B1utZrhWJNdQTBm7m9eR6iX1D9a9YvjbCNeT6dTEdMh4JziVCHD4YHQ7AXkZNMLfaBVf3CCiVWQLxwdU2SnrPcT/{normal_path}/*");
    let s_backup_1 = format!("tprv8ZgxMBicQKsPetPYYt5GUtNmQPChghNDBLbgJXz3cTZopeDrxHMendLpujaBHMPX3dXLZcv2NkgAvxMeuf1jWBU3iYxdeJAhktdeM9cKcYF/{normal_path}/*");
    let x_backup_2 = format!("tprv8ZgxMBicQKsPdf55kYg8pVPrUaW3VLZyt8XwxwrvSPkpskxDah1mAWypsTTZJeomWPrGf4e5RyT4zVzENHrwAsXxJP2EPYbfrYLRVFC1rLb/{normal_path}/*");

    // define DescriptorSecretKeys
    let internal_desc_secret = DescriptorSecretKey::from_str(&internal).unwrap();
    let a_descriptor_desc_secret = DescriptorSecretKey::from_str(&alice).unwrap();
    let b_descriptor_desc_secret = DescriptorSecretKey::from_str(&bob).unwrap();
    let c_descriptor_desc_secret = DescriptorSecretKey::from_str(&charlie).unwrap();
    let d_descriptor_desc_secret = DescriptorSecretKey::from_str(&dave).unwrap();
    let e_descriptor_desc_secret = DescriptorSecretKey::from_str(&eve).unwrap();
    let f_descriptor_desc_secret = DescriptorSecretKey::from_str(&frank).unwrap();
    let h_descriptor_desc_secret = DescriptorSecretKey::from_str(&heather).unwrap();
    let i_descriptor_desc_secret = DescriptorSecretKey::from_str(&ian).unwrap();
    let j_descriptor_desc_secret = DescriptorSecretKey::from_str(&judy).unwrap();
    let l_descriptor_desc_secret = DescriptorSecretKey::from_str(&liam).unwrap();
    let s_descriptor_desc_secret = DescriptorSecretKey::from_str(&s_backup_1).unwrap();
    let x_descriptor_desc_secret = DescriptorSecretKey::from_str(&x_backup_2).unwrap();
    let grim = produce_grim_hash("sovereignty through knowledge");
    let kelly = produce_kelly_hash("the ultimate pre-preimage");

    // ====== 2. Derive Keys, Preimages, Hashes, and Timelocks for Policy and Signing ======

    let internal_xpub: elements_miniscript::DescriptorPublicKey =
        internal_desc_secret.to_public(secp).unwrap();

    // example of how defining the internal xpriv that can be used for signing.
    // let internal_xpriv: DescriptorXKey<bitcoin::bip32::Xpriv> = match internal_desc_secret {
    //     elements_miniscript::descriptor::DescriptorSecretKey::XPrv(x) => Some(x.clone()),
    //     _ => None,
    // }
    // .unwrap();

    let (a_pks, a_prvs) = produce_key_pairs(a_descriptor_desc_secret, secp, normal_path, "alice");
    let (b_pks, b_prvs) = produce_key_pairs(b_descriptor_desc_secret, secp, normal_path, "bob");
    let (c_pks, c_prvs) = produce_key_pairs(c_descriptor_desc_secret, secp, normal_path, "charlie");
    let (d_pks, d_prvs) = produce_key_pairs(d_descriptor_desc_secret, secp, weird_path, "dave");
    let (e_pks, e_prvs) = produce_key_pairs(e_descriptor_desc_secret, secp, normal_path, "eve");
    let (f_pks, f_prvs) = produce_key_pairs(f_descriptor_desc_secret, secp, normal_path, "frank");
    let (h_pks, h_prvs) = produce_key_pairs(h_descriptor_desc_secret, secp, normal_path, "heather");
    let (i_pks, i_prvs) = produce_key_pairs(i_descriptor_desc_secret, secp, unhardened_path, "ian");
    let (j_pks, j_prvs) = produce_key_pairs(j_descriptor_desc_secret, secp, normal_path, "judy");
    let (l_pks, l_prvs) = produce_key_pairs(l_descriptor_desc_secret, secp, normal_path, "liam");
    let (s_pks, _s_prvs) =
        produce_key_pairs(s_descriptor_desc_secret, secp, normal_path, "s_backup1");
    let (x_pks, _x_prvs) =
        produce_key_pairs(x_descriptor_desc_secret, secp, normal_path, "x_backup2");

    // For this example we are grabbing the 9 keys for each persona
    let [a0, a1, a2, a3, a4, a5, a6, a7, a8]: [PublicKey; KEYS_PER_PERSONA] =
        a_pks[..].try_into().unwrap();
    let [b0, b1, b2, b3, b4, b5, b6, b7, b8]: [PublicKey; KEYS_PER_PERSONA] =
        b_pks[..].try_into().unwrap();
    let [c0, c1, c2, c3, c4, c5, c6, c7, c8]: [PublicKey; KEYS_PER_PERSONA] =
        c_pks[..].try_into().unwrap();
    let [d0, d1, d2, d3, d4, d5, d6, d7, d8]: [PublicKey; KEYS_PER_PERSONA] =
        d_pks[..].try_into().unwrap();
    let [e0, e1, e2, e3, e4, e5, e6, e7, e8]: [PublicKey; KEYS_PER_PERSONA] =
        e_pks[..].try_into().unwrap();
    let [f0, f1, f2, f3, f4, f5, f6, f7, f8]: [PublicKey; KEYS_PER_PERSONA] =
        f_pks[..].try_into().unwrap();
    let [h0, h1, h2, h3, h4, h5, h6, h7, h8]: [PublicKey; KEYS_PER_PERSONA] =
        h_pks[..].try_into().unwrap();
    let [i0, i1, i2, i3, i4, i5, i6, i7, i8]: [PublicKey; KEYS_PER_PERSONA] =
        i_pks[..].try_into().unwrap();
    let [j0, j1, j2, j3, j4, j5, j6, j7, j8]: [PublicKey; KEYS_PER_PERSONA] =
        j_pks[..].try_into().unwrap();
    let [l0, l1, l2, l3, l4, l5, l6, l7, l8]: [PublicKey; KEYS_PER_PERSONA] =
        l_pks[..].try_into().unwrap();
    let [_s0, _s1, s2, _s3, s4, s5, _s6, s7, s8]: [PublicKey; KEYS_PER_PERSONA] =
        s_pks[..].try_into().unwrap();
    let [_x0, _x1, x2, _x3, x4, x5, x6, _x7, x8]: [PublicKey; KEYS_PER_PERSONA] =
        x_pks[..].try_into().unwrap();

    // Hashes that will also be used in the policy.
    let g = grim.1;
    let k = kelly.1;
    // Absolute timelocks that were used at TABConf 6, The event took place Oct 23-26 and more spending paths for the puzzle became available during the conference.
    let oct_23_morning: u32 = 1729692000; // Oct 23, 10:00 AM EST
    let oct_24_evening: u32 = 1729819800; // Oct 24, 09:30 PM EST
    let oct_25_afternoon: u32 = 1729877400; // Oct 25, 01:30 PM EST
    let oct_26_morning: u32 = 1729942200; // Oct 26, 07:30 AM EST

    // ====== 3. Create Taptree Policy and Descriptor ======

    let pol_str = format!(
        "or(
            pk({internal_xpub}),
            or(
                and(
                    thresh(10, pk({a0}), pk({b0}), pk({c0}), pk({d0}), pk({e0}), pk({f0}), pk({h0}), pk({i0}), pk({j0}), pk({l0})),
                    thresh(3, sha256({k}), ripemd160({g}), after({oct_23_morning}))
                ),
                or(
                    or(
                        and(
                            thresh(8, pk({a1}), pk({b1}), pk({c1}), pk({e1}), pk({f1}), pk({h1}), pk({i1}), pk({j1}), pk({l1})),
                            thresh(3, pk({d1}), sha256({k}), after({oct_24_evening}))
                        ),
                        and(
                            thresh(4, pk({a2}), pk({b2}), pk({c2}), pk({e2}), pk({f2}), pk({h2}), pk({i2}), pk({l2})),
                            and(
                                thresh(4, pk({d2}), pk({j2}), ripemd160({g}), after({oct_24_evening})),
                                or(pk({s2}), pk({x2}))
                            )
                        )
                    ),
                    or(
                        or(
                            or(
                                and(
                                    thresh(6, pk({a3}), pk({b3}), pk({c3}), pk({e3}), pk({f3}), pk({h3}), pk({i3}), pk({l3})),
                                    thresh(4, pk({d3}), pk({j3}),  sha256({k}), after({oct_25_afternoon}))
                                ),
                                thresh(14, pk({a8}), pk({b8}), pk({c8}), pk({d8}), pk({e8}), pk({f8}), pk({h8}), pk({i8}), pk({j8}), pk({l8}), pk({s8}), pk({x8}), sha256({k}), ripemd160({g}))
                            ),
                            or(
                                and(
                                    thresh(9, pk({a4}), pk({b4}), pk({c4}), pk({d4}), pk({e4}), pk({f4}), pk({h4}), pk({i4}),  pk({j4}), pk({l4}), pk({s4}), pk({x4})),
                                    thresh(2, sha256({k}), after({oct_26_morning}))
                                ),
                                and(
                                    thresh(10, pk({a5}), pk({b5}), pk({c5}), pk({d5}), pk({e5}), pk({f5}), pk({h5}), pk({i5}),  pk({j5}), pk({l5}), pk({s5}), pk({x5})),
                                    after({oct_26_morning})
                                )
                            )
                        ),
                        or(
                            and(
                                thresh(4, pk({a6}), pk({b6}), pk({c6}), pk({e6}), pk({f6}), pk({h6}), pk({i6}), pk({l6})),
                                thresh(5, pk({d6}), pk({x6}), pk({j6}), ripemd160({g}), after({oct_25_afternoon}))
                            ),
                            and(
                                thresh(4, pk({a7}), pk({b7}), pk({c7}), pk({e7}), pk({f7}), pk({h7}), pk({i7}), pk({l7})),
                                thresh(5, pk({d7}), pk({s7}), pk({j7}), ripemd160({g}), after({oct_25_afternoon}))
                            )
                        )
                    )
                )
            )

        )"
    )
    .replace(&[' ', '\n', '\t'][..], "");

    // make sure policy doesn't have any issues
    let pol = Concrete::<DescriptorPublicKey>::from_str(&pol_str).unwrap();
    let policy_desc: Descriptor<DescriptorPublicKey> = pol.compile_tr(None).unwrap();

    // Now, using this public descriptor create the script address
    let derived_descriptor = policy_desc.derive_at_index(0).unwrap();
    let _script_address = derived_descriptor
        .address(&AddressParams::ELEMENTS)
        .unwrap();
    println!("the receiving address of this script is: {}", _script_address);
    println!("\ndescriptor is: {}\n", policy_desc);

    // We assert internal key is the one used in the descriptor
    match &policy_desc {
        Descriptor::Tr(tr) => {
            // println!("internal: {}, eve: {}", tr.internal_key(), eve_xpub);
            assert!(tr.internal_key() == &internal_xpub);
        }
        _ => panic!("internal spending path is not correct"),
    }

    // ====== 4. Construct an Unsigned PSET from the Tapscript ======

    let secp: &secp256k1::Secp256k1<secp256k1::All> = &secp256k1::Secp256k1::new();

    // Elements Taproot sighashes commit to the genesis block hash of the chain the
    // transaction is for; this example only needs a fixed value.
    let genesis_hash = BlockHash::from_byte_array([0x42; 32]);
    let asset = AssetId::LIQUID_BTC;

    let mut psbt = Psbt::new_v2();
    psbt.global.tx_data.fallback_locktime = Some(LockTime::from_time(oct_23_morning).unwrap());

    let mut input = pset::Input::from_prevout(OutPoint::new(
        "8888888899999999aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff"
            .parse()
            .unwrap(),
        0,
    ));
    input.sequence = Some(Sequence::ZERO);
    //        input.sequence = Some(Sequence(40));
    input.witness_utxo = Some(elements_miniscript::elements::TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(100_000_000),
        script_pubkey: derived_descriptor.script_pubkey(),
        ..Default::default()
    });
    psbt.add_input(input);

    let destination_address =
        Address::from_str("ert1qpq2cfgz5lktxzr5zqv7nrzz46hsvq3492ump9pz8rzcl8wqtwqcs2yqnuv")
            .unwrap();
    psbt.add_output(pset::Output::new_explicit(
        destination_address.script_pubkey(),
        99_999_000,
        asset,
        None,
    ));
    // Elements transactions pay their fee in an explicit output with an empty script pubkey.
    psbt.add_output(pset::Output::new_explicit(Script::new(), 1_000, asset, None));

    // Tell the PSET about the descriptor so it can sign with it
    psbt.update_input_with_descriptor(0, &derived_descriptor)
        .unwrap();

    // ====== 5. Sign and Create a Spending Transaction ======

    // Sign every leaf that each of the index 0 keys appears in.
    let unsigned_tx = psbt.extract_tx().unwrap();
    let mut sighash_cache = SighashCache::new(&unsigned_tx);
    for xpriv in [
        &a_prvs[0], &b_prvs[0], &c_prvs[0], &d_prvs[0], &e_prvs[0], &f_prvs[0], &h_prvs[0],
        &i_prvs[0], &j_prvs[0], &l_prvs[0],
    ] {
        sign_tap_leaves(&mut psbt, &mut sighash_cache, xpriv, genesis_hash, secp);
    }

    psbt.inputs_mut()[0].sha256_preimages.insert(
        hashes::sha256::Hash::from_byte_array(kelly.1.to_byte_array()),
        kelly.0.to_byte_array().to_vec(),
    );

    psbt.inputs_mut()[0].ripemd160_preimages.insert(
        hashes::ripemd160::Hash::from_byte_array(grim.1.to_byte_array()),
        grim.0.to_byte_array().to_vec(),
    );

    // Finalize the PSET now that we have all the required signatures and hash preimages.
    psbt.finalize_mut(secp, genesis_hash).unwrap();

    // Now extract the tx, checking it with the interpreter once more.
    let signed_tx = psbt.extract(secp, genesis_hash).unwrap();
    println!("signed transaction: {}", serialize_hex(&signed_tx));

    // A script-path spend: the satisfaction, then the leaf script and the control block.
    let witness = signed_tx.input[0].witness.script_witness.to_vec();
    assert!(witness.len() > 2);
    assert_eq!(signed_tx.output, unsigned_tx.output);
}

// Signs, for the PSET's only input, every Taproot leaf that the key of `xpriv` appears in.
fn sign_tap_leaves(
    psbt: &mut Psbt,
    sighash_cache: &mut SighashCache<&elements_miniscript::elements::Transaction>,
    xpriv: &Xpriv,
    genesis_hash: BlockHash,
    secp: &secp256k1::Secp256k1<secp256k1::All>,
) {
    let keypair = Keypair::from_secret_key(secp, &xpriv.private_key);
    let (x_only_pk, _parity) = keypair.x_only_public_key();
    let leaf_hashes = match psbt.inputs()[0].tap_key_origins.get(&x_only_pk) {
        Some((leaf_hashes, _origin)) => leaf_hashes.clone(),
        None => return,
    };
    for leaf_hash in leaf_hashes {
        let msg = psbt
            .sighash_msg(0, sighash_cache, Some(leaf_hash), genesis_hash)
            .unwrap()
            .to_secp_msg();
        let sig = SchnorrSig {
            sig: secp.sign_schnorr_with_aux_rand(&msg, &keypair, &[0; 32]),
            hash_ty: SchnorrSighashType::Default,
        };
        psbt.inputs_mut()[0]
            .tap_script_sigs
            .insert((x_only_pk, leaf_hash), sig);
    }
}
