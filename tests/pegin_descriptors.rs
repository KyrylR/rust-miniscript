// SPDX-License-Identifier: CC0-1.0

//! Public boundary tests for pegin descriptors
//!
//! Malformed pegin input is an error at the public boundary, and the legacy pegin constructor
//! reproduces the Elements liquidv1 watchman script.

use std::str::FromStr;

use elements_miniscript::bitcoin::opcodes::all::OP_ELSE;
use elements_miniscript::bitcoin::script::Instruction;
use elements_miniscript::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use elements_miniscript::bitcoin::{
    self, CompressedPublicKey, Network, PublicKey, ScriptBuf, Weight,
};
use elements_miniscript::bitcoin_miniscript::descriptor::DescriptorType;
use elements_miniscript::bitcoin_miniscript::{RelLockTime, Threshold};
use elements_miniscript::descriptor::pegin::{Error, LegacyPegin, LegacyPeginKey, Pegin};
use elements_miniscript::descriptor::NonDefiniteKeyError;
use elements_miniscript::DescriptorPublicKey;

/// The liquidv1 `fedpegScript` from Elements src/kernel/chainparams.cpp
const LIQUID_SCRIPT: &str = "745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae";

const FED_KEY: &str = "020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261";
const EMER_KEY: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const USER: &str = "0321da398ca2ddc09be89caa26e6730ae84751b6ea3a1ca46aa365bb5e1c3d9620";

/// The federation and emergency keys of the liquidv1 watchman script
fn liquid_keys() -> (Vec<CompressedPublicKey>, Vec<CompressedPublicKey>) {
    let script = ScriptBuf::from_hex(LIQUID_SCRIPT).unwrap();
    let (mut fed, mut emer, mut emergency_branch) = (vec![], vec![], false);
    for instruction in script.instructions() {
        match instruction.unwrap() {
            Instruction::Op(op) if op == OP_ELSE => emergency_branch = true,
            Instruction::PushBytes(push) if push.len() == 33 => {
                let key = CompressedPublicKey::from_slice(push.as_bytes()).unwrap();
                if emergency_branch {
                    emer.push(key);
                } else {
                    fed.push(key);
                }
            }
            _ => {}
        }
    }
    (fed, emer)
}

fn user_desc() -> elements_miniscript::Descriptor<PublicKey> {
    elements_miniscript::Descriptor::from_str(&format!("elwpkh({USER})")).unwrap()
}

#[test]
fn legacy_pegin_key_rejects_malformed_text() {
    let uncompressed = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
    for s in [
        String::new(),
        "f".to_owned(),
        FED_KEY.to_owned(),
        format!("x{FED_KEY}"),
        format!(" f{FED_KEY}"),
        format!("\n                    f{FED_KEY}"),
        format!("f{FED_KEY}\n"),
        format!("f {FED_KEY}"),
        format!("f{uncompressed}"),
        "\u{e9}".to_owned(),
        format!("f\u{e9}{FED_KEY}"),
    ] {
        assert!(LegacyPeginKey::from_str(&s).is_err(), "{:?}", s);
    }

    let key = LegacyPeginKey::from_str(&format!("u{FED_KEY}")).unwrap();
    assert_eq!(
        key,
        LegacyPeginKey::NonFunctionary(CompressedPublicKey::from_str(FED_KEY).unwrap())
    );
    assert_eq!(key.to_string(), format!("u{FED_KEY}"));
}

// A legacy pegin threshold rejects a k above its number of keys, a zero k and more than 20 keys.
#[test]
fn legacy_pegin_thresholds_must_fit_their_keys() {
    let (fed, _) = liquid_keys();
    let fed: Vec<_> = fed.into_iter().map(LegacyPeginKey::Functionary).collect();
    assert_eq!(fed.len(), 15);
    assert!(Threshold::<_, 20>::new(22, fed.clone()).is_err());
    assert!(Threshold::<_, 20>::new(0, fed.clone()).is_err());
    let mut many = fed.clone();
    many.extend(fed.iter().take(6).copied());
    assert!(Threshold::<_, 20>::new(11, many).is_err());
    Threshold::<_, 20>::new(11, fed).unwrap();
}

#[test]
fn legacy_pegin_parse_rejects_malformed_text() {
    let (fed, emer) = liquid_keys();
    let keys = |prefix: &str, keys: &[CompressedPublicKey]| {
        keys.iter()
            .map(|key| format!("{prefix}{key}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let policy = |k: usize, fed_keys: &str| {
        format!("or_d(multi({k},{fed_keys}),and_v(v:older(4032),multi(2,{})))", keys("u", &emer))
    };
    let valid = format!("legacy_pegin({},elwpkh({USER}))", policy(11, &keys("f", &fed)));
    LegacyPegin::<PublicKey>::from_str(&valid).unwrap();

    for s in [
        format!("legacy_pegin({},elwpkh({USER}))", policy(22, &keys("f", &fed))),
        format!("legacy_pegin({},elwpkh({USER}))", policy(11, &keys(" f", &fed))),
        format!("legacy_pegin({},elwpkh({USER}))", policy(11, &keys("", &fed))),
        format!("legacy_pegin({},wpkh({USER}))", policy(11, &keys("f", &fed))),
        format!("legacy_pegin({})", policy(11, &keys("f", &fed))),
        format!("legacy_pegin({},elwpkh({USER}),elwpkh({USER}))", policy(11, &keys("f", &fed))),
        format!("{valid}#00000000"),
        format!("pegin({},elwpkh({USER}))", policy(11, &keys("f", &fed))),
    ] {
        assert!(LegacyPegin::<PublicKey>::from_str(&s).is_err(), "{}", s);
    }

    assert!(matches!(
        LegacyPegin::<PublicKey>::from_str(&format!(
            "legacy_pegin(multi(11,{}),elwpkh({USER}))",
            keys("f", &fed)
        )),
        Err(Error::UnexpectedLegacyMiniscript)
    ));
    assert!(matches!(
        LegacyPegin::<PublicKey>::from_str(&format!(
            "legacy_pegin({},elwpkh({USER}))",
            policy(2, &keys("f", &fed))
        )),
        Err(Error::EqualLegacyThresholds(2))
    ));
}

// Elements src/pegins.cpp `MatchLiquidWatchman` rejects a watchman script whose federation
// and emergency thresholds are equal, because its depth check could never reach the emergency
// branch. `calculate_contract` would then tweak the emergency keys as well, so the generic
// constructor rejects equal thresholds instead of building a script Elements reads differently.
#[test]
fn legacy_pegin_rejects_equal_thresholds() {
    let (fed, emer) = liquid_keys();
    let fed: Vec<_> = fed.into_iter().map(LegacyPeginKey::Functionary).collect();
    let emer: Vec<_> = emer
        .into_iter()
        .map(LegacyPeginKey::NonFunctionary)
        .collect();
    let timelock = RelLockTime::from_consensus(4032).unwrap();

    for k in [1, 2, 3] {
        assert!(matches!(
            LegacyPegin::new(
                Threshold::new(k, fed.clone()).unwrap(),
                Threshold::new(k, emer.clone()).unwrap(),
                timelock,
                user_desc(),
            ),
            Err(Error::EqualLegacyThresholds(n)) if n == k
        ));
    }
    for k in [1, 3, 11, 15] {
        LegacyPegin::new(
            Threshold::new(k, fed.clone()).unwrap(),
            Threshold::new(2, emer.clone()).unwrap(),
            timelock,
            user_desc(),
        )
        .unwrap();
    }
}

// The generic constructor with the liquidv1 parameters builds the Elements watchman script.
// As in Elements test/functional/rpc_tweakfedpeg.py, the claim script changes only the
// federation keys before OP_ELSE.
#[test]
fn legacy_pegin_builds_liquid_watchman_script() {
    let secp = Secp256k1::new();
    let (fed, emer) = liquid_keys();
    let pegin = LegacyPegin::new(
        Threshold::new(
            11,
            fed.iter()
                .copied()
                .map(LegacyPeginKey::Functionary)
                .collect(),
        )
        .unwrap(),
        Threshold::new(
            2,
            emer.iter()
                .copied()
                .map(LegacyPeginKey::NonFunctionary)
                .collect(),
        )
        .unwrap(),
        RelLockTime::from_consensus(4032).unwrap(),
        user_desc(),
    )
    .unwrap();

    let untweaked = ScriptBuf::from_hex(LIQUID_SCRIPT).unwrap();
    let witness_script = pegin.bitcoin_witness_script(&secp).unwrap();
    assert_eq!(witness_script.len(), untweaked.len());
    let tweaked: Vec<_> = witness_script.instructions().map(Result::unwrap).collect();
    let untweaked: Vec<_> = untweaked.instructions().map(Result::unwrap).collect();
    assert_eq!(tweaked.len(), untweaked.len());
    let mut emergency_branch = false;
    for (tweaked, untweaked) in tweaked.iter().zip(&untweaked) {
        match (tweaked, untweaked) {
            (Instruction::PushBytes(t), Instruction::PushBytes(u)) if u.len() == 33 => {
                assert_eq!(t.len(), 33);
                assert_eq!(t.as_bytes() == u.as_bytes(), emergency_branch);
            }
            _ => {
                assert_eq!(tweaked, untweaked);
                emergency_branch |= *untweaked == Instruction::Op(OP_ELSE);
            }
        }
    }

    // A dynafed federation of one liquidv1 key gets the same tweak for the same claim script.
    let dynafed =
        Pegin::<PublicKey>::from_str(&format!("pegin(wsh(multi(1,{FED_KEY})),elwpkh({USER}))"))
            .unwrap();
    let dynafed_key = dynafed
        .bitcoin_witness_script(&secp)
        .unwrap()
        .instructions()
        .map(Result::unwrap)
        .find_map(|i| {
            i.push_bytes()
                .filter(|p| p.len() == 33)
                .map(|p| p.as_bytes().to_vec())
        })
        .unwrap();
    assert_eq!(fed[0].to_string(), FED_KEY);
    assert!(matches!(tweaked[5], Instruction::PushBytes(p) if p.as_bytes() == &dynafed_key[..]));

    assert_eq!(
        pegin.bitcoin_address(Network::Bitcoin, &secp).unwrap(),
        bitcoin::Address::p2shwsh(&witness_script, Network::Bitcoin)
    );
    assert_eq!(pegin.bitcoin_script_pubkey(&secp).unwrap(), witness_script.to_p2wsh().to_p2sh());
    let mut script_sig = vec![0x22];
    script_sig.extend(witness_script.to_p2wsh().into_bytes());
    assert_eq!(
        pegin
            .bitcoin_unsigned_script_sig(&secp)
            .unwrap()
            .into_bytes(),
        script_sig
    );

    // 4 * 35 for the scriptSig, then the empty element, 11 signatures and the 628-byte
    // witness script with its 3-byte length
    assert_eq!(pegin.max_weight_to_satisfy(), Weight::from_wu(4 * 35 + 1 + 73 * 11 + 3 + 628));

    let s = pegin.to_string();
    assert_eq!(LegacyPegin::<PublicKey>::from_str(&s).unwrap(), pegin);
}

// Elements src/pegins.cpp `IsValidPeginWitness` rejects claim scripts longer than 100 bytes,
// so neither pegin kind exposes a Bitcoin address or script for such a claim descriptor.
#[test]
fn claim_script_limit() {
    let secp = Secp256k1::new();
    let (fed, emer) = liquid_keys();
    let legacy = |claim: &str| {
        LegacyPegin::new(
            Threshold::new(
                11,
                fed.iter()
                    .copied()
                    .map(LegacyPeginKey::Functionary)
                    .collect(),
            )
            .unwrap(),
            Threshold::new(
                2,
                emer.iter()
                    .copied()
                    .map(LegacyPeginKey::NonFunctionary)
                    .collect(),
            )
            .unwrap(),
            RelLockTime::from_consensus(4032).unwrap(),
            elements_miniscript::Descriptor::<PublicKey>::from_str(claim).unwrap(),
        )
        .unwrap()
    };
    let dynafed = |claim: &str| {
        Pegin::<PublicKey>::from_str(&format!("pegin(wsh(multi(1,{FED_KEY})),{claim})")).unwrap()
    };
    let keys = format!("{FED_KEY},{EMER_KEY},{USER}");

    let script_len = |desc: &str| {
        elements_miniscript::Descriptor::<PublicKey>::from_str(desc)
            .unwrap()
            .script_pubkey()
            .len()
    };

    let bare = format!("elmulti(2,{keys})");
    assert_eq!(script_len(&bare), 105);
    let (legacy_pegin, dynafed_pegin) = (legacy(&bare), dynafed(&bare));
    for result in [
        legacy_pegin
            .bitcoin_address(Network::Bitcoin, &secp)
            .map(|_| ()),
        legacy_pegin.bitcoin_script_pubkey(&secp).map(|_| ()),
        legacy_pegin.bitcoin_unsigned_script_sig(&secp).map(|_| ()),
        legacy_pegin.bitcoin_witness_script(&secp).map(|_| ()),
        legacy_pegin
            .get_bitcoin_satisfaction(&secp, Sigs(vec![]))
            .map(|_| ()),
        dynafed_pegin
            .bitcoin_address(Network::Bitcoin, &secp)
            .map(|_| ()),
        dynafed_pegin.bitcoin_script_pubkey(&secp).map(|_| ()),
        dynafed_pegin.bitcoin_unsigned_script_sig(&secp).map(|_| ()),
        dynafed_pegin.bitcoin_witness_script(&secp).map(|_| ()),
        dynafed_pegin
            .get_bitcoin_satisfaction(&secp, Sigs(vec![]))
            .map(|_| ()),
    ] {
        assert!(matches!(result, Err(Error::ClaimScriptTooLarge(105))));
    }

    for claim in [format!("elwsh(multi(2,{keys}))"), format!("eltr({USER})")] {
        assert_eq!(script_len(&claim), 34);
        legacy(&claim)
            .bitcoin_address(Network::Bitcoin, &secp)
            .unwrap();
        dynafed(&claim)
            .bitcoin_address(Network::Bitcoin, &secp)
            .unwrap();
    }
}

struct Sigs(Vec<(PublicKey, bitcoin::ecdsa::Signature)>);

impl elements_miniscript::bitcoin_miniscript::Satisfier<PublicKey> for Sigs {
    fn lookup_ecdsa_sig(&self, pk: &PublicKey) -> Option<bitcoin::ecdsa::Signature> {
        self.0
            .iter()
            .find(|(key, _)| key == pk)
            .map(|(_, sig)| *sig)
    }
}

#[test]
fn dynafed_pegin_boundary() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[1; 32]).unwrap();
    let key = PublicKey::new(sk.public_key(&secp));

    // wsh() federation: no scriptSig, and the witness ends with the tweaked witness script
    let pegin = Pegin::<PublicKey>::from_str(&format!("pegin(wsh(multi(1,{key})),elwpkh({USER}))"))
        .unwrap();
    let witness_script = pegin.bitcoin_witness_script(&secp).unwrap();
    assert_eq!(pegin.bitcoin_unsigned_script_sig(&secp).unwrap(), ScriptBuf::new());
    assert_eq!(
        pegin.bitcoin_address(Network::Bitcoin, &secp).unwrap(),
        bitcoin::Address::p2wsh(&witness_script, Network::Bitcoin)
    );
    let tweaked = witness_script
        .instructions()
        .map(Result::unwrap)
        .find_map(|i| {
            i.push_bytes()
                .filter(|p| p.len() == 33)
                .map(|p| p.as_bytes().to_vec())
        })
        .map(|key| PublicKey::from_slice(&key).unwrap())
        .unwrap();
    assert_ne!(tweaked, key);
    let sig = bitcoin::ecdsa::Signature::sighash_all(
        secp.sign_ecdsa(&Message::from_digest([1; 32]), &sk),
    );
    let (witness, script_sig) = pegin
        .get_bitcoin_satisfaction(&secp, Sigs(vec![(tweaked, sig)]))
        .unwrap();
    assert_eq!(witness, vec![vec![], sig.to_vec(), witness_script.to_bytes()]);
    assert_eq!(script_sig, ScriptBuf::new());
    assert!(matches!(
        pegin.get_bitcoin_satisfaction(&secp, Sigs(vec![(key, sig)])),
        Err(Error::Bitcoin(_))
    ));

    // sh(wsh()) federation: the scriptSig pushes the witness program
    let pegin =
        Pegin::<PublicKey>::from_str(&format!("pegin(sh(wsh(multi(1,{key}))),elwpkh({USER}))"))
            .unwrap();
    let witness_program = pegin.bitcoin_witness_script(&secp).unwrap().to_p2wsh();
    let mut script_sig = vec![0x22];
    script_sig.extend(witness_program.as_bytes());
    assert_eq!(
        pegin
            .bitcoin_unsigned_script_sig(&secp)
            .unwrap()
            .into_bytes(),
        script_sig
    );
    assert_eq!(pegin.bitcoin_script_pubkey(&secp).unwrap(), witness_program.to_p2sh());

    // An eltr claim descriptor has a scriptPubKey like any other claim descriptor.
    let tr =
        Pegin::<PublicKey>::from_str(&format!("pegin(wsh(multi(1,{key})),eltr({USER}))")).unwrap();
    assert_ne!(tr.bitcoin_witness_script(&secp).unwrap(), witness_script);

    // Elements only pays pegins to wsh() and sh(wsh()) federations.
    let pkh = Pegin::<PublicKey>::from_str(&format!("pegin(pkh({key}),elwpkh({USER}))")).unwrap();
    assert!(matches!(
        pkh.bitcoin_address(Network::Bitcoin, &secp),
        Err(Error::UnsupportedFederation(DescriptorType::Pkh))
    ));
    assert!(matches!(
        pkh.bitcoin_script_pubkey(&secp),
        Err(Error::UnsupportedFederation(DescriptorType::Pkh))
    ));
    assert!(matches!(
        pkh.get_bitcoin_satisfaction(&secp, Sigs(vec![])),
        Err(Error::UnsupportedFederation(DescriptorType::Pkh))
    ));
    assert!(matches!(
        pkh.max_weight_to_satisfy(),
        Err(Error::UnsupportedFederation(DescriptorType::Pkh))
    ));

    // The federation is a Bitcoin descriptor and the claim is an Elements descriptor.
    for (s, bitcoin_side) in [
        (format!("pegin(elwsh(multi(1,{key})),elwpkh({USER}))"), true),
        (format!("pegin(wsh(multi(1,{key})),wpkh({USER}))"), false),
        (format!("pegin(wsh(multi(1,{key})))"), false),
        (format!("pegin(wsh(multi(1,{key})),elwpkh({USER}),elwpkh({USER}))"), false),
    ] {
        match Pegin::<PublicKey>::from_str(&s) {
            Err(Error::Bitcoin(_)) => assert!(bitcoin_side, "{}", s),
            Err(Error::Elements(_)) => assert!(!bitcoin_side, "{}", s),
            other => panic!("{}: {:?}", s, other),
        }
    }
}

#[test]
fn dynafed_pegin_derivation() {
    let secp = Secp256k1::new();
    let xpub = "xpub661MyMwAqRbcEcT9W98HZP2kFzyzQQZkYnrRnrM8uD8kH8kSeFoQHq1x2iihLgC6PXGy5LrjCL66uSNhJ8pwjfx2rMUTLWuRMns2EG9xnjs";

    let pegin = Pegin::<DescriptorPublicKey>::from_str(&format!(
        "pegin(wsh(multi(1,{FED_KEY})),elwpkh({xpub}/*))"
    ))
    .unwrap();
    let address_0 = pegin
        .derived_descriptor(&secp, 0)
        .unwrap()
        .bitcoin_address(Network::Bitcoin, &secp)
        .unwrap();
    let address_1 = pegin
        .derived_descriptor(&secp, 1)
        .unwrap()
        .bitcoin_address(Network::Bitcoin, &secp)
        .unwrap();
    assert_ne!(address_0, address_1);

    let hardened = Pegin::<DescriptorPublicKey>::from_str(&format!(
        "pegin(wsh(multi(1,{FED_KEY})),elwpkh({xpub}/*h))"
    ))
    .unwrap();
    assert_eq!(
        hardened.derived_descriptor(&secp, 0).unwrap_err(),
        NonDefiniteKeyError::HardenedStep
    );
}
