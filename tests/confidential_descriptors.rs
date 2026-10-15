// SPDX-License-Identifier: CC0-1.0

//! Public boundary tests for ELIP-150 `ct()` descriptors, ELIP-151 view keys and SLIP-77

use std::str::FromStr;

use elements_miniscript::bitcoin::secp256k1::{Secp256k1, SecretKey};
use elements_miniscript::confidential::slip77::MasterBlindingKey;
use elements_miniscript::confidential::{self, bare, Error, Key};
use elements_miniscript::descriptor::NonDefiniteKeyError;
use elements_miniscript::elements::AddressParams;
use elements_miniscript::{
    translate_hash_fail, DefiniteDescriptorKey, DescriptorPublicKey, Translator,
};

const XPRV: &str = "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5qzmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb";
const XPUB: &str = "xpub661MyMwAqRbcEcT9W98HZP2kFzyzQQZkYnrRnrM8uD8kH8kSeFoQHq1x2iihLgC6PXGy5LrjCL66uSNhJ8pwjfx2rMUTLWuRMns2EG9xnjs";
const SPK_XPUB: &str = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
const ELIP151_XPUB: &str = "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8";
const PK: &str = "03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4";
const MBK: &str = "b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04";

type Definite = confidential::Descriptor<DefiniteDescriptorKey>;
type Ranged = confidential::Descriptor<DescriptorPublicKey>;

// The ELIP-150 view descriptor and the descriptor with its public key give the same address.
#[test]
fn elip150_view_descriptor() {
    let secp = Secp256k1::new();
    let conf_addr = "lq1qq2r0pdvcknjpwev96qu9975alzqs78cvsut5ju82t7tv8d645dgmwknpl78t02k2xqgdh9ltmfmpy9ssk7qfvtk83xqzx62q4";

    for s in [
        format!("ct({XPRV},elwpkh({SPK_XPUB}))#j95xktq7"),
        format!("ct({XPUB},elwpkh({SPK_XPUB}))#elmfpmp9"),
    ] {
        let desc = Definite::from_str(&s).unwrap();
        assert_eq!(desc.to_string(), s);
        assert_eq!(
            desc.address(&secp, &AddressParams::LIQUID)
                .unwrap()
                .to_string(),
            conf_addr
        );
    }
}

#[test]
fn malformed_ct_descriptors_are_errors() {
    for s in [
        "",
        "ct",
        "ct()",
        "ct(,)",
        "ct{02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4)}",
        "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623)",
        "ct(slip77(),elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))",
        "ct(slip77(b2396b3e),elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))",
        "ct(slip77{b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04},elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))",
        "ct(elip151(),elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))",
        "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,wpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))",
        "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,{pk(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4)})",
        "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))#",
        "ct(\u{e9},elwpkh(03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4))",
    ] {
        assert!(Ranged::from_str(s).is_err(), "{}", s);
    }
}

#[test]
fn blinding_keys_must_be_definite() {
    let secp = Secp256k1::new();
    let params = &AddressParams::LIQUID;

    // A hardened step can only be derived from a private key.
    let desc = Definite::from_str(&format!("ct({XPUB}/0h,elwpkh({PK}))")).unwrap();
    assert!(matches!(
        desc.address(&secp, params),
        Err(Error::NonDefiniteKey(NonDefiniteKeyError::HardenedStep))
    ));
    let desc = Definite::from_str(&format!("ct({XPRV}/0h,elwpkh({PK}))")).unwrap();
    desc.address(&secp, params).unwrap();

    // A wildcard needs a derivation index.
    let desc = Definite::from_str(&format!("ct({XPUB}/*,elwpkh({PK}))")).unwrap();
    assert!(matches!(
        desc.address(&secp, params),
        Err(Error::NonDefiniteKey(NonDefiniteKeyError::Wildcard))
    ));

    for s in [
        format!("ct({XPUB}/*h,elwpkh({SPK_XPUB}/*))"),
        format!("ct(slip77({MBK}),elwpkh({SPK_XPUB}/*h))"),
    ] {
        let desc = Ranged::from_str(&s).unwrap();
        assert_eq!(desc.at_derivation_index(0).unwrap_err(), NonDefiniteKeyError::HardenedStep);
    }
    for s in [
        format!("ct({XPUB}/<0;1>/*,elwpkh({SPK_XPUB}/*))"),
        format!("ct({XPRV}/<0;1>/*,elwpkh({SPK_XPUB}/*))"),
    ] {
        let desc = Ranged::from_str(&s).unwrap();
        assert_eq!(desc.at_derivation_index(0).unwrap_err(), NonDefiniteKeyError::Multipath);
    }

    // A private view key derives through a hardened wildcard.
    let desc = Ranged::from_str(&format!("ct({XPRV}/*h,elwpkh({SPK_XPUB}/*))")).unwrap();
    desc.at_derivation_index(7)
        .unwrap()
        .address(&secp, params)
        .unwrap();
}

#[test]
fn blinding_keys_must_be_compressed() {
    let uncompressed = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
    assert!(matches!(
        Definite::from_str(&format!("ct({uncompressed},elwpkh({PK}))")),
        Err(Error::NonCompressedBlindingKey)
    ));
}

// `Descriptor::from_str` compares multi-path keys within each Miniscript. `ct()` also
// compares the Taproot internal key with the leaves and the leaves with each other.
#[test]
fn multipath_lengths_match_across_taproot_keys() {
    let x = ELIP151_XPUB;
    for tr in [
        format!("eltr({x}/<0;1>/*,pk({x}/0/<0;1;2>/*))"),
        format!("eltr({PK},{{pk({x}/<0;1>/*),pk({x}/0/<0;1;2>/*)}})"),
    ] {
        elements_miniscript::Descriptor::<DescriptorPublicKey>::from_str(&tr).unwrap();
        for ct in [
            format!("ct(slip77({MBK}),{tr})"),
            format!("ct(elip151,{tr})"),
        ] {
            assert!(
                matches!(
                    Ranged::from_str(&ct),
                    Err(Error::Descriptor(elements_miniscript::Error::MultipathDescLenMismatch))
                ),
                "{}",
                ct
            );
        }
    }
    Ranged::from_str(&format!("ct(slip77({MBK}),eltr({x}/<0;1>/*,pk({x}/0/<0;1>/*)))")).unwrap();
}

// ELIP-151 test vector 1 and invalid test vectors 1 to 3
#[test]
fn elip151_vectors() {
    let x = ELIP151_XPUB;
    let desc = Ranged::from_str(&format!("ct(elip151,elwpkh({x}/<0;1>/*))")).unwrap();
    assert!(matches!(desc.key, Key::View(_)));
    assert_eq!(
        desc.key.to_string(),
        "b3baf94d60cf8423cd257283575997a2c00664ced3e8de00f8726703142b1989"
    );
    assert_eq!(
        desc,
        Ranged::with_elip151_descriptor_blinding_key(desc.descriptor.clone()).unwrap()
    );

    for s in [
        format!("ct(elip151,elwpkh({x}))#hf047rv6"),
        "ct(elip151,elwpkh(03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494))#3fcvdxu3".to_owned(),
    ] {
        assert!(matches!(
            Ranged::from_str(&s),
            Err(Error::NonDefiniteKey(NonDefiniteKeyError::NoWildcard))
        ));
    }
    assert!(matches!(
        Ranged::from_str(&format!(
            "ct(elip151,elwsh(multi(2,{x}/<0;1>/*,{x}/0/<0;1;2>/*)))#gkrp8f5z"
        )),
        Err(Error::Descriptor(elements_miniscript::Error::MultipathDescLenMismatch))
    ));
}

// Wallets derive blinding private keys directly, and these must match the address keys.
#[test]
fn blinding_private_keys_match_addresses() {
    let secp = Secp256k1::new();
    let params = &AddressParams::LIQUID;

    let desc = Definite::from_str(&format!("ct(slip77({MBK}),elwpkh({PK}))")).unwrap();
    let spk = desc.descriptor.script_pubkey();
    let sk = MasterBlindingKey::from_str(MBK)
        .unwrap()
        .blinding_private_key(&spk)
        .unwrap();
    let addr = desc.address(&secp, params).unwrap();
    assert_eq!(addr.blinding_pubkey, Some(sk.public_key(&secp)));

    let view_key = "c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963";
    let desc = Definite::from_str(&format!("ct({view_key},elwpkh({PK}))")).unwrap();
    let sk = bare::tweak_private_key(&secp, &spk, &SecretKey::from_str(view_key).unwrap());
    let addr = desc.address(&secp, params).unwrap();
    assert_eq!(addr.blinding_pubkey, Some(sk.unwrap().public_key(&secp)));
}

#[test]
fn slip77_key_display() {
    let mbk = MasterBlindingKey::from_seed(b"abcd");
    assert_eq!(mbk.to_string(), MBK);
    assert_eq!(Key::Slip77(mbk).to_string(), format!("slip77({MBK})"));
    assert_eq!(MasterBlindingKey::from_str(MBK).unwrap(), mbk);
}

// Translating the keys of the script descriptor keeps the blinding key.
#[test]
fn translate_pk_keeps_blinding_key() {
    struct Named;

    impl Translator<String> for Named {
        type TargetPk = elements_miniscript::bitcoin::PublicKey;
        type Error = ();

        fn pk(&mut self, pk: &String) -> Result<Self::TargetPk, ()> {
            assert_eq!(pk, "A");
            Ok(elements_miniscript::bitcoin::PublicKey::from_str(PK).unwrap())
        }

        translate_hash_fail!(String, elements_miniscript::bitcoin::PublicKey, ());
    }

    let secp = Secp256k1::new();
    let named =
        confidential::Descriptor::<String>::from_str(&format!("ct(slip77({MBK}),elwpkh(A))"))
            .unwrap();
    let translated = named.translate_pk(&mut Named).unwrap();
    assert_eq!(translated.key, named.key);

    let direct = confidential::Descriptor::<elements_miniscript::bitcoin::PublicKey>::from_str(
        &format!("ct(slip77({MBK}),elwpkh({PK}))"),
    )
    .unwrap();
    assert_eq!(translated, direct);
    assert_eq!(
        translated.address(&secp, &AddressParams::LIQUID).unwrap(),
        direct.address(&secp, &AddressParams::LIQUID).unwrap()
    );
}
