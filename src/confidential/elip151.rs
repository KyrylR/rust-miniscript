// Written in 2023 by Leonardo Comandini
// SPDX-License-Identifier: CC0-1.0

//! ELIP-151
//!
//! Deterministic descriptor blinding keys, documented at
//! <https://github.com/ElementsProject/ELIPs/blob/main/elip-0151.mediawiki>

use bitcoin::hashes::{sha256t_hash_newtype, Hash, HashEngine};
use bitcoin::NetworkKind;
use elements::encode::Encodable;
use elements::opcodes;
use elements::secp256k1_zkp::{Secp256k1, SecretKey};

use super::{multipath_len_mismatch, Descriptor, Error, Key};
use crate::descriptor::{DescriptorSecretKey, SinglePriv};
use crate::DescriptorPublicKey;

sha256t_hash_newtype! {
    /// The ELIP-151 tag `Deterministic-View-Key/1.0`
    pub struct Elip151Tag = hash_str("Deterministic-View-Key/1.0");
    /// The ELIP-151 tagged hash of the scriptPubKeys of a descriptor
    #[hash_newtype(forward)]
    pub struct Elip151Hash(_);
}

impl Key {
    /// Derives the ELIP-151 view key of a descriptor.
    ///
    /// # Errors
    ///
    /// - [`Error::NonDefiniteKey`] with [`NoWildcard`] if the descriptor has no wildcard.
    /// - [`Error::NonDefiniteKey`] with [`HardenedStep`] if a key derives through a hardened
    ///   step, either a fixed step or a hardened wildcard.
    /// - [`Error::Descriptor`] with [`crate::Error::MultipathDescLenMismatch`] if multi-path
    ///   keys have different numbers of paths.
    /// - [`Error::BlindingKeyDerivation`] if the tagged hash is zero or not below the curve
    ///   order, which happens with negligible probability.
    ///
    /// [`NoWildcard`]: crate::descriptor::NonDefiniteKeyError::NoWildcard
    /// [`HardenedStep`]: crate::descriptor::NonDefiniteKeyError::HardenedStep
    pub fn from_elip151(
        descriptor: &crate::Descriptor<DescriptorPublicKey>,
    ) -> Result<Self, Error> {
        if multipath_len_mismatch(descriptor) {
            return Err(Error::Descriptor(crate::Error::MultipathDescLenMismatch));
        }

        let secp = Secp256k1::verification_only();
        let mut eng = Elip151Hash::engine();
        for descriptor in descriptor.clone().into_single_descriptors()? {
            // The last unhardened index, which wallets do not use for addresses
            let script_pubkey = descriptor
                .derive_at_index((1 << 31) - 1)
                .into_result()?
                .derived_descriptor(&secp)
                .script_pubkey();
            // The encoded script `OP_INVALIDOPCODE`, its length then the opcode
            eng.input(&[1, opcodes::all::OP_INVALIDOPCODE.into_u8()]);
            // Encoding fails only if writing does, and a hash engine accepts every write.
            script_pubkey
                .consensus_encode(&mut eng)
                .expect("engines don't error");
        }

        let secret_key = SecretKey::from_slice(&Elip151Hash::from_engine(eng).to_byte_array())
            .map_err(Error::BlindingKeyDerivation)?;
        // Single view keys are displayed as hex, so the network is not used
        Ok(Self::View(DescriptorSecretKey::Single(SinglePriv {
            origin: None,
            key: bitcoin::PrivateKey::new(secret_key, NetworkKind::Main),
        })))
    }
}

impl Descriptor<DescriptorPublicKey> {
    /// Creates a confidential descriptor whose blinding key is the ELIP-151 view key of
    /// `descriptor`.
    ///
    /// # Errors
    ///
    /// As for [`Key::from_elip151`].
    pub fn with_elip151_descriptor_blinding_key(
        descriptor: crate::Descriptor<DescriptorPublicKey>,
    ) -> Result<Self, Error> {
        Ok(Self { key: Key::from_elip151(&descriptor)?, descriptor })
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use bitcoin::hashes::sha256t::Tag;
    use bitcoin::hashes::{sha256, HashEngine};

    use super::*;
    use crate::descriptor::NonDefiniteKeyError;

    /// The SHA-256 initial midstate value for the [`Elip151Hash`].
    const MIDSTATE_ELIP151: [u8; 32] = [
        0x49, 0x81, 0x61, 0xd8, 0x52, 0x45, 0xf7, 0xaa, 0xd8, 0x24, 0x27, 0xb5, 0x64, 0x69, 0xe7,
        0xd6, 0x98, 0x17, 0xeb, 0x0f, 0x27, 0x14, 0x6f, 0x4e, 0x7b, 0x95, 0xb3, 0x6e, 0x46, 0xc1,
        0xb5, 0x61,
    ];

    const XPUB: &str = "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8";

    #[test]
    fn tagged_hash_elip151() {
        // Check that cached midstate is computed correctly, code from rust-bitcoin
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(b"Deterministic-View-Key/1.0");
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(MIDSTATE_ELIP151, engine.midstate().to_byte_array());

        // Test empty hash
        let expected = "dcd8403dcf5af960f69fa41d114931a840877dfb5378046018f78ea894a36ebd";
        assert_eq!(Elip151Hash::from_engine(Elip151Tag::engine()).to_string(), expected);
        assert_eq!(Elip151Hash::hash(&[]).to_string(), expected);
    }

    fn confidential_descriptor(desc: &str) -> Result<Descriptor<DescriptorPublicKey>, Error> {
        let desc = crate::Descriptor::<DescriptorPublicKey>::from_str(desc)?;
        Descriptor::with_elip151_descriptor_blinding_key(desc)
    }

    // ELIP-151 test vectors
    #[test]
    fn test_vectors_elip151() {
        let pubkey = "03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494";

        for (desc, key) in [
            (
                format!("elwpkh({XPUB}/<0;1>/*)"),
                "b3baf94d60cf8423cd257283575997a2c00664ced3e8de00f8726703142b1989",
            ),
            (
                format!("elwpkh({XPUB}/0/*)"),
                "de9c5fb624154624146a8aea0489b30f05c720eed6b493b1f3ab63405a11bf37",
            ),
            (
                format!("elwsh(multi(2,{XPUB}/<0;1>/*,{XPUB}/0/<0;1>/*))"),
                "7fcc1b9a20bbf611d157016192a7d28e353033cfa6a4885b3c48fa5ff9ce1881",
            ),
            (
                format!("elwsh(multi(2,{XPUB}/<0;1>/*,{XPUB}/0/<1;2>/*))"),
                "ff0a08050417f0ca95fb6ef7df979ae464739cb79b8c8f4b05408e0ac681a527",
            ),
        ] {
            let conf_desc = confidential_descriptor(&desc).unwrap();
            let conf_desc_elip151 =
                Descriptor::<DescriptorPublicKey>::from_str(&format!("ct(elip151,{})", desc))
                    .unwrap();
            assert_eq!(conf_desc, conf_desc_elip151);
            assert_eq!(conf_desc.key.to_string(), key);
        }

        for desc in [format!("elwpkh({XPUB})"), format!("elwpkh({pubkey})")] {
            assert!(matches!(
                confidential_descriptor(&desc),
                Err(Error::NonDefiniteKey(NonDefiniteKeyError::NoWildcard))
            ));
        }
        assert!(matches!(
            confidential_descriptor(&format!("elwsh(multi(2,{XPUB}/<0;1>/*,{XPUB}/0/<0;1;2>/*))")),
            Err(Error::Descriptor(crate::Error::MultipathDescLenMismatch))
        ));
    }

    // Mismatching multi-path lengths are invalid whichever list is longer. The first
    // case is ELIP-151 invalid test vector 3. The second has the longer list first,
    // as in the second comment on elements-miniscript issue #107.
    #[test]
    fn elip151_multipath_length_mismatch() {
        for desc in [
            format!("ct(elip151,elwsh(multi(2,{XPUB}/<0;1>/*,{XPUB}/0/<0;1;2>/*)))#gkrp8f5z"),
            format!("ct(elip151,elwsh(multi(2,{XPUB}/<0;1;2>/*,{XPUB}/0/<0;1>/*)))"),
            format!("ct(elip151,eltr({XPUB}/<0;1>/*,pk({XPUB}/2/<0;1;2>/*)))"),
        ] {
            let err = Descriptor::<DescriptorPublicKey>::from_str(&desc).unwrap_err();
            assert!(
                matches!(err, Error::Descriptor(crate::Error::MultipathDescLenMismatch)),
                "{}: {:?}",
                desc,
                err
            );
        }

        let desc = crate::Descriptor::<DescriptorPublicKey>::from_str(&format!(
            "eltr({XPUB}/<0;1>/*,pk({XPUB}/2/<0;1;2>/*))"
        ))
        .unwrap();
        assert!(matches!(
            Key::from_elip151(&desc),
            Err(Error::Descriptor(crate::Error::MultipathDescLenMismatch))
        ));
    }

    // Public keys cannot be derived through hardened steps, so ELIP-151 derivation
    // fails for each case. The cases cover a hardened wildcard in both spellings and
    // in a multi-path key, a hardened fixed step, and the multi-path key with a
    // hardened step from the first comment on elements-miniscript issue #107.
    #[test]
    fn elip151_hardened_derivation() {
        let tpub1 = "[759db348/84'/1'/0']tpubDCRMaF33e44pcJj534LXVhFbHibPbJ5vuLhSSPFAw57kYURv4tzXFL6LSnd78bkjqdmE3USedkbpXJUPA1tdzKfuYSL7PianceqAhwL2UkA";
        let tpub2 = "tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu";

        for desc in [
            format!("elwpkh({XPUB}/0/*h)"),
            format!("elwpkh({XPUB}/0/*')"),
            format!("elwpkh({XPUB}/0h/*)"),
            format!("elwpkh({XPUB}/<0;1>/*h)"),
            format!("elwsh(multi(2,{tpub1}/<0';7>/*,{tpub2}/<0;1>/*))"),
        ] {
            let err = Descriptor::<DescriptorPublicKey>::from_str(&format!("ct(elip151,{desc})"))
                .unwrap_err();
            assert!(
                matches!(err, Error::NonDefiniteKey(NonDefiniteKeyError::HardenedStep)),
                "{}: {:?}",
                desc,
                err
            );
        }
    }
}
