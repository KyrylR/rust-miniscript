// Written in 2020 by Rust Elements developers
// SPDX-License-Identifier: CC0-1.0

//! Dynamic Federation Pegin Descriptors
//!
//! After dynamic federations, the federation script is a `wsh()` or `sh(wsh())` Bitcoin
//! descriptor. Elements tweaks the keys that its witness script pushes with the claim script,
//! and leaves the keys of `pk_h` fragments, which the script only commits to by hash.

use core::fmt;
use core::str::FromStr;

use bitcoin::{Network, PublicKey, ScriptBuf, Weight};
use elements::secp256k1_zkp::{Secp256k1, Verification};

use super::{claim_script, federation_is_sh, split_args, tweak_federation, Error};
use crate::descriptor::{write_descriptor, NonDefiniteKeyError};
use crate::prelude::*;
use crate::{DescriptorPublicKey, FromStrKey, MiniscriptKey, ToPublicKey};

/// A pegin descriptor whose federation script is a Bitcoin descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Pegin<Pk: MiniscriptKey> {
    /// The untweaked Bitcoin federation descriptor
    pub fed_desc: bitcoin_miniscript::Descriptor<PublicKey>,
    /// The Elements descriptor that claims the pegin
    pub elem_desc: crate::Descriptor<Pk>,
}

impl<Pk: MiniscriptKey> Pegin<Pk> {
    /// Creates a pegin descriptor from a federation descriptor and a claim descriptor.
    pub fn new(
        fed_desc: bitcoin_miniscript::Descriptor<PublicKey>,
        elem_desc: crate::Descriptor<Pk>,
    ) -> Self {
        Self { fed_desc, elem_desc }
    }

    /// Computes an upper bound on the weight of a satisfying witness and scriptSig, as the
    /// federation descriptor's `max_weight_to_satisfy` does. Tweaking does not change key sizes.
    pub fn max_weight_to_satisfy(&self) -> Result<Weight, Error> {
        federation_is_sh(&self.fed_desc)?;
        Ok(self.fed_desc.max_weight_to_satisfy()?)
    }
}

impl Pegin<DescriptorPublicKey> {
    /// Derives the claim descriptor at `index`, as `Descriptor::derived_descriptor` does.
    pub fn derived_descriptor<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        index: u32,
    ) -> Result<Pegin<PublicKey>, NonDefiniteKeyError> {
        Ok(Pegin::new(
            self.fed_desc.clone(),
            self.elem_desc.derived_descriptor(secp, index)?,
        ))
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Pegin<Pk> {
    fn tweaked_federation<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<bitcoin_miniscript::Descriptor<PublicKey>, Error> {
        tweak_federation(&self.fed_desc, claim_script(&self.elem_desc)?.as_bytes(), secp)
    }

    /// Computes the Bitcoin address that pays to this pegin.
    pub fn bitcoin_address<C: Verification>(
        &self,
        network: Network,
        secp: &Secp256k1<C>,
    ) -> Result<bitcoin::Address, Error> {
        Ok(self.tweaked_federation(secp)?.address(network)?)
    }

    /// Computes the Bitcoin scriptPubKey that pays to this pegin.
    pub fn bitcoin_script_pubkey<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<ScriptBuf, Error> {
        Ok(self.tweaked_federation(secp)?.script_pubkey())
    }

    /// Computes the scriptSig of an unsigned input spending this pegin. It is empty for
    /// `wsh()` and pushes the witness program for `sh(wsh())`.
    pub fn bitcoin_unsigned_script_sig<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<ScriptBuf, Error> {
        Ok(self.tweaked_federation(secp)?.unsigned_script_sig())
    }

    /// Computes the federation witness script, with its keys tweaked by the claim script.
    pub fn bitcoin_witness_script<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<ScriptBuf, Error> {
        Ok(self.tweaked_federation(secp)?.explicit_script()?)
    }

    /// Returns a witness and scriptSig spending this pegin, if the satisfier has the
    /// signatures for the tweaked federation keys and any other data the script needs.
    pub fn get_bitcoin_satisfaction<S, C>(
        &self,
        secp: &Secp256k1<C>,
        satisfier: S,
    ) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: bitcoin_miniscript::Satisfier<PublicKey>,
        C: Verification,
    {
        Ok(self.tweaked_federation(secp)?.get_satisfaction(satisfier)?)
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Pegin<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pegin({:?},{:?})", self.fed_desc, self.elem_desc)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Pegin<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_descriptor!(f, "pegin({:#},{:#})", self.fed_desc, self.elem_desc)
    }
}

impl<Pk: FromStrKey> FromStr for Pegin<Pk> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let (fed, elem) = split_args(s, "pegin")?;
        Ok(Self::new(
            bitcoin_miniscript::Descriptor::from_str(fed)?,
            crate::Descriptor::from_str(elem)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hex::FromHex;
    use bitcoin::secp256k1::{Message, SecretKey};
    use bitcoin_miniscript::descriptor::DescriptorType;
    use bitcoin_miniscript::{Miniscript, Segwitv0};

    use super::*;
    use crate::confidential;

    /// Liquid's dynamic federation script at Elements block 2976078
    const LIQUID_FEDPEGSCRIPT: &str = "5b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc401021031c41fdbcebe17bec8d49816e00ca1b5ac34766b91c9f2ac37d39c63e5e008afb2103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5fae736402c00fb269522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae68";

    const CLAIM_DESC: &str = "ct(slip77(ab5824f4477b4ebb00a132adfd8eb0b7935cf24f6ac151add5d1913db374ce92),elwpkh([759db348/84'/1'/0']tpubDCRMaF33e44pcJj534LXVhFbHibPbJ5vuLhSSPFAw57kYURv4tzXFL6LSnd78bkjqdmE3USedkbpXJUPA1tdzKfuYSL7PianceqAhwL2UkA/0/*))";

    fn segwitv0(hex: &str) -> Miniscript<PublicKey, Segwitv0> {
        let script = ScriptBuf::from_hex(hex).unwrap();
        let ms = Miniscript::<PublicKey, Segwitv0>::decode(&script).unwrap();
        assert_eq!(ms.encode(), script);
        ms
    }

    fn liquid_fed_desc() -> bitcoin_miniscript::Descriptor<PublicKey> {
        bitcoin_miniscript::Descriptor::new_wsh(segwitv0(LIQUID_FEDPEGSCRIPT)).unwrap()
    }

    fn claim_desc() -> crate::Descriptor<DescriptorPublicKey> {
        CLAIM_DESC
            .parse::<confidential::Descriptor<DescriptorPublicKey>>()
            .unwrap()
            .descriptor
    }

    fn tweaked_address(
        fed: &bitcoin_miniscript::Descriptor<PublicKey>,
        claim_script: &str,
    ) -> String {
        let secp = Secp256k1::verification_only();
        let claim_script = Vec::<u8>::from_hex(claim_script).unwrap();
        tweak_federation(fed, &claim_script, &secp)
            .unwrap()
            .address(Network::Bitcoin)
            .unwrap()
            .to_string()
    }

    #[test]
    fn liquid_dynafed_pegin() {
        let fed = liquid_fed_desc();
        assert_eq!(fed.to_string(), "wsh(or_d(multi(11,020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261,02675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af99,02896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d48,029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c,02a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc4010,031c41fdbcebe17bec8d49816e00ca1b5ac34766b91c9f2ac37d39c63e5e008afb,03079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b,03111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2,0318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa0840174,03230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de1,035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a6,03bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c,03cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d17546,03d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d424828,03ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a),and_v(v:older(4032),multi(2,03aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79,0291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807,0386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb))))#7jwwklk4");

        // `elements-cli getpeginaddress` on Liquid with this federation script
        assert_eq!(
            tweaked_address(&fed, "0014a15906e643f2c9635527ab8658d370e8eaf149b5"),
            "bc1qyya0twwz58kgfslpdgsygeq0r4nngl9tkt89v6phk8nqrwyenwrq5h0dk8"
        );
        assert_eq!(
            tweaked_address(&fed, "0014de8e299d5347503f7ee33247e780b7f412727623"),
            "bc1qssx7ha3zxpq25l6uukphlwj3jumvmcv8qr3dy6uy8l8j4vwa5fhswpcw3p"
        );

        let secp = Secp256k1::verification_only();
        let elem_desc = claim_desc().derived_descriptor(&secp, 0).unwrap();
        let pegin = Pegin::new(fed.clone(), elem_desc);
        assert_eq!(
            pegin.to_string(),
            format!(
                "pegin({:#},elwpkh(0321da398ca2ddc09be89caa26e6730ae84751b6ea3a1ca46aa365bb5e1c3d9620))#qp4fan9q",
                fed
            )
        );
        assert_eq!(pegin.to_string().parse::<Pegin<PublicKey>>().unwrap(), pegin);
    }

    // From the "Elements 0.14 Daemon example" in Elements test/functional/rpc_tweakfedpeg.py,
    // where every key of a 2-of-2 federation script is tweaked.
    #[test]
    fn tweakfedpegscript_vector() {
        let secp = Secp256k1::verification_only();
        let fed = bitcoin_miniscript::Descriptor::new_wsh(segwitv0("52210307fd375ed7cced0f50723e3e1a97bbe7ccff7318c815df4e99a59bc94dbcd819210367c4f666f18279009c941e57fab3e42653c6553e5ca092c104d1db279e328a2852ae")).unwrap();
        let claim_script =
            Vec::<u8>::from_hex("0014008b1fdbaec5a82a9322af1640e871727245bce1").unwrap();
        assert_eq!(
            tweak_federation(&fed, &claim_script, &secp).unwrap().explicit_script().unwrap(),
            ScriptBuf::from_hex("522102f5bc6bc407187d06854005c366b84b411534757f4503587cf335645a620f896a2102fd90164e4e7d53417e4eacfa3f86fd39fe40594791758739e8af31eeea4e79c552ae").unwrap()
        );
    }

    // From Elements src/test/pegin_witness_tests.cpp, where a P2SH-P2WSH federation script
    // is paid by the funding output of a valid pegin witness.
    #[test]
    fn pegin_witness_vector() {
        let secp = Secp256k1::verification_only();
        let fed = bitcoin_miniscript::Descriptor::new_sh_wsh(segwitv0(
            "512103dff4923d778550cc13ce0d887d737553b4b58f4e8e886507fc39f5e447b2186451ae",
        ))
        .unwrap();
        let claim_script =
            Vec::<u8>::from_hex("00141eef6361cd1507a303834285d1521d6baf1b19ae").unwrap();
        assert_eq!(
            tweak_federation(&fed, &claim_script, &secp)
                .unwrap()
                .script_pubkey(),
            ScriptBuf::from_hex("a914cb60b1d7f76ba12b45a116c482c165a74c5d7e3887").unwrap()
        );
    }

    #[test]
    fn pegin_derive() {
        let pegin = Pegin::new(liquid_fed_desc(), claim_desc());
        let secp = Secp256k1::verification_only();

        let address_0 = pegin
            .derived_descriptor(&secp, 0)
            .unwrap()
            .bitcoin_address(Network::Bitcoin, &secp)
            .unwrap();
        assert_eq!(
            address_0.to_string(),
            "bc1qqkq6czql4zqwsylgrfzttjrn5wjeqmwfq5yn80p39amxtnkng9lsn6c5qr"
        );

        let address_1 = pegin
            .derived_descriptor(&secp, 1)
            .unwrap()
            .bitcoin_address(Network::Bitcoin, &secp)
            .unwrap();
        assert_eq!(
            address_1.to_string(),
            "bc1qmevs3n40t394230lptclz55rmxkmr7dmnqhuflxf0cezdupsmvdsk25n3m"
        );
    }

    #[test]
    fn unsupported_federation() {
        let secp = Secp256k1::verification_only();
        let pk = "020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261";
        let pegin =
            Pegin::<PublicKey>::from_str(&format!("pegin(pkh({pk}),elwpkh({pk}))")).unwrap();
        assert!(matches!(
            pegin.bitcoin_address(Network::Bitcoin, &secp),
            Err(Error::UnsupportedFederation(DescriptorType::Pkh))
        ));
        assert!(matches!(
            pegin.bitcoin_witness_script(&secp),
            Err(Error::UnsupportedFederation(DescriptorType::Pkh))
        ));
        assert!(matches!(
            pegin.max_weight_to_satisfy(),
            Err(Error::UnsupportedFederation(DescriptorType::Pkh))
        ));

        let other = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        for (fed, ty) in [
            (format!("wsh(sortedmulti(1,{pk},{other}))"), DescriptorType::WshSortedMulti),
            (
                format!("sh(wsh(sortedmulti(1,{pk},{other})))"),
                DescriptorType::ShWshSortedMulti,
            ),
        ] {
            let pegin =
                Pegin::<PublicKey>::from_str(&format!("pegin({fed},elwpkh({pk}))")).unwrap();
            assert!(matches!(
                pegin.bitcoin_witness_script(&secp),
                Err(Error::UnsupportedFederation(t)) if t == ty
            ));
        }
    }

    fn secret_key(i: u8) -> SecretKey { SecretKey::from_slice(&[i; 32]).unwrap() }

    fn public_key(i: u8) -> PublicKey {
        PublicKey::new(secret_key(i).public_key(&Secp256k1::signing_only()))
    }

    // Keys 1 and 2 tweaked by the scriptPubKey of `elwpkh` with key 8, where key `i` has the
    // secret key of 32 bytes `i`
    const TWEAKED_KEY_1: &str =
        "03697be2c05c7c53ef4a5bced2cb00bb61e101148c183569c1cac78221efd3c570";
    const TWEAKED_KEY_2: &str =
        "036ef7839636ce22279f3e43b36140252e43174d5c10376db69ef9b9a37a82a789";

    /// A pegin to `elwpkh` with key 8, whose `wsh()` federation may repeat a key
    fn pegin_to_key_8(fed: &str) -> Pegin<PublicKey> {
        let ms = Miniscript::<PublicKey, Segwitv0>::from_str_insane(fed).unwrap();
        Pegin::new(
            bitcoin_miniscript::Descriptor::new_wsh(ms).unwrap(),
            crate::Descriptor::new_wpkh(public_key(8)).unwrap(),
        )
    }

    fn signature(i: u8) -> bitcoin::ecdsa::Signature {
        let secp = Secp256k1::signing_only();
        let sig = secp.sign_ecdsa(&Message::from_digest([i; 32]), &secret_key(i));
        bitcoin::ecdsa::Signature::sighash_all(sig)
    }

    // Witness scripts from `elements-cli tweakfedpegscript <claim script> <federation script>`
    // on Elements 23.3.1, with the scriptPubKey of `elwpkh` with key 8 as the claim script.
    // Elements tweaks the pushed keys of `multi`, and `pkh` pushes no key.
    #[test]
    fn elements_node_vectors() {
        let secp = Secp256k1::verification_only();
        assert_eq!(
            public_key(1).to_string(),
            "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
        );
        assert_eq!(
            public_key(2).to_string(),
            "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"
        );

        for (fed, expected) in [
            (
                format!("pkh({})", public_key(1)),
                "76a91479b000887626b294a914501a4cd226b58b23598388ac".to_owned(),
            ),
            (
                format!("multi(1,{},{})", public_key(1), public_key(2)),
                format!("5121{TWEAKED_KEY_1}21{TWEAKED_KEY_2}52ae"),
            ),
        ] {
            assert_eq!(
                pegin_to_key_8(&fed).bitcoin_witness_script(&secp).unwrap(),
                ScriptBuf::from_hex(&expected).unwrap(),
                "{}",
                fed
            );
        }
    }

    struct Sigs(Vec<(PublicKey, bitcoin::ecdsa::Signature)>);

    impl bitcoin_miniscript::Satisfier<PublicKey> for Sigs {
        fn lookup_ecdsa_sig(&self, pk: &PublicKey) -> Option<bitcoin::ecdsa::Signature> {
            self.0
                .iter()
                .find(|(key, _)| key == pk)
                .map(|(_, sig)| *sig)
        }

        fn check_older(&self, _: bitcoin::relative::LockTime) -> bool { true }
    }

    // Only the pushed key of `pk` is tweaked. The `pkh` key keeps its hash and still signs
    // with the untweaked key.
    #[test]
    fn pkh_keys_are_not_tweaked() {
        let secp = Secp256k1::verification_only();
        let (key_1, key_2) = (public_key(1), public_key(2));
        let pegin = pegin_to_key_8(&format!("or_d(pk({key_1}),and_v(v:pkh({key_2}),older(144)))"));
        let expected =
            pegin_to_key_8(&format!("or_d(pk({TWEAKED_KEY_1}),and_v(v:pkh({key_2}),older(144)))"));
        let witness_script = expected.fed_desc.explicit_script().unwrap();
        assert_eq!(pegin.bitcoin_witness_script(&secp).unwrap(), witness_script);

        let sigs = Sigs(vec![(key_2, signature(2))]);
        let (witness, _) = pegin.get_bitcoin_satisfaction(&secp, sigs).unwrap();
        assert_eq!(
            witness,
            vec![
                signature(2).to_vec(),
                key_2.to_bytes(),
                vec![],
                witness_script.into_bytes()
            ]
        );
    }

    // A key in both `pk` and `pkh` is tweaked only where the script pushes it, and the `pkh`
    // branch is still satisfied with the untweaked key.
    #[test]
    fn same_key_in_pk_and_pkh() {
        let secp = Secp256k1::verification_only();
        let key = public_key(1);
        let pegin = pegin_to_key_8(&format!("or_d(pk({key}),and_v(v:pkh({key}),older(144)))"));
        let expected =
            pegin_to_key_8(&format!("or_d(pk({TWEAKED_KEY_1}),and_v(v:pkh({key}),older(144)))"));
        let claim_script = claim_script(&pegin.elem_desc).unwrap();
        let tweaked = tweak_federation(&pegin.fed_desc, claim_script.as_bytes(), &secp).unwrap();
        assert_eq!(tweaked, expected.fed_desc);

        let sigs = Sigs(vec![(key, signature(1))]);
        let (witness, _) = pegin.get_bitcoin_satisfaction(&secp, sigs).unwrap();
        let witness_script = tweaked.explicit_script().unwrap().into_bytes();
        assert_eq!(
            witness,
            vec![
                signature(1).to_vec(),
                key.to_bytes(),
                vec![],
                witness_script
            ]
        );
    }

    // With only a signature for the tweaked key, the `pkh` fragment is dissatisfied with an
    // empty signature and the untweaked key, and the `pk` branch is satisfied.
    #[test]
    fn pkh_dissatisfaction() {
        let secp = Secp256k1::verification_only();
        let key = public_key(1);
        let pegin = pegin_to_key_8(&format!("or_d(pkh({key}),and_v(v:pk({key}),older(144)))"));
        let expected =
            pegin_to_key_8(&format!("or_d(pkh({key}),and_v(v:pk({TWEAKED_KEY_1}),older(144)))"));
        let witness_script = expected.fed_desc.explicit_script().unwrap();
        assert_eq!(pegin.bitcoin_witness_script(&secp).unwrap(), witness_script);

        let sigs = Sigs(vec![(PublicKey::from_str(TWEAKED_KEY_1).unwrap(), signature(1))]);
        let (witness, _) = pegin.get_bitcoin_satisfaction(&secp, sigs).unwrap();
        assert_eq!(
            witness,
            vec![
                signature(1).to_vec(),
                vec![],
                key.to_bytes(),
                witness_script.into_bytes()
            ]
        );
    }
}
