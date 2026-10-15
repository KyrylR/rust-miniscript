// Written in 2023 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! ELIP-150 bare blinding keys
//!
//! A bare blinding key `K` is tweaked with the scriptPubKey of the output, giving
//! `K + H(K || scriptPubKey)G`. Here `H` is the BIP-340 tagged hash with tag
//! `CT-Blinding-Key/1.0` and the scriptPubKey is consensus encoded with its length prefix.

use bitcoin::hashes::{sha256t_hash_newtype, Hash, HashEngine};
use bitcoin::secp256k1;
use elements::encode::Encodable;
use elements::secp256k1_zkp;

use crate::ToPublicKey;

sha256t_hash_newtype! {
    /// The ELIP-150 tag `CT-Blinding-Key/1.0`
    pub struct BlindingKeyTag = hash_str("CT-Blinding-Key/1.0");
    /// The ELIP-150 tagged hash of a bare blinding key and a scriptPubKey
    #[hash_newtype(forward)]
    pub struct BlindingKeyHash(_);
}

/// Tweaks a bare blinding public key with the scriptPubKey of the output
///
/// # Errors
///
/// If the tagged hash is not below the curve order, or the tweaked key is the point at
/// infinity. Each happens with negligible probability.
pub fn tweak_key<Pk, V>(
    secp: &secp256k1_zkp::Secp256k1<V>,
    spk: &elements::Script,
    pk: &Pk,
) -> Result<secp256k1_zkp::PublicKey, secp256k1::Error>
where
    Pk: ToPublicKey,
    V: secp256k1_zkp::Verification,
{
    let pk = pk.to_public_key();
    pk.inner.add_exp_tweak(secp, &tweak(&pk, spk)?)
}

/// Tweaks a bare blinding private key with the scriptPubKey of the output
///
/// The result is the private key of [`tweak_key`] applied to the corresponding public key.
///
/// # Errors
///
/// If the tagged hash is not below the curve order, or the tweaked key is zero. Each happens
/// with negligible probability.
pub fn tweak_private_key<V>(
    secp: &secp256k1_zkp::Secp256k1<V>,
    spk: &elements::Script,
    sk: &secp256k1_zkp::SecretKey,
) -> Result<secp256k1_zkp::SecretKey, secp256k1::Error>
where
    V: secp256k1_zkp::Signing,
{
    let pk = bitcoin::PublicKey::new(sk.public_key(secp));
    sk.add_tweak(&tweak(&pk, spk)?)
}

fn tweak(
    pk: &bitcoin::PublicKey,
    spk: &elements::Script,
) -> Result<secp256k1_zkp::Scalar, secp256k1::Error> {
    let mut eng = BlindingKeyHash::engine();
    if pk.compressed {
        eng.input(&pk.inner.serialize());
    } else {
        eng.input(&pk.inner.serialize_uncompressed());
    }
    // Encoding fails only if writing does, and a hash engine accepts every write.
    spk.consensus_encode(&mut eng).expect("engines don't error");
    secp256k1_zkp::Scalar::from_be_bytes(BlindingKeyHash::from_engine(eng).to_byte_array())
        .map_err(|_| secp256k1::Error::InvalidTweak)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::sha256t::Tag;
    use bitcoin::hashes::{sha256, HashEngine};

    use super::*;

    const MIDSTATE_HASH_TO_PRIVATE_HASH: [u8; 32] = [
        0x2f, 0x85, 0x61, 0xec, 0x30, 0x88, 0xad, 0xa9, 0x5a, 0xe7, 0x43, 0xcd, 0x3c, 0x5f, 0x59,
        0x7d, 0xc0, 0x4b, 0xd0, 0x7f, 0x06, 0x5f, 0x1c, 0x06, 0x47, 0x89, 0x36, 0x63, 0xf3, 0x92,
        0x6e, 0x65,
    ];

    #[test]
    fn tagged_hash() {
        // Check that the cached midstate is computed correctly, as rust-bitcoin's
        // `tag_engine` test does for the BIP-340 tags
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(b"CT-Blinding-Key/1.0");
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(MIDSTATE_HASH_TO_PRIVATE_HASH, engine.midstate().to_byte_array());

        // Test empty hash
        assert_eq!(
            BlindingKeyHash::from_engine(BlindingKeyTag::engine()).to_string(),
            "d12a140aca856fbb917b931f263c42f064608985e2ce17ae5157daa17c55e8d9",
        );
        assert_eq!(
            BlindingKeyHash::hash(&[]).to_string(),
            "d12a140aca856fbb917b931f263c42f064608985e2ce17ae5157daa17c55e8d9",
        );

        // And hash of 80 bytes
        let data: Vec<u8> = (0..80).collect();
        assert_eq!(
            BlindingKeyHash::hash(&data).to_string(),
            "e1e52419a2934d278c50e29608969d2f23c1bd1243a09bfc8026d4ed4b085e39",
        );
    }

    #[test]
    fn tweak() {
        // Check that tweaking blinding keys produce consistent results
        let secp = secp256k1_zkp::Secp256k1::new();
        let sk = secp256k1_zkp::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk = sk.public_key(&secp);
        let spk = elements::Script::default();
        let tweaked_pk = tweak_key(&secp, &spk, &pk).unwrap();
        let tweaked_sk = tweak_private_key(&secp, &spk, &sk).unwrap();
        assert_eq!(tweaked_pk, tweaked_sk.public_key(&secp));
    }
}
