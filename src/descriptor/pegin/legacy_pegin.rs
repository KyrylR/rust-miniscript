// Written in 2018 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Legacy Pegin Descriptors
//!
//! A legacy pegin pays to the Liquid v1 watchman script, which is not Miniscript:
//!
//! `OP_DEPTH <k+1> OP_EQUAL OP_IF <k> <federation keys> <n> OP_ELSE <timelock> OP_CSV OP_DROP
//! <k'> <emergency keys> <n'> OP_ENDIF OP_CHECKMULTISIG`
//!
//! Elements recognizes this template only if `k` and `k'` differ. It then tweaks the
//! federation keys with the claim script and uses the emergency keys as they are. The
//! descriptor writes the federation as the Miniscript with the same spending conditions,
//! `or_d(multi(k,...),and_v(v:older(timelock),multi(k',...)))`. Each key carries an `f`
//! (functionary) or `u` (non-functionary) prefix, which does not change the script.

use core::str::FromStr;
use core::{cmp, fmt};
#[cfg(feature = "std")]
use std::error;

use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::opcodes::all::{
    OP_CHECKMULTISIG, OP_CSV, OP_DEPTH, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_IF,
};
use bitcoin::{script, CompressedPublicKey, Network, PublicKey, Script, ScriptBuf, Weight};
use bitcoin_miniscript::miniscript::limits::MAX_PUBKEYS_PER_MULTISIG;
use bitcoin_miniscript::policy::{semantic, Liftable};
use bitcoin_miniscript::{Miniscript, RelLockTime, Segwitv0, Terminal, Threshold};
use elements::secp256k1_zkp::{Secp256k1, Verification};
use sync::Arc;

use super::{claim_script, split_args, tweak_key, Error};
use crate::descriptor::write_descriptor;
use crate::prelude::*;
use crate::util::varint_len;
use crate::{FromStrKey, MiniscriptKey, ToPublicKey};

/// A key of a legacy pegin federation script
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegacyPeginKey {
    /// A functionary key, written with an `f` prefix
    Functionary(CompressedPublicKey),
    /// A non-functionary key, written with a `u` prefix
    NonFunctionary(CompressedPublicKey),
}

impl LegacyPeginKey {
    /// The key as written, before any claim script tweak
    pub fn as_untweaked(&self) -> &CompressedPublicKey {
        match self {
            Self::Functionary(pk) | Self::NonFunctionary(pk) => pk,
        }
    }
}

impl FromStr for LegacyPeginKey {
    type Err = LegacyPeginKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let error = || LegacyPeginKeyError;
        let key = if let Some(key) = s.strip_prefix('f') {
            CompressedPublicKey::from_str(key).map(Self::Functionary)
        } else if let Some(key) = s.strip_prefix('u') {
            CompressedPublicKey::from_str(key).map(Self::NonFunctionary)
        } else {
            return Err(error());
        };
        key.map_err(|_| error())
    }
}

impl fmt::Display for LegacyPeginKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Functionary(pk) => write!(f, "f{}", pk),
            Self::NonFunctionary(pk) => write!(f, "u{}", pk),
        }
    }
}

impl bitcoin_miniscript::MiniscriptKey for LegacyPeginKey {
    type Sha256 = sha256::Hash;
    type Hash256 = bitcoin_miniscript::hash256::Hash;
    type Ripemd160 = ripemd160::Hash;
    type Hash160 = hash160::Hash;

    fn is_uncompressed(&self) -> bool { false }

    fn is_x_only_key(&self) -> bool { false }

    fn num_der_paths(&self) -> usize { 0 }
}

/// An error parsing a [`LegacyPeginKey`], which is `f` or `u` followed by a compressed
/// public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyPeginKeyError;

impl fmt::Display for LegacyPeginKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("legacy pegin key must be f or u followed by a compressed public key")
    }
}

#[cfg(feature = "std")]
impl error::Error for LegacyPeginKeyError {}

/// A legacy pegin descriptor, for the Liquid v1 watchman federation script
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct LegacyPegin<Pk: MiniscriptKey> {
    /// The federation threshold
    fed: Threshold<LegacyPeginKey, MAX_PUBKEYS_PER_MULTISIG>,
    /// The emergency threshold
    emer: Threshold<LegacyPeginKey, MAX_PUBKEYS_PER_MULTISIG>,
    /// The timelock of the emergency keys
    timelock: RelLockTime,
    /// The Elements descriptor that claims the pegin
    pub desc: crate::Descriptor<Pk>,
    /// The federation as Miniscript, for display and lifting
    ms: Miniscript<LegacyPeginKey, Segwitv0>,
}

impl<Pk: MiniscriptKey> LegacyPegin<Pk> {
    /// Creates a legacy pegin descriptor from the federation and emergency thresholds, the
    /// emergency timelock and the Elements claim descriptor.
    ///
    /// # Errors
    ///
    /// [`Error::EqualLegacyThresholds`] if both thresholds have the same `k`, which Elements
    /// `MatchLiquidWatchman` rejects.
    pub fn new(
        fed: Threshold<LegacyPeginKey, MAX_PUBKEYS_PER_MULTISIG>,
        emer: Threshold<LegacyPeginKey, MAX_PUBKEYS_PER_MULTISIG>,
        timelock: RelLockTime,
        desc: crate::Descriptor<Pk>,
    ) -> Result<Self, Error> {
        if fed.k() == emer.k() {
            return Err(Error::EqualLegacyThresholds(fed.k()));
        }
        let fragment = Miniscript::<LegacyPeginKey, Segwitv0>::from_ast;
        let older = fragment(Terminal::Verify(Arc::new(fragment(Terminal::Older(timelock))?)))?;
        let emer_ms = fragment(Terminal::Multi(emer.clone()))?;
        let emergency = fragment(Terminal::AndV(Arc::new(older), Arc::new(emer_ms)))?;
        let fed_ms = fragment(Terminal::Multi(fed.clone()))?;
        let ms = fragment(Terminal::OrD(Arc::new(fed_ms), Arc::new(emergency)))?;
        Ok(Self { fed, emer, timelock, desc, ms })
    }

    fn from_ms_and_desc(
        desc: crate::Descriptor<Pk>,
        ms: Miniscript<LegacyPeginKey, Segwitv0>,
    ) -> Result<Self, Error> {
        let Terminal::OrD(ref fed, ref emergency) = ms.node else {
            return Err(Error::UnexpectedLegacyMiniscript);
        };
        let (Terminal::Multi(fed), Terminal::AndV(older, emer)) = (&fed.node, &emergency.node)
        else {
            return Err(Error::UnexpectedLegacyMiniscript);
        };
        let (Terminal::Verify(older), Terminal::Multi(emer)) = (&older.node, &emer.node) else {
            return Err(Error::UnexpectedLegacyMiniscript);
        };
        let Terminal::Older(timelock) = older.node else {
            return Err(Error::UnexpectedLegacyMiniscript);
        };
        Self::new(fed.clone(), emer.clone(), timelock, desc)
    }

    /// Builds the watchman script with the given federation keys.
    fn witness_script_with(&self, fed_keys: impl IntoIterator<Item = PublicKey>) -> ScriptBuf {
        let mut builder = script::Builder::new()
            .push_opcode(OP_DEPTH)
            .push_int(self.fed.k() as i64 + 1)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_int(self.fed.k() as i64);
        for key in fed_keys {
            builder = builder.push_key(&key);
        }
        builder = builder
            .push_int(self.fed.n() as i64)
            .push_opcode(OP_ELSE)
            .push_int(i64::from(self.timelock.to_consensus_u32()))
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_int(self.emer.k() as i64);
        for key in public_keys(&self.emer) {
            builder = builder.push_key(&key);
        }
        builder
            .push_int(self.emer.n() as i64)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    /// The federation keys tweaked by the claim script
    fn tweaked_fed_keys<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        claim_script: &[u8],
    ) -> Result<Vec<PublicKey>, Error> {
        public_keys(&self.fed)
            .map(|key| tweak_key(secp, &key, claim_script))
            .collect()
    }

    /// Computes an upper bound on the weight of a satisfying witness and scriptSig, as
    /// `max_weight_to_satisfy` does for an `sh(wsh())` descriptor. Assumes all signatures are
    /// 73 bytes, including the length prefix and sighash suffix.
    pub fn max_weight_to_satisfy(&self) -> Weight {
        // Tweaking does not change key sizes, so the untweaked script has the same length.
        let script_size = self.witness_script_with(public_keys(&self.fed)).len();
        let sigs = cmp::max(self.fed.k(), self.emer.k());
        // The witness is an empty element, the signatures and the witness script.
        let witness_size = varint_len(sigs + 2) - varint_len(0)
            + 1
            + 73 * sigs
            + varint_len(script_size)
            + script_size;
        // scriptSig: OP_PUSHBYTES_34 <OP_0 OP_PUSHBYTES_32 <32-byte hash>>
        Weight::from_wu((4 * 35 + witness_size) as u64)
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> LegacyPegin<Pk> {
    /// Computes the watchman witness script, with the federation keys tweaked by the claim
    /// script.
    pub fn bitcoin_witness_script<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<ScriptBuf, Error> {
        let fed_keys = self.tweaked_fed_keys(secp, claim_script(&self.desc)?.as_bytes())?;
        Ok(self.witness_script_with(fed_keys))
    }

    /// Computes the `sh(wsh())` Bitcoin address that pays to this pegin.
    pub fn bitcoin_address<C: Verification>(
        &self,
        network: Network,
        secp: &Secp256k1<C>,
    ) -> Result<bitcoin::Address, Error> {
        Ok(bitcoin::Address::p2shwsh(&self.bitcoin_witness_script(secp)?, network))
    }

    /// Computes the Bitcoin scriptPubKey that pays to this pegin.
    pub fn bitcoin_script_pubkey<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<ScriptBuf, Error> {
        Ok(self.bitcoin_witness_script(secp)?.to_p2wsh().to_p2sh())
    }

    /// Computes the scriptSig of an input spending this pegin, which pushes the P2WSH
    /// witness program.
    pub fn bitcoin_unsigned_script_sig<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<ScriptBuf, Error> {
        Ok(p2sh_wsh_script_sig(&self.bitcoin_witness_script(secp)?))
    }

    /// Returns a witness and scriptSig spending this pegin.
    ///
    /// Uses `k` federation signatures if the satisfier has them, and otherwise the emergency
    /// signatures if the satisfier reports that the timelock has passed. The witness starts
    /// with the empty element that `OP_CHECKMULTISIG` consumes, then has the signatures in key
    /// order and ends with the witness script.
    pub fn get_bitcoin_satisfaction<S, C>(
        &self,
        secp: &Secp256k1<C>,
        satisfier: S,
    ) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: bitcoin_miniscript::Satisfier<PublicKey>,
        C: Verification,
    {
        let fed_keys = self.tweaked_fed_keys(secp, claim_script(&self.desc)?.as_bytes())?;
        let sigs = match signatures(&satisfier, fed_keys.iter().copied(), self.fed.k()) {
            Some(sigs) => sigs,
            None if satisfier.check_older(self.timelock.into()) => {
                signatures(&satisfier, public_keys(&self.emer), self.emer.k())
                    .ok_or(Error::Bitcoin(bitcoin_miniscript::Error::CouldNotSatisfy))?
            }
            None => return Err(Error::Bitcoin(bitcoin_miniscript::Error::CouldNotSatisfy)),
        };

        let witness_script = self.witness_script_with(fed_keys);
        let script_sig = p2sh_wsh_script_sig(&witness_script);
        let mut witness = Vec::with_capacity(sigs.len() + 2);
        witness.push(vec![]);
        witness.extend(sigs);
        witness.push(witness_script.into_bytes());
        Ok((witness, script_sig))
    }
}

/// The keys of a threshold, as written
fn public_keys(
    thresh: &Threshold<LegacyPeginKey, MAX_PUBKEYS_PER_MULTISIG>,
) -> impl Iterator<Item = PublicKey> + '_ {
    thresh
        .iter()
        .map(|key| PublicKey::from(*key.as_untweaked()))
}

/// Looks up the signatures of the first `k` of `keys` that have one, in key order.
fn signatures<S: bitcoin_miniscript::Satisfier<PublicKey>>(
    satisfier: &S,
    keys: impl Iterator<Item = PublicKey>,
    k: usize,
) -> Option<Vec<Vec<u8>>> {
    let sigs: Vec<_> = keys
        .filter_map(|key| satisfier.lookup_ecdsa_sig(&key))
        .take(k)
        .map(|sig| sig.to_vec())
        .collect();
    if sigs.len() == k {
        Some(sigs)
    } else {
        None
    }
}

/// The P2SH-P2WSH scriptSig, a push of the witness program
fn p2sh_wsh_script_sig(witness_script: &Script) -> ScriptBuf {
    let mut witness_program = [0; 34];
    witness_program[1] = 32;
    witness_program[2..].copy_from_slice(&witness_script.wscript_hash()[..]);
    script::Builder::new()
        .push_slice(witness_program)
        .into_script()
}

impl<Pk: MiniscriptKey> fmt::Debug for LegacyPegin<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "legacy_pegin({:?},{:?})", self.ms, self.desc)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for LegacyPegin<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_descriptor!(f, "legacy_pegin({},{:#})", self.ms, self.desc)
    }
}

impl<Pk: MiniscriptKey> Liftable<LegacyPeginKey> for LegacyPegin<Pk> {
    fn lift(&self) -> Result<semantic::Policy<LegacyPeginKey>, bitcoin_miniscript::Error> {
        self.ms.lift()
    }
}

impl<Pk: FromStrKey> FromStr for LegacyPegin<Pk> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let (ms, desc) = split_args(s, "legacy_pegin")?;
        Self::from_ms_and_desc(crate::Descriptor::from_str(desc)?, Miniscript::from_str(ms)?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::hashes::Hash;
    use bitcoin::hex::FromHex;
    use bitcoin::script::Instruction;
    use bitcoin::secp256k1::{Message, SecretKey};

    use super::*;

    /// The Liquid v1 watchman script from Elements test/functional/rpc_tweakfedpeg.py, which
    /// is also the liquidv1 `fedpegScript` in src/kernel/chainparams.cpp
    const LIQUID_SCRIPT: &str = "745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae";

    /// The "Liquid Daemon example" from Elements test/functional/rpc_tweakfedpeg.py: the
    /// watchman script tweaked with the claim script 0014008b1fdbaec5a82a9322af1640e871727245bce1
    const LIQUID_TWEAKED: &str = "745c87635b2103258857ed88024e5296436f851337451d3d68522fbb21dc5a047b965cd2f790932103ab43d77e8706a799cee3c14678574bccaca98c101217369cee987073cd2546492102ee5c8dfdf742bcc2b08386a6a3ec4b6087d39a6fd7e6f0fdeb82ecc30b11d0342102b104b6a469d8b3ccf0a671198e5f7d7010dbf2eb5587733b168f6e0d3be75760210207fc37d4877529fb0d63b1de352689627400a43f18717fa182fe0eea283bdd7921025d8724d82c61708458bc1a08ec9a7fcaf0ab6747ccf0a7d378faea07a261ab3e2102af6859d48d0a4518a4811f12adb974bbd051931e3f96f0b6ae16142c43ae6fd12102458215967f7977effc21b964bd92d870ae7eca98f343801031639150139e63ed2102cdef66bf4b5d26d0be22cabd5761970cfa84be905dc0137ad08ab634f104cb9e210297fb764f808c126f46ce0444124213bdc6a18f2904e75c9144f53bed4c19376e2103c631e77d14a5eb2fc61496ee3e9ea19d1e56e7e65a07aaa786f25ffc2921efde210270addb9011a4b41987b0848a8dc52e5442964fe5188c6a4c9320fbb9016390772103bf9aa75444d0013c46dcf10d70831b75b46a25d901fb7c6360beb2f6cac9c503210278f303dbaad1410a26d99e4dca8925fae4c90532a156c29e8ab1abf5ccaa663d210394cc0983add2dc60aa988c9faedebdc5463106184d72dd430ef24d215daf8b935f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae";

    const USER: &str = "0321da398ca2ddc09be89caa26e6730ae84751b6ea3a1ca46aa365bb5e1c3d9620";

    fn user_desc() -> crate::Descriptor<PublicKey> {
        crate::Descriptor::from_str(&format!("elwpkh({USER})")).unwrap()
    }

    /// Builds a legacy pegin with the generic constructor from the keys of the Liquid v1
    /// watchman script, its 11-of-15 federation and its 2-of-3 emergency keys after 4032 blocks.
    fn liquid_legacy_pegin() -> LegacyPegin<PublicKey> {
        let script = ScriptBuf::from_hex(LIQUID_SCRIPT).unwrap();
        let (mut fed, mut emer, mut emergency_branch) = (vec![], vec![], false);
        for instruction in script.instructions() {
            match instruction.unwrap() {
                Instruction::Op(op) if op == OP_ELSE => emergency_branch = true,
                Instruction::PushBytes(push) if push.len() == 33 => {
                    let key = CompressedPublicKey::from_slice(push.as_bytes()).unwrap();
                    if emergency_branch {
                        emer.push(LegacyPeginKey::NonFunctionary(key));
                    } else {
                        fed.push(LegacyPeginKey::Functionary(key));
                    }
                }
                _ => {}
            }
        }
        LegacyPegin::new(
            Threshold::new(11, fed).unwrap(),
            Threshold::new(2, emer).unwrap(),
            RelLockTime::from_consensus(4032).unwrap(),
            user_desc(),
        )
        .unwrap()
    }

    #[test]
    fn liquid_watchman_script() {
        let secp = Secp256k1::verification_only();
        let pegin = liquid_legacy_pegin();

        assert_eq!(
            pegin.witness_script_with(public_keys(&pegin.fed)),
            ScriptBuf::from_hex(LIQUID_SCRIPT).unwrap()
        );
        let claim_script =
            Vec::<u8>::from_hex("0014008b1fdbaec5a82a9322af1640e871727245bce1").unwrap();
        let fed_keys = pegin.tweaked_fed_keys(&secp, &claim_script).unwrap();
        assert_eq!(
            pegin.witness_script_with(fed_keys),
            ScriptBuf::from_hex(LIQUID_TWEAKED).unwrap()
        );

        // The 35-byte scriptSig counts four times. The witness has the empty element, 11
        // signatures and the 628-byte script with its 3-byte length.
        assert_eq!(LIQUID_SCRIPT.len(), 2 * 628);
        assert_eq!(pegin.max_weight_to_satisfy(), Weight::from_wu(4 * 35 + 1 + 73 * 11 + 3 + 628));

        let witness_script = pegin.bitcoin_witness_script(&secp).unwrap();
        assert_eq!(
            pegin.bitcoin_script_pubkey(&secp).unwrap(),
            pegin
                .bitcoin_address(Network::Bitcoin, &secp)
                .unwrap()
                .script_pubkey()
        );
        // OP_PUSHBYTES_34 <OP_0 OP_PUSHBYTES_32 <SHA256 of the witness script>>
        let mut script_sig = vec![0x22, 0x00, 0x20];
        script_sig.extend(witness_script.wscript_hash().to_byte_array());
        assert_eq!(
            pegin
                .bitcoin_unsigned_script_sig(&secp)
                .unwrap()
                .into_bytes(),
            script_sig
        );

        let s = pegin.to_string();
        assert_eq!(s.matches('#').count(), 1, "{}", s);
        assert_eq!(LegacyPegin::<PublicKey>::from_str(&s).unwrap(), pegin);
    }

    const FED_KEY: &str = "03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4";
    const EMER_KEY_1: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
    const EMER_KEY_2: &str = "02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623";

    #[test]
    fn legacy_pegin_from_str() {
        let pegin = LegacyPegin::<PublicKey>::from_str(&format!(
            "legacy_pegin(or_d(multi(1,f{FED_KEY}),and_v(v:older(4032),multi(2,u{EMER_KEY_1},u{EMER_KEY_2}))),elwpkh({USER}))"
        ))
        .unwrap();
        let fed = LegacyPeginKey::from_str(&format!("f{FED_KEY}")).unwrap();
        let emer: Vec<_> = [EMER_KEY_1, EMER_KEY_2]
            .iter()
            .map(|key| LegacyPeginKey::from_str(&format!("u{key}")).unwrap())
            .collect();
        let expected = LegacyPegin::new(
            Threshold::new(1, vec![fed]).unwrap(),
            Threshold::new(2, emer).unwrap(),
            RelLockTime::from_consensus(4032).unwrap(),
            user_desc(),
        )
        .unwrap();
        assert_eq!(pegin, expected);

        let s = pegin.to_string();
        assert_eq!(s.matches('#').count(), 1, "{}", s);
        assert_eq!(LegacyPegin::<PublicKey>::from_str(&s).unwrap(), pegin);

        let invalid = format!("legacy_pegin(multi(1,f{FED_KEY}),elwpkh({USER}))");
        assert!(matches!(
            LegacyPegin::<PublicKey>::from_str(&invalid),
            Err(Error::UnexpectedLegacyMiniscript)
        ));
    }

    #[test]
    fn legacy_pegin_miniscript_shape() {
        let fed = format!("f{FED_KEY}");
        let emer = format!("u{EMER_KEY_1}");
        let valid =
            format!("or_d(multi(1,{fed}),and_v(v:older(4032),multi(2,{emer},u{EMER_KEY_2})))");
        let ms = Miniscript::<LegacyPeginKey, Segwitv0>::from_str(&valid).unwrap();
        assert!(LegacyPegin::from_ms_and_desc(user_desc(), ms).is_ok());

        for text in [
            format!("multi(1,{fed})"),
            format!("or_d(pk({fed}),and_v(v:older(4032),multi(1,{emer})))"),
            format!("or_d(multi(1,{fed}),and_v(v:after(4032),multi(1,{emer})))"),
            format!("or_d(multi(1,{fed}),and_v(v:older(4032),pk({emer})))"),
            format!("or_d(multi(1,{fed}),pk({emer}))"),
        ] {
            let ms = Miniscript::<LegacyPeginKey, Segwitv0>::from_str(&text).unwrap();
            assert!(matches!(
                LegacyPegin::from_ms_and_desc(user_desc(), ms),
                Err(Error::UnexpectedLegacyMiniscript)
            ));
        }
    }

    struct Sigs(HashMap<PublicKey, bitcoin::ecdsa::Signature>, bool);

    impl bitcoin_miniscript::Satisfier<PublicKey> for Sigs {
        fn lookup_ecdsa_sig(&self, pk: &PublicKey) -> Option<bitcoin::ecdsa::Signature> {
            self.0.get(pk).copied()
        }

        fn check_older(&self, _: bitcoin::relative::LockTime) -> bool { self.1 }
    }

    #[test]
    fn legacy_pegin_satisfaction() {
        let secp = Secp256k1::new();
        let sk = |i: u8| SecretKey::from_slice(&[i; 32]).unwrap();
        let sig = |i: u8| {
            bitcoin::ecdsa::Signature::sighash_all(
                secp.sign_ecdsa_low_r(&Message::from_digest([i; 32]), &sk(i)),
            )
        };
        let key = |i: u8| CompressedPublicKey(sk(i).public_key(&secp));

        let fed: Vec<_> = (1..=3)
            .map(|i| LegacyPeginKey::Functionary(key(i)))
            .collect();
        let emer: Vec<_> = (4..=5)
            .map(|i| LegacyPeginKey::NonFunctionary(key(i)))
            .collect();
        let pegin = LegacyPegin::new(
            Threshold::new(2, fed).unwrap(),
            Threshold::new(1, emer).unwrap(),
            RelLockTime::from_consensus(4032).unwrap(),
            user_desc(),
        )
        .unwrap();
        let claim_script = user_desc().script_pubkey();
        let tweaked =
            |i: u8| tweak_key(&secp, &PublicKey::from(key(i)), claim_script.as_bytes()).unwrap();
        let witness_script = pegin.bitcoin_witness_script(&secp).unwrap().into_bytes();

        // Federation signatures follow the key order, after the empty element
        let sigs = HashMap::from([(tweaked(3), sig(3)), (tweaked(1), sig(1))]);
        let (witness, script_sig) = pegin
            .get_bitcoin_satisfaction(&secp, Sigs(sigs, false))
            .unwrap();
        assert_eq!(
            witness,
            vec![
                vec![],
                sig(1).to_vec(),
                sig(3).to_vec(),
                witness_script.clone()
            ]
        );
        assert_eq!(script_sig, pegin.bitcoin_unsigned_script_sig(&secp).unwrap());

        let witness_weight = varint_len(witness.len()) - varint_len(0)
            + witness
                .iter()
                .map(|item| varint_len(item.len()) + item.len())
                .sum::<usize>();
        let weight = 4 * (script_sig.len() as u64) + witness_weight as u64;
        assert!(weight <= pegin.max_weight_to_satisfy().to_wu());

        // Without enough federation signatures, the emergency keys need the timelock
        let sigs = HashMap::from([(tweaked(1), sig(1)), (PublicKey::from(key(5)), sig(5))]);
        assert!(matches!(
            pegin.get_bitcoin_satisfaction(&secp, Sigs(sigs.clone(), false)),
            Err(Error::Bitcoin(bitcoin_miniscript::Error::CouldNotSatisfy))
        ));
        let (witness, _) = pegin
            .get_bitcoin_satisfaction(&secp, Sigs(sigs, true))
            .unwrap();
        assert_eq!(witness, vec![vec![], sig(5).to_vec(), witness_script]);
    }
}
