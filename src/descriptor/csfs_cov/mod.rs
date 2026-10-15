// SPDX-License-Identifier: CC0-1.0

//! Legacy covenant descriptors
//!
//! `elcovwsh(KEY,MINISCRIPT)` pays to a P2WSH witness script that runs the Miniscript, then
//! checks that `KEY` signed the spending transaction. Its witness holds, from the bottom of the
//! stack, the signature in DER without a sighash type, the 11 items of the Elements Segwit v0
//! signature hash preimage from the sighash type to the version, and the satisfaction of the
//! Miniscript.
//!
//! The script concatenates the items, checking their sizes, and verifies the signature with
//! `OP_CHECKSIGVERIFY` against the transaction and with `OP_CHECKSIGFROMSTACK` against the
//! SHA256 of the concatenation, which therefore has to be the preimage of the signature hash.
//! The `ver_eq` and `outputs_pref` fragments of the Miniscript read the version and hashOutputs
//! items.

mod satisfy;
pub(crate) mod script;

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use bitcoin::Weight;
use elements::script::Builder;
use elements::{secp256k1_zkp, Script};

pub use self::satisfy::{CovenantSignature, LegacyCovSatisfier};
use crate::descriptor::checksum::verify_checksum;
use crate::descriptor::write_descriptor;
use crate::expression::{self, FromTree, TreeIterItem};
use crate::extensions::{Extension, LegacyOutputsPref, LegacyVerEq, ParseableExt, TxEnv};
use crate::interpreter::{self, Stack};
use crate::miniscript::lex::TokenIter;
use crate::miniscript::limits::MAX_SCRIPT_SIZE;
use crate::miniscript::satisfy::{Placeholder, Satisfaction};
use crate::miniscript::types::{ExtData, Type};
use crate::plan::AssetProvider;
use crate::prelude::*;
use crate::util::varint_len;
use crate::{
    ForEachKey, FromStrKey, Miniscript, MiniscriptKey, ParseError, Satisfier, ScriptContext,
    Segwitv0, Terminal, ToPublicKey, TranslateErr, Translator, ValidationParams,
};

/// The covenant signature and the preimage items at the bottom of the witness.
const COVENANT_ITEMS: usize = script::ITEM_SIZES.len() + 1;

/// The fragments that the Miniscript of an `elcovwsh` descriptor may hold besides the base
/// fragments.
///
/// They read signature hash items that only the covenant check authenticates, so their context
/// is Segwit v0, where only `elcovwsh` builds Miniscript with this extension.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum LegacyCovExt {
    /// `ver_eq`
    VerEq(LegacyVerEq),
    /// `outputs_pref`
    OutputsPref(LegacyOutputsPref),
}

impl fmt::Display for LegacyCovExt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerEq(ver_eq) => ver_eq.fmt(f),
            Self::OutputsPref(outputs_pref) => outputs_pref.fmt(f),
        }
    }
}

impl Extension for LegacyCovExt {
    fn segwit_v0_allowed(&self) -> bool { true }

    fn tap_allowed(&self) -> bool { false }

    fn ty(&self) -> Type {
        match self {
            Self::VerEq(_) => LegacyVerEq::TYPE,
            Self::OutputsPref(_) => LegacyOutputsPref::TYPE,
        }
    }

    fn ext_data(&self) -> ExtData {
        match self {
            Self::VerEq(_) => LegacyVerEq::EXT_DATA,
            Self::OutputsPref(outputs_pref) => outputs_pref.ext_data(),
        }
    }

    fn from_tree(name: &str, node: TreeIterItem) -> Option<Result<Self, crate::Error>> {
        Some(match name {
            "ver_eq" => terminal_arg(node)
                .and_then(LegacyVerEq::from_arg)
                .map(Self::VerEq),
            "outputs_pref" => terminal_arg(node)
                .and_then(LegacyOutputsPref::from_arg)
                .map(Self::OutputsPref),
            _ => return None,
        })
    }
}

impl ParseableExt for LegacyCovExt {
    fn encode(&self, builder: Builder) -> Builder {
        match self {
            Self::VerEq(ver_eq) => ver_eq.encode(builder),
            Self::OutputsPref(outputs_pref) => outputs_pref.encode(builder),
        }
    }

    fn decode(tokens: &mut TokenIter) -> Option<Self> {
        LegacyVerEq::decode(tokens)
            .map(Self::VerEq)
            .or_else(|| LegacyOutputsPref::decode(tokens).map(Self::OutputsPref))
    }

    // `root_has_sig` does not matter: every spend has the covenant signature, which commits to
    // the transaction.
    fn sat_dissat<Pk: ToPublicKey, P: AssetProvider<Pk>>(
        &self,
        provider: &P,
        _: bool,
    ) -> (Satisfaction<Placeholder<Pk>>, Satisfaction<Placeholder<Pk>>) {
        let tx = provider.provider_lookup_tx_env().map(|env| env.tx());
        let (sat, dissat) = match self {
            Self::VerEq(ver_eq) => ver_eq.sat_dissat::<Pk>(tx.map(|tx| tx.version)),
            Self::OutputsPref(outputs_pref) => {
                outputs_pref.sat_dissat::<Pk>(tx.map(|tx| &tx.output[..]))
            }
        };
        let satisfaction = |stack| Satisfaction {
            stack,
            has_sig: false,
            relative_timelock: None,
            absolute_timelock: None,
        };
        (satisfaction(sat), satisfaction(dissat))
    }

    fn evaluate(&self, stack: &mut Stack, _: Option<&TxEnv>) -> Result<bool, interpreter::Error> {
        match self {
            Self::VerEq(ver_eq) => ver_eq.evaluate(stack),
            Self::OutputsPref(outputs_pref) => outputs_pref.evaluate(stack),
        }
    }
}

// The argument of `node`, which must be a single terminal.
fn terminal_arg(node: TreeIterItem<'_>) -> Result<&str, crate::Error> {
    match node.first_child() {
        Some(arg) if node.n_children() == 1 && arg.n_children() == 0 => Ok(arg.name()),
        _ => Err(crate::Error::Unexpected(format!(
            "{}({} args) in a legacy covenant fragment",
            node.name(),
            node.n_children()
        ))),
    }
}

/// A legacy covenant descriptor, `elcovwsh(KEY,MINISCRIPT)`
///
/// Like other Segwit v0 descriptors, parsing checks consensus limits only.
/// [`Self::sanity_check`] checks standardness.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LegacyCSFSCov<Pk: MiniscriptKey> {
    pk: Pk,
    ms: Miniscript<Pk, Segwitv0, LegacyCovExt>,
}

impl<Pk: MiniscriptKey> LegacyCSFSCov<Pk> {
    /// Creates the descriptor, checking the consensus limits of the whole witness script and
    /// witness.
    pub fn new(pk: Pk, ms: Miniscript<Pk, Segwitv0, LegacyCovExt>) -> Result<Self, crate::Error> {
        Segwitv0::check_pk(&pk).map_err(crate::Error::ContextError)?;
        ms.validate(&validation_params(&Segwitv0::CONSENSUS, &ms))
            .map_err(crate::Error::Validation)?;
        Ok(Self { pk, ms })
    }

    /// The covenant key.
    pub fn pk(&self) -> &Pk { &self.pk }

    /// The Miniscript.
    pub fn as_inner(&self) -> &Miniscript<Pk, Segwitv0, LegacyCovExt> { &self.ms }

    /// Checks the standardness limits of the whole witness script and witness, and the other
    /// rules of `Segwitv0::SANE`.
    pub fn sanity_check(&self) -> Result<(), crate::Error> {
        self.ms
            .validate(&validation_params(&Segwitv0::SANE, &self.ms))
            .map_err(crate::Error::Validation)
    }

    /// Computes an upper bound on the difference between the weight of a satisfied and a
    /// non-satisfied input, as [`crate::descriptor::Wsh::max_weight_to_satisfy`] does.
    pub fn max_weight_to_satisfy(&self) -> Result<Weight, crate::Error> {
        let script_size = self.ms.script_size() + covenant_overhead(&self.ms).0;
        let n_items = self.ms.max_satisfaction_witness_elements()? + COVENANT_ITEMS;
        // A DER signature of at most 72 bytes, then the items, each with a length byte.
        let covenant_size = 73
            + script::ITEM_SIZES
                .iter()
                .map(|size| usize::from(size.unwrap_or(33)) + 1)
                .sum::<usize>();
        let size = self.ms.max_satisfaction_size()? + covenant_size;
        Ok(Weight::from_wu(
            (varint_len(n_items) - varint_len(0) + varint_len(script_size) + script_size + size)
                as u64,
        ))
    }

    /// Converts the keys from one type to another.
    pub fn translate_pk<T>(
        &self,
        t: &mut T,
    ) -> Result<LegacyCSFSCov<T::TargetPk>, TranslateErr<T::Error>>
    where
        T: Translator<Pk>,
    {
        let pk = t.pk(&self.pk).map_err(TranslateErr::TranslatorErr)?;
        LegacyCSFSCov::new(pk, self.ms.translate_pk(t)?).map_err(TranslateErr::OuterError)
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> LegacyCSFSCov<Pk> {
    /// The witness script.
    pub fn inner_script(&self) -> Script {
        script::push_covenant(self.ms.node.encode(Builder::new()), &self.pk.to_public_key())
            .into_script()
    }

    /// The script pubkey.
    pub fn script_pubkey(&self) -> Script { self.inner_script().to_v0_p2wsh() }

    /// The address, blinded if `blinder` is given.
    pub fn address(
        &self,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static elements::AddressParams,
    ) -> elements::Address {
        elements::Address::p2wsh(&self.inner_script(), blinder, params)
    }

    /// The script code of signatures by keys of the Miniscript. The covenant key signs
    /// [`LegacyCovSatisfier::sighash`] instead.
    pub fn ecdsa_sighash_script_code(&self) -> Script { self.inner_script() }

    /// Returns a non-malleable witness, and the empty scriptSig, spending the input of `cov`.
    ///
    /// `satisfier` supplies the covenant signature through
    /// [`Satisfier::lookup_legacy_covenant_sig`] and the inner-script assets separately.
    pub fn get_satisfaction<S: Satisfier<Pk>>(
        &self,
        cov: &LegacyCovSatisfier,
        satisfier: S,
    ) -> Result<(Vec<Vec<u8>>, Script), Error> {
        self.satisfy(cov, satisfier, false)
    }

    /// Returns a possibly malleable witness, and the empty scriptSig, spending the input of
    /// `cov`.
    pub fn get_satisfaction_mall<S: Satisfier<Pk>>(
        &self,
        cov: &LegacyCovSatisfier,
        satisfier: S,
    ) -> Result<(Vec<Vec<u8>>, Script), Error> {
        self.satisfy(cov, satisfier, true)
    }

    fn satisfy<S: Satisfier<Pk>>(
        &self,
        cov: &LegacyCovSatisfier,
        satisfier: S,
        allow_mall: bool,
    ) -> Result<(Vec<Vec<u8>>, Script), Error> {
        let (sig, hash_type) = satisfier
            .lookup_legacy_covenant_sig(&self.pk)
            .ok_or(Error::MissingCovenantSignature)?;
        if hash_type != cov.hash_type() {
            return Err(Error::SighashTypeMismatch);
        }
        let outputs_pref = |ms: &Miniscript<Pk, Segwitv0, LegacyCovExt>| {
            matches!(ms.node, Terminal::Ext(LegacyCovExt::OutputsPref(_)))
        };
        if !cov.commits_to_outputs() && self.ms.iter().any(outputs_pref) {
            return Err(Error::OutputsNotCommitted);
        }
        let ms_witness = if allow_mall {
            self.ms.satisfy_malleable((cov, satisfier))?
        } else {
            self.ms.satisfy((cov, satisfier))?
        };

        let mut witness = vec![sig.serialize_der().to_vec()];
        witness.extend(cov.items().iter().rev().cloned());
        witness.extend(ms_witness);
        witness.push(self.inner_script().into_bytes());
        Ok((witness, Script::new()))
    }
}

impl LegacyCSFSCov<bitcoin::PublicKey> {
    /// Decodes the witness script of an `elcovwsh` descriptor, checking consensus limits only.
    pub fn decode_consensus(script: &Script) -> Result<Self, Error> {
        Self::decode_bytes(script.as_bytes())
    }

    pub(crate) fn decode_bytes(script: &[u8]) -> Result<Self, Error> {
        let (ms, pk) = script::split(script).ok_or(Error::NotCovenantScript)?;
        let ms = Miniscript::decode_with_validation_params(&ms, &ValidationParams::MAX)?;
        let cov = Self::new(pk, ms)?;
        if cov.inner_script().as_bytes() == script {
            Ok(cov)
        } else {
            Err(Error::NotCovenantScript)
        }
    }
}

// The size and the non-push opcodes of the covenant check after `ms`, whose last opcode may
// take the VERIFY in.
fn covenant_overhead<Pk: MiniscriptKey>(
    ms: &Miniscript<Pk, Segwitv0, LegacyCovExt>,
) -> (usize, usize) {
    let verify = usize::from(!ms.ext.has_free_verify);
    (script::COVENANT_SIZE + verify, script::COVENANT_OPS + verify)
}

// `base`, with the limits of the whole witness script and witness applied to `ms`.
fn validation_params<Pk: MiniscriptKey>(
    base: &ValidationParams,
    ms: &Miniscript<Pk, Segwitv0, LegacyCovExt>,
) -> ValidationParams {
    let (size, ops) = covenant_overhead(ms);
    ValidationParams {
        // Segwit v0 parameters reject extensions, which only `elcovwsh` uses there.
        allow_extensions: true,
        // The covenant signature commits every spend to the transaction.
        allow_sigless_branch: true,
        max_script_size: base
            .max_script_size
            .min(MAX_SCRIPT_SIZE)
            .saturating_sub(size),
        max_opcode_count: base.max_opcode_count.saturating_sub(ops),
        max_witness_items: base.max_witness_items.saturating_sub(COVENANT_ITEMS),
        max_exec_stack_size: base.max_exec_stack_size.saturating_sub(COVENANT_ITEMS),
        ..*base
    }
}

impl<Pk: FromStrKey> FromTree for LegacyCSFSCov<Pk> {
    fn from_tree(top: TreeIterItem) -> Result<Self, crate::Error> {
        let tree_error = |e| crate::Error::Parse(ParseError::Tree(e));
        top.verify_toplevel("elcovwsh", 2..=2).map_err(tree_error)?;
        let (key, ms) = top.verify_binary("elcovwsh").map_err(tree_error)?;
        let pk = key
            .verify_terminal("public key")
            .map_err(crate::Error::Parse)?;
        Self::new(pk, Miniscript::from_tree(ms)?)
    }
}

impl<Pk: FromStrKey> core::str::FromStr for LegacyCSFSCov<Pk> {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, crate::Error> {
        let s = verify_checksum(s).map_err(|e| crate::Error::Parse(ParseError::Tree(e.into())))?;
        Self::from_tree(expression::Tree::from_str(s)?.root())
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for LegacyCSFSCov<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "elcovwsh({:?},{:?})", self.pk, self.ms)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for LegacyCSFSCov<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_descriptor!(f, "elcovwsh({},{})", self.pk, self.ms)
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for LegacyCSFSCov<Pk> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, mut pred: F) -> bool {
        pred(&self.pk) && self.ms.for_each_key(pred)
    }
}

/// An error decoding or satisfying a legacy covenant descriptor
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The Miniscript is invalid or cannot be satisfied.
    Miniscript(crate::Error),
    /// The script is not the witness script of an `elcovwsh` descriptor.
    NotCovenantScript,
    /// The spent input has an issuance, which the signature hash preimage includes and the
    /// covenant check does not.
    IssuanceInput,
    /// The spent amount is null, which the covenant check rejects.
    NullAmount,
    /// The satisfier has no signature by the covenant key.
    MissingCovenantSignature,
    /// The covenant signature has another sighash type than the transaction data.
    SighashTypeMismatch,
    /// The Miniscript has `outputs_pref`, and the sighash type does not commit to all outputs.
    OutputsNotCommitted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Miniscript(e) => fmt::Display::fmt(e, f),
            Self::NotCovenantScript => f.write_str("not an elcovwsh witness script"),
            Self::IssuanceInput => f.write_str("the spent input has an issuance"),
            Self::NullAmount => f.write_str("the spent amount is null"),
            Self::MissingCovenantSignature => f.write_str("no signature by the covenant key"),
            Self::SighashTypeMismatch => {
                f.write_str("covenant signature and transaction data differ in sighash type")
            }
            Self::OutputsNotCommitted => {
                f.write_str("outputs_pref needs a sighash type that commits to all outputs")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Miniscript(e) => Some(e),
            Self::NotCovenantScript
            | Self::IssuanceInput
            | Self::NullAmount
            | Self::MissingCovenantSignature
            | Self::SighashTypeMismatch
            | Self::OutputsNotCommitted => None,
        }
    }
}

impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self { Self::Miniscript(e) }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::hex::DisplayHex as _;
    use elements::encode::serialize;
    use elements::opcodes::all::{OP_PUSHNUM_1, OP_PUSHNUM_16};
    use elements::script::Instruction;
    use elements::secp256k1_zkp::{ecdsa, Message, Secp256k1, SecretKey};
    use elements::sighash::SighashCache;
    use elements::{
        confidential, AddressParams, AssetId, EcdsaSighashType, LockTime, OutPoint, Transaction,
        TxIn, TxOut, Txid,
    };

    use super::*;
    use crate::util::witness_size;
    use crate::ElementsSig;

    const BTC_ASSET: [u8; 32] = [
        0x23, 0x0f, 0x4f, 0x5d, 0x4b, 0x7c, 0x6f, 0xa8, 0x45, 0x80, 0x6e, 0xe4, 0xf6, 0x77, 0x13,
        0x45, 0x9e, 0x1b, 0x69, 0xe8, 0xe6, 0x0f, 0xce, 0xe2, 0xe4, 0x94, 0x0c, 0x7a, 0x0d, 0x5d,
        0xe1, 0xb2,
    ];

    // Key `i`, whose secret key is the byte `i` followed by zeros.
    fn key(i: u8) -> (bitcoin::PublicKey, SecretKey) {
        let mut sk = [0; 32];
        sk[0] = i;
        let sk = SecretKey::from_slice(&sk).unwrap();
        (bitcoin::PublicKey::new(sk.public_key(&Secp256k1::signing_only())), sk)
    }

    // A transaction spending `txid:vout` to two outputs of 99000 to `script_pubkey`, and a fee.
    fn transaction(txid: &str, vout: u32, script_pubkey: Script) -> Transaction {
        let asset = confidential::Asset::Explicit(AssetId::from_byte_array(BTC_ASSET));
        let output = TxOut {
            script_pubkey,
            value: confidential::Value::Explicit(99_000),
            asset,
            ..Default::default()
        };
        let fee =
            TxOut { value: confidential::Value::Explicit(2_000), asset, ..Default::default() };
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_str(txid).unwrap(), vout },
                ..Default::default()
            }],
            output: vec![output.clone(), output, fee],
        }
    }

    fn spent() -> TxOut {
        TxOut { value: confidential::Value::Explicit(200_000), ..Default::default() }
    }

    fn sign(data: &LegacyCovSatisfier, sk: &SecretKey) -> ecdsa::Signature {
        let msg = Message::from_digest(data.sighash().to_byte_array());
        Secp256k1::signing_only().sign_ecdsa(&msg, sk)
    }

    #[test]
    fn string_round_trip() {
        for s in [
            "elcovwsh(A,pk(B))",
            "elcovwsh(A,or_i(pk(B),pk(C)))",
            "elcovwsh(A,multi(2,B,C,D))",
            "elcovwsh(A,and_v(v:pk(B),pk(C)))",
            "elcovwsh(A,thresh(2,l:ver_eq(1),s:pk(C),s:pk(B)))",
            "elcovwsh(A,outputs_pref(01020304))",
            "elcovwsh(A,outputs_pref(05))",
        ] {
            let cov = LegacyCSFSCov::<String>::from_str(s).unwrap();
            assert_eq!(format!("{:#}", cov), s);
            assert_eq!(LegacyCSFSCov::<String>::from_str(&cov.to_string()).unwrap(), cov);
        }
        for s in [
            "elcovwsh(A)",
            "elcovwsh(A,ver_eq(1,2))",
            "elcovwsh(A,ver_eq(-1))",
            "elcovwsh(A,outputs_pref(0))",
        ] {
            assert!(LegacyCSFSCov::<String>::from_str(s).is_err(), "{}", s);
        }
    }

    // A single-byte prefix from 1 to 16, or 0x81, is pushed as data, which consensus accepts.
    // The lexer enforces minimal pushes, so the script does not decode.
    #[test]
    fn non_minimal_prefix_push() {
        let (pk, b) = (key(1).0, key(2).0);
        for pref in ["01", "10", "81"] {
            let s = format!("elcovwsh({},and_v(v:pk({}),outputs_pref({})))", pk, b, pref);
            let cov = LegacyCSFSCov::<bitcoin::PublicKey>::from_str(&s).unwrap();
            cov.sanity_check().unwrap();
            let script = cov.inner_script();
            assert!(LegacyCSFSCov::<bitcoin::PublicKey>::decode_consensus(&script).is_err());
        }
    }

    #[test]
    fn script_round_trip() {
        let (pk, _) = key(1);
        let (b, c, d) = (key(2).0, key(3).0, key(4).0);
        for ms in [
            "1".to_owned(),
            format!("pk({})", b),
            format!("or_i(pk({}),pk({}))", b, c),
            format!("multi(2,{},{},{})", b, c, d),
            format!("and_v(v:pk({}),pk({}))", b, c),
            format!("and_v(v:ver_eq(2),pk({}))", b),
            format!("and_v(v:outputs_pref(f2f233),pk({}))", b),
        ] {
            let cov =
                LegacyCSFSCov::<bitcoin::PublicKey>::from_str(&format!("elcovwsh({},{})", pk, ms))
                    .unwrap();
            let script = cov.inner_script();
            assert_eq!(script.len(), cov.ms.script_size() + covenant_overhead(&cov.ms).0);
            let decoded = LegacyCSFSCov::<bitcoin::PublicKey>::decode_consensus(&script);
            assert_eq!(decoded.unwrap(), cov, "{}", ms);
        }
        assert!(matches!(
            LegacyCSFSCov::<bitcoin::PublicKey>::decode_consensus(&Script::new()),
            Err(Error::NotCovenantScript)
        ));
    }

    #[test]
    fn covenant_check() {
        let script = script::push_covenant(Builder::new(), &key(1).0).into_script();
        assert_eq!(script.len(), script::COVENANT_SIZE + 1);
        // Consensus counts the opcodes after OP_16.
        let counted = |ins: &Result<Instruction, _>| match ins {
            Ok(Instruction::Op(op)) => op.into_u8() > OP_PUSHNUM_16.into_u8(),
            _ => false,
        };
        let ops = script.instructions().filter(counted).count();
        assert_eq!(ops, script::COVENANT_OPS + 1);
    }

    // The address in the `fund_output` test of elements-miniscript 0.5.
    #[test]
    fn address_vector() {
        let cov =
            LegacyCSFSCov::<bitcoin::PublicKey>::from_str(&format!("elcovwsh({},1)", key(1).0))
                .unwrap();
        assert_eq!(
            cov.address(None, &AddressParams::ELEMENTS).to_string(),
            "ert1qamjdykcfzkcsvc9z32a6qcz3mwr85a3k7z7qf2uaufem2q3lsjxqj4y4fy"
        );
    }

    #[test]
    fn sighash_matches_elements() {
        let mut tx = transaction(
            "141f79c7c254ee3a9a9bc76b4f60564385b784bdfc1882b25154617801fe2237",
            1,
            Script::new(),
        );
        // A fourth input has no output for SIGHASH_SINGLE.
        for vout in 2..5 {
            let mut input = tx.input[0].clone();
            input.previous_output.vout = vout;
            tx.input.push(input);
        }
        let spent = spent();
        for idx in [0, 3] {
            for hash_type in [
                EcdsaSighashType::All,
                EcdsaSighashType::None,
                EcdsaSighashType::Single,
                EcdsaSighashType::AllPlusAnyoneCanPay,
                EcdsaSighashType::NonePlusAnyoneCanPay,
                EcdsaSighashType::SinglePlusAnyoneCanPay,
            ] {
                let spent_refs = [&spent; 4];
                let env = TxEnv::from_refs(&tx, &spent_refs, idx).unwrap();
                let data = LegacyCovSatisfier::new(env, hash_type).unwrap();
                let expected = SighashCache::new(&tx).segwitv0_sighash(
                    idx,
                    &script::script_code(),
                    spent.value,
                    hash_type,
                );
                assert_eq!(data.sighash(), expected, "{} {}", idx, hash_type);
            }
        }
    }

    // The transaction and witness size in the `spend_tx` test of elements-miniscript 0.5.
    #[test]
    fn satisfaction_vector() {
        let (pk, sk) = key(1);
        let cov =
            LegacyCSFSCov::<bitcoin::PublicKey>::from_str(&format!("elcovwsh({},1)", pk)).unwrap();
        let tx = transaction(
            "7c8e615c8da947fefd2d9b6f83f313a9b59d249c93a5f232287633195b461cb7",
            0,
            cov.script_pubkey(),
        );
        let spent = spent();
        let data = LegacyCovSatisfier::new(
            TxEnv::new(&tx, core::slice::from_ref(&spent), 0).unwrap(),
            EcdsaSighashType::All,
        )
        .unwrap();
        let sigs =
            CovenantSignature { key: pk, signature: (sign(&data, &sk), EcdsaSighashType::All) };
        let (witness, script_sig) = cov.get_satisfaction(&data, sigs).unwrap();
        assert!(script_sig.is_empty());
        assert_eq!(witness.len(), 13);
        assert_eq!(witness_size(&witness), 385);

        let weight = varint_len(witness.len()) - varint_len(0)
            + witness
                .iter()
                .map(|item| varint_len(item.len()) + item.len())
                .sum::<usize>();
        assert!(weight as u64 <= cov.max_weight_to_satisfy().unwrap().to_wu());
    }

    // The cases of the `satisfy_and_interpret` test of elements-miniscript 0.5. The interpreter
    // checks of those cases are in `tests/legacy_interpreter.rs`.
    #[test]
    fn fragment_satisfaction() {
        let (pk, sk) = key(1);
        let p2wsh = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .into_script()
            .to_v0_p2wsh();
        let tx = transaction(
            "141f79c7c254ee3a9a9bc76b4f60564385b784bdfc1882b25154617801fe2237",
            1,
            p2wsh,
        );
        let spent = spent();
        let satisfy = |ms: &str, hash_type| {
            let cov =
                LegacyCSFSCov::<bitcoin::PublicKey>::from_str(&format!("elcovwsh({},{})", pk, ms))
                    .unwrap();
            let data = LegacyCovSatisfier::new(
                TxEnv::new(&tx, core::slice::from_ref(&spent), 0).unwrap(),
                hash_type,
            )
            .unwrap();
            let sigs = CovenantSignature { key: pk, signature: (sign(&data, &sk), hash_type) };
            cov.get_satisfaction(&data, sigs)
        };
        let all = EcdsaSighashType::All;
        let could_not_satisfy =
            |result| matches!(result, Err(Error::Miniscript(crate::Error::CouldNotSatisfy)));

        satisfy("ver_eq(2)", all).unwrap();
        assert!(could_not_satisfy(satisfy("ver_eq(3)", all)));

        let pref = |output: &TxOut| serialize(output).as_hex().to_string();
        let outputs_pref = format!("outputs_pref({})", pref(&tx.output[0]));
        let (witness, _) = satisfy(&outputs_pref, all).unwrap();
        assert_eq!(witness.len(), 13 + 7);
        let mut changed = tx.output[0].clone();
        changed.value = confidential::Value::Explicit(99_001);
        assert!(could_not_satisfy(satisfy(&format!("outputs_pref({})", pref(&changed)), all)));

        assert!(matches!(
            satisfy(&outputs_pref, EcdsaSighashType::Single),
            Err(Error::OutputsNotCommitted)
        ));
        satisfy("ver_eq(2)", EcdsaSighashType::Single).unwrap();
    }

    #[test]
    fn satisfaction_errors() {
        let (pk, sk) = key(1);
        let cov =
            LegacyCSFSCov::<bitcoin::PublicKey>::from_str(&format!("elcovwsh({},1)", pk)).unwrap();
        let mut tx = transaction(
            "7c8e615c8da947fefd2d9b6f83f313a9b59d249c93a5f232287633195b461cb7",
            0,
            Script::new(),
        );
        let spent = spent();
        let all = EcdsaSighashType::All;
        let data = LegacyCovSatisfier::new(
            TxEnv::new(&tx, core::slice::from_ref(&spent), 0).unwrap(),
            all,
        )
        .unwrap();

        let no_sigs = BTreeMap::<bitcoin::PublicKey, ElementsSig>::new();
        assert!(matches!(
            cov.get_satisfaction(&data, &no_sigs),
            Err(Error::MissingCovenantSignature)
        ));
        let other_type =
            CovenantSignature { key: pk, signature: (sign(&data, &sk), EcdsaSighashType::Single) };
        assert!(matches!(
            cov.get_satisfaction(&data, other_type),
            Err(Error::SighashTypeMismatch)
        ));

        let null = TxOut::default();
        assert!(matches!(
            LegacyCovSatisfier::new(TxEnv::new(&tx, core::slice::from_ref(&null), 0).unwrap(), all),
            Err(Error::NullAmount)
        ));
        tx.input[0].asset_issuance.amount = confidential::Value::Explicit(1);
        assert!(matches!(
            LegacyCovSatisfier::new(
                TxEnv::new(&tx, core::slice::from_ref(&spent), 0).unwrap(),
                all
            ),
            Err(Error::IssuanceInput)
        ));
    }
}
