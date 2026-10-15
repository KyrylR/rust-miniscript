// SPDX-License-Identifier: CC0-1.0

//! Miniscript Extensions
//!
//! Fragments beyond the base Miniscript language, held by [`Terminal::Ext`]. Each extension
//! fragment is valid in Segwit v0 scripts, Tapscript, or both, and never in legacy or bare
//! scripts.
//!
//! [`Terminal::Ext`]: crate::Terminal::Ext

mod arith;
mod csfs;
mod index_ops;
mod introspect_ops;
pub mod param;

use core::str::FromStr;
use core::{fmt, hash};

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::{self, schnorr, Message, Secp256k1};
use elements::script::Builder;
use elements::{Transaction, TxIn, TxOut};

mod outputs_pref;
mod tx_ver;
pub use self::arith::{Arith, Comparison, Expr};
pub use self::csfs::CheckSigFromStack;
pub use self::index_ops::{IdxConst, IdxExpr};
pub use self::introspect_ops::{CovOps, FieldExpr};
pub use self::outputs_pref::LegacyOutputsPref;
pub use self::param::{CovExtArgs, CsfsKey, CsfsMsg, ExtParam, ExtParamTranslator, Spk};
pub use self::tx_ver::LegacyVerEq;
use crate::expression::TreeIterItem;
use crate::interpreter::{self, Element, Stack};
use crate::miniscript::lex::TokenIter;
use crate::miniscript::satisfy::{Placeholder, Satisfaction, Witness};
use crate::miniscript::types::extra_props::{SatData, TimelockInfo};
use crate::miniscript::types::{Base, Correctness, Dissat, ExtData, Input, Malleability, Type};
use crate::plan::AssetProvider;
use crate::prelude::*;
use crate::{Error, MiniscriptKey, ParseError, Satisfier, ToPublicKey, TranslateErr};

/// A fragment beyond the base Miniscript language.
///
/// Like [`crate::MiniscriptKey`] for keys, this covers what does not depend on concrete
/// parameters; [`ParseableExt`] adds the Script behavior.
pub trait Extension: Clone + Eq + Ord + fmt::Debug + fmt::Display + hash::Hash {
    /// Whether this type has fragments. Text parsing and script decoding skip their extension
    /// checks for a type without fragments.
    const HAS_FRAGMENTS: bool = true;

    /// The type of the fragment.
    fn ty(&self) -> Type;

    /// The script size and resource usage of the fragment.
    fn ext_data(&self) -> ExtData;

    /// Whether the fragment is valid in Segwit v0 scripts.
    fn segwit_v0_allowed(&self) -> bool;

    /// Whether the fragment is valid in Tapscript.
    fn tap_allowed(&self) -> bool;

    /// Parses the fragment from an expression node whose name, without wrappers, is `name`.
    ///
    /// Returns `None` if `name` is not a fragment of this extension. Nodes named after base
    /// fragments, and the arguments of base fragments, are never offered.
    fn from_tree(name: &str, node: TreeIterItem) -> Option<Result<Self, Error>>;
}

/// Script encoding, decoding, satisfaction and evaluation of an [`Extension`].
pub trait ParseableExt: Extension {
    /// Encodes the fragment.
    fn encode(&self, builder: Builder) -> Builder;

    /// Decodes the fragment from the end of `tokens`, consuming them only on success.
    fn decode(tokens: &mut TokenIter) -> Option<Self>;

    /// The satisfaction and dissatisfaction templates of the fragment.
    ///
    /// `root_has_sig` is whether every satisfaction of the whole script requires a signature,
    /// which then commits to the transaction.
    fn sat_dissat<Pk: ToPublicKey, P: AssetProvider<Pk>>(
        &self,
        provider: &P,
        root_has_sig: bool,
    ) -> (Satisfaction<Placeholder<Pk>>, Satisfaction<Placeholder<Pk>>);

    /// Executes the fragment on `stack`, consuming its witness, and returns whether it was
    /// satisfied.
    fn evaluate(&self, stack: &mut Stack, env: Option<&TxEnv>) -> Result<bool, interpreter::Error>;
}

/// No extensions: a [`crate::Miniscript`] of only base fragments.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum NoExt {}

impl fmt::Display for NoExt {
    fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result { match *self {} }
}

impl Extension for NoExt {
    const HAS_FRAGMENTS: bool = false;

    fn ty(&self) -> Type { match *self {} }

    fn ext_data(&self) -> ExtData { match *self {} }

    fn segwit_v0_allowed(&self) -> bool { match *self {} }

    fn tap_allowed(&self) -> bool { match *self {} }

    fn from_tree(_: &str, _: TreeIterItem) -> Option<Result<Self, Error>> { None }
}

impl ParseableExt for NoExt {
    fn encode(&self, _: Builder) -> Builder { match *self {} }

    fn decode(_: &mut TokenIter) -> Option<Self> { None }

    fn sat_dissat<Pk: ToPublicKey, P: AssetProvider<Pk>>(
        &self,
        _: &P,
        _: bool,
    ) -> (Satisfaction<Placeholder<Pk>>, Satisfaction<Placeholder<Pk>>) {
        match *self {}
    }

    fn evaluate(&self, _: &mut Stack, _: Option<&TxEnv>) -> Result<bool, interpreter::Error> {
        match *self {}
    }
}

/// Translates the extensions of a Miniscript, like [`crate::Translator`] does for keys.
pub trait ExtTranslator<PExt: Extension> {
    /// The extension to translate into.
    type TargetExt: Extension;
    /// An error that may occur during translation.
    type Error;

    /// Translates an extension, failing in the translator or with an invalid result.
    fn ext(&mut self, ext: &PExt) -> Result<Self::TargetExt, TranslateErr<Self::Error>>;
}

impl<PArg: ExtParam, T: ExtParamTranslator<PArg>> ExtTranslator<CovenantExt<PArg>> for T {
    type TargetExt = CovenantExt<T::TargetArg>;
    type Error = T::Error;

    fn ext(&mut self, ext: &CovenantExt<PArg>) -> Result<Self::TargetExt, TranslateErr<T::Error>> {
        Ok(match ext {
            CovenantExt::Csfs(csfs) => CovenantExt::Csfs(Box::new(csfs.translate(self)?)),
            CovenantExt::Arith(arith) => CovenantExt::Arith(Box::new(arith.translate(self)?)),
            CovenantExt::Introspect(ops) => CovenantExt::Introspect(Box::new(ops.translate(self)?)),
        })
    }
}

/// The covenant fragments of Elements Tapscript, with abstract or concrete ([`CovExtArgs`])
/// arguments.
///
/// Payloads are boxed so ordinary Miniscript nodes do not reserve space for a covenant fragment.
///
/// Parsing, decoding, translation and the fragment constructors check that each argument suits
/// its position.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum CovenantExt<T: ExtParam> {
    /// `csfs`
    Csfs(Box<CheckSigFromStack<T>>),
    /// `num64_eq`, `num64_lt`, `num64_leq`, `num64_gt` and `num64_geq`
    Arith(Box<Arith<T>>),
    /// `is_exp_asset`, `is_exp_value`, `asset_eq`, `value_eq`, `spk_eq`, `curr_idx_eq` and
    /// `idx_eq`
    Introspect(Box<CovOps<T>>),
}

impl<T: ExtParam> From<NoExt> for CovenantExt<T> {
    fn from(ext: NoExt) -> Self { match ext {} }
}

impl<T: ExtParam> fmt::Display for CovenantExt<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Csfs(csfs) => csfs.fmt(f),
            Self::Arith(arith) => arith.fmt(f),
            Self::Introspect(ops) => ops.fmt(f),
        }
    }
}

impl<T: ExtParam> Extension for CovenantExt<T> {
    fn ty(&self) -> Type {
        // Transaction conditions take no witness besides price attestations, and have no
        // dissatisfaction.
        let condition = |input| Type {
            corr: Correctness { base: Base::B, input, dissatisfiable: false, unit: true },
            mall: Malleability::NonMalleable { dissat: Dissat::None, signed: false },
        };
        match self {
            // Anyone who has seen this message signature can replay it in another transaction.
            Self::Csfs(_) => Type {
                corr: Correctness {
                    base: Base::B,
                    input: Input::One,
                    dissatisfiable: true,
                    unit: true,
                },
                mall: Malleability::NonMalleable { dissat: Dissat::Unique, signed: false },
            },
            Self::Arith(arith) if arith.n_oracles() > 0 => condition(Input::Any),
            Self::Arith(_) | Self::Introspect(_) => condition(Input::Zero),
        }
    }

    fn ext_data(&self) -> ExtData {
        let data = |witness_count, witness_size, exec_stack| SatData {
            max_witness_stack_size: witness_size,
            max_witness_stack_count: witness_count,
            max_script_sig_size: 0,
            max_exec_stack_count: exec_stack,
            max_exec_op_count: 0,
        };
        let (pk_cost, has_free_verify, sat_data, dissat_data) = match self {
            // Pushes the message and key; takes a 64-byte signature or an empty push.
            Self::Csfs(_) => (67, true, Some(data(1, 65, 2)), Some(data(1, 1, 2))),
            Self::Arith(arith) => {
                // Each attestation is a 64-byte signature, then 8-byte timestamp and price.
                let n = arith.n_oracles();
                let sat = data(3 * n, 83 * n, arith.max_stack());
                (arith.script_size(), arith.comparison() == Comparison::Eq, Some(sat), None)
            }
            Self::Introspect(ops) => {
                let sat = data(0, 0, ops.max_stack());
                (ops.script_size(), ops.has_free_verify(), Some(sat), None)
            }
        };
        ExtData {
            pk_cost,
            has_free_verify,
            static_ops: 0,
            sat_data,
            dissat_data,
            timelock_info: TimelockInfo::new(),
            tree_height: 0,
        }
    }

    fn segwit_v0_allowed(&self) -> bool { false }

    fn tap_allowed(&self) -> bool { true }

    fn from_tree(name: &str, node: TreeIterItem) -> Option<Result<Self, Error>> {
        Some(match name {
            "csfs" => CheckSigFromStack::from_tree(node).map(|csfs| Self::Csfs(Box::new(csfs))),
            "num64_eq" | "num64_lt" | "num64_leq" | "num64_gt" | "num64_geq" => {
                Arith::from_tree(name, node).map(|arith| Self::Arith(Box::new(arith)))
            }
            "is_exp_asset" | "is_exp_value" | "asset_eq" | "value_eq" | "spk_eq"
            | "curr_idx_eq" | "idx_eq" => {
                CovOps::from_tree(name, node).map(|ops| Self::Introspect(Box::new(ops)))
            }
            _ => return None,
        })
    }
}

impl ParseableExt for CovenantExt<CovExtArgs> {
    fn encode(&self, builder: Builder) -> Builder {
        match self {
            Self::Csfs(csfs) => csfs.encode(builder),
            Self::Arith(arith) => arith.encode(builder),
            Self::Introspect(ops) => ops.encode(builder),
        }
    }

    fn decode(tokens: &mut TokenIter) -> Option<Self> {
        let tks = tokens.as_slice();
        let (ext, start) = CheckSigFromStack::decode(tks)
            .map(|(csfs, start)| (Self::Csfs(Box::new(csfs)), start))
            .or_else(|| {
                Arith::decode(tks).map(|(arith, start)| (Self::Arith(Box::new(arith)), start))
            })
            .or_else(|| {
                CovOps::decode(tks).map(|(ops, start)| (Self::Introspect(Box::new(ops)), start))
            })?;
        tokens.truncate(start);
        Some(ext)
    }

    fn sat_dissat<Pk: ToPublicKey, P: AssetProvider<Pk>>(
        &self,
        provider: &P,
        root_has_sig: bool,
    ) -> (Satisfaction<Placeholder<Pk>>, Satisfaction<Placeholder<Pk>>) {
        let satisfaction = |stack| Satisfaction {
            stack,
            has_sig: false,
            relative_timelock: None,
            absolute_timelock: None,
        };
        let (sat, dissat) = match self {
            Self::Csfs(csfs) => {
                let sat = if provider.provider_lookup_csfs_sig(csfs.key(), csfs.message()) {
                    Witness::Stack(vec![Placeholder::CsfsSig(*csfs.key(), csfs.message().clone())])
                } else {
                    // Like a hash preimage, a signature missing here may be known to others.
                    Witness::Unavailable
                };
                (sat, Witness::Stack(vec![Placeholder::PushZero]))
            }
            Self::Arith(arith) => {
                let mut attestations = vec![];
                let holds = provider.provider_lookup_tx_env().map(|env| {
                    arith.eval(env, &mut |key: &XOnlyPublicKey,
                                          min_timestamp|
                     -> Result<i64, EvalError> {
                        let (sig, price, timestamp) = provider
                            .provider_lookup_price_oracle_sig(key, min_timestamp)
                            .ok_or(EvalError::MissingOracleWitness)?;
                        check_timestamp(timestamp, min_timestamp)?;
                        attestations.push([
                            Placeholder::Data(sig.serialize().to_vec()),
                            Placeholder::Data(timestamp.to_le_bytes().to_vec()),
                            Placeholder::Data(price.to_le_bytes().to_vec()),
                        ]);
                        Ok(price)
                    })
                });
                // The first attestation that the script consumes is on top of the stack.
                let witness = attestations.into_iter().rev().flatten().collect();
                (
                    tx_condition(holds, witness, root_has_sig && arith.n_oracles() == 0),
                    Witness::Impossible,
                )
            }
            Self::Introspect(ops) => {
                let holds = provider.provider_lookup_tx_env().map(|env| ops.eval(env));
                (tx_condition(holds, vec![], root_has_sig), Witness::Impossible)
            }
        };
        (satisfaction(sat), satisfaction(dissat))
    }

    fn evaluate(&self, stack: &mut Stack, env: Option<&TxEnv>) -> Result<bool, interpreter::Error> {
        let holds = match self {
            Self::Csfs(csfs) => return csfs.evaluate(stack),
            Self::Arith(arith) => env.ok_or(EvalError::TxEnvNotPresent).and_then(|env| {
                let secp = Secp256k1::verification_only();
                arith.eval(env, &mut |key: &XOnlyPublicKey, min_timestamp| {
                    pop_attestation(stack, &secp, key, min_timestamp)
                })
            }),
            Self::Introspect(ops) => env
                .ok_or(EvalError::TxEnvNotPresent)
                .and_then(|env| ops.eval(env)),
        };
        holds.map_err(interpreter::Error::Extension)
    }
}

// The witness of a fragment that holds for some transactions only.
fn tx_condition<Pk: MiniscriptKey>(
    holds: Option<Result<bool, EvalError>>,
    witness: Vec<Placeholder<Pk>>,
    root_has_sig: bool,
) -> Witness<Placeholder<Pk>> {
    match holds {
        Some(Ok(true)) => Witness::Stack(witness),
        // Without the transaction or an attestation, it is unknown whether the condition holds.
        None | Some(Err(EvalError::MissingOracleWitness)) => Witness::Unavailable,
        // A signature commits to the transaction, so nobody can make the condition hold.
        Some(_) if root_has_sig => Witness::Impossible,
        Some(_) => Witness::Unavailable,
    }
}

// Pops a price attestation, checking it like the script does.
fn pop_attestation(
    stack: &mut Stack,
    secp: &Secp256k1<secp256k1::VerifyOnly>,
    key: &XOnlyPublicKey,
    min_timestamp: u64,
) -> Result<i64, EvalError> {
    let mut pop = || match stack.pop() {
        Some(Element::Push(item)) => Ok(item),
        _ => Err(EvalError::MissingOracleWitness),
    };
    let (price, timestamp, sig) = (pop()?, pop()?, pop()?);
    let price = u64::from_le_bytes(
        price
            .try_into()
            .map_err(|_| EvalError::MalformedOracleWitness)?,
    );
    let timestamp = u64::from_le_bytes(
        timestamp
            .try_into()
            .map_err(|_| EvalError::MalformedOracleWitness)?,
    );
    let sig = schnorr::Signature::from_slice(sig).map_err(|_| EvalError::MalformedOracleWitness)?;
    check_timestamp(timestamp, min_timestamp)?;
    if !check_sig_price_oracle_1(secp, &sig, key, timestamp, price) {
        return Err(EvalError::InvalidOracleSignature);
    }
    Ok(i64::from_le_bytes(price.to_le_bytes()))
}

fn check_timestamp(timestamp: u64, min_timestamp: u64) -> Result<(), EvalError> {
    // `GREATERTHANOREQUAL64` compares the 8 bytes of each as signed numbers.
    if i64::from_le_bytes(timestamp.to_le_bytes()) < i64::from_le_bytes(min_timestamp.to_le_bytes())
    {
        return Err(EvalError::OracleTimestampTooEarly { timestamp, min_timestamp });
    }
    Ok(())
}

/// The message that a price oracle signs for the `price_oracle1` fragments: the SHA256 of
/// the timestamp and price, as 8-byte little-endian numbers.
pub fn sighash_msg_price_oracle_1(timestamp: u64, price: u64) -> Message {
    let mut engine = sha256::Hash::engine();
    engine.input(&timestamp.to_le_bytes());
    engine.input(&price.to_le_bytes());
    Message::from_digest(sha256::Hash::from_engine(engine).to_byte_array())
}

/// Checks a price oracle signature for the `price_oracle1` fragments.
pub fn check_sig_price_oracle_1<C: secp256k1::Verification>(
    secp: &Secp256k1<C>,
    sig: &schnorr::Signature,
    pk: &XOnlyPublicKey,
    timestamp: u64,
    price: u64,
) -> bool {
    secp.verify_schnorr(sig, &sighash_msg_price_oracle_1(timestamp, price), pk)
        .is_ok()
}

/// The transaction spending a covenant, which its fragments inspect.
#[derive(Clone, Debug)]
pub struct TxEnv<'tx, 'ptx> {
    tx: &'tx Transaction,
    spent_utxos: SpentUtxos<'ptx>,
    idx: usize,
}

// The outputs that the inputs spend, borrowed as the caller holds them, or references
// collected from another form.
#[derive(Clone, Debug)]
enum SpentUtxos<'ptx> {
    Outputs(&'ptx [TxOut]),
    Refs(&'ptx [&'ptx TxOut]),
    Collected(Vec<&'ptx TxOut>),
}

impl<'ptx> SpentUtxos<'ptx> {
    fn len(&self) -> usize {
        match self {
            Self::Outputs(outputs) => outputs.len(),
            Self::Refs(refs) => refs.len(),
            Self::Collected(refs) => refs.len(),
        }
    }

    fn get(&self, i: usize) -> Option<&'ptx TxOut> {
        match self {
            Self::Outputs(outputs) => outputs.get(i),
            Self::Refs(refs) => refs.get(i).copied(),
            Self::Collected(refs) => refs.get(i).copied(),
        }
    }
}

impl<'tx, 'ptx> TxEnv<'tx, 'ptx> {
    /// Creates the context of input `idx` of `tx`, given the outputs that its inputs spend.
    ///
    /// Returns `None` unless there is one spent output per input and `idx` is an input.
    pub fn new(tx: &'tx Transaction, spent_utxos: &'ptx [TxOut], idx: usize) -> Option<Self> {
        Self::with_spent_utxos(tx, SpentUtxos::Outputs(spent_utxos), idx)
    }

    /// Like [`Self::new`], with references to the spent outputs, as a PSET holds them.
    pub fn from_refs(
        tx: &'tx Transaction,
        spent_utxos: &'ptx [&'ptx TxOut],
        idx: usize,
    ) -> Option<Self> {
        Self::with_spent_utxos(tx, SpentUtxos::Refs(spent_utxos), idx)
    }

    /// Like [`Self::new`], collecting references to the spent outputs into a vector, for
    /// callers that hold them in neither form above.
    pub fn from_iter<I>(tx: &'tx Transaction, spent_utxos: I, idx: usize) -> Option<Self>
    where
        I: IntoIterator<Item = &'ptx TxOut>,
    {
        Self::with_spent_utxos(tx, SpentUtxos::Collected(spent_utxos.into_iter().collect()), idx)
    }

    fn with_spent_utxos(
        tx: &'tx Transaction,
        spent_utxos: SpentUtxos<'ptx>,
        idx: usize,
    ) -> Option<Self> {
        let n_inputs = tx.input.len();
        (spent_utxos.len() == n_inputs && idx < n_inputs).then_some(Self { tx, spent_utxos, idx })
    }

    /// The transaction.
    pub fn tx(&self) -> &'tx Transaction { self.tx }

    /// The index of the input being spent.
    pub fn idx(&self) -> usize { self.idx }

    /// The output that input `i` spends, failing if there is no input `i`.
    pub fn spent_utxo(&self, i: usize) -> Result<&'ptx TxOut, EvalError> {
        self.spent_utxos
            .get(i)
            .ok_or(EvalError::InputIndexOutOfBounds(i, self.spent_utxos.len()))
    }

    fn input(&self, i: usize) -> Result<&TxIn, EvalError> {
        self.tx
            .input
            .get(i)
            .ok_or(EvalError::InputIndexOutOfBounds(i, self.tx.input.len()))
    }

    fn output(&self, i: usize) -> Result<&TxOut, EvalError> {
        self.tx
            .output
            .get(i)
            .ok_or(EvalError::OutputIndexOutOfBounds(i, self.tx.output.len()))
    }
}

impl<Pk: ToPublicKey> Satisfier<Pk> for TxEnv<'_, '_> {
    fn lookup_tx_env(&self) -> Option<&TxEnv<'_, '_>> { Some(self) }
}

/// An error evaluating a covenant fragment, where the script would fail.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EvalError {
    /// The transaction was not provided.
    TxEnvNotPresent,
    /// An input index out of bounds, and the number of inputs.
    InputIndexOutOfBounds(usize, usize),
    /// An output index out of bounds, and the number of outputs.
    OutputIndexOutOfBounds(usize, usize),
    /// An index expression was negative.
    NegativeIndex(i64),
    /// An index expression left the 4-byte script number range.
    IndexOverflow,
    /// A division by zero.
    DivByZero,
    /// The value of the input at the index is confidential.
    NonExplicitInput(usize),
    /// The value of the output at the index is confidential.
    NonExplicitOutput(usize),
    /// The issuance amount of the input at the index is missing or confidential.
    NonExplicitInputIssuance(usize),
    /// The reissuance token amount of the input at the index is missing or confidential.
    NonExplicitInputReIssuance(usize),
    /// An addition overflowed.
    AddOverflow(i64, i64),
    /// A subtraction overflowed.
    SubOverflow(i64, i64),
    /// A multiplication overflowed.
    MulOverflow(i64, i64),
    /// A division overflowed.
    DivOverflow(i64, i64),
    /// A negation overflowed.
    NegOverflow(i64),
    /// A price attestation is missing.
    MissingOracleWitness,
    /// A price attestation has an item of the wrong size.
    MalformedOracleWitness,
    /// A price attestation is older than the fragment allows.
    #[allow(missing_docs)]
    OracleTimestampTooEarly { timestamp: u64, min_timestamp: u64 },
    /// A price attestation has an invalid signature.
    InvalidOracleSignature,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TxEnvNotPresent => f.write_str("covenant evaluation requires the transaction"),
            Self::InputIndexOutOfBounds(i, n) => write!(f, "input {} of {} inputs", i, n),
            Self::OutputIndexOutOfBounds(i, n) => write!(f, "output {} of {} outputs", i, n),
            Self::NegativeIndex(i) => write!(f, "negative index {}", i),
            Self::IndexOverflow => f.write_str("index out of the 4-byte script number range"),
            Self::DivByZero => f.write_str("division by zero"),
            Self::NonExplicitInput(i) => write!(f, "value of input {} is not explicit", i),
            Self::NonExplicitOutput(i) => write!(f, "value of output {} is not explicit", i),
            Self::NonExplicitInputIssuance(i) => {
                write!(f, "issuance amount of input {} is not explicit", i)
            }
            Self::NonExplicitInputReIssuance(i) => {
                write!(f, "reissuance token amount of input {} is not explicit", i)
            }
            Self::AddOverflow(x, y) => write!(f, "{} + {} overflows", x, y),
            Self::SubOverflow(x, y) => write!(f, "{} - {} overflows", x, y),
            Self::MulOverflow(x, y) => write!(f, "{} * {} overflows", x, y),
            Self::DivOverflow(x, y) => write!(f, "{} / {} overflows", x, y),
            Self::NegOverflow(x) => write!(f, "-({}) overflows", x),
            Self::MissingOracleWitness => f.write_str("missing price attestation"),
            Self::MalformedOracleWitness => f.write_str("malformed price attestation"),
            Self::OracleTimestampTooEarly { timestamp, min_timestamp } => {
                write!(f, "price attestation timestamp {} is before {}", timestamp, min_timestamp)
            }
            Self::InvalidOracleSignature => f.write_str("invalid price attestation signature"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EvalError {}

// Parses a decimal number in canonical form: without `+`, leading zeros or `-0`.
fn parse_canonical<N: FromStr>(s: &str) -> Result<N, Error> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (!digits.starts_with('0') || s == "0");
    canonical
        .then(|| N::from_str(s).ok())
        .flatten()
        .ok_or_else(|| Error::Unexpected(format!("{} is not a number in range", s)))
}

// The name of `node`, which must have no children.
fn terminal_name(node: TreeIterItem<'_>) -> Result<&str, Error> {
    match node.n_children() {
        0 => Ok(node.name()),
        _ => Err(unexpected(node)),
    }
}

fn unexpected(node: TreeIterItem) -> Error {
    Error::Unexpected(format!("{}({} args) in a covenant fragment", node.name(), node.n_children()))
}

fn tree_error(e: crate::ParseTreeError) -> Error { Error::Parse(ParseError::Tree(e)) }

// Translates the argument at position `pos` of the fragment `parent`, checking the result.
fn translate_arg<P: ExtParam, T: ExtParamTranslator<P>>(
    t: &mut T,
    arg: &P,
    parent: &str,
    pos: usize,
) -> Result<T::TargetArg, TranslateErr<T::Error>> {
    let arg = t.ext(arg)?;
    arg.check_arg(parent, pos)
        .map_err(TranslateErr::OuterError)?;
    Ok(arg)
}

#[cfg(test)]
mod tests;
