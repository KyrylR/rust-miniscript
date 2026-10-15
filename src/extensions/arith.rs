// SPDX-License-Identifier: CC0-1.0

//! 64-bit arithmetic fragments

use core::fmt;

use bitcoin::key::XOnlyPublicKey;
use elements::confidential;
use elements::opcodes::all::*;
use elements::script::Builder;

use super::param::ExtParamTranslator;
use super::{
    parse_canonical, terminal_name, translate_arg, tree_error, unexpected, CovExtArgs, EvalError,
    ExtParam, IdxExpr, TxEnv,
};
use crate::expression::TreeIterItem;
use crate::miniscript::lex::Token as Tk;
use crate::prelude::*;
use crate::{Error, TranslateErr, MAX_RECURSION_DEPTH};

/// A comparison of two [`Expr`]s: `[X] [Y] <comparison>`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Arith<T: ExtParam> {
    comparison: Comparison,
    left: Expr<T>,
    right: Expr<T>,
}

/// The comparison of an [`Arith`] fragment.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Comparison {
    /// `num64_eq`: `EQUAL`
    Eq,
    /// `num64_lt`: `LESSTHAN64`
    Lt,
    /// `num64_leq`: `LESSTHANOREQUAL64`
    Leq,
    /// `num64_gt`: `GREATERTHAN64`
    Gt,
    /// `num64_geq`: `GREATERTHANOREQUAL64`
    Geq,
}

/// An expression pushing a signed 64-bit little-endian number.
///
/// Evaluation fails where the script fails: on amounts which are not explicit, indexes out of
/// bounds, overflow and division by zero.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Expr<T: ExtParam> {
    /// A constant: `<8-byte number>`
    Const(i64),
    /// The value of the input being spent:
    /// `PUSHCURRENTINPUTINDEX INSPECTINPUTVALUE <1> EQUALVERIFY`
    CurrInputValue,
    /// The value of an input: `[I] INSPECTINPUTVALUE <1> EQUALVERIFY`
    Input(IdxExpr),
    /// The value of an output: `[I] INSPECTOUTPUTVALUE <1> EQUALVERIFY`
    Output(IdxExpr),
    /// The issuance amount of an input:
    /// `[I] INSPECTINPUTISSUANCE SIZE <32> EQUALVERIFY DROP DROP <1> EQUALVERIFY NIP NIP`
    InputIssue(IdxExpr),
    /// The reissuance token amount of an input:
    /// `[I] INSPECTINPUTISSUANCE SIZE <32> EQUALVERIFY DROP DROP DROP DROP <1> EQUALVERIFY`
    InputReIssue(IdxExpr),
    /// `[X] [Y] ADD64 <1> EQUALVERIFY`
    Add(Box<Self>, Box<Self>),
    /// `[X] [Y] SUB64 <1> EQUALVERIFY`
    Sub(Box<Self>, Box<Self>),
    /// `[X] [Y] MUL64 <1> EQUALVERIFY`
    Mul(Box<Self>, Box<Self>),
    /// Euclidean division: `[X] [Y] DIV64 <1> EQUALVERIFY NIP`
    Div(Box<Self>, Box<Self>),
    /// Euclidean remainder, which is never negative: `[X] [Y] DIV64 <1> EQUALVERIFY DROP`
    Mod(Box<Self>, Box<Self>),
    /// `[X] [Y] AND`
    BitAnd(Box<Self>, Box<Self>),
    /// `[X] [Y] OR`
    BitOr(Box<Self>, Box<Self>),
    /// `[X] [Y] XOR`
    Xor(Box<Self>, Box<Self>),
    /// `[X] INVERT`
    Invert(Box<Self>),
    /// `[X] NEG64 <1> EQUALVERIFY`
    Negate(Box<Self>),
    /// A price that the oracle with the key signed with at least the given timestamp, from the
    /// witness `<signature> <timestamp> <price>`:
    /// `2DUP TOALTSTACK <timestamp> GREATERTHANOREQUAL64 VERIFY CAT SHA256 <key>
    /// CHECKSIGFROMSTACKVERIFY FROMALTSTACK`
    ///
    /// The witness must be on top of the stack, so this must be the first operand evaluated.
    PriceOracle1(T, u64),
    /// [`Self::PriceOracle1`] for when the stack holds exactly one evaluated operand, which it
    /// keeps below the price: `TOALTSTACK [PriceOracle1] FROMALTSTACK SWAP`
    PriceOracle1W(T, u64),
}

impl<T: ExtParam> Arith<T> {
    /// Creates a comparison, checking the positions of price oracles and that the operands nest
    /// no deeper than decoding allows.
    pub fn new(comparison: Comparison, left: Expr<T>, right: Expr<T>) -> Result<Self, Error> {
        left.check_depth()?;
        right.check_depth()?;
        left.check(0)?;
        right.check(1)?;
        Ok(Self { comparison, left, right })
    }

    /// The comparison.
    pub fn comparison(&self) -> Comparison { self.comparison }

    /// The left operand.
    pub fn left(&self) -> &Expr<T> { &self.left }

    /// The right operand.
    pub fn right(&self) -> &Expr<T> { &self.right }

    pub(super) fn from_tree(name: &str, node: TreeIterItem) -> Result<Self, Error> {
        let comparison = match name {
            "num64_eq" => Comparison::Eq,
            "num64_lt" => Comparison::Lt,
            "num64_leq" => Comparison::Leq,
            "num64_gt" => Comparison::Gt,
            "num64_geq" => Comparison::Geq,
            _ => return Err(unexpected(node)),
        };
        let (left, right) = node.verify_binary("comparison").map_err(tree_error)?;
        Self::new(comparison, Expr::from_tree(left)?, Expr::from_tree(right)?)
    }

    pub(super) fn script_size(&self) -> usize {
        self.left.script_size() + self.right.script_size() + 1
    }

    /// The most stack and altstack items this has pushed at any point of its execution.
    pub(super) fn max_stack(&self) -> usize {
        self.left.max_stack().max(1 + self.right.max_stack())
    }

    /// The number of price oracle attestations in the witness.
    pub(super) fn n_oracles(&self) -> usize { self.left.n_oracles() + self.right.n_oracles() }

    pub(super) fn translate<X>(
        &self,
        t: &mut X,
    ) -> Result<Arith<X::TargetArg>, TranslateErr<X::Error>>
    where
        X: ExtParamTranslator<T>,
    {
        // Translation keeps the oracle positions, which `new` checked.
        Ok(Arith {
            comparison: self.comparison,
            left: self.left.translate(t)?,
            right: self.right.translate(t)?,
        })
    }
}

impl Arith<CovExtArgs> {
    pub(super) fn encode(&self, builder: Builder) -> Builder {
        let builder = self.right.encode(self.left.encode(builder));
        builder.push_opcode(match self.comparison {
            Comparison::Eq => OP_EQUAL,
            Comparison::Lt => OP_LESSTHAN64,
            Comparison::Leq => OP_LESSTHANOREQUAL64,
            Comparison::Gt => OP_GREATERTHAN64,
            Comparison::Geq => OP_GREATERTHANOREQUAL64,
        })
    }

    /// Decodes the fragment at the end of `tks`, returning it with its start.
    pub(super) fn decode(tks: &[Tk]) -> Option<(Self, usize)> {
        let comparison = match tks.last()? {
            Tk::Equal => Comparison::Eq,
            Tk::Le64 => Comparison::Lt,
            Tk::Leq64 => Comparison::Leq,
            Tk::Ge64 => Comparison::Gt,
            Tk::Geq64 => Comparison::Geq,
            _ => return None,
        };
        let (right, right_start) = Expr::decode(tks, tks.len() - 1, 0)?;
        let (left, start) = Expr::decode(tks, right_start, 0)?;
        Some((Self::new(comparison, left, right).ok()?, start))
    }

    /// Evaluates the comparison, taking price attestations from `oracle` in script order.
    pub(super) fn eval<O>(&self, env: &TxEnv, oracle: &mut O) -> Result<bool, EvalError>
    where
        O: FnMut(&XOnlyPublicKey, u64) -> Result<i64, EvalError>,
    {
        let left = self.left.eval(env, oracle)?;
        let right = self.right.eval(env, oracle)?;
        Ok(match self.comparison {
            Comparison::Eq => left == right,
            Comparison::Lt => left < right,
            Comparison::Leq => left <= right,
            Comparison::Gt => left > right,
            Comparison::Geq => left >= right,
        })
    }
}

impl<T: ExtParam> fmt::Display for Arith<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.comparison {
            Comparison::Eq => "num64_eq",
            Comparison::Lt => "num64_lt",
            Comparison::Leq => "num64_leq",
            Comparison::Gt => "num64_gt",
            Comparison::Geq => "num64_geq",
        };
        write!(f, "{}({},{})", name, self.left, self.right)
    }
}

impl<T: ExtParam> Expr<T> {
    fn from_tree(node: TreeIterItem) -> Result<Self, Error> {
        let mut children = node.children();
        let op: fn(Box<Self>, Box<Self>) -> Self =
            match (node.name(), children.next(), children.next(), children.next()) {
                ("curr_inp_v", None, _, _) => return Ok(Self::CurrInputValue),
                (num, None, _, _) => return parse_canonical(num).map(Self::Const),
                ("inp_v", Some(i), None, _) => return IdxExpr::from_tree(i).map(Self::Input),
                ("out_v", Some(i), None, _) => return IdxExpr::from_tree(i).map(Self::Output),
                ("inp_issue_v", Some(i), None, _) => {
                    return IdxExpr::from_tree(i).map(Self::InputIssue)
                }
                ("inp_reissue_v", Some(i), None, _) => {
                    return IdxExpr::from_tree(i).map(Self::InputReIssue)
                }
                ("bitinv", Some(x), None, _) => {
                    return Ok(Self::Invert(Box::new(Self::from_tree(x)?)))
                }
                ("neg", Some(x), None, _) => {
                    return Ok(Self::Negate(Box::new(Self::from_tree(x)?)))
                }
                (name @ ("price_oracle1" | "price_oracle1_w"), Some(key), Some(time), None) => {
                    let key = T::arg_from_str(terminal_name(key)?, name, 0)?;
                    let time = parse_canonical(terminal_name(time)?)?;
                    return Ok(match name {
                        "price_oracle1" => Self::PriceOracle1(key, time),
                        _ => Self::PriceOracle1W(key, time),
                    });
                }
                ("add", Some(_), Some(_), None) => Self::Add,
                ("sub", Some(_), Some(_), None) => Self::Sub,
                ("mul", Some(_), Some(_), None) => Self::Mul,
                ("div", Some(_), Some(_), None) => Self::Div,
                ("mod", Some(_), Some(_), None) => Self::Mod,
                ("bitand", Some(_), Some(_), None) => Self::BitAnd,
                ("bitor", Some(_), Some(_), None) => Self::BitOr,
                ("bitxor", Some(_), Some(_), None) => Self::Xor,
                _ => return Err(unexpected(node)),
            };
        let (x, y) = node
            .verify_binary("arithmetic operation")
            .map_err(tree_error)?;
        Ok(op(Box::new(Self::from_tree(x)?), Box::new(Self::from_tree(y)?)))
    }

    // Fails if the expression nests deeper than decoding allows, before any recursive method
    // walks it.
    fn check_depth(&self) -> Result<(), Error> {
        let mut stack = vec![(self, 0)];
        while let Some((expr, depth)) = stack.pop() {
            if depth > MAX_RECURSION_DEPTH {
                return Err(Error::MaxRecursiveDepthExceeded);
            }
            match expr {
                Self::Input(i) | Self::Output(i) | Self::InputIssue(i) | Self::InputReIssue(i) => {
                    i.check_depth(depth + 1)?
                }
                Self::Add(x, y)
                | Self::Sub(x, y)
                | Self::Mul(x, y)
                | Self::Div(x, y)
                | Self::Mod(x, y)
                | Self::BitAnd(x, y)
                | Self::BitOr(x, y)
                | Self::Xor(x, y) => {
                    stack.push((&**x, depth + 1));
                    stack.push((&**y, depth + 1));
                }
                Self::Invert(x) | Self::Negate(x) => stack.push((&**x, depth + 1)),
                Self::Const(_)
                | Self::CurrInputValue
                | Self::PriceOracle1(..)
                | Self::PriceOracle1W(..) => {}
            }
        }
        Ok(())
    }

    // Checks the oracles, given the number of operands on the stack when this starts.
    fn check(&self, below: usize) -> Result<(), Error> {
        match self {
            Self::PriceOracle1(key, _) if below == 0 => key.check_arg("price_oracle1", 0),
            Self::PriceOracle1W(key, _) if below == 1 => key.check_arg("price_oracle1_w", 0),
            Self::PriceOracle1(..) | Self::PriceOracle1W(..) => Err(Error::Unexpected(format!(
                "{} with {} operands evaluated before it",
                self, below
            ))),
            Self::Add(x, y)
            | Self::Sub(x, y)
            | Self::Mul(x, y)
            | Self::Div(x, y)
            | Self::Mod(x, y)
            | Self::BitAnd(x, y)
            | Self::BitOr(x, y)
            | Self::Xor(x, y) => {
                x.check(below)?;
                y.check(below + 1)
            }
            Self::Invert(x) | Self::Negate(x) => x.check(below),
            _ => Ok(()),
        }
    }

    fn script_size(&self) -> usize {
        match self {
            Self::Const(_) => 9,
            Self::CurrInputValue => 4,
            Self::Input(i) | Self::Output(i) => i.script_size() + 3,
            Self::InputIssue(i) | Self::InputReIssue(i) => i.script_size() + 11,
            Self::Add(x, y) | Self::Sub(x, y) | Self::Mul(x, y) => {
                x.script_size() + y.script_size() + 3
            }
            Self::Div(x, y) | Self::Mod(x, y) => x.script_size() + y.script_size() + 4,
            Self::BitAnd(x, y) | Self::BitOr(x, y) | Self::Xor(x, y) => {
                x.script_size() + y.script_size() + 1
            }
            Self::Invert(x) => x.script_size() + 1,
            Self::Negate(x) => x.script_size() + 3,
            // Ten opcodes, an 8-byte timestamp push and a 32-byte key push.
            Self::PriceOracle1(..) => 50,
            Self::PriceOracle1W(..) => 53,
        }
    }

    // The most stack and altstack items this has pushed at any point of its execution.
    fn max_stack(&self) -> usize {
        match self {
            Self::Const(_) => 1,
            // The value, its prefix and `<1>`.
            Self::CurrInputValue => 3,
            Self::Input(i) | Self::Output(i) => i.max_stack().max(3),
            // Six issuance items plus the nonce-size check.
            Self::InputIssue(i) | Self::InputReIssue(i) => i.max_stack().max(8),
            // The result, its overflow flag and `<1>`.
            Self::Add(x, y) | Self::Sub(x, y) | Self::Mul(x, y) => {
                x.max_stack().max(1 + y.max_stack()).max(3)
            }
            // The remainder, the quotient, the overflow flag and `<1>`.
            Self::Div(x, y) | Self::Mod(x, y) => x.max_stack().max(1 + y.max_stack()).max(4),
            Self::BitAnd(x, y) | Self::BitOr(x, y) | Self::Xor(x, y) => {
                x.max_stack().max(1 + y.max_stack())
            }
            Self::Invert(x) => x.max_stack(),
            Self::Negate(x) => x.max_stack().max(3),
            // Beyond the witness: the copies of the timestamp and price, and the threshold.
            Self::PriceOracle1(..) | Self::PriceOracle1W(..) => 3,
        }
    }

    fn n_oracles(&self) -> usize {
        match self {
            Self::PriceOracle1(..) | Self::PriceOracle1W(..) => 1,
            Self::Add(x, y)
            | Self::Sub(x, y)
            | Self::Mul(x, y)
            | Self::Div(x, y)
            | Self::Mod(x, y)
            | Self::BitAnd(x, y)
            | Self::BitOr(x, y)
            | Self::Xor(x, y) => x.n_oracles() + y.n_oracles(),
            Self::Invert(x) | Self::Negate(x) => x.n_oracles(),
            _ => 0,
        }
    }

    fn translate<X>(&self, t: &mut X) -> Result<Expr<X::TargetArg>, TranslateErr<X::Error>>
    where
        X: ExtParamTranslator<T>,
    {
        type Op<Q> = fn(Box<Expr<Q>>, Box<Expr<Q>>) -> Expr<Q>;
        let binary = |t: &mut X, op: Op<X::TargetArg>, x: &Self, y: &Self| {
            Ok::<_, TranslateErr<X::Error>>(op(
                Box::new(x.translate(t)?),
                Box::new(y.translate(t)?),
            ))
        };
        match self {
            Self::Const(c) => Ok(Expr::Const(*c)),
            Self::CurrInputValue => Ok(Expr::CurrInputValue),
            Self::Input(i) => Ok(Expr::Input(i.clone())),
            Self::Output(i) => Ok(Expr::Output(i.clone())),
            Self::InputIssue(i) => Ok(Expr::InputIssue(i.clone())),
            Self::InputReIssue(i) => Ok(Expr::InputReIssue(i.clone())),
            Self::Add(x, y) => binary(t, Expr::Add, x, y),
            Self::Sub(x, y) => binary(t, Expr::Sub, x, y),
            Self::Mul(x, y) => binary(t, Expr::Mul, x, y),
            Self::Div(x, y) => binary(t, Expr::Div, x, y),
            Self::Mod(x, y) => binary(t, Expr::Mod, x, y),
            Self::BitAnd(x, y) => binary(t, Expr::BitAnd, x, y),
            Self::BitOr(x, y) => binary(t, Expr::BitOr, x, y),
            Self::Xor(x, y) => binary(t, Expr::Xor, x, y),
            Self::Invert(x) => Ok(Expr::Invert(Box::new(x.translate(t)?))),
            Self::Negate(x) => Ok(Expr::Negate(Box::new(x.translate(t)?))),
            Self::PriceOracle1(key, time) => {
                Ok(Expr::PriceOracle1(translate_arg(t, key, "price_oracle1", 0)?, *time))
            }
            Self::PriceOracle1W(key, time) => {
                Ok(Expr::PriceOracle1W(translate_arg(t, key, "price_oracle1_w", 0)?, *time))
            }
        }
    }
}

impl Expr<CovExtArgs> {
    fn encode(&self, builder: Builder) -> Builder {
        let checked = |builder: Builder| builder.push_int(1).push_opcode(OP_EQUALVERIFY);
        match self {
            Self::Const(c) => builder.push_slice(&c.to_le_bytes()),
            Self::CurrInputValue => checked(
                builder
                    .push_opcode(OP_PUSHCURRENTINPUTINDEX)
                    .push_opcode(OP_INSPECTINPUTVALUE),
            ),
            Self::Input(i) => checked(i.encode(builder).push_opcode(OP_INSPECTINPUTVALUE)),
            Self::Output(i) => checked(i.encode(builder).push_opcode(OP_INSPECTOUTPUTVALUE)),
            Self::InputIssue(i) => checked(
                i.encode(builder)
                    .push_opcode(OP_INSPECTINPUTISSUANCE)
                    .push_opcode(OP_SIZE)
                    .push_int(32)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_opcode(OP_DROP)
                    .push_opcode(OP_DROP),
            )
            .push_opcode(OP_NIP)
            .push_opcode(OP_NIP),
            Self::InputReIssue(i) => checked(
                i.encode(builder)
                    .push_opcode(OP_INSPECTINPUTISSUANCE)
                    .push_opcode(OP_SIZE)
                    .push_int(32)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_opcode(OP_DROP)
                    .push_opcode(OP_DROP)
                    .push_opcode(OP_DROP)
                    .push_opcode(OP_DROP),
            ),
            Self::Add(x, y) => checked(y.encode(x.encode(builder)).push_opcode(OP_ADD64)),
            Self::Sub(x, y) => checked(y.encode(x.encode(builder)).push_opcode(OP_SUB64)),
            Self::Mul(x, y) => checked(y.encode(x.encode(builder)).push_opcode(OP_MUL64)),
            Self::Div(x, y) => {
                checked(y.encode(x.encode(builder)).push_opcode(OP_DIV64)).push_opcode(OP_NIP)
            }
            Self::Mod(x, y) => {
                checked(y.encode(x.encode(builder)).push_opcode(OP_DIV64)).push_opcode(OP_DROP)
            }
            Self::BitAnd(x, y) => y.encode(x.encode(builder)).push_opcode(OP_AND),
            Self::BitOr(x, y) => y.encode(x.encode(builder)).push_opcode(OP_OR),
            Self::Xor(x, y) => y.encode(x.encode(builder)).push_opcode(OP_XOR),
            Self::Invert(x) => x.encode(builder).push_opcode(OP_INVERT),
            Self::Negate(x) => checked(x.encode(builder).push_opcode(OP_NEG64)),
            Self::PriceOracle1(key, time) => price_oracle(builder, key.as_key(), *time),
            Self::PriceOracle1W(key, time) => {
                price_oracle(builder.push_opcode(OP_TOALTSTACK), key.as_key(), *time)
                    .push_opcode(OP_FROMALTSTACK)
                    .push_opcode(OP_SWAP)
            }
        }
    }

    /// Decodes the expression ending just before `tks[end]`, returning it with its start.
    fn decode(tks: &[Tk], end: usize, depth: u32) -> Option<(Self, usize)> {
        if depth > MAX_RECURSION_DEPTH {
            return None;
        }
        let tks = tks.get(..end)?;
        let idx = |op_len, f: fn(IdxExpr) -> Self| {
            IdxExpr::decode(tks, end - op_len, depth + 1).map(|(i, start)| (f(i), start))
        };
        let unary = |op_len, f: fn(Box<Self>) -> Self| {
            Self::decode(tks, end - op_len, depth + 1).map(|(x, start)| (f(Box::new(x)), start))
        };
        #[allow(clippy::type_complexity)]
        let (op, op_len): (fn(Box<Self>, Box<Self>) -> Self, usize) = match tks {
            [.., Tk::Bytes8(c)] => return Some((Self::Const(i64::from_le_bytes(*c)), end - 1)),
            [.., Tk::CurrInp, Tk::InpValue, Tk::Num(1), Tk::Equal, Tk::Verify] => {
                return Some((Self::CurrInputValue, end - 5))
            }
            [.., Tk::InpValue, Tk::Num(1), Tk::Equal, Tk::Verify] => return idx(4, Self::Input),
            [.., Tk::OutValue, Tk::Num(1), Tk::Equal, Tk::Verify] => return idx(4, Self::Output),
            [.., Tk::InpIssue, Tk::Size, Tk::Num(32), Tk::Equal, Tk::Verify, Tk::Drop, Tk::Drop, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Nip, Tk::Nip] => {
                return idx(12, Self::InputIssue)
            }
            [.., Tk::InpIssue, Tk::Size, Tk::Num(32), Tk::Equal, Tk::Verify, Tk::Drop, Tk::Drop, Tk::Drop, Tk::Drop, Tk::Num(1), Tk::Equal, Tk::Verify] => {
                return idx(12, Self::InputReIssue)
            }
            [.., Tk::Invert] => return unary(1, Self::Invert),
            [.., Tk::Neg64, Tk::Num(1), Tk::Equal, Tk::Verify] => return unary(4, Self::Negate),
            [.., Tk::Dup2, Tk::ToAltStack, Tk::Bytes8(time), Tk::Geq64, Tk::Verify, Tk::Cat, Tk::Sha256, Tk::Bytes32(key), Tk::CheckSigFromStack, Tk::Verify, Tk::FromAltStack] =>
            {
                let key = CovExtArgs::csfs_key(XOnlyPublicKey::from_slice(key).ok()?);
                return Some((Self::PriceOracle1(key, u64::from_le_bytes(*time)), end - 11));
            }
            [.., Tk::ToAltStack, Tk::Dup2, Tk::ToAltStack, Tk::Bytes8(time), Tk::Geq64, Tk::Verify, Tk::Cat, Tk::Sha256, Tk::Bytes32(key), Tk::CheckSigFromStack, Tk::Verify, Tk::FromAltStack, Tk::FromAltStack, Tk::Swap] =>
            {
                let key = CovExtArgs::csfs_key(XOnlyPublicKey::from_slice(key).ok()?);
                return Some((Self::PriceOracle1W(key, u64::from_le_bytes(*time)), end - 14));
            }
            [.., Tk::Add64, Tk::Num(1), Tk::Equal, Tk::Verify] => (Self::Add, 4),
            [.., Tk::Sub64, Tk::Num(1), Tk::Equal, Tk::Verify] => (Self::Sub, 4),
            [.., Tk::Mul64, Tk::Num(1), Tk::Equal, Tk::Verify] => (Self::Mul, 4),
            [.., Tk::Div64, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Nip] => (Self::Div, 5),
            [.., Tk::Div64, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Drop] => (Self::Mod, 5),
            [.., Tk::And] => (Self::BitAnd, 1),
            [.., Tk::Or] => (Self::BitOr, 1),
            [.., Tk::Xor] => (Self::Xor, 1),
            _ => return None,
        };
        let (y, y_start) = Self::decode(tks, end - op_len, depth + 1)?;
        let (x, start) = Self::decode(tks, y_start, depth + 1)?;
        Some((op(Box::new(x), Box::new(y)), start))
    }

    fn eval<O>(&self, env: &TxEnv, oracle: &mut O) -> Result<i64, EvalError>
    where
        O: FnMut(&XOnlyPublicKey, u64) -> Result<i64, EvalError>,
    {
        let operands = |x: &Self, y: &Self, oracle: &mut O| -> Result<(i64, i64), EvalError> {
            Ok((x.eval(env, oracle)?, y.eval(env, oracle)?))
        };
        match self {
            Self::Const(c) => Ok(*c),
            Self::CurrInputValue => {
                let i = env.idx();
                explicit(env.spent_utxo(i)?.value, EvalError::NonExplicitInput(i))
            }
            Self::Input(i) => {
                let i = i.eval_index(env)?;
                explicit(env.spent_utxo(i)?.value, EvalError::NonExplicitInput(i))
            }
            Self::Output(i) => {
                let i = i.eval_index(env)?;
                explicit(env.output(i)?.value, EvalError::NonExplicitOutput(i))
            }
            Self::InputIssue(i) => {
                let i = i.eval_index(env)?;
                let issuance = &env.input(i)?.asset_issuance;
                if issuance.is_null() {
                    return Err(EvalError::NonExplicitInputIssuance(i));
                }
                explicit(issuance.amount, EvalError::NonExplicitInputIssuance(i))
            }
            Self::InputReIssue(i) => {
                let i = i.eval_index(env)?;
                let issuance = &env.input(i)?.asset_issuance;
                if issuance.is_null() {
                    return Err(EvalError::NonExplicitInputReIssuance(i));
                }
                explicit(issuance.inflation_keys, EvalError::NonExplicitInputReIssuance(i))
            }
            Self::Add(x, y) => {
                let (x, y) = operands(x, y, oracle)?;
                x.checked_add(y).ok_or(EvalError::AddOverflow(x, y))
            }
            Self::Sub(x, y) => {
                let (x, y) = operands(x, y, oracle)?;
                x.checked_sub(y).ok_or(EvalError::SubOverflow(x, y))
            }
            Self::Mul(x, y) => {
                let (x, y) = operands(x, y, oracle)?;
                x.checked_mul(y).ok_or(EvalError::MulOverflow(x, y))
            }
            Self::Div(x, y) => {
                let (x, y) = operands(x, y, oracle)?;
                div64(x, y).map(|(quotient, _)| quotient)
            }
            Self::Mod(x, y) => {
                let (x, y) = operands(x, y, oracle)?;
                div64(x, y).map(|(_, remainder)| remainder)
            }
            Self::BitAnd(x, y) => operands(x, y, oracle).map(|(x, y)| x & y),
            Self::BitOr(x, y) => operands(x, y, oracle).map(|(x, y)| x | y),
            Self::Xor(x, y) => operands(x, y, oracle).map(|(x, y)| x ^ y),
            Self::Invert(x) => x.eval(env, oracle).map(|x| !x),
            Self::Negate(x) => {
                let x = x.eval(env, oracle)?;
                x.checked_neg().ok_or(EvalError::NegOverflow(x))
            }
            Self::PriceOracle1(key, time) | Self::PriceOracle1W(key, time) => {
                oracle(key.as_key(), *time)
            }
        }
    }
}

fn price_oracle(builder: Builder, key: &XOnlyPublicKey, time: u64) -> Builder {
    builder
        .push_opcode(OP_2DUP)
        .push_opcode(OP_TOALTSTACK)
        .push_slice(&time.to_le_bytes())
        .push_opcode(OP_GREATERTHANOREQUAL64)
        .push_opcode(OP_VERIFY)
        .push_opcode(OP_CAT)
        .push_opcode(OP_SHA256)
        .push_slice(&key.serialize())
        .push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
        .push_opcode(OP_FROMALTSTACK)
}

// The quotient and remainder that `DIV64` pushes.
fn div64(x: i64, y: i64) -> Result<(i64, i64), EvalError> {
    if y == 0 {
        return Err(EvalError::DivByZero);
    }
    match (x.checked_div_euclid(y), x.checked_rem_euclid(y)) {
        (Some(quotient), Some(remainder)) => Ok((quotient, remainder)),
        _ => Err(EvalError::DivOverflow(x, y)),
    }
}

fn explicit(value: confidential::Value, err: EvalError) -> Result<i64, EvalError> {
    // The opcodes push the amount as 8 bytes, which the arithmetic opcodes read as signed.
    match value {
        confidential::Value::Null => Ok(0),
        confidential::Value::Explicit(value) => Ok(i64::from_le_bytes(value.to_le_bytes())),
        confidential::Value::Confidential(_) => Err(err),
    }
}

impl<T: ExtParam> fmt::Display for Expr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(c) => write!(f, "{}", c),
            Self::CurrInputValue => f.write_str("curr_inp_v"),
            Self::Input(i) => write!(f, "inp_v({})", i),
            Self::Output(i) => write!(f, "out_v({})", i),
            Self::InputIssue(i) => write!(f, "inp_issue_v({})", i),
            Self::InputReIssue(i) => write!(f, "inp_reissue_v({})", i),
            Self::Add(x, y) => write!(f, "add({},{})", x, y),
            Self::Sub(x, y) => write!(f, "sub({},{})", x, y),
            Self::Mul(x, y) => write!(f, "mul({},{})", x, y),
            Self::Div(x, y) => write!(f, "div({},{})", x, y),
            Self::Mod(x, y) => write!(f, "mod({},{})", x, y),
            Self::BitAnd(x, y) => write!(f, "bitand({},{})", x, y),
            Self::BitOr(x, y) => write!(f, "bitor({},{})", x, y),
            Self::Xor(x, y) => write!(f, "bitxor({},{})", x, y),
            Self::Invert(x) => write!(f, "bitinv({})", x),
            Self::Negate(x) => write!(f, "neg({})", x),
            Self::PriceOracle1(key, time) => write!(f, "price_oracle1({},{})", key, time),
            Self::PriceOracle1W(key, time) => write!(f, "price_oracle1_w({},{})", key, time),
        }
    }
}
