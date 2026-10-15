// SPDX-License-Identifier: CC0-1.0

//! Index expressions of the introspection fragments

use core::fmt;

use elements::opcodes::all::*;
use elements::script::Builder;

use super::{parse_canonical, tree_error, unexpected, EvalError, TxEnv};
use crate::expression::TreeIterItem;
use crate::miniscript::lex::Token as Tk;
use crate::prelude::*;
use crate::{script_num_size, Error, MAX_RECURSION_DEPTH};

/// A nonnegative constant representable by a four-byte script number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct IdxConst(u32);

impl IdxConst {
    /// Checks that the constant is at most `i32::MAX`.
    pub fn new(value: u32) -> Result<Self, Error> {
        if value <= i32::MAX as u32 {
            Ok(Self(value))
        } else {
            Err(Error::Unexpected(format!("index {} above i32::MAX", value)))
        }
    }

    /// The constant's value.
    pub fn value(self) -> u32 { self.0 }
}

/// An expression pushing a script number, used as an input or output index.
///
/// Numeric consumers require 4-byte script numbers. Addition and subtraction may produce
/// a 5-byte result, which can still be compared by `idx_eq`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum IdxExpr {
    /// A constant, at most `i32::MAX`: `<i>`
    Const(IdxConst),
    /// The index of the input being spent: `PUSHCURRENTINPUTINDEX`
    CurrIdx,
    /// `[X] [Y] ADD`
    Add(Box<Self>, Box<Self>),
    /// `[X] [Y] SUB`
    Sub(Box<Self>, Box<Self>),
    /// `[X] SCRIPTNUMTOLE64 [Y] SCRIPTNUMTOLE64 MUL64 <1> EQUALVERIFY LE64TOSCRIPTNUM`
    Mul(Box<Self>, Box<Self>),
    /// Euclidean division:
    /// `[X] SCRIPTNUMTOLE64 [Y] SCRIPTNUMTOLE64 DIV64 <1> EQUALVERIFY NIP LE64TOSCRIPTNUM`
    Div(Box<Self>, Box<Self>),
}

impl IdxExpr {
    pub(super) fn from_tree(node: TreeIterItem) -> Result<Self, Error> {
        let op: fn(Box<Self>, Box<Self>) -> Self = match (node.name(), node.n_children()) {
            ("curr_idx", 0) => return Ok(Self::CurrIdx),
            (name, 0) => {
                return IdxConst::new(parse_canonical(name)?).map(Self::Const);
            }
            ("idx_add", 2) => Self::Add,
            ("idx_sub", 2) => Self::Sub,
            ("idx_mul", 2) => Self::Mul,
            ("idx_div", 2) => Self::Div,
            _ => return Err(unexpected(node)),
        };
        let (x, y) = node.verify_binary("index operation").map_err(tree_error)?;
        Ok(op(Box::new(Self::from_tree(x)?), Box::new(Self::from_tree(y)?)))
    }

    /// Fails if the expression, starting at `depth`, nests operations deeper than decoding
    /// allows, before any recursive method walks it.
    pub(super) fn check_depth(&self, depth: u32) -> Result<(), Error> {
        let mut stack = vec![(self, depth)];
        while let Some((expr, depth)) = stack.pop() {
            if depth > MAX_RECURSION_DEPTH {
                return Err(Error::MaxRecursiveDepthExceeded);
            }
            match expr {
                Self::Const(_) | Self::CurrIdx => {}
                Self::Add(x, y) | Self::Sub(x, y) | Self::Mul(x, y) | Self::Div(x, y) => {
                    stack.push((&**x, depth + 1));
                    stack.push((&**y, depth + 1));
                }
            }
        }
        Ok(())
    }

    pub(super) fn script_size(&self) -> usize {
        match self {
            Self::Const(i) => script_num_size(i.value() as usize),
            Self::CurrIdx => 1,
            Self::Add(x, y) | Self::Sub(x, y) => x.script_size() + y.script_size() + 1,
            Self::Mul(x, y) => x.script_size() + y.script_size() + 6,
            Self::Div(x, y) => x.script_size() + y.script_size() + 7,
        }
    }

    /// The most stack items this has pushed at any point of its execution.
    pub(super) fn max_stack(&self) -> usize {
        match self {
            Self::Const(_) | Self::CurrIdx => 1,
            Self::Add(x, y) | Self::Sub(x, y) => x.max_stack().max(1 + y.max_stack()),
            // Up to the product or quotient and remainder, their flag and `<1>`.
            Self::Mul(x, y) => x.max_stack().max(1 + y.max_stack()).max(3),
            Self::Div(x, y) => x.max_stack().max(1 + y.max_stack()).max(4),
        }
    }

    pub(super) fn encode(&self, builder: Builder) -> Builder {
        match self {
            Self::Const(i) => builder.push_int(i64::from(i.value())),
            Self::CurrIdx => builder.push_opcode(OP_PUSHCURRENTINPUTINDEX),
            Self::Add(x, y) => y.encode(x.encode(builder)).push_opcode(OP_ADD),
            Self::Sub(x, y) => y.encode(x.encode(builder)).push_opcode(OP_SUB),
            Self::Mul(x, y) => {
                let builder = x.encode(builder).push_opcode(OP_SCRIPTNUMTOLE64);
                y.encode(builder)
                    .push_opcode(OP_SCRIPTNUMTOLE64)
                    .push_opcode(OP_MUL64)
                    .push_int(1)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_opcode(OP_LE64TOSCRIPTNUM)
            }
            Self::Div(x, y) => {
                let builder = x.encode(builder).push_opcode(OP_SCRIPTNUMTOLE64);
                y.encode(builder)
                    .push_opcode(OP_SCRIPTNUMTOLE64)
                    .push_opcode(OP_DIV64)
                    .push_int(1)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_opcode(OP_NIP)
                    .push_opcode(OP_LE64TOSCRIPTNUM)
            }
        }
    }

    /// Decodes the expression ending just before `tks[end]`, returning it with its start.
    pub(super) fn decode(tks: &[Tk], end: usize, depth: u32) -> Option<(Self, usize)> {
        if depth > MAX_RECURSION_DEPTH {
            return None;
        }
        let tks = tks.get(..end)?;
        #[allow(clippy::type_complexity)]
        let (op, op_len, le64): (fn(Box<Self>, Box<Self>) -> Self, _, _) = match tks {
            [.., Tk::Num(i)] => return Some((Self::Const(IdxConst::new(*i).ok()?), end - 1)),
            [.., Tk::CurrInp] => return Some((Self::CurrIdx, end - 1)),
            [.., Tk::Add] => (Self::Add, 1, false),
            [.., Tk::Sub] => (Self::Sub, 1, false),
            [.., Tk::ScriptNumToLe64, Tk::Mul64, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Le64ToScriptNum] => {
                (Self::Mul, 6, true)
            }
            [.., Tk::ScriptNumToLe64, Tk::Div64, Tk::Num(1), Tk::Equal, Tk::Verify, Tk::Nip, Tk::Le64ToScriptNum] => {
                (Self::Div, 7, true)
            }
            _ => return None,
        };
        let (y, mut x_end) = Self::decode(tks, end - op_len, depth + 1)?;
        if le64 {
            x_end = x_end
                .checked_sub(1)
                .filter(|&i| tks[i] == Tk::ScriptNumToLe64)?;
        }
        let (x, start) = Self::decode(tks, x_end, depth + 1)?;
        Some((op(Box::new(x), Box::new(y)), start))
    }

    pub(super) fn eval(&self, env: &TxEnv) -> Result<i64, EvalError> {
        let operands = |x: &Self, y: &Self| Ok((x.eval_num(env)?, y.eval_num(env)?));
        match self {
            Self::Const(i) => Ok(i64::from(i.value())),
            Self::CurrIdx => i64::try_from(env.idx()).map_err(|_| EvalError::IndexOverflow),
            Self::Add(x, y) => {
                let (x, y) = operands(x, y)?;
                Ok(x + y)
            }
            Self::Sub(x, y) => {
                let (x, y) = operands(x, y)?;
                Ok(x - y)
            }
            Self::Mul(x, y) => {
                let (x, y) = operands(x, y)?;
                script_num(x * y)
            }
            Self::Div(x, y) => {
                let (x, y) = operands(x, y)?;
                if y == 0 {
                    return Err(EvalError::DivByZero);
                }
                script_num(x.div_euclid(y))
            }
        }
    }

    fn eval_num(&self, env: &TxEnv) -> Result<i64, EvalError> { script_num(self.eval(env)?) }

    pub(super) fn eval_index(&self, env: &TxEnv) -> Result<usize, EvalError> {
        let n = self.eval_num(env)?;
        usize::try_from(n).map_err(|_| EvalError::NegativeIndex(n))
    }
}

impl fmt::Display for IdxExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(i) => write!(f, "{}", i.value()),
            Self::CurrIdx => f.write_str("curr_idx"),
            Self::Add(x, y) => write!(f, "idx_add({},{})", x, y),
            Self::Sub(x, y) => write!(f, "idx_sub({},{})", x, y),
            Self::Mul(x, y) => write!(f, "idx_mul({},{})", x, y),
            Self::Div(x, y) => write!(f, "idx_div({},{})", x, y),
        }
    }
}

fn script_num(n: i64) -> Result<i64, EvalError> {
    if (-i64::from(i32::MAX)..=i64::from(i32::MAX)).contains(&n) {
        Ok(n)
    } else {
        Err(EvalError::IndexOverflow)
    }
}
