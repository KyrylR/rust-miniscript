// SPDX-License-Identifier: CC0-1.0

//! Introspection fragments

use core::fmt;

use bitcoin::hashes::{sha256, Hash};
use elements::opcodes::all::*;
use elements::opcodes::All;
use elements::script::Builder;
use elements::{confidential, encode, TxOut};

use super::param::{spk_components, ExtParamTranslator, Spk};
use super::{translate_arg, unexpected, CovExtArgs, EvalError, ExtParam, IdxConst, IdxExpr, TxEnv};
use crate::expression::TreeIterItem;
use crate::miniscript::lex::Token as Tk;
use crate::prelude::*;
use crate::{script_num_size, Error, TranslateErr};

/// An introspection fragment.
///
/// The constructors, like parsing, decoding and translation, check that each constant operand
/// suits its position, as [`ExtParam::check_arg`] decides. For [`CovExtArgs`], a constant must
/// have the kind of its field, an asset must not be null, and a script pubkey must push a 20- or
/// 32-byte program. A null value pushes the same items as an explicit zero. The constructors
/// also reject index expressions nested deeper than decoding allows.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct CovOps<T: ExtParam>(Op<T>);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
enum Op<T: ExtParam> {
    IsExpAsset(FieldExpr<T>),
    IsExpValue(FieldExpr<T>),
    AssetEq(FieldExpr<T>, FieldExpr<T>),
    ValueEq(FieldExpr<T>, FieldExpr<T>),
    SpkEq(FieldExpr<T>, FieldExpr<T>),
    CurrIndEq(IdxConst),
    IdxEq(IdxExpr, IdxExpr),
}

/// An asset, value or script pubkey operand of an introspection fragment.
///
/// Operands push two items each: the data, then its prefix (explicit or confidential) or
/// witness version, where a non-witness script pubkey is version -1 with its SHA256 as data.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum FieldExpr<T: ExtParam> {
    /// A constant.
    Const(T),
    /// The field of the input being spent: `PUSHCURRENTINPUTINDEX INSPECTINPUT<FIELD>`
    CurrInput,
    /// The field of an input: `[I] INSPECTINPUT<FIELD>`
    Input(IdxExpr),
    /// The field of an output: `[I] INSPECTOUTPUT<FIELD>`
    Output(IdxExpr),
}

#[derive(Clone, Copy)]
enum Field {
    Asset,
    Value,
    Spk,
}

impl Field {
    // The names of the current input, input and output operands.
    fn names(self) -> [&'static str; 3] {
        match self {
            Self::Asset => ["curr_inp_asset", "inp_asset", "out_asset"],
            Self::Value => ["curr_inp_value", "inp_value", "out_value"],
            Self::Spk => ["curr_inp_spk", "inp_spk", "out_spk"],
        }
    }

    // The opcodes inspecting an input and an output.
    fn opcodes(self) -> (All, All) {
        match self {
            Self::Asset => (OP_INSPECTINPUTASSET, OP_INSPECTOUTPUTASSET),
            Self::Value => (OP_INSPECTINPUTVALUE, OP_INSPECTOUTPUTVALUE),
            Self::Spk => (OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTSCRIPTPUBKEY),
        }
    }

    fn tokens(self) -> (Tk, Tk) {
        match self {
            Self::Asset => (Tk::InpAsset, Tk::OutAsset),
            Self::Value => (Tk::InpValue, Tk::OutValue),
            Self::Spk => (Tk::InpSpk, Tk::OutSpk),
        }
    }

    // The items the opcodes push for the field of `txout`.
    fn of_txout(self, txout: &TxOut) -> (Vec<u8>, i64) {
        match self {
            Self::Asset => split_prefix(encode::serialize(&txout.asset)),
            Self::Value => value_items(&txout.value),
            Self::Spk => spk_items(spk_components(&txout.script_pubkey)),
        }
    }

    // The items a constant pushes, the same as the opcodes would for an equal field.
    fn of_arg(self, arg: &CovExtArgs) -> (Vec<u8>, i64) {
        match self {
            Self::Asset => split_prefix(encode::serialize(arg.as_asset())),
            Self::Value => value_items(arg.as_value()),
            Self::Spk => spk_items(arg.as_spk().components()),
        }
    }
}

fn split_prefix(ser: Vec<u8>) -> (Vec<u8>, i64) {
    match ser.split_first() {
        Some((prefix, data)) => (data.to_vec(), i64::from(*prefix)),
        None => (ser, 0),
    }
}

fn value_items(value: &confidential::Value) -> (Vec<u8>, i64) {
    match value {
        // Unlike its serialization, the pushed explicit value is little-endian.
        confidential::Value::Explicit(value) => (value.to_le_bytes().to_vec(), 1),
        confidential::Value::Null => (vec![0; 8], 1),
        _ => split_prefix(encode::serialize(value)),
    }
}

fn spk_items((version, program): (i8, Vec<u8>)) -> (Vec<u8>, i64) { (program, i64::from(version)) }

impl<T: ExtParam> CovOps<T> {
    /// `is_exp_asset(X)`, whether an asset is explicit: `[X] <1> EQUAL NIP`
    pub fn is_exp_asset(x: FieldExpr<T>) -> Result<Self, Error> { Self::checked(Op::IsExpAsset(x)) }

    /// `is_exp_value(X)`, whether a value is explicit, encoded like `is_exp_asset`
    pub fn is_exp_value(x: FieldExpr<T>) -> Result<Self, Error> { Self::checked(Op::IsExpValue(x)) }

    /// `asset_eq(X,Y)`, asset equality:
    /// `[X] TOALTSTACK [Y] FROMALTSTACK EQUAL TOALTSTACK EQUAL FROMALTSTACK BOOLAND`
    pub fn asset_eq(x: FieldExpr<T>, y: FieldExpr<T>) -> Result<Self, Error> {
        Self::checked(Op::AssetEq(x, y))
    }

    /// `value_eq(X,Y)`, value equality, encoded like `asset_eq`
    pub fn value_eq(x: FieldExpr<T>, y: FieldExpr<T>) -> Result<Self, Error> {
        Self::checked(Op::ValueEq(x, y))
    }

    /// `spk_eq(X,Y)`, script pubkey equality, encoded like `asset_eq`
    pub fn spk_eq(x: FieldExpr<T>, y: FieldExpr<T>) -> Result<Self, Error> {
        Self::checked(Op::SpkEq(x, y))
    }

    /// `curr_idx_eq(i)`, whether the input being spent has index `i`:
    /// `<i> PUSHCURRENTINPUTINDEX EQUAL`
    pub fn curr_idx_eq(i: IdxConst) -> Self { Self(Op::CurrIndEq(i)) }

    /// `idx_eq(X,Y)`, index equality: `[X] [Y] EQUAL`
    pub fn idx_eq(x: IdxExpr, y: IdxExpr) -> Result<Self, Error> { Self::checked(Op::IdxEq(x, y)) }

    fn checked(op: Op<T>) -> Result<Self, Error> {
        let name = op.name();
        match &op {
            Op::IsExpAsset(x) | Op::IsExpValue(x) => x.check(name, 0)?,
            Op::AssetEq(x, y) | Op::ValueEq(x, y) | Op::SpkEq(x, y) => {
                x.check(name, 0)?;
                y.check(name, 1)?;
            }
            Op::IdxEq(x, y) => {
                x.check_depth(0)?;
                y.check_depth(0)?;
            }
            Op::CurrIndEq(_) => {}
        }
        Ok(Self(op))
    }

    // `FieldExpr::from_tree` checks constants as it parses them.
    pub(super) fn from_tree(name: &str, node: TreeIterItem) -> Result<Self, Error> {
        let field_expr = |field, child, pos| FieldExpr::from_tree(field, child, name, pos);
        let mut children = node.children();
        let op = match (name, children.next(), children.next(), children.next()) {
            ("is_exp_asset", Some(x), None, _) => Op::IsExpAsset(field_expr(Field::Asset, x, 0)?),
            ("is_exp_value", Some(x), None, _) => Op::IsExpValue(field_expr(Field::Value, x, 0)?),
            ("asset_eq", Some(x), Some(y), None) => {
                Op::AssetEq(field_expr(Field::Asset, x, 0)?, field_expr(Field::Asset, y, 1)?)
            }
            ("value_eq", Some(x), Some(y), None) => {
                Op::ValueEq(field_expr(Field::Value, x, 0)?, field_expr(Field::Value, y, 1)?)
            }
            ("spk_eq", Some(x), Some(y), None) => {
                Op::SpkEq(field_expr(Field::Spk, x, 0)?, field_expr(Field::Spk, y, 1)?)
            }
            ("curr_idx_eq", Some(i), None, _) => match IdxExpr::from_tree(i)? {
                IdxExpr::Const(i) => Op::CurrIndEq(i),
                _ => return Err(unexpected(node)),
            },
            ("idx_eq", Some(x), Some(y), None) => {
                Op::IdxEq(IdxExpr::from_tree(x)?, IdxExpr::from_tree(y)?)
            }
            _ => return Err(unexpected(node)),
        };
        Ok(Self(op))
    }

    pub(super) fn script_size(&self) -> usize {
        match &self.0 {
            Op::IsExpAsset(x) | Op::IsExpValue(x) => x.script_size() + 3,
            Op::AssetEq(x, y) | Op::ValueEq(x, y) | Op::SpkEq(x, y) => {
                x.script_size() + y.script_size() + 7
            }
            Op::CurrIndEq(i) => script_num_size(i.value() as usize) + 2,
            Op::IdxEq(x, y) => x.script_size() + y.script_size() + 1,
        }
    }

    /// The most stack and altstack items this has pushed at any point of its execution.
    pub(super) fn max_stack(&self) -> usize {
        match &self.0 {
            Op::IsExpAsset(x) | Op::IsExpValue(x) => x.max_stack().max(3),
            Op::AssetEq(x, y) | Op::ValueEq(x, y) | Op::SpkEq(x, y) => {
                x.max_stack().max(2 + y.max_stack())
            }
            Op::CurrIndEq(_) => 2,
            Op::IdxEq(x, y) => x.max_stack().max(1 + y.max_stack()),
        }
    }

    /// Whether the fragment ends with `EQUAL`, which merges with a following `VERIFY`.
    pub(super) fn has_free_verify(&self) -> bool {
        matches!(self.0, Op::CurrIndEq(_) | Op::IdxEq(..))
    }

    pub(super) fn translate<X>(
        &self,
        t: &mut X,
    ) -> Result<CovOps<X::TargetArg>, TranslateErr<X::Error>>
    where
        X: ExtParamTranslator<T>,
    {
        let name = self.0.name();
        Ok(CovOps(match &self.0 {
            Op::IsExpAsset(x) => Op::IsExpAsset(x.translate(t, name, 0)?),
            Op::IsExpValue(x) => Op::IsExpValue(x.translate(t, name, 0)?),
            Op::AssetEq(x, y) => Op::AssetEq(x.translate(t, name, 0)?, y.translate(t, name, 1)?),
            Op::ValueEq(x, y) => Op::ValueEq(x.translate(t, name, 0)?, y.translate(t, name, 1)?),
            Op::SpkEq(x, y) => Op::SpkEq(x.translate(t, name, 0)?, y.translate(t, name, 1)?),
            Op::CurrIndEq(i) => Op::CurrIndEq(*i),
            Op::IdxEq(x, y) => Op::IdxEq(x.clone(), y.clone()),
        }))
    }
}

impl<T: ExtParam> Op<T> {
    fn name(&self) -> &'static str {
        match self {
            Self::IsExpAsset(_) => "is_exp_asset",
            Self::IsExpValue(_) => "is_exp_value",
            Self::AssetEq(..) => "asset_eq",
            Self::ValueEq(..) => "value_eq",
            Self::SpkEq(..) => "spk_eq",
            Self::CurrIndEq(_) => "curr_idx_eq",
            Self::IdxEq(..) => "idx_eq",
        }
    }
}

impl CovOps<CovExtArgs> {
    pub(super) fn encode(&self, builder: Builder) -> Builder {
        match &self.0 {
            Op::IsExpAsset(x) => is_explicit(x.encode(Field::Asset, builder)),
            Op::IsExpValue(x) => is_explicit(x.encode(Field::Value, builder)),
            Op::AssetEq(x, y) => encode_eq(Field::Asset, x, y, builder),
            Op::ValueEq(x, y) => encode_eq(Field::Value, x, y, builder),
            Op::SpkEq(x, y) => encode_eq(Field::Spk, x, y, builder),
            Op::CurrIndEq(i) => builder
                .push_int(i64::from(i.value()))
                .push_opcode(OP_PUSHCURRENTINPUTINDEX)
                .push_opcode(OP_EQUAL),
            Op::IdxEq(x, y) => y.encode(x.encode(builder)).push_opcode(OP_EQUAL),
        }
    }

    /// Decodes the fragment at the end of `tks`, returning it with its start.
    ///
    /// Decoded constants suit their positions: each has the kind of its field, assets and
    /// values are never null, and script pubkeys push 20- or 32-byte programs.
    pub(super) fn decode(tks: &[Tk]) -> Option<(Self, usize)> {
        let end = tks.len();
        let (op, start) = match tks {
            [.., Tk::Num(i), Tk::CurrInp, Tk::Equal] => {
                (Op::CurrIndEq(IdxConst::new(*i).ok()?), end - 3)
            }
            [.., Tk::Equal] => {
                let (y, y_start) = IdxExpr::decode(tks, end - 1, 0)?;
                let (x, start) = IdxExpr::decode(tks, y_start, 0)?;
                (Op::IdxEq(x, y), start)
            }
            [.., Tk::Num(1), Tk::Equal, Tk::Nip] => {
                let end = end - 3;
                FieldExpr::decode(Field::Asset, tks, end)
                    .map(|(x, start)| (Op::IsExpAsset(x), start))
                    .or_else(|| {
                        FieldExpr::decode(Field::Value, tks, end)
                            .map(|(x, start)| (Op::IsExpValue(x), start))
                    })?
            }
            [.., Tk::FromAltStack, Tk::Equal, Tk::ToAltStack, Tk::Equal, Tk::FromAltStack, Tk::BoolAnd] =>
            {
                let end = end - 6;
                decode_eq(Field::Asset, tks, end, Op::AssetEq)
                    .or_else(|| decode_eq(Field::Value, tks, end, Op::ValueEq))
                    .or_else(|| decode_eq(Field::Spk, tks, end, Op::SpkEq))?
            }
            _ => return None,
        };
        Some((Self(op), start))
    }

    pub(super) fn eval(&self, env: &TxEnv) -> Result<bool, EvalError> {
        Ok(match &self.0 {
            Op::IsExpAsset(x) => x.eval(Field::Asset, env)?.1 == 1,
            Op::IsExpValue(x) => x.eval(Field::Value, env)?.1 == 1,
            Op::AssetEq(x, y) => x.eval(Field::Asset, env)? == y.eval(Field::Asset, env)?,
            Op::ValueEq(x, y) => x.eval(Field::Value, env)? == y.eval(Field::Value, env)?,
            Op::SpkEq(x, y) => x.eval(Field::Spk, env)? == y.eval(Field::Spk, env)?,
            Op::CurrIndEq(i) => u32::try_from(env.idx()) == Ok(i.value()),
            Op::IdxEq(x, y) => x.eval(env)? == y.eval(env)?,
        })
    }
}

fn is_explicit(builder: Builder) -> Builder {
    builder
        .push_int(1)
        .push_opcode(OP_EQUAL)
        .push_opcode(OP_NIP)
}

fn encode_eq(
    field: Field,
    x: &FieldExpr<CovExtArgs>,
    y: &FieldExpr<CovExtArgs>,
    builder: Builder,
) -> Builder {
    let builder = x.encode(field, builder).push_opcode(OP_TOALTSTACK);
    y.encode(field, builder)
        .push_opcode(OP_FROMALTSTACK)
        .push_opcode(OP_EQUAL)
        .push_opcode(OP_TOALTSTACK)
        .push_opcode(OP_EQUAL)
        .push_opcode(OP_FROMALTSTACK)
        .push_opcode(OP_BOOLAND)
}

fn decode_eq(
    field: Field,
    tks: &[Tk],
    end: usize,
    op: fn(FieldExpr<CovExtArgs>, FieldExpr<CovExtArgs>) -> Op<CovExtArgs>,
) -> Option<(Op<CovExtArgs>, usize)> {
    let (y, y_start) = FieldExpr::decode(field, tks, end)?;
    let x_end = y_start
        .checked_sub(1)
        .filter(|&i| tks[i] == Tk::ToAltStack)?;
    let (x, start) = FieldExpr::decode(field, tks, x_end)?;
    Some((op(x, y), start))
}

impl<T: ExtParam> fmt::Display for CovOps<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.0.name();
        match &self.0 {
            Op::IsExpAsset(x) => write!(f, "{}({})", name, DisplayField(Field::Asset, x)),
            Op::IsExpValue(x) => write!(f, "{}({})", name, DisplayField(Field::Value, x)),
            Op::AssetEq(x, y) => {
                write!(
                    f,
                    "{}({},{})",
                    name,
                    DisplayField(Field::Asset, x),
                    DisplayField(Field::Asset, y)
                )
            }
            Op::ValueEq(x, y) => {
                write!(
                    f,
                    "{}({},{})",
                    name,
                    DisplayField(Field::Value, x),
                    DisplayField(Field::Value, y)
                )
            }
            Op::SpkEq(x, y) => {
                write!(
                    f,
                    "{}({},{})",
                    name,
                    DisplayField(Field::Spk, x),
                    DisplayField(Field::Spk, y)
                )
            }
            Op::CurrIndEq(i) => write!(f, "{}({})", name, i.value()),
            Op::IdxEq(x, y) => write!(f, "{}({},{})", name, x, y),
        }
    }
}

struct DisplayField<'a, T: ExtParam>(Field, &'a FieldExpr<T>);

impl<T: ExtParam> fmt::Display for DisplayField<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [curr, inp, out] = self.0.names();
        match self.1 {
            FieldExpr::Const(arg) => fmt::Display::fmt(arg, f),
            FieldExpr::CurrInput => f.write_str(curr),
            FieldExpr::Input(i) => write!(f, "{}({})", inp, i),
            FieldExpr::Output(i) => write!(f, "{}({})", out, i),
        }
    }
}

impl<T: ExtParam> FieldExpr<T> {
    fn from_tree(
        field: Field,
        node: TreeIterItem,
        parent: &str,
        pos: usize,
    ) -> Result<Self, Error> {
        let [curr, inp, out] = field.names();
        let mut children = node.children();
        match (node.name(), children.next(), children.next()) {
            (name, None, _) if name == curr => Ok(Self::CurrInput),
            (name, Some(i), None) if name == inp => IdxExpr::from_tree(i).map(Self::Input),
            (name, Some(i), None) if name == out => IdxExpr::from_tree(i).map(Self::Output),
            (name, None, _) => T::arg_from_str(name, parent, pos).map(Self::Const),
            _ => Err(unexpected(node)),
        }
    }

    fn check(&self, parent: &str, pos: usize) -> Result<(), Error> {
        match self {
            Self::Const(arg) => arg.check_arg(parent, pos),
            Self::CurrInput => Ok(()),
            Self::Input(i) | Self::Output(i) => i.check_depth(0),
        }
    }

    fn script_size(&self) -> usize {
        match self {
            // At most 32 bytes of data and a one-byte prefix push.
            Self::Const(_) => 34,
            Self::CurrInput => 2,
            Self::Input(i) | Self::Output(i) => i.script_size() + 1,
        }
    }

    fn max_stack(&self) -> usize {
        match self {
            Self::Const(_) | Self::CurrInput => 2,
            Self::Input(i) | Self::Output(i) => i.max_stack().max(2),
        }
    }

    fn translate<X>(
        &self,
        t: &mut X,
        parent: &str,
        pos: usize,
    ) -> Result<FieldExpr<X::TargetArg>, TranslateErr<X::Error>>
    where
        X: ExtParamTranslator<T>,
    {
        Ok(match self {
            Self::Const(arg) => FieldExpr::Const(translate_arg(t, arg, parent, pos)?),
            Self::CurrInput => FieldExpr::CurrInput,
            Self::Input(i) => FieldExpr::Input(i.clone()),
            Self::Output(i) => FieldExpr::Output(i.clone()),
        })
    }
}

impl FieldExpr<CovExtArgs> {
    fn encode(&self, field: Field, builder: Builder) -> Builder {
        let (inspect_input, inspect_output) = field.opcodes();
        match self {
            Self::Const(arg) => {
                let (data, prefix) = field.of_arg(arg);
                builder.push_slice(&data).push_int(prefix)
            }
            Self::CurrInput => builder
                .push_opcode(OP_PUSHCURRENTINPUTINDEX)
                .push_opcode(inspect_input),
            Self::Input(i) => i.encode(builder).push_opcode(inspect_input),
            Self::Output(i) => i.encode(builder).push_opcode(inspect_output),
        }
    }

    fn decode(field: Field, tks: &[Tk], end: usize) -> Option<(Self, usize)> {
        let (input, output) = field.tokens();
        let tks = tks.get(..end)?;
        let arg = match (field, tks) {
            (_, [.., Tk::CurrInp, tk]) if *tk == input => return Some((Self::CurrInput, end - 2)),
            (_, [.., tk]) if *tk == input => {
                return IdxExpr::decode(tks, end - 1, 0).map(|(i, start)| (Self::Input(i), start))
            }
            (_, [.., tk]) if *tk == output => {
                return IdxExpr::decode(tks, end - 1, 0).map(|(i, start)| (Self::Output(i), start))
            }
            (Field::Asset, [.., Tk::Bytes32(data), Tk::Num(prefix)]) => {
                CovExtArgs::Asset(deserialize_prefixed(*prefix, data)?)
            }
            (Field::Value, [.., Tk::Bytes32(data), Tk::Num(prefix)]) => {
                CovExtArgs::Value(deserialize_prefixed(*prefix, data)?)
            }
            (Field::Value, [.., Tk::Bytes8(value), Tk::Num(1)]) => {
                CovExtArgs::Value(confidential::Value::Explicit(u64::from_le_bytes(*value)))
            }
            (Field::Spk, [.., Tk::Hash20(program), Tk::Num(version)]) => {
                witness_spk(*version, program)?
            }
            (Field::Spk, [.., Tk::Bytes32(program), Tk::Num(version)]) => {
                witness_spk(*version, program)?
            }
            (Field::Spk, [.., Tk::Bytes32(hash), Tk::NumNeg1]) => {
                CovExtArgs::Script(Spk::from_hash(sha256::Hash::from_byte_array(*hash)))
            }
            _ => return None,
        };
        Some((Self::Const(arg), end - 2))
    }

    fn eval(&self, field: Field, env: &TxEnv) -> Result<(Vec<u8>, i64), EvalError> {
        Ok(match self {
            Self::Const(arg) => field.of_arg(arg),
            Self::CurrInput => field.of_txout(env.spent_utxo(env.idx())?),
            Self::Input(i) => field.of_txout(env.spent_utxo(i.eval_index(env)?)?),
            Self::Output(i) => field.of_txout(env.output(i.eval_index(env)?)?),
        })
    }
}

fn deserialize_prefixed<T: encode::Decodable>(prefix: u32, data: &[u8; 32]) -> Option<T> {
    let mut ser = [0; 33];
    ser[0] = u8::try_from(prefix).ok()?;
    ser[1..].copy_from_slice(data);
    encode::deserialize(&ser).ok()
}

fn witness_spk(version: u32, program: &[u8]) -> Option<CovExtArgs> {
    if version > 16 {
        return None;
    }
    let spk = Builder::new()
        .push_int(i64::from(version))
        .push_slice(program)
        .into_script();
    Some(CovExtArgs::spk(spk))
}

#[cfg(test)]
mod tests {
    use bitcoin::key::XOnlyPublicKey;
    use elements::AssetId;

    use super::*;
    use crate::{CovenantExt, Miniscript, Tap, Terminal};

    type TapMs = Miniscript<XOnlyPublicKey, Tap, CovenantExt<CovExtArgs>>;

    fn spk(hex: &str) -> CovExtArgs {
        CovExtArgs::spk(elements::Script::from_hex_no_prefix(hex).unwrap())
    }

    // Encoding and evaluation take each constant to suit its position.
    #[test]
    fn constructors_check_constants() {
        let asset = confidential::Asset::Explicit(AssetId::from_byte_array([1; 32]));
        let asset = CovExtArgs::asset(asset);
        let value = CovExtArgs::value(confidential::Value::Explicit(1));
        let v0 = spk("0014c73ac1b7a518499b9642aed8cfa15d5401e5bd85");
        let c = FieldExpr::Const;

        for ops in [
            CovOps::is_exp_asset(c(asset.clone())).unwrap(),
            CovOps::value_eq(FieldExpr::CurrInput, c(value.clone())).unwrap(),
            CovOps::spk_eq(
                c(v0.clone()),
                FieldExpr::Output(IdxExpr::Const(IdxConst::new(0).unwrap())),
            )
            .unwrap(),
            CovOps::curr_idx_eq(IdxConst::new(1).unwrap()),
            CovOps::idx_eq(IdxExpr::CurrIdx, IdxExpr::Const(IdxConst::new(0).unwrap())).unwrap(),
        ] {
            let ext = CovenantExt::Introspect(Box::new(ops));
            let ms = TapMs::from_ast(Terminal::Ext(ext)).unwrap();
            assert_eq!(TapMs::decode_consensus(&ms.encode()).unwrap(), ms);
            assert_eq!(TapMs::from_str_insane(&ms.to_string()).unwrap(), ms);
        }

        // Another kind
        assert!(CovOps::asset_eq(c(value.clone()), FieldExpr::CurrInput).is_err());
        assert!(CovOps::is_exp_value(c(asset.clone())).is_err());
        assert!(CovOps::spk_eq(FieldExpr::CurrInput, c(asset)).is_err());
        // Null
        let null_asset = CovExtArgs::asset(confidential::Asset::Null);
        assert!(CovOps::is_exp_asset(c(null_asset)).is_err());
        let null_value = CovExtArgs::value(confidential::Value::Null);
        assert!(CovOps::value_eq(c(value), c(null_value)).is_ok());
        // A witness program of neither 20 nor 32 bytes
        let v1_short = spk("5104c73ac1b7");
        assert!(CovOps::spk_eq(c(v0), c(v1_short)).is_err());
    }
}
