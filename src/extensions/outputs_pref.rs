// SPDX-License-Identifier: CC0-1.0

//! The `outputs_pref` legacy covenant fragment

use core::fmt;

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use elements::encode::serialize;
use elements::opcodes::all::{OP_CAT, OP_DEPTH, OP_EQUAL, OP_HASH256, OP_PICK, OP_SUB, OP_SWAP};
use elements::script::Builder;
use elements::TxOut;

use crate::interpreter::{self, Element, Stack};
use crate::miniscript::lex::{Token as Tk, TokenIter};
use crate::miniscript::limits::MAX_SCRIPT_ELEMENT_SIZE;
use crate::miniscript::satisfy::{Placeholder, Witness};
use crate::miniscript::types::extra_props::{SatData, TimelockInfo};
use crate::miniscript::types::{Base, Correctness, Dissat, ExtData, Input, Malleability, Type};
use crate::prelude::*;
use crate::{Error, MiniscriptKey, ParseError};

/// The Elements policy limit on the size of a P2WSH witness item.
const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 80;

/// The number of witness items holding the serialized outputs after the prefix, enough for
/// 520 bytes in items of standard size.
const SUFFIX_ITEMS: usize = MAX_SCRIPT_ELEMENT_SIZE / MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1;

/// The position of hashOutputs from the bottom of an `elcovwsh` witness stack, counted from 1
/// as `DEPTH <4> SUB PICK` does.
const HASH_OUTPUTS_DEPTH: u32 = 4;

/// `outputs_pref(PREFIX)`: the serialized outputs of the spending transaction start with
/// `PREFIX`.
///
/// The witness completes the serialization in 7 items of at most 80 bytes, padded with empty
/// items. The fragment compares HASH256 of the prefix and those items with the hashOutputs
/// that the witness of an `elcovwsh` covenant supplies and the covenant key signs, so it has
/// no meaning outside that descriptor. `OP_CAT` limits the serialization to 520 bytes. Its
/// Script is `CAT CAT CAT CAT CAT CAT <PREFIX> SWAP CAT HASH256 DEPTH <4> SUB PICK EQUAL`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct LegacyOutputsPref {
    pref: Vec<u8>,
}

impl LegacyOutputsPref {
    /// Any 7 items that do not complete the outputs dissatisfy the fragment.
    pub(crate) const TYPE: Type = Type {
        corr: Correctness { base: Base::B, input: Input::Any, dissatisfiable: true, unit: true },
        mall: Malleability::NonMalleable { dissat: Dissat::Unknown, signed: false },
    };

    /// Creates the fragment, failing for a prefix above 520 bytes, which no script can push.
    ///
    /// The fragment pushes the prefix as data, including a single
    /// byte from 1 to 16 or `0x81`. Consensus accepts that push, while Elements policy rejects
    /// executing it and the lexer, which enforces minimal pushes, cannot decode it.
    pub fn new(pref: Vec<u8>) -> Result<Self, Error> {
        if pref.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(Error::Unexpected(format!(
                "outputs_pref prefix of {} bytes, above {}",
                pref.len(),
                MAX_SCRIPT_ELEMENT_SIZE
            )));
        }
        Ok(Self { pref })
    }

    /// The prefix of the serialized outputs.
    pub fn pref(&self) -> &[u8] { &self.pref }

    /// Parses the argument of `outputs_pref`, the prefix in hex.
    pub(crate) fn from_arg(arg: &str) -> Result<Self, Error> {
        let pref = Vec::from_hex(arg).map_err(|e| Error::Parse(ParseError::box_from_str(e)))?;
        Self::new(pref)
    }

    pub(crate) fn ext_data(&self) -> ExtData {
        // At most 520 bytes after the prefix, in items with one length byte each.
        let max_suffix_size = MAX_SCRIPT_ELEMENT_SIZE - self.pref.len() + SUFFIX_ITEMS;
        let data = |size| SatData {
            max_witness_stack_size: size,
            max_witness_stack_count: SUFFIX_ITEMS,
            max_script_sig_size: size,
            max_exec_stack_count: 3,
            max_exec_op_count: 0,
        };
        ExtData {
            pk_cost: self.pref.len() + crate::push_opcode_size(self.pref.len()) + 14,
            has_free_verify: true,
            static_ops: 13,
            sat_data: Some(data(max_suffix_size)),
            // Empty items, with a `1` first if the prefix is the whole serialization.
            dissat_data: Some(data(SUFFIX_ITEMS + 1)),
            timelock_info: TimelockInfo::new(),
            tree_height: 0,
        }
    }

    pub(crate) fn encode(&self, builder: Builder) -> Builder {
        (1..SUFFIX_ITEMS)
            .fold(builder, |builder, _| builder.push_opcode(OP_CAT))
            .push_slice(&self.pref)
            .push_opcode(OP_SWAP)
            .push_opcode(OP_CAT)
            .push_opcode(OP_HASH256)
            .push_opcode(OP_DEPTH)
            .push_int(i64::from(HASH_OUTPUTS_DEPTH))
            .push_opcode(OP_SUB)
            .push_opcode(OP_PICK)
            .push_opcode(OP_EQUAL)
    }

    /// Decodes the fragment from the end of `tokens`, consuming them only on success.
    pub(crate) fn decode(tokens: &mut TokenIter) -> Option<Self> {
        let (pref, start) = match tokens.as_slice() {
            [head @ .., Tk::Cat, Tk::Cat, Tk::Cat, Tk::Cat, Tk::Cat, Tk::Cat, pref, Tk::Swap, Tk::Cat, Tk::Hash256, Tk::Depth, Tk::Num(HASH_OUTPUTS_DEPTH), Tk::Sub, Tk::Pick, Tk::Equal] => {
                (push_bytes(pref)?, head.len())
            }
            _ => return None,
        };
        let outputs_pref = Self::new(pref).ok()?;
        tokens.truncate(start);
        Some(outputs_pref)
    }

    /// The witnesses that satisfy and dissatisfy the fragment for a transaction with the given
    /// outputs, both unavailable if the outputs are unknown.
    pub(crate) fn sat_dissat<Pk: MiniscriptKey>(
        &self,
        outputs: Option<&[TxOut]>,
    ) -> (Witness<Placeholder<Pk>>, Witness<Placeholder<Pk>>) {
        let Some(outputs) = outputs else {
            return (Witness::Unavailable, Witness::Unavailable);
        };
        let serialized: Vec<u8> = outputs.iter().flat_map(serialize).collect();
        let sat = match serialized.strip_prefix(&self.pref[..]) {
            Some(suffix) if serialized.len() <= MAX_SCRIPT_ELEMENT_SIZE => suffix_witness(suffix),
            _ => Witness::Impossible,
        };
        let dissat = if serialized != self.pref {
            suffix_witness(&[])
        } else if self.pref.len() < MAX_SCRIPT_ELEMENT_SIZE {
            suffix_witness(&[1])
        } else {
            Witness::Impossible
        };
        (sat, dissat)
    }

    /// Evaluates the fragment on an `elcovwsh` witness stack, which keeps its signature hash
    /// items at the bottom, consuming the items after the prefix.
    pub(crate) fn evaluate(&self, stack: &mut Stack) -> Result<bool, interpreter::Error> {
        let suffix_start = stack
            .len()
            .checked_sub(SUFFIX_ITEMS)
            .ok_or(interpreter::Error::UnexpectedStackEnd)?;
        let mut serialized = self.pref.clone();
        for item in stack.split_off(suffix_start) {
            serialized.extend_from_slice(element_bytes(&item));
        }
        if serialized.len() > MAX_SCRIPT_ELEMENT_SIZE {
            // `OP_CAT` fails, aborting the script.
            return Err(interpreter::Error::CouldNotEvaluate);
        }
        match stack.get(HASH_OUTPUTS_DEPTH as usize - 1) {
            Some(hash_outputs) => {
                Ok(element_bytes(hash_outputs) == sha256d::Hash::hash(&serialized).as_byte_array())
            }
            None => Err(interpreter::Error::UnexpectedStackEnd),
        }
    }
}

impl fmt::Display for LegacyOutputsPref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "outputs_pref({})", self.pref.as_hex())
    }
}

// The witness items that complete the serialized outputs with `suffix`, from the deepest.
fn suffix_witness<Pk: MiniscriptKey>(suffix: &[u8]) -> Witness<Placeholder<Pk>> {
    let mut items: Vec<_> = suffix
        .chunks(MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
        .map(|chunk| Placeholder::Data(chunk.to_vec()))
        .collect();
    items.resize(SUFFIX_ITEMS, Placeholder::PushZero);
    Witness::Stack(items)
}

// The bytes that a push token pushes, if the encoder would push them with that token. The
// encoder pushes bytes as data, never with `OP_1` to `OP_16`.
fn push_bytes(token: &Tk) -> Option<Vec<u8>> {
    match token {
        Tk::Push(bytes) => Some(bytes[..].to_vec()),
        Tk::Num(n) if !(1..=16).contains(n) => {
            let mut buf = [0; 8];
            let len = bitcoin::script::write_scriptint(&mut buf, i64::from(*n));
            buf.get(..len).map(<[u8]>::to_vec)
        }
        Tk::Bytes8(bytes) => Some(bytes.to_vec()),
        Tk::Hash20(bytes) => Some(bytes.to_vec()),
        Tk::Bytes32(bytes) => Some(bytes.to_vec()),
        Tk::Bytes33(bytes) => Some(bytes.to_vec()),
        Tk::Bytes65(bytes) => Some(bytes.to_vec()),
        _ => None,
    }
}

// The bytes of a stack element. The interpreter reads an empty or `1` item as a boolean.
fn element_bytes<'txin>(element: &Element<'txin>) -> &'txin [u8] {
    match *element {
        Element::Push(bytes) => bytes,
        Element::Satisfied => &[1],
        Element::Dissatisfied => &[],
    }
}

#[cfg(test)]
mod tests {
    use elements::confidential;

    use super::*;
    use crate::miniscript::lex::lex;

    fn decode(script: &elements::Script) -> Option<LegacyOutputsPref> {
        let tokens = lex(bitcoin::Script::from_bytes(script.as_bytes())).ok()?;
        let mut tokens = TokenIter::new(tokens);
        let outputs_pref = LegacyOutputsPref::decode(&mut tokens)?;
        tokens.is_empty().then_some(outputs_pref)
    }

    // Outputs serialized in 132 bytes, 44 each.
    fn outputs() -> Vec<TxOut> {
        (1..=3)
            .map(|value| TxOut {
                value: confidential::Value::Explicit(value),
                asset: confidential::Asset::Explicit(elements::AssetId::from_byte_array([1; 32])),
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn script_round_trip() {
        // Prefixes that the lexer reads as raw pushes, numbers, keys and hashes, including
        // pushes with 1 and 2 length bytes.
        for len in [0, 1, 2, 5, 8, 20, 32, 33, 65, 75, 76, 255, 256, 520] {
            let outputs_pref = LegacyOutputsPref::new(vec![0xaa; len]).unwrap();
            let script = outputs_pref.encode(Builder::new()).into_script();
            assert_eq!(script.len(), outputs_pref.ext_data().pk_cost);
            assert_eq!(decode(&script), Some(outputs_pref.clone()), "{}", len);
            let arg = outputs_pref.pref().as_hex().to_string();
            assert_eq!(LegacyOutputsPref::from_arg(&arg).unwrap(), outputs_pref);
        }
        for pref in [vec![0x11], vec![0x00], vec![0x80]] {
            let outputs_pref = LegacyOutputsPref::new(pref).unwrap();
            let script = outputs_pref.encode(Builder::new()).into_script();
            assert_eq!(decode(&script), Some(outputs_pref));
        }
        let outputs_pref = LegacyOutputsPref::new(vec![1, 2]).unwrap();
        assert_eq!(outputs_pref.to_string(), "outputs_pref(0102)");
        assert!(LegacyOutputsPref::new(vec![0; 521]).is_err());
        assert!(LegacyOutputsPref::from_arg("0g").is_err());
    }

    // A prefix that a minimal push would write as a number opcode is still pushed as data.
    #[test]
    fn non_minimal_prefix_push() {
        for byte in [1, 5, 16, 0x81] {
            let outputs_pref = LegacyOutputsPref::from_arg(&format!("{:02x}", byte)).unwrap();
            let script = outputs_pref.encode(Builder::new()).into_script();
            assert_eq!(script.as_bytes()[SUFFIX_ITEMS - 1..SUFFIX_ITEMS + 1], [1, byte]);
            assert_eq!(script.len(), outputs_pref.ext_data().pk_cost);
            // The lexer rejects the push.
            assert_eq!(decode(&script), None);
        }

        // A number opcode in place of the push is not an encoding of the fragment.
        let number = (1..SUFFIX_ITEMS)
            .fold(Builder::new(), |builder, _| builder.push_opcode(OP_CAT))
            .push_int(5)
            .push_opcode(OP_SWAP)
            .push_opcode(OP_CAT)
            .push_opcode(OP_HASH256)
            .push_opcode(OP_DEPTH)
            .push_int(4)
            .push_opcode(OP_SUB)
            .push_opcode(OP_PICK)
            .push_opcode(OP_EQUAL)
            .into_script();
        assert_eq!(decode(&number), None);
    }

    #[test]
    fn satisfaction() {
        let outputs = outputs();
        let serialized: Vec<u8> = outputs.iter().flat_map(serialize).collect();
        let sat_dissat = |pref: &[u8], outputs: Option<&[TxOut]>| {
            LegacyOutputsPref::new(pref.to_vec())
                .unwrap()
                .sat_dissat::<bitcoin::PublicKey>(outputs)
        };
        let witness = |items: &[&[u8]]| {
            let mut witness: Vec<_> = items
                .iter()
                .map(|item| Placeholder::Data(item.to_vec()))
                .collect();
            witness.resize(SUFFIX_ITEMS, Placeholder::PushZero);
            Witness::Stack(witness)
        };

        let (sat, dissat) = sat_dissat(&serialized[..10], Some(&outputs));
        assert_eq!(sat, witness(&[&serialized[10..90], &serialized[90..]]));
        assert_eq!(dissat, witness(&[]));

        let (sat, dissat) = sat_dissat(&serialized, Some(&outputs));
        assert_eq!(sat, witness(&[]));
        assert_eq!(dissat, witness(&[&[1]]));

        let (sat, dissat) = sat_dissat(&[0x55], Some(&outputs));
        assert_eq!(sat, Witness::Impossible);
        assert_eq!(dissat, witness(&[]));

        let too_many: Vec<_> = (0..4).flat_map(|_| outputs.clone()).collect();
        assert_eq!(sat_dissat(&[], Some(&too_many)).0, Witness::Impossible);
        assert_eq!(sat_dissat(&[], None), (Witness::Unavailable, Witness::Unavailable));
    }

    #[test]
    fn evaluation() {
        let serialized: Vec<u8> = outputs().iter().flat_map(serialize).collect();
        let hash_outputs = sha256d::Hash::hash(&serialized).to_byte_array();
        let other = [0; 32];
        let mut bottom = vec![Element::Push(&other); 3];
        bottom.push(Element::Push(&hash_outputs));
        bottom.extend([Element::Push(&other); 8]);
        let outputs_pref = LegacyOutputsPref::new(serialized[..10].to_vec()).unwrap();

        let mut stack = Stack::from(bottom.clone());
        stack.push(Element::Push(&serialized[10..90]));
        stack.push(Element::Push(&serialized[90..]));
        for _ in 2..SUFFIX_ITEMS {
            stack.push(Element::Dissatisfied);
        }
        assert!(outputs_pref.evaluate(&mut stack).unwrap());
        assert_eq!(stack, Stack::from(bottom.clone()));

        let mut stack = Stack::from(bottom.clone());
        for _ in 0..SUFFIX_ITEMS {
            stack.push(Element::Dissatisfied);
        }
        assert!(!outputs_pref.evaluate(&mut stack).unwrap());

        let mut stack = Stack::from(bottom[..6].to_vec());
        assert!(outputs_pref.evaluate(&mut stack).is_err());
    }
}
