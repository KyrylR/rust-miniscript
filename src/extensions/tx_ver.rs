// SPDX-License-Identifier: CC0-1.0

//! The `ver_eq` legacy covenant fragment

use core::fmt;

use elements::opcodes::all::{OP_DEPTH, OP_EQUAL, OP_PICK, OP_SUB};
use elements::script::Builder;

use crate::interpreter::{self, Element, Stack};
use crate::miniscript::lex::{Token as Tk, TokenIter};
use crate::miniscript::satisfy::{Placeholder, Witness};
use crate::miniscript::types::extra_props::{SatData, TimelockInfo};
use crate::miniscript::types::{Base, Correctness, Dissat, ExtData, Input, Malleability, Type};
use crate::{expression, Error, MiniscriptKey, ParseError};

/// The position of the version from the bottom of an `elcovwsh` witness stack, counted from 1
/// as `DEPTH <12> SUB PICK` does.
const VERSION_DEPTH: u32 = 12;

/// Neither the satisfaction nor the dissatisfaction takes witness items.
const NO_WITNESS: SatData = SatData {
    max_witness_stack_size: 0,
    max_witness_stack_count: 0,
    max_script_sig_size: 0,
    max_exec_stack_count: 2,
    max_exec_op_count: 0,
};

/// `ver_eq(N)`: the version of the spending transaction is `N`.
///
/// The fragment compares `N` with the version that the witness of an `elcovwsh` covenant
/// supplies and the covenant key signs, so it has no meaning outside that descriptor. Its
/// Script is `DEPTH <12> SUB PICK <N> EQUAL`, with `N` pushed as 4 little-endian bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct LegacyVerEq {
    /// The version.
    pub n: u32,
}

impl LegacyVerEq {
    /// Nobody can change the version that the covenant key signs, so the fragment has no
    /// dissatisfaction to rely on.
    pub(crate) const TYPE: Type = Type {
        corr: Correctness { base: Base::B, input: Input::Zero, dissatisfiable: false, unit: true },
        mall: Malleability::NonMalleable { dissat: Dissat::None, signed: false },
    };

    pub(crate) const EXT_DATA: ExtData = ExtData {
        pk_cost: 10,
        has_free_verify: true,
        static_ops: 4,
        sat_data: Some(NO_WITNESS),
        dissat_data: Some(NO_WITNESS),
        timelock_info: TimelockInfo::new(),
        tree_height: 0,
    };

    /// Parses the argument of `ver_eq`, a decimal number in canonical form.
    pub(crate) fn from_arg(arg: &str) -> Result<Self, Error> {
        expression::parse_num(arg)
            .map(|n| Self { n })
            .map_err(|e| Error::Parse(ParseError::Num(e)))
    }

    pub(crate) fn encode(&self, builder: Builder) -> Builder {
        builder
            .push_opcode(OP_DEPTH)
            .push_int(i64::from(VERSION_DEPTH))
            .push_opcode(OP_SUB)
            .push_opcode(OP_PICK)
            .push_slice(&self.n.to_le_bytes())
            .push_opcode(OP_EQUAL)
    }

    /// Decodes the fragment from the end of `tokens`, consuming them only on success.
    pub(crate) fn decode(tokens: &mut TokenIter) -> Option<Self> {
        let (n, start) = match tokens.as_slice() {
            [head @ .., Tk::Depth, Tk::Num(VERSION_DEPTH), Tk::Sub, Tk::Pick, push, Tk::Equal] => {
                let n = match push {
                    Tk::Push(bytes) => u32::from_le_bytes(bytes[..].try_into().ok()?),
                    // The lexer reads a minimal 4-byte push as a number.
                    Tk::Num(n) if (1 << 23..1 << 31).contains(n) => *n,
                    _ => return None,
                };
                (n, head.len())
            }
            _ => return None,
        };
        tokens.truncate(start);
        Some(Self { n })
    }

    /// The witnesses that satisfy and dissatisfy the fragment for a transaction of the given
    /// version, both unavailable if the version is unknown.
    pub(crate) fn sat_dissat<Pk: MiniscriptKey>(
        &self,
        version: Option<u32>,
    ) -> (Witness<Placeholder<Pk>>, Witness<Placeholder<Pk>>) {
        match version {
            Some(n) if n == self.n => (Witness::Stack(vec![]), Witness::Impossible),
            Some(_) => (Witness::Impossible, Witness::Stack(vec![])),
            None => (Witness::Unavailable, Witness::Unavailable),
        }
    }

    /// Evaluates the fragment on an `elcovwsh` witness stack, which keeps its signature hash
    /// items at the bottom.
    pub(crate) fn evaluate(&self, stack: &Stack) -> Result<bool, interpreter::Error> {
        match stack.get(VERSION_DEPTH as usize - 1) {
            Some(Element::Push(version)) => Ok(version[..] == self.n.to_le_bytes()),
            // `EQUAL` compares the 4-byte version with an empty or `1` item.
            Some(_) => Ok(false),
            None => Err(interpreter::Error::UnexpectedStackEnd),
        }
    }
}

impl fmt::Display for LegacyVerEq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "ver_eq({})", self.n) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::miniscript::lex::lex;

    fn decode(script: &elements::Script) -> Option<LegacyVerEq> {
        let tokens = lex(bitcoin::Script::from_bytes(script.as_bytes())).ok()?;
        let mut tokens = TokenIter::new(tokens);
        let ver_eq = LegacyVerEq::decode(&mut tokens)?;
        tokens.is_empty().then_some(ver_eq)
    }

    #[test]
    fn script_round_trip() {
        // Versions whose 4 bytes the lexer reads as a push, and as a number.
        let versions = [
            0,
            2,
            0x7f_ffff,
            0x80_0000,
            0x100_0000,
            0x7fff_ffff,
            0x8000_0000,
            u32::MAX,
        ];
        for n in versions {
            let ver_eq = LegacyVerEq { n };
            let script = ver_eq.encode(Builder::new()).into_script();
            assert_eq!(script.len(), LegacyVerEq::EXT_DATA.pk_cost);
            assert_eq!(decode(&script), Some(ver_eq), "{}", n);
            assert_eq!(LegacyVerEq::from_arg(&n.to_string()).unwrap(), ver_eq);
        }
        assert_eq!(LegacyVerEq { n: 2 }.to_string(), "ver_eq(2)");
        assert!(LegacyVerEq::from_arg("02").is_err());
        assert!(LegacyVerEq::from_arg("4294967296").is_err());

        let three_bytes = Builder::new()
            .push_opcode(OP_DEPTH)
            .push_int(12)
            .push_opcode(OP_SUB)
            .push_opcode(OP_PICK)
            .push_slice(&[2, 0, 0])
            .push_opcode(OP_EQUAL)
            .into_script();
        assert_eq!(decode(&three_bytes), None);
    }

    #[test]
    fn satisfaction() {
        let ver_eq = LegacyVerEq { n: 2 };
        let sat_dissat = |version| ver_eq.sat_dissat::<bitcoin::PublicKey>(version);
        assert_eq!(sat_dissat(Some(2)), (Witness::Stack(vec![]), Witness::Impossible));
        assert_eq!(sat_dissat(Some(3)), (Witness::Impossible, Witness::Stack(vec![])));
        assert_eq!(sat_dissat(None), (Witness::Unavailable, Witness::Unavailable));
    }

    #[test]
    fn evaluation() {
        let (hash, version) = ([0; 32], 2u32.to_le_bytes());
        let mut items = vec![Element::Push(&hash); 11];
        items.push(Element::Push(&version));
        assert!(LegacyVerEq { n: 2 }
            .evaluate(&Stack::from(items.clone()))
            .unwrap());
        assert!(!LegacyVerEq { n: 3 }
            .evaluate(&Stack::from(items.clone()))
            .unwrap());
        items.truncate(11);
        assert!(LegacyVerEq { n: 2 }.evaluate(&Stack::from(items)).is_err());
    }
}
