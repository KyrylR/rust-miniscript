// SPDX-License-Identifier: CC0-1.0

//! The `csfs` fragment

use core::fmt;

use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
use elements::opcodes::all::OP_CHECKSIGFROMSTACK;
use elements::script::Builder;

use super::param::ExtParamTranslator;
use super::{terminal_name, translate_arg, tree_error, CovExtArgs, CsfsMsg, ExtParam};
use crate::expression::TreeIterItem;
use crate::interpreter::{self, Element, Stack};
use crate::miniscript::lex::Token as Tk;
use crate::{Error, TranslateErr};

/// A signature of a message by a key, both fixed: `<msg> <key> CHECKSIGFROMSTACK`
///
/// The signature commits to the message only, so unlike a transaction signature it can be
/// reused by anyone who sees it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct CheckSigFromStack<T: ExtParam> {
    pk: T,
    msg: T,
}

impl<T: ExtParam> CheckSigFromStack<T> {
    /// The key.
    pub fn pk(&self) -> &T { &self.pk }

    /// The message.
    pub fn msg(&self) -> &T { &self.msg }

    pub(super) fn from_tree(node: TreeIterItem) -> Result<Self, Error> {
        let (pk, msg) = node.verify_binary("csfs").map_err(tree_error)?;
        Ok(Self {
            pk: T::arg_from_str(terminal_name(pk)?, "csfs", 0)?,
            msg: T::arg_from_str(terminal_name(msg)?, "csfs", 1)?,
        })
    }

    pub(super) fn translate<X>(
        &self,
        t: &mut X,
    ) -> Result<CheckSigFromStack<X::TargetArg>, TranslateErr<X::Error>>
    where
        X: ExtParamTranslator<T>,
    {
        Ok(CheckSigFromStack {
            pk: translate_arg(t, &self.pk, "csfs", 0)?,
            msg: translate_arg(t, &self.msg, "csfs", 1)?,
        })
    }
}

impl CheckSigFromStack<CovExtArgs> {
    pub(super) fn key(&self) -> &XOnlyPublicKey { self.pk.as_key() }

    pub(super) fn message(&self) -> &CsfsMsg { self.msg.as_msg() }

    pub(super) fn encode(&self, builder: Builder) -> Builder {
        builder
            .push_slice(self.message().as_inner())
            .push_slice(&self.key().serialize())
            .push_opcode(OP_CHECKSIGFROMSTACK)
    }

    /// Decodes the fragment at the end of `tks`, returning it with its start.
    pub(super) fn decode(tks: &[Tk]) -> Option<(Self, usize)> {
        match tks {
            [.., Tk::Bytes32(msg), Tk::Bytes32(pk), Tk::CheckSigFromStack] => {
                let pk = CovExtArgs::csfs_key(XOnlyPublicKey::from_slice(pk).ok()?);
                let msg = CovExtArgs::CsfsMsg(CsfsMsg::from_slice(msg)?);
                Some((Self { pk, msg }, tks.len() - 3))
            }
            _ => None,
        }
    }

    /// Consumes the signature on top of the stack, which is valid or empty.
    pub(super) fn evaluate(&self, stack: &mut Stack) -> Result<bool, interpreter::Error> {
        let sig = match stack.pop() {
            Some(Element::Push(sig)) => sig,
            Some(Element::Dissatisfied) => return Ok(false),
            Some(Element::Satisfied) => return Err(interpreter::Error::UnexpectedStackBoolean),
            None => return Err(interpreter::Error::UnexpectedStackEnd),
        };
        let msg = Message::from_digest(*self.message().as_inner());
        schnorr::Signature::from_slice(sig)
            .and_then(|sig| Secp256k1::verification_only().verify_schnorr(&sig, &msg, self.key()))
            .map_err(|_| interpreter::Error::InvalidSchnorrSignature(*self.key()))?;
        Ok(true)
    }
}

impl<T: ExtParam> fmt::Display for CheckSigFromStack<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "csfs({},{})", self.pk, self.msg)
    }
}
