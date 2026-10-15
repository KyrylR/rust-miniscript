// SPDX-License-Identifier: CC0-1.0

//! Arguments of the covenant fragments

use core::str::FromStr;
use core::{fmt, hash};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::key::XOnlyPublicKey;
use elements::confidential;

use crate::prelude::*;
use crate::Error;

/// An argument of a covenant fragment, either abstract (like [`String`]) or concrete
/// ([`CovExtArgs`]).
pub trait ExtParam: Clone + Eq + Ord + fmt::Debug + fmt::Display + hash::Hash {
    /// Parses the argument at position `pos` of the fragment named `parent`.
    fn arg_from_str(s: &str, parent: &str, pos: usize) -> Result<Self, Error>;

    /// Checks that the argument may appear at position `pos` of the fragment named `parent`.
    fn check_arg(&self, parent: &str, pos: usize) -> Result<(), Error>;
}

impl ExtParam for String {
    fn arg_from_str(s: &str, _: &str, _: usize) -> Result<Self, Error> { Ok(s.to_owned()) }

    fn check_arg(&self, _: &str, _: usize) -> Result<(), Error> { Ok(()) }
}

/// Translates the arguments of covenant fragments, like [`crate::Translator`] does for keys.
pub trait ExtParamTranslator<PArg: ExtParam> {
    /// The argument type to translate into.
    type TargetArg: ExtParam;
    /// An error that may occur during translation.
    type Error;

    /// Translates an argument.
    fn ext(&mut self, arg: &PArg) -> Result<Self::TargetArg, Self::Error>;
}

/// The concrete argument of a covenant fragment.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum CovExtArgs {
    /// The key of `csfs`, `price_oracle1` and `price_oracle1_w`.
    XOnlyKey(CsfsKey),
    /// The message of `csfs`.
    CsfsMsg(CsfsMsg),
    /// An asset of `asset_eq` or `is_exp_asset`.
    Asset(confidential::Asset),
    /// A value of `value_eq` or `is_exp_value`.
    Value(confidential::Value),
    /// A script pubkey of `spk_eq`.
    Script(Spk),
}

impl CovExtArgs {
    /// Creates a key argument.
    pub fn csfs_key(key: XOnlyPublicKey) -> Self { Self::XOnlyKey(CsfsKey(key)) }

    /// Creates a message argument.
    pub fn csfs_msg(msg: elements::secp256k1_zkp::Message) -> Self {
        Self::CsfsMsg(CsfsMsg(*msg.as_ref()))
    }

    /// Creates an asset argument.
    pub fn asset(asset: confidential::Asset) -> Self { Self::Asset(asset) }

    /// Creates a value argument.
    pub fn value(value: confidential::Value) -> Self { Self::Value(value) }

    /// Creates a script pubkey argument.
    pub fn spk(spk: elements::Script) -> Self { Self::Script(Spk(SpkInner::Script(spk))) }

    // Fragment constructors, parsing, decoding and translation validate argument kinds.

    pub(super) fn as_key(&self) -> &XOnlyPublicKey {
        match self {
            Self::XOnlyKey(key) => &key.0,
            _ => panic!("{} is not a key", self),
        }
    }

    pub(super) fn as_msg(&self) -> &CsfsMsg {
        match self {
            Self::CsfsMsg(msg) => msg,
            _ => panic!("{} is not a message", self),
        }
    }

    pub(super) fn as_asset(&self) -> &confidential::Asset {
        match self {
            Self::Asset(asset) => asset,
            _ => panic!("{} is not an asset", self),
        }
    }

    pub(super) fn as_value(&self) -> &confidential::Value {
        match self {
            Self::Value(value) => value,
            _ => panic!("{} is not a value", self),
        }
    }

    pub(super) fn as_spk(&self) -> &Spk {
        match self {
            Self::Script(spk) => spk,
            _ => panic!("{} is not a script pubkey", self),
        }
    }
}

impl fmt::Display for CovExtArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XOnlyKey(key) => key.fmt(f),
            Self::CsfsMsg(msg) => msg.fmt(f),
            Self::Asset(asset) => write!(f, "{}", elements::encode::serialize(asset).as_hex()),
            Self::Value(value) => write!(f, "{}", elements::encode::serialize(value).as_hex()),
            Self::Script(spk) => spk.fmt(f),
        }
    }
}

impl ExtParam for CovExtArgs {
    fn arg_from_str(s: &str, parent: &str, pos: usize) -> Result<Self, Error> {
        let arg = match ArgKind::of(parent, pos)? {
            ArgKind::Key => Self::csfs_key(
                XOnlyPublicKey::from_str(s).map_err(|e| Error::Unexpected(e.to_string()))?,
            ),
            ArgKind::Msg => Self::CsfsMsg(CsfsMsg(
                <[u8; 32]>::from_hex(s).map_err(|e| Error::Unexpected(e.to_string()))?,
            )),
            ArgKind::Asset => Self::Asset(deserialize_hex(s)?),
            ArgKind::Value => Self::Value(deserialize_hex(s)?),
            ArgKind::Spk => Self::spk(
                elements::Script::from_hex_no_prefix(s)
                    .map_err(|e| Error::Unexpected(e.to_string()))?,
            ),
        };
        arg.check_arg(parent, pos)?;
        Ok(arg)
    }

    fn check_arg(&self, parent: &str, pos: usize) -> Result<(), Error> {
        let fits = match (ArgKind::of(parent, pos)?, self) {
            (ArgKind::Key, Self::XOnlyKey(_)) | (ArgKind::Msg, Self::CsfsMsg(_)) => true,
            (ArgKind::Asset, Self::Asset(asset)) => !asset.is_null(),
            (ArgKind::Value, Self::Value(_)) => true,
            (ArgKind::Spk, Self::Script(spk)) => spk.is_decodable(),
            _ => false,
        };
        if fits {
            Ok(())
        } else {
            Err(Error::Unexpected(format!("{} as argument {} of {}", self, pos, parent)))
        }
    }
}

fn deserialize_hex<T: elements::encode::Decodable>(s: &str) -> Result<T, Error> {
    let bytes = Vec::<u8>::from_hex(s).map_err(|e| Error::Unexpected(e.to_string()))?;
    elements::encode::deserialize(&bytes).map_err(|e| Error::Unexpected(e.to_string()))
}

// The kind of concrete argument each fragment position takes.
enum ArgKind {
    Key,
    Msg,
    Asset,
    Value,
    Spk,
}

impl ArgKind {
    fn of(parent: &str, pos: usize) -> Result<Self, Error> {
        Ok(match (parent, pos) {
            ("csfs", 0) | ("price_oracle1", 0) | ("price_oracle1_w", 0) => Self::Key,
            ("csfs", 1) => Self::Msg,
            ("asset_eq", 0) | ("asset_eq", 1) | ("is_exp_asset", 0) => Self::Asset,
            ("value_eq", 0) | ("value_eq", 1) | ("is_exp_value", 0) => Self::Value,
            ("spk_eq", 0) | ("spk_eq", 1) => Self::Spk,
            _ => return Err(Error::Unexpected(format!("argument {} of {}", pos, parent))),
        })
    }
}

/// The key of a `csfs` or price oracle fragment.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct CsfsKey(pub XOnlyPublicKey);

impl fmt::Display for CsfsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}

/// The 32-byte message of a `csfs` fragment.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct CsfsMsg([u8; 32]);

impl CsfsMsg {
    /// Creates a message, which must be 32 bytes long.
    pub fn from_slice(sl: &[u8]) -> Option<Self> { sl.try_into().ok().map(Self) }

    /// The message bytes.
    pub fn as_inner(&self) -> &[u8; 32] { &self.0 }
}

impl fmt::Display for CsfsMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0.as_hex()) }
}

/// The script pubkey of a `spk_eq` fragment.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Spk(SpkInner);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
enum SpkInner {
    Script(elements::Script),
    // Decoding a Script yields only the hash of a non-witness script pubkey.
    Hashed(sha256::Hash),
}

impl Spk {
    pub(super) fn from_hash(hash: sha256::Hash) -> Self { Self(SpkInner::Hashed(hash)) }

    /// The witness version and program that the introspection opcodes push for this script
    /// pubkey, where a non-witness script pubkey is version -1 with its SHA256 as program.
    pub(super) fn components(&self) -> (i8, Vec<u8>) {
        match self.0 {
            SpkInner::Script(ref spk) => spk_components(spk),
            SpkInner::Hashed(hash) => (-1, hash.to_byte_array().to_vec()),
        }
    }

    // Decoding supports the program lengths that have a lexer token.
    fn is_decodable(&self) -> bool { matches!(self.components().1.len(), 20 | 32) }
}

impl fmt::Display for Spk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            SpkInner::Script(ref spk) => write!(f, "{}", spk.as_bytes().as_hex()),
            SpkInner::Hashed(hash) => write!(f, "hashed_spk({})", hash),
        }
    }
}

/// The witness version and program that the introspection opcodes push for `spk`.
pub(super) fn spk_components(spk: &elements::Script) -> (i8, Vec<u8>) {
    let bytes = spk.as_bytes();
    if spk.is_witness_program() {
        // `OP_0` or `OP_1` to `OP_16`, followed by a push of the program.
        let version = bytes[0].saturating_sub(0x50) as i8;
        (version, bytes[2..].to_vec())
    } else {
        (-1, sha256::Hash::hash(bytes).to_byte_array().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_match_positions() {
        let key = "26d137d15e2ae24f2d5158663d190d1269ad6b1a6ce330aa825ba502e7519d44";
        let msg = "f38b23e7d84506eb8eb477792ba607f908fe8a64ac9ae8dc0e760096e1550562";
        let asset = "01c73ac1b7a518499b9642aed8cfa15d5401e5bd85ad760b937b69521c297722f0";
        let value = "010000000011110000";

        let parsed = CovExtArgs::arg_from_str(key, "csfs", 0).unwrap();
        assert_eq!(parsed.to_string(), key);
        assert_eq!(CovExtArgs::arg_from_str(key, "price_oracle1_w", 0).unwrap(), parsed);
        assert_eq!(
            CovExtArgs::arg_from_str(msg, "csfs", 1)
                .unwrap()
                .to_string(),
            msg
        );
        assert_eq!(
            CovExtArgs::arg_from_str(asset, "asset_eq", 1)
                .unwrap()
                .to_string(),
            asset
        );
        assert_eq!(
            CovExtArgs::arg_from_str(value, "is_exp_value", 0)
                .unwrap()
                .to_string(),
            value
        );

        // The position decides the kind: these message bytes are also a valid key.
        assert!(matches!(CovExtArgs::arg_from_str(msg, "csfs", 0), Ok(CovExtArgs::XOnlyKey(_))));
        assert!(matches!(CovExtArgs::arg_from_str(key, "csfs", 1), Ok(CovExtArgs::CsfsMsg(_))));
        // Arguments unsuited to their position, unknown positions and malformed arguments.
        assert!(CovExtArgs::arg_from_str(value, "csfs", 0).is_err());
        assert!(CovExtArgs::arg_from_str(key, "csfs", 2).is_err());
        assert!(parsed.check_arg("value_eq", 0).is_err());
        // A message must be exactly 32 bytes.
        assert!(CovExtArgs::arg_from_str(&msg[2..], "csfs", 1).is_err());
        assert!(CovExtArgs::arg_from_str(&format!("{}00", msg), "csfs", 1).is_err());
        assert!(CsfsMsg::from_slice(&[0; 31]).is_none());
        // Null assets have no Script encoding; null values encode as explicit zero.
        assert!(CovExtArgs::arg_from_str("00", "asset_eq", 0).is_err());
        assert!(CovExtArgs::arg_from_str("00", "value_eq", 0).is_ok());
    }

    #[test]
    fn spk_arg_components() {
        let v0 = "0014c73ac1b7a518499b9642aed8cfa15d5401e5bd85";
        let v1 = "5120c73ac1b7a518499b9642aed8cfa15d5401e5bd85ad760b937b69521c297722f0";
        let p2sh = "a914c73ac1b7a518499b9642aed8cfa15d5401e5bd8587";
        for (spk, version, len) in [(v0, 0, 20), (v1, 1, 32), (p2sh, -1, 32)] {
            let arg = CovExtArgs::arg_from_str(spk, "spk_eq", 1).unwrap();
            assert_eq!(arg.to_string(), spk);
            let (v, program) = arg.as_spk().components();
            assert_eq!((v, program.len()), (version, len));
        }
        // A witness program without a lexer token for its length.
        let v1_short = "5104c73ac1b7";
        assert!(CovExtArgs::arg_from_str(v1_short, "spk_eq", 0).is_err());
    }
}
