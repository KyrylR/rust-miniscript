// SPDX-License-Identifier: CC0-1.0

//! The covenant check that follows the Miniscript in an `elcovwsh` witness script

use elements::opcodes::all::{
    OP_CAT, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGFROMSTACK,
    OP_CHECKSIGFROMSTACKVERIFY, OP_CHECKSIGVERIFY, OP_CODESEPARATOR, OP_DUP, OP_ELSE, OP_ENDIF,
    OP_EQUAL, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_IF, OP_LEFT, OP_NUMEQUAL, OP_NUMEQUALVERIFY,
    OP_PICK, OP_SHA256, OP_SIZE, OP_SWAP, OP_TOALTSTACK, OP_VERIFY,
};
use elements::opcodes::All;
use elements::script::Builder;
use elements::Script;

/// The sizes of the Elements Segwit v0 signature hash preimage items. The spent amount has 9
/// bytes if explicit and 33 if confidential.
pub(crate) const ITEM_SIZES: [Option<u8>; 11] = [
    Some(4),  // version
    Some(32), // hashPrevouts
    Some(32), // hashSequence
    Some(32), // hashIssuances
    Some(36), // outpoint
    Some(3),  // script code
    None,     // spent amount
    Some(4),  // sequence
    Some(32), // hashOutputs
    Some(4),  // locktime
    Some(4),  // sighash type
];

/// The size of the covenant check, without the VERIFY that may merge into the Miniscript.
pub(super) const COVENANT_SIZE: usize = 119;

/// The non-push opcodes of the covenant check, without the VERIFY that may merge into the
/// Miniscript.
pub(super) const COVENANT_OPS: usize = 62;

/// The script that the covenant key signs: the witness script after `OP_CODESEPARATOR`.
pub(crate) fn script_code() -> Script {
    Builder::new()
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_opcode(OP_CHECKSIGFROMSTACK)
        .into_script()
}

/// Verifies the result of the Miniscript, then the signature of `key` over the preimage items.
pub(super) fn push_covenant(builder: Builder, key: &bitcoin::PublicKey) -> Builder {
    // Below the result are the signature and the 11 items, with the version on top. Copy the
    // signature, append the first byte of the sighash type item and keep it for CHECKSIGVERIFY.
    let mut builder = builder
        .push_verify()
        .push_int(11)
        .push_opcode(OP_PICK)
        .push_int(11)
        .push_opcode(OP_PICK)
        .push_int(1)
        .push_opcode(OP_LEFT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_TOALTSTACK);
    // Concatenate the items from the version on, checking their sizes.
    for (i, size) in ITEM_SIZES.iter().enumerate() {
        builder = match size {
            Some(size) => builder
                .push_opcode(OP_SIZE)
                .push_int(i64::from(*size))
                .push_opcode(OP_EQUALVERIFY),
            None => check_amount(builder),
        };
        if i > 0 {
            builder = builder.push_opcode(OP_CAT);
        }
        if i + 1 < ITEM_SIZES.len() {
            builder = builder.push_opcode(OP_SWAP);
        }
    }
    // The signature must verify against the transaction and against the SHA256 of the items.
    builder
        .push_opcode(OP_SHA256)
        .push_key(key)
        .push_opcode(OP_DUP)
        .push_opcode(OP_FROMALTSTACK)
        .push_opcode(OP_SWAP)
        .push_opcode(OP_CODESEPARATOR)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_opcode(OP_CHECKSIGFROMSTACK)
}

// Checks that the spent amount is explicit, a 1 then 8 bytes, or a 33-byte commitment.
fn check_amount(builder: Builder) -> Builder {
    builder
        .push_opcode(OP_DUP)
        .push_int(1)
        .push_opcode(OP_LEFT)
        .push_int(1)
        .push_opcode(OP_EQUAL)
        .push_opcode(OP_IF)
        .push_opcode(OP_SIZE)
        .push_int(9)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_ELSE)
        .push_opcode(OP_SIZE)
        .push_int(33)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_ENDIF)
}

/// Splits an `elcovwsh` witness script into its Miniscript and covenant key, undoing
/// [`push_covenant`].
///
/// Only checks the parts that it takes apart. Decoding encodes the result again and compares.
pub(super) fn split(bytes: &[u8]) -> Option<(Script, bitcoin::PublicKey)> {
    let (body, covenant) = bytes.split_at(bytes.len().checked_sub(COVENANT_SIZE)?);
    // The key is the only 33-byte push of the covenant check. The Bitcoin script type reads
    // the pushes without copying the bytes, and both chains encode pushes alike.
    let key = bitcoin::Script::from_bytes(covenant)
        .instructions()
        .find_map(|ins| match ins {
            Ok(bitcoin::script::Instruction::PushBytes(key)) if key.len() == 33 => {
                bitcoin::PublicKey::from_slice(key.as_bytes()).ok()
            }
            _ => None,
        })?;
    let (verify, ms) = body.split_last()?;
    let mut ms = ms.to_vec();
    match All::from(*verify) {
        OP_VERIFY => {}
        verify => ms.push(unverified(verify)?.into_u8()),
    }
    Some((Script::from(ms), key))
}

// The opcode that `Builder::push_verify` merged with VERIFY into `verify`.
fn unverified(verify: All) -> Option<All> {
    Some(match verify {
        OP_EQUALVERIFY => OP_EQUAL,
        OP_NUMEQUALVERIFY => OP_NUMEQUAL,
        OP_CHECKSIGVERIFY => OP_CHECKSIG,
        OP_CHECKMULTISIGVERIFY => OP_CHECKMULTISIG,
        OP_CHECKSIGFROMSTACKVERIFY => OP_CHECKSIGFROMSTACK,
        _ => return None,
    })
}
