# Migrating from elements-miniscript 0.5

The library uses the current rust-miniscript parser, validation, planning and
descriptor APIs with Elements transaction and script types. Rust 1.74 is
required. Dependencies use the standard library even with
`--no-default-features`, so this does not enable `no_std` support.

## Descriptor derivation

Use `into_definite()` for a descriptor without wildcards. For a wildcard
descriptor, use `derive_at_index(index).into_result()`. If the caller accepts
either form, use `derive_at_index(index).or_fallback()`.

These operations return `NonDefiniteKeyError`, replacing `ConversionError`.
Once a descriptor has `DefiniteDescriptorKey` keys, `derived_descriptor(&secp)`
returns the concrete descriptor directly.

## Checksums

Replace `descriptor::checksum::desc_checksum` with the checksum engine:

```rust
use elements_miniscript::descriptor::checksum::Engine;

let mut engine = Engine::new();
engine.input(descriptor_text)?;
let checksum = engine.checksum();
```

Formatting a parsed descriptor already includes its checksum.

## Miniscript and key translation

`Translator<P>` declares its output key and error types through the associated
types `TargetPk` and `Error`. They are no longer extra trait parameters.
Call the `translate_pk` method without importing `TranslatePk`.

`MiniscriptKey`, `ToPublicKey`, `ForEachKey`, `SigType` and `hash256` are
defined by this crate instead of being re-exports from rust-miniscript. The
`Btc*` aliases, such as `BtcDescriptor` and `BtcSatisfier`, are removed.

`sortedmulti` is a Miniscript terminal. Use `Wsh::as_inner()` to access its
Miniscript rather than matching `WshInner`. Constructors take a `Threshold`
instead of separate threshold and key-list arguments. `DescriptorType` has no
sorted-multi variants.

## Descriptor types

`DescriptorInfo` and the `Pegin` and `LegacyPegin` variants of
`DescriptorType` are removed, as are the `FromStr` and `Display` impls of
`DescriptorType`. Parse the text as a `Descriptor` and call `desc_type()`.
`Descriptor::parse_descriptor` returns any secret keys in its key map.

## PSET signature hashes

The `psbt` module continues to operate on Elements PSETs. Match
`PsbtSighashMsg::LegacySighash` and `PsbtSighashMsg::SegwitV0Sighash` in place of
the combined `EcdsaSighash` variant. Taproot uses `TapSighash`.

## PSET partial signatures

`PsbtExt::extract`, `psbt::finalize` and `psbt::finalize_mall` check every
partial signature. elements-miniscript 0.5 only checked the input count. A
signature must be DER followed by a standard sighash byte. Its sighash type
must equal the input's `sighash_type`, or `ALL` if that is unset. Otherwise
the methods return `InputError::Interpreter` or `InputError::WrongSighashFlag`.
The `PsbtExt` finalize methods reject a partial signature of the input being
finalized that does not parse, rather than treating it as missing.

## Spending plans and weight estimates

A spending plan supplies the scriptSig and script witness. Its size estimate does
not include issuance proofs. Include those fields, their serialized lengths and
the transaction's witness overhead when estimating a complete transaction fee.
Descriptor `max_weight_to_satisfy` is the increase over an unsatisfied input,
rather than the total input weight.

## Address errors

The crate-wide error no longer wraps Bitcoin address parsing or P2SH construction
errors. Elements descriptor address methods do not produce these errors.

## Interpreter constraints

Unlike in rust-miniscript, `KeySigPair` and `SatisfiedConstraint` do not
implement `Hash`, because the rust-elements signature types do not.

`Interpreter::iter` now takes the Elements transaction, input index,
prevouts, and genesis hash instead of the 0.5 `TxEnv`. Supply the matching
prevouts and genesis hash when verifying Taproot signatures.
