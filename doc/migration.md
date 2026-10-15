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
defined by this crate instead of being re-exports from `bitcoin_miniscript`. A
key type used with both libraries implements the traits of each. The `Btc*`
aliases, such as `BtcDescriptor` and `BtcSatisfier`, are removed. Use the
`bitcoin_miniscript` paths instead.

`sortedmulti` is a Miniscript terminal. Use `Wsh::as_inner()` to access its
Miniscript rather than matching `WshInner`. Constructors take a `Threshold`
instead of separate threshold and key-list arguments. `DescriptorType` has no
sorted-multi variants.

## Descriptor types

`DescriptorInfo` and the `Pegin` and `LegacyPegin` variants of
`DescriptorType` are removed, as are the `FromStr` and `Display` impls of
`DescriptorType`. Parse the text as a `Descriptor`, `Pegin` or `LegacyPegin`
and call `desc_type()` on an Elements descriptor. `Descriptor::parse_descriptor`
returns any secret keys in its key map.

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

## Pegin descriptors

The Bitcoin federation side uses the re-exported `bitcoin_miniscript` crate.
The claim descriptor uses Elements Miniscript. Its claim script is its
scriptPubKey and must be at most 100 bytes.

Federation keys are tweaked with the claim script as in Elements
`calculate_contract`. elements-miniscript 0.5 used the claim descriptor's
explicit script, which differs from its scriptPubKey for `elsh` and `elwsh`.
It also tweaked `pkh` keys and hashed the claim script with SHA256 before
tweaking legacy federation keys. Addresses therefore change for legacy pegins,
for such claim descriptors, and for federations with `pkh` keys.

`Pegin` and `LegacyPegin` methods that build Bitcoin scripts, addresses and
satisfactions return `pegin::Error` instead of panicking. `LegacyPegin::new`
returns a `Result`. It rejects equal federation and emergency thresholds
because that script cannot select the emergency branch as intended.

Construct federation thresholds explicitly with `LegacyPegin::new` instead of
using `new_legacy_fed`. The library does not supply federation constants.
`LegacyPeginKey` holds a `CompressedPublicKey`.

Other pegin APIs changed as follows:

- Import `Pegin` and `LegacyPegin` from `descriptor::pegin`. Its submodules
  are private.
- `Pegin::derived_descriptor` takes the secp context before the index.
- `max_satisfaction_weight` is renamed `max_weight_to_satisfy`. The
  `LegacyPegin` method returns a `Weight` rather than a `Result`.
- Use the `elem_desc` and `desc` fields instead of `into_user_descriptor`,
  and `bitcoin_witness_script` instead of `script_code`.
- `sanity_check` is removed, as it is from `Descriptor`.
- `Pegin` does not implement `Liftable`. Lift its `fed_desc` instead.
  `LegacyPegin` implements only the `bitcoin_miniscript` `Liftable`.
- The crate-root `tweak_key` is removed. The pegin methods apply the tweak.

## Spending plans and weight estimates

A spending plan supplies the scriptSig and script witness. Its size estimate does
not include issuance proofs or the pegin witness. Include those fields, their
serialized lengths and the transaction's witness overhead when estimating a
complete transaction fee. Descriptor `max_weight_to_satisfy` is the increase over
an unsatisfied input, rather than the total input weight.

## Address errors

The crate-wide error no longer wraps Bitcoin address parsing or P2SH construction
errors. Elements descriptor address methods do not produce these errors. Handle
Bitcoin federation address errors through the pegin API.

## Blinding key derivation

Bare-key tweaks and SLIP-77 blinding key derivation return `Result`. Propagate
the returned `bitcoin::secp256k1::Error` if a derived scalar or tweaked key
is invalid. Confidential descriptor methods wrap this error in
`confidential::Error::BlindingKeyDerivation`. No replacement scalar or retry
is used.

## Interpreter constraints

Unlike in rust-miniscript, `KeySigPair` and `SatisfiedConstraint` do not
implement `Hash`, because the rust-elements signature types do not.

`Interpreter::iter` now takes the Elements transaction, input index,
prevouts, and genesis hash instead of the 0.5 `TxEnv`. Supply the matching
prevouts and genesis hash when verifying Taproot signatures.
