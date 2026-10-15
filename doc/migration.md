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
`ExtTranslator<PExt>` likewise declares `TargetExt` and `Error`. Call the
`translate_pk` and `translate_ext` methods without importing `TranslatePk` or
`TranslateExt`.

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

## Covenant extension storage

`CovenantExt` variants contain boxed payloads. Use `Box::new(fragment)` when
constructing a variant directly. Parsed extensions allocate this storage only
for covenant fragments, keeping ordinary Miniscript nodes compact.

## Message signatures

`csfs` messages must be exactly 32 bytes, matching the Schnorr message API of the
secp256k1 dependency. Older descriptor text accepted up to 80 bytes, though
script decoding and interpretation did not support the other lengths.

`csfs` signatures and price attestations can be replayed in another transaction.
They do not make a spending branch safe by themselves. Combine them with a
transaction signature such as `pk` to pass the default safety checks.

## Taproot leaves

`Tr::leaves()` and `Tr::spend_info().leaves()` include every leaf in tree order.
Their `miniscript()` accessor returns `None` for an opaque Simplicity commitment.
Use the leaf's script and version methods when building PSET metadata, and skip
opaque leaves when looking for Miniscript keys or spending plans.

Version 0.5 parsed Simplicity policies in leaves such as `eltr(K,sim{pk(A)})`
through the `simplicity-lang` crate. That grammar and the dependency are
removed, so such descriptors no longer parse. Compute the program's CMR with
rust-simplicity and write the leaf as `sim{asm(CMR)}`. The leaf script is the
CMR, so the Taproot output stays the same when the CMR does.

With the `simplicity` feature, `sim{asm(CMR)}` commits to a program without
revealing it. `SimplicityLeaf::from_cmr` and `cmr` use `[u8; 32]`. Pass
`Cmr::to_byte_array()` when using rust-simplicity. The feature adds no runtime
or compiler dependency. Any such leaf makes a complete policy lift and maximum satisfaction
weight unavailable. Available key paths and ordinary script leaves can still be
planned and satisfied. The interpreter returns `UnsupportedTapLeafVersion` for
Simplicity and other leaf versions it cannot evaluate.

## Compiled descriptors

Policy compilation returns `Descriptor<Pk, NoExt>`, because the compiler emits
ordinary Miniscript. Descriptor-consuming PSET methods accept this directly.
When calling generic `parse_descriptor`, specify the key type, for example
`Descriptor::<DescriptorPublicKey>::parse_descriptor`, to select the default
covenant extension type. `NoExt` excludes extensions from Taproot Miniscript
leaves; it does not disable the separate `elcovwsh` descriptor variant.

## Blinding key derivation

Bare-key tweaks and SLIP-77 blinding key derivation return `Result`. Propagate
the returned `bitcoin::secp256k1::Error` if a derived scalar or tweaked key
is invalid. Confidential descriptor methods wrap this error in
`confidential::Error::BlindingKeyDerivation`. No replacement scalar or retry
is used.

## Introspection constructors

`CovOps` has checked constructors instead of public variants. Use `asset_eq`,
`value_eq`, `spk_eq`, `is_exp_asset` and `is_exp_value` to reject constants of
the wrong type before script encoding. Null asset constants are rejected. Null value
constants encode as explicit zero and decode in that form.
`IdxExpr::Const` and `CovOps::curr_idx_eq` take `IdxConst`, whose constructor
rejects values above `i32::MAX`. `CovOps::idx_eq` returns a `Result`. It and the
other `CovOps` constructors and `Arith::new` reject operands nested deeper than
script decoding allows.
`idx_eq(i,curr_idx)` decodes from script as the equivalent `curr_idx_eq(i)`.
Likewise, `inp_v(curr_idx)` decodes as `curr_inp_v`, and `inp_asset(curr_idx)`,
`inp_value(curr_idx)` and `inp_spk(curr_idx)` decode as `curr_inp_asset`,
`curr_inp_value` and `curr_inp_spk`.

## Legacy covenant signatures

`Satisfier::lookup_legacy_covenant_sig` supplies the signature over
`LegacyCovSatisfier::sighash`. Use `CovenantSignature { key, signature }` from
`descriptor::csfs_cov` in a tuple with the inner-script satisfier. Ordinary
`lookup_ecdsa_sig` signatures sign the full witness script, as computed by
`PsbtExt::sighash_msg`. The two signatures are distinct even for the same key.

PSETs hold only one partial signature per key. The finalizer reserves the
covenant key's entry for the covenant signature. It can use another inner
spending path, but cannot finalize a path requiring that same key's inner
signature. Direct satisfaction supports both signatures through the separate
lookups.

## Interpreter constraints

Unlike in rust-miniscript, `KeySigPair` and `SatisfiedConstraint` do not
implement `Hash`, because the rust-elements signature types do not.

## Issuance expressions

`inp_issue_v` and `inp_reissue_v` check that `INSPECTINPUTISSUANCE` returned
an issuance before selecting its amount. Without that check, an absent issuance
lets the following stack operations consume witness data instead. Descriptors
containing these expressions now produce different scripts and addresses.
The decoder rejects the old unguarded encoding. Retain the original script
and spending procedure for outputs created with that encoding.

## Interpreter environments

`Interpreter::iter` takes the Elements genesis hash and derives its transaction
environment from `Prevouts::All`. Custom verifiers and `iter_assume_sigs` can
supply one with `Iter::with_tx_env`. A missing environment produces
`TxEnvNotPresent` when a fragment inspects the transaction.

Implement `Satisfier::lookup_tx_env` instead of the separate transaction, spent
output and input-index lookups. Access individual spent outputs through
`TxEnv::spent_utxo`. `LegacyCovSatisfier` supplies the legacy covenant preimage
items previously supplied by individual `lookup_nversion` through
`lookup_sighashu32` methods.
