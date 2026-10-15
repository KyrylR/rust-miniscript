# Elements Miniscript

Library for handling [Miniscript](http://bitcoin.sipa.be/miniscript/),
which is a subset of Elements Script designed to support simple and general
tooling. Miniscripts represent threshold circuits of spending conditions,
and can therefore be easily visualized or serialized as human-readable
strings.

## High-Level Features

This library supports

* [Output descriptors](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
including embedded Miniscripts
* Parsing and serializing descriptors to a human-readable string format
* Compilation of abstract spending policies to Miniscript (enabled by the
`compiler` flag)
* Semantic analysis of Miniscripts and spending policies, with user-defined
public key types
* Encoding and decoding Miniscript as Elements Script, given key types that
are convertible to `bitcoin::PublicKey`
* Determining satisfiability, and optimal witnesses, for a given descriptor;
completing an unsigned `elements::TxIn` with appropriate data
* Determining the specific keys, hash preimages and timelocks used to spend
coins in a given Elements transaction

Elements requires the Rust standard library. Disabling default features does not enable `no_std` or embedded targets.

Descriptor names use the `el` prefix, for example `elwpkh(KEY)` and
`eltr(KEY,TREE)`. The `psbt` module operates on Elements PSETs.

More information can be found in [the documentation](https://docs.rs/elements-miniscript)
or in [the `examples/` directory](examples/)

## Minimum Supported Rust Version (MSRV)

The minimum supported Rust version is **1.74.0**.

See the [migration guide](doc/migration.md) for changes from elements-miniscript 0.5.

## Contributing

Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in
[##miniscript](https://web.libera.chat/?channels=##miniscript) on Libera.

## Benchmarks

Run the benchmarks with `RUSTFLAGS='--cfg=bench' cargo +nightly bench benchmarks`.


## Other Resources

An [ANTLR4 grammar](https://github.com/antlr/grammars-v4/tree/master/miniscript) for Miniscript expressions is available in the ANTLR `grammars-v4` repository.

## Release Notes

See [CHANGELOG.md](CHANGELOG.md).


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0
Universal license](LICENSE). We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX
IDs](https://spdx.dev/ids/).
