# Workflow notes

`rust.yml` tests the minimal and recent dependency lockfiles on stable, nightly
and Rust 1.74. It also checks formatting, lint, documentation and benchmarks.

The integration job downloads Elements 23.3.1, verifies its archive checksum and
runs the tests in `bitcoind-tests`. For a local run, set `ELEMENTSD_EXE` to an
Elements executable and run `contrib/integration_test.sh`.
