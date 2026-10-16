# Workflow notes

`rust.yml` tests the minimal and recent dependency lockfiles on stable, nightly
and Rust 1.74. It also checks formatting, lint, documentation and benchmarks.
It runs on pull requests and on pushes to `master`, and `shellcheck.yml` runs on
pull requests to `master`, so the default branch must be named `master`. Both
pull request workflows give their Actions tokens read-only access.

The integration job downloads Elements 23.3.1, verifies its archive checksum and
runs the tests in `bitcoind-tests`. For a local run, set `ELEMENTSD_EXE` to an
Elements executable and run `contrib/integration_test.sh`.

`cron-daily-fuzz.yml` schedules every fuzz target daily. Pull requests do not
run it.

`upstream-sync.yml` proposes rust-miniscript updates as draft pull requests. It
does nothing until the `upstream-sync` environment has an `UPSTREAM_SYNC_TOKEN`
secret. The proposals keep `.github` as it is on the default branch, so upstream
changes to it need a separate reviewed commit. See `CONTRIBUTING.md` for the
credentials and the review steps.

The weekly nightly and `cargo-rbmt` update workflows come from rust-miniscript
and run only there. The upstream syncs bring their updates here.
