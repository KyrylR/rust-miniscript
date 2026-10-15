#!/usr/bin/env bash
# Run integration tests against a local Elements executable.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
: "${ELEMENTSD_EXE:?Set ELEMENTSD_EXE to the Elements executable}"
export ELEMENTSD_EXE
cargo test --manifest-path "$REPO_DIR/bitcoind-tests/Cargo.toml" "$@"
