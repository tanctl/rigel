#!/usr/bin/env bash
set -euo pipefail

REQUIRED_SCARB="2.14.0"
REQUIRED_SNFORGE="0.56.0"
REQUIRED_USC="2.7.0"

export SCARB_CACHE="${SCARB_CACHE:-$PWD/.scarb-cache}"
mkdir -p "$SCARB_CACHE"

scarb_version=$(scarb --version | head -n 1 | awk '{print $2}')
if [[ "$scarb_version" != "$REQUIRED_SCARB" ]]; then
  echo "Expected scarb $REQUIRED_SCARB, got $scarb_version" >&2
  exit 1
fi

snforge_version=$(snforge --version | awk '{print $2}')
if [[ "$snforge_version" != "$REQUIRED_SNFORGE" ]]; then
  echo "Expected snforge $REQUIRED_SNFORGE, got $snforge_version" >&2
  exit 1
fi

usc_version=$(universal-sierra-compiler --version | awk '{print $2}')
if [[ "$usc_version" != "$REQUIRED_USC" ]]; then
  echo "Expected universal-sierra-compiler $REQUIRED_USC, got $usc_version" >&2
  exit 1
fi

scarb build
snforge test | tee /tmp/snforge.out

cargo test --manifest-path rigel-prover/Cargo.toml
cargo clippy --manifest-path rigel-prover/Cargo.toml --all-targets -- -D warnings
