#!/usr/bin/env bash
set -euo pipefail

REQUIRED_SCARB="2.14.0"
REQUIRED_SNFORGE="0.56.0"
REQUIRED_USC="2.7.0"
REQUIRED_RUST="1.93.0"

require_command() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing required tool: $tool" >&2
    exit 1
  fi
}

require_version() {
  local tool="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "Expected $tool $expected, got $actual" >&2
    exit 1
  fi
}

export SCARB_CACHE="${SCARB_CACHE:-$PWD/.scarb-cache}"
mkdir -p "$SCARB_CACHE"

require_command scarb
scarb_version=$(scarb --version | head -n 1 | awk '{print $2}')
require_version scarb "$scarb_version" "$REQUIRED_SCARB"

require_command snforge
snforge_version=$(snforge --version | awk '{print $2}')
require_version snforge "$snforge_version" "$REQUIRED_SNFORGE"

require_command universal-sierra-compiler
usc_version=$(universal-sierra-compiler --version | awk '{print $2}')
require_version universal-sierra-compiler "$usc_version" "$REQUIRED_USC"

require_command rustc
rustc_version=$(rustc --version | awk '{print $2}')
require_version rustc "$rustc_version" "$REQUIRED_RUST"

require_command cargo
cargo_version=$(cargo --version | awk '{print $2}')
require_version cargo "$cargo_version" "$REQUIRED_RUST"

scarb build
snforge test | tee /tmp/snforge.out

cargo test --manifest-path rigel-prover/Cargo.toml
cargo clippy --manifest-path rigel-prover/Cargo.toml --all-targets -- -D warnings
