# Fuzzing (cargo-fuzz)

This directory provides libFuzzer harnesses for verifier correctness and panic safety.

Prerequisites
- Install `cargo-fuzz` and a nightly toolchain.

Examples
```bash
# From repo root
cd rigel-prover
cargo fuzz run verify_atomic
cargo fuzz run verify_batch
```

Targets
- `verify_atomic`: fuzzes atomic verifiers plus advanced verifiers (Ring, Pedersen one-out-of-many).
- `verify_batch`: fuzzes batch verifiers across the same protocols.
