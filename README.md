# Rigel

Rigel is a Stark-curve Fiat-Shamir Sigma protocol library composed of a Cairo verifier crate (`rigel`) and a Rust prover / verifier-parity crate (`rigel-prover`).

It exposes typed verification APIs, byte-decoding verification wrappers, canonical felt encoders, and fixed-width proof encodings for off-chain proof generation and Cairo-side verification.

## Protocol Surface

Atomic protocols:

- Schnorr proof of knowledge
- DLog over an explicit base
- Chaum-Pedersen equality of discrete logs
- Okamoto proof of representation

Pedersen-family protocols:

- Pedersen opening proof
- Pedersen equality proof across two commitments
- Pedersen rerandomization proof

Composition and advanced protocols:

- AND composition
- OR composition
- Ring membership
- One-out-of-many over Pedersen commitments

Batch verification:

- Schnorr
- DLog
- Chaum-Pedersen
- Okamoto
- Pedersen opening
- Pedersen equality
- Pedersen rerandomization

## Cryptographic Conventions

- Curve: Stark curve
- Transcript hash: Poseidon
- Domain separation: protocol tag plus `STARK-CURVE`
- Scalar arithmetic: modulo Stark-curve order `q`
- Field arithmetic: Cairo `felt252` field modulo Stark field prime `p`
- Scalar encoding: 32-byte big-endian canonical values `< q`
- Point encoding: 64-byte big-endian uncompressed `x || y`

Challenge Rules:

- globally derived Fiat-Shamir challenges must be non-zero
- OR and ring branch challenges may be zero, but must remain canonical

Pedersen Integration Requirements:

- verifier APIs are explicit-base at the statement boundary
- default Pedersen helper bases exist in Rust, but integrations should keep base choice explicit end to end

One-out-of-many Constraints:

- candidate set size must be a power of two
- current implementation limit is `MAX_ONE_OUT_OF_MANY = 64`

Additional hard limits:

- `MAX_OKAMOTO_BASES = 64`
- `MAX_RING_SIZE = 64`

## API Model

Verifier entrypoints exist in two forms where applicable:

- typed APIs operating on decoded points and canonical scalars
- `*_bytes` APIs that decode fixed-width byte inputs before verification

Short verification APIs are available for the atomic and Pedersen-family protocols. These APIs accept `(challenge, response...)` and reconstruct the commitment before re-deriving and checking the transcript challenge.

## Repository Layout

- `src/core/`: transcript, scalar, canonical encoding, decoding, and verification plumbing
- `src/protocols/`: atomic and Pedersen-family Cairo verifiers
- `src/composition/`: AND, OR, and batch verification logic
- `src/advanced/`: ring and one-out-of-many verifiers
- `src/tests/suite.cairo`: Cairo test suite
- `rigel-prover/src/core/`: Rust scalar, curve, transcript, canonical encoding, and decode logic
- `rigel-prover/src/protocols/`: Rust proving and parity verification for atomic and Pedersen-family protocols
- `rigel-prover/src/composition/`: Rust AND, OR, batch, and proof simulation helpers
- `rigel-prover/src/advanced/`: Rust ring and one-out-of-many proving and verification
- `rigel-prover/tests/`: Rust roundtrip, byte, batch, and adversarial tests
- `rigel-prover/fuzz/`: Rust fuzz targets

## Build And Validation

Pinned toolchain:

- Scarb `2.14.0`
- snforge `0.56.0`
- universal-sierra-compiler `2.7.0`
- Rust `1.93.0`

Local validation:

```bash
scarb build
snforge test
cargo test --manifest-path rigel-prover/Cargo.toml
cargo clippy --manifest-path rigel-prover/Cargo.toml --all-targets -- -D warnings
```

Parity gate:

```bash
bash scripts/ci.sh
```

## Security

Rigel is unaudited cryptographic infrastructure. The current implementation includes in-repo tests, Rust/Cairo parity coverage, malformed-encoding checks, and adversarial composition tests, but deployments should still require an external security review.
