# CLAUDE.md — passforge

Developer guide for this codebase. Start here.

---

## Project overview

passforge is a **WebAuthn relying-party library** written in Rust. It implements
the server-side verification logic for the two core WebAuthn ceremonies —
registration and authentication — following the W3C WebAuthn Level 3 specification.

The project goal is to demonstrate:
- Correct implementation of a real cryptographic protocol
- Idiomatic, readable Rust (not clever — explainable in an interview)
- Layered module design where each file maps to one concept
- Comprehensive error handling with precise, debuggable messages
- Full test coverage including every error path

---

## Crate structure

| File | Purpose |
|------|---------|
| `src/lib.rs` | Public API: `RelyingParty`, wire types, re-exports |
| `src/error.rs` | `PassforgeError` enum + `Result<T>` alias |
| `src/credential.rs` | `Credential`, `PublicKey`, `Challenge`, ceremony result types |
| `src/crypto.rs` | `sha256`, `verify_es256_signature`, `generate_challenge` |
| `src/challenge.rs` | Challenge expiry helpers |
| `src/client_data.rs` | `clientDataJSON` base64url → JSON → `ClientData` |
| `src/authenticator_data.rs` | Authenticator data binary format → `AuthenticatorData` |
| `src/attestation.rs` | Attestation statement verification (currently "none" only) |
| `src/registration.rs` | §7.1 registration ceremony steps |
| `src/authentication.rs` | §7.2 authentication ceremony steps |
| `examples/demo.rs` | End-to-end demo without a browser |
| `tests/integration.rs` | Full pipeline integration tests |

---

## Key design decisions

### `ring` for cryptography

All cryptographic operations (ECDSA P-256 verification, SHA-256, CSPRNG) are
delegated to `ring`, which is an audited library descended from BoringSSL. No
custom crypto. The API is intentionally constrained to prevent misuse.

### `ciborium` for CBOR

WebAuthn uses CBOR for the attestation object and the COSE public key. ciborium
decodes into a `Value` enum (like serde_json's `Value`) which we navigate
explicitly — keeps parsing code readable and avoids opaque serde derives.

### Step-number comments in ceremony code

`registration.rs` and `authentication.rs` cite spec step numbers as comments
(`// §7.1 step 8`). This makes it straightforward to audit the implementation
against the spec. Follow this convention when adding steps.

### Stateless `RelyingParty`

`RelyingParty` holds no state. Callers pass the stored `Credential` in and
get back result types. This keeps the library storage-agnostic.

### `PublicKey::ES256(Vec<u8>)` stores the uncompressed point

The inner `Vec<u8>` is `0x04 || x (32 bytes) || y (32 bytes)` — the format ring
expects. The COSE key's separate `x` and `y` fields are joined here during parsing.

---

## Running the demo

```
cargo run --example demo
```

The demo simulates an authenticator entirely in software: it generates a P-256
keypair with ring, constructs valid `clientDataJSON`, `authenticatorData`, and
an attestation object, then calls the library. It demonstrates:
1. Registration
2. Valid authentication
3. Replay attack rejection

Expected output ends with `All checks passed.`

---

## Running tests

```
cargo test               # all unit + integration tests + doc tests
cargo test --lib         # unit tests only
cargo test --test integration  # integration tests only
```

Unit tests live inside each module (`#[cfg(test)]`). Integration tests in
`tests/integration.rs` exercise the full ceremony pipeline using real P-256 keys.

---

## Adding a test

Unit test pattern:

```rust
#[test]
fn rejects_my_new_error_case() {
    // Arrange: minimal valid state
    // Act: mutate one thing to trigger the error
    // Assert: match on the specific PassforgeError variant
}
```

Integration test pattern (see `tests/integration.rs`):

1. Create a `Fixture` (generates a real keypair)
2. Call `fixture.make_registration_response(...)` with the desired parameters
3. Call `rp.verify_registration(...)` and assert on Ok or Err

---

## Spec references

The WebAuthn spec sections most relevant to this codebase:

- **§6.1** Authenticator Data — the binary format parsed in `authenticator_data.rs`
- **§6.5** Attestation — the structure decoded in `registration.rs::parse_attestation_object`
- **§7.1** Registration — step-by-step in `registration.rs::verify`
- **§7.2** Authentication — step-by-step in `authentication.rs::verify`
- **§8.7** None Attestation — the only format we support, handled in `attestation.rs`
- **RFC 8152 §13** COSE Key Parameters — the CBOR map decoded in `authenticator_data.rs::parse_cose_key`

Canonical URL: https://www.w3.org/TR/webauthn-3/

---

## Known limitations

- RS256 (RSA) public keys: the type exists but verification is not implemented.
- Only `"none"` attestation format is supported.
- Extension data in authenticator data is silently ignored.
- `crossOrigin: true` in clientDataJSON is accepted (some RPs should reject it).
- Single-use challenge enforcement is the caller's responsibility.
- No FIDO Metadata Service integration.

---

## Style guide

- No comments that restate what the code does — only WHY (hidden constraints,
  spec citations, non-obvious invariants).
- All public items must have `///` doc comments.
- Ceremony verification steps must cite the spec section and step number.
- Errors must be specific enough to debug without leaking sensitive data.
- No `unwrap()` in library code — only in tests and the demo.
