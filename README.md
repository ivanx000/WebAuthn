# WebAuthn

A WebAuthn relying-party library written in Rust.

This library implements the server-side ceremony verification logic for both WebAuthn
flows — registration and authentication — following the
[W3C WebAuthn Level 2 specification](https://www.w3.org/TR/webauthn-2/).
It is built as a portfolio project demonstrating practical applied cryptography,
correct protocol implementation, and idiomatic Rust.

---

## What are WebAuthn and Passkeys?

**WebAuthn** (Web Authentication) is a W3C standard that lets users authenticate
to websites using public-key cryptography instead of passwords. When you register,
the authenticator (your phone, laptop, or a hardware key) generates a keypair. The
private key never leaves the device; the public key goes to the server. When you
log in, the authenticator signs a server-issued challenge with the private key, and
the server verifies the signature. An attacker who steals the server's database gets
only public keys — useless without the corresponding private keys.

**Passkeys** are the consumer-facing name for WebAuthn credentials that sync across
devices via platform ecosystems (iCloud Keychain, Google Password Manager, etc.).
Technically, a passkey is a WebAuthn credential stored in a platform authenticator.
The underlying cryptography is identical.

Both eliminate the biggest password risks: phishing (the credential is
cryptographically bound to the origin), credential stuffing (public keys are
worthless without private keys), and password reuse (each site gets a unique keypair).

---

## What this library implements

| Feature | Status |
|---------|--------|
| Registration ceremony (§7.1) | Implemented |
| Authentication ceremony (§7.2) | Implemented |
| ES256 (ECDSA P-256 + SHA-256) | Implemented |
| Attestation format `"none"` | Implemented |
| Sign-count replay attack detection | Implemented |
| Challenge generation (32-byte random) | Implemented |
| RS256 (RSA PKCS#1v1.5 + SHA-256) | Struct defined, verification not yet impl |
| Packed / FIDO-U2F / TPM attestation | Not implemented |
| Token binding | Not implemented |
| FIDO Metadata Service (MDS) lookup | Not implemented |
| Attestation trust chain validation | Not implemented |

This scope is intentional. The library demonstrates mastery of the core protocol
and cryptographic operations without adding surface area that obscures the design.

---

## Quick start

```rust
use webauthn::{RelyingParty, AuthenticatorAttestationResponse,
               AuthenticatorAssertionResponse, Challenge};

// 1. Configure the relying party once, at startup.
let rp = RelyingParty::new("example.com", "https://example.com", "My Service");

// ── Registration ──────────────────────────────────────────
// 2. Generate a challenge and send it to the browser.
let reg_challenge = Challenge::new()?;

// 3. Browser calls navigator.credentials.create() and returns:
let reg_response = AuthenticatorAttestationResponse {
    client_data_json:   todo!("raw bytes from browser response"),
    attestation_object: todo!("raw bytes from browser response"),
};

// 4. Verify and store the credential.
let result = rp.verify_registration(&reg_challenge, &reg_response, b"user-id-42")?;
let mut stored = result.credential; // persist this in your database

// ── Authentication ────────────────────────────────────────
// 5. Issue a new challenge (never reuse challenges).
let auth_challenge = Challenge::new()?;

// 6. Browser calls navigator.credentials.get() and returns:
let auth_response = AuthenticatorAssertionResponse {
    client_data_json:   todo!("raw bytes from browser response"),
    authenticator_data: todo!("raw bytes from browser response"),
    signature:          todo!("raw bytes from browser response"),
    user_handle:        None,
};

// 7. Verify, then update the stored sign count.
let auth_result = rp.verify_authentication(&stored, &auth_challenge, &auth_response)?;
stored.sign_count = auth_result.new_sign_count;
```

Run the self-contained demo to see a full registration → authentication → replay-attack
sequence without a browser:

```
cargo run --example demo
```

---

## Running tests

```
cargo test          # unit + integration tests
cargo clippy        # lint (zero-warning policy)
cargo doc --open    # API documentation
```

---

## Security considerations

### What the library verifies

- **Origin binding** — `clientDataJSON.origin` must exactly equal `expected_origin`.
  This defeats cross-origin replays (a credential from `bank.com` cannot be used at
  `evil.com`).

- **RP ID binding** — the authenticator data's `rpIdHash` is verified to equal
  `SHA-256(rp_id)`. This binds the credential to the relying party identifier.

- **Challenge freshness** — the challenge in `clientDataJSON` must match the
  server-issued challenge byte-for-byte. The relying party must invalidate the
  challenge after use (single-use enforcement is the caller's responsibility).

- **User presence** — the UP flag in authenticator data must be set. The
  authenticator confirmed that a human was physically present.

- **Cryptographic signature** — the ECDSA-P256-SHA256 signature over
  `authData || SHA-256(clientDataJSON)` is verified using `ring`.

- **Sign count** — a non-zero received count must be strictly greater than the
  stored count. A violation indicates a possible cloned authenticator.

### What the caller must provide

| Responsibility | Notes |
|----------------|-------|
| Credential storage | A durable, indexed key-value store keyed by credential ID |
| Single-use challenges | Invalidate each challenge after it is used or expires |
| Challenge expiry | `webauthn::challenge::is_expired()` checks a 5-minute window |
| HTTPS | WebAuthn requires a secure context; enforce TLS at the transport layer |
| Sign-count update | After successful auth, write `auth_result.new_sign_count` back |
| User enumeration prevention | Return the same error for unknown vs. invalid credential |

### What this library does NOT protect against

- **Full attestation chain** — only `"none"` attestation is verified. Unverified
  attestation means you cannot distinguish genuine authenticators from software
  emulators.
- **Token binding** — `tokenBinding` in `clientDataJSON` is ignored.
- **Cloned authenticators with zero counters** — if `sign_count == 0` the spec
  allows accepting the assertion (the authenticator simply doesn't count). Clone
  detection is unavailable in this case.
- **Side-channel attacks** — ring's `verify` provides constant-time comparison of
  the signature, but this library itself does not claim constant-time credential
  lookups or error responses.

---

## Tech stack

| Crate | Purpose |
|-------|---------|
| `ring` 0.17 | ECDSA P-256 signature verification, SHA-256, CSPRNG |
| `ciborium` 0.2 | CBOR decoding for authenticator data and attestation objects |
| `serde` + `serde_json` 1 | `clientDataJSON` parsing |
| `base64` 0.22 | URL-safe base64 encoding/decoding |
| `thiserror` 1 | Structured, descriptive error types |

---

## References

- [W3C Web Authentication Level 2](https://www.w3.org/TR/webauthn-2/)
- [FIDO Alliance CTAP2 specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/)
- [RFC 8152 — CBOR Object Signing and Encryption (COSE)](https://www.rfc-editor.org/rfc/rfc8152)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [passkeys.dev — developer documentation](https://passkeys.dev)

---

> **Note:** This is a learning and portfolio project. It is not production-hardened,
> has not been security audited, and is missing several features required for
> production use (full attestation, metadata service integration, token binding).
> Do not use it to protect real user accounts without significant additional work.
