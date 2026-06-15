# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-06-14

### Added

- **Registration ceremony** (W3C WebAuthn Level 2, §7.1)
  - `RelyingParty::verify_registration` verifies clientDataJSON, attestation object, and
    authenticator data for new credential registration
- **Authentication ceremony** (W3C WebAuthn Level 2, §7.2)
  - `RelyingParty::verify_authentication` verifies clientDataJSON, authenticator data, and
    ECDSA/RSA signature for subsequent authentication
- **ES256** — ECDSA P-256 + SHA-256 (COSE algorithm -7), the most common WebAuthn algorithm
- **RS256** — RSA PKCS#1 v1.5 + SHA-256 (COSE algorithm -257), for legacy YubiKey 4 devices
  and Windows Hello
- **Packed attestation** — self-attestation fully verified; basic attestation (x5c) detected
  but certificate chain not verified (no FIDO MDS integration)
- **None attestation** — accepted per §8.7
- **Sign-count replay protection** — received count must exceed stored count
- **Challenge expiry** — configurable TTL with `CHALLENGE_MAX_AGE_SECS` default
- **`#![forbid(unsafe_code)]`** — zero unsafe in this crate; enforced at compile time
- **`#![deny(clippy::unwrap_used)]`** — no panics in library code; enforced at compile time
- **No-panic fuzz tests** — two deterministic tests exercise all ceremony paths with random
  inputs and assert no panic occurs
- **Fixed test vectors** — pre-generated P-256 ceremony fixtures for regression detection
- **Axum server example** — `examples/server.rs` demonstrates real HTTP integration with all
  five WebAuthn endpoints
- **End-to-end demo** — `examples/demo.rs` exercises ES256 + RS256 registration, authentication,
  and replay attack rejection entirely in software

[0.1.0]: https://github.com/ivanxie/WebAuthn/releases/tag/v0.1.0
