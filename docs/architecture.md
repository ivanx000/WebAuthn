# Architecture

How passforge is structured and why.

---

## Module map

```
passforge
├── lib.rs                  Public API surface
│   └── RelyingParty        Stateless ceremony verifier (entry point)
│   └── AuthenticatorAttestationResponse   Registration wire type
│   └── AuthenticatorAssertionResponse     Authentication wire type
│
├── error.rs                PassforgeError enum + Result alias
│
├── credential.rs           Domain types
│   ├── Credential          Stored credential (post-registration)
│   ├── PublicKey           ES256 / RS256 public key wrapper
│   ├── Challenge           Random bytes + creation timestamp
│   ├── RegistrationResult  Return value of verify_registration
│   ├── AuthenticationResult Return value of verify_authentication
│   └── AttestationType     None / SelfAttestation
│
├── crypto.rs               Cryptographic primitives (delegated to ring)
│   ├── sha256()            SHA-256 digest
│   ├── verify_es256_signature()   ECDSA P-256 verification
│   └── generate_challenge()       32-byte CSPRNG challenge
│
├── challenge.rs            Challenge lifecycle helpers
│   ├── is_expired()        Checks against 5-minute default
│   └── is_expired_with_max_age()  Configurable expiry
│
├── client_data.rs          clientDataJSON parsing
│   └── parse()             base64url → UTF-8 → JSON → ClientData
│
├── authenticator_data.rs   Binary authenticator data parsing
│   ├── parse()             Raw bytes → AuthenticatorData
│   └── (internal) parse_cose_key()  CBOR COSE key → PublicKey
│
├── attestation.rs          Attestation statement verification
│   └── verify()            Only "none" format currently supported
│
├── registration.rs         §7.1 registration ceremony
│   └── verify()            All steps in spec order, cited by step number
│
└── authentication.rs       §7.2 authentication ceremony
    └── verify()            All steps in spec order, cited by step number
```

---

## Data flow: registration

```
AuthenticatorAttestationResponse
    │
    │  client_data_json  (base64url)
    ├─► base64url::decode → UTF-8 bytes → serde_json::parse → ClientData
    │     │
    │     ├─ verify type == "webauthn.create"
    │     ├─ verify challenge bytes match issued challenge
    │     └─ verify origin == expected_origin
    │
    │  attestation_object  (base64url)
    └─► base64url::decode → CBOR bytes → ciborium::parse → {fmt, authData}
          │
          │  authData  (raw bytes)
          └─► parse_authenticator_data()
                ├─ rp_id_hash [0..32]  → verify == SHA-256(rp_id)
                ├─ flags [32]          → verify UP bit is set
                ├─ sign_count [33..37] → stored in Credential
                └─ attested_credential_data [37..]
                      ├─ aaguid [0..16]
                      ├─ credential_id
                      └─ COSE key (CBOR) → parse_cose_key()
                            └─ x, y → 0x04 || x || y → PublicKey::ES256

→ attestation::verify(fmt, ...)   [only "none" accepted]
→ Credential { id, public_key, sign_count, user_id, rp_id, created_at }
→ RegistrationResult { credential, attestation_type }
```

## Data flow: authentication

```
AuthenticatorAssertionResponse
    │
    ├─ client_data_json  → same parsing as registration, type must be "webauthn.get"
    │     └─ SHA-256(client_data_json_bytes) → clientDataHash
    │
    ├─ authenticator_data  (base64url)
    │     └─► base64url::decode → parse_authenticator_data()
    │           ├─ verify rp_id_hash
    │           └─ verify UP flag
    │
    ├─ signature  (base64url DER-encoded ECDSA)
    │
    └─ Verify signature:
          message = auth_data_bytes || clientDataHash
          ring::signature::UnparsedPublicKey::verify(message, signature)
              └─ internal: SHA-256(message), ECDSA verify with stored public key

→ verify sign_count > stored (replay protection)
→ AuthenticationResult { credential_id, new_sign_count, user_verified }
```

---

## Design decisions

### Why `ring` instead of RustCrypto?

`ring` is a production-grade crypto library descended from BoringSSL. It:
- Has been audited by Cure53
- Is used in production by Cloudflare, Firefox, and many others
- Minimizes the API surface to reduce misuse (no ad-hoc cipher composition)
- Provides constant-time implementations by default

RustCrypto (`ecdsa`, `p256`, `sha2`) is also correct and audited, but `ring`'s
more constrained API is harder to misuse — appropriate for a security-focused project.

### Why `ciborium` for CBOR?

ciborium is a pure-Rust CBOR library that implements RFC 7049 and deserializes into
a `Value` enum. WebAuthn uses CBOR in two places: the attestation object and the
COSE key inside authenticator data. ciborium's `Value` type lets us navigate these
structures without defining serde schemas for CBOR, keeping the parsing code explicit
and easy to follow.

### Why separate registration.rs and authentication.rs?

The W3C spec separates the two ceremonies into §7.1 and §7.2. Keeping them in
separate files means each file directly maps to one spec section. Reviewers can
read the spec and the code side-by-side without context-switching.

### Why is RelyingParty stateless?

Credential storage is application-specific. A relying party might store credentials
in Postgres, Redis, DynamoDB, or an in-memory hashmap. Baking storage into
`RelyingParty` would force a choice that most callers would need to undo. The
caller passes `&Credential` in and gets a `Credential` out; they are responsible
for persistence.

### Why are the response types separate from the core types?

`AuthenticatorAttestationResponse` and `AuthenticatorAssertionResponse` are wire
types — they match the shape of the `navigator.credentials` API in browsers. The
internal types (`ClientData`, `AuthenticatorData`) are richer, fully parsed
representations. Keeping them separate means the parsing code is testable
independently of the base64 decoding layer.

### Why does the public key use the uncompressed point format?

ring's `ECDSA_P256_SHA256_ASN1` verifier expects public keys as uncompressed EC
points: `0x04 || x (32 bytes) || y (32 bytes)`. This is the ANSI X9.62 format
and the one most commonly found in the WebAuthn ecosystem. Storing the key in
this format means no conversion is needed at authentication time.

COSE keys use raw `x` and `y` bytes separately. passforge extracts them and
reassembles the uncompressed point when parsing the registration response.

---

## Spec compliance reference

| Spec section | passforge location |
|---|---|
| §6.1 Authenticator Data | `authenticator_data.rs` |
| §6.5 Attestation | `attestation.rs` |
| §7.1 Registration | `registration.rs` |
| §7.2 Authentication | `authentication.rs` |
| §8.7 "none" attestation | `attestation.rs::verify` |
| RFC 8152 COSE keys | `authenticator_data::parse_cose_key` |

---

## Known limitations and future work

- **RS256** — the `PublicKey::RS256` variant is defined but not verified. ring
  supports RSA, so adding verification is straightforward.
- **Packed attestation** — requires certificate chain validation against the FIDO
  MDS. Substantial additional code.
- **Extension data** — authenticator data extensions are silently ignored.
- **Token binding** — not checked.
- **Multiple origins** — a `Vec<String>` of allowed origins could replace the
  single `expected_origin`.
- **`crossOrigin` enforcement** — the `crossOrigin: true` case is accepted, which
  some relying parties should reject.
