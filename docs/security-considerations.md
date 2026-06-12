# Security Considerations

Detailed security notes for implementers using passforge.

---

## Challenge security

### Why challenges must be random

The challenge is the relying party's proof that a ceremony response was produced
*now* and *for this session*. If an attacker can predict or reuse a challenge, they
can pre-compute or replay a valid signature.

**Requirements:**
- At least 128 bits of entropy (passforge uses 256 bits — 32 bytes from the OS CSPRNG)
- Generated fresh for every ceremony, never reused
- Destroyed after a single use (the relying party must enforce this)

passforge generates challenges via `ring::rand::SystemRandom`, which reads from
`/dev/urandom` on Linux/macOS and `BCryptGenRandom` on Windows. These are
cryptographically secure and cannot be predicted by an attacker.

### Why challenges must be single-use

A captured challenge + response could be replayed to authenticate without the
authenticator. If the same challenge is accepted more than once, a man-in-the-middle
who observed one authentication can impersonate the user in a second session.

**passforge does not enforce single-use** — this is the caller's responsibility.
After calling `verify_registration` or `verify_authentication`, mark the challenge
as consumed in your session store and reject any future presentation of it.

### Challenge expiry

passforge provides `passforge::challenge::is_expired()` which checks a 5-minute
window. Long-lived challenges give attackers more time to observe and replay. The
5-minute default is conservative; a 60-second window is common in production.

```rust
if passforge::challenge::is_expired(&challenge) {
    return Err("challenge expired");
}
```

---

## Origin and RP ID verification

### Why origin verification matters

The `origin` field in `clientDataJSON` is set by the **browser** (not the
authenticator). A malicious page at `https://evil.com` that tricks a user into
running a WebAuthn ceremony will produce a response with `origin: "https://evil.com"`.
If the relying party at `https://bank.com` does not check the origin, that
response could be used to authenticate there.

passforge compares `client_data.origin == expected_origin` as an exact byte
comparison. There is no fuzzy matching, subdomain allowlisting, or wildcards.
The caller must supply the exact origin (scheme + host + port) that should be accepted.

**Example values:**
- `"https://example.com"` — production
- `"http://localhost:8080"` — local development (note: HTTP is allowed for localhost)

### Why RP ID hash verification matters

The `rpIdHash` in authenticator data is computed **by the authenticator** as
`SHA-256(rp_id)`. The authenticator refuses to sign for an RP ID that does not
match the origin the browser reports. This binding is enforced in hardware on
platform authenticators and in firmware on FIDO2 hardware keys.

If the relying party doesn't verify the RP ID hash, an attacker could present an
authenticator data blob from a *different* RP — one they control — with a valid
signature, but where the public key matches a credential registered to the victim
site. This attack is stopped by the RP ID hash check.

passforge verifies `auth_data.rp_id_hash == SHA-256(rp_id)` on every ceremony.

---

## Sign count and replay attack protection

### What the sign count protects against

The sign count is a monotonically increasing integer maintained by the authenticator.
Each authentication increments it by at least 1. The relying party stores the last
seen count and rejects any assertion where the received count is not strictly greater.

This detects **cloned authenticators**: if an attacker extracts a private key from
one device and installs it on another, both devices will produce signatures from the
same counter starting point. When the cloned device's count is lower than the
legitimate device's count (or vice versa), the relying party sees a violation.

**passforge's check (§7.2 step 25):**
```
if received != 0 && received <= stored {
    return Err(SignCountInvalid { stored, received });
}
```

### Limitations of sign count

The sign count mechanism has well-known limitations:

**Synced credentials (passkeys)** — when a private key is synced across devices via
iCloud Keychain or Google Password Manager, all devices share the key but may not
share the counter. Platforms typically set the counter to 0 for synced credentials.
passforge accepts count 0 (spec requirement) but this means clone detection is not
available for synced passkeys.

**Non-monotonic increments** — the spec allows the count to increase by more than 1
per authentication. An attacker who intercepts an assertion and plays it back slightly
later might succeed if the legitimate device hasn't incremented past the replay count.
The protection is probabilistic, not absolute.

**First assertion** — a freshly registered credential with a sign count of 1 (or 0)
provides no clone-detection baseline. Clone detection only becomes meaningful after
at least one successful authentication.

### What to do when sign count is violated

A `SignCountInvalid` error does not definitively prove cloning — it could be a
legitimate app bug or platform sync issue. The recommended response:

1. Log the anomaly with credential ID, stored count, received count, and timestamp.
2. Reject the current authentication attempt.
3. Flag the credential for review or require re-enrollment.
4. Notify the user (optional, to avoid alarming legitimate users of synced keys).

---

## What this library does NOT protect against

### Full attestation chain

passforge only accepts the `"none"` attestation format. This means you cannot verify:
- That the authenticator is genuine hardware (not a software emulator)
- The authenticator model or firmware version
- Whether the device has been compromised at the hardware level

For applications where device provenance matters (banking, government, enterprise),
implement `"packed"` attestation and validate the certificate chain against the
[FIDO Metadata Service (MDS)](https://fidoalliance.org/metadata/).

### Token binding

The `tokenBinding` field in `clientDataJSON` is ignored. Token binding cryptographically
ties a session to a TLS channel, preventing token theft. It is rarely implemented and
has been removed from most browsers, but if you need it, passforge does not provide it.

### Side-channel attacks

passforge uses `ring` for signature verification, which provides constant-time
ECDSA operations. However, passforge itself does not guarantee constant-time
credential lookups, error responses, or JSON parsing. A timing attacker observing
response latency might infer whether a credential ID was found in the database.
Use constant-time credential ID comparison if this is a concern.

### Credential storage security

passforge returns a `Credential` struct containing the public key. The caller must
store it securely. Public keys are not secret, but credential IDs can be used to
determine which users are registered, so treat the credential table as sensitive:

- Index by credential ID (opaque bytes, not user-chosen)
- Protect with row-level access control
- Audit reads of the credential table
- Consider encrypting at rest if your threat model includes database theft

---

## Summary of security responsibilities

| Property | Enforced by | Notes |
|----------|-------------|-------|
| Challenge randomness | passforge (`ring` CSPRNG) | 256 bits entropy |
| Challenge single-use | **Caller** | Must invalidate after use |
| Challenge expiry | Caller via `is_expired()` | Default 5 min |
| Origin binding | passforge | Exact string match |
| RP ID binding | passforge | SHA-256 comparison |
| User presence | passforge | UP flag check |
| Signature validity | passforge (`ring` ECDSA) | Constant-time |
| Sign count monotonicity | passforge | Non-zero counts only |
| HTTPS enforcement | **Caller** / infrastructure | Browsers require it |
| Attestation trust | **Caller** | passforge only validates "none" |
| Credential storage | **Caller** | Treat as sensitive data |
