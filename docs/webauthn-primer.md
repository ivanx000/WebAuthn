# WebAuthn Primer

A plain-English explanation of how WebAuthn and Passkeys work.

---

## The problem with passwords

Passwords have three fundamental problems that no amount of policy can fix:

**They can be stolen from the server.** When a site stores your password (even
hashed), a data breach exposes something an attacker can use to gain access. A
credential database dump is worth billions of dollars on underground markets
precisely because people reuse passwords.

**They can be phished.** A convincing fake login page captures your password in
real time and relays it to the real site before you notice anything is wrong.
SMS two-factor codes suffer from the same problem — the attacker simply prompts
for it and uses it immediately.

**They rely on secrets you have to remember.** Humans choose weak passwords,
reuse them across sites, and write them down. Password managers help, but they
add complexity and a new single point of failure.

WebAuthn eliminates all three problems by replacing the secret you type with a
cryptographic operation the authenticator performs automatically.

---

## How public-key cryptography solves it

In public-key cryptography, you generate a **keypair**:

- The **private key** is secret and never leaves its safe place.
- The **public key** is safe to share with anyone.

Two operations are possible:

| Operation | Who can do it | Input | Output |
|-----------|---------------|-------|--------|
| Sign | Private-key holder | Message | Signature |
| Verify | Anyone with public key | Message + Signature | Valid or invalid |

WebAuthn maps these operations to authentication:

| Passwords | WebAuthn |
|-----------|---------|
| Type a secret → server compares to stored hash | Authenticator signs a challenge → server verifies with stored public key |
| Steal DB → crack hashes → passwords | Steal DB → public keys → useless without private key |
| Phish password at evil.com → use at bank.com | Signature is bound to origin; evil.com's challenge cannot authenticate at bank.com |

---

## The registration flow

Registration is how the authenticator creates a new keypair and gives the
relying party (your server) the public key.

```
User          Browser          Authenticator         Relying Party (Server)
 │                │                  │                        │
 │  Click          │                  │                        │
 │ "Register" ──► │                  │                        │
 │                │  POST /register  │                        │
 │                │ ────────────────────────────────────────► │
 │                │                  │   challenge (32 random bytes) │
 │                │ ◄──────────────────────────────────────── │
 │                │                  │                        │
 │                │ navigator.credentials.create()            │
 │                │ ─────────────── ► │                        │
 │  Touch/FaceID  │                  │                        │
 │ ─────────────► │   ┌──────────────────────────────────┐    │
 │                │   │ Authenticator:                   │    │
 │                │   │ 1. Generate P-256 keypair        │    │
 │                │   │ 2. Build authenticatorData       │    │
 │                │   │    (rpIdHash, flags, pubKey)     │    │
 │                │   │ 3. Build clientDataJSON          │    │
 │                │   │    (type, challenge, origin)     │    │
 │                │   └──────────────────────────────────┘    │
 │                │  ◄─────────────  │                        │
 │                │   attestationResponse                      │
 │                │ ────────────────────────────────────────► │
 │                │                  │   Relying Party verifies:
 │                │                  │   ✓ type == "webauthn.create"
 │                │                  │   ✓ challenge matches
 │                │                  │   ✓ origin matches
 │                │                  │   ✓ rpIdHash == SHA256(rp_id)
 │                │                  │   ✓ UP flag set
 │                │                  │   stores Credential {
 │                │                  │     id, public_key, sign_count
 │                │                  │   }
 │                │  200 OK          │                        │
 │                │ ◄──────────────────────────────────────── │
```

After registration, the server stores:
- The **credential ID** (to look up the right public key at auth time)
- The **public key** (to verify signatures)
- The **sign count** (to detect cloned authenticators)

The private key stays on the device, protected by the OS and hardware security.

---

## The authentication flow

Authentication proves that you still have the private key associated with a
previously registered credential.

```
User          Browser          Authenticator         Relying Party (Server)
 │                │                  │                        │
 │  Click          │                  │                        │
 │ "Sign in"  ──► │                  │                        │
 │                │  POST /auth      │                        │
 │                │ ────────────────────────────────────────► │
 │                │                  │   challenge (32 new random bytes) │
 │                │ ◄──────────────────────────────────────── │
 │                │                  │                        │
 │                │ navigator.credentials.get()               │
 │                │ ─────────────── ► │                        │
 │  Touch/FaceID  │                  │                        │
 │ ─────────────► │   ┌──────────────────────────────────┐    │
 │                │   │ Authenticator:                   │    │
 │                │   │ 1. Build clientDataJSON          │    │
 │                │   │    (type, challenge, origin)     │    │
 │                │   │ 2. Build authenticatorData       │    │
 │                │   │    (rpIdHash, flags, counter++)  │    │
 │                │   │ 3. Compute message =             │    │
 │                │   │    authData || SHA256(CDJ)       │    │
 │                │   │ 4. Sign message with private key │    │
 │                │   └──────────────────────────────────┘    │
 │                │  ◄─────────────  │                        │
 │                │   assertionResponse                        │
 │                │ ────────────────────────────────────────► │
 │                │                  │   Relying Party verifies:
 │                │                  │   ✓ type == "webauthn.get"
 │                │                  │   ✓ challenge matches
 │                │                  │   ✓ origin matches
 │                │                  │   ✓ rpIdHash == SHA256(rp_id)
 │                │                  │   ✓ UP flag set
 │                │                  │   ✓ signature valid
 │                │                  │   ✓ sign_count > stored (clone detection)
 │                │                  │   updates stored sign_count
 │                │  200 OK          │                        │
 │                │ ◄──────────────────────────────────────── │
```

The key insight: the signature is bound to both the **challenge** (freshness) and
the **origin** (prevents phishing — a signature made for `evil.com`'s challenge
cannot be presented to `bank.com`).

---

## What the relying party is responsible for

The relying party (server) must:

1. **Issue a fresh challenge** before each ceremony and invalidate it after use.
2. **Store credentials** securely, indexed by credential ID and associated with users.
3. **Enforce origin and RP ID** in every ceremony response.
4. **Update the sign count** after each successful authentication.
5. **Revoke credentials** when sign count anomalies suggest cloning.
6. **Serve over HTTPS** — browsers enforce WebAuthn only in secure contexts.

The relying party does NOT need to worry about:
- Private key security (that's the authenticator's job)
- Phishing resistance (cryptographically enforced by origin binding)
- Password hashing, salting, or policy

---

## Passkeys vs. raw WebAuthn credentials

| Property | Raw WebAuthn | Passkey |
|----------|-------------|---------|
| Keypair lives on | Single device | Synced across devices |
| If device is lost | Credential is gone | Restored from cloud backup |
| Roaming authenticators | Supported | Usually platform authenticators |
| AAGUID | Any | Platform (Apple/Google/Windows) |
| Attestation | Device-specific | Platform attestation |
| User experience | Varies | Consistent (OS-native prompt) |

A passkey is a WebAuthn credential where the private key is backed up and synced
by a platform (e.g. iCloud Keychain). From the protocol's perspective, the ceremony
is identical — the relying party cannot and need not distinguish a passkey from a
device-bound WebAuthn credential.

---

## Key terms

| Term | Meaning |
|------|---------|
| Relying Party (RP) | The website/server that accepts credentials |
| Authenticator | The device or software that holds the private key |
| Attestation | Proof that the authenticator is genuine hardware |
| RP ID | A domain (e.g. `example.com`) that scopes credentials |
| Origin | Full scheme+host+port (e.g. `https://example.com`) |
| clientDataJSON | JSON created by the browser, binding the ceremony to a challenge and origin |
| authenticatorData | Binary blob from the authenticator: RP ID hash + flags + counter (+ key at registration) |
| COSE | CBOR Object Signing and Encryption — the key format WebAuthn uses |
| AAGUID | Authenticator Attestation GUID — identifies the authenticator model |
