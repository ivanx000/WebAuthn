//! Core domain types for stored credentials, challenges, and ceremony results.

use std::time::SystemTime;

/// A registered credential persisted on the relying-party side after a successful
/// registration ceremony.
///
/// The caller is responsible for storing this in a durable, server-side store keyed
/// by `id` (the credential ID) and associated with the `user_id`.
#[derive(Debug, Clone)]
pub struct Credential {
    /// Opaque byte string that uniquely identifies this credential.
    /// Produced by the authenticator during registration.
    pub id: Vec<u8>,

    /// The authenticator's public key, in the format signalled during registration.
    pub public_key: PublicKey,

    /// Monotonically increasing counter maintained by the authenticator.
    /// Used to detect cloned authenticators (replay attack protection).
    pub sign_count: u32,

    /// Application-defined identifier for the user this credential belongs to.
    pub user_id: Vec<u8>,

    /// Relying party ID (e.g. `"example.com"`).
    /// Stored so that authentication can verify the credential is for this RP.
    pub rp_id: String,

    /// When this credential was first registered.
    pub created_at: SystemTime,
}

/// The public key extracted from a COSE key structure during registration.
///
/// ES256 (P-256 ECDSA with SHA-256) is implemented and is by far the most common
/// algorithm used by passkey authenticators. RS256 is listed for completeness but
/// signature verification for it is not yet implemented.
#[derive(Debug, Clone)]
pub enum PublicKey {
    /// P-256 ECDSA public key.
    ///
    /// The inner `Vec<u8>` holds the **uncompressed** EC point in ANSI X9.62 form:
    /// `0x04 || x (32 bytes) || y (32 bytes)` — exactly what `ring` expects.
    ES256(Vec<u8>),

    /// RSA-PKCS1v15 SHA-256 public key. (Stretch goal — not yet verified.)
    RS256(Vec<u8>),
}

impl PublicKey {
    /// Returns the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::ES256(b) | PublicKey::RS256(b) => b,
        }
    }
}

/// A single-use challenge issued by the relying party before a ceremony.
///
/// **Security contract**: each `Challenge` must be used at most once and should
/// expire after a short window (typically 60–300 seconds). The caller is responsible
/// for enforcing both properties; see `challenge::is_expired`.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// 32 cryptographically random bytes.
    pub bytes: Vec<u8>,

    /// When this challenge was generated — used for expiry checks.
    pub created_at: SystemTime,
}

/// Successful outcome of a registration ceremony.
#[derive(Debug)]
pub struct RegistrationResult {
    /// The newly registered credential — store this in your database.
    pub credential: Credential,

    /// What kind of attestation the authenticator provided.
    pub attestation_type: AttestationType,
}

/// Successful outcome of an authentication ceremony.
#[derive(Debug)]
pub struct AuthenticationResult {
    /// The credential ID that was used to authenticate.
    pub credential_id: Vec<u8>,

    /// The sign count returned by the authenticator this ceremony.
    /// Update the stored credential's `sign_count` to this value after a
    /// successful authentication.
    pub new_sign_count: u32,

    /// Whether the authenticator signalled that the user was verified
    /// (biometric check, PIN, etc.) — corresponds to the UV flag.
    pub user_verified: bool,
}

/// The level of attestation the authenticator provided.
#[derive(Debug, PartialEq, Eq)]
pub enum AttestationType {
    /// The authenticator explicitly sent no attestation (`"fmt": "none"`).
    /// The credential is still usable, but the relying party cannot verify
    /// the authenticator model or provenance.
    None,

    /// The attestation was signed by the same key used for authentication
    /// (self-attestation). Proves the credential is fresh but not the device model.
    SelfAttestation,
}
