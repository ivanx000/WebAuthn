//! Low-level cryptographic primitives used throughout the ceremony verification code.
//!
//! All cryptographic operations are delegated to [`ring`], which is a carefully
//! audited, FIPS-aligned library. No custom crypto is implemented here.

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, UnparsedPublicKey};
use std::time::SystemTime;

use crate::credential::Challenge;
use crate::error::{PassforgeError, Result};

/// Compute SHA-256 of `data` and return the 32-byte digest.
///
/// Used to hash `clientDataJSON` before signature verification and to compute
/// the RP ID hash for comparison against authenticator data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, data);
    // digest::SHA256 always produces exactly 32 bytes; the unwrap is safe.
    digest
        .as_ref()
        .try_into()
        .expect("SHA-256 digest is always 32 bytes")
}

/// Verify an ES256 (ECDSA P-256 + SHA-256) signature.
///
/// # Arguments
/// * `public_key` — Uncompressed P-256 point: `0x04 || x (32 bytes) || y (32 bytes)`.
/// * `message`    — The raw message that was signed (ring hashes it internally).
/// * `signature`  — DER-encoded ASN.1 ECDSA signature (as produced by authenticators).
///
/// Returns `true` only when the signature is cryptographically valid. Any error
/// from ring (invalid key format, signature parse failure, wrong key) returns `false`.
pub fn verify_es256_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key);
    key.verify(message, signature).is_ok()
}

/// Generate a fresh 32-byte [`Challenge`] using the OS cryptographic RNG.
///
/// 32 bytes = 256 bits of entropy, which is far beyond any brute-force threat.
///
/// # Errors
/// Returns [`PassforgeError::InvalidClientData`] if the system RNG fails (extremely
/// unlikely in practice; would indicate a kernel-level failure).
pub fn generate_challenge() -> Result<Challenge> {
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; 32];
    rng.fill(&mut bytes).map_err(|_| {
        PassforgeError::InvalidClientData(
            "system random number generator failed to produce bytes".to_string(),
        )
    })?;
    Ok(Challenge {
        bytes,
        created_at: SystemTime::now(),
    })
}
