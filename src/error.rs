//! Error types for the passforge library.
//!
//! Every variant produces a message that aids debugging without leaking
//! security-sensitive material (key bytes, challenge values, etc.).

use thiserror::Error;

/// All errors that can be returned by passforge ceremony verification.
#[derive(Debug, Error)]
pub enum PassforgeError {
    /// The client data JSON could not be decoded or is structurally invalid.
    #[error("invalid client data: {0}")]
    InvalidClientData(String),

    /// The challenge inside the client data does not match the issued challenge.
    ///
    /// This is a security-critical check — a mismatch means the response was
    /// not produced for this ceremony.
    #[error("challenge mismatch: client challenge does not equal the issued challenge")]
    ChallengeMismatch,

    /// The `origin` field in the client data does not match `expected_origin`.
    ///
    /// Prevents a credential from one origin being replayed at another.
    #[error("origin mismatch: client origin does not match expected origin")]
    OriginMismatch,

    /// The RP ID hash in authenticator data does not equal SHA-256(rp_id).
    ///
    /// Ensures the authenticator bound the credential to the correct relying party.
    #[error("RP ID hash mismatch: authenticator data is not bound to this relying party")]
    RpIdHashMismatch,

    /// The User Present (UP) flag is not set in the authenticator data flags byte.
    #[error("user presence flag not set: the authenticator did not signal user presence")]
    UserNotPresent,

    /// The attestation object could not be decoded or is missing required fields.
    #[error("invalid attestation object: {0}")]
    InvalidAttestationObject(String),

    /// The authenticator data bytes are malformed or too short.
    #[error("invalid authenticator data: {0}")]
    InvalidAuthenticatorData(String),

    /// The COSE public key inside the credential data is invalid.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// ECDSA signature verification returned a failure.
    ///
    /// The message was either tampered with or signed by the wrong key.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// The sign count in the assertion is not greater than the stored sign count.
    ///
    /// This indicates a possible authenticator clone or replay attack.
    #[error("sign count invalid: stored={stored}, received={received}")]
    SignCountInvalid { stored: u32, received: u32 },

    /// A CBOR decoding step failed.
    #[error("CBOR decode error: {0}")]
    CborDecodeError(String),

    /// A base64url decoding step failed.
    #[error("base64 decode error: {0}")]
    Base64DecodeError(String),
}

/// Convenience alias so callers write `passforge::Result<T>`.
pub type Result<T> = std::result::Result<T, PassforgeError>;
