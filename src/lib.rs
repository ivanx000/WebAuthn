//! # passforge — WebAuthn / Passkey relying-party library
//!
//! passforge implements the server-side (relying party) logic for the two core
//! WebAuthn ceremonies:
//!
//! - **Registration** — the authenticator generates a keypair and the relying party
//!   verifies and stores the public key.
//! - **Authentication** — the authenticator signs a challenge with the private key
//!   and the relying party verifies the signature.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use passforge::{RelyingParty, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse};
//! use passforge::generate_challenge;
//!
//! // 1. Issue a registration challenge
//! let rp = RelyingParty::new();
//! let challenge = generate_challenge().unwrap();
//!
//! // 2. Send challenge to the browser; get back the attestation response
//! # let response = AuthenticatorAttestationResponse {
//! #     client_data_json: String::new(),
//! #     attestation_object: String::new(),
//! # };
//! let result = rp.verify_registration(
//!     "example.com",
//!     "https://example.com",
//!     &challenge,
//!     &response,
//!     b"user-id-42".to_vec(),
//! ).unwrap();
//!
//! // 3. Store result.credential in your database
//! let stored = result.credential;
//!
//! // 4. Later: authenticate
//! let auth_challenge = generate_challenge().unwrap();
//! # let auth_response = AuthenticatorAssertionResponse {
//! #     client_data_json: String::new(),
//! #     authenticator_data: String::new(),
//! #     signature: String::new(),
//! #     user_handle: None,
//! # };
//! let auth_result = rp.verify_authentication(
//!     &stored,
//!     "https://example.com",
//!     &auth_challenge,
//!     &auth_response,
//! ).unwrap();
//! ```
//!
//! ## Spec references
//!
//! - [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
//! - [FIDO CTAP2](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/)
//! - [RFC 8152 — COSE](https://www.rfc-editor.org/rfc/rfc8152)

// Internal modules
pub mod attestation;
pub mod authenticator_data;
pub mod challenge;
pub mod client_data;
pub mod credential;
pub mod crypto;
pub mod error;

mod authentication;
mod registration;

// ─── Public re-exports ────────────────────────────────────────────────────────

pub use challenge::{is_expired, is_expired_with_max_age, CHALLENGE_MAX_AGE_SECS};
pub use credential::{
    AttestationType, AuthenticationResult, Challenge, Credential, PublicKey, RegistrationResult,
};
pub use crypto::generate_challenge;
pub use error::{PassforgeError, Result};

// ─── Wire-format input types ──────────────────────────────────────────────────

/// The browser's response after a `navigator.credentials.create()` call.
///
/// All fields are base64url-encoded, exactly as the browser delivers them.
#[derive(Debug, Clone)]
pub struct AuthenticatorAttestationResponse {
    /// Base64url-encoded JSON: the client data (type, challenge, origin).
    pub client_data_json: String,

    /// Base64url-encoded CBOR: the attestation object (format, statement, authData).
    pub attestation_object: String,
}

/// The browser's response after a `navigator.credentials.get()` call.
///
/// All fields are base64url-encoded, exactly as the browser delivers them.
#[derive(Debug, Clone)]
pub struct AuthenticatorAssertionResponse {
    /// Base64url-encoded JSON: the client data (type, challenge, origin).
    pub client_data_json: String,

    /// Base64url-encoded raw bytes: authenticator data (rpIdHash, flags, counter).
    pub authenticator_data: String,

    /// Base64url-encoded DER-encoded ECDSA signature.
    pub signature: String,

    /// Base64url-encoded user handle (optional — some authenticators omit it).
    pub user_handle: Option<String>,
}

// ─── RelyingParty ─────────────────────────────────────────────────────────────

/// The main entry point for ceremony verification.
///
/// `RelyingParty` is a stateless struct — it carries no credential storage. The
/// caller is responsible for persisting `Credential` objects returned from
/// `verify_registration` and for looking up credentials by ID before calling
/// `verify_authentication`.
#[derive(Debug, Default)]
pub struct RelyingParty;

impl RelyingParty {
    /// Create a new `RelyingParty` instance.
    pub fn new() -> Self {
        Self
    }

    /// Verify a registration ceremony response.
    ///
    /// On success, persist `result.credential` in your database and return a
    /// success response to the browser.
    ///
    /// # Arguments
    /// * `rp_id`           — Relying party identifier, e.g. `"example.com"`.
    /// * `expected_origin` — Full origin of your web app, e.g. `"https://example.com"`.
    /// * `challenge`       — The challenge you issued for this ceremony.
    /// * `response`        — The attestation response from the browser.
    /// * `user_id`         — Your application's identifier for this user.
    ///
    /// # Errors
    /// Returns a [`PassforgeError`] variant indicating exactly which verification
    /// step failed.
    pub fn verify_registration(
        &self,
        rp_id: &str,
        expected_origin: &str,
        challenge: &Challenge,
        response: &AuthenticatorAttestationResponse,
        user_id: Vec<u8>,
    ) -> Result<RegistrationResult> {
        registration::verify(rp_id, expected_origin, challenge, response, user_id)
    }

    /// Verify an authentication ceremony response.
    ///
    /// On success, update the stored credential's `sign_count` to
    /// `result.new_sign_count`.
    ///
    /// # Arguments
    /// * `stored_credential` — Retrieved from your database by credential ID.
    /// * `expected_origin`   — Full origin of your web app.
    /// * `challenge`         — The challenge you issued for this ceremony.
    /// * `response`          — The assertion response from the browser.
    ///
    /// # Errors
    /// Returns a [`PassforgeError`] variant indicating exactly which verification
    /// step failed, including `SignCountInvalid` for suspected authenticator clones.
    pub fn verify_authentication(
        &self,
        stored_credential: &Credential,
        expected_origin: &str,
        challenge: &Challenge,
        response: &AuthenticatorAssertionResponse,
    ) -> Result<AuthenticationResult> {
        authentication::verify(stored_credential, expected_origin, challenge, response)
    }
}
