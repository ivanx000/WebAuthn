//! Authentication ceremony (W3C WebAuthn §7.2).
//!
//! The authentication ceremony is how a user proves possession of a previously
//! registered credential. The relying party's job is to:
//!
//! 1. Verify that the response was produced for *this* challenge and *this* origin.
//! 2. Verify that the authenticator data is bound to *this* RP ID.
//! 3. Verify the ECDSA signature over `authData || SHA-256(clientDataJSON)`.
//! 4. Check the sign count to detect cloned authenticators.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::authenticator_data;
use crate::client_data;
use crate::credential::{AuthenticationResult, Credential, PublicKey};
use crate::crypto::{sha256, verify_es256_signature};
use crate::error::{PassforgeError, Result};
use crate::{AuthenticatorAssertionResponse, Challenge};

/// Verify an authentication response against a stored credential.
///
/// Call this after the client returns an `AuthenticatorAssertionResponse`.
/// If it returns `Ok`, update the stored credential's `sign_count` to
/// `result.new_sign_count` and accept the authentication.
///
/// # Arguments
/// * `stored_credential` — The credential looked up by credential ID from your database.
/// * `expected_origin`   — The exact origin of your app, e.g. `"https://example.com"`.
/// * `challenge`         — The challenge you previously issued for this ceremony.
/// * `response`          — The `AuthenticatorAssertionResponse` from the client.
///
/// # Spec reference
/// W3C WebAuthn §7.2 "Verifying an Authentication Assertion"
pub fn verify(
    stored_credential: &Credential,
    expected_origin: &str,
    challenge: &Challenge,
    response: &AuthenticatorAssertionResponse,
) -> Result<AuthenticationResult> {
    // ── §7.2 step 11 ─────────────────────────────────────────────────────────
    // Parse clientDataJSON: base64url-decode, then parse JSON.
    let (client_data, client_data_json_bytes) = client_data::parse(&response.client_data_json)?;

    // ── §7.2 step 13 ─────────────────────────────────────────────────────────
    // Verify the type is "webauthn.get".
    if client_data.type_ != "webauthn.get" {
        return Err(PassforgeError::InvalidClientData(format!(
            "expected type \"webauthn.get\", got \"{}\"",
            client_data.type_
        )));
    }

    // ── §7.2 step 14 ─────────────────────────────────────────────────────────
    // Verify the challenge matches the one the relying party issued.
    if client_data.challenge != challenge.bytes {
        return Err(PassforgeError::ChallengeMismatch);
    }

    // ── §7.2 step 15 ─────────────────────────────────────────────────────────
    // Verify the origin matches exactly.
    if client_data.origin != expected_origin {
        return Err(PassforgeError::OriginMismatch);
    }

    // ── §7.2 step 17 ─────────────────────────────────────────────────────────
    // Hash clientDataJSON with SHA-256. This is the clientDataHash that was
    // included in the signed payload.
    let client_data_hash = sha256(&client_data_json_bytes);

    // ── §7.2 step 18 ─────────────────────────────────────────────────────────
    // Decode the authenticator data: base64url → raw bytes.
    let auth_data_bytes = URL_SAFE_NO_PAD
        .decode(&response.authenticator_data)
        .map_err(|e| {
            PassforgeError::Base64DecodeError(format!("authenticatorData: {e}"))
        })?;

    // ── §7.2 step 18 (continued) ──────────────────────────────────────────────
    // Parse the authenticator data binary structure.
    let auth_data = authenticator_data::parse(&auth_data_bytes)?;

    // ── §7.2 step 19 ─────────────────────────────────────────────────────────
    // Verify rpIdHash = SHA-256(stored credential's rp_id).
    let expected_rp_id_hash = sha256(stored_credential.rp_id.as_bytes());
    if auth_data.rp_id_hash != expected_rp_id_hash {
        return Err(PassforgeError::RpIdHashMismatch);
    }

    // ── §7.2 step 20 ─────────────────────────────────────────────────────────
    // Verify the User Present (UP) flag.
    if !auth_data.flags.user_present {
        return Err(PassforgeError::UserNotPresent);
    }

    // ── §7.2 step 21 ─────────────────────────────────────────────────────────
    // (UV check is optional in this library — the caller decides whether to require it.)

    // ── §7.2 step 23 ─────────────────────────────────────────────────────────
    // Decode the raw signature bytes.
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&response.signature)
        .map_err(|e| PassforgeError::Base64DecodeError(format!("signature: {e}")))?;

    // ── §7.2 step 24 ─────────────────────────────────────────────────────────
    // Verify the signature over: authData || SHA-256(clientDataJSON).
    //
    // Note on double hashing: ES256 is ECDSA-P256-SHA256, meaning the signing
    // algorithm hashes the message itself. The message to sign is:
    //   authData_bytes || SHA-256(clientDataJSON_bytes)
    // ring hashes *that* message internally, so we do NOT pre-hash it.
    let mut signed_data = auth_data_bytes.clone();
    signed_data.extend_from_slice(&client_data_hash);

    let verified = match &stored_credential.public_key {
        PublicKey::ES256(pk_bytes) => {
            verify_es256_signature(pk_bytes, &signed_data, &signature_bytes)
        }
        PublicKey::RS256(_) => {
            return Err(PassforgeError::InvalidPublicKey(
                "RS256 signature verification is not yet implemented".to_string(),
            ))
        }
    };

    if !verified {
        return Err(PassforgeError::SignatureVerificationFailed);
    }

    // ── §7.2 step 25 ─────────────────────────────────────────────────────────
    // Verify the sign count is strictly greater than the stored value.
    //
    // A sign count of 0 from the authenticator means it doesn't support
    // counting; in that case we accept the assertion but cannot detect clones.
    // A non-zero received count that is <= stored indicates a possible clone.
    let received = auth_data.sign_count;
    let stored = stored_credential.sign_count;

    if received != 0 && received <= stored {
        return Err(PassforgeError::SignCountInvalid {
            stored,
            received,
        });
    }

    Ok(AuthenticationResult {
        credential_id: stored_credential.id.clone(),
        new_sign_count: received,
        user_verified: auth_data.flags.user_verified,
    })
}
