//! Registration ceremony (W3C WebAuthn §7.1).
//!
//! The registration ceremony is how a user's authenticator creates a new credential
//! and proves it to the relying party. The relying party's job is to:
//!
//! 1. Verify that the response was produced for *this* challenge and *this* origin.
//! 2. Verify that the authenticator data is bound to *this* RP ID.
//! 3. Extract and store the public key for future authentication.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::value::Value;
use std::time::SystemTime;

use crate::attestation;
use crate::authenticator_data;
use crate::client_data;
use crate::credential::{Credential, RegistrationResult};
use crate::crypto::sha256;
use crate::error::{PassforgeError, Result};
use crate::{AuthenticatorAttestationResponse, Challenge};

/// Verify a registration response and return the new [`Credential`] to store.
///
/// Call this after the client returns an `AuthenticatorAttestationResponse`.
/// If it returns `Ok`, persist the `credential` in the result. If it returns
/// `Err`, the registration must be rejected.
///
/// # Arguments
/// * `rp_id`            — Your relying party ID, e.g. `"example.com"`.
/// * `expected_origin`  — The exact origin of your app, e.g. `"https://example.com"`.
/// * `challenge`        — The challenge you previously issued for this ceremony.
/// * `response`         — The `AuthenticatorAttestationResponse` from the client.
/// * `user_id`          — Application-level user identifier to store in the credential.
///
/// # Spec reference
/// W3C WebAuthn §7.1 "Registering a New Credential"
pub fn verify(
    rp_id: &str,
    expected_origin: &str,
    challenge: &Challenge,
    response: &AuthenticatorAttestationResponse,
    user_id: Vec<u8>,
) -> Result<RegistrationResult> {
    // ── §7.1 step 5 ──────────────────────────────────────────────────────────
    // Parse clientDataJSON: base64url-decode, then parse JSON.
    let (client_data, client_data_json_bytes) = client_data::parse(&response.client_data_json)?;

    // ── §7.1 step 7 ──────────────────────────────────────────────────────────
    // Verify the type is "webauthn.create".
    if client_data.type_ != "webauthn.create" {
        return Err(PassforgeError::InvalidClientData(format!(
            "expected type \"webauthn.create\", got \"{}\"",
            client_data.type_
        )));
    }

    // ── §7.1 step 8 ──────────────────────────────────────────────────────────
    // Verify the challenge: decode the challenge from client data and compare
    // it byte-for-byte with the challenge the relying party issued.
    if client_data.challenge != challenge.bytes {
        return Err(PassforgeError::ChallengeMismatch);
    }

    // ── §7.1 step 9 ──────────────────────────────────────────────────────────
    // Verify the origin matches exactly.
    if client_data.origin != expected_origin {
        return Err(PassforgeError::OriginMismatch);
    }

    // ── §7.1 step 11 ─────────────────────────────────────────────────────────
    // Hash clientDataJSON with SHA-256. This becomes the clientDataHash that
    // is included in the signed data during authentication.
    let client_data_hash = sha256(&client_data_json_bytes);

    // ── §7.1 step 12 ─────────────────────────────────────────────────────────
    // Decode the attestation object: base64url → CBOR.
    let att_obj_bytes = URL_SAFE_NO_PAD
        .decode(&response.attestation_object)
        .map_err(|e| PassforgeError::Base64DecodeError(format!("attestationObject: {e}")))?;

    // ── §7.1 step 13 ─────────────────────────────────────────────────────────
    // Parse the CBOR attestation object, extracting fmt and authData.
    let (fmt, auth_data_bytes) = parse_attestation_object(&att_obj_bytes)?;

    // ── §7.1 step 14 ─────────────────────────────────────────────────────────
    // Parse the raw authenticator data bytes.
    let auth_data = authenticator_data::parse(&auth_data_bytes)?;

    // ── §7.1 step 15 ─────────────────────────────────────────────────────────
    // Verify rpIdHash = SHA-256(rp_id). This binds the credential to this RP.
    let expected_rp_id_hash = sha256(rp_id.as_bytes());
    if auth_data.rp_id_hash != expected_rp_id_hash {
        return Err(PassforgeError::RpIdHashMismatch);
    }

    // ── §7.1 step 16 ─────────────────────────────────────────────────────────
    // Verify the User Present (UP) flag. A registration without UP is invalid.
    if !auth_data.flags.user_present {
        return Err(PassforgeError::UserNotPresent);
    }

    // ── §7.1 step 21 ─────────────────────────────────────────────────────────
    // Extract the attested credential data (public key, credential ID).
    // This must be present during registration (AT flag must be set).
    let cred_data = auth_data.attested_credential_data.ok_or_else(|| {
        PassforgeError::InvalidAuthenticatorData(
            "attested credential data (AT flag) is required for registration".to_string(),
        )
    })?;

    // ── §7.1 step 22 ─────────────────────────────────────────────────────────
    // Verify the attestation statement.
    let attestation_type = attestation::verify(&fmt, &auth_data_bytes, &client_data_hash)?;

    // ── §7.1 step 25 ─────────────────────────────────────────────────────────
    // Assemble and return the credential. The caller must persist this.
    let credential = Credential {
        id: cred_data.credential_id,
        public_key: cred_data.public_key,
        sign_count: auth_data.sign_count,
        user_id,
        rp_id: rp_id.to_string(),
        created_at: SystemTime::now(),
    };

    Ok(RegistrationResult {
        credential,
        attestation_type,
    })
}

/// Decode the CBOR attestation object and return `(fmt, authData bytes)`.
///
/// The attestation object is a CBOR map with at least these keys:
/// - `"fmt"` (text): the attestation format
/// - `"attStmt"` (map): the attestation statement (verified separately)
/// - `"authData"` (bytes): the raw authenticator data
fn parse_attestation_object(data: &[u8]) -> Result<(String, Vec<u8>)> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| PassforgeError::CborDecodeError(format!("attestation object: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(PassforgeError::InvalidAttestationObject(
                "attestation object must be a CBOR map".to_string(),
            ))
        }
    };

    let mut fmt: Option<String> = None;
    let mut auth_data: Option<Vec<u8>> = None;

    for (k, v) in map {
        match k {
            Value::Text(ref key) if key == "fmt" => {
                if let Value::Text(s) = v {
                    fmt = Some(s);
                }
            }
            Value::Text(ref key) if key == "authData" => {
                if let Value::Bytes(b) = v {
                    auth_data = Some(b);
                }
            }
            // "attStmt" is intentionally ignored here; attestation::verify handles it.
            _ => {}
        }
    }

    let fmt = fmt.ok_or_else(|| {
        PassforgeError::InvalidAttestationObject("missing \"fmt\" field".to_string())
    })?;
    let auth_data = auth_data.ok_or_else(|| {
        PassforgeError::InvalidAttestationObject("missing \"authData\" field".to_string())
    })?;

    Ok((fmt, auth_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_attestation_object_cbor() {
        // 0xFF is a CBOR "break" code, which is invalid at the start of a data item.
        let bad_bytes = &[0xFF, 0x00, 0x00];
        let result = parse_attestation_object(bad_bytes);
        assert!(matches!(result, Err(PassforgeError::CborDecodeError(_))));
    }

    #[test]
    fn rejects_attestation_object_that_is_not_a_map() {
        // Valid CBOR (integer 0) but not a map — should produce InvalidAttestationObject.
        let integer_cbor = &[0x00u8]; // CBOR integer 0
        let result = parse_attestation_object(integer_cbor);
        assert!(matches!(
            result,
            Err(PassforgeError::InvalidAttestationObject(_))
        ));
    }

    #[test]
    fn rejects_attestation_object_missing_fmt() {
        // Valid CBOR map but missing the "fmt" key
        let mut buf = Vec::new();
        let v = Value::Map(vec![(
            Value::Text("authData".to_string()),
            Value::Bytes(vec![0u8; 37]),
        )]);
        ciborium::into_writer(&v, &mut buf).unwrap();
        let result = parse_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(PassforgeError::InvalidAttestationObject(_))
        ));
    }

    #[test]
    fn rejects_attestation_object_missing_auth_data() {
        let mut buf = Vec::new();
        let v = Value::Map(vec![(
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        )]);
        ciborium::into_writer(&v, &mut buf).unwrap();
        let result = parse_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(PassforgeError::InvalidAttestationObject(_))
        ));
    }
}
