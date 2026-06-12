//! Parsing and validation of `clientDataJSON`.
//!
//! `clientDataJSON` is a JSON object created by the browser (or simulated
//! authenticator) that binds a ceremony to a specific type, challenge, and origin.
//! It is base64url-encoded on the wire.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;

use crate::error::{PassforgeError, Result};

/// The JSON fields we care about in `clientDataJSON`.
///
/// Additional fields (e.g. `crossOrigin`, `tokenBinding`) are ignored — the spec
/// allows unknown fields and we don't need them for basic verification.
#[derive(Debug, Deserialize)]
struct RawClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
}

/// Decoded and validated client data.
#[derive(Debug)]
pub struct ClientData {
    /// The ceremony type string — `"webauthn.create"` or `"webauthn.get"`.
    pub type_: String,

    /// The raw challenge bytes (base64url-decoded from the JSON `challenge` field).
    pub challenge: Vec<u8>,

    /// The origin the client reports (e.g. `"https://example.com"`).
    pub origin: String,
}

/// Decode base64url `encoded` and parse it as `clientDataJSON`.
///
/// Does **not** verify the type, challenge, or origin — the caller performs
/// those checks as part of the ceremony flow so that error messages are precise.
pub fn parse(encoded: &str) -> Result<(ClientData, Vec<u8>)> {
    // Decode the base64url wrapper to get the raw UTF-8 JSON bytes.
    let json_bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| PassforgeError::Base64DecodeError(format!("clientDataJSON: {e}")))?;

    // Parse JSON. serde_json accepts any valid UTF-8 JSON.
    let raw: RawClientData = serde_json::from_slice(&json_bytes)
        .map_err(|e| PassforgeError::InvalidClientData(format!("JSON parse failed: {e}")))?;

    // Decode the base64url-encoded challenge field into raw bytes.
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&raw.challenge)
        .map_err(|e| PassforgeError::Base64DecodeError(format!("challenge field: {e}")))?;

    let data = ClientData {
        type_: raw.type_,
        challenge: challenge_bytes,
        origin: raw.origin,
    };

    // Return both the parsed struct and the raw JSON bytes.
    // The raw bytes are needed to compute clientDataHash = SHA-256(clientDataJSON).
    Ok((data, json_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    fn make_encoded(type_: &str, challenge_b64: &str, origin: &str) -> String {
        let json = format!(
            r#"{{"type":"{type_}","challenge":"{challenge_b64}","origin":"{origin}"}}"#
        );
        URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    #[test]
    fn parses_valid_create() {
        let challenge_bytes = vec![1u8; 32];
        let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let encoded = make_encoded("webauthn.create", &challenge_b64, "https://example.com");

        let (data, raw) = parse(&encoded).unwrap();
        assert_eq!(data.type_, "webauthn.create");
        assert_eq!(data.challenge, challenge_bytes);
        assert_eq!(data.origin, "https://example.com");
        assert!(!raw.is_empty());
    }

    #[test]
    fn parses_valid_get() {
        let challenge_bytes = vec![2u8; 32];
        let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let encoded = make_encoded("webauthn.get", &challenge_b64, "https://example.com");

        let (data, _) = parse(&encoded).unwrap();
        assert_eq!(data.type_, "webauthn.get");
    }

    #[test]
    fn rejects_invalid_base64() {
        let result = parse("!!!not-base64!!!");
        assert!(matches!(result, Err(PassforgeError::Base64DecodeError(_))));
    }

    #[test]
    fn rejects_invalid_json() {
        let not_json = URL_SAFE_NO_PAD.encode(b"not json at all");
        let result = parse(&not_json);
        assert!(matches!(result, Err(PassforgeError::InvalidClientData(_))));
    }

    #[test]
    fn rejects_bad_challenge_encoding() {
        // challenge field contains invalid base64
        let json = r#"{"type":"webauthn.create","challenge":"!!!","origin":"https://x.com"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let result = parse(&encoded);
        assert!(matches!(result, Err(PassforgeError::Base64DecodeError(_))));
    }
}
