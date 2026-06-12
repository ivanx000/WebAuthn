//! Authenticator data parsing.
//!
//! The authenticator data (`authData`) is a binary structure defined in
//! [WebAuthn §6.1](https://www.w3.org/TR/webauthn-3/#authenticator-data).
//! It is produced by the authenticator hardware and carries the RP ID binding,
//! user-presence/verification flags, a sign counter, and (during registration)
//! the new credential's public key.
//!
//! ## Binary layout
//!
//! ```text
//! Offset   Len   Field
//! ──────   ───   ─────────────────────────────────────────────────
//!      0    32   rpIdHash   — SHA-256 of the RP ID
//!     32     1   flags      — bitmask (see AuthenticatorFlags)
//!     33     4   signCount  — big-endian u32
//!     37     *   attestedCredentialData (present iff AT flag is set)
//!              16   aaguid
//!               2   credentialIdLength  (big-endian u16)
//!               *   credentialId
//!               *   credentialPublicKey (COSE_Key in CBOR)
//! ```

use ciborium::value::Value;

use crate::credential::PublicKey;
use crate::error::{PassforgeError, Result};

// ─── Flags bitmask constants ──────────────────────────────────────────────────

/// Bit 0: User Present — the authenticator confirmed physical user presence.
const FLAG_UP: u8 = 0x01;
/// Bit 2: User Verified — biometric / PIN check passed.
const FLAG_UV: u8 = 0x04;
/// Bit 6: Attested Credential Data — `attestedCredentialData` is present.
const FLAG_AT: u8 = 0x40;
/// Bit 7: Extension Data — CBOR extensions follow the credential data.
const FLAG_ED: u8 = 0x80;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Decoded flags byte from authenticator data.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatorFlags {
    /// User Present (UP): the authenticator confirmed physical user presence.
    pub user_present: bool,

    /// User Verified (UV): biometric or PIN check passed.
    pub user_verified: bool,

    /// Attested Credential Data (AT): credential data is included (registration only).
    pub attested_credential_data: bool,

    /// Extension Data (ED): CBOR extension map follows the credential data.
    pub extension_data: bool,
}

/// Credential data embedded in the authenticator data during registration.
#[derive(Debug)]
pub struct AttestedCredentialData {
    /// Authenticator Attestation GUID — identifies the authenticator model.
    /// All-zeros indicates no AAGUID (common for platform authenticators).
    pub aaguid: [u8; 16],

    /// Opaque credential identifier chosen by the authenticator.
    pub credential_id: Vec<u8>,

    /// The new credential's public key in COSE format, converted to our type.
    pub public_key: PublicKey,
}

/// Fully parsed authenticator data structure.
#[derive(Debug)]
pub struct AuthenticatorData {
    /// SHA-256 hash of the RP ID. Verified against `SHA-256(rp_id)` by the caller.
    pub rp_id_hash: [u8; 32],

    /// Decoded flags byte.
    pub flags: AuthenticatorFlags,

    /// Authenticator-maintained signature counter.
    pub sign_count: u32,

    /// Present only during registration (when the AT flag is set).
    pub attested_credential_data: Option<AttestedCredentialData>,
}

// ─── Public parsing function ──────────────────────────────────────────────────

/// Parse the raw authenticator data bytes into an [`AuthenticatorData`].
///
/// # Errors
/// Returns [`PassforgeError::InvalidAuthenticatorData`] if the bytes are too
/// short or structurally malformed.
/// Returns [`PassforgeError::InvalidPublicKey`] or [`PassforgeError::CborDecodeError`]
/// if the embedded COSE key cannot be decoded.
pub fn parse(data: &[u8]) -> Result<AuthenticatorData> {
    // Minimum: 32 (rpIdHash) + 1 (flags) + 4 (signCount) = 37 bytes
    if data.len() < 37 {
        return Err(PassforgeError::InvalidAuthenticatorData(format!(
            "too short: {} bytes (need at least 37)",
            data.len()
        )));
    }

    // §6.1 step 1: Parse rpIdHash (32 bytes)
    let rp_id_hash: [u8; 32] = data[0..32]
        .try_into()
        .expect("slice of exactly 32 bytes always converts");

    // §6.1 step 2: Parse flags byte
    let flags_byte = data[32];
    let flags = AuthenticatorFlags {
        user_present: flags_byte & FLAG_UP != 0,
        user_verified: flags_byte & FLAG_UV != 0,
        attested_credential_data: flags_byte & FLAG_AT != 0,
        extension_data: flags_byte & FLAG_ED != 0,
    };

    // §6.1 step 3: Parse sign count (big-endian u32)
    let sign_count = u32::from_be_bytes(
        data[33..37]
            .try_into()
            .expect("slice of exactly 4 bytes always converts"),
    );

    // §6.1 step 4: Conditionally parse attested credential data
    let attested_credential_data = if flags.attested_credential_data {
        Some(parse_attested_credential_data(&data[37..])?)
    } else {
        None
    };

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested_credential_data,
    })
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Parse the attested credential data that follows byte 37 in authenticator data.
fn parse_attested_credential_data(data: &[u8]) -> Result<AttestedCredentialData> {
    // Minimum: 16 (aaguid) + 2 (credentialIdLength) = 18 bytes before credential
    if data.len() < 18 {
        return Err(PassforgeError::InvalidAuthenticatorData(
            "attested credential data too short (need at least 18 bytes after flags/counter)"
                .to_string(),
        ));
    }

    let mut offset = 0;

    // aaguid: 16 bytes
    let aaguid: [u8; 16] = data[offset..offset + 16]
        .try_into()
        .expect("slice of exactly 16 bytes always converts");
    offset += 16;

    // credentialIdLength: big-endian u16
    let cred_id_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if data.len() < offset + cred_id_len {
        return Err(PassforgeError::InvalidAuthenticatorData(format!(
            "credential ID length ({cred_id_len}) exceeds remaining data"
        )));
    }

    // credentialId: cred_id_len bytes
    let credential_id = data[offset..offset + cred_id_len].to_vec();
    offset += cred_id_len;

    // credentialPublicKey: remaining bytes are a COSE_Key encoded in CBOR.
    // ciborium::from_reader reads exactly one CBOR item; any trailing bytes
    // (extension data) are not consumed, which is the correct behaviour.
    let cose_bytes = &data[offset..];
    let public_key = parse_cose_key(cose_bytes)?;

    Ok(AttestedCredentialData {
        aaguid,
        credential_id,
        public_key,
    })
}

/// Decode a COSE_Key from `data` and return a typed [`PublicKey`].
///
/// Only EC2 / ES256 (algorithm -7, curve P-256) is currently supported.
/// The extracted x and y coordinates are re-encoded as an uncompressed P-256 point
/// (`0x04 || x || y`) because that is the format `ring` requires.
fn parse_cose_key(data: &[u8]) -> Result<PublicKey> {
    // Decode the outermost CBOR item — must be a map.
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| PassforgeError::CborDecodeError(format!("COSE key: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(PassforgeError::InvalidPublicKey(
                "COSE key must be a CBOR map".to_string(),
            ))
        }
    };

    // Helper: find a value by its integer map key. Returns None for non-integer keys.
    let get_int_key = |key: i128| -> Option<&Value> {
        map.iter().find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                if i128::from(*i) == key {
                    return Some(v);
                }
            }
            None
        })
    };

    // COSE map key 1 = kty (key type). kty = 2 means EC2 (elliptic curve).
    let kty = get_int_key(1)
        .and_then(int_to_i128)
        .ok_or_else(|| PassforgeError::InvalidPublicKey("missing or non-integer kty".to_string()))?;

    // COSE map key 3 = alg (algorithm). alg = -7 means ES256.
    let alg = get_int_key(3)
        .and_then(int_to_i128)
        .ok_or_else(|| PassforgeError::InvalidPublicKey("missing or non-integer alg".to_string()))?;

    match (kty, alg) {
        (2, -7) => {
            // EC2 / ES256: extract x (-2) and y (-3) coordinates
            let x = get_int_key(-2)
                .and_then(bytes_val)
                .ok_or_else(|| PassforgeError::InvalidPublicKey("missing x coordinate".to_string()))?;
            let y = get_int_key(-3)
                .and_then(bytes_val)
                .ok_or_else(|| PassforgeError::InvalidPublicKey("missing y coordinate".to_string()))?;

            if x.len() != 32 || y.len() != 32 {
                return Err(PassforgeError::InvalidPublicKey(format!(
                    "P-256 coordinates must be 32 bytes each; got x={}, y={}",
                    x.len(),
                    y.len()
                )));
            }

            // Uncompressed point format: 0x04 || x (32 bytes) || y (32 bytes)
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            Ok(PublicKey::ES256(point))
        }
        _ => Err(PassforgeError::InvalidPublicKey(format!(
            "unsupported key type or algorithm: kty={kty}, alg={alg}"
        ))),
    }
}

/// Extract the i128 value from a `Value::Integer`, returning `None` for other variants.
fn int_to_i128(v: &Value) -> Option<i128> {
    if let Value::Integer(i) = v {
        Some(i128::from(*i))
    } else {
        None
    }
}

/// Extract the byte slice from a `Value::Bytes`, returning `None` for other variants.
fn bytes_val(v: &Value) -> Option<&Vec<u8>> {
    if let Value::Bytes(b) = v {
        Some(b)
    } else {
        None
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal authenticator data buffer for testing.
    /// `flags` is the raw flags byte; `include_cred_data` controls the AT bit.
    pub fn make_auth_data(
        rp_id_hash: &[u8; 32],
        flags: u8,
        sign_count: u32,
        cred_data: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(rp_id_hash);
        out.push(flags);
        out.extend_from_slice(&sign_count.to_be_bytes());
        if let Some(cd) = cred_data {
            out.extend_from_slice(cd);
        }
        out
    }

    #[test]
    fn rejects_too_short() {
        let result = parse(&[0u8; 10]);
        assert!(matches!(
            result,
            Err(PassforgeError::InvalidAuthenticatorData(_))
        ));
    }

    #[test]
    fn parses_minimal_auth_data() {
        let rp_hash = [0xAB; 32];
        let data = make_auth_data(&rp_hash, FLAG_UP, 42, None);
        let parsed = parse(&data).unwrap();

        assert_eq!(parsed.rp_id_hash, rp_hash);
        assert!(parsed.flags.user_present);
        assert!(!parsed.flags.user_verified);
        assert_eq!(parsed.sign_count, 42);
        assert!(parsed.attested_credential_data.is_none());
    }

    #[test]
    fn parses_up_and_uv_flags() {
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_UV, 0, None);
        let parsed = parse(&data).unwrap();
        assert!(parsed.flags.user_present);
        assert!(parsed.flags.user_verified);
    }

    #[test]
    fn parses_flags_all_clear() {
        let data = make_auth_data(&[0u8; 32], 0x00, 0, None);
        let parsed = parse(&data).unwrap();
        assert!(!parsed.flags.user_present);
        assert!(!parsed.flags.user_verified);
        assert!(!parsed.flags.attested_credential_data);
    }
}
