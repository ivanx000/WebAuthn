//! Integration tests for the full WebAuthn registration + authentication pipeline.
//!
//! These tests simulate both the authenticator (key generation, signing) and the
//! relying party (passforge library) to exercise the complete ceremony flows.
//!
//! All wire-type fields use raw bytes (not base64url), matching the updated API
//! where base64url decoding is the caller's responsibility.

use ciborium::value::Value;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use passforge::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, Challenge, PassforgeError,
    RelyingParty,
};

// ─── Shared constants ─────────────────────────────────────────────────────────

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

// ─── Test fixture ─────────────────────────────────────────────────────────────

struct Fixture {
    rng: SystemRandom,
    key_pair: EcdsaKeyPair,
    cred_id: Vec<u8>,
    public_key_bytes: Vec<u8>, // 65-byte uncompressed point
}

impl Fixture {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        Self {
            rng,
            key_pair,
            cred_id: vec![0xABu8; 16],
            public_key_bytes,
        }
    }

    fn make_registration_response(
        &self,
        challenge: &[u8],
        type_str: &str,
        origin: &str,
        rp_id: &str,
        flags: u8,
        sign_count: u32,
        fmt: &str,
    ) -> AuthenticatorAttestationResponse {
        let client_data_json =
            make_client_data_json_bytes(type_str, challenge, origin);
        let auth_data = make_authenticator_data(
            rp_id,
            flags,
            sign_count,
            Some((&self.cred_id, &self.public_key_bytes)),
        );
        let att_obj = make_attestation_object(&auth_data, fmt);

        AuthenticatorAttestationResponse {
            client_data_json,
            attestation_object: att_obj,
        }
    }

    fn make_auth_response(
        &self,
        challenge: &[u8],
        origin: &str,
        rp_id: &str,
        sign_count: u32,
    ) -> AuthenticatorAssertionResponse {
        let client_data_bytes = make_client_data_json_bytes("webauthn.get", challenge, origin);
        let auth_data = make_authenticator_data(rp_id, 0x01, sign_count, None);

        let client_data_hash = passforge::crypto::sha256(&client_data_bytes);
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&client_data_hash);

        let sig = self.key_pair.sign(&self.rng, &signed_data).unwrap();

        AuthenticatorAssertionResponse {
            client_data_json: client_data_bytes,
            authenticator_data: auth_data,
            signature: sig.as_ref().to_vec(),
            user_handle: None,
        }
    }
}

// ─── Happy-path tests ─────────────────────────────────────────────────────────

#[test]
fn full_registration_and_authentication_flow() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    // Registration
    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41, // UP + AT
        1,
        "none",
    );
    let reg_result = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .expect("registration should succeed");

    assert_eq!(reg_result.credential.sign_count, 1);
    assert_eq!(reg_result.credential.rp_id, RP_ID);
    assert!(matches!(
        reg_result.attestation_type,
        passforge::AttestationType::None
    ));

    // Authentication
    let mut credential = reg_result.credential;
    let auth_challenge = Challenge::new().unwrap();
    let auth_response = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 2);

    let auth_result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("authentication should succeed");

    assert_eq!(auth_result.new_sign_count, 2);
    assert!(!auth_result.user_verified);
    credential.sign_count = auth_result.new_sign_count;
    assert_eq!(credential.sign_count, 2);
}

#[test]
fn authentication_with_uv_flag() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x45, // UP + UV + AT
        0,
        "none",
    );
    let credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let auth_challenge = Challenge::new().unwrap();
    let client_data_bytes =
        make_client_data_json_bytes("webauthn.get", &auth_challenge.bytes, ORIGIN);
    let auth_data = make_authenticator_data(RP_ID, 0x05, 1, None); // UP + UV
    let client_data_hash = passforge::crypto::sha256(&client_data_bytes);
    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(&client_data_hash);
    let sig = fixture.key_pair.sign(&fixture.rng, &signed_data).unwrap();

    let auth_response = AuthenticatorAssertionResponse {
        client_data_json: client_data_bytes,
        authenticator_data: auth_data,
        signature: sig.as_ref().to_vec(),
        user_handle: None,
    };

    let result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .unwrap();
    assert!(result.user_verified);
}

// ─── Error cases — every PassforgeError variant ───────────────────────────────

#[test]
fn rejects_wrong_type_in_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.get", // wrong type
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::InvalidClientData(_)));
}

#[test]
fn rejects_challenge_mismatch_on_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let wrong_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &wrong_challenge.bytes, // response contains wrong challenge
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::ChallengeMismatch));
}

#[test]
fn rejects_origin_mismatch_on_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        "https://evil.com", // wrong origin in clientDataJSON
        RP_ID,
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(
        err,
        PassforgeError::OriginMismatch { expected, got }
        if expected == ORIGIN && got == "https://evil.com"
    ));
}

#[test]
fn rejects_rp_id_hash_mismatch_on_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        "evil.com", // wrong RP ID used to build authenticator data
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::RpIdHashMismatch));
}

#[test]
fn rejects_missing_user_present_flag() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x40, // AT set, UP NOT set
        1,
        "none",
    );
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::UserNotPresent));
}

#[test]
fn rejects_unsupported_attestation_format() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "packed", // not supported
    );
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(
        err,
        PassforgeError::InvalidAttestationObject(_)
    ));
}

#[test]
fn rejects_invalid_client_data_json() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let challenge = Challenge::new().unwrap();
    let response = AuthenticatorAttestationResponse {
        client_data_json: b"not json at all".to_vec(),
        attestation_object: vec![],
    };
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::InvalidClientData(_)));
}

#[test]
fn rejects_invalid_attestation_object_cbor() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();

    let client_data_json = make_client_data_json_bytes("webauthn.create", &challenge.bytes, ORIGIN);
    let _ = fixture;
    let response = AuthenticatorAttestationResponse {
        client_data_json,
        attestation_object: vec![0xFF, 0x00, 0x00], // invalid CBOR
    };
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::CborDecodeError(_)));
}

#[test]
fn rejects_expired_challenge() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    // Create a challenge backdated to the past (well beyond the 5 min TTL).
    let expired_challenge = Challenge {
        bytes: vec![0u8; 32],
        created_at: std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(600))
            .unwrap(),
    };

    let response = fixture.make_registration_response(
        &expired_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(&expired_challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::ChallengeExpired));
}

#[test]
fn rejects_challenge_mismatch_on_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let real_challenge = Challenge::new().unwrap();
    let wrong_challenge = Challenge::new().unwrap();
    let response = fixture.make_auth_response(&wrong_challenge.bytes, ORIGIN, RP_ID, 2);

    let err = rp
        .verify_authentication(&credential, &real_challenge, &response)
        .unwrap_err();
    assert!(matches!(err, PassforgeError::ChallengeMismatch));
}

#[test]
fn rejects_origin_mismatch_on_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = Challenge::new().unwrap();
    let response = fixture.make_auth_response(&challenge.bytes, "https://phishing.com", RP_ID, 2);

    let err = rp
        .verify_authentication(&credential, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, PassforgeError::OriginMismatch { .. }));
}

#[test]
fn rejects_rp_id_hash_mismatch_on_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = Challenge::new().unwrap();
    let response = fixture.make_auth_response(&challenge.bytes, ORIGIN, "evil.com", 2);

    let err = rp
        .verify_authentication(&credential, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, PassforgeError::RpIdHashMismatch));
}

#[test]
fn rejects_signature_verification_failed() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = Challenge::new().unwrap();
    let mut response = fixture.make_auth_response(&challenge.bytes, ORIGIN, RP_ID, 2);

    // Corrupt the signature by flipping a bit.
    response.signature[10] ^= 0xFF;

    let err = rp
        .verify_authentication(&credential, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, PassforgeError::SignatureVerificationFailed));
}

#[test]
fn rejects_replay_attack_same_sign_count() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);

    let ch1 = Challenge::new().unwrap();
    let r1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 2);
    let result = rp.verify_authentication(&credential, &ch1, &r1).unwrap();
    credential.sign_count = result.new_sign_count;

    let ch2 = Challenge::new().unwrap();
    let r2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 2); // same count

    let err = rp
        .verify_authentication(&credential, &ch2, &r2)
        .unwrap_err();
    assert!(matches!(
        err,
        PassforgeError::SignCountInvalid {
            stored: 2,
            received: 2
        }
    ));
}

#[test]
fn rejects_replay_attack_lower_sign_count() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);

    let ch1 = Challenge::new().unwrap();
    let r1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 5);
    credential.sign_count = rp
        .verify_authentication(&credential, &ch1, &r1)
        .unwrap()
        .new_sign_count;

    let ch2 = Challenge::new().unwrap();
    let r2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 3); // lower
    let err = rp
        .verify_authentication(&credential, &ch2, &r2)
        .unwrap_err();
    assert!(matches!(
        err,
        PassforgeError::SignCountInvalid {
            stored: 5,
            received: 3
        }
    ));
}

#[test]
fn accepts_zero_sign_count_passthrough() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        0, // counter-less authenticator
        "none",
    );
    let credential = rp
        .verify_registration(&reg_challenge, &response, &[])
        .unwrap()
        .credential;

    let auth_challenge = Challenge::new().unwrap();
    let auth_response = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 0);
    rp.verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("zero sign count should be accepted");
}

// ─── Convenience helpers ──────────────────────────────────────────────────────

fn register_credential(rp: &RelyingParty, fixture: &Fixture) -> passforge::Credential {
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "none",
    );
    rp.verify_registration(&challenge, &response, b"uid")
        .unwrap()
        .credential
}

fn make_client_data_json_bytes(type_: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let b64 = URL_SAFE_NO_PAD.encode(challenge);
    format!(
        r#"{{"type":"{type_}","challenge":"{b64}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes()
}

fn make_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    cred_data: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let rp_hash = passforge::crypto::sha256(rp_id.as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&rp_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((cred_id, pk)) = cred_data {
        out.extend_from_slice(&[0u8; 16]); // aaguid
        out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        out.extend_from_slice(cred_id);
        out.extend_from_slice(&encode_cose_key(pk));
    }
    out
}

fn encode_cose_key(uncompressed: &[u8]) -> Vec<u8> {
    let x = uncompressed[1..33].to_vec();
    let y = uncompressed[33..65].to_vec();
    let cose = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(x)),
        (Value::Integer((-3i64).into()), Value::Bytes(y)),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&cose, &mut buf).unwrap();
    buf
}

fn make_attestation_object(auth_data: &[u8], fmt: &str) -> Vec<u8> {
    let obj = Value::Map(vec![
        (Value::Text("fmt".to_string()), Value::Text(fmt.to_string())),
        (Value::Text("attStmt".to_string()), Value::Map(vec![])),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&obj, &mut buf).unwrap();
    buf
}
