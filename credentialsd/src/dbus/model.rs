//! This module contains types and methods used for serializing data to and from D-Bus method calls.
//!
//! Types shared between components within this service belong in credentialsd_common::model.

use credentialsd_common::{
    model::WebAuthnError,
    server::{
        CreateCredentialRequest, CreatePublicKeyCredentialResponse, GetCredentialRequest,
        GetPublicKeyCredentialResponse,
    },
};

use crate::model::{GetAssertionResponseInternal, MakeCredentialResponseInternal};
use crate::webauthn::{
    self, GetAssertionRequest, GetPublicKeyCredentialUnsignedExtensionsResponse,
    MakeCredentialRequest, RelyingPartyId, WebAuthnIDL,
};

/// Parses a WebAuthn create credential request from D-Bus into a CTAP2 MakeCredentialRequest.
///
/// Uses libwebauthn's `WebAuthnIDL::from_json()` for parsing, which handles:
/// - Challenge decoding from base64url
/// - User entity parsing with base64url-encoded user ID
/// - Relying party entity parsing
/// - Extension parsing (credProps, credBlob, largeBlobSupport, prf, etc.)
/// - Authenticator selection criteria (residentKey, userVerification)
/// - Excluded credentials list
/// - Public key credential parameters
///
/// Returns the parsed request and the client data JSON (needed for response serialization).
pub(super) fn create_credential_request_try_into_ctap2(
    request: &CreateCredentialRequest,
) -> std::result::Result<(MakeCredentialRequest, String), WebAuthnError> {
    if request.public_key.is_none() {
        return Err(WebAuthnError::NotSupportedError);
    }
    let options = request.public_key.as_ref().ok_or_else(|| {
        tracing::info!("Invalid request: missing public_key");
        WebAuthnError::TypeError
    })?;

    // Get origin and determine relying party ID
    let (origin, _is_cross_origin) =
        match (request.origin.as_ref(), request.is_same_origin.as_ref()) {
            (Some(origin), Some(is_same_origin)) => (origin.to_string(), !is_same_origin),
            (Some(origin), None) => (origin.to_string(), true),
            (None, _) => {
                tracing::info!("Error reading origin from request.");
                return Err(WebAuthnError::TypeError);
            }
        };

    // Extract rpId from JSON for RelyingPartyId construction
    // libwebauthn validates that the rpId in the request matches this
    let request_value =
        serde_json::from_str::<serde_json::Value>(&options.request_json).map_err(|err| {
            tracing::info!("Invalid request JSON: {err}");
            WebAuthnError::TypeError
        })?;
    let json = request_value.as_object().ok_or_else(|| {
        tracing::info!("Invalid request JSON: not an object");
        WebAuthnError::TypeError
    })?;

    // Get rpId from the request, or derive from origin
    let rp_id_str = json
        .get("rp")
        .and_then(|rp| rp.get("id"))
        .and_then(|id| id.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // Default to effective domain from origin
            origin
                .strip_prefix("https://")
                .map(|rest| rest.split_once('/').map(|(d, _)| d).unwrap_or(rest))
                .unwrap_or(&origin)
                .to_string()
        });

    let rp_id = RelyingPartyId::try_from(rp_id_str.as_str()).map_err(|_| {
        tracing::info!("Invalid relying party ID");
        WebAuthnError::TypeError
    })?;

    // Use libwebauthn's JSON parsing
    let mut make_cred_request = MakeCredentialRequest::from_json(&rp_id, &options.request_json)
        .map_err(|err| {
            tracing::info!("Failed to parse MakeCredential request JSON: {err}");
            WebAuthnError::TypeError
        })?;

    // Set origin and cross_origin from D-Bus request context
    make_cred_request.origin = origin;
    make_cred_request.cross_origin = request.is_same_origin.as_ref().map(|same| !same);

    // Get the client data JSON from the request for response serialization
    let client_data_json = make_cred_request.client_data_json();

    Ok((make_cred_request, client_data_json))
}

/// Serializes a CTAP2 MakeCredentialResponse to WebAuthn JSON format.
pub(super) fn create_credential_response_try_from_ctap2(
    response: &MakeCredentialResponseInternal,
    client_data_json: String,
) -> std::result::Result<CreatePublicKeyCredentialResponse, String> {
    let auth_data = &response.ctap.authenticator_data;
    let attested_credential = auth_data
        .attested_credential
        .as_ref()
        .ok_or_else(|| "missing attested credential data".to_string())?;

    let unsigned_extensions = serde_json::to_string(&response.ctap.unsigned_extensions_output)
        .map_err(|err| format!("failed to serialized unsigned extensions output: {err}"))
        .unwrap();
    let authenticator_data_blob = auth_data
        .to_response_bytes()
        .map_err(|err| format!("failed to serialize authenticator data into bytes: {err}"))?;
    let attestation_statement = (&response.ctap.attestation_statement)
        .try_into()
        .map_err(|_| "Could not serialize attestation statement".to_string())?;
    let attestation_object = webauthn::create_attestation_object(
        &authenticator_data_blob,
        &attestation_statement,
        response.ctap.enterprise_attestation.unwrap_or(false),
    )
    .map_err(|_| "Failed to create attestation object".to_string())?;

    let registration_response_json = webauthn::CreatePublicKeyCredentialResponse::new(
        attested_credential.credential_id.clone(),
        attestation_object,
        client_data_json,
        Some(response.transport.clone()),
        unsigned_extensions,
        response.attachment_modality.clone(),
    )
    .to_json();
    let response = CreatePublicKeyCredentialResponse {
        registration_response_json,
    };
    Ok(response)
}

/// Parses a WebAuthn get credential request from D-Bus into a CTAP2 GetAssertionRequest.
///
/// Uses libwebauthn's `WebAuthnIDL::from_json()` for parsing, which handles:
/// - Challenge decoding from base64url
/// - Allowed credentials list with transports
/// - Extension parsing (getCredBlob, largeBlob, prf, hmac-secret)
/// - User verification requirement
///
/// Returns the parsed request and the client data JSON (needed for response serialization).
pub(super) fn get_credential_request_try_into_ctap2(
    request: &GetCredentialRequest,
) -> std::result::Result<(GetAssertionRequest, String), WebAuthnError> {
    if request.public_key.is_none() {
        return Err(WebAuthnError::NotSupportedError);
    }
    let options = request.public_key.as_ref().ok_or_else(|| {
        tracing::info!("Invalid request: no \"publicKey\" options specified.");
        WebAuthnError::TypeError
    })?;

    // Get origin
    let (origin, _is_cross_origin) =
        match (request.origin.as_ref(), request.is_same_origin.as_ref()) {
            (Some(origin), Some(is_same_origin)) => (origin.to_string(), !is_same_origin),
            (Some(origin), None) => (origin.to_string(), true),
            (None, _) => {
                tracing::info!("Error reading origin from client request.");
                return Err(WebAuthnError::TypeError);
            }
        };

    // Extract rpId from JSON for RelyingPartyId construction
    let request_value =
        serde_json::from_str::<serde_json::Value>(&options.request_json).map_err(|err| {
            tracing::info!("Invalid request JSON: {err}");
            WebAuthnError::TypeError
        })?;
    let json = request_value.as_object().ok_or_else(|| {
        tracing::info!("Invalid request JSON: not an object");
        WebAuthnError::TypeError
    })?;

    // Get rpId from the request, or derive from origin
    let rp_id_str = json
        .get("rpId")
        .and_then(|id| id.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // Default to effective domain from origin
            origin
                .strip_prefix("https://")
                .map(|rest| rest.split_once('/').map(|(d, _)| d).unwrap_or(rest))
                .unwrap_or(&origin)
                .to_string()
        });

    let rp_id = RelyingPartyId::try_from(rp_id_str.as_str()).map_err(|_| {
        tracing::info!("Invalid relying party ID");
        WebAuthnError::TypeError
    })?;

    // Use libwebauthn's JSON parsing
    let mut get_assertion_request = GetAssertionRequest::from_json(&rp_id, &options.request_json)
        .map_err(|err| {
        tracing::info!("Failed to parse GetAssertion request JSON: {err}");
        WebAuthnError::TypeError
    })?;

    // Set origin and cross_origin from D-Bus request context
    get_assertion_request.origin = origin;
    get_assertion_request.cross_origin = request.is_same_origin.as_ref().map(|same| !same);

    // Get the client data JSON from the request for response serialization
    let client_data_json = get_assertion_request.client_data_json();

    Ok((get_assertion_request, client_data_json))
}

/// Serializes a CTAP2 GetAssertionResponse to WebAuthn JSON format.
pub(super) fn get_credential_response_try_from_ctap2(
    response: &GetAssertionResponseInternal,
    client_data_json: String,
) -> std::result::Result<GetPublicKeyCredentialResponse, String> {
    let authenticator_data_blob = response
        .ctap
        .authenticator_data
        .to_response_bytes()
        .map_err(|err| format!("Failed to parse authenticator data: {err}"))?;

    let unsigned_extensions = response
        .ctap
        .unsigned_extensions_output
        .as_ref()
        .map(GetPublicKeyCredentialUnsignedExtensionsResponse::from);

    let authentication_response_json = webauthn::GetPublicKeyCredentialResponse::new(
        client_data_json,
        response
            .ctap
            .credential_id
            .as_ref()
            .map(|c| c.id.clone().into_vec()),
        authenticator_data_blob,
        response.ctap.signature.clone(),
        response.ctap.user.as_ref().map(|u| u.id.clone().into_vec()),
        response.attachment_modality.clone(),
        unsigned_extensions,
    )
    .to_json();

    let response = GetPublicKeyCredentialResponse {
        authentication_response_json,
    };
    Ok(response)
}
