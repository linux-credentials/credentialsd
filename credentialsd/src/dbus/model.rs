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

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, RelyingPartyId, WebAuthnIDL, WebAuthnIDLResponse,
};

use crate::model::{GetAssertionResponseInternal, MakeCredentialResponseInternal};

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
pub(super) fn create_credential_request_try_into_ctap2(
    request: &CreateCredentialRequest,
) -> std::result::Result<MakeCredentialRequest, WebAuthnError> {
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

    Ok(make_cred_request)
}

/// Serializes a CTAP2 MakeCredentialResponse to WebAuthn JSON format.
///
/// Uses libwebauthn's `WebAuthnIDLResponse::to_inner_model()` for serialization,
/// then adds transport and authenticator attachment information that is known
/// at the credential service level.
pub(super) fn create_credential_response_try_from_ctap2(
    response: &MakeCredentialResponseInternal,
    request: &MakeCredentialRequest,
) -> std::result::Result<CreatePublicKeyCredentialResponse, String> {
    let mut registration_json = response
        .ctap
        .to_inner_model(request)
        .map_err(|err| format!("Failed to serialize registration response: {err}"))?;

    // TODO(libwebauthn#159): transports and authenticatorAttachment should be
    // populated by libwebauthn once it has access to transport-level information.
    registration_json.response.transports = response.transport.clone();
    registration_json.authenticator_attachment = Some(response.attachment_modality.clone());

    let registration_response_json = serde_json::to_string(&registration_json)
        .map_err(|err| format!("Failed to serialize registration response to JSON: {err}"))?;

    Ok(CreatePublicKeyCredentialResponse {
        registration_response_json,
    })
}

/// Parses a WebAuthn get credential request from D-Bus into a CTAP2 GetAssertionRequest.
///
/// Uses libwebauthn's `WebAuthnIDL::from_json()` for parsing, which handles:
/// - Challenge decoding from base64url
/// - Allowed credentials list with transports
/// - Extension parsing (getCredBlob, largeBlob, prf, hmac-secret)
/// - User verification requirement
pub(super) fn get_credential_request_try_into_ctap2(
    request: &GetCredentialRequest,
) -> std::result::Result<GetAssertionRequest, WebAuthnError> {
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

    Ok(get_assertion_request)
}

/// Serializes a CTAP2 GetAssertionResponse to WebAuthn JSON format.
///
/// Uses libwebauthn's `WebAuthnIDLResponse::to_inner_model()` for serialization,
/// then adds authenticator attachment information that is known at the
/// credential service level.
pub(super) fn get_credential_response_try_from_ctap2(
    response: &GetAssertionResponseInternal,
    request: &GetAssertionRequest,
) -> std::result::Result<GetPublicKeyCredentialResponse, String> {
    let mut authentication_json = response
        .ctap
        .to_inner_model(request)
        .map_err(|err| format!("Failed to serialize authentication response: {err}"))?;

    // TODO(libwebauthn#159): authenticatorAttachment should be populated by
    // libwebauthn once it has access to transport-level information.
    authentication_json.authenticator_attachment = Some(response.attachment_modality.clone());

    let authentication_response_json = serde_json::to_string(&authentication_json)
        .map_err(|err| format!("Failed to serialize authentication response to JSON: {err}"))?;

    Ok(GetPublicKeyCredentialResponse {
        authentication_response_json,
    })
}
