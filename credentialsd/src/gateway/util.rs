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
    GetAssertionRequest, MakeCredentialRequest, NavigationContext, Origin, RelyingPartyId,
    WebAuthnIDL, WebAuthnIDLResponse,
};

/// Reads the rpId from a create-credential request JSON (`rp.id`).
///
/// Used as a fallback when the origin is an AppId and the effective domain
/// cannot be derived from the origin alone.
// TODO(libwebauthn#185)
fn peek_make_credential_rp_id(request_json: &str) -> Result<RelyingPartyId, WebAuthnError> {
    let value = serde_json::from_str::<serde_json::Value>(request_json).map_err(|err| {
        tracing::info!("Invalid request JSON: {err}");
        WebAuthnError::TypeError
    })?;
    let rp_id_str = value
        .get("rp")
        .and_then(|rp| rp.get("id"))
        .and_then(|id| id.as_str())
        .ok_or_else(|| {
            tracing::info!("RP ID required if using app ID as origin");
            WebAuthnError::SecurityError
        })?;
    RelyingPartyId::try_from(rp_id_str).map_err(|_| {
        tracing::info!("Invalid relying party ID");
        WebAuthnError::TypeError
    })
}

/// Reads the rpId from a get-credential request JSON (`rpId`).
///
/// Used as a fallback when the origin is an AppId and the effective domain
/// cannot be derived from the origin alone.
// TODO(libwebauthn#185)
fn peek_get_assertion_rp_id(request_json: &str) -> Result<RelyingPartyId, WebAuthnError> {
    let value = serde_json::from_str::<serde_json::Value>(request_json).map_err(|err| {
        tracing::info!("Invalid request JSON: {err}");
        WebAuthnError::TypeError
    })?;
    let rp_id_str = value
        .get("rpId")
        .and_then(|id| id.as_str())
        .ok_or_else(|| {
            tracing::info!("RP ID required if using app ID as origin");
            WebAuthnError::SecurityError
        })?;
    RelyingPartyId::try_from(rp_id_str).map_err(|_| {
        tracing::info!("Invalid relying party ID");
        WebAuthnError::TypeError
    })
}

/// Parses a WebAuthn create credential request from D-Bus into a CTAP2 MakeCredentialRequest.
///
/// Uses libwebauthn's `WebAuthnIDL::from_json()` for parsing. The relying party ID is derived
/// from the request's origin; libwebauthn validates that any rpId in the JSON matches it.
pub(super) fn create_credential_request_try_into_ctap2(
    request: &CreateCredentialRequest,
    request_environment: &NavigationContext,
) -> std::result::Result<MakeCredentialRequest, WebAuthnError> {
    let options = request.public_key.as_ref().ok_or_else(|| {
        tracing::info!("Invalid request: missing public_key");
        WebAuthnError::NotSupportedError
    })?;

    let origin = request_environment.origin();
    let rp_id = match origin {
        Origin::Https { .. } => RelyingPartyId::try_from(origin).map_err(|err| {
            tracing::info!("Cannot derive relying party ID from origin: {err}");
            WebAuthnError::SecurityError
        })?,
        Origin::AppId(_) => peek_make_credential_rp_id(&options.request_json)?,
    };

    let mut make_cred_request = MakeCredentialRequest::from_json(&rp_id, &options.request_json)
        .map_err(|err| {
            tracing::info!("Failed to parse MakeCredential request JSON: {err}");
            WebAuthnError::TypeError
        })?;

    // TODO(libwebauthn#185)
    make_cred_request.origin = origin.to_string();
    make_cred_request.cross_origin = Some(matches!(
        request_environment,
        NavigationContext::CrossOrigin(_)
    ));

    Ok(make_cred_request)
}

/// Serializes a CTAP2 MakeCredentialResponse to WebAuthn JSON format.
///
/// Uses libwebauthn's `WebAuthnIDLResponse::to_idl_model()` for serialization, then adds
/// transport and authenticator-attachment information that is known at the credential
/// service level.
pub(super) fn create_credential_response_try_from_ctap2(
    response: &MakeCredentialResponseInternal,
    request: &MakeCredentialRequest,
) -> std::result::Result<CreatePublicKeyCredentialResponse, String> {
    let mut registration_json = response
        .ctap
        .to_idl_model(request)
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
/// Uses libwebauthn's `WebAuthnIDL::from_json()` for parsing. The relying party ID is derived
/// from the request's origin; libwebauthn validates that any rpId in the JSON matches it.
pub(super) fn get_credential_request_try_into_ctap2(
    request: &GetCredentialRequest,
    request_environment: &NavigationContext,
) -> std::result::Result<GetAssertionRequest, WebAuthnError> {
    let options = request.public_key.as_ref().ok_or_else(|| {
        tracing::info!("Invalid request: no \"publicKey\" options specified.");
        WebAuthnError::NotSupportedError
    })?;

    let origin = request_environment.origin();
    let rp_id = match origin {
        Origin::Https { .. } => RelyingPartyId::try_from(origin).map_err(|err| {
            tracing::info!("Cannot derive relying party ID from origin: {err}");
            WebAuthnError::SecurityError
        })?,
        Origin::AppId(_) => peek_get_assertion_rp_id(&options.request_json)?,
    };

    let mut get_assertion_request = GetAssertionRequest::from_json(&rp_id, &options.request_json)
        .map_err(|err| {
        tracing::info!("Failed to parse GetAssertion request JSON: {err}");
        WebAuthnError::TypeError
    })?;

    // TODO(libwebauthn#185)
    get_assertion_request.origin = origin.to_string();
    get_assertion_request.cross_origin = Some(matches!(
        request_environment,
        NavigationContext::CrossOrigin(_)
    ));

    Ok(get_assertion_request)
}

/// Serializes a CTAP2 GetAssertionResponse to WebAuthn JSON format.
///
/// Uses libwebauthn's `WebAuthnIDLResponse::to_idl_model()` for serialization, then adds
/// authenticator-attachment information that is known at the credential service level.
pub(super) fn get_credential_response_try_from_ctap2(
    response: &GetAssertionResponseInternal,
    request: &GetAssertionRequest,
) -> std::result::Result<GetPublicKeyCredentialResponse, String> {
    let mut authentication_json = response
        .ctap
        .to_idl_model(request)
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
