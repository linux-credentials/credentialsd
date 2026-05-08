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
    MakeCredentialRequest, NavigationContext, Origin, RelyingPartyId, WebAuthnIDL,
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
) -> std::result::Result<(MakeCredentialRequest, String), WebAuthnError> {
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
/// Uses libwebauthn's `WebAuthnIDL::from_json()` for parsing. The relying party ID is derived
/// from the request's origin; libwebauthn validates that any rpId in the JSON matches it.
pub(super) fn get_credential_request_try_into_ctap2(
    request: &GetCredentialRequest,
    request_environment: &NavigationContext,
) -> std::result::Result<(GetAssertionRequest, String), WebAuthnError> {
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
