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
use libwebauthn::ops::webauthn::idl::origin::{
    Origin as LibwebauthnOrigin, RequestOrigin as LibwebauthnRequestOrigin,
};
use libwebauthn::ops::webauthn::psl::SystemPublicSuffixList;

use crate::model::{GetAssertionResponseInternal, MakeCredentialResponseInternal};
use crate::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, NavigationContext, Origin, WebAuthnIDL,
    WebAuthnIDLResponse,
};

impl TryFrom<&Origin> for LibwebauthnOrigin {
    type Error = WebAuthnError;

    fn try_from(value: &Origin) -> Result<Self, Self::Error> {
        match value {
            Origin::Https { .. } => value.to_string().parse().map_err(|err| {
                tracing::info!("Cannot convert origin to libwebauthn Origin: {err}");
                WebAuthnError::SecurityError
            }),
            // TODO: AppId support is being removed.
            Origin::AppId(_) => unimplemented!("AppId origins are not supported"),
        }
    }
}

impl TryFrom<&NavigationContext> for LibwebauthnRequestOrigin {
    type Error = WebAuthnError;

    fn try_from(value: &NavigationContext) -> Result<Self, Self::Error> {
        match value {
            NavigationContext::SameOrigin(o) => Ok(LibwebauthnRequestOrigin::new(o.try_into()?)),
            NavigationContext::CrossOrigin((o, top)) => Ok(
                LibwebauthnRequestOrigin::new_cross_origin(o.try_into()?, top.try_into()?),
            ),
        }
    }
}

fn load_system_psl() -> Result<SystemPublicSuffixList, WebAuthnError> {
    SystemPublicSuffixList::auto().map_err(|err| {
        tracing::error!("Failed to load system Public Suffix List: {err}");
        WebAuthnError::NotAllowedError
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

    let request_origin: LibwebauthnRequestOrigin = request_environment.try_into()?;
    let psl = load_system_psl()?;

    let make_cred_request =
        MakeCredentialRequest::from_json(&request_origin, &psl, &options.request_json).map_err(
            |err| {
                tracing::info!("Failed to parse MakeCredential request JSON: {err}");
                WebAuthnError::TypeError
            },
        )?;

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

    let request_origin: LibwebauthnRequestOrigin = request_environment.try_into()?;
    let psl = load_system_psl()?;

    let get_assertion_request =
        GetAssertionRequest::from_json(&request_origin, &psl, &options.request_json).map_err(
            |err| {
                tracing::info!("Failed to parse GetAssertion request JSON: {err}");
                WebAuthnError::TypeError
            },
        )?;

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
