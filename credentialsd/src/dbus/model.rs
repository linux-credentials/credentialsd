//! This module contains types and methods used for serializing data to and from D-Bus method calls.
//!
//! Types shared between components within this service belong in credentialsd_common::model.

use std::{collections::HashMap, time::Duration};

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use credentialsd_common::{
    model::{
        GetAssertionResponseInternal, MakeCredentialResponseInternal, Operation, WebAuthnError,
    },
    server::{
        CreateCredentialRequest, CreatePublicKeyCredentialResponse, GetCredentialRequest,
        GetPublicKeyCredentialResponse,
    },
};

use crate::{
    cose::CoseKeyAlgorithmIdentifier,
    webauthn::{
        self, CredentialProtectionExtension, Ctap2PublicKeyCredentialDescriptor,
        Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity,
        GetAssertionHmacOrPrfInput, GetAssertionLargeBlobExtension, GetAssertionRequest,
        GetAssertionRequestExtensions, GetPublicKeyCredentialUnsignedExtensionsResponse,
        MakeCredentialHmacOrPrfInput, MakeCredentialRequest, MakeCredentialsRequestExtensions,
        PublicKeyCredentialParameters, ResidentKeyRequirement, UserVerificationRequirement,
    },
};

// Helper functions for translating D-Bus types into internal types
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

    let request_value =
        serde_json::from_str::<serde_json::Value>(&options.request_json).map_err(|err| {
            tracing::info!("Invalid request JSON: {err}");
            WebAuthnError::TypeError
        })?;
    let json = request_value.as_object().ok_or_else(|| {
        tracing::info!("Invalid request JSON: not an object");
        WebAuthnError::TypeError
    })?;
    let challenge = json
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            tracing::info!("JSON missing `challenge` field.");
            WebAuthnError::TypeError
        })?
        .to_owned();
    let rp = json
        .get("rp")
        .and_then(|val| {
            serde_json::from_str::<Ctap2PublicKeyCredentialRpEntity>(&val.to_string()).ok()
        })
        .ok_or_else(|| {
            tracing::info!("JSON missing `rp` field");
            WebAuthnError::TypeError
        })?;
    let user =
        json.get("user")
            .ok_or_else(|| {
                tracing::info!("JSON missing `user` field.");
                WebAuthnError::TypeError
            })
            .and_then(|val| {
                serde_json::from_str::<Ctap2PublicKeyCredentialUserEntity>(&val.to_string())
                    .map_err(|e| {
                        tracing::info!("JSON missing `user` field: {e}");
                        WebAuthnError::TypeError
                    })
            })?;
    let other_options =
        serde_json::from_str::<webauthn::MakeCredentialOptions>(&request_value.to_string())
            .map_err(|e| {
                tracing::info!("Received invalid request JSON: {e}");
                WebAuthnError::TypeError
            })?;
    let (resident_key, user_verification) =
        if let Some(authenticator_selection) = other_options.authenticator_selection {
            let resident_key = match authenticator_selection.resident_key.as_deref() {
                Some("required") => Some(ResidentKeyRequirement::Required),
                Some("preferred") => Some(ResidentKeyRequirement::Preferred),
                Some("discouraged") => Some(ResidentKeyRequirement::Discouraged),
                Some(_) => None,
                // legacy webauthn-1 member
                None if authenticator_selection.require_resident_key == Some(true) => {
                    Some(ResidentKeyRequirement::Required)
                }
                None => None,
            };

            let user_verification = authenticator_selection
                .user_verification
                .map(|uv| match uv.as_ref() {
                    "required" => UserVerificationRequirement::Required,
                    "preferred" => UserVerificationRequirement::Preferred,
                    "discouraged" => UserVerificationRequirement::Discouraged,
                    _ => todo!("This should be fixed in the future"),
                })
                .unwrap_or(UserVerificationRequirement::Preferred);

            (resident_key, user_verification)
        } else {
            (None, UserVerificationRequirement::Preferred)
        };
    let extensions = if let Some(incoming_extensions) = other_options.extensions {
        let extensions = MakeCredentialsRequestExtensions {
            cred_props: incoming_extensions.cred_props,
            cred_blob: incoming_extensions
                .cred_blob
                .and_then(|x| URL_SAFE_NO_PAD.decode(x).ok()),
            min_pin_length: incoming_extensions.min_pin_length,
            cred_protect: match incoming_extensions.credential_protection_policy {
                Some(cred_prot_policy) => Some(CredentialProtectionExtension {
                    policy: cred_prot_policy,
                    enforce_policy: incoming_extensions
                        .enforce_credential_protection_policy
                        .unwrap_or_default(),
                }),
                None => None,
            },
            large_blob: incoming_extensions
                .large_blob
                .map(|x| x.support.unwrap_or_default())
                .unwrap_or_default(),
            hmac_or_prf: if incoming_extensions.prf.is_some() {
                // CTAP currently doesn't support PRF queries at credentials.create()
                // So we ignore any potential value set in the request and only mark this
                // credential to activate HMAC for future PRF queries using credentials.get()
                MakeCredentialHmacOrPrfInput::Prf
            } else {
                // MakeCredentialHmacOrPrfInput::Hmac is not used directly by webauthn
                MakeCredentialHmacOrPrfInput::None
            },
        };
        Some(extensions)
    } else {
        None
    };

    let credential_parameters = match request_value.clone().get("pubKeyCredParams") {
        // https://www.w3.org/TR/webauthn-3/#sctn-createCredential Section 5.1.3.10
        // Default to ES256 and RS256 if no params are given.
        None => Ok(vec![
            PublicKeyCredentialParameters {
                alg: CoseKeyAlgorithmIdentifier::ES256.into(),
            },
            PublicKeyCredentialParameters {
                alg: CoseKeyAlgorithmIdentifier::RS256.into(),
            },
        ]),
        Some(val) => serde_json::from_str::<Vec<PublicKeyCredentialParameters>>(&val.to_string())
            .map_err(|e| {
                tracing::info!("Request JSON missing or invalid `pubKeyCredParams` key: {e}.");
                WebAuthnError::TypeError
            }),
    }?;
    let algorithms = credential_parameters
        .iter()
        .filter_map(|p| p.try_into().ok())
        .collect();
    let exclude = other_options.excluded_credentials.map(|v| {
        v.iter()
            .map(|e| e.try_into())
            .filter_map(|e| e.ok())
            .collect()
    });
    let (origin, is_cross_origin) = match (request.origin.as_ref(), request.is_same_origin.as_ref())
    {
        (Some(origin), Some(is_same_origin)) => (origin.to_string(), !is_same_origin),
        (Some(origin), None) => (origin.to_string(), true),
        // origin should always be set on request either by client or D-Bus service,
        // so this shouldn't be called
        (None, _) => {
            tracing::info!("Error reading origin from request.");
            return Err(WebAuthnError::TypeError);
        }
    };
    let client_data_json =
        webauthn::format_client_data_json(Operation::Create, &challenge, &origin, is_cross_origin);
    let client_data_hash = webauthn::create_client_data_hash(&client_data_json);
    Ok((
        MakeCredentialRequest {
            hash: client_data_hash,
            origin,

            relying_party: rp,
            user,
            resident_key,
            user_verification,
            algorithms,
            exclude,
            extensions,
            timeout: other_options.timeout.unwrap_or(Duration::from_secs(300)),
        },
        client_data_json,
    ))
}

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
    // TODO: do we need to check that the client_data_hash is the same?
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

pub(super) fn get_credential_request_try_into_ctap2(
    request: &GetCredentialRequest,
) -> std::result::Result<(GetAssertionRequest, String), WebAuthnError> {
    if request.public_key.is_none() {
        return Err(WebAuthnError::NotSupportedError);
    }
    let options: webauthn::GetCredentialOptions = request
        .public_key
        .as_ref()
        .ok_or_else(|| {
            tracing::info!("Invalid request: no \"publicKey\" options specified.");
            WebAuthnError::TypeError
        })
        .and_then(|o| {
            serde_json::from_str(&o.request_json).map_err(|e| {
                tracing::info!("Received invalid request JSON: {:?}", e);
                WebAuthnError::TypeError
            })
        })?;
    let mut allow: Vec<Ctap2PublicKeyCredentialDescriptor> = options
        .allow_credentials
        .iter()
        .filter_map(|cred| {
            if cred.cred_type == "public-key" {
                cred.try_into().ok()
            } else {
                None
            }
        })
        .collect();
    // TODO: The allow is returning an empty list instead of either None or a list of transports.
    // This should be investigated, but this is just a UI hint and isn't necessary to pass to the authenticator.
    // Just removing it for now.
    for c in allow.iter_mut() {
        c.transports = None;
    }
    let (origin, is_cross_origin) = match (request.origin.as_ref(), request.is_same_origin.as_ref())
    {
        (Some(origin), Some(is_same_origin)) => (origin.to_string(), !is_same_origin),
        (Some(origin), None) => (origin.to_string(), true),
        // origin should always be set on request either by client or D-Bus service,
        // so this shouldn't be called
        (None, _) => {
            tracing::info!("Error reading origin from client request.");
            return Err(WebAuthnError::TypeError);
        }
    };

    let client_data_json = webauthn::format_client_data_json(
        Operation::Get,
        &options.challenge,
        &origin,
        is_cross_origin,
    );
    let client_data_hash = webauthn::create_client_data_hash(&client_data_json);
    // TODO: actually calculate correct effective domain, and use fallback to related origin requests to fill this in. For now, just default to origin.
    let user_verification = match options
        .user_verification
        .unwrap_or_else(|| String::from("preferred"))
        .as_ref()
    {
        "required" => UserVerificationRequirement::Required,
        "preferred" => UserVerificationRequirement::Preferred,
        "discouraged" => UserVerificationRequirement::Discouraged,
        _ => {
            tracing::info!("Invalid user verification requirement specified by client.");
            return Err(WebAuthnError::TypeError);
        }
    };
    let relying_party_id = options.rp_id.unwrap_or_else(|| {
        // TODO: We're assuming that the origin is `<scheme>://data`, which is
        // currently checked by the caller, but we should encode this in a type.
        let (_, effective_domain) = origin.rsplit_once('/').unwrap();
        effective_domain.to_string()
    });

    let extensions = if let Some(incoming_extensions) = options.extensions {
        let extensions = GetAssertionRequestExtensions {
            cred_blob: incoming_extensions.get_cred_blob,
            hmac_or_prf: incoming_extensions
                .prf
                .and_then(|x| {
                    x.eval.map(|eval| {
                        let eval = Some(eval.decode());
                        let mut eval_by_credential = HashMap::new();
                        if let Some(incoming_eval) = x.eval_by_credential {
                            for (key, val) in incoming_eval.iter() {
                                eval_by_credential.insert(key.clone(), val.decode());
                            }
                        }
                        GetAssertionHmacOrPrfInput::Prf {
                            eval,
                            eval_by_credential,
                        }
                    })
                })
                .unwrap_or_default(),
            large_blob: incoming_extensions
                .large_blob
                // TODO: Implement GetAssertionLargeBlobExtension::Write, once libwebauthn supports it
                .filter(|x| x.read == Some(true))
                .map(|_| GetAssertionLargeBlobExtension::Read)
                .unwrap_or(GetAssertionLargeBlobExtension::None),
        };
        Some(extensions)
    } else {
        None
    };

    Ok((
        GetAssertionRequest {
            hash: client_data_hash,
            relying_party_id,
            user_verification,
            allow,
            extensions,
            timeout: options.timeout.unwrap_or(Duration::from_secs(300)),
        },
        client_data_json,
    ))
}

pub(super) fn get_credential_response_try_from_ctap2(
    response: &GetAssertionResponseInternal,
    client_data_json: String,
) -> std::result::Result<GetPublicKeyCredentialResponse, String> {
    let authenticator_data_blob = response
        .ctap
        .authenticator_data
        .to_response_bytes()
        .map_err(|err| format!("Failed to parse authenticator data: {err}"))?;

    // We can't just do this here, because we need encode all byte arrays for the JS-communication:
    // let unsigned_extensions = response
    //     .ctap
    //     .unsigned_extensions_output
    //     .as_ref()
    //     .map(|extensions| serde_json::to_string(&extensions).unwrap());
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
