//! This module contains types and methods used for serializing data to and from D-Bus method calls.
//!
//! Types shared between components within this service belong in credentialsd_common::model.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use libwebauthn::ops::webauthn::idl::origin::{
    Origin as LibwebauthnOrigin, RequestOrigin as LibwebauthnRequestOrigin,
};
use libwebauthn::ops::webauthn::psl::SystemPublicSuffixList;
use libwebauthn::ops::webauthn::{
    GetAssertionPrepareError, MakeCredentialPrepareError, MaxRegistrableLabels, OriginValidation,
    RelatedOrigins, RequestSettings, ReqwestRelatedOriginsSource,
};

use crate::{
    gateway::{
        CreateCredentialRequest, CreatePublicKeyCredentialResponse, GetCredentialRequest,
        GetPublicKeyCredentialResponse, WebAuthnError,
    },
    model::{GetAssertionResponseInternal, MakeCredentialResponseInternal},
    webauthn::{
        GetAssertionRequest, MakeCredentialRequest, NavigationContext, Origin, WebAuthnIDLResponse,
    },
};

impl TryFrom<&Origin> for LibwebauthnOrigin {
    type Error = WebAuthnError;

    fn try_from(value: &Origin) -> Result<Self, Self::Error> {
        match value {
            Origin::Https { .. } => value.to_string().parse().map_err(|err| {
                tracing::info!("Cannot convert origin to libwebauthn Origin: {err}");
                WebAuthnError::InvalidOrigin
            }),
            // TODO: AppId support is being removed.
            Origin::AppId(_) => {
                tracing::info!("AppId origins are not supported: {value}");
                Err(WebAuthnError::InvalidOrigin)
            }
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
        WebAuthnError::NotAllowed
    })
}

fn build_related_origins_source() -> Result<ReqwestRelatedOriginsSource, WebAuthnError> {
    ReqwestRelatedOriginsSource::new().map_err(|err| {
        tracing::error!("Failed to build related-origins source: {err}");
        WebAuthnError::NotAllowed
    })
}

fn request_settings<'a>(
    psl: &'a SystemPublicSuffixList,
    related_origins: &'a ReqwestRelatedOriginsSource,
) -> RequestSettings<'a> {
    RequestSettings {
        origin: OriginValidation::Validate {
            public_suffix_list: psl,
            related_origins: RelatedOrigins::Enabled {
                source: related_origins,
                max_labels: MaxRegistrableLabels::default(),
            },
        },
    }
}

/// Parses a WebAuthn create credential request from D-Bus into a CTAP2 MakeCredentialRequest.
pub(super) async fn create_credential_request_try_into_ctap2(
    request: &CreateCredentialRequest,
    request_environment: &NavigationContext,
) -> std::result::Result<MakeCredentialRequest, WebAuthnError> {
    let options = request.public_key.as_ref().ok_or_else(|| {
        tracing::info!("Invalid request: missing public_key");
        WebAuthnError::InvalidOptions
    })?;
    // WebAuthn checks user.id before validating the RP ID, which may require
    // fetching related origins from the network, so check it up front.
    if let Some(user_id) = user_id_from_json(&options.request_json) {
        validate_user_id(&user_id)?;
    }

    let request_origin: LibwebauthnRequestOrigin = request_environment.try_into()?;
    let psl = load_system_psl()?;
    let related_origins = build_related_origins_source()?;
    let settings = request_settings(&psl, &related_origins);

    let make_cred_request =
        MakeCredentialRequest::prepare(&request_origin, &options.request_json, &settings)
            .await
            .map_err(|err| {
                tracing::info!("Failed to parse MakeCredential request JSON: {err}");
                make_credential_prepare_error(&err)
            })?;
    // In case the early check above could not decode user.id.
    validate_user_id(&make_cred_request.user.id)?;

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
pub(super) async fn get_credential_request_try_into_ctap2(
    request: &GetCredentialRequest,
    request_environment: &NavigationContext,
) -> std::result::Result<GetAssertionRequest, WebAuthnError> {
    let options = request.public_key.as_ref().ok_or_else(|| {
        tracing::info!("Invalid request: no \"publicKey\" options specified.");
        WebAuthnError::InvalidOptions
    })?;

    let request_origin: LibwebauthnRequestOrigin = request_environment.try_into()?;
    let psl = load_system_psl()?;
    let related_origins = build_related_origins_source()?;
    let settings = request_settings(&psl, &related_origins);

    let get_assertion_request =
        GetAssertionRequest::prepare(&request_origin, &options.request_json, &settings)
            .await
            .map_err(|err| {
                tracing::info!("Failed to parse GetAssertion request JSON: {err}");
                get_assertion_prepare_error(&err)
            })?;

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

/// Maps a libwebauthn registration request parsing error to a gateway error.
///
/// All of these can be deduced from the caller's own request, so they are
/// safe to report specifically.
fn make_credential_prepare_error(err: &MakeCredentialPrepareError) -> WebAuthnError {
    match err {
        MakeCredentialPrepareError::EncodingError(_) => WebAuthnError::InvalidOptions,
        MakeCredentialPrepareError::InvalidRelyingPartyId(_)
        | MakeCredentialPrepareError::MismatchingRelyingPartyId(_, _)
        | MakeCredentialPrepareError::InvalidAppId(_) => WebAuthnError::InvalidOrigin,
    }
}

/// Maps a libwebauthn assertion request parsing error to a gateway error.
///
/// All of these can be deduced from the caller's own request, so they are
/// safe to report specifically.
fn get_assertion_prepare_error(err: &GetAssertionPrepareError) -> WebAuthnError {
    match err {
        GetAssertionPrepareError::EncodingError(_)
        | GetAssertionPrepareError::UnexpectedLengthError(_, _) => WebAuthnError::InvalidOptions,
        GetAssertionPrepareError::NotSupported(_) => WebAuthnError::NotSupported,
        GetAssertionPrepareError::InvalidRelyingPartyId(_)
        | GetAssertionPrepareError::MismatchingRelyingPartyId(_, _)
        | GetAssertionPrepareError::InvalidAppId(_) => WebAuthnError::InvalidOrigin,
    }
}

/// Extracts and decodes `user.id` from a registration request, if present and
/// valid base64url. Anything else is left for libwebauthn to reject.
fn user_id_from_json(request_json: &str) -> Option<Vec<u8>> {
    let request: serde_json::Value = serde_json::from_str(request_json).ok()?;
    let user_id = request.pointer("/user/id")?.as_str()?;
    URL_SAFE_NO_PAD.decode(user_id.trim_end_matches('=')).ok()
}

/// Maximum length of `user.id`, per [WebAuthn § 5.4.3][user-id].
///
/// [user-id]: https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id
const MAX_USER_ID_LEN: usize = 64;

/// Checks that `user.id` is between 1 and 64 bytes long, as required by
/// [WebAuthn § 5.1.3][create] step 5.
///
/// [create]: https://www.w3.org/TR/webauthn-3/#sctn-createCredential
fn validate_user_id(user_id: &[u8]) -> Result<(), WebAuthnError> {
    if user_id.is_empty() || user_id.len() > MAX_USER_ID_LEN {
        tracing::info!(
            "Invalid request: user.id is {} bytes long, expected 1 to {MAX_USER_ID_LEN}",
            user_id.len()
        );
        return Err(WebAuthnError::InvalidUserId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use libwebauthn::ops::webauthn::{
        GetAssertionPrepareError, MakeCredentialPrepareError,
        idl::origin::Origin as LibwebauthnOrigin,
    };

    use super::{
        WebAuthnError, create_credential_request_try_into_ctap2, get_assertion_prepare_error,
        make_credential_prepare_error, validate_user_id,
    };
    use crate::{
        gateway::{CreateCredentialRequest, CreatePublicKeyCredentialRequest},
        webauthn::{NavigationContext, Origin},
    };

    fn create_request(request_json: &str) -> CreateCredentialRequest {
        CreateCredentialRequest {
            r#type: "publicKey".to_string(),
            public_key: Some(CreatePublicKeyCredentialRequest {
                request_json: request_json.to_string(),
            }),
        }
    }

    #[tokio::test]
    async fn registration_rejects_invalid_user_id_before_checking_rp_id() {
        // rp.id does not match the origin, which would otherwise trigger a
        // related origins lookup and an InvalidOrigin error.
        let request = create_request(
            r#"{"rp":{"id":"other.example","name":"x"},"user":{"id":"","name":"a","displayName":"a"},"challenge":"AAAAAAAAAAAAAAAAAAAAAA","pubKeyCredParams":[{"type":"public-key","alg":-7}]}"#,
        );
        let origin = NavigationContext::SameOrigin("https://example.com".parse().unwrap());
        assert_eq!(
            create_credential_request_try_into_ctap2(&request, &origin)
                .await
                .unwrap_err(),
            WebAuthnError::InvalidUserId
        );
    }

    #[test]
    fn app_id_origin_is_invalid_origin() {
        let origin: Origin = "app:com.example.App".parse().unwrap();
        assert_eq!(
            LibwebauthnOrigin::try_from(&origin).unwrap_err(),
            WebAuthnError::InvalidOrigin
        );
    }

    fn json_error() -> serde_json::Error {
        serde_json::from_str::<u8>("not json").unwrap_err()
    }

    #[test]
    fn malformed_registration_json_is_invalid_options() {
        let err = MakeCredentialPrepareError::EncodingError(json_error());
        assert_eq!(
            make_credential_prepare_error(&err),
            WebAuthnError::InvalidOptions
        );
    }

    #[test]
    fn registration_rp_id_errors_are_invalid_origin() {
        let errors = [
            MakeCredentialPrepareError::InvalidRelyingPartyId("bad".into()),
            MakeCredentialPrepareError::MismatchingRelyingPartyId(
                "other.example".into(),
                "example.com".into(),
            ),
            MakeCredentialPrepareError::InvalidAppId("bad".into()),
        ];
        for err in errors {
            assert_eq!(
                make_credential_prepare_error(&err),
                WebAuthnError::InvalidOrigin,
                "{err:?}"
            );
        }
    }

    #[test]
    fn malformed_assertion_options_are_invalid_options() {
        let errors = [
            GetAssertionPrepareError::EncodingError(json_error()),
            GetAssertionPrepareError::UnexpectedLengthError("challenge".into(), 0),
        ];
        for err in errors {
            assert_eq!(
                get_assertion_prepare_error(&err),
                WebAuthnError::InvalidOptions,
                "{err:?}"
            );
        }
    }

    #[test]
    fn unsupported_assertion_options_are_not_supported() {
        let err = GetAssertionPrepareError::NotSupported("hints".into());
        assert_eq!(
            get_assertion_prepare_error(&err),
            WebAuthnError::NotSupported
        );
    }

    #[test]
    fn assertion_rp_id_errors_are_invalid_origin() {
        let errors = [
            GetAssertionPrepareError::InvalidRelyingPartyId("bad".into()),
            GetAssertionPrepareError::MismatchingRelyingPartyId(
                "other.example".into(),
                "example.com".into(),
            ),
            GetAssertionPrepareError::InvalidAppId("bad".into()),
        ];
        for err in errors {
            assert_eq!(
                get_assertion_prepare_error(&err),
                WebAuthnError::InvalidOrigin,
                "{err:?}"
            );
        }
    }

    #[test]
    fn user_id_must_not_be_empty() {
        assert_eq!(validate_user_id(&[]), Err(WebAuthnError::InvalidUserId));
    }

    #[test]
    fn user_id_must_not_exceed_64_bytes() {
        assert_eq!(
            validate_user_id(&[0; 65]),
            Err(WebAuthnError::InvalidUserId)
        );
    }

    #[test]
    fn user_id_of_1_to_64_bytes_is_accepted() {
        assert_eq!(validate_user_id(&[0; 1]), Ok(()));
        assert_eq!(validate_user_id(&[0; 64]), Ok(()));
    }
}
