//! Implements the service that public clients can connect to. Responsible for
//! authorizing clients for origins and validating request parameters.

use std::sync::Arc;

use credentialsd_common::{
    model::{CredentialRequest, CredentialResponse, GetClientCapabilitiesResponse, WebAuthnError},
    server::{
        CreateCredentialRequest, CreateCredentialResponse, GetCredentialRequest,
        GetCredentialResponse,
    },
};
use tokio::sync::Mutex as AsyncMutex;
use zbus::{fdo, interface, Connection, DBusError};

use crate::dbus::{
    create_credential_request_try_into_ctap2, create_credential_response_try_from_ctap2,
    get_credential_request_try_into_ctap2, get_credential_response_try_from_ctap2,
    CredentialRequestController,
};

pub const SERVICE_NAME: &str = "xyz.iinuwa.credentialsd.Credentials";
pub const SERVICE_PATH: &str = "/xyz/iinuwa/credentialsd/Credentials";

pub async fn start_gateway<C: CredentialRequestController + Send + Sync + 'static>(
    controller: C,
) -> Result<Connection, zbus::Error> {
    zbus::connection::Builder::session()
        .inspect_err(|err| {
            tracing::error!("Failed to connect to D-Bus session: {err}");
        })?
        .name(SERVICE_NAME)?
        .serve_at(
            SERVICE_PATH,
            CredentialGateway {
                controller: Arc::new(AsyncMutex::new(controller)),
            },
        )?
        .build()
        .await
}

struct CredentialGateway<C: CredentialRequestController> {
    controller: Arc<AsyncMutex<C>>,
}

/// These are public methods that can be called by arbitrary clients to begin a credential flow.
#[interface(name = "xyz.iinuwa.credentialsd.Credentials1")]
impl<C: CredentialRequestController + Send + Sync + 'static> CredentialGateway<C> {
    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
    ) -> Result<CreateCredentialResponse, Error> {
        let (_origin, is_same_origin, _top_origin) =
            check_origin(request.origin.as_deref(), request.is_same_origin)
                .await
                .map_err(Error::from)?;
        if let ("publicKey", Some(_)) = (request.r#type.as_ref(), &request.public_key) {
            if !is_same_origin {
                // TODO: Once we modify the models to convey the top-origin in cross origin requests to the UI, we can remove this error message.
                // We should still reject cross-origin requests for conditionally-mediated requests.
                tracing::warn!("Client attempted to issue cross-origin request for credentials, which are not supported by this platform.");
                return Err(WebAuthnError::NotAllowedError.into());
            }
            let (make_cred_request, client_data_json) =
                create_credential_request_try_into_ctap2(&request).map_err(|e| {
                    if let WebAuthnError::TypeError = e {
                        tracing::error!(
                            "Could not parse passkey creation request. Rejecting request."
                        );
                    }
                    e
                })?;
            if make_cred_request.algorithms.is_empty() {
                tracing::info!("No supported algorithms given in request. Rejecting request.");
                return Err(Error::NotSupportedError);
            }
            let cred_request =
                CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request);

            let response = self
                .controller
                .lock()
                .await
                .request_credential(cred_request)
                .await?;

            if let CredentialResponse::CreatePublicKeyCredentialResponse(cred_response) = response {
                let public_key_response =
                    create_credential_response_try_from_ctap2(&cred_response, client_data_json)
                        .map_err(|err| {
                            tracing::error!(
                                "Failed to parse credential response from authenticator: {err}"
                            );
                            // Using NotAllowedError as a catch-all error.
                            WebAuthnError::NotAllowedError
                        })?;
                Ok(public_key_response.into())
            } else {
                // TODO: is response safe to log here?
                // tracing::error!("Expected create public key credential response, received {response:?}");
                tracing::error!("Did not receive expected create public key credential response.");
                // Using NotAllowedError as a catch-all error.
                Err(WebAuthnError::NotAllowedError.into())
            }
        } else {
            tracing::error!("Unknown credential type request: {}", request.r#type);
            Err(WebAuthnError::TypeError.into())
        }
    }

    async fn get_credential(
        &self,
        request: GetCredentialRequest,
    ) -> Result<GetCredentialResponse, Error> {
        let (_origin, is_same_origin, _top_origin) =
            check_origin(request.origin.as_deref(), request.is_same_origin)
                .await
                .map_err(Error::from)?;
        if let ("publicKey", Some(_)) = (request.r#type.as_ref(), &request.public_key) {
            if !is_same_origin {
                // TODO: Once we modify the models to convey the top-origin in cross origin requests to the UI, we can remove this error message.
                tracing::warn!("Client attempted to issue cross-origin request for credentials, which are not supported by this platform.");
                return Err(WebAuthnError::NotAllowedError.into());
            }
            // Setup request

            // TODO: assert that RP ID is bound to origin:
            // - if RP ID is not set, set the RP ID to the origin's effective domain
            // - if RP ID is set, assert that it matches origin's effective domain
            // - if RP ID is set, but origin's effective domain doesn't match
            //    - query for related origins, if supported
            //    - fail if not supported, or if RP ID doesn't match any related origins.
            let (get_cred_request, client_data_json) =
                get_credential_request_try_into_ctap2(&request).map_err(|e| {
                    tracing::error!("Could not parse passkey assertion request: {e:?}");
                    WebAuthnError::TypeError
                })?;
            let cred_request = CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request);

            let response = self
                .controller
                .lock()
                .await
                .request_credential(cred_request)
                .await?;

            if let CredentialResponse::GetPublicKeyCredentialResponse(cred_response) = response {
                let public_key_response =
                    get_credential_response_try_from_ctap2(&cred_response, client_data_json)
                        .map_err(|err| {
                            tracing::error!(
                                "Failed to parse credential response from authenticator: {err}"
                            );
                            // Using NotAllowedError as a catch-all error.
                            WebAuthnError::NotAllowedError
                        })?;
                Ok(public_key_response.into())
            } else {
                // TODO: is response safe to log here?
                // tracing::error!("Expected get public key credential response, received {response:?}");
                tracing::error!("Did not receive expected get public key credential response.");
                // Using NotAllowedError as a catch-all error.
                Err(WebAuthnError::NotAllowedError.into())
            }
        } else {
            tracing::error!("Unknown credential type request: {}", request.r#type);
            Err(WebAuthnError::TypeError.into())
        }
    }

    async fn get_client_capabilities(&self) -> fdo::Result<GetClientCapabilitiesResponse> {
        Ok(GetClientCapabilitiesResponse {
            conditional_create: false,
            conditional_get: false,
            hybrid_transport: true,
            passkey_platform_authenticator: false,
            user_verifying_platform_authenticator: false,
            related_origins: false,
            signal_all_accepted_credentials: false,
            signal_current_user_details: false,
            signal_unknown_credential: false,
        })
    }
}

async fn check_origin(
    origin: Option<&str>,
    is_same_origin: Option<bool>,
    // TODO: Replace is_same_origin with explicit top_origin
    // top_origin: Option<&str>,
) -> Result<(String, bool, String), WebAuthnError> {
    let origin = if let Some(origin) = origin {
        origin.to_string()
    } else {
        tracing::warn!(
            "Caller requested implicit origin, which is not yet implemented. Rejecting request."
        );
        return Err(WebAuthnError::SecurityError);
    };
    if !origin.starts_with("https://") {
        tracing::warn!("Caller requested non-HTTPS schemed origin, which is not supported.");
        return Err(WebAuthnError::SecurityError);
    }
    let is_same_origin = is_same_origin.unwrap_or(false);
    let top_origin = if is_same_origin {
        origin.clone()
    } else {
        tracing::warn!("Client attempted to issue cross-origin request for credentials, which are not supported by this platform.");
        return Err(WebAuthnError::NotAllowedError);
    };
    Ok((origin, true, top_origin))
}

#[allow(clippy::enum_variant_names)]
#[derive(DBusError, Debug)]
#[zbus(prefix = "xyz.iinuwa.credentials")]
enum Error {
    #[zbus(error)]
    ZBus(zbus::Error),

    /// The ceremony was cancelled by an AbortController. See § 5.6 Abort
    /// Operations with AbortSignal and § 1.3.4 Aborting Authentication
    /// Operations.
    AbortError,

    /// Either `residentKey` was set to required and no available authenticator
    /// supported resident keys, or `userVerification` was set to required and no
    /// available authenticator could perform user verification.
    ConstraintError,

    /// The authenticator used in the ceremony recognized an entry in
    /// `excludeCredentials` after the user consented to registering a credential.
    InvalidStateError,

    /// No entry in `pubKeyCredParams` had a type property of `public-key`, or the
    /// authenticator did not support any of the signature algorithms specified
    /// in `pubKeyCredParams`.
    NotSupportedError,

    /// The effective domain was not a valid domain, or `rp.id` was not equal to
    /// or a registrable domain suffix of the effective domain. In the latter
    /// case, the client does not support related origin requests or the related
    /// origins validation procedure failed.
    SecurityError,

    /// A catch-all error covering a wide range of possible reasons, including
    /// common ones like the user canceling out of the ceremony. Some of these
    /// causes are documented throughout this spec, while others are
    /// client-specific.
    NotAllowedError,

    /// The options argument was not a valid `CredentialCreationOptions` value, or
    /// the value of `user.id` was empty or was longer than 64 bytes.
    TypeError,
}

impl From<WebAuthnError> for Error {
    fn from(value: WebAuthnError) -> Self {
        match value {
            WebAuthnError::AbortError => Self::AbortError,
            WebAuthnError::ConstraintError => Self::ConstraintError,
            WebAuthnError::InvalidStateError => Self::InvalidStateError,
            WebAuthnError::NotSupportedError => Self::NotSupportedError,
            WebAuthnError::SecurityError => Self::SecurityError,
            WebAuthnError::NotAllowedError => Self::NotAllowedError,
            WebAuthnError::TypeError => Self::TypeError,
        }
    }
}

#[cfg(test)]
mod test {
    use std::future::Future;

    use credentialsd_common::model::WebAuthnError;

    use crate::dbus::gateway::check_origin;

    #[tokio::test]
    async fn test_only_https_origins() {
        let check = |origin: &'static str| async { check_origin(Some(origin), Some(true)).await };
        assert!(matches!(
            check("https://example.com").await,
            Ok((o, ..)) if o == "https://example.com"
        ));
        assert!(matches!(
            check("http://example.com").await,
            Err(WebAuthnError::SecurityError)
        ));
    }
}
