//! Implements the service that public clients can connect to. Responsible for
//! authorizing clients for origins and validating request parameters.

mod dbus;
mod util;

use std::{
    collections::HashMap,
    fmt::Display,
    path::{Path, PathBuf},
    sync::Arc,
};

use credentialsd_common::model::WindowHandle;
use tokio::sync::Mutex as AsyncMutex;
use zbus::{
    Connection,
    zvariant::{DeserializeDict, NoneValue, OwnedValue, SerializeDict, Type},
};

use crate::{
    dbus::CredentialRequestController,
    model::{ClientDetails, CredentialRequest, CredentialResponse},
    webauthn::{AppId, NavigationContext, Origin},
};
use util::{
    create_credential_request_try_into_ctap2, create_credential_response_try_from_ctap2,
    get_credential_request_try_into_ctap2, get_credential_response_try_from_ctap2,
};

pub async fn start_gateway<C: CredentialRequestController + Send + Sync + 'static>(
    controller: C,
) -> Result<Connection, zbus::Error> {
    let svc = Arc::new(AsyncMutex::new(GatewayService {
        request_controller: Box::new(controller),
    }));
    dbus::start_dbus_gateway(svc).await
}

/// Type denoting a request's privilege level and origin.
#[derive(Debug)]
enum RequestKind {
    /// Only privileged clients are trusted to set both the origin and top origin.
    Privileged {
        origin: Origin,
        top_origin: Option<Origin>,
    },
    /// Unprivileged clients may only set an origin, which will be verified
    /// against a static list of allowed origins for the client.
    Unprivileged(Origin),
}

/// Details about the credential request and the client making it.
#[derive(Debug)]
struct RequestContext {
    app_id: AppId,
    pid: u32,
    request_kind: RequestKind,
}

impl From<RequestContext> for ClientDetails {
    fn from(value: RequestContext) -> Self {
        ClientDetails {
            app_id: value.app_id.as_ref().to_string(),
            pid: value.pid,
        }
    }
}

/// Service responsible for processing credential requests received from various
/// client interfaces.
struct GatewayService {
    /// Coordinates between user and various devices connected to the machine to
    /// fulfill credential requests.
    request_controller: Box<dyn CredentialRequestController + Send + Sync>,
}

impl GatewayService {
    async fn handle_create_credential(
        &self,
        request: CreateCredentialRequest,
        context: RequestContext,
        parent_window: Option<WindowHandle>,
        activation_token: Option<String>,
    ) -> Result<CreateCredentialResponse, WebAuthnError> {
        let request_environment = validate_request(&context)?;

        if let ("publicKey", Some(_)) = (request.r#type.as_ref(), &request.public_key) {
            // TODO: assert that RP ID is bound to origin:
            // - if RP ID is not set, set the RP ID to the origin's effective domain
            // - if RP ID is set, assert that it matches origin's effective domain
            // - if RP ID is set, but origin's effective domain doesn't match
            //    - query for related origins, if supported
            //    - fail if not supported, or if RP ID doesn't match any related origins.
            let make_cred_request =
                create_credential_request_try_into_ctap2(&request, &request_environment)
                    .await
                    .inspect_err(|_| {
                        tracing::error!(
                            "Could not parse passkey creation request. Rejecting request."
                        );
                    })?;
            if make_cred_request.algorithms.is_empty() {
                tracing::info!("No supported algorithms given in request. Rejecting request.");
                return Err(WebAuthnError::NotSupportedError);
            }
            let cred_request =
                CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request.clone());

            let response = self
                .request_controller
                .request_credential(
                    context.into(),
                    cred_request,
                    parent_window,
                    activation_token,
                )
                .await?;

            if let CredentialResponse::CreatePublicKeyCredentialResponse(cred_response) = response {
                let public_key_response =
                    create_credential_response_try_from_ctap2(&cred_response, &make_cred_request)
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
                Err(WebAuthnError::NotAllowedError)
            }
        } else {
            tracing::error!("Unknown credential type request: {}", request.r#type);
            Err(WebAuthnError::TypeError)
        }
    }

    async fn handle_get_credential(
        &self,
        request: GetCredentialRequest,
        context: RequestContext,
        parent_window: Option<WindowHandle>,
        activation_token: Option<String>,
    ) -> Result<GetCredentialResponse, WebAuthnError> {
        let request_environment = validate_request(&context)?;

        if request.public_key.is_some() {
            // Setup request

            // TODO: assert that RP ID is bound to origin:
            // - if RP ID is not set, set the RP ID to the origin's effective domain
            // - if RP ID is set, assert that it matches origin's effective domain
            // - if RP ID is set, but origin's effective domain doesn't match
            //    - query for related origins, if supported
            //    - fail if not supported, or if RP ID doesn't match any related origins.
            let get_cred_request =
                get_credential_request_try_into_ctap2(&request, &request_environment)
                    .await
                    .map_err(|e| {
                        tracing::error!("Could not parse passkey assertion request: {e:?}");
                        WebAuthnError::TypeError
                    })?;
            let cred_request =
                CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request.clone());

            let response = self
                .request_controller
                .request_credential(
                    context.into(),
                    cred_request,
                    parent_window,
                    activation_token,
                )
                .await?;

            if let CredentialResponse::GetPublicKeyCredentialResponse(cred_response) = response {
                let public_key_response =
                    get_credential_response_try_from_ctap2(&cred_response, &get_cred_request)
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
                Err(WebAuthnError::NotAllowedError)
            }
        } else {
            tracing::error!(
                "Request did not match any known credential types. Supported types: [`public_key`]."
            );
            Err(WebAuthnError::TypeError)
        }
    }
}

/// Verifies that the calling client is able to request credentials for the
/// given origin, then returns the origin.
fn validate_request(context: &RequestContext) -> Result<NavigationContext, WebAuthnError> {
    let request_environment = match &context.request_kind {
        RequestKind::Privileged { origin, top_origin } => {
            check_origin_from_privileged_client(origin, top_origin.as_ref())?
        }
        RequestKind::Unprivileged(origin) => {
            let origin_allowed_for_app_id = true;
            if origin_allowed_for_app_id {
                NavigationContext::SameOrigin(origin.clone())
            } else {
                tracing::warn!(
                    "App ID {:?} is not allowed for origin {origin}",
                    context.app_id
                );
                return Err(WebAuthnError::SecurityError);
            }
        }
    };
    Ok(request_environment)
}

async fn should_trust_app_id(pid: u32) -> bool {
    // Verify if we should trust the peer based on the file name. We verify that
    // we're in the same mount namespace before using the exe path.

    // TODO: If the portal is running in a separate mount namespace for security
    // reasons, then this check will fail with a false negative.
    // In the future, we should retrieve this information from another trusted
    // source, e.g. check if the PID is in a cgroup managed by systemd and
    // corresponds to the org.freedesktop.portal.Desktop D-Bus service unit.
    let Ok(my_mnt_ns) = tokio::fs::read_link("/proc/self/ns/mnt").await else {
        tracing::debug!("Could not read peer mount namespace");
        return false;
    };
    let Ok(peer_mnt_ns) = tokio::fs::read_link(format!("/proc/{pid}/ns/mnt")).await else {
        tracing::debug!("Could not determine our mount namespace");
        return false;
    };
    tracing::debug!(
        "mount namespace:\n  ours:   {:?}\n  theirs: {:?}",
        my_mnt_ns,
        peer_mnt_ns
    );
    if my_mnt_ns != peer_mnt_ns {
        tracing::warn!("Peer mount namespace is not the same as ours, not trusting the request.");
        return false;
    }

    let Ok(exe_path) = tokio::fs::read_link(format!("/proc/{pid}/exe")).await else {
        tracing::warn!("Cannot read executable name from procfs");
        return false;
    };

    tracing::debug!(?exe_path, %pid, "Found executable path:");
    let trusted_callers: Vec<PathBuf> = if cfg!(debug_assertions) {
        let trusted_callers_env = std::env::var("CREDSD_TRUSTED_CALLERS").unwrap_or_default();
        trusted_callers_env
            .split(',')
            .filter_map(|path| Path::new(path).canonicalize().ok())
            .collect()
    } else {
        vec![
            PathBuf::from("/usr/lib/xdg-desktop-portal"),
            PathBuf::from("/usr/libexec/xdg-desktop-portal"),
            PathBuf::from("/usr/local/lib/xdg-desktop-portal"),
            PathBuf::from("/usr/local/libexec/xdg-desktop-portal"),
        ]
    };
    tracing::debug!(
        ?trusted_callers,
        ?exe_path,
        "Testing whether request is from trusted caller"
    );
    if !trusted_callers.as_slice().contains(&exe_path) {
        tracing::warn!(?exe_path, "Request received from untrusted caller");
        false
    } else {
        true
    }
}

fn check_origin_from_app(
    app_id: &AppId,
    origin: Origin,
    top_origin: Option<Origin>,
) -> Result<RequestKind, WebAuthnError> {
    let is_privileged_client = {
        let trusted_clients = [
            "org.mozilla.firefox",
            "xyz.iinuwa.credentialsd.DemoCredentialsUi",
        ];
        let mut privileged = trusted_clients.contains(&app_id.as_ref());
        if cfg!(debug_assertions) && !privileged {
            let trusted_clients_env = std::env::var("CREDSD_TRUSTED_APP_IDS").unwrap_or_default();
            privileged = trusted_clients_env
                .split(',')
                .map(String::from)
                .any(|c| app_id.as_ref() == c);
        }
        privileged
    };
    if is_privileged_client {
        let (origin, top_origin) =
            match check_origin_from_privileged_client(&origin, top_origin.as_ref())? {
                NavigationContext::SameOrigin(origin) => (origin, None),
                NavigationContext::CrossOrigin((origin, top_origin)) => (origin, Some(top_origin)),
            };
        Ok(RequestKind::Privileged { origin, top_origin })
    } else {
        Ok(RequestKind::Unprivileged(origin))
    }
}

fn check_origin_from_privileged_client(
    origin: &Origin,
    top_origin: Option<&Origin>,
) -> Result<NavigationContext, WebAuthnError> {
    match (origin, top_origin) {
        (origin @ Origin::Https { .. }, None) => Ok(NavigationContext::SameOrigin(origin.clone())),
        (origin @ Origin::Https { .. }, Some(top_origin @ Origin::Https { .. })) => {
            if origin == top_origin {
                Ok(NavigationContext::SameOrigin(origin.clone()))
            } else {
                Ok(NavigationContext::CrossOrigin((
                    origin.clone(),
                    top_origin.clone(),
                )))
            }
        }
        _ => {
            tracing::warn!("Caller requested non-HTTPS schemed origin, which is not supported.");
            Err(WebAuthnError::SecurityError)
        }
    }
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetCredentialRequest {
    #[zvariant(rename = "publicKey")]
    pub public_key: Option<GetPublicKeyCredentialRequest>,
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPublicKeyCredentialRequest {
    pub request_json: String,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetCredentialResponse {
    #[zvariant(rename = "type")]
    r#type: String,
    public_key: Option<GetPublicKeyCredentialResponse>,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPublicKeyCredentialResponse {
    pub authentication_response_json: String,
}

impl From<GetPublicKeyCredentialResponse> for GetCredentialResponse {
    fn from(response: GetPublicKeyCredentialResponse) -> Self {
        GetCredentialResponse {
            // TODO: Decide on camelCase or kebab-case for cred types
            r#type: "public-key".to_string(),
            public_key: Some(response),
        }
    }
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialRequest {
    #[zvariant(rename = "type")]
    pub r#type: String,
    #[zvariant(rename = "publicKey")]
    pub public_key: Option<CreatePublicKeyCredentialRequest>,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialResponse {
    #[zvariant(rename = "type")]
    r#type: String,
    public_key: Option<CreatePublicKeyCredentialResponse>,
}

impl NoneValue for CreateCredentialResponse {
    type NoneType = HashMap<String, OwnedValue>;

    fn null_value() -> Self::NoneType {
        HashMap::new()
    }
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialRequest {
    pub request_json: String,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialResponse {
    pub registration_response_json: String,
}

impl From<CreatePublicKeyCredentialResponse> for CreateCredentialResponse {
    fn from(response: CreatePublicKeyCredentialResponse) -> Self {
        CreateCredentialResponse {
            // TODO: Decide on camelCase or kebab-case for cred types
            r#type: "public-key".to_string(),
            public_key: Some(response),
        }
    }
}

// We want to keep these aligned with how the spec names them.
#[expect(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum WebAuthnError {
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

impl std::error::Error for WebAuthnError {}

impl Display for WebAuthnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            WebAuthnError::AbortError => "Operation was aborted by client.",
            WebAuthnError::ConstraintError => "Resident key or user verification requirement was not able to be met.",
            WebAuthnError::InvalidStateError => "A user consented to create a new credential after trying to use an authenticator with a previously registered credential.",
            WebAuthnError::NotSupportedError => "Operation parameters are not supported.",
            WebAuthnError::SecurityError => "Validation of the client context for given RP ID failed.",
            WebAuthnError::NotAllowedError => "An unspecified error occurred, and the operation is not allowed to continue.",
            WebAuthnError::TypeError => "Invalid parameters specified.",
        })
    }
}

#[cfg(test)]
mod test {
    use crate::webauthn::{NavigationContext, Origin};

    use super::{WebAuthnError, check_origin_from_privileged_client};

    fn check_same_origin(origin: &str) -> Result<NavigationContext, WebAuthnError> {
        let origin = origin.parse().unwrap();
        check_origin_from_privileged_client(&origin, None)
    }

    #[test]
    fn test_https_origin_returns_success() {
        assert!(matches!(
            check_same_origin("https://example.com"),
            Ok(NavigationContext::SameOrigin(Origin::Https { host, .. })) if host == "example.com"
        ))
    }

    #[test]
    fn test_throws_security_error_when_passing_app_id_origin() {
        assert!(matches!(
            check_same_origin("app:com.example.App"),
            Err(WebAuthnError::SecurityError)
        ))
    }
}
