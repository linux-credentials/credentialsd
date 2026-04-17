//! Implements the service that public clients can connect to. Responsible for
//! authorizing clients for origins and validating request parameters.

mod dbus;
mod util;

use std::sync::Arc;

use credentialsd_common::{
    model::{GetClientCapabilitiesResponse, RequestingApplication, WebAuthnError},
    server::{
        CreateCredentialRequest, CreateCredentialResponse, GetCredentialRequest,
        GetCredentialResponse, WindowHandle,
    },
};
use tokio::sync::Mutex as AsyncMutex;
use zbus::Connection;

use crate::{
    dbus::CredentialRequestController,
    model::{CredentialRequest, CredentialResponse},
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
    app_name: String,
    pid: u32,
    request_kind: RequestKind,
}

impl From<RequestContext> for RequestingApplication {
    fn from(value: RequestContext) -> Self {
        RequestingApplication {
            path_or_app_id: value.app_id.as_ref().to_string(),
            name: Some(value.app_name).into(),
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
    ) -> Result<CreateCredentialResponse, WebAuthnError> {
        let request_environment = validate_request(&context)?;

        if let ("publicKey", Some(_)) = (request.r#type.as_ref(), &request.public_key) {
            // TODO: assert that RP ID is bound to origin:
            // - if RP ID is not set, set the RP ID to the origin's effective domain
            // - if RP ID is set, assert that it matches origin's effective domain
            // - if RP ID is set, but origin's effective domain doesn't match
            //    - query for related origins, if supported
            //    - fail if not supported, or if RP ID doesn't match any related origins.
            let (make_cred_request, client_data_json) =
                create_credential_request_try_into_ctap2(&request, &request_environment)
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
                CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request);

            let response = self
                .request_controller
                .request_credential(Some(context.into()), cred_request, parent_window)
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
            let (get_cred_request, client_data_json) =
                get_credential_request_try_into_ctap2(&request, &request_environment).map_err(
                    |e| {
                        tracing::error!("Could not parse passkey assertion request: {e:?}");
                        WebAuthnError::TypeError
                    },
                )?;
            let cred_request = CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request);

            let response = self
                .request_controller
                .request_credential(Some(context.into()), cred_request, parent_window)
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
                Err(WebAuthnError::NotAllowedError)
            }
        } else {
            tracing::error!("Request did not match any known credential types. Supported types: [`public_key`].");
            Err(WebAuthnError::TypeError)
        }
    }

    fn handle_get_client_capabilities(&self) -> GetClientCapabilitiesResponse {
        GetClientCapabilitiesResponse {
            conditional_create: false,
            conditional_get: false,
            hybrid_transport: true,
            passkey_platform_authenticator: false,
            user_verifying_platform_authenticator: false,
            related_origins: false,
            signal_all_accepted_credentials: false,
            signal_current_user_details: false,
            signal_unknown_credential: false,
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

fn get_app_info_from_pid(pid: u32) -> Option<RequestingApplication> {
    // Get binary path via PID from /proc file-system
    // TODO: To be REALLY sure, we may want to look at /proc/PID/exe instead. It is a symlink to
    //       the actual binary, giving a full path instead of only the command name.
    //       This should in theory be "more secure", but also may disconcert novice users with no
    //       technical background.
    let command_name = match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        Ok(c) => c.trim().to_string(),
        Err(e) => {
            tracing::error!(
                "Failed to read /proc/{pid}/comm, so we don't know the command name of peer: {e:?}"
            );
            return None;
        }
    };
    tracing::debug!("Request is from: {command_name}");

    let exe_path = match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(
                "Failed to follow link of /proc/{pid}/exe, so we don't know the executable path of peer: {e:?}"
            );
            return None;
        }
    };
    tracing::debug!("Request is from: {exe_path:?}");

    Some(RequestingApplication {
        name: Some(command_name).into(),
        path_or_app_id: exe_path.to_string_lossy().to_string(),
        pid,
    })
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
        return false;
    };

    // The target binaries are hard-coded to valid UTF-8, so it's acceptable to
    // lose some data here.
    let Some(exe_path) = exe_path.to_str() else {
        return false;
    };
    tracing::debug!(?exe_path, %pid, "Found executable path:");
    let trusted_callers: Vec<String> = if cfg!(debug_assertions) {
        let trusted_callers_env = std::env::var("CREDSD_TRUSTED_CALLERS").unwrap_or_default();
        trusted_callers_env.split(',').map(String::from).collect()
    } else {
        vec!["/usr/bin/xdg-desktop-portal".to_string()]
    };
    trusted_callers.as_slice().contains(&exe_path.to_string())
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

#[cfg(test)]
mod test {
    use credentialsd_common::model::WebAuthnError;

    use crate::webauthn::{NavigationContext, Origin};

    use super::check_origin_from_privileged_client;
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
