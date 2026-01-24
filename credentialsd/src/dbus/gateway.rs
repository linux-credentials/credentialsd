//! Implements the service that public clients can connect to. Responsible for
//! authorizing clients for origins and validating request parameters.

use std::{collections::HashMap, os::fd::AsRawFd, sync::Arc};

use credentialsd_common::{
    model::{GetClientCapabilitiesResponse, RequestingApplication, WebAuthnError},
    server::{
        CreateCredentialRequest, CreateCredentialResponse, GetCredentialRequest,
        GetCredentialResponse, WindowHandle,
    },
};
use serde::{ser::SerializeTuple, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use zbus::{
    fdo, interface,
    message::Header,
    names::{BusName, UniqueName},
    zvariant::{ObjectPath, Optional, OwnedValue, Type, Value},
    Connection, DBusError,
};

use crate::{
    dbus::{
        create_credential_request_try_into_ctap2, create_credential_response_try_from_ctap2,
        get_credential_request_try_into_ctap2, get_credential_response_try_from_ctap2,
        CredentialRequestController,
    },
    model::{CredentialRequest, CredentialResponse},
    webauthn::Origin,
};

pub const SERVICE_NAME: &str = "xyz.iinuwa.credentialsd.Credentials";
pub const SERVICE_PATH: &str = "/xyz/iinuwa/credentialsd/Credentials";
pub const PORTAL_SERVICE_PATH: &str = "/org/freedesktop/portal/desktop";

pub async fn start_gateway<C: CredentialRequestController + Send + Sync + 'static>(
    controller: C,
) -> Result<Connection, zbus::Error> {
    let controller = Arc::new(AsyncMutex::new(controller));
    zbus::connection::Builder::session()
        .inspect_err(|err| {
            tracing::error!("Failed to connect to D-Bus session: {err}");
        })?
        .name(SERVICE_NAME)?
        .serve_at(
            SERVICE_PATH,
            CredentialGateway {
                controller: controller.clone(),
            },
        )?
        .serve_at(
            PORTAL_SERVICE_PATH,
            CredentialPortalGateway {
                controller: controller.clone(),
            },
        )?
        .build()
        .await
}

struct CredentialGateway<C: CredentialRequestController> {
    controller: Arc<AsyncMutex<C>>,
}

struct CredentialPortalGateway<C: CredentialRequestController> {
    controller: Arc<AsyncMutex<C>>,
}

async fn query_peer_pid_via_fdinfo(
    connection: &Connection,
    sender_unique_name: &UniqueName<'_>,
) -> Option<u32> {
    let dbus_proxy = match zbus::fdo::DBusProxy::new(connection).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to establish DBus proxy to query peer info: {e:?}");
            return None;
        }
    };

    let peer_credentials = match dbus_proxy
        .get_connection_credentials(BusName::from(sender_unique_name.to_owned()))
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to get peer credentials: {e:?}");
            return None;
        }
    };

    let pidfd = match peer_credentials.process_fd() {
        Some(p) => p.as_raw_fd(),
        None => {
            tracing::error!("Failed to get process fd from peer credentials");
            return None;
        }
    };

    let fdinfo_str = match std::fs::read_to_string(format!("/proc/self/fdinfo/{pidfd}")) {
        Ok(fdinfo) => fdinfo,
        Err(e) => {
            tracing::error!("Failed to read fdinfo from procfs: {e}");
            return None;
        }
    };

    // Find the line that starts with "Pid:"
    let pid_line = match fdinfo_str.lines().find(|line| line.starts_with("Pid:")) {
        Some(line) => line,
        None => {
            tracing::error!("Failed to read PID from fdinfo");
            return None;
        }
    };

    let pid_str = pid_line[4..].trim();

    // std::process::id() also returns u32
    let pid: u32 = match pid_str.parse() {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("Failed to parse PID from fdinfo entry: {e}");
            return None;
        }
    };

    Some(pid)
}

async fn query_connection_peer_binary(
    header: Header<'_>,
    connection: &Connection,
) -> Option<RequestingApplication> {
    // Get the sender's unique bus name
    let sender_unique_name = header.sender()?;

    tracing::debug!("Received request from sender: {}", sender_unique_name);

    // First, try to get the PID by peer's pidfd
    let Some(pid) = query_peer_pid_via_fdinfo(connection, sender_unique_name).await else {
        tracing::error!("Failed to determine peer's PID. Skipping application details query.");
        return None;
    };

    // Get binary path via PID from /proc file-system. Use command name as a
    // friendly name, and exe path as the more definitive name.
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

    // TODO: Check the mount namespace of the executable; if we're not in the same namespace, we should not return the path at all.
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
        path: exe_path.to_string_lossy().to_string(),
        pid,
    })
}

/// These are public methods that can be called by arbitrary clients to begin a credential flow.
#[interface(name = "xyz.iinuwa.credentialsd.Credentials1")]
impl<C: CredentialRequestController + Send + Sync + 'static> CredentialGateway<C> {
    async fn create_credential(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        parent_window: Optional<WindowHandle>,
        request: CreateCredentialRequest,
    ) -> Result<CreateCredentialResponse, Error> {
        // TODO: Add authorization check for privileged client.
        let top_origin = if request.is_same_origin.unwrap_or_default() {
            None
        } else {
            // TODO: Once we modify the models to convey the top-origin in cross origin requests to the UI, we can remove this error message.
            // We should still reject cross-origin requests for conditionally-mediated requests.
            tracing::warn!("Client attempted to issue cross-origin request for credentials, which are not supported by this platform.");
            return Err(WebAuthnError::NotAllowedError.into());
        };
        let origin = check_origin_from_privileged_client(request.origin.as_deref(), top_origin)?;
        // Find out where this request is coming from (which application is requesting this)
        let requesting_app = query_connection_peer_binary(header, connection).await;
        let response = handle_create_credential(
            &self.controller,
            request,
            origin,
            requesting_app,
            parent_window.into(),
        )
        .await?;
        Ok(response)
    }

    async fn get_credential(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        parent_window: Optional<WindowHandle>,
        request: GetCredentialRequest,
    ) -> Result<GetCredentialResponse, Error> {
        // TODO: Add authorization check for privileged client.
        let top_origin = if request.is_same_origin.unwrap_or_default() {
            None
        } else {
            // TODO: Once we modify the models to convey the top-origin in cross origin requests to the UI, we can remove this error message.
            // We should still reject cross-origin requests for conditionally-mediated requests.
            tracing::warn!("Client attempted to issue cross-origin request for credentials, which are not supported by this platform.");
            return Err(WebAuthnError::NotAllowedError.into());
        };
        let origin = check_origin_from_privileged_client(request.origin.as_deref(), top_origin)?;
        // Find out where this request is coming from (which application is requesting this)
        let requesting_app = query_connection_peer_binary(header, connection).await;
        let response = handle_get_credential(
            &self.controller,
            request,
            origin,
            requesting_app,
            parent_window.into(),
        )
        .await?;
        Ok(response)
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

#[interface(name = "org.freedesktop.impl.portal.CredentialsX")]
impl<C: CredentialRequestController + Send + Sync + 'static> CredentialPortalGateway<C> {
    #[zbus(out_args("response", "results"))]
    async fn create_credential(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        portal_request_handle: ObjectPath<'_>,
        claimed_app_id: String,
        claimed_app_display_name: Optional<String>,
        parent_window: Optional<WindowHandle>,
        claimed_origin: Optional<String>,
        claimed_top_origin: Optional<String>,
        request: CreateCredentialRequest,
        _options: HashMap<String, OwnedValue>,
    ) -> PortalResult<CreateCredentialResponse, Error> {
        let app_validation_result = validate_app_details(
            connection,
            &header,
            claimed_app_id,
            claimed_app_display_name.into(),
            claimed_origin.into(),
            claimed_top_origin.into(),
        )
        .await;
        let (requesting_app, origin) = match app_validation_result {
            Ok(validated) => validated,
            Err(err) => return Err(err).into(),
        };
        tracing::debug!(
            ?requesting_app,
            ?origin,
            ?request,
            ?parent_window,
            ?portal_request_handle,
            "Received request for creating credential"
        );
        let response = handle_create_credential(
            &self.controller,
            request,
            origin,
            Some(requesting_app),
            parent_window.into(),
        )
        .await
        .map_err(Error::from);

        response.into()
    }

    async fn get_credential(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        portal_request_handle: ObjectPath<'_>,
        parent_window: Optional<WindowHandle>,
        claimed_app_id: String,
        claimed_app_display_name: Optional<String>,
        claimed_origin: Optional<String>,
        claimed_top_origin: Optional<String>,
        request: GetCredentialRequest,
        _options: HashMap<String, OwnedValue>,
    ) -> PortalResult<GetCredentialResponse, Error> {
        let app_validation_result = validate_app_details(
            connection,
            &header,
            claimed_app_id,
            claimed_app_display_name.into(),
            claimed_origin.into(),
            claimed_top_origin.into(),
        )
        .await;
        let (requesting_app, origin) = match app_validation_result {
            Ok(validated) => validated,
            Err(err) => return Err(err).into(),
        };

        tracing::debug!(
            ?requesting_app,
            ?origin,
            ?request,
            ?parent_window,
            ?portal_request_handle,
            "Received request for retrieving credential"
        );
        let response = handle_get_credential(
            &self.controller,
            request,
            origin,
            Some(requesting_app),
            parent_window.into(),
        )
        .await
        .map_err(Error::from);
        response.into()
    }

    fn get_client_capabilities(&self) -> fdo::Result<GetClientCapabilitiesResponse> {
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

async fn handle_create_credential<C: CredentialRequestController>(
    controller: &AsyncMutex<C>,
    request: CreateCredentialRequest,
    origin: Origin,
    requesting_app: Option<RequestingApplication>,
    parent_window: Option<WindowHandle>,
) -> Result<CreateCredentialResponse, WebAuthnError> {
    if let ("publicKey", Some(_)) = (request.r#type.as_ref(), &request.public_key) {
        // TODO: assert that RP ID is bound to origin:
        // - if RP ID is not set, set the RP ID to the origin's effective domain
        // - if RP ID is set, assert that it matches origin's effective domain
        // - if RP ID is set, but origin's effective domain doesn't match
        //    - query for related origins, if supported
        //    - fail if not supported, or if RP ID doesn't match any related origins.
        let (make_cred_request, client_data_json) =
            create_credential_request_try_into_ctap2(&request, &origin).map_err(|e| {
                if let WebAuthnError::TypeError = e {
                    tracing::error!("Could not parse passkey creation request. Rejecting request.");
                }
                e
            })?;
        if make_cred_request.algorithms.is_empty() {
            tracing::info!("No supported algorithms given in request. Rejecting request.");
            return Err(WebAuthnError::NotSupportedError);
        }
        let cred_request = CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request);

        let response = controller
            .lock()
            .await
            .request_credential(requesting_app, cred_request, parent_window.into())
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
        Err(WebAuthnError::TypeError)
    }
}

async fn handle_get_credential<C: CredentialRequestController>(
    controller: &AsyncMutex<C>,
    request: GetCredentialRequest,
    origin: Origin,
    requesting_app: Option<RequestingApplication>,
    parent_window: Option<WindowHandle>,
) -> Result<GetCredentialResponse, WebAuthnError> {
    if let ("publicKey", Some(_)) = (request.r#type.as_ref(), &request.public_key) {
        // Setup request

        // TODO: assert that RP ID is bound to origin:
        // - if RP ID is not set, set the RP ID to the origin's effective domain
        // - if RP ID is set, assert that it matches origin's effective domain
        // - if RP ID is set, but origin's effective domain doesn't match
        //    - query for related origins, if supported
        //    - fail if not supported, or if RP ID doesn't match any related origins.
        let (get_cred_request, client_data_json) =
            get_credential_request_try_into_ctap2(&request, &origin).map_err(|e| {
                tracing::error!("Could not parse passkey assertion request: {e:?}");
                WebAuthnError::TypeError
            })?;
        let cred_request = CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request);

        let response = controller
            .lock()
            .await
            .request_credential(requesting_app, cred_request, parent_window.into())
            .await?;

        if let CredentialResponse::GetPublicKeyCredentialResponse(cred_response) = response {
            let public_key_response = get_credential_response_try_from_ctap2(
                &cred_response,
                client_data_json,
            )
            .map_err(|err| {
                tracing::error!("Failed to parse credential response from authenticator: {err}");
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

async fn validate_app_details(
    connection: &Connection,
    header: &Header<'_>,
    claimed_app_id: String,
    claimed_app_display_name: Option<String>,
    claimed_origin: Option<String>,
    claimed_top_origin: Option<String>,
) -> Result<(RequestingApplication, Origin), Error> {
    if claimed_app_id.is_empty() || !should_trust_app_id(connection, &header).await {
        tracing::warn!("App ID could not be determined. Rejecting request.");
        return Err(Error::SecurityError);
    }
    // Now we can trust these app detail parameters.
    let app_id = format!("app:{claimed_app_id}");
    let display_name = claimed_app_display_name.unwrap_or_default();

    // Verify that the origin is valid for the given app ID.
    let origin = check_origin_from_app(
        &app_id,
        claimed_origin.as_deref(),
        claimed_top_origin.as_deref(),
    )?;
    let app_details = RequestingApplication {
        name: Some(display_name).into(),
        path: app_id,
        pid: 0,
    };
    Ok((app_details, origin))
}

async fn should_trust_app_id(connection: &Connection, header: &Header<'_>) -> bool {
    let Some(unique_name) = header.sender() else {
        return false;
    };

    let Some(pid) = query_peer_pid_via_fdinfo(connection, unique_name).await else {
        return false;
    };

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
        "mount namespace:\n  ours:  {:?}\n  theirs: {:?}",
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
    return trusted_callers.as_slice().contains(&exe_path.to_string());
}

fn check_origin_from_app<'a>(
    app_id: &str,
    origin: Option<&str>,
    top_origin: Option<&str>,
) -> Result<Origin, WebAuthnError> {
    let is_privileged_client = {
        let trusted_clients = ["app:org.mozilla.firefox"];
        let mut privileged = trusted_clients.contains(&app_id.as_ref());
        if cfg!(debug_assertions) && !privileged {
            let trusted_clients_env = std::env::var("CREDSD_TRUSTED_APP_IDS").unwrap_or_default();
            privileged = trusted_clients_env
                .split(',')
                .map(String::from)
                .any(|c| app_id == c);
        }
        privileged
    };
    if is_privileged_client {
        check_origin_from_privileged_client(origin, top_origin)
    } else {
        Ok(Origin::AppId(app_id.to_string()))
    }
}

fn check_origin_from_privileged_client(
    origin: Option<&str>,
    top_origin: Option<&str>,
) -> Result<Origin, WebAuthnError> {
    let origin = match (origin, top_origin) {
        (Some(origin), top_origin) => {
            if !origin.starts_with("https://") {
                tracing::warn!(
                    "Caller requested non-HTTPS schemed origin, which is not supported."
                );
                return Err(WebAuthnError::SecurityError);
            }
            if let Some(top_origin) = top_origin {
                if origin == top_origin {
                    Origin::SameOrigin(origin.to_string())
                } else {
                    Origin::CrossOrigin((origin.to_string(), top_origin.to_string()))
                }
            } else {
                Origin::SameOrigin(origin.to_string())
            }
        }
        (None, Some(_)) => {
            tracing::warn!("Top origin cannot be set if origin is not set.");
            return Err(WebAuthnError::SecurityError);
        }
        (None, None) => {
            tracing::warn!("No origin given. Rejecting request.");
            return Err(WebAuthnError::SecurityError);
        }
    };

    if let Origin::CrossOrigin(_) = origin {
        tracing::warn!("Client attempted to issue cross-origin request for credentials, which are not supported by this platform.");
        return Err(WebAuthnError::NotAllowedError);
    };
    Ok(origin)
}

#[allow(clippy::enum_variant_names)]
#[derive(DBusError, Debug)]
#[zbus(prefix = "xyz.iinuwa.credentialsd")]
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

#[repr(u32)]
#[derive(Serialize)]
enum PortalResponse {
    Success = 0,
    Cancelled = 1,
    Other = 2,
}

#[derive(Type)]
#[zvariant(signature = "ua{sv}")]
struct PortalResult<T, E> {
    inner: Result<T, E>,
}

impl<T, E> Serialize for PortalResult<T, E>
where
    T: Serialize + Type,
    E: std::error::Error,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_tuple(2)?;
        match &self.inner {
            Err(err) => {
                map.serialize_element(&(PortalResponse::Other as u32))?;
                map.serialize_element(&HashMap::<&str, Value<'_>>::from([(
                    "error",
                    Value::Str(err.to_string().into()),
                )]))?;
            }
            Ok(response) => {
                map.serialize_element(&(PortalResponse::Success as u32))?;
                map.serialize_element(&response)?;
            }
        };
        map.end()
    }
}

impl<T, E> From<Result<T, E>> for PortalResult<T, E> {
    fn from(value: Result<T, E>) -> Self {
        PortalResult { inner: value }
    }
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
    use credentialsd_common::model::WebAuthnError;

    use crate::webauthn::Origin;

    use super::check_origin_from_privileged_client;
    fn check_same_origin(origin: &str) -> Result<Origin, WebAuthnError> {
        check_origin_from_privileged_client(Some(origin), Some(origin))
    }

    #[test]
    fn test_only_https_origins() {
        assert!(matches!(
            check_same_origin("https://example.com"),
            Ok(Origin::SameOrigin(o)) if o == "https://example.com"
        ))
    }

    #[test]
    fn test_privileged_client_cannot_set_http_origins() {
        assert!(matches!(
            check_same_origin("http://example.com"),
            Err(WebAuthnError::SecurityError)
        ));
    }
}
