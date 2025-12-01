//! Implements the service that public clients can connect to. Responsible for
//! authorizing clients for origins and validating request parameters.

use std::sync::Arc;

use credentialsd_common::{
    model::{
        CredentialRequest, CredentialResponse, GetClientCapabilitiesResponse,
        RequestingApplication, WebAuthnError,
    },
    server::{
        CreateCredentialRequest, CreateCredentialResponse, GetCredentialRequest,
        GetCredentialResponse, WindowHandle,
    },
};
use tokio::sync::Mutex as AsyncMutex;
use zbus::{
    Connection, DBusError, fdo, interface, message::Header, names::{BusName, UniqueName}, zvariant::Optional
};

use crate::dbus::{
    create_credential_request_try_into_ctap2, create_credential_response_try_from_ctap2,
    get_credential_request_try_into_ctap2, get_credential_response_try_from_ctap2,
    CredentialRequestController,
};
use std::os::fd::AsRawFd;

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

async fn query_peer_pid_via_dbus(
    connection: &Connection,
    sender_unique_name: &UniqueName<'_>,
) -> Option<u32> {
    // Use the connection to query the D-Bus daemon for more info
    let proxy = match zbus::Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to establish DBus proxy to query peer info: {e:?}");
            return None;
        }
    };

    // Get the Process ID (PID) of the peer
    let pid_result = match proxy
        .call_method("GetConnectionUnixProcessID", &(sender_unique_name))
        .await
    {
        Ok(pid) => pid,
        Err(e) => {
            tracing::error!("Failed to get peer PID via DBus: {e:?}");
            return None;
        }
    };
    let pid: u32 = match pid_result.body().deserialize() {
        Ok(pid) => pid,
        Err(e) => {
            tracing::error!("Retrieved peer PID is not an integer: {e:?}");
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

    // Get the senders PID.
    //
    // First, try to get the PID via the more secure fdinfo
    let mut pid = query_peer_pid_via_fdinfo(connection, sender_unique_name).await;
    // If that fails, we fall back to asking dbus directly for the peers PID
    if pid.is_none() {
        pid = query_peer_pid_via_dbus(connection, sender_unique_name).await;
    }

    let Some(pid) = pid else {
        tracing::error!("Failed to determine peers PID. Skipping application details query.");
        return None;
    };

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
        name: command_name,
        path: exe_path,
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
        request: CreateCredentialRequest,
        window_handle: Optional<WindowHandle>,
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
            // Find out where this request is coming from (which application is requesting this)
            let requesting_app = query_connection_peer_binary(header, connection).await;
            let cred_request =
                CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request);

            let response = self
                .controller
                .lock()
                .await
                .request_credential(requesting_app, cred_request, window_handle.into())
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
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        request: GetCredentialRequest,
        window_handle: Optional<WindowHandle>,
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
            // Find out where this request is coming from (which application is requesting this)
            let requesting_app = query_connection_peer_binary(header, connection).await;

            let response = self
                .controller
                .lock()
                .await
                .request_credential(requesting_app, cred_request, window_handle.into())
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
