use std::{os::fd::AsRawFd, sync::Arc};

use tokio::sync::Mutex as AsyncMutex;
use zbus::{
    fdo, interface,
    message::Header,
    names::{BusName, UniqueName},
    zvariant::Optional,
    Connection, DBusError,
};

use credentialsd_common::{
    model::{GetClientCapabilitiesResponse, RequestingApplication, WebAuthnError},
    server::{
        CreateCredentialRequest, CreateCredentialResponse, GetCredentialRequest,
        GetCredentialResponse, WindowHandle,
    },
};

use crate::webauthn::{AppId, NavigationContext, Origin};

use super::{
    check_origin_from_app, check_origin_from_privileged_client, get_app_info_from_pid,
    GatewayService,
};

pub const SERVICE_NAME: &str = "xyz.iinuwa.credentialsd.Credentials";
pub const SERVICE_PATH: &str = "/xyz/iinuwa/credentialsd/Credentials";

pub(super) async fn start_dbus_gateway(
    svc: Arc<AsyncMutex<GatewayService>>,
) -> Result<Connection, zbus::Error> {
    zbus::connection::Builder::session()
        .inspect_err(|err| {
            tracing::error!("Failed to connect to D-Bus session: {err}");
        })?
        .name(SERVICE_NAME)?
        .serve_at(
            SERVICE_PATH,
            CredentialGateway {
                gateway_service: svc.clone(),
            },
        )?
        .build()
        .await
}

/// Struct to hold state for the D-Bus interface.
struct CredentialGateway {
    /// Service responsible for processing credential requests.
    gateway_service: Arc<AsyncMutex<GatewayService>>,
}

/// These are public methods that can be called by arbitrary clients to begin a
/// credential flow.
///
/// The D-Bus interface is responsible for authorizing the client and collecting
/// the contextual information about the client to pass onto the GatewayService
/// for evaluation.
#[interface(name = "xyz.iinuwa.credentialsd.Credentials1")]
impl CredentialGateway {
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
        let Some(origin) = request
            .origin
            .as_ref()
            .map(|o| {
                o.parse::<Origin>().map_err(|_| {
                    tracing::warn!("Invalid origin specified: {:?}", request.origin);
                    Error::SecurityError
                })
            })
            .transpose()?
        else {
            tracing::warn!(
            "Caller requested implicit origin, which is not yet implemented. Rejecting request."
        );
            return Err(Error::SecurityError);
        };
        let request_environment = check_origin_from_privileged_client(origin, top_origin)?;
        // Find out where this request is coming from (which application is requesting this)
        let requesting_app = query_connection_peer_binary(header, connection).await;
        let response = self
            .gateway_service
            .lock()
            .await
            .handle_create_credential(
                request,
                request_environment,
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
        let Some(origin) = request
            .origin
            .as_ref()
            .map(|o| {
                o.parse::<Origin>().map_err(|_| {
                    tracing::warn!("Invalid origin specified: {:?}", request.origin);
                    Error::SecurityError
                })
            })
            .transpose()?
        else {
            tracing::warn!(
            "Caller requested implicit origin, which is not yet implemented. Rejecting request."
        );
            return Err(Error::SecurityError);
        };
        let request_environment = check_origin_from_privileged_client(origin, top_origin)?;
        // Find out where this request is coming from (which application is requesting this)
        let requesting_app = query_connection_peer_binary(header, connection).await;
        let response = self
            .gateway_service
            .lock()
            .await
            .handle_get_credential(
                request,
                request_environment,
                requesting_app,
                parent_window.into(),
            )
            .await?;
        Ok(response)
    }

    async fn get_client_capabilities(&self) -> fdo::Result<GetClientCapabilitiesResponse> {
        let capabilities = self
            .gateway_service
            .lock()
            .await
            .handle_get_client_capabilities();
        Ok(capabilities)
    }
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

async fn validate_app_details(
    connection: &Connection,
    header: &Header<'_>,
    claimed_app_id: String,
    claimed_app_display_name: Option<String>,
    claimed_origin: Option<String>,
    claimed_top_origin: Option<String>,
) -> Result<(RequestingApplication, NavigationContext), Error> {
    let Some(unique_name) = header.sender() else {
        return Err(Error::SecurityError);
    };

    let Some(pid) = query_peer_pid_via_fdinfo(connection, unique_name).await else {
        return Err(Error::SecurityError);
    };

    if claimed_app_id.is_empty() || !super::should_trust_app_id(pid).await {
        tracing::warn!("App ID could not be determined. Rejecting request.");
        return Err(Error::SecurityError);
    }
    // Now we can trust these app detail parameters.
    let Ok(app_id) = claimed_app_id.parse::<AppId>() else {
        tracing::warn!("Invalid app ID passed: {claimed_app_id}");
        return Err(Error::SecurityError);
    };
    let display_name = claimed_app_display_name.unwrap_or_default();

    // Verify that the origin is valid for the given app ID.
    let claimed_origin = claimed_origin
        .map(|o| {
            o.parse().map_err(|_| {
                tracing::warn!("Invalid origin passed: {o}");
                Error::SecurityError
            })
        })
        .transpose()?;
    let request_env = if let Some(claimed_origin) = claimed_origin {
        let claimed_top_origin = claimed_top_origin
            .map(|o| {
                o.parse().map_err(|_| {
                    tracing::warn!("Invalid origin passed: {o}");
                    Error::SecurityError
                })
            })
            .transpose()?;
        check_origin_from_app(&app_id, claimed_origin, claimed_top_origin)?
    } else {
        NavigationContext::SameOrigin(Origin::AppId(app_id))
    };
    let app_details = RequestingApplication {
        name: Some(display_name).into(),
        path_or_app_id: claimed_app_id,
        pid,
    };
    Ok((app_details, request_env))
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

    get_app_info_from_pid(pid)
}
