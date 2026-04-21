use std::{collections::HashMap, fmt::Display, os::fd::AsRawFd, sync::Arc};

use serde::{ser::SerializeTuple, Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use zbus::{
    fdo, interface,
    message::Header,
    names::{BusName, UniqueName},
    zvariant::{DeserializeDict, Optional, Type, Value},
    Connection, DBusError,
};

use credentialsd_common::{
    model::{GetClientCapabilitiesResponse, RequestingApplication, WebAuthnError},
    server::{
        CreateCredentialRequest, CreateCredentialResponse, CreatePublicKeyCredentialRequest,
        GetCredentialRequest, GetCredentialResponse, GetPublicKeyCredentialRequest, WindowHandle,
    },
};

use crate::webauthn::{AppId, Origin};

use super::{
    check_origin_from_app, get_app_info_from_pid, GatewayService, RequestContext, RequestKind,
};

pub const SERVICE_NAME: &str = "xyz.iinuwa.credentialsd.Credentials";
pub const SERVICE_PATH: &str = "/xyz/iinuwa/credentialsd/Credentials";
pub const PORTAL_SERVICE_PATH: &str = "/org/freedesktop/portal/desktop";

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
        .serve_at(
            PORTAL_SERVICE_PATH,
            CredentialPortalGateway {
                gateway_service: svc,
            },
        )?
        .build()
        .await
}

/// Struct to hold state for the privileged D-Bus interface.
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
        let context = extract_client_details(
            header,
            connection,
            request.origin.as_ref().cloned(),
            request.is_same_origin.unwrap_or_default(),
        )
        .await?;

        let response = self
            .gateway_service
            .lock()
            .await
            .handle_create_credential(request, context, parent_window.into())
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
        let context = extract_client_details(
            header,
            connection,
            request.origin.as_ref().cloned(),
            request.is_same_origin.unwrap_or_default(),
        )
        .await?;

        let response = self
            .gateway_service
            .lock()
            .await
            .handle_get_credential(request, context, parent_window.into())
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

/// Returns contextual details about the client and the request needed for
/// authorization.
async fn extract_client_details(
    header: Header<'_>,
    connection: &Connection,
    origin: Option<String>,
    is_same_origin: bool,
) -> Result<RequestContext, Error> {
    let top_origin = if is_same_origin {
        None
    } else {
        // TODO: Once we modify the models to convey the top-origin in cross origin requests to the UI, we can remove this error message.
        // We should still reject cross-origin requests for conditionally-mediated requests.
        tracing::warn!("Client attempted to issue cross-origin request for credentials, which are not supported by this platform.");
        return Err(WebAuthnError::NotAllowedError.into());
    };
    /*
    let top_origin =
        top_origin.as_ref()
        .map(|o| o.parse::<Origin>())
        .transpose()
        .map_err(|err| {
            tracing::warn!(%err, "Invalid top origin specified: {:?}", client_details.top_origin);
            WebAuthnError::SecurityError
        })?;
    */

    let Some(origin) = origin.as_ref().cloned() else {
        tracing::warn!(
            "Caller requested implicit origin, which is not yet implemented. Rejecting request."
        );
        return Err(Error::SecurityError);
    };
    let origin = origin.parse::<Origin>().map_err(|err| {
        tracing::warn!(%err, "Invalid origin specified: {:?}", origin);
        WebAuthnError::SecurityError
    })?;

    // Find out where this request is coming from (which application is requesting this)
    let requesting_app = query_connection_peer_binary(header, connection)
        .await
        .ok_or_else(|| {
            tracing::error!("Could not retrieve client details from D-Bus connection");
            Error::SecurityError
        })?;
    Ok(RequestContext {
        app_id: "xyz.iinuwa.credentialsd.CredentialGateway".parse().unwrap(), // hardcoding this for now; this will be obsolete soon
        app_name: requesting_app.name.as_ref().unwrap().clone(),
        pid: requesting_app.pid,
        request_kind: RequestKind::Privileged { origin, top_origin },
    })
}

/// Struct to hold state for the portal D-Bus interface.
struct CredentialPortalGateway {
    /// Service responsible for processing credential requests.
    gateway_service: Arc<AsyncMutex<GatewayService>>,
}

/// These are public methods that can be called by arbitrary clients to begin a
/// credential flow.
///
/// The D-Bus interface is responsible for authorizing the client and collecting
/// the contextual information about the client to pass onto the GatewayService
/// for evaluation.
#[interface(name = "org.freedesktop.handler.portal.experimental.Credential")]
impl CredentialPortalGateway {
    #[zbus(out_args("response", "results"))]
    async fn create_credential(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        parent_window: Optional<WindowHandle>,
        origin: String,
        cred_type: CredentialType,
        options: CreateCredentialPortalOptions,
        claimed_app_id: String,
        claimed_app_display_name: Optional<String>,
    ) -> PortalResult<CreateCredentialResponse, Error> {
        let CreateCredentialPortalOptions {
            top_origin,
            public_key,
        } = options;

        let request_json = match (&cred_type, public_key) {
            (CredentialType::PublicKey, Some(json)) => json,
            (CredentialType::PublicKey, None) => {
                tracing::warn!("Client did not send `public_key` request with type `publicKey`");
                return Err(Error::TypeError).into();
            }
        };

        let app_validation_result = validate_app_details(
            connection,
            &header,
            claimed_app_id,
            claimed_app_display_name.into(),
            origin.clone(),
            top_origin.clone().into(),
        )
        .await;
        let context = match app_validation_result {
            Ok(context) => context,
            Err(err) => return Err(err).into(),
        };

        tracing::debug!(
            ?context,
            ?request_json,
            ?parent_window,
            "Received request for creating credential"
        );

        let request = CreateCredentialRequest {
            origin: Some(origin.clone()),
            is_same_origin: Some(top_origin.is_none()),
            r#type: cred_type.to_string(),
            public_key: Some(CreatePublicKeyCredentialRequest { request_json }),
        };

        let response = self
            .gateway_service
            .lock()
            .await
            .handle_create_credential(request, context, parent_window.into())
            .await
            .map_err(Error::from);

        response.into()
    }

    #[zbus(out_args("response", "results"))]
    async fn get_credential(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        parent_window: Optional<WindowHandle>,
        origin: String,
        options: GetCredentialPortalOptions,
        claimed_app_id: String,
        claimed_app_display_name: Optional<String>,
    ) -> PortalResult<GetCredentialResponse, Error> {
        let GetCredentialPortalOptions {
            top_origin,
            public_key,
        } = options;
        let app_validation_result = validate_app_details(
            connection,
            &header,
            claimed_app_id,
            claimed_app_display_name.into(),
            origin.clone(),
            top_origin.clone().into(),
        )
        .await;

        let Some(request_json) = public_key else {
            tracing::warn!("Client did not send parameters for any valid credential type.");
            return Err(Error::TypeError).into();
        };

        let context = match app_validation_result {
            Ok(context) => context,
            Err(err) => return Err(err).into(),
        };

        tracing::debug!(
            ?context,
            %request_json,
            ?parent_window,
            "Received request for retrieving credential"
        );

        let request = GetCredentialRequest {
            origin: Some(origin),
            is_same_origin: Some(top_origin.is_none()),
            public_key: Some(GetPublicKeyCredentialRequest { request_json }),
        };

        let response = self
            .gateway_service
            .lock()
            .await
            .handle_get_credential(request, context, parent_window.into())
            .await
            .map_err(Error::from);
        response.into()
    }
}

#[derive(Debug, Deserialize, Type)]
#[zvariant(signature = "s")]
enum CredentialType {
    #[serde(rename = "publicKey")]
    PublicKey,
}

impl Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialType::PublicKey => f.write_str("publicKey"),
        }
    }
}

#[derive(Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
struct CreateCredentialPortalOptions {
    /// The top-level origin of the client window for cross-origin requests.
    /// If omitted, denotes a same-origin request.
    top_origin: Option<String>,

    /// A string of JSON that corresponds to the WebAuthn
    /// [PublicKeyCredentialRequestOptions](https://www.w3.org/TR/webauthn-3/#publickeycredential)
    /// type.
    public_key: Option<String>,
}

#[derive(Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
struct GetCredentialPortalOptions {
    /// The top-level origin of the client window for cross-origin requests.
    /// If omitted, denotes a same-origin request.
    top_origin: Option<String>,

    /// A string of JSON that corresponds to the WebAuthn
    /// [PublicKeyCredentialRequestOptions](https://www.w3.org/TR/webauthn-3/#publickeycredential)
    /// type.
    public_key: Option<String>,
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

async fn validate_app_details(
    connection: &Connection,
    header: &Header<'_>,
    claimed_app_id: String,
    claimed_app_display_name: Option<String>,
    claimed_origin: String,
    claimed_top_origin: Option<String>,
) -> Result<RequestContext, Error> {
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
    let claimed_origin = claimed_origin.parse().map_err(|err| {
        tracing::warn!(%err, "Invalid origin passed: {claimed_origin}");
        Error::SecurityError
    })?;
    let claimed_top_origin = claimed_top_origin
        .map(|o| {
            o.parse().map_err(|_| {
                tracing::warn!("Invalid origin passed: {o}");
                Error::SecurityError
            })
        })
        .transpose()?;
    let request_kind = check_origin_from_app(&app_id, claimed_origin, claimed_top_origin)?;

    Ok(RequestContext {
        app_id,
        app_name: display_name,
        pid,
        request_kind,
    })
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
