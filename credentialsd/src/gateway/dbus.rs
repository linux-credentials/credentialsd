use std::{
    collections::HashMap,
    fmt::Display,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    str::FromStr,
    sync::Arc,
};

use serde::{Deserialize, Serialize, ser::SerializeTuple};
use tokio::sync::Mutex as AsyncMutex;
use zbus::{
    Connection, DBusError,
    fdo::PropertiesProxy,
    interface,
    message::Header,
    names::{BusName, InterfaceName, UniqueName},
    zvariant::{self, DeserializeDict, Optional, OwnedFd, OwnedValue, Type, Value},
};

use credentialsd_common::model::WindowHandle;
use zbus_systemd::systemd1::ManagerProxy;

use crate::{
    DBUS_SERVICE_NAME,
    gateway::{
        CreateCredentialRequest, CreateCredentialResponse, CreatePublicKeyCredentialRequest,
        GetCredentialRequest, GetCredentialResponse, GetPublicKeyCredentialRequest, WebAuthnError,
    },
    webauthn::AppId,
};

use super::{GatewayService, RequestContext, check_origin_from_app};

pub const PORTAL_SERVICE_PATH: &str = "/org/freedesktop/portal/desktop";

pub(super) async fn start_dbus_gateway(
    svc: Arc<AsyncMutex<GatewayService>>,
) -> Result<Connection, zbus::Error> {
    zbus::connection::Builder::session()
        .inspect_err(|err| {
            tracing::error!("Failed to connect to D-Bus session: {err}");
        })?
        .name(DBUS_SERVICE_NAME)?
        .serve_at(
            PORTAL_SERVICE_PATH,
            CredentialPortalGateway {
                gateway_service: svc,
            },
        )?
        .build()
        .await
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
// D-Bus has long argument signatures.
#[expect(clippy::too_many_arguments)]
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
    ) -> PortalResult<CreateCredentialResponse, Error> {
        let CreateCredentialPortalOptions {
            activation_token,
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
            origin.clone(),
            top_origin.clone(),
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
            r#type: cred_type.to_string(),
            public_key: Some(CreatePublicKeyCredentialRequest { request_json }),
        };

        let response = self
            .gateway_service
            .lock()
            .await
            .handle_create_credential(request, context, parent_window.into(), activation_token)
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
    ) -> PortalResult<GetCredentialResponse, Error> {
        let GetCredentialPortalOptions {
            activation_token,
            top_origin,
            public_key,
        } = options;
        let app_validation_result = validate_app_details(
            connection,
            &header,
            claimed_app_id,
            origin.clone(),
            top_origin.clone(),
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

        tracing::trace!(
            ?context,
            %request_json,
            ?parent_window,
            "Received request for retrieving credential"
        );

        let request = GetCredentialRequest {
            public_key: Some(GetPublicKeyCredentialRequest { request_json }),
        };

        let response = self
            .gateway_service
            .lock()
            .await
            .handle_get_credential(request, context, parent_window.into(), activation_token)
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
    /// A token that can be used to activate the UI window.
    activation_token: Option<String>,

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
    /// A token that can be used to activate the UI window.
    activation_token: Option<String>,

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
    // Cancelled = 1,
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
    claimed_origin: String,
    claimed_top_origin: Option<String>,
) -> Result<RequestContext, Error> {
    let Some(unique_name) = header.sender() else {
        return Err(Error::SecurityError);
    };

    let Some(service_info) = query_peer_service_info(connection, unique_name).await else {
        return Err(Error::SecurityError);
    };

    if claimed_app_id.is_empty() || !super::should_trust_app_id(&service_info).await {
        tracing::warn!(
            ?claimed_app_id,
            "App ID could not be verified. Rejecting request."
        );
        return Err(Error::SecurityError);
    }
    // Now we can trust these app detail parameters.
    let Ok(app_id) = claimed_app_id.parse::<AppId>() else {
        tracing::warn!("Invalid app ID passed: {claimed_app_id}");
        return Err(Error::SecurityError);
    };

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
        pid: service_info.pid,
        request_kind,
    })
}

pub struct ServiceInfo {
    pub names: Vec<String>,
    pub executable: String,
    pub pid: u32,
}

async fn query_peer_service_info(
    connection: &Connection,
    sender_unique_name: &UniqueName<'_>,
) -> Option<ServiceInfo> {
    let dbus_proxy = match zbus::fdo::DBusProxy::new(connection).await {
        Ok(p) => p,
        Err(error) => {
            tracing::error!(
                ?error,
                "Failed to establish DBus proxy to query service name info."
            );
            return None;
        }
    };

    let manager_proxy = match ManagerProxy::new(connection).await {
        Ok(p) => p,
        Err(error) => {
            tracing::error!(
                ?error,
                "Failed to establish DBus proxy to query service name info."
            );
            return None;
        }
    };

    let peer_credentials = match dbus_proxy
        .get_connection_credentials(BusName::from(sender_unique_name.to_owned()))
        .await
    {
        Ok(c) => c,
        Err(error) => {
            tracing::error!(?error, "Failed to get peer credentials");
            return None;
        }
    };

    let Some(pidfd) = peer_credentials
        .process_fd()
        .and_then(|p| p.as_fd().try_clone_to_owned().ok())
    else {
        tracing::error!("Failed to get process fd from peer credentials");
        return None;
    };

    let Some(pid) = read_pid_from_procfs(pidfd.as_fd()) else {
        tracing::error!("Failed to read PID from fdinfo");
        return None;
    };

    let unit = match manager_proxy.get_unit_by_pidfd(OwnedFd::from(pidfd)).await {
        Ok(unit) => unit,
        Err(error) => {
            tracing::error!(?error, "Failed to get systemd unit from pidfd.");
            return None;
        }
    };

    let properties_proxy =
        match PropertiesProxy::new(connection, "org.freedesktop.systemd1", unit.0).await {
            Ok(p) => p,
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Failed to establish DBus proxy to query unit properties."
                );
                return None;
            }
        };

    let names = read_dbus_property(
        &properties_proxy,
        InterfaceName::from_static_str("org.freedesktop.systemd1.Unit").unwrap(),
        "Names",
    )
    .await?;
    let executable: Vec<ExecCommand> = read_dbus_property(
        &properties_proxy,
        InterfaceName::from_static_str("org.freedesktop.systemd1.Service").unwrap(),
        "ExecStart",
    )
    .await?;

    let Some((executable, pid)) = executable
        .into_iter()
        .find(|e| e.pid == pid)
        .map(|e| (e.path, e.pid))
    else {
        tracing::error!(?names, pid, "Couldn't find process in systemd unit.");
        return None;
    };

    Some(ServiceInfo {
        names,
        executable,
        pid,
    })
}

fn read_pid_from_procfs(pidfd: BorrowedFd) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
        .inspect_err(|error| tracing::error!(%error, "Failed to read fdinfo from procfs"))
        .ok()?
        .lines()
        .find(|line| line.starts_with("Pid:"))
        .map(|line| line[4..].trim())
        .and_then(|line| {
            u32::from_str(line)
                .inspect_err(
                    |error| tracing::error!(%error, "Failed to parse PID from fdinfo entry."),
                )
                .ok()
        })
}

#[derive(Debug, Clone, Type, Deserialize, Value, OwnedValue)]
struct ExecCommand {
    pub path: String,
    pub argv: Vec<String>,
    pub ignore_failure: bool,
    pub start_timestamp: u64,
    pub start_timestamp_monotonic: u64,
    pub exit_timestamp: u64,
    pub exit_timestamp_monotonic: u64,
    pub pid: u32,
    pub code: i32,
    pub status: i32,
}

async fn read_dbus_property<'a, T>(
    proxy: &PropertiesProxy<'a>,
    interface: InterfaceName<'a>,
    name: &str,
) -> Option<T>
where
    T: TryFrom<OwnedValue, Error = zvariant::Error>,
{
    Some(match proxy.get(interface, name).await {
        Ok(n) => match n.try_into() {
            Ok(n) => n,
            Err(error) => {
                tracing::error!(?error, "Failed to read DBus response data.");
                return None;
            }
        },
        Err(error) => {
            tracing::error!(?error, property = name, "Failed to read DBus property.");
            return None;
        }
    })
}
