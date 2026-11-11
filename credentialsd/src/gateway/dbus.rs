use std::{
    collections::HashMap,
    fmt::Display,
    os::fd::{AsFd, OwnedFd},
    sync::Arc,
};

use serde::{Deserialize, Serialize, ser::SerializeTuple};
use tokio::sync::Mutex as AsyncMutex;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use zbus::{
    Connection, DBusError, fdo, interface,
    message::Header,
    names::{BusName, OwnedUniqueName, OwnedWellKnownName, UniqueName},
    zvariant::{DeserializeDict, Optional, OwnedObjectPath, Type, Value},
};

use credentialsd_common::model::WindowHandle;

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

/// Prefix of the request object paths created by xdg-desktop-portal.
const PORTAL_REQUEST_PATH_PREFIX: &str = "/org/freedesktop/portal/desktop/request/";

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
            request_handle,
            ui_backend,
        } = options;

        let request_json = match (&cred_type, public_key) {
            (CredentialType::PublicKey, Some(json)) => json,
            (CredentialType::PublicKey, None) => {
                tracing::warn!("Client did not send `public_key` request with type `publicKey`");
                return Err(Error::InvalidOptions).into();
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
        let ui_backend = match parse_ui_backend(ui_backend) {
            Ok(ui_backend) => ui_backend,
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

        run_ceremony(
            connection,
            header.sender(),
            request_handle,
            |cancellation| async move {
                let Some(svc) = cancellation
                    .run_until_cancelled(self.gateway_service.lock())
                    .await
                else {
                    return Err(Error::Aborted);
                };
                svc.handle_create_credential(
                    request,
                    context,
                    cancellation,
                    parent_window.into(),
                    activation_token,
                    ui_backend,
                )
                .await
                .map_err(Error::from)
            },
        )
        .await
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
            request_handle,
            ui_backend,
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
            return Err(Error::InvalidOptions).into();
        };

        let context = match app_validation_result {
            Ok(context) => context,
            Err(err) => return Err(err).into(),
        };
        let ui_backend = match parse_ui_backend(ui_backend) {
            Ok(ui_backend) => ui_backend,
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

        run_ceremony(
            connection,
            header.sender(),
            request_handle,
            |cancellation| async move {
                let Some(svc) = cancellation
                    .run_until_cancelled(self.gateway_service.lock())
                    .await
                else {
                    return Err(Error::Aborted);
                };
                svc.handle_get_credential(
                    request,
                    context,
                    cancellation,
                    parent_window.into(),
                    activation_token,
                    ui_backend,
                )
                .await
                .map_err(Error::from)
            },
        )
        .await
    }
}

/// Runs a ceremony that the client can cancel.
///
/// If `request_handle` is set, an
/// `org.freedesktop.handler.portal.experimental.Request` object is exported at
/// that path for the duration of the ceremony. Calling `Close()` on it cancels
/// the token passed to `ceremony`, and the ceremony is reported as cancelled.
async fn run_ceremony<T, F, Fut>(
    connection: &Connection,
    sender: Option<&UniqueName<'_>>,
    request_handle: Option<OwnedObjectPath>,
    ceremony: F,
) -> PortalResult<T, Error>
where
    F: FnOnce(CancellationToken) -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let cancellation = CancellationToken::new();
    // Cancel the request if the caller leaves the bus, e.g. because it crashed.
    let _caller_watch = match sender {
        Some(sender) => match watch_caller(connection, sender, cancellation.clone()).await {
            Ok(watch) => Some(watch),
            Err(err) => {
                tracing::warn!(%sender, %err, "Failed to watch caller for disconnection");
                None
            }
        },
        None => None,
    };

    let Some(request_handle) = request_handle else {
        let result = ceremony(cancellation.clone()).await;
        return ceremony_result(result, &cancellation, None);
    };

    let Some(sender) = sender else {
        return Err(Error::UntrustedCaller).into();
    };
    if !request_handle
        .as_str()
        .starts_with(PORTAL_REQUEST_PATH_PREFIX)
    {
        tracing::warn!(%request_handle, "Invalid request handle passed. Rejecting request.");
        return Err(Error::InvalidOptions).into();
    }
    let request = HandlerRequest {
        caller: sender.to_owned().into(),
        cancellation: cancellation.clone(),
    };
    match connection
        .object_server()
        .at(request_handle.as_ref(), request)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(%request_handle, "Request handle already in use. Rejecting request.");
            return Err(Error::InvalidOptions).into();
        }
        Err(err) => return Err(Error::ZBus(err)).into(),
    }

    let result = ceremony(cancellation.clone()).await;

    if let Err(err) = connection
        .object_server()
        .remove::<HandlerRequest, _>(request_handle.as_ref())
        .await
    {
        tracing::warn!(%request_handle, %err, "Failed to remove request handle after ceremony completed");
    }

    ceremony_result(result, &cancellation, Some(&request_handle))
}

/// Reports a ceremony that failed because it was cancelled as cancelled.
fn ceremony_result<T>(
    result: Result<T, Error>,
    cancellation: &CancellationToken,
    request_handle: Option<&OwnedObjectPath>,
) -> PortalResult<T, Error> {
    if result.is_err() && cancellation.is_cancelled() {
        tracing::debug!(?request_handle, "Request cancelled");
        PortalResult::cancelled()
    } else {
        result.into()
    }
}

/// Cancels `cancellation` once `caller` has left the bus.
///
/// Watching stops when the returned guard is dropped.
async fn watch_caller(
    connection: &Connection,
    caller: &UniqueName<'_>,
    cancellation: CancellationToken,
) -> zbus::Result<CallerWatch> {
    let dbus = fdo::DBusProxy::new(connection).await?;
    let mut changes = dbus
        .receive_name_owner_changed_with_args(&[(0, caller.as_str())])
        .await?;
    // The caller may have left before the match rule was added.
    if !dbus.name_has_owner(BusName::Unique(caller.clone())).await? {
        tracing::debug!(%caller, "Caller left the bus, cancelling request");
        cancellation.cancel();
    }
    let caller = caller.to_owned();
    let task = tokio::spawn(async move {
        while let Some(signal) = changes.next().await {
            // Unique names are never reused, so losing the owner means the
            // caller has disconnected.
            if signal.args().is_ok_and(|args| args.new_owner().is_none()) {
                tracing::debug!(%caller, "Caller left the bus, cancelling request");
                cancellation.cancel();
                break;
            }
        }
    });
    Ok(CallerWatch(task))
}

/// Stops watching the caller when dropped.
struct CallerWatch(tokio::task::JoinHandle<()>);

impl Drop for CallerWatch {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Request object that lets the caller cancel an in-flight ceremony.
///
/// This is part of the internal interface between xdg-desktop-portal and the
/// handler, not of the backend portal API: clients should close the
/// `org.freedesktop.portal.Request` object exported by xdg-desktop-portal, which
/// forwards the call here.
struct HandlerRequest {
    /// Unique bus name of the caller that started the ceremony.
    caller: OwnedUniqueName,
    cancellation: CancellationToken,
}

#[interface(name = "org.freedesktop.handler.portal.experimental.Request")]
impl HandlerRequest {
    async fn close(&self, #[zbus(header)] header: Header<'_>) -> fdo::Result<()> {
        if header.sender() != Some(&self.caller) {
            tracing::warn!(sender = ?header.sender(), "Rejecting request to close request from untrusted caller");
            return Err(fdo::Error::AccessDenied(
                "Only the caller that started the request may close it".to_string(),
            ));
        }
        self.cancellation.cancel();
        Ok(())
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

    /// Path at which to export an
    /// `org.freedesktop.handler.portal.experimental.Request`
    /// object that the caller can use to cancel the request.
    request_handle: Option<OwnedObjectPath>,

    /// D-Bus name of the `org.freedesktop.impl.portal.experimental.Credential`
    /// backend to show the UI with, as chosen by the portal configuration.
    /// If omitted, the default UI is used.
    ui_backend: Option<String>,
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

    /// Path at which to export an
    /// `org.freedesktop.handler.portal.experimental.Request`
    /// object that the caller can use to cancel the request.
    request_handle: Option<OwnedObjectPath>,

    /// D-Bus name of the `org.freedesktop.impl.portal.experimental.Credential`
    /// backend to show the UI with, as chosen by the portal configuration.
    /// If omitted, the default UI is used.
    ui_backend: Option<String>,
}

/// Errors returned over D-Bus. See [`WebAuthnError`] for their meaning.
#[derive(DBusError, Debug)]
#[zbus(prefix = "xyz.iinuwa.credentialsd")]
enum Error {
    #[zbus(error)]
    ZBus(zbus::Error),
    Aborted,
    UserVerificationUnsatisfiable,
    DiscoverableCredentialUnsatisfiable,
    CredentialExcluded,
    NotSupported,
    InvalidOrigin,
    UntrustedCaller,
    InvalidUserId,
    InvalidOptions,
    NotAllowed,
}

impl From<WebAuthnError> for Error {
    fn from(value: WebAuthnError) -> Self {
        match value {
            WebAuthnError::Aborted => Self::Aborted,
            WebAuthnError::UserVerificationUnsatisfiable => Self::UserVerificationUnsatisfiable,
            WebAuthnError::DiscoverableCredentialUnsatisfiable => {
                Self::DiscoverableCredentialUnsatisfiable
            }
            WebAuthnError::CredentialExcluded => Self::CredentialExcluded,
            WebAuthnError::NotSupported => Self::NotSupported,
            WebAuthnError::InvalidOrigin => Self::InvalidOrigin,
            WebAuthnError::UntrustedCaller => Self::UntrustedCaller,
            WebAuthnError::InvalidUserId => Self::InvalidUserId,
            WebAuthnError::InvalidOptions => Self::InvalidOptions,
            WebAuthnError::NotAllowed => Self::NotAllowed,
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
    /// `None` if the request was cancelled.
    inner: Option<Result<T, E>>,
}

impl<T, E> PortalResult<T, E> {
    fn cancelled() -> Self {
        PortalResult { inner: None }
    }
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
            None => {
                map.serialize_element(&(PortalResponse::Cancelled as u32))?;
                map.serialize_element(&HashMap::<&str, Value<'_>>::new())?;
            }
            Some(Err(err)) => {
                map.serialize_element(&(PortalResponse::Other as u32))?;
                map.serialize_element(&HashMap::<&str, Value<'_>>::from([(
                    "error",
                    Value::Str(err.to_string().into()),
                )]))?;
            }
            Some(Ok(response)) => {
                map.serialize_element(&(PortalResponse::Success as u32))?;
                map.serialize_element(&response)?;
            }
        };
        map.end()
    }
}

impl<T, E> From<Result<T, E>> for PortalResult<T, E> {
    fn from(value: Result<T, E>) -> Self {
        PortalResult { inner: Some(value) }
    }
}

/// Validates the UI backend name passed by the portal frontend. Call this only
/// after `validate_app_details`: only trusted callers get that far, so any valid
/// well-known name is accepted.
fn parse_ui_backend(ui_backend: Option<String>) -> Result<Option<OwnedWellKnownName>, Error> {
    ui_backend
        .filter(|name| !name.is_empty())
        .map(|name| {
            OwnedWellKnownName::try_from(name.as_str()).map_err(|err| {
                tracing::warn!(%err, "Invalid UI backend name passed: {name}");
                Error::InvalidOptions
            })
        })
        .transpose()
}

async fn validate_app_details(
    connection: &Connection,
    header: &Header<'_>,
    claimed_app_id: String,
    claimed_origin: String,
    claimed_top_origin: Option<String>,
) -> Result<RequestContext, Error> {
    let Some(unique_name) = header.sender() else {
        return Err(Error::UntrustedCaller);
    };
    let claimed_app_id = if !claimed_app_id.is_empty() {
        claimed_app_id
    } else {
        tracing::warn!("App ID not specified on request. Rejecting request.");
        return Err(Error::UntrustedCaller);
    };

    let app_id = {
        let Some(pidfd) = query_peer_pidfd(connection, unique_name).await else {
            return Err(Error::UntrustedCaller);
        };

        if !super::should_trust_app_id(connection, pidfd.as_fd()).await {
            tracing::warn!(
                ?claimed_app_id,
                "App ID could not be verified. Rejecting request."
            );
            return Err(Error::UntrustedCaller);
        }

        // Now we can trust these app detail parameters.
        let Ok(app_id) = claimed_app_id.parse::<AppId>() else {
            tracing::warn!("Invalid app ID passed: {claimed_app_id}");
            return Err(Error::InvalidOptions);
        };
        app_id
    };

    // Verify that the origin is valid for the given app ID.
    let claimed_origin = claimed_origin.parse().map_err(|err| {
        tracing::warn!(%err, "Invalid origin passed: {claimed_origin}");
        Error::InvalidOrigin
    })?;
    let claimed_top_origin = claimed_top_origin
        .map(|o| {
            o.parse().map_err(|_| {
                tracing::warn!("Invalid origin passed: {o}");
                Error::InvalidOrigin
            })
        })
        .transpose()?;
    let request_kind = check_origin_from_app(&app_id, claimed_origin, claimed_top_origin)?;

    Ok(RequestContext {
        app_id,
        // TODO: we're no longer using the PID in the UI, but we need to update
        // the spec before removing it completely. For now, send invalid PID.
        pid: 0,
        request_kind,
    })
}

async fn query_peer_pidfd(
    connection: &Connection,
    sender_unique_name: &UniqueName<'_>,
) -> Option<OwnedFd> {
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

    let Some(pidfd) = peer_credentials.process_fd() else {
        tracing::error!("Failed to get process fd from peer credentials");
        return None;
    };

    pidfd
        .as_fd()
        .try_clone_to_owned()
        .inspect_err(
            |err| tracing::error!(%err, "Failed to duplicate peer process file descriptor"),
        )
        .ok()
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, rc::Rc};

    use gio::{TestDBus, TestDBusFlags};
    use tokio::sync::oneshot;
    use zbus::zvariant::{LE, ObjectPath, OwnedValue, Value, serialized::Context, to_bytes};

    use super::*;

    const REQUEST_HANDLE: &str = "/org/freedesktop/portal/desktop/request/1_42/t";

    type TestResponse = HashMap<&'static str, Value<'static>>;

    fn encode<T: Serialize + Type>(
        value: &T,
    ) -> zbus::zvariant::serialized::Data<'static, 'static> {
        to_bytes(Context::new_dbus(LE, 0), value).unwrap()
    }

    fn options(request_handle: Option<&str>) -> HashMap<&'static str, Value<'static>> {
        let mut options = HashMap::from([
            ("top_origin", Value::from("https://example.com")),
            ("public_key", Value::from("{}")),
        ]);
        if let Some(handle) = request_handle {
            let path = ObjectPath::try_from(handle.to_string()).unwrap();
            options.insert("request_handle", Value::from(path));
        }
        options
    }

    fn decode_portal_result(
        result: PortalResult<HashMap<&str, Value<'_>>, Error>,
    ) -> (u32, HashMap<String, OwnedValue>) {
        encode(&result).deserialize().unwrap().0
    }

    #[test]
    fn test_create_options_without_request_handle() {
        let (options, _): (CreateCredentialPortalOptions, _) =
            encode(&options(None)).deserialize().unwrap();
        assert_eq!(options.public_key.as_deref(), Some("{}"));
        assert!(options.request_handle.is_none());
    }

    #[test]
    fn test_create_options_with_request_handle() {
        let (options, _): (CreateCredentialPortalOptions, _) =
            encode(&options(Some(REQUEST_HANDLE)))
                .deserialize()
                .unwrap();
        assert_eq!(options.request_handle.unwrap().as_str(), REQUEST_HANDLE);
    }

    #[test]
    fn test_get_options_without_request_handle() {
        let (options, _): (GetCredentialPortalOptions, _) =
            encode(&options(None)).deserialize().unwrap();
        assert_eq!(options.top_origin.as_deref(), Some("https://example.com"));
        assert!(options.request_handle.is_none());
    }

    #[test]
    fn test_get_options_with_request_handle() {
        let (options, _): (GetCredentialPortalOptions, _) = encode(&options(Some(REQUEST_HANDLE)))
            .deserialize()
            .unwrap();
        assert_eq!(options.request_handle.unwrap().as_str(), REQUEST_HANDLE);
    }

    #[test]
    fn test_portal_result_response_codes() {
        let (code, results) = decode_portal_result(Ok(HashMap::new()).into());
        assert_eq!(code, PortalResponse::Success as u32);
        assert!(results.is_empty());

        let (code, results) = decode_portal_result(PortalResult::cancelled());
        assert_eq!(code, PortalResponse::Cancelled as u32);
        assert!(results.is_empty());

        let (code, results) = decode_portal_result(Err(Error::NotAllowed).into());
        assert_eq!(code, PortalResponse::Other as u32);
        assert!(results.contains_key("error"));
    }

    #[tokio::test]
    async fn test_ceremony_without_request_handle_is_not_cancellable() {
        let result = run_ceremony(
            &connect_test_bus(None).await.0,
            None,
            None,
            |cancellation| async move {
                assert!(!cancellation.is_cancelled());
                Ok(TestResponse::new())
            },
        )
        .await;
        assert_eq!(
            decode_portal_result(result).0,
            PortalResponse::Success as u32
        );
    }

    #[tokio::test]
    async fn test_invalid_request_handle_is_rejected() {
        let (connection, _bus) = connect_test_bus(None).await;
        let handle = OwnedObjectPath::try_from(PORTAL_SERVICE_PATH).unwrap();
        let result = run_ceremony(
            &connection,
            connection.unique_name().map(|n| n.inner()),
            Some(handle),
            |_| async { Ok(TestResponse::new()) },
        )
        .await;
        assert!(matches!(result.inner, Some(Err(Error::InvalidOptions))));
    }

    #[tokio::test]
    async fn test_close_cancels_ceremony() {
        let (gateway, bus) = connect_test_bus(None).await;
        let (caller, _) = connect_test_bus(Some(&bus)).await;
        let (other, _) = connect_test_bus(Some(&bus)).await;
        let handle = OwnedObjectPath::try_from(REQUEST_HANDLE).unwrap();
        let (started_tx, started_rx) = oneshot::channel();

        let ceremony = run_ceremony(
            &gateway,
            caller.unique_name().map(|n| n.inner()),
            Some(handle.clone()),
            |cancellation| async move {
                started_tx.send(()).unwrap();
                // Like the credential service, fail once the request is cancelled.
                cancellation.cancelled().await;
                Err::<TestResponse, _>(Error::NotAllowed)
            },
        );
        let client = async {
            started_rx.await.unwrap();
            let err = close_request(&other, &gateway, &handle).await.unwrap_err();
            assert!(matches!(err, fdo::Error::AccessDenied(_)), "{err:?}");
            close_request(&caller, &gateway, &handle).await.unwrap();
        };
        let (result, ()) = tokio::join!(ceremony, client);

        let (code, _) = decode_portal_result(result);
        assert_eq!(code, PortalResponse::Cancelled as u32);
        // The request object is removed when the ceremony ends.
        assert!(close_request(&caller, &gateway, &handle).await.is_err());
    }

    #[tokio::test]
    async fn test_caller_disconnect_cancels_ceremony() {
        let (gateway, bus) = connect_test_bus(None).await;
        let (caller, _) = connect_test_bus(Some(&bus)).await;
        let caller_name = caller.unique_name().unwrap().to_owned();
        let handle = OwnedObjectPath::try_from(REQUEST_HANDLE).unwrap();
        let (started_tx, started_rx) = oneshot::channel();

        let ceremony = run_ceremony(
            &gateway,
            Some(&caller_name),
            Some(handle.clone()),
            |cancellation| async move {
                started_tx.send(()).unwrap();
                cancellation.cancelled().await;
                Err::<TestResponse, _>(Error::NotAllowed)
            },
        );
        let client = async {
            started_rx.await.unwrap();
            caller.close().await.unwrap();
        };
        let (result, ()) = expect_cancelled_in_time(async { tokio::join!(ceremony, client) }).await;

        assert_eq!(
            decode_portal_result(result).0,
            PortalResponse::Cancelled as u32
        );
    }

    #[tokio::test]
    async fn test_caller_disconnect_cancels_ceremony_without_request_handle() {
        let (gateway, bus) = connect_test_bus(None).await;
        let (caller, _) = connect_test_bus(Some(&bus)).await;
        let caller_name = caller.unique_name().unwrap().to_owned();
        let (started_tx, started_rx) = oneshot::channel();

        let ceremony = run_ceremony(
            &gateway,
            Some(&caller_name),
            None,
            |cancellation| async move {
                started_tx.send(()).unwrap();
                cancellation.cancelled().await;
                Err::<TestResponse, _>(Error::NotAllowed)
            },
        );
        let client = async {
            started_rx.await.unwrap();
            caller.close().await.unwrap();
        };
        let (result, ()) = expect_cancelled_in_time(async { tokio::join!(ceremony, client) }).await;

        assert_eq!(
            decode_portal_result(result).0,
            PortalResponse::Cancelled as u32
        );
    }

    #[tokio::test]
    async fn test_caller_already_gone_cancels_ceremony() {
        let (gateway, bus) = connect_test_bus(None).await;
        let (caller, _) = connect_test_bus(Some(&bus)).await;
        let caller_name = caller.unique_name().unwrap().to_owned();
        caller.close().await.unwrap();

        let ceremony = run_ceremony(
            &gateway,
            Some(&caller_name),
            None,
            |cancellation| async move {
                cancellation.cancelled().await;
                Err::<TestResponse, _>(Error::NotAllowed)
            },
        );
        let result = expect_cancelled_in_time(ceremony).await;

        assert_eq!(
            decode_portal_result(result).0,
            PortalResponse::Cancelled as u32
        );
    }

    #[tokio::test]
    async fn test_request_handle_removed_after_success() {
        let (gateway, bus) = connect_test_bus(None).await;
        let (caller, _) = connect_test_bus(Some(&bus)).await;
        let handle = OwnedObjectPath::try_from(REQUEST_HANDLE).unwrap();

        let result = run_ceremony(
            &gateway,
            caller.unique_name().map(|n| n.inner()),
            Some(handle.clone()),
            |_| async { Ok(TestResponse::new()) },
        )
        .await;

        assert_eq!(
            decode_portal_result(result).0,
            PortalResponse::Success as u32
        );
        assert!(close_request(&caller, &gateway, &handle).await.is_err());
    }

    /// Fails the test instead of hanging if the ceremony is never cancelled.
    async fn expect_cancelled_in_time<F: Future>(future: F) -> F::Output {
        tokio::time::timeout(std::time::Duration::from_secs(5), future)
            .await
            .expect("ceremony was not cancelled")
    }

    /// Connects to a private test bus, starting one if `bus` is `None`.
    async fn connect_test_bus(bus: Option<&TestBus>) -> (Connection, TestBus) {
        let bus = match bus {
            Some(bus) => bus.clone(),
            None => TestBus::new(),
        };
        let connection = zbus::connection::Builder::address(bus.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        (connection, bus)
    }

    async fn close_request(
        caller: &Connection,
        gateway: &Connection,
        handle: &OwnedObjectPath,
    ) -> fdo::Result<()> {
        caller
            .call_method(
                gateway.unique_name(),
                handle,
                Some("org.freedesktop.handler.portal.experimental.Request"),
                "Close",
                &(),
            )
            .await
            .map(|_| ())
            .map_err(fdo::Error::from)
    }

    #[derive(Clone)]
    struct TestBus {
        address: String,
        _bus: Rc<TestBusGuard>,
    }

    struct TestBusGuard(TestDBus);

    impl Drop for TestBusGuard {
        fn drop(&mut self) {
            self.0.down();
        }
    }

    impl TestBus {
        fn new() -> Self {
            let bus = TestDBus::new(TestDBusFlags::NONE);
            bus.up();
            let address = bus.bus_address().expect("test bus to be up").to_string();
            Self {
                address,
                _bus: Rc::new(TestBusGuard(bus)),
            }
        }
    }

    #[test]
    fn test_ui_backend_defaults_when_missing_or_empty() {
        assert_eq!(parse_ui_backend(None).unwrap(), None);
        assert_eq!(parse_ui_backend(Some(String::new())).unwrap(), None);
    }

    #[test]
    fn test_ui_backend_accepts_well_known_name() {
        let backend = parse_ui_backend(Some("org.freedesktop.impl.portal.desktop.gnome".into()))
            .unwrap()
            .unwrap();
        assert_eq!(
            backend.as_str(),
            "org.freedesktop.impl.portal.desktop.gnome"
        );
    }

    #[test]
    fn test_ui_backend_rejects_invalid_names() {
        // Unique names would bypass activation and the owner checks.
        for name in [":1.42", "not a name", "nodots", "/org/freedesktop"] {
            assert!(parse_ui_backend(Some(name.into())).is_err(), "{name}");
        }
    }
}
