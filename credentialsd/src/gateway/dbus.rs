use std::{
    collections::HashMap,
    fmt::Display,
    os::fd::{AsFd, AsRawFd},
    sync::{Arc, Mutex, RwLock},
};

use futures::{Stream, StreamExt};
use libwebauthn::ops::webauthn::{GetAssertionRequest, MakeCredentialRequest};
use serde::{Deserialize, Serialize, ser::SerializeTuple};
use tokio::{
    sync::{Mutex as AsyncMutex, mpsc::Sender, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use zbus::{
    Connection, DBusError, ObjectServer, interface,
    message::Header,
    names::{BusName, OwnedUniqueName, UniqueName},
    object_server::SignalEmitter,
    zvariant::{DeserializeDict, Optional, OwnedFd, OwnedObjectPath, SerializeDict, Type, Value},
};

use credentialsd_common::{
    memfd,
    model::{
        BACKGROUND_EVENT_ERROR_AUTHENTICATOR, BACKGROUND_EVENT_ERROR_CANCELLED,
        BACKGROUND_EVENT_ERROR_CREDENTIAL_EXCLUDED, BACKGROUND_EVENT_ERROR_INTERNAL,
        BACKGROUND_EVENT_ERROR_NO_CREDENTIALS, BACKGROUND_EVENT_ERROR_PIN_ATTEMPTS_EXHAUSTED,
        BACKGROUND_EVENT_ERROR_PIN_NOT_SET, BACKGROUND_EVENT_ERROR_TIMED_OUT, BackgroundEvent,
        Credential, Device, NotifyHybridConnectedOptions, NotifyHybridConnectingOptions,
        NotifyHybridRestartingOptions, NotifyHybridStartedOptions, NotifyNeedsPinOptions,
        NotifyNeedsUserPresenceOptions, NotifyNeedsUserVerificationOptions,
        NotifyNfcConnectedOptions, NotifyNfcRestartingOptions, NotifyPinNotSetOptions,
        NotifySelectingCredentialOptions, NotifyUsbConnectedOptions, NotifyUsbRestartingOptions,
        PinNotSetError, WindowHandle,
    },
};

use crate::{
    DBUS_SERVICE_NAME,
    credential_service::{
        CredentialServiceError, DeviceStateUpdate, ManageDevice, RequestId, UsbState, nfc::NfcState,
    },
    gateway::{
        CreateCredentialRequest, CreateCredentialResponse, CreatePublicKeyCredentialRequest,
        GetCredentialRequest, GetCredentialResponse, GetPublicKeyCredentialRequest, WebAuthnError,
        create_credential_response_try_from_ctap2, get_credential_response_try_from_ctap2,
    },
    model::{CredentialRequest, CredentialResponse},
    webauthn::{AppId, NavigationContext, Origin},
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

#[derive(Debug, Serialize, Deserialize, Type)]
#[zvariant(signature = "s")]
enum CredentialType {
    // TODO: Make this PascalCase.
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

#[derive(Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
struct GetCredentialOptions {
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

    let Some(pid) = query_peer_pid_via_fdinfo(connection, unique_name).await else {
        return Err(Error::SecurityError);
    };

    if claimed_app_id.is_empty() || !super::should_trust_app_id(pid).await {
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

pub struct Credentialsd {
    pub svc: Arc<AsyncMutex<dyn ManageDevice + Send + Sync + 'static>>,
}

#[interface(name = "xyz.iinuwa.credentialsd.Manager")]
impl Credentialsd {
    async fn create_public_key_credential(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        cred_fd: OwnedFd,
        request_json: String,
        origin: &str,
        top_origin: Optional<&str>,
    ) -> Result<OwnedObjectPath, CredentialsdError> {
        // TODO: verify that a trusted service is calling, e.g. xdg-desktop-portal via systemd.

        let Some(sender) = header.sender().map(|s| OwnedUniqueName::from(s.to_owned())) else {
            return Err(CredentialsdError::InvalidRequest(
                "D-Bus message malformed".to_string(),
            ));
        };

        let request = CreateCredentialRequest {
            r#type: CredentialType::PublicKey.to_string(),
            public_key: Some(CreatePublicKeyCredentialRequest { request_json }),
        };
        let origin = origin
            .parse::<Origin>()
            .map_err(|err| CredentialsdError::InvalidOrigin(err.to_string()))?;
        let top_origin = top_origin
            .map(|top| {
                top.parse::<Origin>()
                    .map_err(|err| CredentialsdError::InvalidOrigin(err.to_string()))
            })
            .transpose()?;
        let context = match top_origin {
            Some(top_origin) => NavigationContext::CrossOrigin((origin, top_origin)),
            None => NavigationContext::SameOrigin(origin),
        };
        let make_cred_request = super::create_credential_request_try_into_ctap2(&request, &context)
            .await
            .map_err(|err| {
                tracing::error!("Could not parse passkey creation request. Rejecting request.");
                CredentialsdError::InvalidRequest(format!(
                    "Could not parse passkey creation request: {err:#}"
                ))
            })?;
        if make_cred_request.algorithms.is_empty() {
            tracing::info!("No supported algorithms given in request. Rejecting request.");
            return Err(CredentialsdError::UnsupportedRequest(
                "No supported algorithms given in request".to_string(),
            ));
        }
        let cred_request =
            CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request.clone());
        let (request_tx, request_rx) = oneshot::channel();
        let (request_id, cancellation_token) = self
            .svc
            .lock()
            .await
            .init_request(&cred_request, request_tx)
            .await?;
        let initial_devices = self
            .svc
            .lock()
            .await
            .get_available_public_key_devices()
            .await
            .unwrap_or_default();

        let session = CredentialsdSession::new(
            cred_fd,
            LibwebauthnCredentialRequest::Make(make_cred_request),
            cancellation_token,
            request_id,
            sender,
            self.svc.clone(),
            cred_request.relying_party_id().to_string(),
            initial_devices,
            request_rx,
        );

        let session_path =
            OwnedObjectPath::try_from(format!("/xyz/iinuwa/credentialsd/Session/{request_id}"))
                .expect("valid object path");
        if !object_server
            .at(&session_path, session)
            .await
            .map_err(|err| {
                tracing::error!(%session_path, %err, "Failed to create session for request");
                CredentialsdError::Internal
            })?
        {
            tracing::warn!("Generated session path already in use. Caller should try again.");
            return Err(CredentialsdError::Busy(
                "Could not create session. Please try again".to_string(),
            ));
        }
        Ok(session_path)
    }

    async fn get_credential(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        cred_fd: OwnedFd,
        origin: &str,
        top_origin: Optional<&str>,
        options: GetCredentialOptions,
    ) -> Result<OwnedObjectPath, CredentialsdError> {
        // TODO: verify that a trusted service is calling, e.g. xdg-desktop-portal via systemd.

        let Some(sender) = header.sender().map(|s| OwnedUniqueName::from(s.to_owned())) else {
            return Err(CredentialsdError::InvalidRequest(
                "D-Bus message malformed".to_string(),
            ));
        };

        let Some(request_json) = options.public_key else {
            return Err(CredentialsdError::NoRequestParameters(
                "Parameters for at least one credential must be given, none found".to_string(),
            ));
        };

        let request = GetCredentialRequest {
            public_key: Some(GetPublicKeyCredentialRequest { request_json }),
        };

        let origin = origin
            .parse::<Origin>()
            .map_err(|err| CredentialsdError::InvalidOrigin(err.to_string()))?;
        let top_origin = top_origin
            .map(|top| {
                top.parse::<Origin>()
                    .map_err(|err| CredentialsdError::InvalidOrigin(err.to_string()))
            })
            .transpose()?;
        let context = match top_origin {
            Some(top_origin) => NavigationContext::CrossOrigin((origin, top_origin)),
            None => NavigationContext::SameOrigin(origin),
        };
        let get_cred_request = super::get_credential_request_try_into_ctap2(&request, &context)
            .await
            .map_err(|err| {
                tracing::error!("Could not parse passkey assertion request. Rejecting request.");
                CredentialsdError::InvalidRequest(format!(
                    "Could not parse passkey assertion request: {err:#}"
                ))
            })?;

        let cred_request =
            CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request.clone());

        let (request_tx, request_rx) = oneshot::channel();
        let (request_id, cancellation_token) = self
            .svc
            .lock()
            .await
            .init_request(&cred_request, request_tx)
            .await?;
        let initial_devices = self
            .svc
            .lock()
            .await
            .get_available_public_key_devices()
            .await
            .unwrap_or_default();

        let session = CredentialsdSession::new(
            cred_fd,
            LibwebauthnCredentialRequest::Get(get_cred_request),
            cancellation_token,
            request_id,
            sender,
            self.svc.clone(),
            cred_request.relying_party_id().to_string(),
            initial_devices,
            request_rx,
        );

        let session_path =
            OwnedObjectPath::try_from(format!("/xyz/iinuwa/credentialsd/Session/{request_id}"))
                .expect("valid object path");
        if !object_server
            .at(&session_path, session)
            .await
            .map_err(|err| {
                tracing::error!(%session_path, %err, "Failed to create session for request");
                CredentialsdError::Internal
            })?
        {
            tracing::warn!("Generated session path already in use. Caller should try again.");
            return Err(CredentialsdError::Busy(
                "Could not create session. Please try again".to_string(),
            ));
        }
        Ok(session_path)
    }
}

#[derive(Debug, DBusError)]
#[zbus(prefix = "xyz.iinuwa.credentialsd")]
pub enum CredentialsdError {
    /// A request is in progress
    Busy(String),
    InvalidOrigin(String),
    InvalidRequest(String),
    NoRequestParameters(String),
    UnsupportedRequest(String),
    /// Some unknown error with the authenticator occurred.
    AuthenticatorError,
    /// No matching credentials were found on the device.
    NoCredentials,
    /// Credential was already registered with this device (credential ID contained in excludeCredentials)
    CredentialExcluded,
    /// Too many incorrect PIN attempts, and authenticator must be removed and
    /// reinserted to continue any more PIN attempts.
    ///
    /// Note that this is different than exhausting the PIN count that fully
    /// locks out the device.
    PinAttemptsExhausted,
    Internal,
    /// Hybrid is not running, or invocation data was already transmitted.
    HybridSecretTaken,
    RequestCancelled,
}

impl From<CredentialServiceError> for CredentialsdError {
    fn from(value: CredentialServiceError) -> Self {
        match value {
            CredentialServiceError::AuthenticatorError => Self::AuthenticatorError,
            CredentialServiceError::NoCredentials => Self::NoCredentials,
            CredentialServiceError::CredentialExcluded => Self::CredentialExcluded,
            CredentialServiceError::PinAttemptsExhausted => Self::PinAttemptsExhausted,
            CredentialServiceError::Internal(_) => Self::Internal,
            // TODO: This shouldn't be emitted at this level?
            CredentialServiceError::NonTerminatingCancellation => Self::RequestCancelled,
        }
    }
}

#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
struct CeremonyCompletedOptions {
    #[zvariant(rename = "type")]
    pub r#type: CredentialType,
}

#[derive(Clone)]
enum LibwebauthnCredentialRequest {
    Make(MakeCredentialRequest),
    Get(GetAssertionRequest),
}

struct CredentialsdSession {
    cred_fd: Arc<Mutex<Option<OwnedFd>>>,
    cred_request: LibwebauthnCredentialRequest,
    request_id: RequestId,
    svc: Arc<AsyncMutex<dyn ManageDevice + Send + Sync + 'static>>,
    rp_id: String,
    destination: OwnedUniqueName,
    response_channel:
        Mutex<Option<oneshot::Receiver<Result<CredentialResponse, CredentialServiceError>>>>,
    event_task: Mutex<Option<JoinHandle<()>>>,

    devices: RwLock<Vec<Device>>,
    client_pin_tx: Arc<Mutex<Option<Sender<String>>>>,
    set_pin_tx: Arc<Mutex<Option<Sender<String>>>>,
    cred_selector_tx: Arc<Mutex<Option<Sender<String>>>>,
    hybrid_invocation_data: Arc<Mutex<Option<OwnedFd>>>,
}

#[interface(name = "xyz.iinuwa.credentialsd.Session")]
impl CredentialsdSession {
    async fn start(
        &self,
        #[zbus(signal_emitter)] signal_emitter: SignalEmitter<'_>,
    ) -> Result<(), CredentialsdError> {
        // TODO: verify this is the same sender.
        let response_channel = {
            let Ok(mut session_guard) = self.response_channel.try_lock() else {
                tracing::info!(request_id = %self.request_id, "Session.Start() called twice");
                return Err(CredentialsdError::Busy(
                    "Session.Start() can only be called once".to_string(),
                ));
            };
            session_guard.take().ok_or_else(|| {
                tracing::info!(request_id = %self.request_id, "Response channel already taken");
                CredentialsdError::Busy("Session.Start() can only be called once".to_string())
            })?
        };

        let device_state_update_stream = self.svc.lock().await.start_discovery().await;
        let mut stream = Self::to_background_event_stream(
            device_state_update_stream,
            self.client_pin_tx.clone(),
            self.set_pin_tx.clone(),
            self.cred_selector_tx.clone(),
        );

        let s = signal_emitter
            .into_owned()
            .set_destination(self.destination.clone().into());

        let request_id = self.request_id;
        let request = self.cred_request.clone();
        let hybrid_invocation_data = self.hybrid_invocation_data.clone();
        let response_fd = self.cred_fd.clone();

        let task = tokio::spawn(async move {
            while let Some(event) = stream.next().await {
                match event {
                    BackgroundEvent::CeremonyCompleted => {
                        tracing::info!(request_id, "Ceremony completed");
                        let msg = match response_channel.await {
                            Ok(msg) => msg,
                            Err(_) => {
                                tracing::error!(
                                    "Credential service sent CeremonyCompleted before sending response."
                                );
                                if s.error_occurred(BACKGROUND_EVENT_ERROR_INTERNAL)
                                    .await
                                    .is_err()
                                {
                                    tracing::debug!("Failed to send error response to caller");
                                };
                                // TODO: Tear down request
                                break;
                            }
                        };

                        match msg {
                            Ok(response) => {
                                let public_key_response: String = match response {
                                    CredentialResponse::CreatePublicKeyCredentialResponse(cred_response) => {
                                        if let LibwebauthnCredentialRequest::Make(make_request) = request  {
                                            create_credential_response_try_from_ctap2(&cred_response, &make_request).map(|c| c.registration_response_json)
                                        }
                                        else {
                                            Err("Expected get response, received make response".to_string())
                                        }
                                    }
                                    CredentialResponse::GetPublicKeyCredentialResponse(cred_response) => {
                                        if let LibwebauthnCredentialRequest::Get(get_request) = request  {
                                            get_credential_response_try_from_ctap2(&cred_response, &get_request).map(|c| c.authentication_response_json)
                                        }
                                        else {
                                            Err("Expected make response, received get response".to_string())
                                        }
                                    }
                                }.map_err(|err| {
                                    tracing::error!(%request_id,
                                        "Failed to parse credential response from authenticator: {err}"
                                    );
                                    CredentialsdError::Internal
                                }).unwrap();
                                tracing::debug!("Sending ceremony completed response");
                                {
                                    let Some(cred_fd) =
                                        response_fd.lock().expect("not poisoned").take()
                                    else {
                                        tracing::error!(
                                            request_id,
                                            "File descriptor was already taken"
                                        );
                                        break;
                                    };

                                    if let Err(err) = memfd::fill_mmap_with_secret(
                                        cred_fd.as_fd(),
                                        public_key_response.into_bytes(),
                                    ) {
                                        tracing::error!(
                                            request_id,
                                            %err,
                                            "Failed to fill credential"
                                        );
                                        break;
                                    }
                                }
                                if s.ceremony_completed(CeremonyCompletedOptions {
                                    r#type: CredentialType::PublicKey,
                                })
                                .await
                                .is_err()
                                {
                                    tracing::error!(
                                        request_id,
                                        "Failed to send ceremony completed event to backend."
                                    );
                                }
                            }
                            Err(err) => {
                                // TODO: This should do the same matching as send_state_update
                                tracing::error!(%err, "Credential manager returned an error");
                                if s.error_occurred(BACKGROUND_EVENT_ERROR_INTERNAL)
                                    .await
                                    .is_err()
                                {
                                    tracing::error!(
                                        request_id,
                                        "Failed to send ceremony completed event to backend."
                                    );
                                }
                            }
                        }
                        break;
                    }
                    BackgroundEvent::HybridStarted(invocation_data_fd) => {
                        *hybrid_invocation_data.lock().expect("not poisoned") =
                            Some(invocation_data_fd);
                        if s.hybrid_started(NotifyHybridStartedOptions {})
                            .await
                            .is_err()
                        {
                            tracing::error!(
                                "Failed to send state update event to backend. Stopping flow"
                            );
                            break;
                        }
                    }
                    _ => {
                        let send_result = Self::send_state_update(s.clone(), event).await;
                        if send_result.is_err() {
                            tracing::error!(
                                "Failed to send state update event to backend. Stopping flow"
                            );
                            break;
                        }
                    }
                }
            }
        });
        *self.event_task.lock().expect("not poisoned") = Some(task);
        Ok(())
    }

    async fn get_hybrid_invocation_data(&self) -> Result<OwnedFd, CredentialsdError> {
        // TODO: bind to original caller of the session, e.g. self.destination
        self.hybrid_invocation_data
            .lock()
            .expect("not poisoned")
            .take()
            .ok_or_else(|| CredentialsdError::HybridSecretTaken)
    }

    async fn enter_client_pin(&self) -> Result<(), CredentialsdError> {
        // TODO: bind to original caller of the session, e.g. self.destination
        tracing::error!("Not implemented");
        Err(CredentialsdError::Internal)
    }

    async fn select_credential(&self, _credential_id: String) -> Result<(), CredentialsdError> {
        // TODO: bind to original caller of the session, e.g. self.destination
        tracing::error!("Not implemented");
        Err(CredentialsdError::Internal)
    }

    #[zbus(property)]
    fn devices(&self) -> Vec<Device> {
        self.devices.read().expect("not poisoned").clone()
    }

    #[zbus(property)]
    fn rp_id(&self) -> String {
        self.rp_id.clone()
    }

    #[zbus(signal)]
    async fn needs_pin(
        emitter: &SignalEmitter<'_>,
        attempts_left: u32,
        _options: NotifyNeedsPinOptions,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn pin_not_set(
        emitter: &SignalEmitter<'_>,
        error: PinNotSetError,
        _options: NotifyPinNotSetOptions,
    ) -> zbus::Result<()>;

    /// Emitted when the authenticator needs a user verification gesture.
    #[zbus(signal)]
    async fn needs_user_verification(
        emitter: &SignalEmitter<'_>,
        attempts_left: u32,
        _options: NotifyNeedsUserVerificationOptions,
    ) -> zbus::Result<()>;

    /// Emitted when the authenticator needs a user presence gesture.
    #[zbus(signal)]
    async fn needs_user_presence(
        emitter: &SignalEmitter<'_>,
        _options: NotifyNeedsUserPresenceOptions,
    ) -> zbus::Result<()>;

    /// Emitted when the authenticator detects multiple credentials matching
    /// credentials for a request.
    #[zbus(signal)]
    async fn selecting_credential(
        emitter: &SignalEmitter<'_>,
        credentials: Vec<Credential>,
        _options: NotifySelectingCredentialOptions,
    ) -> zbus::Result<()>;

    /// Emitted when the platform begins scanning for CTAP2 hybrid advertisements.
    #[zbus(signal)]
    async fn hybrid_started(
        emitter: &SignalEmitter<'_>,
        _options: NotifyHybridStartedOptions,
    ) -> zbus::Result<()>;

    /// Emitted when the platform has received a CTAP2 hybrid advertisement and is
    /// establishing a channel.
    #[zbus(signal)]
    async fn hybrid_connecting(
        emitter: &SignalEmitter<'_>,
        _options: NotifyHybridConnectingOptions,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn hybrid_connected(
        emitter: &SignalEmitter<'_>,
        _options: NotifyHybridConnectedOptions,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn hybrid_restarting(
        emitter: &SignalEmitter<'_>,
        _options: NotifyHybridRestartingOptions,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn nfc_connected(
        emitter: &SignalEmitter<'_>,
        _options: NotifyNfcConnectedOptions,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn nfc_restarting(
        emitter: &SignalEmitter<'_>,
        _options: NotifyNfcRestartingOptions,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn usb_connected(
        emitter: &SignalEmitter<'_>,
        _options: NotifyUsbConnectedOptions,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn usb_restarting(
        emitter: &SignalEmitter<'_>,
        _options: NotifyUsbRestartingOptions,
    ) -> zbus::Result<()>;

    // TODO: we need to disambiguate get and create responses
    #[zbus(signal)]
    async fn ceremony_completed(
        emitter: &SignalEmitter<'_>,
        _options: CeremonyCompletedOptions,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn error_occurred(emitter: &SignalEmitter<'_>, error: u32) -> zbus::Result<()>;
}

impl CredentialsdSession {
    fn new(
        cred_fd: OwnedFd,
        cred_request: LibwebauthnCredentialRequest,
        _cancellation_token: CancellationToken,
        request_id: RequestId,
        destination: OwnedUniqueName,
        svc: Arc<AsyncMutex<dyn ManageDevice + Send + Sync + 'static>>,
        rp_id: String,
        devices: Vec<Device>,
        response_channel: oneshot::Receiver<Result<CredentialResponse, CredentialServiceError>>,
    ) -> Self {
        // TODO: watch for sender disconnected, sender cancelled, or if we disconnect from bus
        Self {
            cred_fd: Arc::new(Mutex::new(Some(cred_fd))),
            cred_request,
            request_id,
            svc,
            rp_id,
            devices: RwLock::new(devices),
            client_pin_tx: Arc::new(Mutex::new(None)),
            set_pin_tx: Arc::new(Mutex::new(None)),
            cred_selector_tx: Arc::new(Mutex::new(None)),
            destination,
            response_channel: Mutex::new(Some(response_channel)),
            event_task: Mutex::new(None),
            hybrid_invocation_data: Arc::new(Mutex::new(None)),
        }
    }

    fn to_background_event_stream<D: Stream<Item = DeviceStateUpdate>>(
        device_event_stream: D,
        client_pin_tx: Arc<Mutex<Option<Sender<String>>>>,
        set_pin_tx: Arc<Mutex<Option<Sender<String>>>>,
        cred_selector_tx: Arc<Mutex<Option<Sender<String>>>>,
    ) -> impl Stream<Item = BackgroundEvent> {
        // TODO: copied from crate::dbus::flow_control, refactor to reuse
        device_event_stream.map(move |device_update| {
            match &device_update {
                DeviceStateUpdate::Nfc(NfcState::NeedsPin { pin_tx, .. }) => {
                    *client_pin_tx.lock().expect("not poisoned") = Some(pin_tx.clone());
                }

                DeviceStateUpdate::Usb(UsbState::NeedsPin { pin_tx, .. }) => {
                    *client_pin_tx.lock().expect("not poisoned") = Some(pin_tx.clone());
                }
                DeviceStateUpdate::Nfc(NfcState::PinNotSet { pin_tx, .. }) => {
                    *set_pin_tx.lock().expect("not poisoned") = Some(pin_tx.clone());
                }

                DeviceStateUpdate::Usb(UsbState::PinNotSet { pin_tx, .. }) => {
                    *set_pin_tx.lock().expect("not poisoned") = Some(pin_tx.clone());
                }
                DeviceStateUpdate::Usb(UsbState::SelectingCredential { cred_tx, .. }) => {
                    *cred_selector_tx.lock().expect("not poisoned") = Some(cred_tx.clone());
                }
                _ => {}
            }
            device_update.into()
        })
    }

    async fn send_state_update(
        signal_emitter: SignalEmitter<'static>,
        event: BackgroundEvent,
    ) -> Result<(), ()> {
        let response = match event {
            // TODO: Remove these events. They are no longer needed by backends, since the user
            // needs to select a device anyway.
            BackgroundEvent::NfcIdle
            | BackgroundEvent::NfcWaiting
            | BackgroundEvent::UsbIdle
            | BackgroundEvent::UsbSelectingDevice
            | BackgroundEvent::UsbWaiting => {
                return Ok(());
            }
            BackgroundEvent::NeedsPin { attempts_left } => {
                signal_emitter
                    .needs_pin(attempts_left.unwrap_or(u32::MAX), NotifyNeedsPinOptions {})
                    .await
            }
            BackgroundEvent::PinNotSet { error } => {
                signal_emitter
                    .pin_not_set(error, NotifyPinNotSetOptions {})
                    .await
            }
            BackgroundEvent::NeedsUserVerification { attempts_left } => {
                signal_emitter
                    .needs_user_verification(
                        attempts_left.unwrap_or(u32::MAX),
                        NotifyNeedsUserVerificationOptions {},
                    )
                    .await
            }
            BackgroundEvent::NeedsUserPresence => {
                signal_emitter
                    .needs_user_presence(NotifyNeedsUserPresenceOptions {})
                    .await
            }
            BackgroundEvent::SelectingCredential { creds } => {
                signal_emitter
                    .selecting_credential(creds, NotifySelectingCredentialOptions {})
                    .await
            }
            BackgroundEvent::HybridIdle => todo!(),
            BackgroundEvent::HybridConnecting => {
                signal_emitter
                    .hybrid_connecting(NotifyHybridConnectingOptions {})
                    .await
            }
            BackgroundEvent::HybridConnected => {
                signal_emitter
                    .hybrid_connected(NotifyHybridConnectedOptions {})
                    .await
            }
            BackgroundEvent::HybridRestarting => {
                signal_emitter
                    .hybrid_restarting(NotifyHybridRestartingOptions {})
                    .await
            }
            BackgroundEvent::NfcConnected => {
                signal_emitter
                    .nfc_connected(NotifyNfcConnectedOptions {})
                    .await
            }
            BackgroundEvent::NfcRestarting => {
                signal_emitter
                    .nfc_restarting(NotifyNfcRestartingOptions {})
                    .await
            }
            BackgroundEvent::UsbConnected => {
                signal_emitter
                    .usb_connected(NotifyUsbConnectedOptions {})
                    .await
            }
            BackgroundEvent::UsbRestarting => {
                signal_emitter
                    .usb_restarting(NotifyUsbRestartingOptions {})
                    .await
            }
            BackgroundEvent::ErrorInternal => {
                let error = BACKGROUND_EVENT_ERROR_INTERNAL;
                signal_emitter.error_occurred(error).await
            }
            BackgroundEvent::ErrorTimedOut => {
                let error = BACKGROUND_EVENT_ERROR_TIMED_OUT;
                signal_emitter.error_occurred(error).await
            }
            BackgroundEvent::ErrorCancelled => {
                // TODO: Just call org.freedesktop.impl.portal.Session.Close()
                let error = BACKGROUND_EVENT_ERROR_CANCELLED;
                signal_emitter.error_occurred(error).await
            }
            BackgroundEvent::ErrorAuthenticator => {
                let error = BACKGROUND_EVENT_ERROR_AUTHENTICATOR;
                signal_emitter.error_occurred(error).await
            }
            BackgroundEvent::ErrorNoCredentials => {
                let error = BACKGROUND_EVENT_ERROR_NO_CREDENTIALS;
                signal_emitter.error_occurred(error).await
            }
            BackgroundEvent::ErrorCredentialExcluded => {
                let error = BACKGROUND_EVENT_ERROR_CREDENTIAL_EXCLUDED;
                signal_emitter.error_occurred(error).await
            }
            BackgroundEvent::ErrorPinAttemptsExhausted => {
                let error = BACKGROUND_EVENT_ERROR_PIN_ATTEMPTS_EXHAUSTED;
                signal_emitter.error_occurred(error).await
            }
            BackgroundEvent::ErrorPinNotSet => {
                let error = BACKGROUND_EVENT_ERROR_PIN_NOT_SET;
                signal_emitter.error_occurred(error).await
            }
            BackgroundEvent::HybridStarted(_) => {
                // Handled outside of this method.
                tracing::trace!(
                    "HybridStarted should have been handled before send_state_update, but was not"
                );
                Ok(())
            }
            BackgroundEvent::CeremonyCompleted => {
                // Handled outside of this method.
                tracing::trace!(
                    "CeremonyCompleted should have been handled before send_state_update, but was not"
                );
                Ok(())
            }
        };

        if let Err(err) = response {
            tracing::error!(%err, "Failed to send update to backend");
            return Err(());
        }
        Ok(())
    }
}

/*
 * Manager
 *   CreatePublicKeyCredential(s request_json) -> PublicKeySession
 *   CreatePasswordCredential(s serviceIdentifier, h? password, a{sv} options) -> PasswordSession
 *     // options should allow seeding an OTP?
 *   CreateOtpCredential(s serviceIdentifier, s type, h secret)
 *     // I think creating these is dumb, just create a passkey. But if Apple made their QR
 *     // code scanning feature open source, then the browser could automatically
 *     // scan for OTPs and call the platform to store the QR code automatically.
 *   CreateDigitalCredential() -> DigitalCredentialSession
 *   CreateFederatedCredential() -> FederatedCredentialSession
 *   GetCredential(s type, a{sv} type options) -> GetCredentialSession
 * Session
 *   Start()
 *   Cancel()
 *   ::Completed
 *   ::Error
 *   // PublicKey/DigitalCredential
 *   EnterClientPin(h pin_fd)
 *   SelectCredential(s id)
 *   ::HybridStarted
 *   ::HybridConnecting
 *   ::HybridConnected
 *   ::NfcConnected
 *   ::UsbConnected
 *   ::NeedsPin
 *   ::NeedsUserVerification
 *   ::NeedsUserPresence
 *   ::SelectingCredential
 *   .InitialDevices aa{sv}
 *   // PasswordSession
 *   // No methods or signals
 *   .mediation: required (default) | conditional | silent
 *   .uiMode: immediate
 * DigitalCredentialSession
 * GetCredentialSession()
 */
