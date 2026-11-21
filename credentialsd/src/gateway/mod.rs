//! Implements the service that public clients can connect to. Responsible for
//! authorizing clients for origins and validating request parameters.

mod dbus;
mod util;

use std::{
    collections::HashMap,
    fmt::Display,
    future::Future,
    os::fd::{AsRawFd, BorrowedFd},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use credentialsd_common::model::WindowHandle;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;
use zbus::{
    Connection,
    names::OwnedWellKnownName,
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

impl RequestContext {
    fn is_privileged(&self) -> bool {
        matches!(self.request_kind, RequestKind::Privileged { .. })
    }
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
        cancellation: CancellationToken,
        parent_window: Option<WindowHandle>,
        activation_token: Option<String>,
        ui_backend: Option<OwnedWellKnownName>,
    ) -> Result<CreateCredentialResponse, WebAuthnError> {
        let privileged = context.is_privileged();
        self.create_credential(
            request,
            context,
            cancellation,
            parent_window,
            activation_token,
            ui_backend,
        )
        .await
        .map_err(|err| err.for_caller(privileged))
    }

    async fn handle_get_credential(
        &self,
        request: GetCredentialRequest,
        context: RequestContext,
        cancellation: CancellationToken,
        parent_window: Option<WindowHandle>,
        activation_token: Option<String>,
        ui_backend: Option<OwnedWellKnownName>,
    ) -> Result<GetCredentialResponse, WebAuthnError> {
        let privileged = context.is_privileged();
        self.get_credential(
            request,
            context,
            cancellation,
            parent_window,
            activation_token,
            ui_backend,
        )
        .await
        .map_err(|err| err.for_caller(privileged))
    }

    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
        context: RequestContext,
        cancellation: CancellationToken,
        parent_window: Option<WindowHandle>,
        activation_token: Option<String>,
        ui_backend: Option<OwnedWellKnownName>,
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
                return Err(WebAuthnError::NotSupported);
            }
            let cred_request =
                CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request.clone());

            let response = with_timeout(
                ceremony_timeout(make_cred_request.timeout),
                &cancellation,
                |cancellation| {
                    self.request_controller.request_credential(
                        context.into(),
                        cred_request,
                        cancellation,
                        parent_window,
                        activation_token,
                        ui_backend,
                    )
                },
            )
            .await?;

            if let CredentialResponse::CreatePublicKeyCredentialResponse(cred_response) = response {
                let public_key_response =
                    create_credential_response_try_from_ctap2(&cred_response, &make_cred_request)
                        .map_err(|err| {
                        tracing::error!(
                            "Failed to parse credential response from authenticator: {err}"
                        );
                        WebAuthnError::Internal
                    })?;
                Ok(public_key_response.into())
            } else {
                // TODO: is response safe to log here?
                // tracing::error!("Expected create public key credential response, received {response:?}");
                tracing::error!("Did not receive expected create public key credential response.");
                Err(WebAuthnError::Internal)
            }
        } else {
            tracing::error!("Unknown credential type request: {}", request.r#type);
            Err(WebAuthnError::InvalidOptions)
        }
    }

    async fn get_credential(
        &self,
        request: GetCredentialRequest,
        context: RequestContext,
        cancellation: CancellationToken,
        parent_window: Option<WindowHandle>,
        activation_token: Option<String>,
        ui_backend: Option<OwnedWellKnownName>,
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
                    .inspect_err(|_| {
                        tracing::error!(
                            "Could not parse passkey assertion request. Rejecting request."
                        );
                    })?;
            let cred_request =
                CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request.clone());

            let response = with_timeout(
                ceremony_timeout(get_cred_request.timeout),
                &cancellation,
                |cancellation| {
                    self.request_controller.request_credential(
                        context.into(),
                        cred_request,
                        cancellation,
                        parent_window,
                        activation_token,
                        ui_backend,
                    )
                },
            )
            .await?;

            if let CredentialResponse::GetPublicKeyCredentialResponse(cred_response) = response {
                let public_key_response =
                    get_credential_response_try_from_ctap2(&cred_response, &get_cred_request)
                        .map_err(|err| {
                            tracing::error!(
                                "Failed to parse credential response from authenticator: {err}"
                            );
                            WebAuthnError::Internal
                        })?;
                Ok(public_key_response.into())
            } else {
                // TODO: is response safe to log here?
                // tracing::error!("Expected get public key credential response, received {response:?}");
                tracing::error!("Did not receive expected get public key credential response.");
                Err(WebAuthnError::Internal)
            }
        } else {
            tracing::error!(
                "Request did not match any known credential types. Supported types: [`public_key`]."
            );
            Err(WebAuthnError::InvalidOptions)
        }
    }
}

/// The shortest time a ceremony may take, following WebAuthn's recommended
/// range for ceremony timeouts.
const MIN_CEREMONY_TIMEOUT: Duration = Duration::from_secs(300);
/// The longest time a ceremony may take, following WebAuthn's recommended
/// range for ceremony timeouts.
const MAX_CEREMONY_TIMEOUT: Duration = Duration::from_secs(600);

/// Returns how long a ceremony may take, given the request's `timeout`.
///
/// Requests that leave `timeout` out get libwebauthn's default of 5 minutes.
/// libwebauthn still uses the request's own `timeout` for each command it
/// sends to an authenticator.
fn ceremony_timeout(requested: Duration) -> Duration {
    requested.clamp(MIN_CEREMONY_TIMEOUT, MAX_CEREMONY_TIMEOUT)
}

/// Runs `ceremony`, cancelling it if it takes longer than `timeout`.
///
/// `ceremony` is given a token that is cancelled when the client cancels the
/// request or the timeout passes. It should end soon after that. A timeout is
/// reported as [`WebAuthnError::Timeout`], unless the ceremony still ends in
/// another way, e.g. because the authenticator answered at the same time.
async fn with_timeout<T, F, Fut>(
    timeout: Duration,
    client_cancellation: &CancellationToken,
    ceremony: F,
) -> Result<T, WebAuthnError>
where
    F: FnOnce(CancellationToken) -> Fut,
    Fut: Future<Output = Result<T, WebAuthnError>>,
{
    let cancellation = client_cancellation.child_token();
    let ceremony = ceremony(cancellation.clone());
    tokio::pin!(ceremony);
    tokio::select! {
        biased;
        result = &mut ceremony => result,
        () = tokio::time::sleep(timeout) => {
            tracing::info!(?timeout, "Ceremony timed out, cancelling it");
            cancellation.cancel();
            // Wait for the ceremony to end, so that its UI is dismissed before
            // the next request starts.
            ceremony.await.map_err(|err| match err {
                WebAuthnError::UserCancelled => WebAuthnError::Timeout,
                err => err,
            })
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
                return Err(WebAuthnError::UntrustedCaller);
            }
        }
    };
    Ok(request_environment)
}

async fn should_trust_app_id(connection: &Connection, pidfd: BorrowedFd<'_>) -> bool {
    // Verify by systemd unit name
    if let Ok(true) = check_by_systemd_unit_name(connection, pidfd).await {
        return true;
    }

    // Verify if we should trust the peer based on the file name. We verify that
    // we're in the same mount namespace before using the exe path.
    let Some(pid) = read_pid_from_pidfd(pidfd).await else {
        return false;
    };
    // TODO: If the portal is running in a separate mount namespace for security
    // reasons, then this check will fail with a false negative.
    let Ok(my_mnt_ns) = tokio::fs::read_link("/proc/self/ns/mnt").await else {
        tracing::debug!("Could not read peer mount namespace");
        return false;
    };
    let Ok(peer_mnt_ns) = tokio::fs::read_link(format!("/proc/{}/ns/mnt", pid)).await else {
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

    let Ok(exe_path) = tokio::fs::read_link(format!("/proc/{}/exe", pid)).await else {
        tracing::warn!("Cannot read executable name from procfs");
        return false;
    };

    tracing::debug!(?exe_path, pidfd = %pidfd.as_raw_fd(), "Found executable path:");

    let mut trusted_callers: Vec<PathBuf> = vec![
        PathBuf::from("/usr/lib/xdg-desktop-portal"),
        PathBuf::from("/usr/libexec/xdg-desktop-portal"),
        PathBuf::from("/usr/local/lib/xdg-desktop-portal"),
        PathBuf::from("/usr/local/libexec/xdg-desktop-portal"),
    ];
    if let Some(trusted_callers_env) = trusted_client_override(TRUSTED_CALLERS_ENV) {
        let custom_paths = trusted_callers_env
            .split(',')
            .filter_map(|path| Path::new(path).canonicalize().ok());
        trusted_callers.extend(custom_paths);
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

async fn check_by_systemd_unit_name(
    connection: &Connection,
    pidfd: BorrowedFd<'_>,
) -> zbus::Result<bool> {
    let systemd_manager = crate::systemd::Manager::create(connection).await?;

    systemd_manager
        .match_unit_name_by_pidfd(pidfd, "xdg-desktop-portal.service")
        .await
}

async fn read_pid_from_pidfd<'a>(pidfd: BorrowedFd<'a>) -> Option<u32> {
    let pidfd_raw = pidfd.as_raw_fd();
    let fdinfo_str = match std::fs::read_to_string(format!("/proc/self/fdinfo/{pidfd_raw}")) {
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

pub(crate) const TRUSTED_CALLERS_ENV: &str = "CREDSD_TRUSTED_CALLERS";
pub(crate) const TRUSTED_APP_IDS_ENV: &str = "CREDSD_TRUSTED_APP_IDS";

/// Reads a development-only override of the trusted callers or app IDs.
/// Always `None` unless built with `-Denable_trusted_client_overrides=true`.
fn trusted_client_override(var: &str) -> Option<String> {
    if cfg!(feature = "trusted-client-overrides") {
        Some(std::env::var(var).unwrap_or_default())
    } else {
        None
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
            "firefox",
            "firefox-developer-edition",
            // Debian's Firefox ESR, launched from firefox-esr.desktop
            "firefox-esr",
            "xyz.iinuwa.credentialsd.DemoCredentialsUi",
        ];
        let mut privileged = trusted_clients.contains(&app_id.as_ref());
        if !privileged
            && let Some(trusted_clients_env) = trusted_client_override(TRUSTED_APP_IDS_ENV)
        {
            privileged = trusted_clients_env.split(',').any(|c| app_id.as_ref() == c);
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
            Err(WebAuthnError::InvalidOrigin)
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

/// Errors returned to gateway clients.
///
/// These are credentialsd-specific rather than WebAuthn DOMException names so
/// that they can carry more detail and be used by non-WebAuthn callers. Clients
/// map them back to WebAuthn errors as needed.
///
/// Errors that the caller could deduce from its own request parameters are
/// reported to every caller. Errors about how the ceremony went, like the user
/// cancelling it, are only reported to privileged clients, which are trusted
/// to pass them on to websites as WebAuthn errors that keep the user's
/// privacy. Other callers get [`WebAuthnError::NotAllowed`] instead (see
/// [`WebAuthnError::for_caller`]), so that they cannot learn whether the user
/// has credentials without the user's consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebAuthnError {
    /// The request was cancelled by the client. Not returned yet.
    ///
    /// WebAuthn equivalent: `AbortError`.
    Aborted,

    /// `userVerification` was set to `required` and no available authenticator
    /// can perform user verification. Not returned yet.
    ///
    /// WebAuthn equivalent: `ConstraintError`.
    UserVerificationUnsatisfiable,

    /// `residentKey` was set to `required` and no available authenticator
    /// supports discoverable credentials. Not returned yet.
    ///
    /// WebAuthn equivalent: `ConstraintError`.
    DiscoverableCredentialUnsatisfiable,

    /// The authenticator recognized an entry in `excludeCredentials`.
    ///
    /// WebAuthn equivalent: `InvalidStateError`.
    CredentialExcluded,

    /// No entry in `pubKeyCredParams` is supported, or the request uses an
    /// option that is not supported.
    ///
    /// WebAuthn equivalent: `NotSupportedError`.
    NotSupported,

    /// The origin is not a valid HTTPS origin, or the RP ID (or AppID) is not
    /// valid for the origin.
    ///
    /// WebAuthn equivalent: `SecurityError`.
    InvalidOrigin,

    /// The calling application could not be verified, or is not allowed to
    /// make requests for the given origin.
    ///
    /// WebAuthn equivalent: `SecurityError`.
    UntrustedCaller,

    /// `user.id` is empty or longer than 64 bytes.
    ///
    /// WebAuthn equivalent: `TypeError`.
    InvalidUserId,

    /// The request options are missing or malformed.
    ///
    /// WebAuthn equivalent: `TypeError`.
    InvalidOptions,

    /// The user cancelled the ceremony. Only reported to privileged clients.
    ///
    /// WebAuthn equivalent: `NotAllowedError`.
    UserCancelled,

    /// The ceremony did not finish before its timeout. Only reported to
    /// privileged clients.
    ///
    /// WebAuthn equivalent: `NotAllowedError`.
    Timeout,

    /// The ceremony failed because of a problem in credentialsd or its UI,
    /// not because of anything the user or the request did. Only reported to
    /// privileged clients.
    ///
    /// WebAuthn equivalent: `NotAllowedError`.
    Internal,

    /// A catch-all error. Unprivileged clients get this for the errors that
    /// only privileged clients are told about.
    ///
    /// WebAuthn equivalent: `NotAllowedError`.
    NotAllowed,
}

impl WebAuthnError {
    /// Returns the error to report to a caller, hiding the ones that only
    /// privileged clients may see.
    fn for_caller(self, privileged: bool) -> Self {
        match self {
            Self::UserCancelled | Self::Timeout | Self::Internal if !privileged => Self::NotAllowed,
            err => err,
        }
    }
}

impl std::error::Error for WebAuthnError {}

impl Display for WebAuthnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            WebAuthnError::Aborted => "Operation was aborted by client.",
            WebAuthnError::UserVerificationUnsatisfiable => {
                "User verification was required, but no available authenticator supports it."
            }
            WebAuthnError::DiscoverableCredentialUnsatisfiable => {
                "A discoverable credential was required, but no available authenticator supports it."
            }
            WebAuthnError::CredentialExcluded => {
                "The authenticator already contains a credential listed in excludeCredentials."
            }
            WebAuthnError::NotSupported => "Operation parameters are not supported.",
            WebAuthnError::InvalidOrigin => "The origin or RP ID is not valid for this request.",
            WebAuthnError::UntrustedCaller => "The calling application could not be verified.",
            WebAuthnError::InvalidUserId => "user.id must be between 1 and 64 bytes long.",
            WebAuthnError::InvalidOptions => "Invalid request options specified.",
            WebAuthnError::UserCancelled => "The user cancelled the operation.",
            WebAuthnError::Timeout => "The operation timed out.",
            WebAuthnError::Internal => "The operation failed because of an internal error.",
            WebAuthnError::NotAllowed => {
                "An unspecified error occurred, and the operation is not allowed to continue."
            }
        })
    }
}

#[cfg(test)]
mod test {
    use crate::webauthn::{AppId, NavigationContext, Origin};

    use std::time::Duration;

    use async_trait::async_trait;
    use credentialsd_common::model::WindowHandle;
    use tokio_util::sync::CancellationToken;
    use zbus::names::OwnedWellKnownName;

    use crate::{
        dbus::CredentialRequestController,
        model::{ClientDetails, CredentialRequest, CredentialResponse},
    };

    use super::{
        CreateCredentialRequest, CreatePublicKeyCredentialRequest, GatewayService, RequestContext,
        RequestKind, WebAuthnError, ceremony_timeout, check_origin_from_app,
        check_origin_from_privileged_client, trusted_client_override, with_timeout,
    };

    /// A controller whose ceremonies always fail with the given error.
    struct FailingController(WebAuthnError);

    #[async_trait]
    impl CredentialRequestController for FailingController {
        async fn request_credential(
            &self,
            _requesting_app: ClientDetails,
            _request: CredentialRequest,
            _cancellation: CancellationToken,
            _window_handle: Option<WindowHandle>,
            _activation_token: Option<String>,
            _ui_backend: Option<OwnedWellKnownName>,
        ) -> Result<CredentialResponse, WebAuthnError> {
            Err(self.0)
        }
    }

    async fn create_credential_error(
        err: WebAuthnError,
        request_kind: RequestKind,
    ) -> WebAuthnError {
        let service = GatewayService {
            request_controller: Box::new(FailingController(err)),
        };
        let request = CreateCredentialRequest {
            r#type: "publicKey".to_string(),
            public_key: Some(CreatePublicKeyCredentialRequest {
                request_json: r#"{"rp":{"id":"example.com","name":"x"},"user":{"id":"AAAA","name":"a","displayName":"a"},"challenge":"AAAAAAAAAAAAAAAAAAAAAA","pubKeyCredParams":[{"type":"public-key","alg":-7}]}"#.to_string(),
            }),
        };
        let context = RequestContext {
            app_id: "org.example.App".parse().unwrap(),
            pid: 0,
            request_kind,
        };
        service
            .handle_create_credential(request, context, CancellationToken::new(), None, None, None)
            .await
            .err()
            .expect("the ceremony should fail")
    }

    #[tokio::test]
    async fn test_gateway_hides_outcome_errors_from_unprivileged_callers() {
        let origin: Origin = "https://example.com".parse().unwrap();
        for err in OUTCOME_ERRORS {
            assert_eq!(
                create_credential_error(err, RequestKind::Unprivileged(origin.clone())).await,
                WebAuthnError::NotAllowed,
                "{err:?}"
            );
            assert_eq!(
                create_credential_error(
                    err,
                    RequestKind::Privileged {
                        origin: origin.clone(),
                        top_origin: None,
                    }
                )
                .await,
                err
            );
        }
    }

    /// Errors that every caller may see. Apart from `CredentialExcluded`, which
    /// WebAuthn also reports to websites once the user has confirmed it on the
    /// authenticator, they only depend on the request.
    const REQUEST_ERRORS: [WebAuthnError; 9] = [
        WebAuthnError::Aborted,
        WebAuthnError::UserVerificationUnsatisfiable,
        WebAuthnError::DiscoverableCredentialUnsatisfiable,
        WebAuthnError::CredentialExcluded,
        WebAuthnError::NotSupported,
        WebAuthnError::InvalidOrigin,
        WebAuthnError::UntrustedCaller,
        WebAuthnError::InvalidUserId,
        WebAuthnError::InvalidOptions,
    ];

    /// Errors about how the ceremony went, which only privileged callers see.
    const OUTCOME_ERRORS: [WebAuthnError; 3] = [
        WebAuthnError::UserCancelled,
        WebAuthnError::Timeout,
        WebAuthnError::Internal,
    ];

    #[test]
    fn test_ceremony_timeout_is_kept_within_the_recommended_range() {
        let secs = Duration::from_secs;
        assert_eq!(ceremony_timeout(secs(30)), secs(300));
        assert_eq!(ceremony_timeout(secs(300)), secs(300));
        assert_eq!(ceremony_timeout(secs(450)), secs(450));
        assert_eq!(ceremony_timeout(secs(3600)), secs(600));
    }

    #[tokio::test]
    async fn test_ceremony_is_cancelled_when_it_times_out() {
        let client_cancellation = CancellationToken::new();
        let result: Result<(), _> = with_timeout(
            Duration::from_millis(10),
            &client_cancellation,
            |cancellation| async move {
                // Like the real flow, end the ceremony once it is cancelled.
                cancellation.cancelled().await;
                Err(WebAuthnError::UserCancelled)
            },
        )
        .await;
        assert_eq!(result, Err(WebAuthnError::Timeout));
        assert!(
            !client_cancellation.is_cancelled(),
            "a timeout must not look like the client cancelling"
        );
    }

    #[tokio::test]
    async fn test_other_errors_are_kept_when_the_ceremony_times_out() {
        let result: Result<(), _> = with_timeout(
            Duration::from_millis(10),
            &CancellationToken::new(),
            |cancellation| async move {
                // The authenticator answered just as the ceremony was cancelled.
                cancellation.cancelled().await;
                Err(WebAuthnError::CredentialExcluded)
            },
        )
        .await;
        assert_eq!(result, Err(WebAuthnError::CredentialExcluded));
    }

    #[tokio::test]
    async fn test_ceremony_result_is_kept_when_it_ends_in_time() {
        let result: Result<(), _> = with_timeout(
            Duration::from_secs(60),
            &CancellationToken::new(),
            |_| async { Err(WebAuthnError::CredentialExcluded) },
        )
        .await;
        assert_eq!(result, Err(WebAuthnError::CredentialExcluded));
    }

    #[tokio::test]
    async fn test_ceremony_is_cancelled_when_the_client_cancels() {
        let client_cancellation = CancellationToken::new();
        client_cancellation.cancel();
        let result: Result<(), _> = with_timeout(
            Duration::from_secs(60),
            &client_cancellation,
            |cancellation| async move {
                cancellation.cancelled().await;
                Err(WebAuthnError::UserCancelled)
            },
        )
        .await;
        assert_eq!(result, Err(WebAuthnError::UserCancelled));
    }

    #[test]
    fn test_outcome_errors_are_hidden_from_unprivileged_callers() {
        for err in OUTCOME_ERRORS {
            assert_eq!(err.for_caller(false), WebAuthnError::NotAllowed, "{err:?}");
        }
    }

    #[test]
    fn test_outcome_errors_are_shown_to_privileged_callers() {
        for err in OUTCOME_ERRORS {
            assert_eq!(err.for_caller(true), err);
        }
    }

    #[test]
    fn test_request_errors_are_shown_to_every_caller() {
        for privileged in [true, false] {
            for err in REQUEST_ERRORS
                .into_iter()
                .chain([WebAuthnError::NotAllowed])
            {
                assert_eq!(err.for_caller(privileged), err, "privileged: {privileged}");
            }
        }
    }

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
    fn test_returns_invalid_origin_when_passing_app_id_origin() {
        assert!(matches!(
            check_same_origin("app:com.example.App"),
            Err(WebAuthnError::InvalidOrigin)
        ))
    }

    fn request_kind_for_app(app_id: &str) -> RequestKind {
        let app_id: AppId = app_id.parse().unwrap();
        let origin = "https://example.com".parse().unwrap();
        check_origin_from_app(&app_id, origin, None).unwrap()
    }

    #[test]
    fn test_firefox_esr_is_privileged() {
        assert!(matches!(
            request_kind_for_app("firefox-esr"),
            RequestKind::Privileged { .. }
        ))
    }

    #[test]
    fn test_unknown_app_is_unprivileged() {
        assert!(matches!(
            request_kind_for_app("com.example.App"),
            RequestKind::Unprivileged(_)
        ))
    }

    // PATH is always set, so these check the feature gate without set_var.
    #[cfg(not(feature = "trusted-client-overrides"))]
    #[test]
    fn test_env_overrides_are_ignored_without_overrides_feature() {
        assert_eq!(trusted_client_override("PATH"), None);
    }

    #[cfg(feature = "trusted-client-overrides")]
    #[test]
    fn test_env_overrides_are_read_with_overrides_feature() {
        assert!(trusted_client_override("PATH").is_some_and(|p| !p.is_empty()));
    }
}
