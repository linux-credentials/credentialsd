pub mod bluetooth;
pub mod hybrid;
pub mod nfc;
pub mod usb;

use std::{
    fmt::{Debug, Display},
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::Poll,
    time::Duration,
};

use async_trait::async_trait;
use futures_lite::{FutureExt, Stream, StreamExt};
use libwebauthn::{
    self,
    ops::webauthn::{GetAssertionResponse, MakeCredentialResponse},
};
use libwebauthn::{
    available_transports,
    pin::persistent_token::{MemoryPersistentTokenStore, PersistentTokenStore},
};
use nfc::{NfcEvent, NfcHandler, NfcState, NfcStateInternal};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use credentialsd_common::model::{BackgroundEvent, Device, Transport};
use zbus::zvariant::{self, Value};

use crate::{
    credential_service::{hybrid::HybridEvent, usb::UsbEvent},
    model::{CredentialRequest, CredentialResponse},
};

use self::{
    hybrid::{HybridHandler, HybridState, HybridStateInternal},
    usb::{UsbHandler, UsbStateInternal},
};

pub use usb::UsbState;

/// Identifier for a request to be used for cancellation.
pub type RequestId = u32;

/// Helper function to sleep with cancellation support.
async fn cancellable_sleep(
    duration: std::time::Duration,
    cancellation: &CancellationToken,
) -> Result<(), CredentialServiceError> {
    tokio::select! {
        _ = tokio::time::sleep(duration) => Ok(()),
        _ = cancellation.cancelled() => {
            Err(CredentialServiceError::NonTerminatingCancellation)
        }
    }
}

/// Process-wide in-memory store so a security key's pinUvAuthToken is reused across ceremonies.
fn persistent_token_store() -> Arc<dyn PersistentTokenStore> {
    static STORE: OnceLock<Arc<MemoryPersistentTokenStore>> = OnceLock::new();
    STORE
        .get_or_init(|| Arc::new(MemoryPersistentTokenStore::new()))
        .clone()
}

#[derive(Debug, Clone)]
pub enum CredentialServiceError {
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
    /// Internal cancellation — the ceremony was cancelled because another transport
    /// completed first (superseded), or because a code-path cancellation propagated.
    /// This is distinct from user- or client-issued cancellation: the response channel
    /// has already been consumed elsewhere, so `complete_request` must NOT be called.
    NonTerminatingCancellation,
    // TODO: We may want to hide the details on this variant from the public API.
    /// Something went wrong with the credential service itself, not the authenticator.
    Internal(String),
}

impl std::error::Error for CredentialServiceError {}

impl Display for CredentialServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticatorError => f.write_str("AuthenticatorError"),
            Self::NoCredentials => f.write_str("NoCredentials"),
            Self::CredentialExcluded => f.write_str("CredentialExcluded"),
            Self::PinAttemptsExhausted => f.write_str("PinAttemptsExhausted"),
            Self::NonTerminatingCancellation => f.write_str("NonTerminatingCancellation"),
            Self::Internal(s) => write!(f, "InternalError: {s}"),
        }
    }
}

impl TryFrom<&Value<'_>> for CredentialServiceError {
    type Error = zvariant::Error;

    fn try_from(value: &Value<'_>) -> Result<Self, Self::Error> {
        let err_code: &str = value.downcast_ref()?;
        let err = match err_code {
            "AuthenticatorError" => Self::AuthenticatorError,
            "NoCredentials" => Self::NoCredentials,
            "CredentialExcluded" => Self::CredentialExcluded,
            "PinAttemptsExhausted" => Self::PinAttemptsExhausted,
            "NonTerminatingCancellation" => Self::NonTerminatingCancellation,
            s => Self::Internal(String::from(s)),
        };
        Ok(err)
    }
}

#[derive(Debug)]
struct RequestContext {
    request: CredentialRequest,
    response_channel: oneshot::Sender<Result<CredentialResponse, CredentialServiceError>>,
    request_id: RequestId,
    cancellation: CancellationToken,
}

impl RequestContext {
    fn send_response(self, response: Result<CredentialResponse, CredentialServiceError>) {
        if self.response_channel.send(response).is_err() {
            tracing::error!(
                "Attempted to send credential response to caller, but channel was closed."
            );
        }
    }
}

/// Manages request to authenticator devices.
#[async_trait]
pub trait ManageDevice {
    async fn init_request(
        &self,
        request: &CredentialRequest,
        tx: oneshot::Sender<Result<CredentialResponse, CredentialServiceError>>,
    ) -> Result<(RequestId, CancellationToken), CredentialServiceError>;
    async fn cancel_request(&self, request_id: RequestId);
    async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()>;
    async fn start_discovery(
        &self,
    ) -> Pin<Box<dyn Stream<Item = DeviceStateUpdate> + Send + 'static>>;
}

#[derive(Debug)]
pub struct CredentialService<H: HybridHandler, N: NfcHandler, U: UsbHandler> {
    /// Current request and channel to respond to caller.
    ctx: Arc<Mutex<Option<RequestContext>>>,

    /// Shared so hybrid discovery can be started later in a request, once
    /// Bluetooth becomes available.
    hybrid_handler: Arc<Mutex<H>>,
    _nfc_handler: Mutex<N>,
    usb_handler: Mutex<U>,
}

impl<H: HybridHandler + Debug, N: NfcHandler + Debug, U: UsbHandler + Debug>
    CredentialService<H, N, U>
{
    pub fn new(hybrid_handler: H, nfc_handler: N, usb_handler: U) -> Self {
        Self {
            ctx: Arc::new(Mutex::new(None)),

            hybrid_handler: Arc::new(Mutex::new(hybrid_handler)),
            _nfc_handler: Mutex::new(nfc_handler),
            usb_handler: Mutex::new(usb_handler),
        }
    }
}

impl<H: HybridHandler + Send, N: NfcHandler + Send, U: UsbHandler + Send>
    CredentialService<H, N, U>
{
    async fn get_hybrid_credential(
        &self,
    ) -> Pin<Box<dyn Stream<Item = HybridState> + Send + 'static>> {
        let request_id = self.ctx.lock().unwrap().as_ref().map(|ctx| ctx.request_id);
        match request_id.and_then(|id| start_hybrid(&self.hybrid_handler, &self.ctx, id)) {
            Some(stream) => stream,
            None => {
                tracing::error!(
                    "Attempted to start hybrid credential flow, but no request context was found."
                );
                todo!("Handle error when context is not set up.")
            }
        }
    }

    async fn get_usb_credential(&self) -> Pin<Box<dyn Stream<Item = UsbState> + Send + 'static>> {
        let guard = self.ctx.lock().unwrap();
        if let Some(RequestContext {
            ref request,
            ref cancellation,
            ..
        }) = *guard
        {
            let stream = self
                .usb_handler
                .lock()
                .unwrap()
                .start(request, cancellation.clone());
            let ctx = self.ctx.clone();
            Box::pin(UsbStateStream {
                inner: stream,
                ctx,
                cancellation_token: cancellation.clone(),
            })
        } else {
            tracing::error!(
                "Attempted to start usb credential flow, but no request context was found."
            );
            todo!("Handle error when context is not set up.")
        }
    }

    async fn _get_nfc_credential(&self) -> Pin<Box<dyn Stream<Item = NfcState> + Send + 'static>> {
        let guard = self.ctx.lock().unwrap();
        if let Some(RequestContext {
            ref request,
            ref cancellation,
            ..
        }) = *guard
        {
            let stream = self
                ._nfc_handler
                .lock()
                .unwrap()
                .start(request, cancellation.clone());
            let ctx = self.ctx.clone();
            Box::pin(NfcStateStream {
                inner: stream,
                ctx,
                cancellation_token: cancellation.clone(),
            })
        } else {
            tracing::error!(
                "Attempted to start nfc credential flow, but no request context was found."
            );
            todo!("Handle error when context is not set up.")
        }
    }
}

#[async_trait]
impl<H: HybridHandler + Send + 'static, N: NfcHandler + Send, U: UsbHandler + Send> ManageDevice
    for CredentialService<H, N, U>
{
    async fn init_request(
        &self,
        request: &CredentialRequest,
        tx: oneshot::Sender<Result<CredentialResponse, CredentialServiceError>>,
    ) -> Result<(RequestId, CancellationToken), CredentialServiceError> {
        let mut cred_request = self.ctx.lock().unwrap();
        if cred_request.is_some() {
            Err(CredentialServiceError::Internal(
                "Already a request in progress.".to_string(),
            ))
        } else {
            // Generate non-zero request ID
            let request_id: RequestId = rand::random_range(1..=u32::MAX);
            let cancellation = CancellationToken::new();
            // TODO: Spawn a task here that will listen to the signals from ui_control_client.
            // Move the get_*_credential(), etc. from gateway to here.
            let ctx = RequestContext {
                request: request.clone(),
                response_channel: tx,
                request_id,
                cancellation: cancellation.clone(),
            };
            _ = cred_request.insert(ctx);
            Ok((request_id, cancellation))
        }
    }

    async fn cancel_request(&self, request_id: RequestId) {
        let mut guard = self.ctx.lock().expect("Lock to be taken");
        if let Some(ctx) = guard.take_if(|ctx| ctx.request_id == request_id)
            && request_id == ctx.request_id
        {
            tracing::debug!("Cancelling request {request_id}");
            ctx.cancellation.cancel();

            // It's fine if the requestor is no longer listening for the response.
            // TODO: create Cancelled variant
            _ = ctx
                .response_channel
                .send(Err(CredentialServiceError::Internal(format!(
                    "Cancelled request {request_id}."
                ))));
        }
    }

    async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        // We create the list new for each call, in case someone plugs in
        // an NFC-reader in the middle of an auth-flow
        Ok(devices_for_transports(&usable_transports().await))
    }

    async fn start_discovery(
        &self,
    ) -> Pin<Box<dyn Stream<Item = DeviceStateUpdate> + Send + 'static>> {
        let available_transports = usable_transports().await;
        // The UI got its device list before it asked for discovery, and
        // Bluetooth may have been turned on or off in between.
        let mut selected_transports = vec![
            futures_lite::stream::once(DeviceStateUpdate::DevicesChanged(devices_for_transports(
                &available_transports,
            )))
            .boxed(),
        ];
        if available_transports.contains(&libwebauthn::Transport::Usb) {
            let usb = self
                .get_usb_credential()
                .await
                .map(DeviceStateUpdate::from)
                .boxed();
            selected_transports.push(usb);
        }
        /*
        TODO: Some cards that support NFC but not CCID (SoloKey Solo 2 NFC)
        cause a framing error immediately after establishing a libwebauthn
        Channel, which causes the whole ceremony to abort without the user
        intending to. We need to determine some way of working around buggy
        security keys, while at the same time supporting actual NFC cards and CCID.
        Maybe we can defer sending "Connected" to the UI until a user presence
        or verification message is sent.
        if available_transports.contains(&libwebauthn::Transport::Nfc) {
            let nfc = self
                .get_nfc_credential()
                .await
                .map(DeviceStateUpdate::from)
                .boxed();
            selected_transports.push(nfc);
        }
        */
        if available_transports.contains(&libwebauthn::Transport::Hybrid) {
            let hybrid = self
                .get_hybrid_credential()
                .await
                .map(DeviceStateUpdate::from)
                .boxed();
            selected_transports.push(hybrid);
        } else if let Some((request_id, cancellation)) = self
            .ctx
            .lock()
            .unwrap()
            .as_ref()
            .map(|ctx| (ctx.request_id, ctx.cancellation.clone()))
        {
            let handler = self.hybrid_handler.clone();
            let ctx = self.ctx.clone();
            let without_bluetooth = available_transports.clone();
            // Only BlueZ is asked again; USB and NFC availability is kept from
            // the start of the request.
            let probe = move || {
                let without_bluetooth = without_bluetooth.clone();
                async move {
                    let powered = bluetooth::adapter_powered().await;
                    let mut transports = without_bluetooth;
                    if powered {
                        transports
                            .extend([libwebauthn::Transport::Ble, libwebauthn::Transport::Hybrid]);
                    }
                    transports
                }
            };
            let watch =
                hybrid_when_available(probe, TRANSPORT_POLL_INTERVAL, cancellation, move || {
                    start_hybrid(&handler, &ctx, request_id)
                        .map(|stream| stream.map(DeviceStateUpdate::from))
                })
                .boxed();
            selected_transports.push(watch);
        }
        futures::stream::select_all(selected_transports).boxed()
    }
}

pub struct HybridStateStream<H> {
    inner: H,
    ctx: Arc<Mutex<Option<RequestContext>>>,
    cancellation_token: CancellationToken,
}

impl<H> Stream for HybridStateStream<H>
where
    H: Stream<Item = HybridEvent> + Unpin + Sized,
{
    type Item = HybridState;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let ctx = &self.ctx.clone();
        let cancellation_token = self.cancellation_token.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(HybridEvent { state })) => {
                if cancellation_token.is_cancelled() {
                    return Poll::Ready(None);
                }
                match &state {
                    HybridStateInternal::Completed(response) => {
                        complete_request(ctx, Ok(response.clone()));
                    }
                    HybridStateInternal::Failed(err) if is_ceremony_terminating(err) => {
                        complete_request(ctx, Err(err.clone()));
                    }
                    HybridStateInternal::Failed(_) => {
                        // Non-terminating: forward the Failed state to the UI
                        // without calling complete_request. The ceremony stays alive
                        // for other transports. The transport is expected to restart
                        // itself.
                    }
                    _ => {}
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

struct UsbStateStream<H> {
    inner: H,
    ctx: Arc<Mutex<Option<RequestContext>>>,
    cancellation_token: CancellationToken,
}

impl<H> Stream for UsbStateStream<H>
where
    H: Stream<Item = UsbEvent> + Unpin + Sized,
{
    type Item = UsbState;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let ctx = &self.ctx.clone();
        let cancellation_token = self.cancellation_token.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(UsbEvent { state })) => {
                if cancellation_token.is_cancelled() {
                    return Poll::Ready(None);
                }
                match &state {
                    UsbStateInternal::Completed(response) => {
                        complete_request(ctx, Ok(response.clone()));
                    }
                    UsbStateInternal::Failed(err) if is_ceremony_terminating(err) => {
                        complete_request(ctx, Err(err.clone()));
                    }
                    UsbStateInternal::Failed(_) => {
                        // Non-terminating: forward the Failed state to the UI
                        // without calling complete_request. The ceremony stays alive
                        // for other transports. The transport is expected to restart
                        // itself.
                    }
                    _ => {}
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

#[expect(unused)]
struct NfcStateStream<H> {
    inner: H,
    ctx: Arc<Mutex<Option<RequestContext>>>,
    cancellation_token: CancellationToken,
}

impl<H> Stream for NfcStateStream<H>
where
    H: Stream<Item = NfcEvent> + Unpin + Sized,
{
    type Item = NfcState;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let ctx = &self.ctx.clone();
        let cancellation_token = self.cancellation_token.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(NfcEvent { state })) => {
                if cancellation_token.is_cancelled() {
                    return Poll::Ready(None);
                }

                match &state {
                    NfcStateInternal::Completed(response) => {
                        complete_request(ctx, Ok(response.clone()));
                    }
                    NfcStateInternal::Failed(err) if is_ceremony_terminating(err) => {
                        complete_request(ctx, Err(err.clone()));
                    }
                    NfcStateInternal::Failed(_) => {
                        // Non-terminating: forward the Failed state to the UI
                        // without calling complete_request. The ceremony stays alive
                        // for other transports. The transport is expected to restart
                        // itself.
                    }
                    _ => {}
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

pub enum DeviceStateUpdate {
    Hybrid(HybridState),
    Nfc(NfcState),
    Usb(UsbState),
    /// The devices offered to the user changed during the request.
    DevicesChanged(Vec<Device>),
}

impl From<DeviceStateUpdate> for BackgroundEvent {
    fn from(value: DeviceStateUpdate) -> Self {
        match value {
            DeviceStateUpdate::DevicesChanged(devices) => BackgroundEvent::DevicesChanged(devices),
            DeviceStateUpdate::Hybrid(state) => (&state).into(),
            DeviceStateUpdate::Nfc(state) => (&state).into(),
            DeviceStateUpdate::Usb(state) => (&state).into(),
        }
    }
}

impl From<HybridState> for DeviceStateUpdate {
    fn from(value: HybridState) -> Self {
        Self::Hybrid(value)
    }
}

impl From<NfcState> for DeviceStateUpdate {
    fn from(value: NfcState) -> Self {
        Self::Nfc(value)
    }
}

impl From<UsbState> for DeviceStateUpdate {
    fn from(value: UsbState) -> Self {
        Self::Usb(value)
    }
}

/// Returns `true` if this arm of `poll_next` must call `complete_request()`,
/// terminating the entire ceremony. Returns `false` if the error is
/// per-authenticator or already-handled: the ceremony continues on other
/// transports, and this transport is expected to restart itself.
///
/// The `match` has no wildcard arm so any new `Error` variant forces a
/// deliberate decision here. The mapping follows the WebAuthn specification:
///   - https://www.w3.org/TR/webauthn-3/#sctn-create-request-exceptions
///   - https://www.w3.org/TR/webauthn-3/#sctn-get-request-exceptions
pub(super) fn is_ceremony_terminating(err: &CredentialServiceError) -> bool {
    match err {
        // WebAuthn spec requires CredentialExcluded be remapped to InvalidStateError
        // and returned to the RP. The credential is already registered on this
        // authenticator.
        CredentialServiceError::CredentialExcluded => true,

        // NonTerminatingCancellation is emitted by transports whose ceremony was
        // cancelled by *another* path — the winning transports `complete_request()`,
        // or `cancel_request()` sending its own response. The response channel is
        // already consumed, so this arm must NOT invoke `complete_request()` again.
        // A future `TerminatingCancellation` variant will handle user-initiated
        // cancellation from the trusted UI, which is ceremony-terminating.
        CredentialServiceError::NonTerminatingCancellation => false,

        // Per-authenticator errors: keep the ceremony alive. The user may succeed
        // on another transport, or the same transport may recover and retry
        // (the latter is not yet implemented).
        CredentialServiceError::AuthenticatorError => false,
        CredentialServiceError::NoCredentials => false,
        CredentialServiceError::PinAttemptsExhausted => false,

        // Transient internal errors: do not kill the ceremony.
        CredentialServiceError::Internal(_) => false,
    }
}

fn complete_request(
    ctx: &Mutex<Option<RequestContext>>,
    response: Result<CredentialResponse, CredentialServiceError>,
) {
    match ctx.lock().unwrap().take() {
        Some(ctx) => {
            ctx.cancellation.cancel();
            ctx.send_response(response);
        }
        _ => {
            tracing::error!("Tried to consume context to respond to caller, but none was found.")
        }
    }
}

#[derive(Debug, Clone)]
enum AuthenticatorResponse {
    CredentialCreated(Box<MakeCredentialResponse>),
    CredentialsAsserted(GetAssertionResponse),
}

impl From<MakeCredentialResponse> for AuthenticatorResponse {
    fn from(value: MakeCredentialResponse) -> Self {
        Self::CredentialCreated(Box::new(value))
    }
}

impl From<GetAssertionResponse> for AuthenticatorResponse {
    fn from(value: GetAssertionResponse) -> Self {
        Self::CredentialsAsserted(value)
    }
}

/// The transports that can be used right now: libwebauthn's list, without
/// the Bluetooth-based ones unless an adapter is powered on.
async fn usable_transports() -> Vec<libwebauthn::Transport> {
    let transports = available_transports().await;
    let powered =
        transports.contains(&libwebauthn::Transport::Hybrid) && bluetooth::adapter_powered().await;
    with_bluetooth_power(transports, powered)
}

fn with_bluetooth_power(
    mut transports: Vec<libwebauthn::Transport>,
    powered: bool,
) -> Vec<libwebauthn::Transport> {
    if !powered {
        transports.retain(|t| {
            !matches!(
                t,
                libwebauthn::Transport::Ble | libwebauthn::Transport::Hybrid
            )
        });
    }
    transports
}

/// How often to check whether Bluetooth became available during a request.
const TRANSPORT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Starts hybrid discovery for request `request_id`, or returns `None` if that
/// request is no longer the current one.
fn start_hybrid<H: HybridHandler>(
    handler: &Mutex<H>,
    ctx: &Arc<Mutex<Option<RequestContext>>>,
    request_id: RequestId,
) -> Option<Pin<Box<dyn Stream<Item = HybridState> + Send + 'static>>> {
    let guard = ctx.lock().unwrap();
    let RequestContext {
        request,
        cancellation,
        ..
    } = guard.as_ref().filter(|ctx| ctx.request_id == request_id)?;
    let stream = handler.lock().unwrap().start(request, cancellation.clone());
    Some(Box::pin(HybridStateStream {
        inner: stream,
        ctx: ctx.clone(),
        cancellation_token: cancellation.clone(),
    }))
}

/// Waits for hybrid to become available during a request, e.g. because the
/// user turned Bluetooth on, by calling `probe` every `interval`. Then yields
/// the new device list and continues with the stream from `start_hybrid`.
///
/// Ends without yielding anything if `cancellation` fires first (the request
/// finished or was cancelled), or if `start_hybrid` returns `None`.
fn hybrid_when_available<P, F, S>(
    mut probe: P,
    interval: Duration,
    cancellation: CancellationToken,
    start_hybrid: impl FnOnce() -> Option<S> + Send + 'static,
) -> impl Stream<Item = DeviceStateUpdate> + Send + 'static
where
    P: FnMut() -> F + Send + 'static,
    F: Future<Output = Vec<libwebauthn::Transport>> + Send,
    S: Stream<Item = DeviceStateUpdate> + Send + 'static,
{
    let wait_for_hybrid = async move {
        let transports = cancellation
            .run_until_cancelled(async {
                loop {
                    tokio::time::sleep(interval).await;
                    let transports = probe().await;
                    if transports.contains(&libwebauthn::Transport::Hybrid) {
                        break transports;
                    }
                }
            })
            .await?;
        if cancellation.is_cancelled() {
            return None;
        }
        let hybrid = start_hybrid()?;
        tracing::debug!("Bluetooth became available, starting hybrid discovery");
        let devices = DeviceStateUpdate::DevicesChanged(devices_for_transports(&transports));
        Some(futures_lite::stream::once(devices).chain(hybrid))
    };
    futures_lite::stream::once_future(wait_for_hybrid)
        .filter_map(|stream| stream)
        .flatten()
}

/// The devices to offer the user for the given available transports, with a
/// stable ID per transport.
///
/// libwebauthn reports Bluetooth availability as both `Ble` and `Hybrid`; only
/// hybrid (QR code) flows are offered for now.
fn devices_for_transports(available: &[libwebauthn::Transport]) -> Vec<Device> {
    [
        (libwebauthn::Transport::Usb, "0", Transport::Usb),
        (libwebauthn::Transport::Hybrid, "1", Transport::HybridQr),
        (libwebauthn::Transport::Nfc, "2", Transport::Nfc),
    ]
    .into_iter()
    .filter(|(available_transport, _, _)| available.contains(available_transport))
    .map(|(_, id, transport)| Device {
        id: String::from(id),
        transport,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Mock handlers for testing
    #[derive(Debug)]
    struct MockUsbHandler;
    impl UsbHandler for MockUsbHandler {
        fn start(
            &self,
            _request: &CredentialRequest,
            _cancellation: CancellationToken,
        ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static {
            futures::stream::empty()
        }
    }

    #[derive(Debug)]
    struct MockHybridHandler;
    impl HybridHandler for MockHybridHandler {
        fn start(
            &self,
            _request: &CredentialRequest,
            _cancellation: CancellationToken,
        ) -> impl Stream<Item = HybridEvent> + Unpin + Send + Sized + 'static {
            futures::stream::empty()
        }
    }

    #[derive(Debug)]
    struct MockNfcHandler;
    impl NfcHandler for MockNfcHandler {
        fn start(
            &self,
            _request: &CredentialRequest,
            _cancellation: CancellationToken,
        ) -> impl Stream<Item = NfcEvent> + Send + Sized + Unpin + 'static {
            futures::stream::empty()
        }
    }

    fn create_test_credential_response() -> CredentialResponse {
        use libwebauthn::ops::webauthn::GetAssertionResponse;

        // Create a minimal GetAssertion response for testing
        let get_assertion_response = GetAssertionResponse {
            assertions: vec![libwebauthn::ops::webauthn::Assertion {
                credential_id: None,
                authenticator_data: libwebauthn::fido::AuthenticatorData {
                    rp_id_hash: [0u8; 32],
                    flags: libwebauthn::fido::AuthenticatorDataFlags::empty(),
                    signature_count: 0,
                    attested_credential: None,
                    extensions: None,
                    raw: None,
                },
                signature: vec![],
                user: None,
                credentials_count: None,
                user_selected: None,
                unsigned_extensions_output: None,
                transport: None,
            }],
        };

        CredentialResponse::from_get_assertion(
            &get_assertion_response.assertions[0],
            "cross-platform",
        )
    }

    async fn create_test_request() -> CredentialRequest {
        use libwebauthn::ops::webauthn::{
            MakeCredentialRequest, OriginValidation, RequestSettings, idl::origin::RequestOrigin,
        };

        let request_json = r#"
            {
                "rp": {
                    "id": "example.com",
                    "name": "Example Relying Party"
                },
                "user": {
                    "id": "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg",
                    "name": "test@example.com",
                    "displayName": "Test User"
                },
                "challenge": "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg",
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7}
                ],
                "timeout": 60000,
                "excludeCredentials": [],
                "authenticatorSelection": {
                    "residentKey": "discouraged",
                    "userVerification": "preferred"
                },
                "attestation": "none"
            }
        "#;

        let request_origin: RequestOrigin =
            "https://example.com".try_into().expect("Invalid origin");

        let settings = RequestSettings {
            origin: OriginValidation::Trust,
        };

        let make_credentials_request =
            MakeCredentialRequest::prepare(&request_origin, request_json, &settings)
                .await
                .expect("Failed to parse request JSON");

        CredentialRequest::CreatePublicKeyCredentialRequest(make_credentials_request)
    }

    #[test]
    fn devices_for_transports_follow_available_transports() {
        let ids_and_transports =
            |available: &[libwebauthn::Transport]| -> Vec<(String, Transport)> {
                devices_for_transports(available)
                    .into_iter()
                    .map(|d| (d.id, d.transport))
                    .collect()
            };

        assert_eq!(
            ids_and_transports(&[libwebauthn::Transport::Usb]),
            vec![(String::from("0"), Transport::Usb)]
        );
        assert_eq!(
            ids_and_transports(&[
                libwebauthn::Transport::Usb,
                libwebauthn::Transport::Ble,
                libwebauthn::Transport::Hybrid,
                libwebauthn::Transport::Nfc,
            ]),
            vec![
                (String::from("0"), Transport::Usb),
                (String::from("1"), Transport::HybridQr),
                (String::from("2"), Transport::Nfc),
            ]
        );
        // IDs stay the same when a transport in between is unavailable.
        assert_eq!(
            ids_and_transports(&[libwebauthn::Transport::Nfc, libwebauthn::Transport::Usb]),
            vec![
                (String::from("0"), Transport::Usb),
                (String::from("2"), Transport::Nfc),
            ]
        );
    }

    #[test]
    fn devices_for_transports_does_not_offer_ble_alone() {
        assert!(devices_for_transports(&[libwebauthn::Transport::Ble]).is_empty());
        assert!(devices_for_transports(&[]).is_empty());
    }

    #[test]
    fn bluetooth_transports_are_dropped_when_powered_off() {
        use libwebauthn::Transport::{Ble, Hybrid, Nfc, Usb};
        assert_eq!(
            with_bluetooth_power(vec![Usb, Ble, Hybrid, Nfc], false),
            [Usb, Nfc]
        );
        assert_eq!(
            with_bluetooth_power(vec![Usb, Ble, Hybrid], true),
            [Usb, Ble, Hybrid]
        );
    }

    const POLL: Duration = Duration::from_millis(5);

    /// A probe that reports no Bluetooth for the first `misses` calls.
    fn bluetooth_after(
        misses: usize,
    ) -> impl FnMut() -> std::future::Ready<Vec<libwebauthn::Transport>> + Send + 'static {
        let mut calls = 0;
        move || {
            calls += 1;
            let mut transports = vec![libwebauthn::Transport::Usb];
            if calls > misses {
                transports.extend([libwebauthn::Transport::Ble, libwebauthn::Transport::Hybrid]);
            }
            std::future::ready(transports)
        }
    }

    fn fake_hybrid() -> Option<futures_lite::stream::Boxed<DeviceStateUpdate>> {
        Some(futures_lite::stream::once(DeviceStateUpdate::Hybrid(HybridState::Connecting)).boxed())
    }

    #[tokio::test]
    async fn hybrid_starts_when_bluetooth_becomes_available() {
        let updates: Vec<_> = hybrid_when_available(
            bluetooth_after(2),
            POLL,
            CancellationToken::new(),
            fake_hybrid,
        )
        .collect()
        .await;

        assert_eq!(updates.len(), 2);
        let DeviceStateUpdate::DevicesChanged(devices) = &updates[0] else {
            panic!("expected the new device list first");
        };
        let transports: Vec<_> = devices.iter().map(|d| d.transport.clone()).collect();
        assert_eq!(transports, [Transport::Usb, Transport::HybridQr]);
        assert!(matches!(
            updates[1],
            DeviceStateUpdate::Hybrid(HybridState::Connecting)
        ));
    }

    #[tokio::test]
    async fn bluetooth_watch_ends_when_request_ends() {
        let cancellation = CancellationToken::new();
        let mut updates = hybrid_when_available(
            bluetooth_after(usize::MAX),
            POLL,
            cancellation.clone(),
            || -> Option<futures_lite::stream::Boxed<DeviceStateUpdate>> {
                panic!("hybrid must not start")
            },
        )
        .boxed();
        tokio::time::sleep(POLL * 3).await;
        cancellation.cancel();
        let next = tokio::time::timeout(Duration::from_secs(1), updates.next()).await;
        assert!(matches!(next, Ok(None)), "stream should end once cancelled");
    }

    #[tokio::test]
    async fn bluetooth_watch_ends_if_request_context_is_gone() {
        let updates: Vec<_> = hybrid_when_available(
            bluetooth_after(0),
            POLL,
            CancellationToken::new(),
            || -> Option<futures_lite::stream::Boxed<DeviceStateUpdate>> { None },
        )
        .collect()
        .await;
        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn late_hybrid_start_only_applies_to_its_own_request() {
        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, MockUsbHandler);
        let (tx, _rx) = oneshot::channel();
        let (request_id, _) = service
            .init_request(&create_test_request().await, tx)
            .await
            .unwrap();

        assert!(start_hybrid(&service.hybrid_handler, &service.ctx, request_id + 1).is_none());
        assert!(start_hybrid(&service.hybrid_handler, &service.ctx, request_id).is_some());

        service.cancel_request(request_id).await;
        assert!(start_hybrid(&service.hybrid_handler, &service.ctx, request_id).is_none());
    }

    #[tokio::test]
    async fn test_init_request_returns_token_and_id() {
        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, MockUsbHandler);
        let (tx, _rx) = oneshot::channel();
        let request = create_test_request().await;

        let result = service.init_request(&request, tx).await;

        assert!(result.is_ok());
        let (request_id, cancellation_token) = result.unwrap();
        assert!(request_id > 0);
        assert!(!cancellation_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_cancel_request_triggers_cancellation() {
        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, MockUsbHandler);
        let (tx, _rx) = oneshot::channel();
        let request = create_test_request().await;

        let (request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();
        assert!(!cancellation_token.is_cancelled());

        service.cancel_request(request_id).await;
        assert!(cancellation_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_cancellable_sleep_completes_normally() {
        let token = CancellationToken::new();
        let start = tokio::time::Instant::now();

        let result = cancellable_sleep(Duration::from_millis(50), &token).await;

        assert!(result.is_ok());
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_cancellable_sleep_respects_cancellation() {
        let token = CancellationToken::new();
        token.cancel(); // Pre-cancel the token

        let start = tokio::time::Instant::now();
        let result = cancellable_sleep(Duration::from_secs(5), &token).await;

        // Must return NonTerminatingCancellation, not a generic Internal error
        assert!(
            matches!(
                result,
                Err(CredentialServiceError::NonTerminatingCancellation)
            ),
            "cancellable_sleep must return NonTerminatingCancellation when the token is cancelled"
        );
        // Should return immediately, not after 5 seconds
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_init_request_rejects_concurrent() {
        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, MockUsbHandler);
        let (tx1, _rx1) = oneshot::channel();
        let (tx2, _rx2) = oneshot::channel();
        let request = create_test_request().await;

        // First request should succeed
        let result1 = service.init_request(&request, tx1).await;
        assert!(result1.is_ok());

        // Second concurrent request should fail
        let result2 = service.init_request(&request, tx2).await;
        assert!(result2.is_err());
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Already a request in progress")
        );
    }

    // Generic push-based handler that tracks cancellation.
    // Before moving a handler into the service, call `get_handler_ref()` to obtain
    // a `HandlerRef<T>` — a handle that exposes `shift_state()` and `was_cancelled()`
    // for use in the test body.
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

    /// Clone-able test handle for a `CancellationTrackingHandler<T>`.
    /// Obtained via `handler.get_handler_ref()` before the handler is moved into the
    /// service.
    #[derive(Clone)]
    struct HandlerRef<T> {
        tx: UnboundedSender<T>,
        cancelled: Arc<AtomicBool>,
    }

    impl<T> HandlerRef<T> {
        /// Push the next state to be emitted by the handler's stream.
        /// Panics if the stream receiver has been dropped.
        fn shift_state(&self, state: T) {
            self.tx.send(state).unwrap();
        }

        fn was_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
    }

    struct CancellationTrackingHandler<T> {
        tx: UnboundedSender<T>,
        rx: std::sync::Mutex<Option<UnboundedReceiver<T>>>,
        cancelled: Arc<AtomicBool>,
    }

    impl<T> std::fmt::Debug for CancellationTrackingHandler<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CancellationTrackingHandler")
                .field("cancelled", &self.cancelled.load(Ordering::SeqCst))
                .finish_non_exhaustive()
        }
    }

    impl<T> CancellationTrackingHandler<T> {
        fn new() -> Self {
            let (tx, rx) = unbounded_channel();
            Self {
                tx,
                rx: std::sync::Mutex::new(Some(rx)),
                cancelled: Arc::new(AtomicBool::new(false)),
            }
        }

        /// Return a `HandlerRef` that can be kept by the test after this handler is
        /// moved into the service.
        fn get_handler_ref(&self) -> HandlerRef<T> {
            HandlerRef {
                tx: self.tx.clone(),
                cancelled: self.cancelled.clone(),
            }
        }
    }

    /// Shared stream body for all three transport trait impls.
    ///
    /// Uses a `biased` `select!` with the cancellation branch first so that
    /// cancellation always wins over a simultaneously-ready channel item. This
    /// guarantees that no queued state is emitted once the token is cancelled,
    /// making the "no emission after cancel" assertions in tests deterministic.
    fn run_tracking_stream<T, E>(
        rx: Option<UnboundedReceiver<T>>,
        cancellation: CancellationToken,
        cancelled: Arc<AtomicBool>,
        wrap: impl Fn(T) -> E + Send + 'static,
    ) -> impl Stream<Item = E> + Send + Unpin + 'static
    where
        T: Send + 'static,
        E: Send + 'static,
    {
        Box::pin(async_stream::stream! {
            let Some(mut rx) = rx else { return; };
            // This allows to simulate when the handler detected cancellation,
            // but still emit a single event after cancellation to simulate a
            // race.
            let mut cancel_detected = false;
            loop {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled(), if !cancel_detected => {
                        cancel_detected = true;
                        cancelled.store(true, Ordering::SeqCst);
                    }
                    maybe = rx.recv() => match maybe {
                        Some(state) => {
                            yield wrap(state)
                            if cancel_detected {
                                break;
                            }
                        },
                        None => break, // all senders dropped
                    }
                }
            }
        })
    }

    impl UsbHandler for CancellationTrackingHandler<UsbStateInternal> {
        fn start(
            &self,
            _request: &CredentialRequest,
            cancellation: CancellationToken,
        ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static {
            let rx = self.rx.lock().unwrap().take();
            run_tracking_stream(rx, cancellation, self.cancelled.clone(), |state| UsbEvent {
                state,
            })
        }
    }

    impl HybridHandler for CancellationTrackingHandler<HybridStateInternal> {
        fn start(
            &self,
            _request: &CredentialRequest,
            cancellation: CancellationToken,
        ) -> impl Stream<Item = HybridEvent> + Unpin + Send + Sized + 'static {
            let rx = self.rx.lock().unwrap().take();
            run_tracking_stream(rx, cancellation, self.cancelled.clone(), |state| {
                HybridEvent { state }
            })
        }
    }

    impl NfcHandler for CancellationTrackingHandler<NfcStateInternal> {
        fn start(
            &self,
            _request: &CredentialRequest,
            cancellation: CancellationToken,
        ) -> impl Stream<Item = NfcEvent> + Send + Sized + Unpin + 'static {
            let rx = self.rx.lock().unwrap().take();
            run_tracking_stream(rx, cancellation, self.cancelled.clone(), |state| NfcEvent {
                state,
            })
        }
    }

    #[tokio::test]
    async fn test_cancel_request_by_id() {
        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, MockUsbHandler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        // Token should not be cancelled initially
        assert!(!cancellation_token.is_cancelled());

        // Cancel by ID
        service.cancel_request(request_id).await;

        // Token should now be cancelled
        assert!(cancellation_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_multiple_handlers_all_cancelled() {
        let usb_handler = CancellationTrackingHandler::<UsbStateInternal>::new();
        let hybrid_handler = CancellationTrackingHandler::<HybridStateInternal>::new();
        let usb_ref = usb_handler.get_handler_ref();
        let hybrid_ref = hybrid_handler.get_handler_ref();

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Push and consume one state from each to confirm streams are live
        usb_ref.shift_state(UsbStateInternal::Waiting);
        hybrid_ref.shift_state(HybridStateInternal::Init("qr".to_string()));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        // Queue additional states that should never be emitted after cancellation.
        // These sit in the channel when cancel_request() fires.
        usb_ref.shift_state(UsbStateInternal::Waiting);
        usb_ref.shift_state(UsbStateInternal::Waiting);
        hybrid_ref.shift_state(HybridStateInternal::Connecting);

        // Cancel the request — token is now cancelled synchronously
        service.cancel_request(request_id).await;
        assert!(cancellation_token.is_cancelled());

        // biased select! polls cancellation first each iteration, discarding
        // the queued states before they can be emitted.
        let usb_remaining: Vec<_> = usb_stream.collect().await;
        let hybrid_remaining: Vec<_> = hybrid_stream.collect().await;

        assert!(
            usb_remaining.is_empty(),
            "USB should not emit any more states after cancellation"
        );
        assert!(
            hybrid_remaining.is_empty(),
            "Hybrid should not emit any more states after cancellation"
        );
    }

    #[tokio::test]
    async fn test_cancellation_cleans_up_request_context() {
        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, MockUsbHandler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (request_id, _token) = service.init_request(&request, tx).await.unwrap();

        // Cancel the request
        service.cancel_request(request_id).await;

        // Should be able to start a new request now (context cleaned up)
        let (tx2, _rx2) = oneshot::channel();
        let result = service.init_request(&request, tx2).await;
        assert!(
            result.is_ok(),
            "Should be able to init new request after cancel"
        );
    }

    #[tokio::test]
    async fn test_cancel_with_unknown_id_is_noop() {
        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, MockUsbHandler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        // Cancel with a different ID (should be a no-op)
        let wrong_id = request_id.wrapping_add(1);
        service.cancel_request(wrong_id).await;

        // Original request should still be active
        assert!(
            !cancellation_token.is_cancelled(),
            "Token should not be cancelled with wrong ID"
        );

        // Now cancel with correct ID
        service.cancel_request(request_id).await;
        assert!(
            cancellation_token.is_cancelled(),
            "Token should be cancelled with correct ID"
        );
    }

    #[tokio::test]
    async fn test_cancel_with_no_active_request_is_noop() {
        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, MockUsbHandler);

        // Cancel when no request is active (should not crash or panic)
        service.cancel_request(12345).await;

        // Should still be able to start a new request
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();
        let result = service.init_request(&request, tx).await;
        assert!(
            result.is_ok(),
            "Should be able to init request after no-op cancel"
        );
    }

    #[tokio::test]
    async fn test_request_id_matches_on_init() {
        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, MockUsbHandler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (request_id_1, _token_1) = service.init_request(&request, tx).await.unwrap();

        // Cancel to free up the service
        service.cancel_request(request_id_1).await;

        // Start a new request
        let (tx2, _rx2) = oneshot::channel();
        let (request_id_2, _token_2) = service.init_request(&request, tx2).await.unwrap();

        // IDs should be different (random)
        assert_ne!(
            request_id_1, request_id_2,
            "Sequential requests should (almost certainly) have different IDs"
        );
    }

    #[tokio::test]
    async fn test_explicit_cancel_stops_all_transports() {
        let usb_handler = CancellationTrackingHandler::<UsbStateInternal>::new();
        let hybrid_handler = CancellationTrackingHandler::<HybridStateInternal>::new();
        let usb_ref = usb_handler.get_handler_ref();
        let hybrid_ref = hybrid_handler.get_handler_ref();

        assert!(!usb_ref.was_cancelled());
        assert!(!hybrid_ref.was_cancelled());

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Push and consume one state each to confirm streams are live
        usb_ref.shift_state(UsbStateInternal::Waiting);
        hybrid_ref.shift_state(HybridStateInternal::Init("qr".to_string()));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        // Queue additional states that should never be emitted after cancellation.
        // These sit in the channel when cancel_request() fires.
        usb_ref.shift_state(UsbStateInternal::Waiting);
        usb_ref.shift_state(UsbStateInternal::Waiting);
        hybrid_ref.shift_state(HybridStateInternal::Connecting);

        // Explicitly cancel — token becomes cancelled synchronously
        service.cancel_request(request_id).await;
        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered after cancel_request"
        );
        // Add explicit post-cancellation message.
        usb_ref.shift_state(UsbStateInternal::Failed(CredentialServiceError::Internal(
            "Cancelled".to_string(),
        )));

        // biased select! polls cancellation first, discarding the queued states
        let usb_remaining: Vec<_> = usb_stream.collect().await;
        let hybrid_remaining: Vec<_> = hybrid_stream.collect().await;

        assert!(
            usb_remaining.is_empty(),
            "USB should not emit any more states after cancellation"
        );
        assert!(
            hybrid_remaining.is_empty(),
            "Hybrid should not emit any more states after cancellation"
        );

        // Flags are set by run_tracking_stream when it observes the cancelled token
        assert!(
            usb_ref.was_cancelled(),
            "USB handler should have detected cancellation"
        );
        assert!(
            hybrid_ref.was_cancelled(),
            "Hybrid handler should have detected cancellation"
        );
    }

    #[tokio::test]
    async fn test_terminating_failure_ends_ceremony() {
        let usb_handler = CancellationTrackingHandler::<UsbStateInternal>::new();
        let usb_ref = usb_handler.get_handler_ref();

        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, rx) = oneshot::channel();

        let (_id, token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        assert!(!token.is_cancelled());

        // CredentialExcluded is ceremony-terminating per the WebAuthn spec
        usb_ref.shift_state(UsbStateInternal::Failed(
            CredentialServiceError::CredentialExcluded,
        ));
        assert!(matches!(
            usb_stream.next().await,
            Some(UsbState::Failed(CredentialServiceError::CredentialExcluded))
        ));

        // complete_request was called: token cancelled, response delivered to caller
        assert!(
            token.is_cancelled(),
            "ceremony must end on terminating error"
        );
        assert!(
            matches!(
                rx.await,
                Ok(Err(CredentialServiceError::CredentialExcluded))
            ),
            "caller must receive the terminating error"
        );
    }

    #[tokio::test]
    async fn test_non_terminating_failure_keeps_ceremony_alive() {
        let usb_handler = CancellationTrackingHandler::<UsbStateInternal>::new();
        let hybrid_handler = CancellationTrackingHandler::<HybridStateInternal>::new();
        let usb_ref = usb_handler.get_handler_ref();
        let hybrid_ref = hybrid_handler.get_handler_ref();

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();
        let (id, token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // USB fails with a non-terminating error — forwarded to UI but ceremony lives
        usb_ref.shift_state(UsbStateInternal::Failed(
            CredentialServiceError::AuthenticatorError,
        ));
        assert!(matches!(
            usb_stream.next().await,
            Some(UsbState::Failed(CredentialServiceError::AuthenticatorError))
        ));

        // Token must still be live — is_ceremony_terminating(AuthenticatorError) == false
        assert!(
            !token.is_cancelled(),
            "ceremony must stay alive on non-terminating error"
        );

        // Other transports must still be operational
        hybrid_ref.shift_state(HybridStateInternal::Connecting);
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Connecting)
        ));

        service.cancel_request(id).await;
    }

    #[tokio::test]
    async fn test_failed_request_cancels_other_transports() {
        let usb_handler = CancellationTrackingHandler::<UsbStateInternal>::new();
        let hybrid_handler = CancellationTrackingHandler::<HybridStateInternal>::new();
        let usb_ref = usb_handler.get_handler_ref();
        let hybrid_ref = hybrid_handler.get_handler_ref();

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Confirm hybrid stream is live
        hybrid_ref.shift_state(HybridStateInternal::Init("qr".to_string()));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        // Queue an extra hybrid state that should be discarded once USB fails.
        // It sits in the channel when complete_request() cancels the token.
        hybrid_ref.shift_state(HybridStateInternal::Connecting);

        // USB fails with a ceremony-terminating error → complete_request → token cancelled
        usb_ref.shift_state(UsbStateInternal::Waiting);
        usb_ref.shift_state(UsbStateInternal::Failed(
            CredentialServiceError::CredentialExcluded,
        ));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));
        assert!(matches!(
            usb_stream.next().await,
            Some(UsbState::Failed(CredentialServiceError::CredentialExcluded))
        ));

        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered when USB fails"
        );

        // biased select! polls cancellation first, discarding the queued Connecting state
        let hybrid_remaining: Vec<_> = hybrid_stream.collect().await;
        assert!(
            hybrid_remaining.is_empty(),
            "Hybrid should not emit any more states after USB fails"
        );
        assert!(
            hybrid_ref.was_cancelled(),
            "Hybrid handler should have detected cancellation when USB failed"
        );
    }

    #[tokio::test]
    async fn test_completed_request_triggers_cancellation() {
        let credential_response = create_test_credential_response();

        let usb_handler = CancellationTrackingHandler::<UsbStateInternal>::new();
        let usb_ref = usb_handler.get_handler_ref();

        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        assert!(!cancellation_token.is_cancelled());

        usb_ref.shift_state(UsbStateInternal::Waiting);
        usb_ref.shift_state(UsbStateInternal::Completed(credential_response));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Completed)));

        // UsbStateStream calls complete_request on Completed, which cancels the token
        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered when request completes successfully"
        );
    }

    #[tokio::test]
    async fn test_completed_request_cancels_other_transports() {
        let credential_response = create_test_credential_response();

        let usb_handler = CancellationTrackingHandler::<UsbStateInternal>::new();
        let hybrid_handler = CancellationTrackingHandler::<HybridStateInternal>::new();
        let usb_ref = usb_handler.get_handler_ref();
        let hybrid_ref = hybrid_handler.get_handler_ref();

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Confirm hybrid stream is live
        hybrid_ref.shift_state(HybridStateInternal::Init("qr".to_string()));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        // Queue an extra hybrid state that should be discarded once USB completes.
        // It sits in the channel when complete_request() cancels the token.
        hybrid_ref.shift_state(HybridStateInternal::Connecting);

        // USB completes — UsbStateStream calls complete_request → token cancelled
        usb_ref.shift_state(UsbStateInternal::Waiting);
        usb_ref.shift_state(UsbStateInternal::Completed(credential_response));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Completed)));

        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered when USB completes"
        );

        // biased select! polls cancellation first, discarding the queued Connecting state
        let hybrid_remaining: Vec<_> = hybrid_stream.collect().await;
        assert!(
            hybrid_remaining.is_empty(),
            "Hybrid should not emit any more states after USB completes"
        );
        assert!(
            hybrid_ref.was_cancelled(),
            "Hybrid handler should have detected cancellation when USB completed"
        );
    }

    /// When USB is cancelled (by another transport winning), the stream must emit
    /// no Failed/ErrorInternal state — it should simply end cleanly.
    #[tokio::test]
    async fn test_cancelled_usb_emits_no_failed_state() {
        let usb_handler = CancellationTrackingHandler::<UsbStateInternal>::new();
        let usb_ref = usb_handler.get_handler_ref();

        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();
        let (request_id, token) = service.init_request(&request, tx).await.unwrap();
        let mut usb_stream = service.get_usb_credential().await;

        // Confirm stream is live
        usb_ref.shift_state(UsbStateInternal::Waiting);
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));

        // Queue a NonTerminatingCancellation — simulates what process() emits when
        // the cancellation token fires internally before the outer branch catches it.
        usb_ref.shift_state(UsbStateInternal::Failed(
            CredentialServiceError::NonTerminatingCancellation,
        ));

        // Cancel the request synchronously so the token is already cancelled
        // when the stream is next polled.
        service.cancel_request(request_id).await;
        assert!(token.is_cancelled());

        // The stream must not yield the Failed(NonTerminatingCancellation) state.
        // biased select! polls cancellation first; the queued state is discarded.
        let remaining: Vec<_> = usb_stream.collect().await;
        assert!(
            remaining.is_empty(),
            "cancelled USB stream must emit no further states, including Failed(NonTerminatingCancellation)"
        );
    }

    /// When hybrid is cancelled, it must not emit a Failed state on the stream.
    /// complete_request must be invoked exactly once (by the winning transport or
    /// cancel_request), not a second time from hybrid's terminal-state path.
    #[tokio::test]
    async fn test_cancelled_hybrid_emits_no_failed_state() {
        let hybrid_handler = CancellationTrackingHandler::<HybridStateInternal>::new();
        let hybrid_ref = hybrid_handler.get_handler_ref();

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, MockUsbHandler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();
        let (request_id, token) = service.init_request(&request, tx).await.unwrap();
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Confirm stream is live
        hybrid_ref.shift_state(HybridStateInternal::Init("qr".to_string()));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        // Queue a NonTerminatingCancellation — what the real handler would emit when
        // run_until_cancelled returns None
        hybrid_ref.shift_state(HybridStateInternal::Failed(
            CredentialServiceError::NonTerminatingCancellation,
        ));

        service.cancel_request(request_id).await;
        assert!(token.is_cancelled());

        // Stream must stop without emitting the Failed(NonTerminatingCancellation) state.
        let remaining: Vec<_> = hybrid_stream.collect().await;
        assert!(
            remaining.is_empty(),
            "cancelled hybrid stream must emit no further states"
        );
    }

    // The following tests are stupid, but try to prevent regressions regarding changes around
    // `is_ceremony_terminating()`
    #[test]
    fn test_classifier_ceremony_terminating_errors() {
        // These return true — this arm must call complete_request and end the ceremony.
        assert!(is_ceremony_terminating(
            &CredentialServiceError::CredentialExcluded
        ));
    }

    #[test]
    fn test_classifier_per_authenticator_errors() {
        // Per-authenticator: ceremony stays alive; the same or another transport can retry.
        let errors = [
            CredentialServiceError::AuthenticatorError,
            CredentialServiceError::NoCredentials,
            CredentialServiceError::PinAttemptsExhausted,
            CredentialServiceError::Internal("x".into()),
        ];
        for err in errors {
            assert!(!is_ceremony_terminating(&err));
        }
    }

    #[test]
    fn test_classifier_non_terminating_cancellation() {
        // NonTerminatingCancellation: the response channel has already been consumed
        // by the winning transport's complete_request or by cancel_request directly.
        // This arm must NOT invoke complete_request again — hence false.
        assert!(!is_ceremony_terminating(
            &CredentialServiceError::NonTerminatingCancellation
        ));
    }

    /// After a non-terminating USB failure, the mock stream remains live and
    /// continues to emit subsequent states.
    #[tokio::test]
    async fn test_usb_non_terminating_error_transport_continues() {
        let usb_handler = CancellationTrackingHandler::<UsbStateInternal>::new();
        let usb_ref = usb_handler.get_handler_ref();

        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();
        let (id, token) = service.init_request(&request, tx).await.unwrap();
        let mut usb_stream = service.get_usb_credential().await;

        // Non-terminating error: forwarded to UI, ceremony stays alive
        usb_ref.shift_state(UsbStateInternal::Failed(
            CredentialServiceError::AuthenticatorError,
        ));
        assert!(matches!(
            usb_stream.next().await,
            Some(UsbState::Failed(CredentialServiceError::AuthenticatorError))
        ));
        assert!(
            !token.is_cancelled(),
            "ceremony must stay alive on non-terminating error"
        );

        // Transport is still live — subsequent states arrive
        usb_ref.shift_state(UsbStateInternal::Waiting);
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));

        service.cancel_request(id).await;
    }

    /// After a non-terminating hybrid failure, a new QR Init is emitted — simulating
    /// the retry loop in run_hybrid_ceremony / start() re-issuing a fresh QR code.
    #[tokio::test]
    async fn test_hybrid_qr_reissued_after_non_terminating_error() {
        let hybrid_handler = CancellationTrackingHandler::<HybridStateInternal>::new();
        let hybrid_ref = hybrid_handler.get_handler_ref();

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, MockUsbHandler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();
        let (id, token) = service.init_request(&request, tx).await.unwrap();
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // First QR issued
        hybrid_ref.shift_state(HybridStateInternal::Init("qr-code-1".to_string()));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        // Tunnel fails with a non-terminating error — forwarded to UI
        hybrid_ref.shift_state(HybridStateInternal::Failed(
            CredentialServiceError::AuthenticatorError,
        ));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Failed(
                CredentialServiceError::AuthenticatorError
            ))
        ));
        assert!(!token.is_cancelled(), "ceremony must stay alive");

        // Real retry loop re-issues a new QR; simulated here via shift_state
        hybrid_ref.shift_state(HybridStateInternal::Init("qr-code-2".to_string()));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        service.cancel_request(id).await;
    }

    /// A Restarting state from the hybrid handler is forwarded to the UI stream
    /// and does not call complete_request or cancel the ceremony token.
    #[tokio::test]
    async fn test_hybrid_restarting_forwarded_ceremony_alive() {
        let hybrid_handler = CancellationTrackingHandler::<HybridStateInternal>::new();
        let hybrid_ref = hybrid_handler.get_handler_ref();

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, MockUsbHandler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();
        let (id, token) = service.init_request(&request, tx).await.unwrap();
        let mut hybrid_stream = service.get_hybrid_credential().await;

        hybrid_ref.shift_state(HybridStateInternal::Restarting);
        assert!(
            matches!(hybrid_stream.next().await, Some(HybridState::Restarting)),
            "Restarting state must be forwarded to the UI stream"
        );
        assert!(
            !token.is_cancelled(),
            "ceremony must stay alive on Restarting"
        );

        service.cancel_request(id).await;
    }

    /// A Restarting state from the USB handler is forwarded to the UI stream
    /// and does not call complete_request or cancel the ceremony token.
    #[tokio::test]
    async fn test_usb_restarting_forwarded_ceremony_alive() {
        let usb_handler = CancellationTrackingHandler::<UsbStateInternal>::new();
        let usb_ref = usb_handler.get_handler_ref();

        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();
        let (id, token) = service.init_request(&request, tx).await.unwrap();
        let mut usb_stream = service.get_usb_credential().await;

        usb_ref.shift_state(UsbStateInternal::Restarting);
        assert!(
            matches!(usb_stream.next().await, Some(UsbState::Restarting)),
            "Restarting state must be forwarded to the UI stream"
        );
        assert!(
            !token.is_cancelled(),
            "ceremony must stay alive on Restarting"
        );

        service.cancel_request(id).await;
    }
}
