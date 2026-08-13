pub mod hybrid;
pub mod nfc;
pub mod usb;

use std::{
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::Poll,
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

use credentialsd_common::model::{
    BackgroundEvent, Device, Error as CredentialServiceError, Transport,
};

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
            Err(CredentialServiceError::Internal("Request cancelled".to_string()))
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

    hybrid_handler: Mutex<H>,
    _nfc_handler: Mutex<N>,
    usb_handler: Mutex<U>,
}

impl<H: HybridHandler + Debug, N: NfcHandler + Debug, U: UsbHandler + Debug>
    CredentialService<H, N, U>
{
    pub fn new(hybrid_handler: H, nfc_handler: N, usb_handler: U) -> Self {
        Self {
            ctx: Arc::new(Mutex::new(None)),

            hybrid_handler: Mutex::new(hybrid_handler),
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
        let guard = self.ctx.lock().unwrap();
        if let Some(RequestContext {
            ref request,
            ref cancellation,
            ..
        }) = *guard
        {
            let stream = self
                .hybrid_handler
                .lock()
                .unwrap()
                .start(request, cancellation.clone());
            let ctx = self.ctx.clone();
            Box::pin(HybridStateStream { inner: stream, ctx })
        } else {
            tracing::error!(
                "Attempted to start hybrid credential flow, but no request context was found."
            );
            todo!("Handle error when context is not set up.")
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
            Box::pin(UsbStateStream { inner: stream, ctx })
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
            Box::pin(NfcStateStream { inner: stream, ctx })
        } else {
            tracing::error!(
                "Attempted to start nfc credential flow, but no request context was found."
            );
            todo!("Handle error when context is not set up.")
        }
    }
}

#[async_trait]
impl<H: HybridHandler + Send, N: NfcHandler + Send, U: UsbHandler + Send> ManageDevice
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
        let mut devices = vec![Device {
            id: String::from("0"),
            transport: Transport::Usb,
        }];
        if libwebauthn::transport::cable::is_available().await {
            devices.push(Device {
                id: String::from("1"),
                transport: Transport::HybridQr,
            });
        }
        if libwebauthn::transport::nfc::is_nfc_available() {
            devices.push(Device {
                id: String::from("2"),
                transport: Transport::Nfc,
            });
        }
        Ok(devices)
    }

    async fn start_discovery(
        &self,
    ) -> Pin<Box<dyn Stream<Item = DeviceStateUpdate> + Send + 'static>> {
        let available_transports = available_transports().await;
        let mut selected_transports = Vec::new();
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
        }
        futures::stream::select_all(selected_transports).boxed()
    }
}

pub struct HybridStateStream<H> {
    inner: H,
    ctx: Arc<Mutex<Option<RequestContext>>>,
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
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(HybridEvent { state })) => {
                match &state {
                    HybridStateInternal::Completed(hybrid_response) => {
                        let response = match &**hybrid_response {
                            AuthenticatorResponse::CredentialCreated(make_credential_response) => {
                                CredentialResponse::from_make_credential(
                                    make_credential_response,
                                    &["hybrid"],
                                    "cross-platform",
                                )
                            }
                            AuthenticatorResponse::CredentialsAsserted(get_assertion_response) => {
                                CredentialResponse::from_get_assertion(
                                    // When doing hybrid, the authenticator is capable of displaying it's own UI.
                                    // So we assume here, it only ever returns one assertion.
                                    // In case this doesn't hold true, we have to implement credential selection here,
                                    // as is done for USB.
                                    &get_assertion_response.assertions[0],
                                    "cross-platform",
                                )
                            }
                        };
                        complete_request(ctx, Ok(response.clone()));
                    }
                    HybridStateInternal::Failed => {
                        complete_request(ctx, Err(CredentialServiceError::AuthenticatorError));
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
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(UsbEvent { state })) => {
                match &state {
                    UsbStateInternal::Completed(response) => {
                        complete_request(ctx, Ok(response.clone()));
                    }
                    UsbStateInternal::Failed(error) => {
                        complete_request(ctx, Err(error.clone()));
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
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(NfcEvent { state })) => {
                match &state {
                    NfcStateInternal::Completed(response) => {
                        complete_request(ctx, Ok(response.clone()));
                    }
                    NfcStateInternal::Failed(error) => {
                        complete_request(ctx, Err(error.clone()));
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
}

impl From<DeviceStateUpdate> for BackgroundEvent {
    fn from(value: DeviceStateUpdate) -> Self {
        match value {
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

        assert!(result.is_err());
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

    // Mock handlers that track cancellation and emit configurable states
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, Clone)]
    struct CancellationTrackingUsbHandler {
        cancelled: Arc<AtomicBool>,
        emit_states: Arc<Vec<UsbStateInternal>>,
        delay_ms: u64,
    }

    impl CancellationTrackingUsbHandler {
        fn new(emit_states: Vec<UsbStateInternal>, delay_ms: u64) -> Self {
            Self {
                cancelled: Arc::new(AtomicBool::new(false)),
                emit_states: Arc::new(emit_states),
                delay_ms,
            }
        }

        fn was_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
    }

    impl UsbHandler for CancellationTrackingUsbHandler {
        fn start(
            &self,
            _request: &CredentialRequest,
            cancellation: CancellationToken,
        ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static {
            let cancelled = self.cancelled.clone();
            let states = self.emit_states.clone();
            let delay_ms = self.delay_ms;
            Box::pin(async_stream::stream! {
                for state in states.iter() {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {
                            yield UsbEvent { state: state.clone() };
                        }
                        _ = cancellation.cancelled() => {
                            cancelled.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            })
        }
    }

    #[derive(Debug, Clone)]
    struct CancellationTrackingHybridHandler {
        cancelled: Arc<AtomicBool>,
        emit_states: Arc<Vec<HybridStateInternal>>,
        delay_ms: u64,
    }

    impl CancellationTrackingHybridHandler {
        fn new(emit_states: Vec<HybridStateInternal>, delay_ms: u64) -> Self {
            Self {
                cancelled: Arc::new(AtomicBool::new(false)),
                emit_states: Arc::new(emit_states),
                delay_ms,
            }
        }

        fn was_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
    }

    impl HybridHandler for CancellationTrackingHybridHandler {
        fn start(
            &self,
            _request: &CredentialRequest,
            cancellation: CancellationToken,
        ) -> impl Stream<Item = HybridEvent> + Unpin + Send + Sized + 'static {
            let cancelled = self.cancelled.clone();
            let states = self.emit_states.clone();
            let delay_ms = self.delay_ms;
            Box::pin(async_stream::stream! {
                for state in states.iter() {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {
                            yield HybridEvent { state: state.clone() };
                        }
                        _ = cancellation.cancelled() => {
                            cancelled.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            })
        }
    }

    #[tokio::test]
    async fn test_handler_respects_cancellation_during_polling() {
        // Create a handler that would emit many states if not cancelled
        let usb_handler = CancellationTrackingUsbHandler::new(
            vec![
                UsbStateInternal::Waiting,
                UsbStateInternal::Waiting,
                UsbStateInternal::Waiting,
            ],
            100, // 100ms between each state
        );

        let request = create_test_request().await;
        let cancellation = CancellationToken::new();

        let mut stream = usb_handler.start(&request, cancellation.clone());

        // Collect first state
        let first = stream.next().await;
        assert!(first.is_some());

        // Cancel immediately
        cancellation.cancel();

        // Stream should stop immediately - no more states should be emitted
        let remaining: Vec<_> = stream.collect().await;
        assert!(
            remaining.is_empty(),
            "Handler should not emit any more states after cancellation"
        );

        // Handler should have detected cancellation during collect
        assert!(usb_handler.was_cancelled());
    }

    #[tokio::test]
    async fn test_handler_stops_on_external_cancellation() {
        // Test that handlers respect cancellation from external source
        let hybrid_handler = CancellationTrackingHybridHandler::new(
            vec![
                HybridStateInternal::Init("qr_code".to_string()),
                HybridStateInternal::Connecting,
                HybridStateInternal::Connected,
                // Would continue forever if not cancelled
            ],
            100,
        );

        let request = create_test_request().await;
        let cancellation = CancellationToken::new();

        let mut stream = hybrid_handler.start(&request, cancellation.clone());

        // Collect first couple states
        let _first = stream.next().await;
        let _second = stream.next().await;

        // Simulate external cancellation (e.g., another transport completed)
        cancellation.cancel();

        // Stream should stop immediately - no more states should be emitted
        let remaining: Vec<_> = stream.collect().await;
        assert!(
            remaining.is_empty(),
            "Handler should not emit any more states after cancellation"
        );

        // Handler should have detected cancellation during collect
        assert!(hybrid_handler.was_cancelled());
    }

    #[tokio::test]
    async fn test_all_states_delivered_without_cancellation() {
        // Test that all states are emitted when not cancelled
        let hybrid_handler = CancellationTrackingHybridHandler::new(
            vec![
                HybridStateInternal::Init("qr_code".to_string()),
                HybridStateInternal::Connecting,
                HybridStateInternal::Connected,
            ],
            10,
        );

        let request = create_test_request().await;
        let cancellation = CancellationToken::new();

        let stream = hybrid_handler.start(&request, cancellation);
        let states: Vec<_> = stream.collect().await;

        // Should have all 3 states
        assert_eq!(states.len(), 3, "Should emit all states when not cancelled");
        assert!(matches!(states[0].state, HybridStateInternal::Init(_)));
        assert!(matches!(states[1].state, HybridStateInternal::Connecting));
        assert!(matches!(states[2].state, HybridStateInternal::Connected));
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
        // All three handlers emit states slowly
        let usb_handler =
            CancellationTrackingUsbHandler::new(vec![UsbStateInternal::Waiting; 5], 100);
        let hybrid_handler = CancellationTrackingHybridHandler::new(
            vec![
                HybridStateInternal::Init("qr".to_string()),
                HybridStateInternal::Connecting,
                HybridStateInternal::Connected,
            ],
            100,
        );
        let nfc_handler = MockNfcHandler;

        let service = CredentialService::new(hybrid_handler, nfc_handler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        // Start all handlers
        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Let them emit a couple states
        let _ = usb_stream.next().await;
        let _ = hybrid_stream.next().await;

        // Cancel the request
        service.cancel_request(request_id).await;

        // Small delay for propagation
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Token should be cancelled
        assert!(cancellation_token.is_cancelled());

        // Streams should stop immediately - no more states should be emitted
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
        // USB would keep polling
        let usb_handler = CancellationTrackingUsbHandler::new(
            vec![
                UsbStateInternal::Waiting,
                UsbStateInternal::Waiting,
                UsbStateInternal::Waiting,
            ],
            100,
        );

        // Hybrid would keep connecting
        let hybrid_handler = CancellationTrackingHybridHandler::new(
            vec![
                HybridStateInternal::Init("qr".to_string()),
                HybridStateInternal::Connecting,
                HybridStateInternal::Connected,
            ],
            100,
        );

        // Clone handlers to verify cancellation later
        let usb_handler_ref = usb_handler.clone();
        let hybrid_handler_ref = hybrid_handler.clone();
        assert!(
            !usb_handler_ref.was_cancelled(),
            "USB handler should not have detected cancellation"
        );
        assert!(
            !hybrid_handler_ref.was_cancelled(),
            "Hybrid handler should not have detected cancellation"
        );

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        // Start both streams
        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Let them emit a state each
        let _ = usb_stream.next().await;
        let _ = hybrid_stream.next().await;

        // Explicitly cancel the request
        service.cancel_request(request_id).await;

        // Cancellation token should be triggered
        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered after cancel_request"
        );

        // Both streams should stop emitting states
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

        // Verify both handlers detected cancellation
        assert!(
            usb_handler_ref.was_cancelled(),
            "USB handler should have detected cancellation"
        );
        assert!(
            hybrid_handler_ref.was_cancelled(),
            "Hybrid handler should have detected cancellation"
        );
    }

    #[tokio::test]
    async fn test_failed_request_triggers_cancellation() {
        use credentialsd_common::model::Error;

        // Handler that emits a Failed state
        let usb_handler = CancellationTrackingUsbHandler::new(
            vec![
                UsbStateInternal::Waiting,
                UsbStateInternal::Failed(Error::Internal("test failure".to_string())),
            ],
            10,
        );

        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        // Start the USB stream
        let mut usb_stream = service.get_usb_credential().await;

        // Token should not be cancelled initially
        assert!(!cancellation_token.is_cancelled());

        // Consume states until we hit the Failed state
        while let Some(state) = usb_stream.next().await {
            if matches!(state, UsbState::Failed(_)) {
                break;
            }
        }

        // The Failed state should have triggered cancellation
        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered when request fails"
        );
    }

    #[tokio::test]
    async fn test_failed_request_cancels_other_transports() {
        use credentialsd_common::model::Error;

        // USB will fail quickly
        let usb_handler = CancellationTrackingUsbHandler::new(
            vec![
                UsbStateInternal::Waiting,
                UsbStateInternal::Failed(Error::Internal("test".to_string())),
            ],
            10,
        );

        // Hybrid would keep going if not cancelled
        let hybrid_handler = CancellationTrackingHybridHandler::new(
            vec![
                HybridStateInternal::Init("qr".to_string()),
                HybridStateInternal::Connecting,
                HybridStateInternal::Connected,
            ],
            100,
        );

        // Clone handler to verify cancellation later
        let hybrid_handler_ref = hybrid_handler.clone();

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        // Start both streams
        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Collect one state from hybrid
        let _ = hybrid_stream.next().await;

        // Consume USB until it fails
        while let Some(state) = usb_stream.next().await {
            if matches!(state, UsbState::Failed(_)) {
                break;
            }
        }

        // Cancellation token should be triggered by USB failure
        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered when USB fails"
        );

        // Hybrid should stop emitting states (cancelled by USB failure)
        let hybrid_remaining: Vec<_> = hybrid_stream.collect().await;
        assert!(
            hybrid_remaining.is_empty(),
            "Hybrid should not emit any more states after USB fails"
        );

        // Verify the handler actually detected cancellation
        assert!(
            hybrid_handler_ref.was_cancelled(),
            "Hybrid handler should have detected cancellation when USB failed"
        );
    }

    #[tokio::test]
    async fn test_completed_request_triggers_cancellation() {
        let credential_response = create_test_credential_response();

        // Handler that emits a Completed state
        let usb_handler = CancellationTrackingUsbHandler::new(
            vec![
                UsbStateInternal::Waiting,
                UsbStateInternal::Completed(credential_response),
            ],
            10,
        );

        let service = CredentialService::new(MockHybridHandler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        // Start the USB stream
        let mut usb_stream = service.get_usb_credential().await;

        // Token should not be cancelled initially
        assert!(!cancellation_token.is_cancelled());

        // Consume states until we hit the Completed state
        while let Some(state) = usb_stream.next().await {
            if matches!(state, UsbState::Completed) {
                break;
            }
        }

        // The Completed state should have triggered cancellation
        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered when request completes successfully"
        );
    }

    #[tokio::test]
    async fn test_completed_request_cancels_other_transports() {
        let credential_response = create_test_credential_response();

        // USB will complete quickly
        let usb_handler = CancellationTrackingUsbHandler::new(
            vec![
                UsbStateInternal::Waiting,
                UsbStateInternal::Completed(credential_response),
            ],
            10,
        );

        // Hybrid would keep going if not cancelled
        let hybrid_handler = CancellationTrackingHybridHandler::new(
            vec![
                HybridStateInternal::Init("qr".to_string()),
                HybridStateInternal::Connecting,
                HybridStateInternal::Connected,
            ],
            100,
        );

        // Clone handler to verify cancellation later
        let hybrid_handler_ref = hybrid_handler.clone();

        let service = CredentialService::new(hybrid_handler, MockNfcHandler, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        // Start both streams
        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Collect one state from hybrid
        let _ = hybrid_stream.next().await;

        // Consume USB until it completes
        while let Some(state) = usb_stream.next().await {
            if matches!(state, UsbState::Completed) {
                break;
            }
        }

        // Cancellation token should be triggered by USB completion
        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered when USB completes"
        );

        // Hybrid should stop emitting states (cancelled by USB completion)
        let hybrid_remaining: Vec<_> = hybrid_stream.collect().await;
        assert!(
            hybrid_remaining.is_empty(),
            "Hybrid should not emit any more states after USB completes"
        );

        // Verify the handler actually detected cancellation
        assert!(
            hybrid_handler_ref.was_cancelled(),
            "Hybrid handler should have detected cancellation when USB completed"
        );
    }
}
