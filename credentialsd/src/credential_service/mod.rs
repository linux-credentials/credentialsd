pub mod hybrid;
pub mod nfc;
pub mod usb;

#[cfg(test)]
mod test_support;

use std::{
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
};

use async_trait::async_trait;
use futures_lite::{Stream, StreamExt};
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
struct RequestMarker;

#[derive(Clone, Debug)]
struct RequestLifecycle {
    request_id: RequestId,
    request_marker: Arc<RequestMarker>,
    cancellation: CancellationToken,
}

#[derive(Debug)]
struct RequestContext {
    request: CredentialRequest,
    response_channel: oneshot::Sender<Result<CredentialResponse, CredentialServiceError>>,
    request_id: RequestId,
    request_marker: Arc<RequestMarker>,
    cancellation: CancellationToken,
}

impl RequestContext {
    fn lifecycle(&self) -> RequestLifecycle {
        RequestLifecycle {
            request_id: self.request_id,
            request_marker: self.request_marker.clone(),
            cancellation: self.cancellation.clone(),
        }
    }

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
    fn current_request(&self) -> Option<(CredentialRequest, RequestLifecycle)> {
        self.ctx
            .lock()
            .unwrap()
            .as_ref()
            .map(|ctx| (ctx.request.clone(), ctx.lifecycle()))
    }

    fn hybrid_credential_stream(
        &self,
        request: &CredentialRequest,
        lifecycle: RequestLifecycle,
    ) -> Pin<Box<dyn Stream<Item = HybridState> + Send + 'static>> {
        let stream = self
            .hybrid_handler
            .lock()
            .unwrap()
            .start(request, lifecycle.cancellation.clone());
        credential_state_stream(stream, self.ctx.clone(), lifecycle)
    }

    fn usb_credential_stream(
        &self,
        request: &CredentialRequest,
        lifecycle: RequestLifecycle,
    ) -> Pin<Box<dyn Stream<Item = UsbState> + Send + 'static>> {
        let stream = self
            .usb_handler
            .lock()
            .unwrap()
            .start(request, lifecycle.cancellation.clone());
        credential_state_stream(stream, self.ctx.clone(), lifecycle)
    }

    #[cfg_attr(not(test), expect(dead_code))]
    fn nfc_credential_stream(
        &self,
        request: &CredentialRequest,
        lifecycle: RequestLifecycle,
    ) -> Pin<Box<dyn Stream<Item = NfcState> + Send + 'static>> {
        let stream = self
            ._nfc_handler
            .lock()
            .unwrap()
            .start(request, lifecycle.cancellation.clone());
        credential_state_stream(stream, self.ctx.clone(), lifecycle)
    }

    #[cfg(test)]
    async fn get_hybrid_credential(
        &self,
    ) -> Pin<Box<dyn Stream<Item = HybridState> + Send + 'static>> {
        if let Some((request, lifecycle)) = self.current_request() {
            self.hybrid_credential_stream(&request, lifecycle)
        } else {
            tracing::error!(
                "Attempted to start hybrid credential flow, but no request context was found."
            );
            todo!("Handle error when context is not set up.")
        }
    }

    #[cfg(test)]
    async fn get_usb_credential(&self) -> Pin<Box<dyn Stream<Item = UsbState> + Send + 'static>> {
        if let Some((request, lifecycle)) = self.current_request() {
            self.usb_credential_stream(&request, lifecycle)
        } else {
            tracing::error!(
                "Attempted to start usb credential flow, but no request context was found."
            );
            todo!("Handle error when context is not set up.")
        }
    }

    #[cfg(test)]
    async fn _get_nfc_credential(&self) -> Pin<Box<dyn Stream<Item = NfcState> + Send + 'static>> {
        if let Some((request, lifecycle)) = self.current_request() {
            self.nfc_credential_stream(&request, lifecycle)
        } else {
            tracing::error!(
                "Attempted to start nfc credential flow, but no request context was found."
            );
            todo!("Handle error when context is not set up.")
        }
    }

    fn merge_discovery_streams(
        &self,
        selected_transports: Vec<Pin<Box<dyn Stream<Item = DeviceStateUpdate> + Send + 'static>>>,
        lifecycle: RequestLifecycle,
    ) -> Pin<Box<dyn Stream<Item = DeviceStateUpdate> + Send + 'static>> {
        let selected_transports = futures::stream::select_all(selected_transports);
        discovery_state_stream(selected_transports, self.ctx.clone(), lifecycle)
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
                request_marker: Arc::new(RequestMarker),
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
        let Some((request, lifecycle)) = self.current_request() else {
            tracing::error!(
                "Attempted to start credential discovery, but no request context was found."
            );
            return futures::stream::empty().boxed();
        };
        let mut selected_transports = Vec::new();
        if available_transports.contains(&libwebauthn::Transport::Usb) {
            let usb = self
                .usb_credential_stream(&request, lifecycle.clone())
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
                .nfc_credential_stream(&request, lifecycle.clone())
                .map(DeviceStateUpdate::from)
                .boxed();
            selected_transports.push(nfc);
        }
        */
        if available_transports.contains(&libwebauthn::Transport::Hybrid) {
            let hybrid = self
                .hybrid_credential_stream(&request, lifecycle.clone())
                .map(DeviceStateUpdate::from)
                .boxed();
            selected_transports.push(hybrid);
        }

        self.merge_discovery_streams(selected_transports, lifecycle)
    }
}

/// An event emitted by a credential transport.
///
/// Transport implementations keep their privileged internal states private and
/// use this trait to expose the corresponding public state. Terminal events
/// additionally carry the result used to complete the active request.
trait TransportEvent {
    type PublicState;

    fn into_state_and_result(
        self,
    ) -> (
        Self::PublicState,
        Option<Result<CredentialResponse, CredentialServiceError>>,
    );
}

impl TransportEvent for HybridEvent {
    type PublicState = HybridState;

    fn into_state_and_result(
        self,
    ) -> (
        Self::PublicState,
        Option<Result<CredentialResponse, CredentialServiceError>>,
    ) {
        let result = match &self.state {
            HybridStateInternal::Completed(response) => Some(Ok(response.clone())),
            HybridStateInternal::Failed(error) => Some(Err(error.clone())),
            _ => None,
        };
        (self.state.into(), result)
    }
}

impl TransportEvent for UsbEvent {
    type PublicState = UsbState;

    fn into_state_and_result(
        self,
    ) -> (
        Self::PublicState,
        Option<Result<CredentialResponse, CredentialServiceError>>,
    ) {
        let result = match &self.state {
            UsbStateInternal::Completed(response) => Some(Ok(response.clone())),
            UsbStateInternal::Failed(error) => Some(Err(error.clone())),
            _ => None,
        };
        (self.state.into(), result)
    }
}

impl TransportEvent for NfcEvent {
    type PublicState = NfcState;

    fn into_state_and_result(
        self,
    ) -> (
        Self::PublicState,
        Option<Result<CredentialResponse, CredentialServiceError>>,
    ) {
        let result = match &self.state {
            NfcStateInternal::Completed(response) => Some(Ok(response.clone())),
            NfcStateInternal::Failed(error) => Some(Err(error.clone())),
            _ => None,
        };
        (self.state.into(), result)
    }
}

/// Applies request lifecycle handling to a transport's stream of events.
fn credential_state_stream<S, E>(
    mut inner: S,
    ctx: Arc<Mutex<Option<RequestContext>>>,
    lifecycle: RequestLifecycle,
) -> Pin<Box<dyn Stream<Item = E::PublicState> + Send + 'static>>
where
    S: Stream<Item = E> + Unpin + Send + 'static,
    E: TransportEvent + Send + 'static,
    E::PublicState: Send + 'static,
{
    Box::pin(async_stream::stream! {
        loop {
            let Some(event) = lifecycle.cancellation
                .run_until_cancelled(inner.next())
                .await
                .flatten()
            else {
                break;
            };

            if lifecycle.cancellation.is_cancelled() {
                break;
            }

            let (state, result) = event.into_state_and_result();
            if let Some(result) = result {
                if !complete_request(&ctx, &lifecycle, result) {
                    break;
                }
                yield state;
                break;
            }

            yield state;
        }
    })
}

/// Completes the request if every selected credential transport stops without
/// producing a terminal event.
fn discovery_state_stream<S>(
    mut inner: S,
    ctx: Arc<Mutex<Option<RequestContext>>>,
    lifecycle: RequestLifecycle,
) -> Pin<Box<dyn Stream<Item = DeviceStateUpdate> + Send + 'static>>
where
    S: Stream<Item = DeviceStateUpdate> + Unpin + Send + 'static,
{
    Box::pin(async_stream::stream! {
        loop {
            match lifecycle.cancellation.run_until_cancelled(inner.next()).await {
                None => break,
                Some(Some(state)) => yield state,
                Some(None) => {
                    if lifecycle.cancellation.is_cancelled() {
                        break;
                    }

                    let error = CredentialServiceError::Internal(
                        "All credential transports ended without a terminal event.".to_string(),
                    );
                    if complete_request(&ctx, &lifecycle, Err(error.clone())) {
                        yield DeviceStateUpdate::Failed(error);
                    }
                    break;
                }
            }
        }
    })
}

pub enum DeviceStateUpdate {
    Failed(CredentialServiceError),
    Hybrid(HybridState),
    Nfc(NfcState),
    Usb(UsbState),
}

impl From<DeviceStateUpdate> for BackgroundEvent {
    fn from(value: DeviceStateUpdate) -> Self {
        match value {
            DeviceStateUpdate::Failed(error) => match error {
                CredentialServiceError::AuthenticatorError => BackgroundEvent::ErrorAuthenticator,
                CredentialServiceError::NoCredentials => BackgroundEvent::ErrorNoCredentials,
                CredentialServiceError::CredentialExcluded => {
                    BackgroundEvent::ErrorCredentialExcluded
                }
                CredentialServiceError::PinAttemptsExhausted => BackgroundEvent::ErrorAuthenticator,
                CredentialServiceError::Internal(_) => BackgroundEvent::ErrorInternal,
            },
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
    lifecycle: &RequestLifecycle,
    response: Result<CredentialResponse, CredentialServiceError>,
) -> bool {
    let request_ctx = ctx.lock().unwrap().take_if(|request_ctx| {
        request_ctx.request_id == lifecycle.request_id
            && Arc::ptr_eq(&request_ctx.request_marker, &lifecycle.request_marker)
    });
    let Some(request_ctx) = request_ctx else {
        tracing::debug!(
            request_id = lifecycle.request_id,
            "Ignoring terminal event for a request that is no longer active."
        );
        return false;
    };

    request_ctx.cancellation.cancel();
    request_ctx.send_response(response);
    true
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
    use std::{task::Poll, time::Duration};

    use super::test_support::{EmptyTransport, ScriptedTransport};
    use super::*;

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
        let service = CredentialService::new(EmptyTransport, EmptyTransport, EmptyTransport);
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
        let service = CredentialService::new(EmptyTransport, EmptyTransport, EmptyTransport);
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
        let service = CredentialService::new(EmptyTransport, EmptyTransport, EmptyTransport);
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

    #[tokio::test]
    async fn test_cancel_request_by_id() {
        let service = CredentialService::new(EmptyTransport, EmptyTransport, EmptyTransport);
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
        let (usb_handler, usb_ref) = ScriptedTransport::<UsbStateInternal>::new();
        let (hybrid_handler, hybrid_ref) = ScriptedTransport::<HybridStateInternal>::new();

        let service = CredentialService::new(hybrid_handler, EmptyTransport, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        usb_ref.emit(UsbStateInternal::Waiting);
        hybrid_ref.emit(HybridStateInternal::Init("qr".to_string()));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        usb_ref.emit(UsbStateInternal::Waiting);
        usb_ref.emit(UsbStateInternal::Waiting);
        hybrid_ref.emit(HybridStateInternal::Connecting);

        service.cancel_request(request_id).await;
        assert!(cancellation_token.is_cancelled());

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
        let service = CredentialService::new(EmptyTransport, EmptyTransport, EmptyTransport);
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
        let service = CredentialService::new(EmptyTransport, EmptyTransport, EmptyTransport);
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
        let service = CredentialService::new(EmptyTransport, EmptyTransport, EmptyTransport);

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
        let service = CredentialService::new(EmptyTransport, EmptyTransport, EmptyTransport);
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
        let (usb_handler, usb_ref) = ScriptedTransport::<UsbStateInternal>::new();
        let (hybrid_handler, hybrid_ref) = ScriptedTransport::<HybridStateInternal>::new();

        assert!(!usb_ref.was_cancelled());
        assert!(!hybrid_ref.was_cancelled());

        let service = CredentialService::new(hybrid_handler, EmptyTransport, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Push and consume one state each to confirm streams are live
        usb_ref.emit(UsbStateInternal::Waiting);
        hybrid_ref.emit(HybridStateInternal::Init("qr".to_string()));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        // Queue additional states that should never be emitted after cancellation.
        // These sit in the channel when cancel_request() fires.
        usb_ref.emit(UsbStateInternal::Waiting);
        usb_ref.emit(UsbStateInternal::Waiting);
        hybrid_ref.emit(HybridStateInternal::Connecting);

        // Explicitly cancel — token becomes cancelled synchronously
        service.cancel_request(request_id).await;
        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered after cancel_request"
        );
        // Add explicit post-cancellation message.
        usb_ref.fail(CredentialServiceError::Internal("Cancelled".to_string()));

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

        // Flags are set by ScriptedTransport when it observes the cancelled token.
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
    async fn test_failed_request_triggers_cancellation() {
        use credentialsd_common::model::Error;

        let (usb_handler, usb_ref) = ScriptedTransport::<UsbStateInternal>::new();

        let service = CredentialService::new(EmptyTransport, EmptyTransport, usb_handler);
        let request = create_test_request().await;
        let (tx, rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        assert!(!cancellation_token.is_cancelled());

        usb_ref.emit(UsbStateInternal::Waiting);
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));

        usb_ref.fail(Error::Internal("test failure".to_string()));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Failed(_))));

        let result = rx.await.expect("request result should be sent");
        assert!(matches!(result, Err(Error::Internal(message)) if message == "test failure"));

        // The lifecycle stream completes a failed request and cancels its token.
        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered when request fails"
        );
    }

    #[tokio::test]
    async fn test_scripted_nfc_transport_uses_generic_lifecycle_stream() {
        use credentialsd_common::model::Error;

        let (nfc_handler, nfc_controller) = ScriptedTransport::<NfcStateInternal>::new();
        let service = CredentialService::new(EmptyTransport, nfc_handler, EmptyTransport);
        let request = create_test_request().await;
        let (tx, rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();
        let mut nfc_stream = service._get_nfc_credential().await;

        nfc_controller.emit(NfcStateInternal::Waiting);
        assert!(matches!(nfc_stream.next().await, Some(NfcState::Waiting)));

        nfc_controller.fail(Error::Internal("mock NFC failure".to_string()));
        assert!(matches!(nfc_stream.next().await, Some(NfcState::Failed(_))));
        assert!(cancellation_token.is_cancelled());

        let result = rx.await.expect("request result should be sent");
        assert!(matches!(result, Err(Error::Internal(message)) if message == "mock NFC failure"));
    }

    #[tokio::test]
    async fn test_scripted_nfc_transport_propagates_successful_response() {
        let (nfc_handler, nfc_controller) = ScriptedTransport::<NfcStateInternal>::new();
        let service = CredentialService::new(EmptyTransport, nfc_handler, EmptyTransport);
        let request = create_test_request().await;
        let (tx, rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();
        let mut nfc_stream = service._get_nfc_credential().await;

        nfc_controller.emit(NfcStateInternal::Waiting);
        assert!(matches!(nfc_stream.next().await, Some(NfcState::Waiting)));

        nfc_controller.complete(create_test_credential_response());
        assert!(matches!(nfc_stream.next().await, Some(NfcState::Completed)));
        assert!(cancellation_token.is_cancelled());

        let result = rx.await.expect("request result should be sent");
        let Ok(CredentialResponse::GetPublicKeyCredentialResponse(response)) = result else {
            panic!("NFC completion should propagate the credential response");
        };
        assert_eq!(response.attachment_modality, "cross-platform");
    }

    #[tokio::test]
    async fn test_scripted_hybrid_transport_propagates_failure() {
        use credentialsd_common::model::Error;

        let (hybrid_handler, hybrid_controller) = ScriptedTransport::<HybridStateInternal>::new();
        let service = CredentialService::new(hybrid_handler, EmptyTransport, EmptyTransport);
        let request = create_test_request().await;
        let (tx, rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();
        let mut hybrid_stream = service.get_hybrid_credential().await;

        hybrid_controller.emit(HybridStateInternal::Connecting);
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Connecting)
        ));

        hybrid_controller.fail(Error::NoCredentials);
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Failed(Error::NoCredentials))
        ));
        assert!(cancellation_token.is_cancelled());

        let result = rx.await.expect("request result should be sent");
        assert!(matches!(result, Err(Error::NoCredentials)));
    }

    #[tokio::test]
    async fn test_scripted_hybrid_transport_propagates_successful_response() {
        let (hybrid_handler, hybrid_controller) = ScriptedTransport::<HybridStateInternal>::new();
        let service = CredentialService::new(hybrid_handler, EmptyTransport, EmptyTransport);
        let request = create_test_request().await;
        let (tx, rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();
        let mut hybrid_stream = service.get_hybrid_credential().await;

        hybrid_controller.emit(HybridStateInternal::Connecting);
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Connecting)
        ));

        hybrid_controller.complete(create_test_credential_response());
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Completed)
        ));
        assert!(cancellation_token.is_cancelled());

        let result = rx.await.expect("request result should be sent");
        let Ok(CredentialResponse::GetPublicKeyCredentialResponse(response)) = result else {
            panic!("Hybrid completion should propagate the credential response");
        };
        assert_eq!(response.attachment_modality, "cross-platform");
    }

    #[tokio::test]
    async fn test_lifecycle_stream_discards_event_after_cancellation() {
        let request = create_test_request().await;
        let (response_channel, _response_rx) = oneshot::channel();
        let cancellation = CancellationToken::new();
        let request_marker = Arc::new(RequestMarker);
        cancellation.cancel();
        let ctx = Arc::new(Mutex::new(Some(RequestContext {
            request,
            response_channel,
            request_id: 1,
            request_marker: request_marker.clone(),
            cancellation: cancellation.clone(),
        })));
        let lifecycle = RequestLifecycle {
            request_id: 1,
            request_marker,
            cancellation,
        };
        let mut stream = credential_state_stream(
            futures::stream::iter([UsbEvent {
                state: UsbStateInternal::Waiting,
            }]),
            ctx.clone(),
            lifecycle,
        );

        assert!(stream.next().await.is_none());
        assert!(
            ctx.lock().unwrap().is_some(),
            "discarding a stale event must not complete the active request"
        );
    }

    #[tokio::test]
    async fn test_lifecycle_stream_discards_terminal_event_ready_during_cancellation() {
        let request = create_test_request().await;
        let (response_channel, mut response_rx) = oneshot::channel();
        let cancellation = CancellationToken::new();
        let cancellation_from_inner = cancellation.clone();
        let request_marker = Arc::new(RequestMarker);
        let ctx = Arc::new(Mutex::new(Some(RequestContext {
            request,
            response_channel,
            request_id: 1,
            request_marker: request_marker.clone(),
            cancellation: cancellation.clone(),
        })));
        let lifecycle = RequestLifecycle {
            request_id: 1,
            request_marker,
            cancellation,
        };
        let mut event = Some(UsbEvent {
            state: UsbStateInternal::Completed(create_test_credential_response()),
        });
        let inner = futures::stream::poll_fn(move |_cx| {
            cancellation_from_inner.cancel();
            Poll::Ready(event.take())
        });
        let mut stream = credential_state_stream(inner, ctx.clone(), lifecycle);

        assert!(stream.next().await.is_none());
        assert!(
            ctx.lock().unwrap().is_some(),
            "a terminal event concurrent with cancellation must not complete the request"
        );
        assert!(matches!(
            response_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn test_lifecycle_stream_wakes_when_cancelled_while_inner_is_pending() {
        let request = create_test_request().await;
        let (response_channel, _response_rx) = oneshot::channel();
        let cancellation = CancellationToken::new();
        let request_marker = Arc::new(RequestMarker);
        let ctx = Arc::new(Mutex::new(Some(RequestContext {
            request,
            response_channel,
            request_id: 1,
            request_marker: request_marker.clone(),
            cancellation: cancellation.clone(),
        })));
        let lifecycle = RequestLifecycle {
            request_id: 1,
            request_marker,
            cancellation: cancellation.clone(),
        };
        let (polled_tx, polled_rx) = oneshot::channel();
        let mut polled_tx = Some(polled_tx);
        let pending_inner = futures::stream::poll_fn(move |_cx| {
            if let Some(polled_tx) = polled_tx.take() {
                _ = polled_tx.send(());
            }
            Poll::<Option<UsbEvent>>::Pending
        });
        let mut stream = credential_state_stream(pending_inner, ctx.clone(), lifecycle);

        let waiting_task = tokio::spawn(async move { stream.next().await });
        polled_rx.await.expect("inner stream should be polled");
        cancellation.cancel();

        let event = tokio::time::timeout(Duration::from_secs(1), waiting_task)
            .await
            .expect("cancellation should wake the lifecycle stream")
            .expect("stream task should not panic");
        assert!(event.is_none());
        assert!(
            ctx.lock().unwrap().is_some(),
            "cancelling a pending stream must not complete the active request"
        );
    }

    #[tokio::test]
    async fn test_discovery_continues_when_one_transport_ends_unexpectedly() {
        let request = create_test_request().await;
        let (response_channel, response_rx) = oneshot::channel();
        let cancellation = CancellationToken::new();
        let request_id = 7;
        let request_marker = Arc::new(RequestMarker);
        let ctx = Arc::new(Mutex::new(Some(RequestContext {
            request,
            response_channel,
            request_id,
            request_marker: request_marker.clone(),
            cancellation: cancellation.clone(),
        })));
        let lifecycle = RequestLifecycle {
            request_id,
            request_marker,
            cancellation: cancellation.clone(),
        };
        let hybrid_stream = credential_state_stream(
            futures::stream::empty::<HybridEvent>(),
            ctx.clone(),
            lifecycle.clone(),
        )
        .map(DeviceStateUpdate::from)
        .boxed();
        let usb_stream = credential_state_stream(
            futures::stream::iter([
                UsbEvent {
                    state: UsbStateInternal::Waiting,
                },
                UsbEvent {
                    state: UsbStateInternal::Completed(create_test_credential_response()),
                },
            ]),
            ctx.clone(),
            lifecycle.clone(),
        )
        .map(DeviceStateUpdate::from)
        .boxed();
        let mut stream = discovery_state_stream(
            futures::stream::select_all(vec![hybrid_stream, usb_stream]),
            ctx,
            lifecycle,
        );

        assert!(matches!(
            stream.next().await,
            Some(DeviceStateUpdate::Usb(UsbState::Waiting))
        ));
        assert!(!cancellation.is_cancelled());
        assert!(matches!(
            stream.next().await,
            Some(DeviceStateUpdate::Usb(UsbState::Completed))
        ));

        let result = response_rx.await.expect("request result should be sent");
        assert!(result.is_ok());
        assert!(cancellation.is_cancelled());
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_discovery_fails_when_all_transports_end_unexpectedly() {
        let service = CredentialService::new(EmptyTransport, EmptyTransport, EmptyTransport);
        let request = create_test_request().await;
        let (response_channel, response_rx) = oneshot::channel();
        let (_request_id, cancellation) = service
            .init_request(&request, response_channel)
            .await
            .unwrap();
        let lifecycle = service.current_request().unwrap().1;
        let usb_stream = futures::stream::iter([DeviceStateUpdate::Usb(UsbState::Waiting)]).boxed();
        let hybrid_stream = futures::stream::empty::<DeviceStateUpdate>().boxed();
        let mut stream =
            service.merge_discovery_streams(vec![usb_stream, hybrid_stream], lifecycle);

        assert!(matches!(
            stream.next().await,
            Some(DeviceStateUpdate::Usb(UsbState::Waiting))
        ));

        let state = stream
            .next()
            .await
            .expect("exhausting all transports should emit a failure state");
        assert!(matches!(
            &state,
            DeviceStateUpdate::Failed(CredentialServiceError::Internal(message))
                if message == "All credential transports ended without a terminal event."
        ));
        assert_eq!(BackgroundEvent::from(state), BackgroundEvent::ErrorInternal);

        let result = response_rx.await.expect("request result should be sent");
        assert!(matches!(
            result,
            Err(CredentialServiceError::Internal(message))
                if message == "All credential transports ended without a terminal event."
        ));
        assert!(cancellation.is_cancelled());
        assert!(service.ctx.lock().unwrap().is_none());
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_cancelling_pending_discovery_does_not_report_transport_exhaustion() {
        let (usb_handler, usb_controller) = ScriptedTransport::<UsbStateInternal>::new();
        let service = CredentialService::new(EmptyTransport, EmptyTransport, usb_handler);
        let request = create_test_request().await;
        let (response_channel, response_rx) = oneshot::channel();
        let (request_id, cancellation) = service
            .init_request(&request, response_channel)
            .await
            .unwrap();
        let usb_stream = service
            .get_usb_credential()
            .await
            .map(DeviceStateUpdate::from)
            .boxed();
        let lifecycle = service.current_request().unwrap().1;
        let mut stream = service.merge_discovery_streams(vec![usb_stream], lifecycle);

        usb_controller.emit(UsbStateInternal::Waiting);
        assert!(matches!(
            stream.next().await,
            Some(DeviceStateUpdate::Usb(UsbState::Waiting))
        ));

        let waiting_task = tokio::spawn(async move { stream.next().await });
        tokio::task::yield_now().await;
        service.cancel_request(request_id).await;

        let event = tokio::time::timeout(Duration::from_secs(1), waiting_task)
            .await
            .expect("cancellation should wake the aggregate discovery stream")
            .expect("discovery task should not panic");
        assert!(event.is_none());
        assert!(cancellation.is_cancelled());
        assert!(usb_controller.was_cancelled());

        let result = response_rx.await.expect("request result should be sent");
        assert!(matches!(
            result,
            Err(CredentialServiceError::Internal(message))
                if message == format!("Cancelled request {request_id}.")
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_terminal_events_emit_only_one_terminal_state() {
        let request = create_test_request().await;
        let (response_channel, response_rx) = oneshot::channel();
        let cancellation = CancellationToken::new();
        let request_id = 11;
        let request_marker = Arc::new(RequestMarker);
        let ctx = Arc::new(Mutex::new(Some(RequestContext {
            request,
            response_channel,
            request_id,
            request_marker: request_marker.clone(),
            cancellation: cancellation.clone(),
        })));
        let lifecycle = RequestLifecycle {
            request_id,
            request_marker,
            cancellation: cancellation.clone(),
        };
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let make_discovery = || {
            let barrier = barrier.clone();
            let usb_events = futures::stream::once(async move {
                barrier.wait().await;
                UsbEvent {
                    state: UsbStateInternal::Completed(create_test_credential_response()),
                }
            })
            .boxed();
            let usb_stream = credential_state_stream(usb_events, ctx.clone(), lifecycle.clone())
                .map(DeviceStateUpdate::from)
                .boxed();
            discovery_state_stream(
                futures::stream::select_all(vec![usb_stream]),
                ctx.clone(),
                lifecycle.clone(),
            )
        };
        let mut first_discovery = make_discovery();
        let mut second_discovery = make_discovery();
        let first = tokio::spawn(async move { first_discovery.next().await });
        let second = tokio::spawn(async move { second_discovery.next().await });

        barrier.wait().await;
        let (first, second) = tokio::join!(first, second);
        let events = [
            first.expect("first discovery task should not panic"),
            second.expect("second discovery task should not panic"),
        ];
        assert_eq!(
            events
                .into_iter()
                .filter(|event| {
                    matches!(event, Some(DeviceStateUpdate::Usb(UsbState::Completed)))
                })
                .count(),
            1,
            "only the winning terminal event should be emitted"
        );
        assert!(cancellation.is_cancelled());
        assert!(ctx.lock().unwrap().is_none());
        assert!(
            response_rx
                .await
                .expect("request result should be sent")
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_lifecycle_stream_cannot_complete_a_newer_request() {
        let request = create_test_request().await;
        let (response_channel, mut response_rx) = oneshot::channel();
        let current_cancellation = CancellationToken::new();
        let current_request_marker = Arc::new(RequestMarker);
        let ctx = Arc::new(Mutex::new(Some(RequestContext {
            request,
            response_channel,
            request_id: 1,
            request_marker: current_request_marker,
            cancellation: current_cancellation.clone(),
        })));
        let stale_cancellation = CancellationToken::new();
        let stale_request_marker = Arc::new(RequestMarker);
        let mut stale_stream = credential_state_stream(
            futures::stream::iter([UsbEvent {
                state: UsbStateInternal::Completed(create_test_credential_response()),
            }]),
            ctx.clone(),
            RequestLifecycle {
                request_id: 1,
                request_marker: stale_request_marker,
                cancellation: stale_cancellation.clone(),
            },
        );

        assert!(stale_stream.next().await.is_none());
        assert!(!stale_cancellation.is_cancelled());
        assert!(!current_cancellation.is_cancelled());
        assert_eq!(
            ctx.lock().unwrap().as_ref().map(|ctx| ctx.request_id),
            Some(1)
        );
        assert!(matches!(
            response_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn test_stale_discovery_exhaustion_cannot_complete_a_newer_request() {
        let service = CredentialService::new(EmptyTransport, EmptyTransport, EmptyTransport);
        let request = create_test_request().await;
        let (stale_response_tx, stale_response_rx) = oneshot::channel();
        let (stale_request_id, _stale_cancellation) = service
            .init_request(&request, stale_response_tx)
            .await
            .unwrap();
        let stale_lifecycle = service.current_request().unwrap().1;

        service.cancel_request(stale_request_id).await;
        assert!(stale_response_rx.await.unwrap().is_err());

        let (current_response_tx, mut current_response_rx) = oneshot::channel();
        let (current_request_id, current_cancellation) = service
            .init_request(&request, current_response_tx)
            .await
            .unwrap();
        let stale_transport = futures::stream::empty::<DeviceStateUpdate>().boxed();
        let mut stale_discovery =
            service.merge_discovery_streams(vec![stale_transport], stale_lifecycle);

        assert!(stale_discovery.next().await.is_none());
        assert!(!current_cancellation.is_cancelled());
        assert_eq!(
            service
                .ctx
                .lock()
                .unwrap()
                .as_ref()
                .map(|ctx| ctx.request_id),
            Some(current_request_id)
        );
        assert!(matches!(
            current_response_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        service.cancel_request(current_request_id).await;
    }

    #[tokio::test]
    async fn test_failed_request_cancels_other_transports() {
        use credentialsd_common::model::Error;

        let (usb_handler, usb_ref) = ScriptedTransport::<UsbStateInternal>::new();
        let (hybrid_handler, hybrid_ref) = ScriptedTransport::<HybridStateInternal>::new();

        let service = CredentialService::new(hybrid_handler, EmptyTransport, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Confirm hybrid stream is live
        hybrid_ref.emit(HybridStateInternal::Init("qr".to_string()));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        // Queue an extra hybrid state that should be discarded once USB fails.
        // It sits in the channel when complete_request() cancels the token.
        hybrid_ref.emit(HybridStateInternal::Connecting);

        // USB failure completes the request and cancels the token.
        usb_ref.emit(UsbStateInternal::Waiting);
        usb_ref.fail(Error::Internal("test".to_string()));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Failed(_))));

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

        let (usb_handler, usb_ref) = ScriptedTransport::<UsbStateInternal>::new();

        let service = CredentialService::new(EmptyTransport, EmptyTransport, usb_handler);
        let request = create_test_request().await;
        let (tx, rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        assert!(!cancellation_token.is_cancelled());

        usb_ref.emit(UsbStateInternal::Waiting);
        usb_ref.complete(credential_response);
        assert!(matches!(usb_stream.next().await, Some(UsbState::Waiting)));
        assert!(matches!(usb_stream.next().await, Some(UsbState::Completed)));

        assert!(rx.await.expect("request result should be sent").is_ok());

        // The lifecycle stream completes the request and cancels its token.
        assert!(
            cancellation_token.is_cancelled(),
            "Cancellation token should be triggered when request completes successfully"
        );
    }

    #[tokio::test]
    async fn test_completed_request_cancels_other_transports() {
        let credential_response = create_test_credential_response();

        let (usb_handler, usb_ref) = ScriptedTransport::<UsbStateInternal>::new();
        let (hybrid_handler, hybrid_ref) = ScriptedTransport::<HybridStateInternal>::new();

        let service = CredentialService::new(hybrid_handler, EmptyTransport, usb_handler);
        let request = create_test_request().await;
        let (tx, _rx) = oneshot::channel();

        let (_request_id, cancellation_token) = service.init_request(&request, tx).await.unwrap();

        let mut usb_stream = service.get_usb_credential().await;
        let mut hybrid_stream = service.get_hybrid_credential().await;

        // Confirm hybrid stream is live
        hybrid_ref.emit(HybridStateInternal::Init("qr".to_string()));
        assert!(matches!(
            hybrid_stream.next().await,
            Some(HybridState::Init(_))
        ));

        // Queue an extra hybrid state that should be discarded once USB completes.
        // It sits in the channel when complete_request() cancels the token.
        hybrid_ref.emit(HybridStateInternal::Connecting);

        // USB completion completes the request and cancels the token.
        usb_ref.emit(UsbStateInternal::Waiting);
        usb_ref.complete(credential_response);
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
}
