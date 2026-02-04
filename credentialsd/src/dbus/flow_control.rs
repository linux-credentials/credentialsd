//! This module implements the service to allow the user to control the flow of
//! the credential request through the trusted UI.

use std::future::Future;
use std::{collections::VecDeque, fmt::Debug, sync::Arc};

use credentialsd_common::model::{
    BackgroundEvent, Error as CredentialServiceError, RequestingApplication, WebAuthnError,
};
use credentialsd_common::server::{Device, RequestId, WindowHandle};
use futures_lite::StreamExt;
use tokio::sync::oneshot;
use tokio::{
    sync::{
        mpsc::{self, Sender},
        Mutex as AsyncMutex,
    },
    task::AbortHandle,
};
use zbus::{
    connection::{Builder, Connection},
    fdo, interface,
    object_server::{InterfaceRef, SignalEmitter},
    ObjectServer,
};

use crate::{
    credential_service::{
        hybrid::{HybridHandler, HybridState},
        nfc::{NfcHandler, NfcState},
        usb::UsbHandler,
        CredentialService, UiController, UsbState,
    },
    model::{CredentialRequest, CredentialResponse},
};

pub const SERVICE_PATH: &str = "/xyz/iinuwa/credentialsd/FlowControl";
pub const SERVICE_NAME: &str = "xyz.iinuwa.credentialsd.FlowControl";

pub async fn start_flow_control_service<
    H: HybridHandler + Debug + Send + Sync + 'static,
    U: UsbHandler + Debug + Send + Sync + 'static,
    N: NfcHandler + Debug + Send + Sync + 'static,
    UC: UiController + Debug + Send + Sync + 'static,
>(
    credential_service: CredentialService<H, U, N, UC>,
) -> zbus::Result<(
    Connection,
    Sender<(
        CredentialRequest,
        Option<RequestingApplication>, // Application name sending the request
        Option<WindowHandle>,          // Client window handle
        oneshot::Sender<Result<CredentialResponse, CredentialServiceError>>,
    )>,
)> {
    let svc = Arc::new(AsyncMutex::new(credential_service));
    let svc2 = svc.clone();
    let conn = Builder::session()?
        .name(SERVICE_NAME)?
        .serve_at(
            SERVICE_PATH,
            FlowControlService {
                signal_state: Arc::new(AsyncMutex::new(SignalState::Idle)),
                svc,
                pin_tx: Arc::new(AsyncMutex::new(None)),
                cred_tx: Arc::new(AsyncMutex::new(None)),
                usb_event_forwarder_task: Arc::new(AsyncMutex::new(None)),
                nfc_event_forwarder_task: Arc::new(AsyncMutex::new(None)),
                hybrid_event_forwarder_task: Arc::new(AsyncMutex::new(None)),
            },
        )?
        .build()
        .await?;
    let (initiator_tx, mut initiator_rx) = mpsc::channel(2);
    tokio::spawn(async move {
        let svc = svc2;
        while let Some((msg, requesting_app, window_handle, tx)) = initiator_rx.recv().await {
            svc.lock()
                .await
                .init_request(&msg, requesting_app, window_handle, tx)
                .await;
        }
    });
    Ok((conn, initiator_tx))
}

struct FlowControlService<H: HybridHandler, U: UsbHandler, N: NfcHandler, UC: UiController> {
    signal_state: Arc<AsyncMutex<SignalState>>,
    svc: Arc<AsyncMutex<CredentialService<H, U, N, UC>>>,
    pin_tx: Arc<AsyncMutex<Option<Sender<String>>>>,
    cred_tx: Arc<AsyncMutex<Option<Sender<String>>>>,
    usb_event_forwarder_task: Arc<AsyncMutex<Option<AbortHandle>>>,
    nfc_event_forwarder_task: Arc<AsyncMutex<Option<AbortHandle>>>,
    hybrid_event_forwarder_task: Arc<AsyncMutex<Option<AbortHandle>>>,
}

/// The following methods are for communication between the [trusted]
/// UI and the credential service, and should not be called by arbitrary
/// clients.
#[interface(
    name = "xyz.iinuwa.credentialsd.FlowControl1",
    proxy(
        gen_blocking = false,
        default_path = "/xyz/iinuwa/credentialsd/FlowControl",
        default_service = "xyz.iinuwa.credentialsd.FlowControl",
    )
)]
impl<H, U, N, UC> FlowControlService<H, U, N, UC>
where
    H: HybridHandler + Debug + Send + Sync + 'static,
    U: UsbHandler + Debug + Send + Sync + 'static,
    N: NfcHandler + Debug + Send + Sync + 'static,
    UC: UiController + Debug + Send + Sync + 'static,
{
    async fn subscribe(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        let mut signal_state = self.signal_state.lock().await;
        match *signal_state {
            SignalState::Idle => {}
            SignalState::Pending(ref mut pending) => {
                for msg in pending.iter_mut() {
                    emitter.state_changed(msg.clone()).await?;
                }
            }
            SignalState::Active => {}
        };
        *signal_state = SignalState::Active;
        Ok(())
    }

    async fn get_available_public_key_devices(&self) -> fdo::Result<Vec<Device>> {
        let devices = self
            .svc
            .lock()
            .await
            .get_available_public_key_devices()
            .await
            .map_err(|_| fdo::Error::Failed("Failed to retrieve available devices".to_string()))?;
        let dbus_devices: Vec<Device> = devices.into_iter().map(Device::from).collect();

        Ok(dbus_devices)
    }

    async fn get_hybrid_credential(
        &self,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<()> {
        let svc = self.svc.lock().await;
        let mut stream = svc.get_hybrid_credential();
        let signal_state = self.signal_state.clone();
        let object_server = object_server.clone();
        let task = tokio::spawn(async move {
            let interface: zbus::Result<InterfaceRef<FlowControlService<H, U, N, UC>>> =
                object_server.interface(SERVICE_PATH).await;

            let emitter = match interface {
                Ok(ref i) => i.signal_emitter(),
                Err(err) => {
                    tracing::error!("Failed to get connection to D-Bus to send signals: {err}");
                    return;
                }
            };
            while let Some(state) = stream.next().await {
                let event = credentialsd_common::model::BackgroundEvent::HybridQrStateChanged(
                    state.clone().into(),
                );
                if let Err(err) = send_state_update(emitter, &signal_state, event).await {
                    tracing::error!("Failed to send state update to UI: {err}");
                    break;
                };
                match state {
                    HybridState::Completed | HybridState::Failed => {
                        break;
                    }
                    _ => {}
                };
            }
        })
        .abort_handle();
        if let Some(prev_task) = self.hybrid_event_forwarder_task.lock().await.replace(task) {
            prev_task.abort();
        }
        Ok(())
    }

    async fn get_usb_credential(
        &self,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<()> {
        let mut stream = self.svc.lock().await.get_usb_credential();
        let usb_pin_tx = self.pin_tx.clone();
        let usb_cred_tx = self.cred_tx.clone();
        let signal_state = self.signal_state.clone();
        let object_server = object_server.clone();
        let task = tokio::spawn(async move {
            let interface: zbus::Result<InterfaceRef<FlowControlService<H, U, N, UC>>> =
                object_server.interface(SERVICE_PATH).await;

            let emitter = match interface {
                Ok(ref i) => i.signal_emitter(),
                Err(err) => {
                    tracing::error!("Failed to get connection to D-Bus to send signals: {err}");
                    return;
                }
            };
            while let Some(state) = stream.next().await {
                let event =
                    credentialsd_common::model::BackgroundEvent::UsbStateChanged((&state).into());
                if let Err(err) = send_state_update(emitter, &signal_state, event).await {
                    tracing::error!("Failed to send state update to UI: {err}");
                    break;
                };
                match state {
                    UsbState::NeedsPin { pin_tx, .. } => {
                        let mut usb_pin_tx = usb_pin_tx.lock().await;
                        let _ = usb_pin_tx.insert(pin_tx);
                    }
                    UsbState::SelectCredential { cred_tx, .. } => {
                        let mut usb_cred_tx = usb_cred_tx.lock().await;
                        let _ = usb_cred_tx.insert(cred_tx);
                    }
                    UsbState::Completed | UsbState::Failed(_) => {
                        break;
                    }
                    _ => {}
                };
            }
        })
        .abort_handle();
        if let Some(prev_task) = self.usb_event_forwarder_task.lock().await.replace(task) {
            prev_task.abort();
        }
        Ok(())
    }

    async fn get_nfc_credential(
        &self,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<()> {
        let mut stream = self.svc.lock().await.get_nfc_credential();
        let nfc_pin_tx = self.pin_tx.clone();
        let nfc_cred_tx = self.cred_tx.clone();
        let signal_state = self.signal_state.clone();
        let object_server = object_server.clone();
        let task = tokio::spawn(async move {
            let interface: zbus::Result<InterfaceRef<FlowControlService<H, U, N, UC>>> =
                object_server.interface(SERVICE_PATH).await;

            let emitter = match interface {
                Ok(ref i) => i.signal_emitter(),
                Err(err) => {
                    tracing::error!("Failed to get connection to D-Bus to send signals: {err}");
                    return;
                }
            };
            while let Some(state) = stream.next().await {
                let event =
                    credentialsd_common::model::BackgroundEvent::NfcStateChanged((&state).into());
                if let Err(err) = send_state_update(emitter, &signal_state, event).await {
                    tracing::error!("Failed to send state update to UI: {err}");
                    break;
                };
                match state {
                    NfcState::NeedsPin { pin_tx, .. } => {
                        let mut nfc_pin_tx = nfc_pin_tx.lock().await;
                        let _ = nfc_pin_tx.insert(pin_tx);
                    }
                    NfcState::SelectCredential { cred_tx, .. } => {
                        let mut nfc_cred_tx = nfc_cred_tx.lock().await;
                        let _ = nfc_cred_tx.insert(cred_tx);
                    }
                    NfcState::Completed | NfcState::Failed(_) => {
                        break;
                    }
                    _ => {}
                };
            }
        })
        .abort_handle();
        if let Some(prev_task) = self.nfc_event_forwarder_task.lock().await.replace(task) {
            prev_task.abort();
        }
        Ok(())
    }

    async fn enter_client_pin(&self, pin: String) -> fdo::Result<()> {
        if let Some(pin_tx) = self.pin_tx.lock().await.take() {
            pin_tx.send(pin).await.unwrap();
        }
        Ok(())
    }

    async fn select_credential(&self, credential_id: String) -> fdo::Result<()> {
        if let Some(cred_tx) = self.cred_tx.lock().await.take() {
            cred_tx.send(credential_id).await.unwrap();
        }
        Ok(())
    }

    async fn cancel_request(&self, request_id: RequestId) -> fdo::Result<()> {
        self.svc.lock().await.cancel_request(request_id).await;
        Ok(())
    }

    #[zbus(signal)]
    async fn state_changed(
        emitter: &SignalEmitter<'_>,
        update: BackgroundEvent,
    ) -> zbus::Result<()>;
}

async fn send_state_update(
    emitter: &SignalEmitter<'_>,
    signal_state: &Arc<AsyncMutex<SignalState>>,
    update: BackgroundEvent,
) -> fdo::Result<()> {
    let mut signal_state = signal_state.lock().await;
    match *signal_state {
        SignalState::Idle => {
            let pending = VecDeque::from([update]);
            *signal_state = SignalState::Pending(pending);
        }
        SignalState::Pending(ref mut pending) => {
            pending.push_back(update);
        }
        SignalState::Active => {
            emitter.state_changed(update).await?;
        }
    };
    Ok(())
}

enum SignalState {
    /// No state
    Idle,
    /// Waiting for client to signal that it's ready to receive events.
    /// Holds a cache of events to send once the client connects.
    Pending(VecDeque<BackgroundEvent>),
    /// Client is actively receiving messages.
    Active,
}

pub trait CredentialRequestController {
    fn request_credential(
        &self,
        requesting_app: Option<RequestingApplication>,
        request: CredentialRequest,
        window_handle: Option<WindowHandle>,
    ) -> impl Future<Output = Result<CredentialResponse, WebAuthnError>> + Send;
}

pub struct CredentialRequestControllerClient {
    pub initiator: Sender<(
        CredentialRequest,
        Option<RequestingApplication>, // Application name sending the request
        Option<WindowHandle>,          // Client window handle,
        oneshot::Sender<Result<CredentialResponse, CredentialServiceError>>,
    )>,
}

impl CredentialRequestController for CredentialRequestControllerClient {
    async fn request_credential(
        &self,
        requesting_app: Option<RequestingApplication>,
        request: CredentialRequest,
        window_handle: Option<WindowHandle>,
    ) -> Result<CredentialResponse, WebAuthnError> {
        let (tx, rx) = oneshot::channel();
        self.initiator
            .send((request, requesting_app, window_handle, tx))
            .await
            .unwrap();
        let response = rx.await.map_err(|_| {
            tracing::error!("Credential response channel closed prematurely");
            WebAuthnError::NotAllowedError
        })?;
        // TODO: CredentialServiceError is returning the wrong errors types to the flow controller
        // We need to be able to bubble up the InvalidStateError, when the
        // selected authenticator has the credential known by the RP, and
        // the user wants to let the RP know.
        // All the other possible errors from the spec (AbortError,
        // ConstraintError, SecurityError, TypeError) should be handled
        // earlier by the gateway.
        // Every other error should be squashed into NotAllowed as a catch-all
        // For now, just squashing.
        response.map_err(|_| WebAuthnError::NotAllowedError)
    }
}

#[cfg(test)]
pub mod test {
    use std::{
        error::Error,
        fmt::Debug,
        pin::Pin,
        sync::{Arc, Mutex},
    };

    use credentialsd_common::{
        client::FlowController,
        model::{BackgroundEvent, Device},
        server::RequestId,
    };
    use futures_lite::{Stream, StreamExt};
    use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

    use crate::credential_service::{
        hybrid::{HybridHandler, HybridState},
        nfc::{NfcHandler, NfcState},
        usb::UsbHandler,
        CredentialService, UiController, UsbState,
    };

    #[allow(clippy::enum_variant_names)]
    #[derive(Debug)]
    pub enum DummyFlowRequest {
        EnterClientPin(String),
        GetDevices,
        GetHybridCredential,
        GetUsbCredential,
        GetNfcCredential,
        InitStream,
    }

    // Clippy complains that these variant names have the same prefix, but that's
    // intentional for now.
    #[allow(clippy::enum_variant_names)]
    pub enum DummyFlowResponse {
        EnterClientPin(Result<(), ()>),
        GetDevices(Vec<Device>),
        GetHybridCredential,
        GetUsbCredential,
        GetNfcCredential,
        InitStream(Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()>),
    }

    impl Debug for DummyFlowResponse {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::EnterClientPin(arg0) => f.debug_tuple("EnterClientPin").field(arg0).finish(),
                Self::GetDevices(arg0) => f.debug_tuple("GetDevices").field(arg0).finish(),
                Self::GetHybridCredential => f.debug_tuple("GetHybridCredential").finish(),
                Self::GetUsbCredential => f.debug_tuple("GetUsbCredential").finish(),
                Self::GetNfcCredential => f.debug_tuple("GetNfcCredential").finish(),
                Self::InitStream(_) => f
                    .debug_tuple("InitStream")
                    .field(&String::from("<BackgroundEventStream>"))
                    .finish(),
            }
        }
    }
    /// Represents a client for the UI to call methods on the credential service.
    #[derive(Debug)]
    pub struct DummyFlowClient {
        tx: mpsc::Sender<(DummyFlowRequest, oneshot::Sender<DummyFlowResponse>)>,
    }

    impl DummyFlowClient {
        async fn send(&self, request: DummyFlowRequest) -> Result<DummyFlowResponse, ()> {
            let (response_tx, response_rx) = oneshot::channel();
            self.tx.send((request, response_tx)).await.unwrap();
            match response_rx.await {
                Ok(response) => Ok(response),
                Err(err) => {
                    tracing::error!("Failed to retrieve response from server: {:?}", err);
                    Err(())
                }
            }
        }
    }

    impl FlowController for DummyFlowClient {
        async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
            let response = self.send(DummyFlowRequest::GetDevices).await.unwrap();
            if let DummyFlowResponse::GetDevices(devices) = response {
                Ok(devices)
            } else {
                Err(())
            }
        }

        async fn get_hybrid_credential(&mut self) -> Result<(), ()> {
            if let Ok(DummyFlowResponse::GetHybridCredential) =
                self.send(DummyFlowRequest::GetHybridCredential).await
            {
                Ok(())
            } else {
                Err(())
            }
        }

        async fn get_usb_credential(&mut self) -> Result<(), ()> {
            let response = self.send(DummyFlowRequest::GetUsbCredential).await.unwrap();
            if let DummyFlowResponse::GetUsbCredential = response {
                Ok(())
            } else {
                Err(())
            }
        }

        async fn get_nfc_credential(&mut self) -> Result<(), ()> {
            let response = self.send(DummyFlowRequest::GetNfcCredential).await.unwrap();
            if let DummyFlowResponse::GetNfcCredential = response {
                Ok(())
            } else {
                Err(())
            }
        }

        async fn subscribe(
            &mut self,
        ) -> Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()> {
            if let Ok(DummyFlowResponse::InitStream(Ok(stream))) =
                self.send(DummyFlowRequest::InitStream).await
            {
                Ok(stream)
            } else {
                Err(())
            }
        }

        async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
            if let Ok(DummyFlowResponse::EnterClientPin(Ok(()))) =
                self.send(DummyFlowRequest::EnterClientPin(pin)).await
            {
                Ok(())
            } else {
                Err(())
            }
        }

        async fn select_credential(&self, _credential_id: String) -> Result<(), ()> {
            todo!();
        }

        async fn cancel_request(&self, _request_id: RequestId) -> Result<(), ()> {
            todo!()
        }
    }

    #[derive(Debug)]
    pub struct DummyFlowServer<H, U, N, UC>
    where
        H: HybridHandler + Debug + Send + Sync,
        U: UsbHandler + Debug + Send + Sync,
        N: NfcHandler + Debug + Send + Sync,
        UC: UiController + Debug + Send + Sync,
    {
        rx: mpsc::Receiver<(DummyFlowRequest, oneshot::Sender<DummyFlowResponse>)>,
        svc: Arc<AsyncMutex<CredentialService<H, U, N, UC>>>,
        bg_event_tx: Option<mpsc::Sender<BackgroundEvent>>,
        pin_tx: Arc<AsyncMutex<Option<tokio::sync::mpsc::Sender<String>>>>,
        usb_event_forwarder_task: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
        nfc_event_forwarder_task: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
        hybrid_event_forwarder_task: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    }

    impl<
            H: HybridHandler + Debug + Send + Sync,
            U: UsbHandler + Debug + Send + Sync,
            N: NfcHandler + Debug + Send + Sync,
            UC: UiController + Debug + Send + Sync,
        > DummyFlowServer<H, U, N, UC>
    {
        /*
        async fn send(&self, request: ManagementRequest) -> Result<ManagementResponse, ()> {
            let (response_tx, response_rx) = oneshot::channel();
            self.tx
                .send((InProcessServerRequest::Management(request), response_tx))
                .await
                .unwrap();
            match response_rx.await {
                Ok(InProcessServerResponse::Management(response)) => Ok(response),
                Ok(_) => {
                    tracing::error!("invalid response received from server");
                    Err(())
                }
                Err(err) => {
                    tracing::error!("Failed to retrieve response from server: {:?}", err);
                    Err(())
                }
            }
        }
        */
        pub fn new(
            svc: Arc<AsyncMutex<CredentialService<H, U, N, UC>>>,
        ) -> (Self, DummyFlowClient) {
            let (request_tx, request_rx) = mpsc::channel(32);
            let server = Self {
                rx: request_rx,
                svc,
                bg_event_tx: None,
                pin_tx: Arc::new(AsyncMutex::new(None)),
                usb_event_forwarder_task: Arc::new(Mutex::new(None)),
                nfc_event_forwarder_task: Arc::new(Mutex::new(None)),
                hybrid_event_forwarder_task: Arc::new(Mutex::new(None)),
            };
            let client = DummyFlowClient { tx: request_tx };
            (server, client)
        }

        pub async fn run(&mut self) {
            while let Some((request, tx)) = self.rx.recv().await {
                tracing::debug!(target: "DummyFlowServer", "Received message: {request:?}");
                let response = match request {
                    DummyFlowRequest::EnterClientPin(pin) => {
                        let rsp = self.enter_client_pin(pin).await;
                        DummyFlowResponse::EnterClientPin(rsp)
                    }
                    DummyFlowRequest::GetDevices => {
                        let rsp = self.get_available_public_key_devices().await.unwrap();
                        DummyFlowResponse::GetDevices(rsp)
                    }
                    DummyFlowRequest::GetHybridCredential => {
                        self.get_hybrid_credential().await.unwrap();
                        DummyFlowResponse::GetHybridCredential
                    }

                    DummyFlowRequest::GetUsbCredential => {
                        self.get_usb_credential().await.unwrap();
                        DummyFlowResponse::GetUsbCredential
                    }
                    DummyFlowRequest::GetNfcCredential => {
                        self.get_nfc_credential().await.unwrap();
                        DummyFlowResponse::GetNfcCredential
                    }
                    DummyFlowRequest::InitStream => {
                        let rsp = self.subscribe().await;
                        DummyFlowResponse::InitStream(rsp)
                    }
                };
                tx.send(response).unwrap()
            }
        }

        async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, Box<dyn Error>> {
            tracing::debug!(target: "DummyFlowServer", "get_available_public_key_devices()");
            let devices = self
                .svc
                .lock()
                .await
                .get_available_public_key_devices()
                .await
                .map_err(|_| "Failed to get public key devices".to_string())?;
            Ok(devices)
        }

        async fn get_hybrid_credential(&mut self) -> Result<(), ()> {
            let svc = self.svc.lock().await;
            let mut stream = svc.get_hybrid_credential();
            tracing::debug!(target: "DummyFlowServer", "Subscribing to hybrid credential state changes");
            if let Some(tx_weak) = self.bg_event_tx.as_ref().map(|t| t.clone().downgrade()) {
                let task = tokio::spawn(async move {
                    while let Some(hybrid_state) = stream.next().await {
                        tracing::debug!(target: "DummyFlowServer", "Received hybrid state change: {hybrid_state:?}");
                        if let Some(tx) = tx_weak.upgrade() {
                            match hybrid_state {
                                HybridState::Completed | HybridState::Failed => {
                                    tx.send(BackgroundEvent::HybridQrStateChanged(
                                        hybrid_state.into(),
                                    ))
                                    .await
                                    .unwrap();
                                    break;
                                }
                                _ => tx
                                    .send(BackgroundEvent::HybridQrStateChanged(
                                        hybrid_state.into(),
                                    ))
                                    .await
                                    .unwrap(),
                            };
                        }
                    }
                })
                .abort_handle();
                if let Some(prev_task) = self
                    .hybrid_event_forwarder_task
                    .lock()
                    .unwrap()
                    .replace(task)
                {
                    prev_task.abort();
                }
            } else {
                tracing::warn!(target: "DummyFlowServer", "Output stream not initialized before setting up hybrid state stream; some messages may be missed.");
            }
            Ok(())
        }

        async fn get_usb_credential(&mut self) -> Result<(), ()> {
            let mut stream = self.svc.lock().await.get_usb_credential();
            if let Some(tx_weak) = self.bg_event_tx.as_ref().map(|t| t.clone().downgrade()) {
                let usb_pin_tx = self.pin_tx.clone();
                let task = tokio::spawn(async move {
                    while let Some(state) = stream.next().await {
                        if let Some(tx) = tx_weak.upgrade() {
                            if tx
                                .send(BackgroundEvent::UsbStateChanged(state.clone().into()))
                                .await
                                .is_err()
                            {
                                tracing::debug!("Closing USB background event forwarder");
                                break;
                            }
                            match state {
                                UsbState::NeedsPin { pin_tx, .. } => {
                                    let mut usb_pin_tx = usb_pin_tx.lock().await;
                                    let _ = usb_pin_tx.insert(pin_tx);
                                }
                                UsbState::Completed | UsbState::Failed(_) => {
                                    break;
                                }
                                _ => {}
                            };
                        }
                    }
                })
                .abort_handle();
                if let Some(prev_task) = self.usb_event_forwarder_task.lock().unwrap().replace(task)
                {
                    prev_task.abort();
                }
            } else {
                tracing::warn!(target: "DummyFlowServer", "Output stream not initialized before setting up USB state stream; some messages may be missed.");
            }
            Ok(())
        }

        async fn get_nfc_credential(&mut self) -> Result<(), ()> {
            let mut stream = self.svc.lock().await.get_nfc_credential();
            if let Some(tx_weak) = self.bg_event_tx.as_ref().map(|t| t.clone().downgrade()) {
                let nfc_pin_tx = self.pin_tx.clone();
                let task = tokio::spawn(async move {
                    while let Some(state) = stream.next().await {
                        if let Some(tx) = tx_weak.upgrade() {
                            if tx
                                .send(BackgroundEvent::NfcStateChanged(state.clone().into()))
                                .await
                                .is_err()
                            {
                                tracing::debug!("Closing NFC background event forwarder");
                                break;
                            }
                            match state {
                                NfcState::NeedsPin { pin_tx, .. } => {
                                    let mut nfc_pin_tx = nfc_pin_tx.lock().await;
                                    let _ = nfc_pin_tx.insert(pin_tx);
                                }
                                NfcState::Completed | NfcState::Failed(_) => {
                                    break;
                                }
                                _ => {}
                            };
                        }
                    }
                })
                .abort_handle();
                if let Some(prev_task) = self.nfc_event_forwarder_task.lock().unwrap().replace(task)
                {
                    prev_task.abort();
                }
            } else {
                tracing::warn!(target: "DummyFlowServer", "Output stream not initialized before setting up NFC state stream; some messages may be missed.");
            }
            Ok(())
        }

        async fn subscribe(
            &mut self,
        ) -> Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()> {
            let (tx, mut rx) = mpsc::channel(32);
            self.bg_event_tx = Some(tx);
            Ok(Box::pin(async_stream::stream! {
                // TODO: we need to add a shutdown event that tells this stream
                // to shut down when completed, failed or cancelled
                while let Some(bg_event) = rx.recv().await {
                    yield bg_event
                }
                tracing::debug!("event stream ended");
            }))
        }

        async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
            if let Some(pin_tx) = self.pin_tx.lock().await.take() {
                pin_tx.send(pin).await.unwrap();
            }
            Ok(())
        }

        async fn select_credential(&self, _credential_id: String) -> Result<(), ()> {
            todo!();
        }

        async fn cancel_request(&self, _request_id: RequestId) -> Result<(), ()> {
            todo!();
        }
    }

    impl<
            H: HybridHandler + Debug + Send + Sync,
            U: UsbHandler + Debug + Send + Sync,
            N: NfcHandler + Debug + Send + Sync,
            UC: UiController + Debug + Send + Sync,
        > Drop for DummyFlowServer<H, U, N, UC>
    {
        fn drop(&mut self) {
            if let Some(task) = self.usb_event_forwarder_task.lock().unwrap().take() {
                task.abort();
            }

            if let Some(task) = self.nfc_event_forwarder_task.lock().unwrap().take() {
                task.abort();
            }

            if let Some(task) = self.hybrid_event_forwarder_task.lock().unwrap().take() {
                task.abort();
            }
        }
    }
}
