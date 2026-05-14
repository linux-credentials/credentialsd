//! This module implements the service to allow the user to control the flow of
//! the credential request through the trusted UI.

use std::{
    fmt::Debug,
    io::{self, ErrorKind},
    mem::MaybeUninit,
    os::{fd::AsRawFd, raw::c_void},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use credentialsd_common::model::{
    Error as CredentialServiceError, Operation, PortalBackendOptions, RequestingApplication,
    UserInteractedEvent, WebAuthnError,
};
use credentialsd_common::server::{BackgroundEvent, WindowHandle};
use futures_lite::{Stream, StreamExt};
use libc::{MAP_SHARED, PROT_READ, PROT_WRITE};
use tokio::sync::mpsc::Receiver;
use tokio::sync::oneshot;
use tokio::sync::{mpsc::Sender, Mutex as AsyncMutex};
use tokio::task::AbortHandle;
use zbus::connection::Connection;
use zbus::zvariant::OwnedObjectPath;

use crate::credential_service::{nfc::NfcState, DeviceStateUpdate, ManageDevice};
use crate::dbus::ui_control::Ceremony;
use crate::dbus::UiControlServiceClient;
use crate::{
    credential_service::UsbState,
    dbus::ui_control::UiController,
    model::{CredentialRequest, CredentialResponse},
};
pub struct UiRequestContext {
    request: CredentialRequest,
    app: RequestingApplication,
    /// Client window handle
    window_handle: Option<WindowHandle>,
    activation_token: Option<String>,
    response_channel: oneshot::Sender<Result<CredentialResponse, CredentialServiceError>>,
}

pub async fn start_flow_control_service<M: ManageDevice + Debug + Send + Sync + 'static>(
    conn: Connection,
    mut listener: Receiver<UiRequestContext>,
    device_manager: M,
) -> zbus::Result<AbortHandle> {
    let svc = Arc::new(AsyncMutex::new(device_manager));
    let svc2 = svc.clone();

    let task = tokio::spawn(async move {
        while let Some(ui_request_ctx) = listener.recv().await {
            let svc = svc2.clone();
            let ui_control_client = UiControlServiceClient::new(conn.clone());
            let UiRequestContext {
                request,
                app,
                window_handle,
                activation_token,
                response_channel,
            } = ui_request_ctx;
            let response = handle(
                svc,
                ui_control_client,
                request,
                app,
                window_handle,
                activation_token,
            )
            .await;
            if let Err(_) = response_channel.send(response) {
                tracing::error!(
                    "Received response to credential request, but failed to forward it to gateway"
                );
            }
        }
    });
    Ok(task.abort_handle())
}

async fn handle<M: ManageDevice + Debug + Send + Sync + 'static, UC: UiController + Debug>(
    svc: Arc<AsyncMutex<M>>,
    ui_control_client: UC,
    msg: CredentialRequest,
    requesting_app: RequestingApplication,
    window_handle: Option<WindowHandle>,
    activation_token: Option<String>,
) -> Result<CredentialResponse, CredentialServiceError> {
    let (request_tx, request_rx) = oneshot::channel();
    let request_id = svc.lock().await.init_request(&msg, request_tx).await?;
    let operation = match &msg {
        CredentialRequest::CreatePublicKeyCredentialRequest(_) => Operation::PublicKeyCreate,
        CredentialRequest::GetPublicKeyCredentialRequest(_) => Operation::PublicKeyGet,
    };
    let rp_id = match &msg {
        CredentialRequest::CreatePublicKeyCredentialRequest(r) => r.relying_party.id.clone(),
        CredentialRequest::GetPublicKeyCredentialRequest(r) => r.relying_party_id.clone(),
    };

    // TODO: pass origin to this method so we can do this correctly.
    let origin = match &msg {
        CredentialRequest::CreatePublicKeyCredentialRequest(r) => r.origin.clone(),
        CredentialRequest::GetPublicKeyCredentialRequest(r) => {
            format!("https://{}", r.relying_party_id.clone())
        }
    };

    // TODO: pass top_origin to this method so we can do this correctly.
    let top_origin = match &msg {
        CredentialRequest::CreatePublicKeyCredentialRequest(r) => None,
        CredentialRequest::GetPublicKeyCredentialRequest(r) => None,
    };
    let initial_devices = svc
        .lock()
        .await
        .get_available_public_key_devices()
        .await
        .unwrap_or_default();

    let RequestingApplication {
        path_or_app_id,
        name: app_name,
        pid: app_pid,
    } = requesting_app;
    let app_name = Option::from(app_name).unwrap_or_else(|| "TODO: Require app name".to_string());
    let handle: OwnedObjectPath = format!(
        "/org/freedesktop/portal/desktop/request/CREDENTIALSD_{}",
        rand::random::<u32>()
    )
    .try_into()
    .expect("valid object path");
    let flow = match ui_control_client
        .initialize(
            handle,
            window_handle,
            origin,
            operation,
            request_id,
            initial_devices,
            path_or_app_id.clone(),
            app_name,
            app_pid,
            // TODO: Make path and app ID separate.
            path_or_app_id,
            PortalBackendOptions {
                activation_token: activation_token.into(),
                top_origin: top_origin.into(),
                rp_id: Some(rp_id).into(),
            },
        )
        .await
    {
        Ok(rx) => rx,
        Err(err) => {
            tracing::error!("Failed to launch UI for credentials: {err}. Cancelling request.");
            return Err(CredentialServiceError::Internal(err.to_string()));
        }
    };
    tokio::spawn(async move {
        let client_pin_tx: Arc<Mutex<Option<Sender<String>>>> = Arc::new(Mutex::new(None));
        let cred_selector_tx = Arc::new(Mutex::new(None));
        while let Some(ui_request) = flow.receive_ui_event().await {
            match ui_request {
                UserInteractedEvent::DiscoveryRequested => {
                    let client_pin_tx = client_pin_tx.clone();
                    let cred_selector_tx = cred_selector_tx.clone();
                    let stream =
                        svc.lock()
                            .await
                            .start_discovery()
                            .await
                            .map(move |device_update| {
                                match &device_update {
                                    DeviceStateUpdate::Nfc(NfcState::NeedsPin {
                                        pin_tx, ..
                                    }) => {
                                        *client_pin_tx.lock().unwrap() = Some(pin_tx.clone());
                                    }

                                    DeviceStateUpdate::Usb(UsbState::NeedsPin {
                                        pin_tx, ..
                                    }) => {
                                        *client_pin_tx.lock().unwrap() = Some(pin_tx.clone());
                                    }
                                    DeviceStateUpdate::Usb(UsbState::SelectingCredential {
                                        cred_tx,
                                        ..
                                    }) => {
                                        *cred_selector_tx.lock().unwrap() = Some(cred_tx.clone());
                                    }
                                    _ => {}
                                }
                                device_update.into()
                            });
                    let flow = flow.clone();
                    forward_background_event_stream(flow, stream);
                }
                UserInteractedEvent::ClientPinEntered(pin_fd) => {
                    let pin_fd = std::os::fd::OwnedFd::from(pin_fd);
                    let pin = match read_secret(pin_fd.into()) {
                        Ok(pin) => pin,
                        // TODO: need to send an error to the UI, cancel the request and terminate the loop.
                        Err(err) => {
                            tracing::error!(%err, "Failed to read client PIN. Stopping event loop. TODO: cancel the request");
                            break;
                        }
                    };
                    let tx = { client_pin_tx.lock().unwrap().take() };
                    if let Some(tx) = tx {
                        if tx.send(pin).await.is_err() {
                            tracing::error!("Failed to send client PIN to device");
                        }
                    } else {
                        tracing::error!(
                            "Invalid state: received a client PIN with no pending request."
                        );
                    }
                }
                UserInteractedEvent::CredentialSelected(id) => {
                    let tx = { cred_selector_tx.lock().unwrap().take() };
                    if let Some(tx) = tx {
                        if tx.send(id).await.is_err() {
                            tracing::error!("Failed to send credential selection to device");
                        }
                    } else {
                        tracing::error!(
                            "Invalid state: received a credential selection ID with no pending request."
                        );
                    }
                }
                UserInteractedEvent::RequestCancelled => {
                    tracing::debug!(%request_id, "Cancelling request");
                    svc.lock().await.cancel_request(request_id).await;
                }
            }
        }
    });
    tracing::debug!("Finished setting up request {request_id}");
    let cred_response = request_rx
        .await
        .expect("Credential service not to drop request channel before responding.");
    let f = cred_response.map_err(|err| err.into());
    f
}

fn forward_background_event_stream(
    flow: Ceremony,
    mut stream: impl Stream<Item = BackgroundEvent> + Send + Unpin + 'static,
) {
    tokio::spawn(async move {
        while let Some(event) = stream.next().await {
            let send_result = flow.send_state_update(event).await;
            if send_result.is_err() {
                tracing::error!("Failed to send state update event to backend. Stopping flow");
                break;
            }
        }
    });
}

/// Coordinates between user and various devices connected to the machine to
/// fulfill credential requests.
#[async_trait]
pub trait CredentialRequestController {
    async fn request_credential(
        &self,
        requesting_app: RequestingApplication,
        request: CredentialRequest,
        window_handle: Option<WindowHandle>,
        activation_token: Option<String>,
    ) -> Result<CredentialResponse, WebAuthnError>;
}

pub struct CredentialRequestControllerClient {
    pub initiator: Sender<UiRequestContext>,
}

#[async_trait]
impl CredentialRequestController for CredentialRequestControllerClient {
    async fn request_credential(
        &self,
        app: RequestingApplication,
        request: CredentialRequest,
        window_handle: Option<WindowHandle>,
        activation_token: Option<String>,
    ) -> Result<CredentialResponse, WebAuthnError> {
        let (tx, rx) = oneshot::channel();
        self.initiator
            .send(UiRequestContext {
                request,
                app,
                window_handle,
                activation_token,
                response_channel: tx,
            })
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

fn read_secret(pin_fd: std::os::fd::OwnedFd) -> Result<String, std::io::Error> {
    // Get pin length
    let len = {
        let mut stat_buf = MaybeUninit::<libc::stat>::uninit();
        let res = unsafe { libc::fstat(pin_fd.as_raw_fd(), stat_buf.as_mut_ptr()) };
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        let stat_buf = unsafe { stat_buf.assume_init() };
        usize::try_from(stat_buf.st_size)
            .map_err(|_| io::Error::new(ErrorKind::FileTooLarge, "pin is too large"))?
    };

    // map the memory from the file descriptor
    let ptr = unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            pin_fd.as_raw_fd(),
            0,
        );
        if ptr == usize::MAX as *mut c_void {
            return Err(std::io::Error::last_os_error());
        }
        ptr as *const u8
    };

    // Copy the bytes.
    let buf = unsafe {
        // let len = ptr.read() as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(len);
        ptr.copy_to_nonoverlapping(buf.as_mut_ptr().cast(), len);
        buf.set_len(len);
        buf
    };

    // Clean up mapping
    unsafe {
        if libc::munmap(ptr as *mut c_void, 4096) == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    drop(pin_fd);

    String::from_utf8(buf).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid UTF-8 data found in buffer",
        )
    })
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
        model::{Device, RequestId},
        server::BackgroundEvent,
    };
    use futures_lite::{Stream, StreamExt};
    use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

    use crate::credential_service::{hybrid::HybridState, nfc::NfcState, ManageDevice, UsbState};

    #[allow(clippy::enum_variant_names)]
    #[derive(Debug)]
    pub enum DummyFlowRequest {
        EnterClientPin(String),
        GetDevices,
        GetCredential,
        InitStream,
    }

    // Clippy complains that these variant names have the same prefix, but that's
    // intentional for now.
    #[allow(clippy::enum_variant_names)]
    pub enum DummyFlowResponse {
        EnterClientPin(Result<(), ()>),
        GetDevices(Vec<Device>),
        GetCredential,
        InitStream(Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()>),
    }

    impl Debug for DummyFlowResponse {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::EnterClientPin(arg0) => f.debug_tuple("EnterClientPin").field(arg0).finish(),
                Self::GetDevices(arg0) => f.debug_tuple("GetDevices").field(arg0).finish(),
                Self::GetCredential => f.debug_tuple("GetCredential").finish(),
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

        async fn start_discovery(&mut self) -> Result<(), ()> {
            if let Ok(DummyFlowResponse::GetCredential) =
                self.send(DummyFlowRequest::GetCredential).await
            {
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
    pub struct DummyFlowServer<M>
    where
        M: ManageDevice,
    {
        rx: mpsc::Receiver<(DummyFlowRequest, oneshot::Sender<DummyFlowResponse>)>,
        svc: Arc<AsyncMutex<M>>,
        bg_event_tx: Option<mpsc::Sender<BackgroundEvent>>,
        pin_tx: Arc<AsyncMutex<Option<tokio::sync::mpsc::Sender<String>>>>,
        usb_event_forwarder_task: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
        nfc_event_forwarder_task: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
        hybrid_event_forwarder_task: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    }

    impl<M: ManageDevice> DummyFlowServer<M> {
        pub fn new(svc: Arc<AsyncMutex<M>>) -> (Self, DummyFlowClient) {
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
                    DummyFlowRequest::GetCredential => {
                        self.start_discovery().await.unwrap();
                        DummyFlowResponse::GetCredential
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

        async fn start_discovery(&mut self) -> Result<(), ()> {
            unimplemented!();
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

    impl<M: ManageDevice> Drop for DummyFlowServer<M> {
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
