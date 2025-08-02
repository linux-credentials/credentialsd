use std::error::Error;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use creds_lib::client::CredentialServiceClient;
use creds_lib::server::ViewRequest;
use futures_lite::{Stream, StreamExt};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

use creds_lib::model::{BackgroundEvent, CredentialRequest, CredentialResponse, Device};

use super::hybrid::{HybridHandler, HybridState};
use super::usb::{UsbHandler, UsbState};
use super::CredentialService;

enum ManagementRequest {
    InitRequest(Box<CredentialRequest>),
    CompleteAuth,
    GetDevices,
    GetHybridCredential,
    GetUsbCredential,
}

enum ManagementResponse {
    EnterClientPin,
    InitRequest(Receiver<Result<CredentialResponse, creds_lib::model::Error>>),
    CompleteAuth(Result<CredentialResponse, String>),
    GetDevices(Vec<Device>),
    GetHybridCredential,
    GetUsbCredential,
    InitStream(Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()>),
}

impl Debug for ManagementResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitRequest(arg0) => f.debug_tuple("InitRequest").field(arg0).finish(),
            Self::CompleteAuth(arg0) => f.debug_tuple("CompleteAuth").field(arg0).finish(),
            Self::EnterClientPin => f.debug_tuple("EnterClientPin").finish(),
            Self::GetDevices(arg0) => f.debug_tuple("GetDevices").field(arg0).finish(),
            Self::GetHybridCredential => f.debug_tuple("GetHybridCredential").finish(),
            Self::GetUsbCredential => f.debug_tuple("GetUsbCredential").finish(),
            Self::InitStream(_) => f
                .debug_tuple("InitStream")
                .field(&String::from("<BackgroundEventStream>"))
                .finish(),
        }
    }
}

#[allow(clippy::enum_variant_names)]
pub enum ServiceRequest {
    EnterClientPin(String),
    GetDevices,
    GetHybridCredential,
    GetUsbCredential,
    InitStream,
}

// Clippy complains that these variant names have the same prefix, but that's
// intentional for now.
#[allow(clippy::enum_variant_names)]
pub enum ServiceResponse {
    EnterClientPin,
    GetDevices(Vec<Device>),
    GetHybridCredential,
    GetUsbCredential,
    InitStream(Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()>),
}

impl Debug for ServiceResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnterClientPin => f.debug_tuple("EnterClientPin").finish(),
            Self::GetDevices(arg0) => f.debug_tuple("GetDevices").field(arg0).finish(),
            Self::GetHybridCredential => f.debug_tuple("GetHybridCredential").finish(),
            Self::GetUsbCredential => f.debug_tuple("GetUsbCredential").finish(),
            Self::InitStream(_) => f
                .debug_tuple("InitStream")
                .field(&String::from("<BackgroundEventStream>"))
                .finish(),
        }
    }
}

enum InProcessServerRequest {
    Client(ServiceRequest),
    Management(ManagementRequest),
}

#[derive(Debug)]
enum InProcessServerResponse {
    Client(ServiceResponse),
    Management(ManagementResponse),
}

/// Used for communication from privileged broker to credential service
pub trait CredentialManagementClient {
    fn init_request(
        &self,
        cred_request: CredentialRequest,
    ) -> impl Future<Output = Receiver<Result<CredentialResponse, creds_lib::model::Error>>> + Send;
    fn complete_auth(&self) -> impl Future<Output = Result<CredentialResponse, String>> + Send;

    fn get_available_public_key_devices(
        &self,
    ) -> impl Future<Output = Result<Vec<Device>, Box<dyn Error>>> + Send;

    fn get_hybrid_credential(&mut self) -> impl Future<Output = Result<(), ()>> + Send;
    fn get_usb_credential(&mut self) -> impl Future<Output = Result<(), ()>> + Send;
    fn initiate_event_stream(
        &mut self,
    ) -> impl Future<
        Output = Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()>,
    > + Send;
    fn enter_client_pin(&mut self, pin: String) -> impl Future<Output = Result<(), ()>> + Send;
    fn select_credential(
        &self,
        credential_id: String,
    ) -> impl Future<Output = Result<(), ()>> + Send;
}

#[derive(Debug)]
pub struct InProcessManager<H, U, UC>
where
    H: HybridHandler + Debug + Send + Sync,
    U: UsbHandler + Debug + Send + Sync,
    UC: UiController + Debug + Send + Sync,
{
    tx: mpsc::Sender<(
        InProcessServerRequest,
        oneshot::Sender<InProcessServerResponse>,
    )>,
    svc: Arc<AsyncMutex<CredentialService<H, U, UC>>>,
    bg_event_tx: Option<mpsc::Sender<BackgroundEvent>>,
    usb_pin_tx: Arc<AsyncMutex<Option<tokio::sync::mpsc::Sender<String>>>>,
    usb_event_forwarder_task: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    hybrid_event_forwarder_task: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
}

impl<
        H: HybridHandler + Debug + Send + Sync,
        U: UsbHandler + Debug + Send + Sync,
        UC: UiController + Debug + Send + Sync,
    > Clone for InProcessManager<H, U, UC>
{
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            svc: self.svc.clone(),
            bg_event_tx: self.bg_event_tx.clone(),
            usb_pin_tx: self.usb_pin_tx.clone(),
            usb_event_forwarder_task: self.usb_event_forwarder_task.clone(),
            hybrid_event_forwarder_task: self.hybrid_event_forwarder_task.clone(),
        }
    }
}

impl<
        H: HybridHandler + Debug + Send + Sync,
        U: UsbHandler + Debug + Send + Sync,
        UC: UiController + Debug + Send + Sync,
    > InProcessManager<H, U, UC>
{
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
}

impl<
        H: HybridHandler + Debug + Send + Sync,
        U: UsbHandler + Debug + Send + Sync,
        UC: UiController + Debug + Send + Sync,
    > CredentialManagementClient for InProcessManager<H, U, UC>
{
    async fn init_request(
        &self,
        cred_request: CredentialRequest,
    ) -> Receiver<Result<CredentialResponse, creds_lib::model::Error>> {
        self.svc.lock().await.init_request(&cred_request).await
    }

    async fn complete_auth(&self) -> Result<CredentialResponse, String> {
        self.svc
            .lock()
            .await
            .complete_auth()
            .ok_or("No credentials in credential service".to_string())
    }

    async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, Box<dyn Error>> {
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
        if let Some(tx_weak) = self.bg_event_tx.as_ref().map(|t| t.clone().downgrade()) {
            let task = tokio::spawn(async move {
                while let Some(hybrid_state) = stream.next().await {
                    if let Some(tx) = tx_weak.upgrade() {
                        match hybrid_state {
                            HybridState::Completed | HybridState::Failed => {
                                tx.send(BackgroundEvent::HybridQrStateChanged(hybrid_state.into()))
                                    .await
                                    .unwrap();
                                break;
                            }
                            _ => tx
                                .send(BackgroundEvent::HybridQrStateChanged(hybrid_state.into()))
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
        }
        Ok(())
    }

    async fn get_usb_credential(&mut self) -> Result<(), ()> {
        let mut stream = self.svc.lock().await.get_usb_credential();
        if let Some(tx_weak) = self.bg_event_tx.as_ref().map(|t| t.clone().downgrade()) {
            let usb_pin_tx = self.usb_pin_tx.clone();
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
            if let Some(prev_task) = self.usb_event_forwarder_task.lock().unwrap().replace(task) {
                prev_task.abort();
            }
        }
        Ok(())
    }

    async fn initiate_event_stream(
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
        if let Some(pin_tx) = self.usb_pin_tx.lock().await.take() {
            pin_tx.send(pin).await.unwrap();
        }
        Ok(())
    }

    async fn select_credential(&self, credential_id: String) -> Result<(), ()> {
        todo!();
    }
}

impl<
        H: HybridHandler + Debug + Send + Sync,
        U: UsbHandler + Debug + Send + Sync,
        UC: UiController + Debug + Send + Sync,
    > Drop for InProcessManager<H, U, UC>
{
    fn drop(&mut self) {
        if let Some(task) = self.usb_event_forwarder_task.lock().unwrap().take() {
            task.abort();
        }

        if let Some(task) = self.hybrid_event_forwarder_task.lock().unwrap().take() {
            task.abort();
        }
    }
}

/// Represents a client for the UI to call methods on the credential service.
pub struct InProcessClient {
    tx: mpsc::Sender<(
        InProcessServerRequest,
        oneshot::Sender<InProcessServerResponse>,
    )>,
}

impl InProcessClient {
    async fn send(&self, request: ServiceRequest) -> Result<ServiceResponse, ()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((InProcessServerRequest::Client(request), response_tx))
            .await
            .unwrap();
        match response_rx.await {
            Ok(InProcessServerResponse::Client(response)) => Ok(response),
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
}

impl CredentialServiceClient for InProcessClient {
    async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        let response = self.send(ServiceRequest::GetDevices).await.unwrap();
        if let ServiceResponse::GetDevices(devices) = response {
            Ok(devices)
        } else {
            Err(())
        }
    }

    async fn get_hybrid_credential(&mut self) -> Result<(), ()> {
        if let Ok(ServiceResponse::GetHybridCredential) =
            self.send(ServiceRequest::GetHybridCredential).await
        {
            Ok(())
        } else {
            Err(())
        }
    }

    async fn get_usb_credential(&mut self) -> Result<(), ()> {
        let response = self.send(ServiceRequest::GetUsbCredential).await.unwrap();
        if let ServiceResponse::GetUsbCredential = response {
            Ok(())
        } else {
            Err(())
        }
    }

    async fn initiate_event_stream(
        &mut self,
    ) -> Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()> {
        if let Ok(ServiceResponse::InitStream(Ok(stream))) =
            self.send(ServiceRequest::InitStream).await
        {
            Ok(stream)
        } else {
            Err(())
        }
    }

    async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
        if let Ok(ServiceResponse::EnterClientPin) =
            self.send(ServiceRequest::EnterClientPin(pin)).await
        {
            Ok(())
        } else {
            Err(())
        }
    }

    async fn select_credential(&self, credential_id: String) -> Result<(), ()> {
        todo!();
    }
}

struct ArcInProcessClient(Arc<InProcessClient>);
impl CredentialServiceClient for ArcInProcessClient {
    fn get_available_public_key_devices(&self) -> impl Future<Output = Result<Vec<Device>, ()>> {
        InProcessClient::get_available_public_key_devices(&self.0)
    }

    async fn get_hybrid_credential(&mut self) -> Result<(), ()> {
        let client = Arc::get_mut(&mut self.0).ok_or(())?;
        InProcessClient::get_hybrid_credential(client).await
    }

    async fn get_usb_credential(&mut self) -> Result<(), ()> {
        let client = Arc::get_mut(&mut self.0).ok_or(())?;
        InProcessClient::get_usb_credential(client).await
    }

    async fn initiate_event_stream(
        &mut self,
    ) -> Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()> {
        let client = Arc::get_mut(&mut self.0).ok_or(())?;
        InProcessClient::initiate_event_stream(client).await
    }

    async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
        let client = Arc::get_mut(&mut self.0).ok_or(())?;
        InProcessClient::enter_client_pin(client, pin).await
    }

    fn select_credential(&self, credential_id: String) -> impl Future<Output = Result<(), ()>> {
        InProcessClient::select_credential(&self.0, credential_id)
    }
}

#[derive(Debug)]
pub struct InProcessServer<H, U, UC>
where
    H: HybridHandler + Debug + Send + Sync,
    U: UsbHandler + Debug + Send + Sync,
    UC: UiController + Debug + Send + Sync,
{
    rx: mpsc::Receiver<(
        InProcessServerRequest,
        oneshot::Sender<InProcessServerResponse>,
    )>,
    mgr: InProcessManager<H, U, UC>,
    responder_rx: Option<Receiver<Result<CredentialResponse, creds_lib::model::Error>>>,
}

impl<H, U, UC> InProcessServer<H, U, UC>
where
    H: HybridHandler + Debug + Send + Sync,
    U: UsbHandler + Debug + Send + Sync,
    UC: UiController + Debug + Send + Sync,
{
    pub fn new(
        svc: CredentialService<H, U, UC>,
    ) -> (Self, InProcessManager<H, U, UC>, InProcessClient) {
        let (tx, rx) = mpsc::channel(256);

        let svc_arc = Arc::new(AsyncMutex::new(svc));
        let mgr_tx = tx.clone();
        let mgr = InProcessManager {
            tx: mgr_tx.clone(),
            svc: svc_arc,
            bg_event_tx: None,
            usb_pin_tx: Arc::new(AsyncMutex::new(None)),
            usb_event_forwarder_task: Arc::new(Mutex::new(None)),
            hybrid_event_forwarder_task: Arc::new(Mutex::new(None)),
        };
        let client_tx = tx.clone();
        let client = InProcessClient { tx: client_tx };
        let server = Self {
            rx,
            mgr: mgr.clone(),
            responder_rx: None,
        };
        (server, mgr, client)
    }

    pub async fn run(&mut self) {
        while let Some((request, tx)) = self.rx.recv().await {
            let response = match request {
                InProcessServerRequest::Client(ServiceRequest::EnterClientPin(pin)) => {
                    let rsp = self.mgr.enter_client_pin(pin).await;
                    InProcessServerResponse::Client(ServiceResponse::EnterClientPin)
                }
                InProcessServerRequest::Client(ServiceRequest::GetDevices) => {
                    let rsp = self.mgr.get_available_public_key_devices().await.unwrap();
                    InProcessServerResponse::Client(ServiceResponse::GetDevices(rsp))
                }
                InProcessServerRequest::Client(ServiceRequest::GetHybridCredential) => {
                    let rsp = self.mgr.get_hybrid_credential().await;
                    InProcessServerResponse::Client(ServiceResponse::GetHybridCredential)
                }

                InProcessServerRequest::Client(ServiceRequest::GetUsbCredential) => {
                    let rsp = self.mgr.get_usb_credential().await;
                    InProcessServerResponse::Client(ServiceResponse::GetUsbCredential)
                }
                InProcessServerRequest::Client(ServiceRequest::InitStream) => {
                    let rsp = self.mgr.initiate_event_stream().await;
                    InProcessServerResponse::Client(ServiceResponse::InitStream(rsp))
                }
                InProcessServerRequest::Management(ManagementRequest::InitRequest(request)) => {
                    let rsp = self.mgr.init_request(*request).await;
                    InProcessServerResponse::Management(ManagementResponse::InitRequest(rsp))
                }
                InProcessServerRequest::Management(ManagementRequest::CompleteAuth) => {
                    let rsp = self.mgr.complete_auth().await;
                    InProcessServerResponse::Management(ManagementResponse::CompleteAuth(rsp))
                }
                InProcessServerRequest::Management(ManagementRequest::GetDevices) => {
                    let rsp = self.mgr.get_available_public_key_devices().await.unwrap();
                    InProcessServerResponse::Management(ManagementResponse::GetDevices(rsp))
                }
                InProcessServerRequest::Management(ManagementRequest::GetHybridCredential) => {
                    let rsp = self.mgr.get_hybrid_credential().await;
                    InProcessServerResponse::Management(ManagementResponse::GetHybridCredential)
                }
                InProcessServerRequest::Management(ManagementRequest::GetUsbCredential) => {
                    let rsp = self.mgr.get_usb_credential().await;
                    InProcessServerResponse::Client(ServiceResponse::GetUsbCredential)
                }
            };
            tx.send(response).unwrap()
        }
    }
}

/// Used by the credential service to control the UI.
pub trait UiController {
    fn launch_ui(
        &self,
        request: ViewRequest,
    ) -> impl Future<Output = std::result::Result<(), Box<dyn Error>>> + Send;
}
