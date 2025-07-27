use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_std::sync::Mutex as AsyncMutex;
use futures_lite::{Stream, StreamExt};
use tokio::sync::{mpsc, oneshot};

use crate::model::{BackgroundEvent, CredentialRequest, CredentialResponse, Device};

use super::hybrid::{HybridHandler, HybridState};
use super::usb::{UsbHandler, UsbState};
use super::CredentialService;

#[allow(clippy::enum_variant_names)]
pub enum ServiceRequest {
    GetDevices,
    GetHybridCredential,
    GetUsbCredential,
}

enum ManagementRequest {
    InitRequest(Box<CredentialRequest>),
    CompleteAuth,
}

#[derive(Debug)]
enum ManagementResponse {
    InitRequest(Result<(), String>),
    CompleteAuth(Option<CredentialResponse>),
}

// Clippy complains that these variant names have the same prefix, but that's
// intentional for now.
#[allow(clippy::enum_variant_names)]
pub enum ServiceResponse {
    GetDevices(Vec<Device>),
    GetHybridCredential(Pin<Box<dyn Stream<Item = HybridState> + Send>>),
    GetUsbCredential(Pin<Box<dyn Stream<Item = UsbState> + Send>>),
}

impl Debug for ServiceResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetDevices(arg0) => f.debug_tuple("GetDevices").field(arg0).finish(),
            Self::GetHybridCredential(_) => f
                .debug_tuple("GetHybridCredential")
                .field(&String::from("<HybridStateStream>"))
                .finish(),
            Self::GetUsbCredential(_) => f
                .debug_tuple("GetUsbCredential")
                .field(&String::from("<HybridStateStream>"))
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

pub trait CredentialServiceClient {
    fn get_available_public_key_devices(
        &self,
    ) -> impl Future<Output = Result<Vec<Device>, ()>> + Send;

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

pub trait CredentialManagementClient {
    fn init_request(
        &self,
        cred_request: CredentialRequest,
    ) -> impl Future<Output = Result<(), String>> + Send;
    fn complete_auth(&self) -> impl Future<Output = Result<CredentialResponse, String>> + Send;

    fn get_available_public_key_devices(
        &self,
    ) -> impl Future<Output = Result<Vec<Device>, ()>> + Send;

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

pub struct InProcessManager {
    tx: mpsc::Sender<(
        InProcessServerRequest,
        oneshot::Sender<InProcessServerResponse>,
    )>,
}

impl InProcessManager {
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

impl CredentialManagementClient for InProcessManager {
    async fn init_request(&self, cred_request: CredentialRequest) -> Result<(), String> {
        let response = self
            .send(ManagementRequest::InitRequest(Box::new(cred_request)))
            .await
            .unwrap();
        if let ManagementResponse::InitRequest(result) = response {
            result
        } else {
            Err("No credentials in credential service".to_string())
        }
    }

    async fn complete_auth(&self) -> Result<CredentialResponse, String> {
        let response = self.send(ManagementRequest::CompleteAuth).await.unwrap();
        if let ManagementResponse::CompleteAuth(Some(cred_response)) = response {
            Ok(cred_response)
        } else {
            Err("No credentials in credential service".to_string())
        }
    }

    fn get_available_public_key_devices(
        &self,
    ) -> impl Future<Output = Result<Vec<Device>, ()>> + Send {
        todo!()
    }

    fn get_hybrid_credential(&mut self) -> impl Future<Output = Result<(), ()>> + Send {
        todo!()
    }

    fn get_usb_credential(&mut self) -> impl Future<Output = Result<(), ()>> + Send {
        todo!()
    }

    fn initiate_event_stream(
        &mut self,
    ) -> impl Future<
        Output = Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()>,
    > + Send {
        todo!()
    }

    fn enter_client_pin(&mut self, pin: String) -> impl Future<Output = Result<(), ()>> + Send {
        todo!()
    }

    fn select_credential(
        &self,
        credential_id: String,
    ) -> impl Future<Output = Result<(), ()>> + Send {
        todo!()
    }
}

pub struct InProcessClient {
    tx: mpsc::Sender<(
        InProcessServerRequest,
        oneshot::Sender<InProcessServerResponse>,
    )>,
    bg_event_tx: Option<mpsc::Sender<BackgroundEvent>>,
    usb_pin_tx: Arc<AsyncMutex<Option<tokio::sync::mpsc::Sender<String>>>>,
    usb_event_forwarder_task: Option<async_std::task::JoinHandle<()>>,
    hybrid_event_forwarder_task: Option<async_std::task::JoinHandle<()>>,
}

impl Drop for InProcessClient {
    fn drop(&mut self) {
        if let Some(task) = self.usb_event_forwarder_task.take() {
            async_std::task::block_on(task.cancel());
        }

        if let Some(task) = self.hybrid_event_forwarder_task.take() {
            async_std::task::block_on(task.cancel());
        }
    }
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
        let response = self
            .send(ServiceRequest::GetHybridCredential)
            .await
            .unwrap();
        if let ServiceResponse::GetHybridCredential(mut stream) = response {
            if let Some(tx_weak) = self.bg_event_tx.as_ref().map(|t| t.clone().downgrade()) {
                let task = async_std::task::spawn(async move {
                    while let Some(hybrid_state) = stream.next().await {
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
                });
                if let Some(prev_task) = self.hybrid_event_forwarder_task.replace(task) {
                    prev_task.cancel().await;
                }
            }
            Ok(())
        } else {
            panic!("Unable to get hybrid credential");
        }
    }

    async fn get_usb_credential(&mut self) -> Result<(), ()> {
        let response = self.send(ServiceRequest::GetUsbCredential).await.unwrap();
        if let ServiceResponse::GetUsbCredential(mut stream) = response {
            if let Some(tx_weak) = self.bg_event_tx.as_ref().map(|t| t.clone().downgrade()) {
                let usb_pin_tx = self.usb_pin_tx.clone();
                let task = async_std::task::spawn(async move {
                    while let Some(state) = stream.next().await {
                        if let Some(tx) = tx_weak.upgrade() {
                            if tx
                                .send(BackgroundEvent::UsbStateChanged((&state).into()))
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
                });
                if let Some(prev_task) = self.usb_event_forwarder_task.replace(task) {
                    prev_task.cancel().await;
                }
            }
            Ok(())
        } else {
            panic!("Unable to get usb credential");
        }
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

impl CredentialServiceClient for Arc<InProcessClient> {
    fn get_available_public_key_devices(&self) -> impl Future<Output = Result<Vec<Device>, ()>> {
        InProcessClient::get_available_public_key_devices(self)
    }

    async fn get_hybrid_credential(&mut self) -> Result<(), ()> {
        let client = Arc::get_mut(self).ok_or(())?;
        InProcessClient::get_hybrid_credential(client).await
    }

    async fn get_usb_credential(&mut self) -> Result<(), ()> {
        let client = Arc::get_mut(self).ok_or(())?;
        InProcessClient::get_usb_credential(client).await
    }

    async fn initiate_event_stream(
        &mut self,
    ) -> Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()> {
        let client = Arc::get_mut(self).ok_or(())?;
        InProcessClient::initiate_event_stream(client).await
    }

    async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
        let client = Arc::get_mut(self).ok_or(())?;
        InProcessClient::enter_client_pin(client, pin).await
    }

    fn select_credential(&self, credential_id: String) -> impl Future<Output = Result<(), ()>> {
        InProcessClient::select_credential(self, credential_id)
    }
}

#[derive(Debug)]
pub struct InProcessServer<H, U>
where
    H: HybridHandler + Debug,
    U: UsbHandler + Debug,
{
    svc: CredentialService<H, U>,
    rx: mpsc::Receiver<(
        InProcessServerRequest,
        oneshot::Sender<InProcessServerResponse>,
    )>,
}

impl<H, U> InProcessServer<H, U>
where
    H: HybridHandler + Debug,
    U: UsbHandler + Debug,
{
    pub fn new(svc: CredentialService<H, U>) -> (Self, InProcessManager, InProcessClient) {
        let (tx, rx) = mpsc::channel(256);

        let mgr_tx = tx.clone();
        let mgr = InProcessManager { tx: mgr_tx };
        let client_tx = tx.clone();
        let client = InProcessClient {
            tx: client_tx,
            bg_event_tx: None,
            usb_pin_tx: Arc::new(AsyncMutex::new(None)),
            usb_event_forwarder_task: None,
            hybrid_event_forwarder_task: None,
        };
        (Self { svc, rx }, mgr, client)
    }

    pub async fn run(&mut self) {
        while let Some((request, tx)) = self.rx.recv().await {
            let response = match request {
                InProcessServerRequest::Client(ServiceRequest::GetDevices) => {
                    let rsp = self.svc.get_available_public_key_devices().await.unwrap();
                    InProcessServerResponse::Client(ServiceResponse::GetDevices(rsp))
                }
                InProcessServerRequest::Client(ServiceRequest::GetHybridCredential) => {
                    let rsp = self.svc.get_hybrid_credential();
                    InProcessServerResponse::Client(ServiceResponse::GetHybridCredential(rsp))
                }
                InProcessServerRequest::Client(ServiceRequest::GetUsbCredential) => {
                    let rsp = self.svc.get_usb_credential();
                    InProcessServerResponse::Client(ServiceResponse::GetUsbCredential(rsp))
                }
                InProcessServerRequest::Management(ManagementRequest::InitRequest(request)) => {
                    let rsp = self.svc.init_request(&request);
                    InProcessServerResponse::Management(ManagementResponse::InitRequest(rsp))
                }
                InProcessServerRequest::Management(ManagementRequest::CompleteAuth) => {
                    let rsp = self.svc.complete_auth();
                    InProcessServerResponse::Management(ManagementResponse::CompleteAuth(rsp))
                }
            };
            tx.send(response).unwrap()
        }
    }
}
