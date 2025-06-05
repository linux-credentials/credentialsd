use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures_lite::Stream;
use tokio::sync::{mpsc, oneshot};

use crate::dbus::{CredentialRequest, CredentialResponse};
use crate::view_model::Device;

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

    fn get_hybrid_credential(
        &self,
    ) -> impl Future<Output = Pin<Box<dyn Stream<Item = HybridState> + Send>>> + Send;
    fn get_usb_credential(
        &self,
    ) -> impl Future<Output = Pin<Box<dyn Stream<Item = UsbState> + Send>>> + Send;
}

pub trait CredentialManagementClient {
    fn init_request(
        &self,
        cred_request: CredentialRequest,
    ) -> impl Future<Output = Result<(), String>> + Send;
    fn complete_auth(&self) -> impl Future<Output = Result<CredentialResponse, String>> + Send;
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
}

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

    async fn get_hybrid_credential(&self) -> Pin<Box<dyn Stream<Item = HybridState> + Send>> {
        let response = self
            .send(ServiceRequest::GetHybridCredential)
            .await
            .unwrap();
        if let ServiceResponse::GetHybridCredential(stream) = response {
            stream
        } else {
            panic!("Unable to get hybrid credential");
        }
    }

    async fn get_usb_credential(&self) -> Pin<Box<dyn Stream<Item = UsbState> + Send>> {
        let response = self.send(ServiceRequest::GetUsbCredential).await.unwrap();
        if let ServiceResponse::GetUsbCredential(stream) = response {
            stream
        } else {
            panic!("Unable to get usb credential");
        }
    }
}

impl CredentialServiceClient for Arc<InProcessClient> {
    fn get_available_public_key_devices(&self) -> impl Future<Output = Result<Vec<Device>, ()>> {
        InProcessClient::get_available_public_key_devices(self)
    }

    fn get_hybrid_credential(
        &self,
    ) -> impl Future<Output = Pin<Box<dyn Stream<Item = HybridState> + Send>>> {
        InProcessClient::get_hybrid_credential(self)
    }

    fn get_usb_credential(
        &self,
    ) -> impl Future<Output = Pin<Box<dyn Stream<Item = UsbState> + Send>>> {
        InProcessClient::get_usb_credential(self)
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
        let client = InProcessClient { tx: client_tx };
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
