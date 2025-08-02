//! This module hosts the D-Bus endpoints needed for this service.
//!
//! The D-Bus endpoints are structured to allow sandboxing with small component processes connected with a central broker.
//! # Broker:
//! The broker's main responsibility is to enforce permissions between the various components.
//! To do that, the broker has a bunch of seemingly redundant methods that forwards to the actual
//! implementations.
//!
//! The internal components should sandboxed only to have access to resources needed to fulfill the request.
//!
//! ## Client -> pub service -> broker -> Cred Service:
//! These methods are called by the pub service on behalf of a client requesting credentials.
//! The pub service must pass appropriate context for the broker to determine the client's permissions.
//! - get_cred(options)
//! - create_cred(options)
//! - get_client_capabilities()
//!
//! ## UI -> broker -> Cred service:
//! These methods are called by the trusted UI to interact with the credential service.
//! - initialize_event_stream()
//! - get_hybrid_credential()
//! - get_usb_credential()
//! - get_available_devices() # a device is a discrete authenticator or a group of potential authenticators accessible via a particular transport, or a credential?
//! - send_pin()
//! - select_credential()
//! - cancel_request()
//!
//! ## Cred Service -> broker -> UI:
//! - launch UI
//! - send_state_changed()

mod model;

use std::pin::Pin;
use std::{collections::VecDeque, error::Error, fmt::Debug, sync::Arc};

use creds_lib::model::MakeCredentialRequest;
use creds_lib::server::{CreateCredentialRequest, CreatePublicKeyCredentialRequest, ViewRequest};
use futures_lite::{Stream, StreamExt};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::AbortHandle;
use zbus::object_server::{InterfaceRef, SignalEmitter};
use zbus::{
    connection::{self, Connection},
    fdo, interface,
};
use zbus::{proxy, ObjectServer};

use creds_lib::{
    client::CredentialServiceClient,
    model::{
        CredentialRequest, CredentialResponse, CredentialType, GetClientCapabilitiesResponse,
        Operation,
    },
    server::{
        BackgroundEvent, CreateCredentialResponse, CreatePublicKeyCredentialResponse, Device,
        GetCredentialRequest, GetCredentialResponse, GetPublicKeyCredentialResponse,
    },
};

use self::model::{
    create_credential_request_try_into_ctap2, create_credential_response_try_from_ctap2,
    get_credential_request_try_into_ctap2, get_credential_response_try_from_ctap2,
};
use crate::credential_service::hybrid::{HybridHandler, HybridState};
use crate::credential_service::usb::UsbHandler;
use crate::credential_service::{
    CredentialManagementClient, CredentialService, UiController, UsbState,
};

pub(crate) async fn start_service<C: CredentialManagementClient + Send + Sync + 'static>(
    service_name: &str,
    path: &str,
    manager_client: C,
) -> zbus::Result<Connection> {
    let lock = Arc::new(AsyncMutex::new(()));
    connection::Builder::session()?
        .name(service_name)?
        .serve_at(
            path,
            CredentialManager {
                app_lock: lock,
                manager_client,
            },
        )?
        .build()
        .await
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

struct CredentialManager<C: CredentialManagementClient> {
    // app_lock: Arc<AsyncMutex<Sender<ViewRequest>>>,
    app_lock: Arc<AsyncMutex<()>>,
    manager_client: C,
}

/// These are public methods that can be called by arbitrary clients to begin a credential flow.
#[interface(name = "xyz.iinuwa.credentials.Credentials1")]
impl<C: CredentialManagementClient + Send + Sync + 'static> CredentialManager<C> {
    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
    ) -> fdo::Result<CreateCredentialResponse> {
        if let Ok(tx) = self.app_lock.try_lock() {
            if request.origin.is_none() {
                todo!("Implicit caller-origin binding not yet implemented.")
            };
            let is_same_origin = request.is_same_origin.unwrap_or(false);
            let response = match (request.r#type.as_ref(), &request.public_key) {
                ("publicKey", Some(_)) => {
                    if !is_same_origin {
                        return Err(fdo::Error::AccessDenied(String::from(
                            "Cross-origin public-key credentials are not allowed.",
                        )));
                    }
                    let (make_cred_request, client_data_json) =
                        create_credential_request_try_into_ctap2(&request).map_err(|e| {
                            fdo::Error::Failed(format!(
                                "Could not parse passkey creation request: {e:?}"
                            ))
                        })?;
                    let cred_request =
                        CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request);

                    let response =
                        execute_flow(/* &tx, */ &self.manager_client, &cred_request).await?;

                    if let CredentialResponse::CreatePublicKeyCredentialResponse(cred_response) =
                        response
                    {
                        let public_key_response = create_credential_response_try_from_ctap2(
                            &cred_response,
                            client_data_json,
                        )?;
                        Ok(public_key_response.into())
                    } else {
                        Err(fdo::Error::Failed("Failed to create passkey".to_string()))
                    }
                }
                _ => Err(fdo::Error::Failed(
                    "Unknown credential request type".to_string(),
                )),
            };
            response
        } else {
            tracing::info!("Window already open");
            Err(fdo::Error::ObjectPathInUse(
                "WebAuthn session already open.".into(),
            ))
        }
    }

    async fn get_credential(
        &self,
        request: GetCredentialRequest,
    ) -> fdo::Result<GetCredentialResponse> {
        if let Ok(tx) = self.app_lock.try_lock() {
            if request.origin.is_none() {
                todo!("Implicit caller-origin binding is not yet implemented.");
            }
            let is_same_origin = request.is_same_origin.unwrap_or(false);
            let response = match (request.r#type.as_ref(), &request.public_key) {
                ("publicKey", Some(_)) => {
                    if !is_same_origin {
                        return Err(fdo::Error::AccessDenied(String::from(
                            "Cross-origin public-key credentials are not allowed.",
                        )));
                    }
                    // Setup request

                    // TODO: assert that RP ID is bound to origin:
                    // - if RP ID is not set, set the RP ID to the origin's effective domain
                    // - if RP ID is set, assert that it matches origin's effective domain
                    // - if RP ID is set, but origin's effective domain doesn't match
                    //    - query for related origins, if supported
                    //    - fail if not supported, or if RP ID doesn't match any related origins.
                    let (get_cred_request, client_data_json) =
                        get_credential_request_try_into_ctap2(&request).map_err(|_| {
                            fdo::Error::Failed(
                                "Could not parse passkey assertion request.".to_owned(),
                            )
                        })?;
                    let cred_request =
                        CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request);

                    let response =
                        execute_flow(/* &tx, */ &self.manager_client, &cred_request).await?;

                    match response {
                        CredentialResponse::GetPublicKeyCredentialResponse(cred_response) => {
                            let public_key_response = get_credential_response_try_from_ctap2(
                                &cred_response,
                                client_data_json,
                            )?;
                            Ok(public_key_response.into())
                        }
                        _ => Err(fdo::Error::Failed(
                            "Invalid credential response received from authenticator".to_string(),
                        )),
                    }
                }
                _ => Err(fdo::Error::Failed(
                    "Unknown credential request type".to_string(),
                )),
            };
            response
        } else {
            tracing::info!("Window already open");
            Err(fdo::Error::ObjectPathInUse(
                "WebAuthn session already open.".into(),
            ))
        }
    }

    async fn get_client_capabilities(&self) -> fdo::Result<GetClientCapabilitiesResponse> {
        Ok(GetClientCapabilitiesResponse {
            conditional_create: false,
            conditional_get: false,
            hybrid_transport: true,
            passkey_platform_authenticator: false,
            user_verifying_platform_authenticator: false,
            related_origins: false,
            signal_all_accepted_credentials: false,
            signal_current_user_details: false,
            signal_unknown_credential: false,
        })
    }
}

pub async fn start_internal_service<
    H: HybridHandler + Debug + Send + Sync + 'static,
    U: UsbHandler + Debug + Send + Sync + 'static,
    UC: UiController + Debug + Send + Sync + 'static,
>(
    service_name: &str,
    path: &str,
    credential_service: CredentialService<H, U, UC>,
) -> zbus::Result<Connection> {
    connection::Builder::session()?
        .name(service_name)?
        .serve_at(
            path,
            InternalService {
                signal_state: Arc::new(AsyncMutex::new(SignalState::Idle)),
                svc: Arc::new(AsyncMutex::new(credential_service)),
                usb_pin_tx: Arc::new(AsyncMutex::new(None)),
                usb_event_forwarder_task: Arc::new(AsyncMutex::new(None)),
                hybrid_event_forwarder_task: Arc::new(AsyncMutex::new(None)),
            },
        )?
        .build()
        .await
}

struct CredentialRequestController<H: HybridHandler, U: UsbHandler, UC: UiController> {
    svc: Arc<AsyncMutex<CredentialService<H, U, UC>>>,
}

#[interface(name = "xyz.iinuwa.credentials.impl.Credentials")]
impl<H, U, UC> CredentialRequestController<H, U, UC>
where
    H: HybridHandler + Debug + Send + Sync + 'static,
    U: UsbHandler + Debug + Send + Sync + 'static,
    UC: UiController + Debug + Send + Sync + 'static,
{
    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
    ) -> fdo::Result<CreateCredentialResponse> {
        match create_credential_request_try_into_ctap2(&request) {
            Ok((make_request, client_data_json)) => {
                let mut rx = {
                    let rx: Receiver<Result<CredentialResponse, creds_lib::model::Error>> = self
                        .svc
                        .lock()
                        .await
                        .init_request(&CredentialRequest::CreatePublicKeyCredentialRequest(
                            make_request,
                        ))
                        .await;
                    rx
                };
                let msg = rx.recv().await.ok_or_else(|| {
                    tracing::error!("Credential service shutdown response channel prematurely");
                    fdo::Error::Failed("Credential service shutdown".to_string())
                })?;
                match msg {
                    Ok(CredentialResponse::CreatePublicKeyCredentialResponse(cred_response)) => {
                        let public_key_response = create_credential_response_try_from_ctap2(
                            &cred_response,
                            client_data_json,
                        )?;
                        Ok(public_key_response.into())
                    }
                    // We should be returning the correct kind of response, so this shouldn't happen.
                    Ok(_) => Err(fdo::Error::Failed("Internal error occurred".to_string())),
                    Err(_) => Err(fdo::Error::Failed(
                        "Failed to create credential".to_string(),
                    )),
                }
            }
            Err(_) => Err(fdo::Error::InvalidArgs(
                "Unable to parse create credential request".to_string(),
            )),
        }
    }

    async fn get_credential(
        &self,
        request: GetCredentialRequest,
    ) -> fdo::Result<GetCredentialResponse> {
        match get_credential_request_try_into_ctap2(&request) {
            Ok((get_request, client_data_json)) => {
                let mut rx = {
                    let rx: Receiver<Result<CredentialResponse, creds_lib::model::Error>> = self
                        .svc
                        .lock()
                        .await
                        .init_request(&CredentialRequest::GetPublicKeyCredentialRequest(
                            get_request,
                        ))
                        .await;
                    rx
                };
                let msg = rx.recv().await.ok_or_else(|| {
                    tracing::error!("Credential service shutdown response channel prematurely");
                    fdo::Error::Failed("Credential service shutdown".to_string())
                })?;
                match msg {
                    Ok(CredentialResponse::GetPublicKeyCredentialResponse(cred_response)) => {
                        let public_key_response = get_credential_response_try_from_ctap2(
                            &cred_response,
                            client_data_json,
                        )?;
                        Ok(public_key_response.into())
                    }
                    // We should be returning the correct kind of response, so this shouldn't happen.
                    Ok(_) => Err(fdo::Error::Failed("Internal error occurred".to_string())),
                    Err(_) => Err(fdo::Error::Failed("Failed to get credential".to_string())),
                }
            }
            Err(_) => Err(fdo::Error::InvalidArgs(
                "Unable to parse get credential request".to_string(),
            )),
        }
    }
}

pub struct InternalService<H: HybridHandler, U: UsbHandler, UC: UiController> {
    signal_state: Arc<AsyncMutex<SignalState>>,
    svc: Arc<AsyncMutex<CredentialService<H, U, UC>>>,
    usb_pin_tx: Arc<AsyncMutex<Option<Sender<String>>>>,
    usb_event_forwarder_task: Arc<AsyncMutex<Option<AbortHandle>>>,
    hybrid_event_forwarder_task: Arc<AsyncMutex<Option<AbortHandle>>>,
}

/// The following methods are for communication between the [trusted]
/// UI and the credential service, and should not be called by arbitrary
/// clients.
#[interface(
    name = "xyz.iinuwa.credentials.CredentialManagerInternal1",
    proxy(
        gen_blocking = false,
        default_path = "/xyz/iinuwa/credentials/CredentialManagerInternal",
        default_service = "xyz.iinuwa.credentials.CredentialManagerInternal",
    )
)]
impl<H, U, UC> InternalService<H, U, UC>
where
    H: HybridHandler + Debug + Send + Sync + 'static,
    U: UsbHandler + Debug + Send + Sync + 'static,
    UC: UiController + Debug + Send + Sync + 'static,
{
    async fn initiate_event_stream(
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
            .map_err(|_| {
                fdo::Error::Failed("Failed to get retrieve available devices".to_string())
            })?;
        Ok(devices.into_iter().map(Device::from).collect())
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
            let interface: zbus::Result<InterfaceRef<InternalService<H, U, UC>>> = object_server
                .interface("/xyz/iinuwa/credentials/CredentialManagerInternal")
                .await;

            let emitter = match interface {
                Ok(ref i) => i.signal_emitter(),
                Err(err) => {
                    tracing::error!("Failed to get connection to D-Bus to send signals: {err}");
                    return;
                }
            };
            while let Some(state) = stream.next().await {
                let event =
                    creds_lib::model::BackgroundEvent::HybridQrStateChanged(state.clone().into())
                        .try_into();
                match event {
                    Err(err) => {
                        tracing::error!("Failed to serialize state update: {err}");
                        break;
                    }
                    Ok(event) => match send_state_update(&emitter, &signal_state, event).await {
                        Ok(_) => {}
                        Err(err) => {
                            tracing::error!("Failed to send state update to UI: {err}");
                            break;
                        }
                    },
                }
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
        let usb_pin_tx = self.usb_pin_tx.clone();
        let signal_state = self.signal_state.clone();
        let object_server = object_server.clone();
        let task = tokio::spawn(async move {
            let interface: zbus::Result<InterfaceRef<InternalService<H, U, UC>>> = object_server
                .interface("/xyz/iinuwa/credentials/CredentialManagerInternal")
                .await;

            let emitter = match interface {
                Ok(ref i) => i.signal_emitter(),
                Err(err) => {
                    tracing::error!("Failed to get connection to D-Bus to send signals: {err}");
                    return;
                }
            };
            while let Some(state) = stream.next().await {
                match creds_lib::model::BackgroundEvent::UsbStateChanged((&state).into()).try_into()
                {
                    Err(err) => {
                        tracing::error!("Failed to serialize state update: {err}");
                        break;
                    }
                    Ok(event) => match send_state_update(&emitter, &signal_state, event).await {
                        Ok(_) => {}
                        Err(err) => {
                            tracing::error!("Failed to send state update to UI: {err}");
                            break;
                        }
                    },
                };
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
        })
        .abort_handle();
        if let Some(prev_task) = self.usb_event_forwarder_task.lock().await.replace(task) {
            prev_task.abort();
        }
        Ok(())
    }

    async fn select_device(&self, device_id: String) -> fdo::Result<()> {
        todo!()
    }

    async fn enter_client_pin(&self, pin: String) -> fdo::Result<()> {
        if let Some(pin_tx) = self.usb_pin_tx.lock().await.take() {
            pin_tx.send(pin).await.unwrap();
        }
        Ok(())
    }

    async fn select_credential(&self, credential_id: String) -> fdo::Result<()> {
        todo!()
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

pub struct CredentialControlServiceClient {
    conn: Connection,
}

impl CredentialControlServiceClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    async fn proxy(&self) -> zbus::Result<InternalServiceProxy> {
        InternalServiceProxy::new(&self.conn).await
    }
}

impl CredentialManagementClient for CredentialControlServiceClient {
    async fn init_request(
        &self,
        cred_request: CredentialRequest,
    ) -> Receiver<Result<CredentialResponse, creds_lib::model::Error>> {
        // TODO: Start here
        self.proxy().await.unwrap().
    }

    async fn complete_auth(&self) -> Result<CredentialResponse, String> {
        todo!()
    }

    async fn get_available_public_key_devices(
        &self,
    ) -> Result<Vec<creds_lib::model::Device>, Box<dyn Error>> {
        let devices: Result<Vec<creds_lib::model::Device>, String> = self
            .proxy()
            .await?
            .get_available_public_key_devices()
            .await?
            .into_iter()
            .map(|d| d.try_into().map_err(|_| "Failed".to_string()))
            .collect();
        Ok(devices?)
    }

    async fn get_hybrid_credential(&mut self) -> Result<(), ()> {
        todo!()
    }

    async fn get_usb_credential(&mut self) -> Result<(), ()> {
        todo!()
    }

    async fn initiate_event_stream(
        &mut self,
    ) -> Result<Pin<Box<dyn Stream<Item = creds_lib::model::BackgroundEvent> + Send + 'static>>, ()>
    {
        todo!()
    }

    async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
        if let Err(err) = self.proxy().await.unwrap().enter_client_pin(pin).await {
            tracing::error!("Failed to send client pin: {err}");
            return Err(());
        }
        Ok(())
    }

    async fn select_credential(&self, credential_id: String) -> Result<(), ()> {
        todo!()
    }
}

/// These methods are called by the credential service to control the UI.
#[proxy(
    gen_blocking = false,
    interface = "xyz.iinuwa.credentials.UiControl1",
    default_service = "xyz.iinuwa.credentials.UiControl",
    default_path = "/xyz/iinuwa/credentials/UiControl"
)]
// The #[proxy] macro renames this type to this creates a type UiControlServiceClientProxy
trait UiControlServiceClient {
    fn launch_ui(&self, request: ViewRequest) -> fdo::Result<()>;
}

#[derive(Debug)]
pub struct UiControlServiceClient {
    conn: Connection,
}
impl UiControlServiceClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    async fn proxy(&self) -> Result<UiControlServiceClientProxy, zbus::Error> {
        UiControlServiceClientProxy::new(&self.conn).await
    }
}
impl UiController for UiControlServiceClient {
    async fn launch_ui(&self, request: ViewRequest) -> Result<(), Box<dyn Error>> {
        self.proxy()
            .await?
            .launch_ui(request)
            .await
            .map_err(|err| err.into())
    }
}

async fn execute_flow<C: CredentialManagementClient>(
    // TODO: Replace this with UiControlClient
    // gui_tx: &async_std::channel::Sender<ViewRequest>,
    manager_client: &C,
    cred_request: &CredentialRequest,
) -> zbus::Result<CredentialResponse> {
    let mut signal_rx = manager_client.init_request(cred_request.clone()).await;
    let rsp = signal_rx
        .recv()
        .await
        .ok_or(fdo::Error::Failed(
            "Credential service unexpectedly interrupted".to_string(),
        ))?
        .map_err(|err| fdo::Error::Failed(err.to_string()))?;
    Ok(rsp)

    /*
    // start GUI
    let operation = match &cred_request {
        CredentialRequest::CreatePublicKeyCredentialRequest(_) => Operation::Create,
        CredentialRequest::GetPublicKeyCredentialRequest(_) => Operation::Get,
    };
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
    let view_request = ViewRequest {
        operation,
        signal: signal_tx,
    };
    // TODO: Replace this with a UiControlClient
    // gui_tx.send(view_request).await.unwrap();
    // wait for gui to complete
    signal_rx.await.map_err(|_| {
        zbus::Error::Failure("GUI channel closed before completing request.".to_string())
    })?;

    // finish up
    manager_client.complete_auth().await.map_err(|err| {
        tracing::error!("Error retrieving credential: {:?}", err);
        zbus::Error::Failure("Error retrieving credential".to_string())
    })
    */
}
