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

use futures_lite::StreamExt;
use std::collections::VecDeque;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use zbus::object_server::SignalEmitter;
use zbus::zvariant;
use zbus::{
    connection::{self, Connection},
    fdo, interface, Result,
};

use crate::credential_service::{CredentialManagementClient, CredentialServiceClient};
use crate::model::{
    CredentialRequest, CredentialResponse, CredentialType, GetClientCapabilitiesResponse,
    Operation, ViewRequest,
};

use self::model::{
    BackgroundEvent, CreateCredentialResponse, CreatePublicKeyCredentialResponse, Device,
    GetCredentialRequest, GetCredentialResponse, GetPublicKeyCredentialResponse,
};
// TODO: This is a workaround for testing credential_service. Refactor so that
// these private structs don't need to be exported.
pub use self::model::{CreateCredentialRequest, CreatePublicKeyCredentialRequest};

pub(crate) async fn start_service<C: CredentialManagementClient + Send + Sync + 'static>(
    service_name: &str,
    path: &str,
    // gui_tx: Sender<ViewRequest>,
    manager_client: C,
) -> Result<Connection> {
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
#[interface(name = "xyz.iinuwa.credentials.CredentialManagerUi1")]
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
                        request.clone().try_into_ctap2_request().map_err(|e| {
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
                        let public_key_response =
                            CreatePublicKeyCredentialResponse::try_from_ctap2_response(
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
                        request.clone().try_into_ctap2_request().map_err(|_| {
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
                            let public_key_response =
                                GetPublicKeyCredentialResponse::try_from_ctap2_response(
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

struct InternalService {
    signal_state: Arc<AsyncMutex<SignalState>>,
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
impl InternalService {
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
        todo!()
    }

    async fn get_hybrid_credential(&self) -> fdo::Result<()> {
        todo!()
    }

    async fn get_usb_credential(&self) -> fdo::Result<()> {
        todo!()
    }

    async fn select_device(&self, device_id: String) -> fdo::Result<()> {
        todo!()
    }
    async fn enter_client_pin(&self, pin: String) -> fdo::Result<()> {
        todo!()
    }
    async fn select_credential(&self, credential_id: String) -> fdo::Result<()> {
        todo!()
    }

    async fn send_state_update(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        update: BackgroundEvent,
    ) -> fdo::Result<()> {
        let mut signal_state = self.signal_state.lock().await;
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

    #[zbus(signal)]
    async fn state_changed(
        emitter: &SignalEmitter<'_>,
        update: BackgroundEvent,
    ) -> zbus::Result<()>;
}

struct UiControlServiceImpl;

/// These methods are called by the credential service to control the UI.
#[interface(
    name = "xyz.iinuwa.credentials.UiControl1",
    proxy(
        gen_blocking = false,
        default_path = "/xyz/iinuwa/credentials/UiControl",
        default_service = "xyz.iinuwa.credentials.UiControl",
    )
)]
impl UiControlService for UiControlServiceImpl {
    fn launch_ui(&self) {}
    fn send_state_changed(&self) {}
}

trait UiControlService {
    fn launch_ui(&self);
    fn send_state_changed(&self);
}

async fn execute_flow<C: CredentialManagementClient>(
    // TODO: Replace this with UiControlClient
    // gui_tx: &async_std::channel::Sender<ViewRequest>,
    manager_client: &C,
    cred_request: &CredentialRequest,
) -> Result<CredentialResponse> {
    manager_client
        .init_request(cred_request.clone())
        .await
        .map_err(|_| fdo::Error::Failed("Request already running".to_string()))?;

    // start GUI
    let operation = match &cred_request {
        CredentialRequest::CreatePublicKeyCredentialRequest(_) => Operation::Create {
            cred_type: CredentialType::Passkey,
        },
        CredentialRequest::GetPublicKeyCredentialRequest(_) => Operation::Get {
            cred_types: vec![CredentialType::Passkey],
        },
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
}

pub struct DbusCredentialClient {
    conn: Connection,
}

impl DbusCredentialClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
    async fn proxy(&self) -> std::result::Result<InternalServiceProxy, ()> {
        InternalServiceProxy::new(&self.conn)
            .await
            .map_err(|err| tracing::error!("Failed to communicate with D-Bus service: {err}"))
    }
}

impl CredentialServiceClient for DbusCredentialClient {
    async fn get_available_public_key_devices(
        &self,
    ) -> std::result::Result<Vec<crate::model::Device>, ()> {
        let dbus_devices = self
            .proxy()
            .await?
            .get_available_public_key_devices()
            .await
            .map_err(|_| ())?;
        dbus_devices.into_iter().map(|d| d.try_into()).collect()
    }

    async fn get_hybrid_credential(&mut self) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .get_hybrid_credential()
            .await
            .inspect_err(|err| tracing::error!("Failed to start hybrid credential flow: {err}"))
            .map_err(|_| ())
    }

    async fn get_usb_credential(&mut self) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .get_hybrid_credential()
            .await
            .inspect_err(|err| tracing::error!("Failed to start USB credential flow: {err}"))
            .map_err(|_| ())
    }

    async fn initiate_event_stream(
        &mut self,
    ) -> std::result::Result<
        std::pin::Pin<
            Box<dyn futures_lite::Stream<Item = crate::model::BackgroundEvent> + Send + 'static>,
        >,
        (),
    > {
        let stream = self
            .proxy()
            .await?
            .receive_state_changed()
            .await
            .map_err(|err| tracing::error!("Failed to initalize event stream: {err}"))?
            .filter_map(|msg| {
                msg.args()
                    .and_then(|args| {
                        args.update
                            .try_into()
                            .map_err(|err: zvariant::Error| err.into())
                    })
                    .inspect_err(|err| tracing::warn!("Failed to parse StateChanged signal: {err}"))
                    .ok()
            })
            .boxed();
        self.proxy()
            .await?
            .initiate_event_stream()
            .await
            .map_err(|err| tracing::error!("Failed to initialize event stream: {err}"))
            .and_then(|_| Ok(stream))
    }

    async fn enter_client_pin(&mut self, pin: String) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .enter_client_pin(pin)
            .await
            .map_err(|err| tracing::error!("Failed to send PIN to authenticator: {err}"))
    }

    async fn select_credential(&self, credential_id: String) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .select_credential(credential_id)
            .await
            .map_err(|err| tracing::error!("Failed to select credential: {err}"))
    }
}
