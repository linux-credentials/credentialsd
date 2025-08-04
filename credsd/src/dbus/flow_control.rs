use std::future::Future;
use std::{collections::VecDeque, error::Error, fmt::Debug, pin::Pin, sync::Arc};

use creds_lib::model::{
    CredentialRequest, CredentialResponse, Error as CredentialServiceError, WebAuthnError,
};
use creds_lib::server::{BackgroundEvent, Device};
use futures_lite::{Stream, StreamExt};
use tokio::{
    sync::{
        mpsc::{self, Receiver, Sender},
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

use crate::credential_service::{
    hybrid::{HybridHandler, HybridState},
    usb::UsbHandler,
    CredentialManagementClient, CredentialService, UiController, UsbState,
};
pub const INTERFACE_NAME: &'static str = "xyz.iinuwa.credentials.FlowControl1";
pub const SERVICE_PATH: &'static str = "/xyz/iinuwa/credentials/FlowControl";
pub const SERVICE_NAME: &'static str = "xyz.iinuwa.credentials.FlowControl";

pub async fn start_flow_control_service<
    H: HybridHandler + Debug + Send + Sync + 'static,
    U: UsbHandler + Debug + Send + Sync + 'static,
    UC: UiController + Debug + Send + Sync + 'static,
>(
    credential_service: CredentialService<H, U, UC>,
) -> zbus::Result<(
    Connection,
    Sender<(
        CredentialRequest,
        Sender<Result<CredentialResponse, CredentialServiceError>>,
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
                usb_pin_tx: Arc::new(AsyncMutex::new(None)),
                usb_event_forwarder_task: Arc::new(AsyncMutex::new(None)),
                hybrid_event_forwarder_task: Arc::new(AsyncMutex::new(None)),
            },
        )?
        .build()
        .await?;
    let (initiator_tx, mut initiator_rx) = mpsc::channel(2);
    tokio::spawn(async move {
        let svc = svc2;
        while let Some((msg, tx)) = initiator_rx.recv().await {
            svc.lock().await.init_request(&msg, tx).await;
        }
    });
    Ok((conn, initiator_tx))
}

struct FlowControlService<H: HybridHandler, U: UsbHandler, UC: UiController> {
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
    name = "xyz.iinuwa.credentials.FlowControl1",
    proxy(
        gen_blocking = false,
        default_path = "/xyz/iinuwa/credentials/FlowControl",
        default_service = "xyz.iinuwa.credentials.FlowControl",
    )
)]
impl<H, U, UC> FlowControlService<H, U, UC>
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
            let interface: zbus::Result<InterfaceRef<FlowControlService<H, U, UC>>> =
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
            let interface: zbus::Result<InterfaceRef<FlowControlService<H, U, UC>>> =
                object_server.interface(SERVICE_PATH).await;

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

enum SignalState {
    /// No state
    Idle,
    /// Waiting for client to signal that it's ready to receive events.
    /// Holds a cache of events to send once the client connects.
    Pending(VecDeque<BackgroundEvent>),
    /// Client is actively receiving messages.
    Active,
}

pub struct CredentialControlServiceClient {
    conn: Connection,
}

impl CredentialControlServiceClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    async fn proxy(&self) -> zbus::Result<FlowControlServiceProxy> {
        FlowControlServiceProxy::new(&self.conn).await
    }
}

/*
impl CredentialManagementClient for CredentialControlServiceClient {
    async fn init_request(
        &self,
        cred_request: CredentialRequest,
    ) -> Receiver<Result<CredentialResponse, creds_lib::model::Error>> {
        // TODO: Start here
        // self.proxy().await.unwrap().
        todo!()
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
    */

pub trait CredentialRequestController {
    fn request_credential(
        &self,
        request: CredentialRequest,
    ) -> impl Future<Output = Result<CredentialResponse, WebAuthnError>> + Send;
}

pub struct CredentialRequestControllerClient {
    pub initiator: Sender<(
        CredentialRequest,
        Sender<Result<CredentialResponse, CredentialServiceError>>,
    )>,
}

impl CredentialRequestController for CredentialRequestControllerClient {
    async fn request_credential(
        &self,
        request: CredentialRequest,
    ) -> Result<CredentialResponse, WebAuthnError> {
        let (tx, mut rx) = mpsc::channel(4);
        // TODO: We need a PlatformError variant.
        self.initiator.send((request, tx)).await.unwrap();
        if let Some(msg) = rx.recv().await {
            // TODO: Pass real WebAuthnError from credential service
            msg.map_err(|_| WebAuthnError::NotAllowedError)
        } else {
            // if the sender was dropped, then the operation is cancelled.
            Err(WebAuthnError::NotAllowedError)
        }
    }
}
