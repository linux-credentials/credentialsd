use std::sync::Arc;

use async_std::{channel::Sender, stream::StreamExt, sync::Mutex as AsyncMutex};
use zbus::{
    Connection, ObjectServer, fdo, interface, message::Header, names::OwnedUniqueName,
    object_server::SignalEmitter, proxy, zvariant::ObjectPath,
};

use credentialsd_common::{
    client::FlowController,
    model::{BackendRequest, BackgroundEvent, Device, RequestId},
    server::ViewRequest,
};

use crate::client::{DbusCredentialClient, FlowControlClient};

#[proxy(
    gen_blocking = false,
    interface = "xyz.iinuwa.credentialsd.FlowControl1",
    default_path = "/xyz/iinuwa/credentialsd/FlowControl",
    default_service = "xyz.iinuwa.credentialsd.FlowControl"
)]
pub trait FlowControlService {
    async fn subscribe(&self) -> fdo::Result<()>;

    async fn get_available_public_key_devices(&self) -> fdo::Result<Vec<Device>>;

    async fn get_hybrid_credential(&self) -> fdo::Result<()>;

    async fn get_usb_credential(&self) -> fdo::Result<()>;
    async fn get_nfc_credential(&self) -> fdo::Result<()>;

    async fn select_device(&self, device_id: String) -> fdo::Result<()>;
    async fn enter_client_pin(&self, pin: String) -> fdo::Result<()>;
    async fn select_credential(&self, credential_id: String) -> fdo::Result<()>;
    async fn cancel_request(&self, request_id: RequestId) -> fdo::Result<()>;

    #[zbus(signal)]
    async fn state_changed(update: BackgroundEvent) -> zbus::Result<()>;
}

pub struct UiControlService {
    pub request_tx: Sender<(ViewRequest, Arc<AsyncMutex<FlowControlClient>>)>,
}

/// These methods are called by the credential service to control the UI.
#[interface(name = "xyz.iinuwa.credentialsd.UiControl1")]
impl UiControlService {
    async fn launch_ui(
        &self,
        #[zbus(connection)] conn: &Connection,
        request: ViewRequest,
    ) -> fdo::Result<()> {
        tracing::debug!("Received UI launch request");
        let mut client = DbusCredentialClient::new(conn.clone());
        let (fc_tx, fc_rx) = async_std::channel::unbounded();
        let (bg_tx, bg_rx) = async_std::channel::unbounded();
        match client.subscribe().await {
            Ok(mut bg_event_stream) => async_std::task::spawn(async move {
                while let Some(bg_event) = bg_event_stream.next().await {
                    if let Err(_) = bg_tx.send(bg_event).await {
                        tracing::debug!("Background event receiver dropped. Stopping.");
                        break;
                    }
                }
            }),
            Err(_) => {
                tracing::error!(
                    ?request,
                    "Failed to subscribe to background events for request"
                );
                return Err(fdo::Error::Failed(
                    "Failed to subscribe to background events for request".to_string(),
                ));
            }
        };
        async_std::task::spawn(async move {
            while let Ok(msg) = fc_rx.recv().await {
                // UI doesn't get an error if these fail...
                let result = match &msg {
                    BackendRequest::StartHybridDiscovery => client.get_hybrid_credential().await,
                    BackendRequest::StartNfcDiscovery => client.get_nfc_credential().await,
                    BackendRequest::StartUsbDiscovery => client.get_usb_credential().await,
                    BackendRequest::EnterClientPin(pin) => {
                        client.enter_client_pin(pin.to_string()).await
                    }
                    BackendRequest::SelectCredential(cred_id) => {
                        client.select_credential(cred_id.to_string()).await
                    }
                    BackendRequest::CancelRequest => client.cancel_request(request.id).await,
                };
                if let Err(err) = result {
                    tracing::error!("Failed to send {msg:?} to frontend: {err:?}");
                }
            }
            client
        });
        let flow_control_client = FlowControlClient {
            tx: fc_tx,
            rx: AsyncMutex::new(Some(bg_rx)),
        };
        self.request_tx
            .send((request, Arc::new(AsyncMutex::new(flow_control_client))))
            .await
            .map_err(|_| fdo::Error::Failed("UI failed to launch".to_string()))
    }
}

pub struct CredentialPortalBackend {
    pub request_tx: Sender<(ViewRequest, Arc<AsyncMutex<FlowControlClient>>)>,
}

/// These methods are called by the credential service to control the UI.
#[interface(name = "org.freedesktop.impl.portal.experimental.Credential")]
impl CredentialPortalBackend {
    async fn initialize(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        request: ViewRequest,
    ) -> fdo::Result<ObjectPath<'_>> {
        let Some(sender) = header.sender() else {
            return Err(fdo::Error::BadAddress("Sender not found".to_string()));
        };
        let object_path = ObjectPath::from_string_unchecked(format!(
            "/org/freedesktop/portal/Credential/{}",
            request.id
        ));
        let flow_object = FlowObject {
            request,
            request_tx: self.request_tx.clone(),
            return_address: sender.to_owned().into(),
        };
        object_server.at(object_path.clone(), flow_object).await?;
        tracing::debug!("Received UI launch request");
        Ok(object_path)
    }
}

pub struct FlowObject {
    request: ViewRequest,
    pub request_tx: Sender<ViewRequest>,
    pub return_address: OwnedUniqueName,
}

#[interface(name = "org.freedesktop.impl.portal.experimental.Credential.FlowObject")]
impl FlowObject {
    /// Start the UI flow with an initial set of available credential interfaces.
    /// Call this method after subscribing to the signals.
    async fn start(&self) -> fdo::Result<()> {
        if let Err(err) = self.request_tx.send(self.request.clone()).await {
            tracing::error!("Received message to start flow, but GUI thread is not listening.");
            return Err(fdo::Error::Failed("Failed to start GUI".to_string()));
        }
        Ok(())
    }

    async fn notify_state_changed(&self, event: BackgroundEvent) -> fdo::Result<()> {
        todo!()
    }

    async fn cancel(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<()> {
        if let Some(path) = header.path() {
            // TODO: Send clean up task to GUI thread.
            object_server.remove::<FlowObject, _>(path).await?;
        }
        Ok(())
    }

    #[zbus(signal)]
    async fn user_interacted(emitter: SignalEmitter<'_>) -> zbus::Result<()>;
}
