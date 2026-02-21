use std::sync::Arc;

use async_std::{channel::Sender, stream::StreamExt, sync::Mutex as AsyncMutex};
use zbus::{Connection, fdo, interface, proxy};

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
                    BackendRequest::GetHybridCredential => client.get_hybrid_credential().await,
                    BackendRequest::GetNfcCredential => client.get_nfc_credential().await,
                    BackendRequest::GetUsbCredential => client.get_usb_credential().await,
                    BackendRequest::EnterClientPin(pin) => {
                        client.enter_client_pin(pin.to_string()).await
                    }
                    BackendRequest::SelectCredential(cred_id) => {
                        client.select_credential(cred_id.to_string()).await
                    }
                    BackendRequest::CancelRequest(request_id) => {
                        client.cancel_request(*request_id).await
                    }
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
