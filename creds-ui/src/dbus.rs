use async_std::channel::Sender;
use creds_lib::server::{BackgroundEvent, Device, ViewRequest};
use zbus::{fdo, interface, proxy};

#[proxy(
    gen_blocking = false,
    interface = "xyz.iinuwa.credentials.FlowControl1",
    default_path = "/xyz/iinuwa/credentials/FlowControl",
    default_service = "xyz.iinuwa.credentials.FlowControl"
)]
pub trait FlowControlService {
    async fn initiate_event_stream(&self) -> fdo::Result<()>;

    async fn get_available_public_key_devices(&self) -> fdo::Result<Vec<Device>>;

    async fn get_hybrid_credential(&self) -> fdo::Result<()>;

    async fn get_usb_credential(&self) -> fdo::Result<()>;

    async fn select_device(&self, device_id: String) -> fdo::Result<()>;
    async fn enter_client_pin(&self, pin: String) -> fdo::Result<()>;
    async fn select_credential(&self, credential_id: String) -> fdo::Result<()>;

    #[zbus(signal)]
    async fn state_changed(update: BackgroundEvent) -> zbus::Result<()>;
}

pub struct UiControlService {
    pub request_tx: Sender<crate::dbus::ViewRequest>,
}

/// These methods are called by the credential service to control the UI.
#[interface(name = "xyz.iinuwa.credentials.UiControl1")]
impl UiControlService {
    async fn launch_ui(&self, request: creds_lib::server::ViewRequest) -> fdo::Result<()> {
        tracing::debug!("Received UI launch request");
        self.request_tx
            .send(request)
            .await
            .map_err(|_| fdo::Error::Failed("UI failed to launch".to_string()))
    }
}
