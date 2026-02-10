use async_std::channel::Sender;
use credentialsd_common::{
    model::BackgroundEvent,
    server::{Device, RequestId, ViewRequest},
};
use zbus::{fdo, interface, proxy};

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

    async fn set_usb_device_pin(&self, pin: String) -> fdo::Result<()>;
    async fn set_nfc_device_pin(&self, pin: String) -> fdo::Result<()>;
    #[zbus(signal)]
    async fn state_changed(update: BackgroundEvent) -> zbus::Result<()>;
}

pub struct UiControlService {
    pub request_tx: Sender<ViewRequest>,
}

/// These methods are called by the credential service to control the UI.
#[interface(name = "xyz.iinuwa.credentialsd.UiControl1")]
impl UiControlService {
    async fn launch_ui(&self, request: ViewRequest) -> fdo::Result<()> {
        tracing::debug!("Received UI launch request");
        self.request_tx
            .send(request)
            .await
            .map_err(|_| fdo::Error::Failed("UI failed to launch".to_string()))
    }
}
