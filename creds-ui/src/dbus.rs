use async_std::channel::Sender;
use creds_lib::server::{BackgroundEvent, Device, ViewRequest};
use zbus::{fdo, interface, proxy};

#[proxy(
    gen_blocking = false,
    default_path = "/xyz/iinuwa/credentials/CredentialManagerInternal",
    default_service = "xyz.iinuwa.credentials.CredentialManagerInternal"
)]
pub trait InternalService {
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
    // pub update_tx: Sender<BackgroundEvent>,
}

/// These methods are called by the credential service to control the UI.
#[interface(name = "xyz.iinuwa.credentials.UiControl1")]
impl UiControlService {
    fn launch_ui(&self, request: creds_lib::server::ViewRequest) {}
    // fn send_state_changed(&self, event: BackgroundEvent) {}
}
