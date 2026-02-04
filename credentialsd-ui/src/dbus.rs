use std::pin::Pin;

use async_std::{
    channel::{self, Receiver, Sender},
    sync::Mutex as AsyncMutex,
};
use credentialsd_common::{
    model::BackgroundEvent,
    server::{Device, RequestId, ViewRequest},
};
use futures_lite::Stream;
use serde::Serialize;
use zbus::{
    ObjectServer, fdo, interface,
    message::Header,
    names::BusName,
    object_server::SignalEmitter,
    proxy,
    zvariant::{ObjectPath, Type},
};

const CREDENTIAL_CEREMONY_REQUEST_PREFIX: &str = "/org/freedesktop/portal/credential/request";

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
    pub request_tx: Sender<ViewRequest>,
    pub bg_event_tx: Sender<BackgroundEvent>,
    pub ui_event_rx: AsyncMutex<Option<Receiver<UserInteractionEvent>>>,
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

pub struct CredentialPortalBackend {}

#[interface(name = "org.freedesktop.impl.portal.experimental.Credential")]
impl CredentialPortalBackend {
    async fn start_ceremony(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        request: ViewRequest,
    ) -> Result<ObjectPath, fdo::Error> {
        let unique_name = header
            .sender()
            .ok_or_else(|| {
                tracing::info!("No sender unique name on incoming request. Rejecting");
                fdo::Error::InvalidArgs("Sender unique name must be specified".to_string())
            })?
            .to_owned();
        let sender = unique_name
            .strip_prefix(':')
            .map(|sender| sender.replace('.', "_").to_string())
            // TODO: Use a random string for unique name if missing.
            .unwrap_or(String::from("0_0000"));
        let path = ObjectPath::try_from(format!(
            "{CREDENTIAL_CEREMONY_REQUEST_PREFIX}/{sender}/{}",
            request.id
        ))
        .map_err(|err| {
            tracing::error!("Invalid object path: {err}");
            fdo::Error::Failed("Invalid sender unique name".to_string())
        })?;
        let (bg_event_tx, bg_event_rx) = channel::bounded(32);
        let (ui_event_tx, ui_event_rx) = channel::bounded(32);
        let destination = BusName::Unique(unique_name);
        let object = Ceremony {
            destination: destination.clone(),
            bg_event_tx,
        };
        object_server
            .at(path.clone(), object)
            .await
            .map_err(|err| fdo::Error::from(err))?;
        let interface = object_server.interface::<_, Ceremony>(&path).await?;
        async_std::task::spawn(async move {
            let emitter = interface
                .signal_emitter()
                .clone()
                .set_destination(destination);
            while let Ok(event) = ui_event_rx.recv().await {
                interface.user_interacted(&emitter, event);
            }
        });
        Ok(path)
    }
}

pub struct Ceremony {
    destination: BusName<'static>,
    bg_event_tx: Sender<BackgroundEvent>,
}

impl Ceremony {
    async fn start(&self) {
        async_std::task::spawn(async move {
            while let Ok(ui_event) = ui_event_rx.recv().await {
                self.user_interacted(emitter, event).await;
            }
        });
    }
}
#[interface(name = "org.freedesktop.impl.portal.experimental.Credential")]
impl Ceremony {
    async fn notify(&self, event: BackgroundEvent) -> Result<(), fdo::Error> {
        self.bg_event_tx.send(event).await.map_err(|err| {
            tracing::error!("Failed to forward background event to GUI: {err}");
            fdo::Error::Failed("Failed to forward background event to GUI".to_string())
        })
    }

    #[zbus(signal)]
    async fn user_interacted(
        &self,
        emitter: &SignalEmitter<'_>,
        event: UserInteractionEvent,
    ) -> zbus::Result<()>;
}

#[derive(Serialize, Type)]
enum UserInteractionEvent {
    GetAvailablePublicKeyDevices,
    GetHybridCredential,
    GetUsbCredential,
    GetNfcCredential,
    // SelectDevice { device_id: String },
    // EnterClientPin { pin: String },
    // SelectCredential { credential_id: String },
    // CancelRequest { request_id: RequestId },
}
