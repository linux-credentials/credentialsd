//! These methods are called by the flow controller to launch the trusted UI.

use std::{error::Error, future::Future, sync::Arc};

use futures_lite::StreamExt;
use tokio::sync::{
    mpsc::{self, Receiver},
    Mutex as AsyncMutex,
};
use zbus::{
    fdo, proxy,
    zvariant::{ObjectPath, Optional, OwnedObjectPath},
    Connection,
};

use credentialsd_common::{
    model::{Device, Operation, PortalBackendOptions, RequestId, UserInteractedEvent},
    server::{BackgroundEvent, WindowHandle},
};

/// Used by the credential service to control the UI.
pub trait UiController {
    fn initialize(
        &self,
        handle: OwnedObjectPath,
        parent_window: Option<WindowHandle>,
        origin: String,
        r#type: Operation,
        request_id: RequestId,
        devices: Vec<Device>,
        app_id: String,
        app_pid: u32,
        app_path: String,
        options: PortalBackendOptions,
    ) -> impl Future<Output = std::result::Result<Ceremony, Box<dyn Error>>> + Send;
}

#[proxy(
    gen_blocking = false,
    interface = "org.freedesktop.impl.portal.experimental.Credential",
    default_service = "xyz.iinuwa.credentialsd.UiControl",
    default_path = "/org/freedesktop/portal/desktop"
)]
trait UiControlService2 {
    fn initialize(
        &self,
        handle: ObjectPath<'_>,
        parent_window: Optional<WindowHandle>,
        origin: String,
        r#type: Operation,
        request_id: RequestId,
        devices: Vec<Device>,
        app_id: String,
        app_pid: u32,
        app_path: String,
        options: PortalBackendOptions,
    ) -> fdo::Result<()>;
}

#[derive(Clone, Debug)]
pub struct Ceremony {
    proxy: Arc<CeremonyObjectProxy<'static>>,
    ui_events_rx: Arc<AsyncMutex<Receiver<UserInteractedEvent>>>,
}

impl Ceremony {
    pub async fn receive_ui_event(&self) -> Option<UserInteractedEvent> {
        self.ui_events_rx.lock().await.recv().await
    }

    pub async fn send_state_update(&self, event: BackgroundEvent) -> Result<(), ()> {
        if let Err(err) = self.proxy.notify_state_changed(event).await {
            match err {
                fdo::Error::UnknownObject(description) => {
                    tracing::error!(%description, "Flow D-Bus object no longer available at path");
                }
                _ => tracing::error!(%err, "Failed to send update to backend"),
            }
            return Err(());
        }
        Ok(())
    }
}
#[proxy(
    gen_blocking = false,
    interface = "org.freedesktop.impl.portal.experimental.Credential.Ceremony",
    default_service = "xyz.iinuwa.credentialsd.UiControl"
)]
trait CeremonyObject {
    async fn notify_state_changed(&self, event: BackgroundEvent) -> fdo::Result<()>;

    async fn cancel(&self) -> fdo::Result<()>;

    #[zbus(signal)]
    async fn user_interacted(&self, update: UserInteractedEvent) -> zbus::Result<()>;
}

#[derive(Debug)]
pub struct UiControlServiceClient {
    conn: Connection,
}

impl UiControlServiceClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    async fn proxy2(&self) -> Result<UiControlService2Proxy<'_>, zbus::Error> {
        UiControlService2Proxy::new(&self.conn).await
    }
}

impl UiController for UiControlServiceClient {
    async fn initialize(
        &self,
        handle: OwnedObjectPath,
        parent_window: Option<WindowHandle>,
        origin: String,
        r#type: Operation,
        request_id: RequestId,
        devices: Vec<Device>,
        app_id: String,
        app_pid: u32,
        app_path: String,
        options: PortalBackendOptions,
    ) -> Result<Ceremony, Box<dyn Error>> {
        let ceremony = CeremonyObjectProxy::new(&self.conn, handle.clone()).await?;
        let (from_ui_tx, from_ui_rx) = mpsc::channel(32);
        let from_ui_tx2 = from_ui_tx.clone();
        let ui_event_stream = ceremony.receive_user_interacted().await?;
        tokio::task::spawn(async move {
            _ = forward_ui_events(ui_event_stream, from_ui_tx2).await;
        });
        self.proxy2()
            .await?
            .initialize(
                handle.as_ref(),
                parent_window.into(),
                origin,
                r#type,
                request_id,
                devices,
                app_id,
                app_pid,
                app_path,
                options,
            )
            .await?;
        tracing::debug!(path = ?handle, "Path initialized");
        Ok(Ceremony {
            proxy: Arc::new(ceremony),
            ui_events_rx: Arc::new(AsyncMutex::new(from_ui_rx)),
        })
    }
}

async fn forward_ui_events(
    mut ui_event_stream: UserInteractedStream,
    tx: mpsc::Sender<UserInteractedEvent>,
) -> Result<(), Box<dyn Error>> {
    tracing::debug!("Listening for events from UI");
    while let Some(signal) = ui_event_stream.next().await {
        tracing::trace!(?signal, "Received event from UI");
        let event = signal.args()?.update;
        if let Err(_) = tx.send(event).await {
            tracing::trace!("credential service event listener stopped listening for UI events. Ending event stream listener");
            break;
        }
    }
    tracing::trace!("Stopping UI event forwarder");
    Ok(())
}
