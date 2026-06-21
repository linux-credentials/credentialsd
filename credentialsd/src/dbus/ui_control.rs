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

#[cfg(test)]
pub mod test {
    use std::{
        error::Error,
        fmt::Debug,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    use credentialsd_common::{
        client::FlowController,
        model::{Device, Operation, PortalBackendOptions, RequestId},
        server::{BackgroundEvent, ViewRequest, WindowHandle},
    };
    use futures_lite::StreamExt;
    use tokio::sync::{
        mpsc::{self, Receiver, Sender},
        Mutex as AsyncMutex, Notify,
    };
    use zbus::zvariant::OwnedObjectPath;

    use crate::dbus::ui_control::Ceremony;

    use super::UiController;

    #[derive(Debug)]
    pub struct DummyUiClient {
        tx: Sender<ViewRequest>,
    }

    impl UiController for DummyUiClient {
        async fn initialize(
            &self,
            _handle: OwnedObjectPath,
            _parent_window: Option<WindowHandle>,
            _origin: String,
            _type: Operation,
            _request_id: RequestId,
            _devices: Vec<Device>,
            _app_id: String,
            _app_pid: u32,
            _app_path: String,
            _options: PortalBackendOptions,
        ) -> Result<Ceremony, Box<dyn Error>> {
            unimplemented!()
        }
    }

    pub struct DummyUiServer<F>
    where
        F: FlowController + Debug,
    {
        rx: AsyncMutex<Receiver<ViewRequest>>,
        svc: Arc<AsyncMutex<Option<F>>>,
        events: Arc<AsyncMutex<Vec<BackgroundEvent>>>,
        stream_initialized: AtomicBool,
        stream_initialized_notifier: Notify,
    }
    impl<F: FlowController + Debug + Send + Sync + 'static> DummyUiServer<F> {
        pub fn new(events: Vec<BackgroundEvent>) -> (Self, DummyUiClient) {
            let (tx, rx) = mpsc::channel(32);
            let server = Self {
                rx: AsyncMutex::new(rx),
                svc: Arc::new(AsyncMutex::new(None)),
                events: Arc::new(AsyncMutex::new(events)),
                stream_initialized: AtomicBool::new(false),
                stream_initialized_notifier: Notify::new(),
            };
            let client = DummyUiClient { tx };
            (server, client)
        }

        pub async fn init(&self, flow_controller: F) {
            _ = self.svc.lock().await.insert(flow_controller);
        }

        pub async fn run(&self) {
            tracing::debug!(
                target: "DummyUiServer",
                "Starting launch_ui() request listener"
            );
            let mut rx = self.rx.lock().await;
            while let Some(request) = rx.recv().await {
                self.launch_ui(request).await.unwrap();
            }
        }

        pub async fn enter_client_pin(&self, pin: String) {
            tracing::debug!(
                target: "DummyUiServer",
                "Received enter_client_pin() request"
            );
            self.svc
                .lock()
                .await
                .as_mut()
                .unwrap()
                .enter_client_pin(pin)
                .await
                .unwrap();
        }

        pub async fn select_credential(&self, _cred_id: String) {
            tracing::debug!(
                target: "DummyUiServer",
                "Received select_credential() request"
            );
        }

        async fn launch_ui(&self, request: ViewRequest) -> Result<(), Box<dyn Error>> {
            tracing::debug!(
                target: "DummyUiServer",
                "Received launch_ui() request"
            );
            println!("Starting {:?} request UI", request.operation);
            let events = self.events.clone();
            let mut stream = self
                .svc
                .lock()
                .await
                .as_mut()
                .unwrap()
                .subscribe()
                .await
                .unwrap();
            self.stream_initialized.store(true, Ordering::Release);
            self.stream_initialized_notifier.notify_waiters();
            tokio::spawn(async move {
                tracing::debug!(target: "DummyUiServer", "Starting background event stream");
                while let Some(event) = stream.next().await {
                    tracing::debug!(
                        target: "DummyUiServer",
                        "Received background event: {event:?}"
                    );
                    events.lock().await.push(event);
                }
            });
            self.svc
                .lock()
                .await
                .as_ref()
                .unwrap()
                .get_available_public_key_devices()
                .await
                .unwrap();
            tracing::debug!(
                target: "DummyUiServer",
                "Finished launch_ui() request"
            );
            Ok(())
        }
    }
}
