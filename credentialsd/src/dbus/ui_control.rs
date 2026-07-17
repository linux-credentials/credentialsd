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
    Connection, MatchRule, MessageStream,
};

use credentialsd_common::model::{
    BackgroundEvent, Device, Operation, PortalBackendOptions, UserInteractedEvent, WindowHandle,
};

/// Used by the credential service to control the UI.
pub trait UiController {
    // D-Bus has a lot of arguments
    #[expect(clippy::too_many_arguments)]
    fn create_session(
        &self,
        session_handle: OwnedObjectPath,
        parent_window: Option<WindowHandle>,
        origin: String,
        r#type: Operation,
        devices: Vec<Device>,
        app_id: String,
        app_pid: u32,
        options: PortalBackendOptions,
    ) -> impl Future<Output = std::result::Result<Ceremony, Box<dyn Error>>> + Send;
}

#[proxy(
    gen_blocking = false,
    interface = "org.freedesktop.impl.portal.experimental.Credential",
    default_service = "xyz.iinuwa.credentialsd.UiControl",
    default_path = "/org/freedesktop/portal/desktop"
)]
trait UiControlService {
    // D-Bus has a lot of arguments
    #[expect(clippy::too_many_arguments)]
    fn create_session(
        &self,
        session_handle: ObjectPath<'_>,
        parent_window: Optional<WindowHandle>,
        origin: String,
        r#type: Operation,
        devices: Vec<Device>,
        app_id: String,
        app_pid: u32,
        options: PortalBackendOptions,
    ) -> fdo::Result<()>;

    async fn notify_state_changed(
        &self,
        session_handle: ObjectPath<'_>,
        event: BackgroundEvent,
    ) -> fdo::Result<()>;

    #[zbus(signal)]
    async fn user_interacted(
        &self,
        session_handle: ObjectPath<'_>,
        update: UserInteractedEvent,
    ) -> zbus::Result<()>;
}

#[derive(Clone, Debug)]
pub struct Ceremony {
    proxy: Arc<UiControlServiceProxy<'static>>,
    ui_events_rx: Arc<AsyncMutex<Receiver<UserInteractedEvent>>>,
    session_handle: OwnedObjectPath,
}

impl Ceremony {
    pub async fn receive_ui_event(&self) -> Option<UserInteractedEvent> {
        self.ui_events_rx.lock().await.recv().await
    }

    pub async fn send_state_update(&self, event: BackgroundEvent) -> Result<(), ()> {
        if let Err(err) = self
            .proxy
            .notify_state_changed(self.session_handle.as_ref(), event)
            .await
        {
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
    interface = "org.freedesktop.impl.portal.Session"
)]
trait CeremonySession {
    async fn close(&self) -> fdo::Result<()>;
}

#[derive(Debug)]
pub struct UiControlServiceClient {
    conn: Connection,
}

impl UiControlServiceClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}

impl UiController for UiControlServiceClient {
    async fn create_session(
        &self,
        session_handle: OwnedObjectPath,
        parent_window: Option<WindowHandle>,
        origin: String,
        r#type: Operation,
        devices: Vec<Device>,
        app_id: String,
        app_pid: u32,
        options: PortalBackendOptions,
    ) -> Result<Ceremony, Box<dyn Error>> {
        let (from_ui_tx, from_ui_rx) = mpsc::channel(32);
        subscribe_ui_events(self.conn.clone(), session_handle.clone(), from_ui_tx).await?;

        let backend_proxy = UiControlServiceProxy::new(&self.conn).await?;
        backend_proxy
            .create_session(
                session_handle.as_ref(),
                parent_window.into(),
                origin,
                r#type,
                devices,
                app_id,
                app_pid,
                options,
            )
            .await?;
        tracing::debug!(path = ?session_handle, "Session initialized");
        Ok(Ceremony {
            proxy: Arc::new(backend_proxy),
            ui_events_rx: Arc::new(AsyncMutex::new(from_ui_rx)),
            session_handle,
        })
    }
}

async fn subscribe_ui_events(
    connection: Connection,
    session_handle: OwnedObjectPath,
    tx: mpsc::Sender<UserInteractedEvent>,
) -> zbus::Result<()> {
    let match_rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.impl.portal.experimental.Credential")?
        .member("UserInteracted")?
        .arg_path(0, session_handle.clone())?
        .build();

    let session_handle2 = session_handle.clone();
    let mut ui_event_stream = MessageStream::for_match_rule(match_rule, &connection, Some(16)).await?
        .filter_map(move |response| match response {
            Ok(msg) => Some(msg),
            Err(err) => {
                tracing::error!(%session_handle, %err, "Error receiving a message the UserInteracted stream");
                None
            }
        })
        .filter_map(move |msg| match UserInteracted::from_message(msg) {
            Some(ui_event) => Some(ui_event),
            None => {
                tracing::error!(session_handle = %session_handle2, "Error parsing message as {}", stringify!(UserInteracted));
                None
            },
        });

    // Forward the events to the receiver in the background.
    tokio::task::spawn(async move {
        // _ = forward_ui_events(Box::pin(ui_event_stream), from_ui_tx2).await;
        tracing::debug!("Listening for events from UI");
        while let Some(signal) = ui_event_stream.next().await {
            tracing::trace!(?signal, "Received event from UI");
            let event = signal.args()?.update;
            if tx.send(event).await.is_err() {
                tracing::trace!(
                    "UI event listener stopped listening events. Ending event stream listener"
                );
                break;
            }
        }
        tracing::trace!("Stopping UI event forwarder");
        Ok::<_, zbus::Error>(())
    });
    Ok(())
}
