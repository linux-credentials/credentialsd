//! These methods are called by the flow controller to launch the trusted UI.

use std::{error::Error, future::Future, sync::Arc};

use tokio::sync::{
    mpsc::{self, Receiver},
    Mutex as AsyncMutex,
};
use tokio_stream::StreamExt;
use zbus::{
    fdo::{self, DBusProxy},
    names::OwnedUniqueName,
    proxy,
    zvariant::{ObjectPath, Optional, OwnedObjectPath},
    Connection, MatchRule, MessageStream,
};

use credentialsd_common::model::{
    BackgroundEvent, ClientPinEnteredEvent, CredentialSelectedEvent, Device,
    DiscoveryRequestedEvent, Operation, PortalBackendOptions, UserInteractedEvent, WindowHandle,
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

    #[zbus(signal)]
    async fn discovery_requested(
        &self,
        session_handle: ObjectPath<'_>,
        event: DiscoveryRequestedEvent,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn client_pin_entered(
        &self,
        session_handle: ObjectPath<'_>,
        event: ClientPinEnteredEvent,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn credential_selected(
        &self,
        session_handle: ObjectPath<'_>,
        event: CredentialSelectedEvent,
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

    #[zbus(signal)]
    async fn closed(&self) -> zbus::Result<()>;
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
        let backend_proxy = UiControlServiceProxy::new(&self.conn).await?;
        let dbus_proxy = DBusProxy::new(&self.conn).await?;
        let sender = dbus_proxy
            .get_name_owner(backend_proxy.as_ref().destination().clone())
            .await?;
        subscribe_ui_events(
            self.conn.clone(),
            sender,
            session_handle.clone(),
            from_ui_tx,
        )
        .await?;

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
    sender: OwnedUniqueName,
    session_handle: OwnedObjectPath,
    tx: mpsc::Sender<UserInteractedEvent>,
) -> zbus::Result<()> {
    let match_rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.impl.portal.experimental.Credential")?
        .destination(
            connection
                .unique_name()
                .expect("unique name to be set for connection")
                .clone(),
        )?
        .path("/org/freedesktop/portal/desktop")?
        .sender(sender.clone())?
        .arg_path(0, session_handle.clone())?
        .build();

    let session_handle2 = session_handle.clone();
    let ui_event_stream = MessageStream::for_match_rule(match_rule, &connection, Some(16)).await?
        .filter_map(move |response| match response {
            Ok(msg) => {
                Some(msg)
            },
            Err(err) => {
                tracing::error!(session_handle = %session_handle2, %err, "Error receiving a message from the UI event stream");
                None
            }
        })
        .filter_map(|msg| {
            let signal_name = msg.header().member().map(|name| name.to_string())?;

            match signal_name.as_str() {
                stringify!(DiscoveryRequested) => {
                    DiscoveryRequested::from_message(msg)?
                        .args().ok()
                        .map(|args| args.event)
                        .map(UserInteractedEvent::from)
                }
                stringify!(ClientPinEntered) => {
                    ClientPinEntered::from_message(msg)?
                        .args().ok()
                        .map(|args| args.event)
                        .map(UserInteractedEvent::from)
                }
                stringify!(CredentialSelected) => {
                    CredentialSelected::from_message(msg)?
                        .args().ok()
                        .map(|args| args.event)
                        .map(UserInteractedEvent::from)
                }
                _ => None
            }
        });

    let closed_match_rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.impl.portal.Session")?
        .member("Closed")?
        .destination(
            connection
                .unique_name()
                .expect("unique name to be set for connection")
                .clone(),
        )?
        .path(session_handle.clone())?
        .sender(sender.clone())?
        .build();

    let closed_event_stream =
        MessageStream::for_match_rule(closed_match_rule, &connection, Some(1))
            .await?
            .filter_map(|s| s.ok())
            .map(|_| UserInteractedEvent::RequestCancelled);

    let mut ui_event_stream = ui_event_stream.merge(closed_event_stream);

    // Forward the events to the receiver in the background.
    tokio::task::spawn(async move {
        tracing::debug!("Listening for events from UI");
        while let Some(ui_event) = ui_event_stream.next().await {
            tracing::trace!(?ui_event, "Received event from UI");
            if tx.send(ui_event).await.is_err() {
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
