use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use async_std::{
    channel::{self, Receiver, Sender},
    sync::Mutex as AsyncMutex,
    task::JoinHandle,
};
use futures_lite::{FutureExt, StreamExt};
use gio_unix::DesktopAppInfo;
use gio_unix::prelude::AppInfoExt;
use tracing::Instrument;
use zbus::{
    Connection, ObjectServer,
    fdo::{self, DBusProxy},
    interface,
    message::Header,
    names::{BusName, OwnedUniqueName},
    object_server::{InterfaceRef, SignalEmitter},
    zvariant::{ObjectPath, Optional, OwnedObjectPath},
};

use credentialsd_common::model::{
    BackgroundEvent, ClientPinEnteredEvent, CredentialSelectedEvent, Device,
    DiscoveryRequestedEvent, Operation, PortalBackendOptions, UserInteractedEvent, WindowHandle,
};

use crate::{RequestingApplication, ViewRequest, client::FlowControlClient};

pub struct CredentialPortalBackend {
    pub request_tx: Sender<(
        ViewRequest,
        Arc<AsyncMutex<FlowControlClient>>,
        Receiver<()>,
    )>,
}

#[derive(Debug, Clone)]
pub(crate) struct UiContext {
    parent_window: Option<WindowHandle>,
    r#type: Operation,
    devices: Vec<Device>,
    app_id: String,
    app_display_name: String,
    app_pid: u32,
    options: PortalBackendOptions,
}

/// These methods are called by the credential service to control the UI.
#[interface(name = "org.freedesktop.impl.portal.experimental.Credential")]
impl CredentialPortalBackend {
    // D-Bus has long argument signatures.
    #[expect(clippy::too_many_arguments)]
    async fn create_session(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        #[zbus(signal_emitter)] signal_emitter: SignalEmitter<'_>,
        session_handle: OwnedObjectPath,
        parent_window: Optional<WindowHandle>,
        _origin: String,
        r#type: Operation,
        devices: Vec<Device>,
        app_id: String,
        app_pid: u32,
        options: PortalBackendOptions,
    ) -> fdo::Result<()> {
        let Some(sender) = header.sender().map(|h| h.to_owned()) else {
            return Err(fdo::Error::BadAddress("Sender not found".to_string()));
        };

        // Set up cancellation background task.
        let CancelHandle {
            cancel_task,
            client_cancelled_tx,
            gui_stopped_tx,
            cancel_gui_rx,
        } = setup_cancellation(
            connection,
            object_server.to_owned(),
            sender.to_owned().into(),
            session_handle.clone(),
        )
        .await?;

        let app_display_name = DesktopAppInfo::new(&format!("{app_id}.desktop"))
            .ok_or_else(|| {
                fdo::Error::Failed(format!(
                    "Failed to retrieve app name for {app_id}: Could not find desktop file"
                ))
            })?
            .display_name()
            .to_string();

        let ui_context = UiContext {
            parent_window: parent_window.into(),
            r#type,
            devices,
            app_id,
            app_display_name,
            app_pid,
            options,
        };
        let ui_events_forwarder_task = Arc::new(AsyncMutex::new(None));
        let ceremony = CeremonyObject {
            ui_context,
            request_tx: self.request_tx.clone(),
            return_address: sender.to_owned().into(),
            ui_events_forwarder_task: ui_events_forwarder_task.clone(),
            bg_events_tx: None,
            session_handle: session_handle.clone(),
        };

        let mut session = CeremonySession::new(
            ui_events_forwarder_task,
            Arc::new(AsyncMutex::new(Some(cancel_task))),
            client_cancelled_tx,
            ceremony,
            session_handle.clone(),
        );
        session
            .start(
                object_server.to_owned(),
                gui_stopped_tx,
                cancel_gui_rx,
                signal_emitter.to_owned(),
            )
            .await?;
        let session_created = object_server.at(session_handle.clone(), session).await?;
        if !session_created {
            tracing::warn!(%session_handle, "Client requested session that already exists");
            return Err(fdo::Error::Failed("Could not create session".to_string()));
        }

        tracing::debug!(%session_handle, "Received UI launch request");
        Ok(())
    }

    async fn notify_state_changed(
        &self,
        #[zbus(object_server)] object_server: &ObjectServer,
        session_handle: ObjectPath<'_>,
        event: BackgroundEvent,
    ) -> fdo::Result<()> {
        let span = tracing::info_span!("NotifyStateChanged", %session_handle);
        match object_server
            .interface::<_, CeremonySession>(&session_handle)
            .instrument(span)
            .await
        {
            Ok(session_iface) => {
                let session = session_iface.get_mut().await;
                if let Err(err) = session.ceremony.on_state_changed(event).await {
                    tracing::debug!(
                        %err, "Error occurred while forwarding state update to ceremony session. Closing session."
                    );
                    CeremonySession::shutdown(object_server, session_handle).await?;
                    return Err(fdo::Error::Failed(
                        "Error sending state notification. Closing session.".to_string(),
                    ));
                };
                Ok(())
            }
            Err(zbus::Error::InterfaceNotFound) => {
                tracing::info!(%session_handle, "No session exists at the requested path");
                Err(fdo::Error::Failed(format!(
                    "No session exists at {session_handle}"
                )))
            }
            Err(err) => {
                tracing::error!(%session_handle, %err, "Unknown error occurred while looking up session");
                Err(fdo::Error::Failed(format!(
                    "Unknown error occurred while looking up session for {session_handle}"
                )))
            }
        }
    }

    #[zbus(signal)]
    async fn discovery_requested(
        emitter: SignalEmitter<'_>,
        session_handle: ObjectPath<'_>,
        event: &DiscoveryRequestedEvent,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn client_pin_entered(
        emitter: SignalEmitter<'_>,
        session_handle: ObjectPath<'_>,
        event: &ClientPinEnteredEvent,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn credential_selected(
        emitter: SignalEmitter<'_>,
        session_handle: ObjectPath<'_>,
        event: &CredentialSelectedEvent,
    ) -> zbus::Result<()>;
}

struct CancelHandle {
    cancel_task: JoinHandle<()>,
    client_cancelled_tx: Sender<Result<(), fdo::Error>>,
    gui_stopped_tx: Sender<Result<(), fdo::Error>>,
    cancel_gui_rx: Receiver<()>,
}

async fn setup_cancellation(
    connection: &Connection,
    object_server: ObjectServer,
    sender: OwnedUniqueName,
    session_handle: OwnedObjectPath,
) -> fdo::Result<CancelHandle> {
    let (client_cancelled_tx, client_cancelled_rx) = channel::bounded(1);
    let (gui_stopped_tx, gui_stopped_rx) = channel::bounded(1);
    let (cancel_gui_tx, cancel_gui_rx) = channel::bounded(1);
    let client_disconnected_rx = notify_on_disconnected(connection, sender.clone().into()).await?;
    let cancel_task = async_std::task::spawn(async move {
        let disconnect_fut = client_disconnected_rx.recv();
        let cancel_fut = client_cancelled_rx.recv();
        let gui_stopped_fut = gui_stopped_rx.recv();

        match disconnect_fut.race(cancel_fut).race(gui_stopped_fut).await {
            Ok(Ok(())) => {
                tracing::debug!(%sender, "Client cancelled or disconnected, dropping request")
            }
            Ok(Err(err)) => {
                tracing::error!(%sender, %err, "Failed to watch for client disconnection")
            }
            Err(_) => {
                tracing::error!(%sender, "Client disconnection task dropped prematurely")
            }
        }

        if cancel_gui_tx.send(()).await.is_err() {
            tracing::error!("Failed to send cancellation request to GUI");
        };

        match CeremonySession::shutdown(&object_server, session_handle.as_ref()).await {
            Ok(_) => {}
            Err(zbus::Error::InterfaceNotFound) => {
                tracing::debug!(%session_handle, "Session handle not found");
            }
            Err(err) => {
                tracing::error!(%session_handle, %err, "Error occurred while shutting down session");
            }
        };
    });
    Ok(CancelHandle {
        cancel_task,
        client_cancelled_tx,
        gui_stopped_tx,
        cancel_gui_rx,
    })
}

async fn notify_on_disconnected(
    conn: &Connection,
    bus_name: BusName<'static>,
) -> Result<Receiver<fdo::Result<()>>, fdo::Error> {
    let (tx, rx) = channel::bounded(1);
    let dbus = DBusProxy::new(conn).await?;

    if !dbus.name_has_owner((&bus_name).into()).await? {
        _ = tx.send(Ok(())).await;
        tracing::trace!(%bus_name, "Name not connected.");
        return Ok(rx);
    }
    async_std::task::spawn(async move {
        async fn watch(dbus: DBusProxy<'_>, bus_name: BusName<'_>) -> fdo::Result<()> {
            let mut stream = dbus.receive_name_owner_changed().await?;
            while let Some(signal) = stream.next().await {
                let args = signal.args()?;
                if args.name == bus_name && args.new_owner.is_none() {
                    tracing::trace!(%bus_name, "Name owner disconnected.");
                    return Ok(());
                }
            }
            Err(fdo::Error::Disconnected(format!(
                "Disconnected from bus while waiting for name owner change on {bus_name}"
            )))
        }
        let res = watch(dbus, bus_name).await;
        _ = tx.send(res).await;
    });
    Ok(rx)
}

pub struct CeremonyObject {
    ui_context: UiContext,
    pub request_tx: Sender<(
        ViewRequest,
        Arc<AsyncMutex<FlowControlClient>>,
        Receiver<()>,
    )>,
    pub return_address: OwnedUniqueName,
    ui_events_forwarder_task: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
    bg_events_tx: Option<Sender<BackgroundEvent>>,
    session_handle: OwnedObjectPath,
}

impl CeremonyObject {
    /// Start the UI ceremony with an initial set of available credential interfaces.
    async fn start(
        &mut self,
        object_server: ObjectServer,
        stopped_tx: Sender<fdo::Result<()>>,
        cancel_rx: Receiver<()>,
        emitter: SignalEmitter<'static>,
    ) -> fdo::Result<()> {
        let mut ui_events_task = self.ui_events_forwarder_task.lock().await;
        if ui_events_task.is_some() {
            tracing::warn!("Start() method called more than once. Ignoring.");
            return Ok(());
        }

        let (ui_events_tx, ui_events_rx) = channel::bounded(32);
        let (bg_events_tx, bg_events_rx) = channel::bounded(32);
        let flow_control_client = FlowControlClient {
            tx: ui_events_tx,
            rx: AsyncMutex::new(Some(bg_events_rx)),
        };
        self.bg_events_tx = Some(bg_events_tx);

        let emitter = emitter
            .set_destination(BusName::Unique(self.return_address.as_ref()))
            .to_owned();
        let session_handle = self.session_handle.clone();
        *ui_events_task = Some(async_std::task::spawn(async move {
            while let Ok(ui_event) = ui_events_rx.recv().await {
                if let Err(err) = Self::on_user_interacted(
                    &object_server,
                    &emitter,
                    session_handle.as_ref(),
                    ui_event,
                )
                .await
                {
                    tracing::trace!(%session_handle, %err, "Failed to send UI event signal.");
                    break;
                }
            }
            tracing::trace!("ui_events_task ending");
            if stopped_tx.send(Ok(())).await.is_err() {
                tracing::error!(
                    "Failed to notify CredentialPortalBackend that request is ready for cleanup"
                );
            };
        }));

        // TODO:
        // - calculate the registrable domain of the origin's hostname using Public Suffix List.
        // - if rp_id does not match origin, then send both origin's domain and the
        // domain and RP ID, and follow the guidance in WebAuthn level 3 for
        // displaying dialogs for cross-origin ceremonies.
        // https://www.w3.org/TR/webauthn-3/#sctn-cross-origin-use
        let rp_id = match self.ui_context.r#type {
            Operation::PublicKeyCreate | Operation::PublicKeyGet => self
                .ui_context
                .options
                .rp_id
                .as_ref()
                .ok_or_else(|| {
                    {
                        fdo::Error::InvalidArgs(
                            "rp_id is required for public key credential requests".to_string(),
                        )
                    }
                })?
                .to_string(),
        };

        let req = (
            ViewRequest {
                operation: self.ui_context.r#type.clone(),
                rp_id,
                requesting_app: RequestingApplication {
                    path_or_app_id: self.ui_context.app_id.clone(),
                    name: self.ui_context.app_display_name.clone(),
                    pid: self.ui_context.app_pid,
                },
                initial_devices: self.ui_context.devices.clone(),
                window_handle: self.ui_context.parent_window.clone(),
            },
            Arc::new(AsyncMutex::new(flow_control_client)),
            cancel_rx,
        );
        if self.request_tx.send(req).await.is_err() {
            tracing::error!("Received message to start flow, but GUI thread is not listening.");
            return Err(fdo::Error::Failed("Failed to start GUI".to_string()));
        }
        Ok(())
    }

    async fn on_state_changed(&self, event: BackgroundEvent) -> fdo::Result<()> {
        tracing::trace!(?event, "Received background event");
        if let Some(tx) = &self.bg_events_tx {
            if tx.send(event).await.is_ok() {
                return Ok(());
            }
            tracing::error!("Failed to send event to GUI thread");
        } else {
            tracing::error!("Flow was not properly initialized before receiving events.");
        }
        Err(fdo::Error::Failed("Failed to handle event".to_string()))
    }

    async fn on_user_interacted(
        object_server: &ObjectServer,
        emitter: &SignalEmitter<'_>,
        session_handle: ObjectPath<'_>,
        ui_event: UserInteractedEvent,
    ) -> zbus::Result<()> {
        tracing::trace!(?ui_event, "Sending UI event signal to portal");
        match ui_event {
            UserInteractedEvent::DiscoveryRequested => {
                emitter
                    .discovery_requested(session_handle, &DiscoveryRequestedEvent {})
                    .await?;
            }
            UserInteractedEvent::ClientPinEntered(pin_fd) => {
                emitter
                    .client_pin_entered(session_handle, &ClientPinEnteredEvent { pin_fd })
                    .await?;
            }
            UserInteractedEvent::CredentialSelected(id) => {
                emitter
                    .credential_selected(session_handle, &CredentialSelectedEvent { id })
                    .await?;
            }
            UserInteractedEvent::RequestCancelled => {
                CeremonySession::shutdown(object_server, session_handle).await?;
            }
        }
        Ok(())
    }
}

struct CeremonySession {
    ui_events_forwarder_task: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
    cancel_task: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
    client_cancelled_tx: Sender<fdo::Result<()>>,
    ceremony: CeremonyObject,
    object_path: OwnedObjectPath,
    emit_closed_signal: AtomicBool,
}

#[interface(name = "org.freedesktop.impl.portal.Session")]
impl CeremonySession {
    async fn close(
        &mut self,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<()> {
        let session_handle = &self.object_path;
        tracing::debug!(%session_handle, "Client requested cancellation");
        if let Some(task) = self.ui_events_forwarder_task.lock().await.take() {
            task.cancel().await;
        }
        if let Some(task) = self.cancel_task.lock().await.take() {
            task.cancel().await;
        }
        if self.client_cancelled_tx.send(Ok(())).await.is_err() {
            tracing::warn!(%session_handle, "Session already cancelled");
        }
        // Don't emit the signal when the caller initiates close
        self.emit_closed_signal.store(false, Ordering::Relaxed);
        tracing::debug!(%session_handle, "Removing session");
        if let Err(err) = Self::shutdown(object_server, session_handle.as_ref()).await {
            tracing::warn!(%session_handle, %err, "Failed to tear down session");
        };
        Ok(())
    }

    #[zbus(signal)]
    async fn closed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

impl CeremonySession {
    fn new(
        ui_events_forwarder_task: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
        cancel_task: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
        client_cancelled_tx: Sender<fdo::Result<()>>,
        ceremony: CeremonyObject,
        object_path: OwnedObjectPath,
    ) -> Self {
        Self {
            ui_events_forwarder_task,
            cancel_task,
            client_cancelled_tx,
            ceremony,
            object_path,
            emit_closed_signal: AtomicBool::new(true),
        }
    }

    async fn start(
        &mut self,
        object_server: ObjectServer,
        stopped_tx: Sender<fdo::Result<()>>,
        cancel_rx: Receiver<()>,
        emitter: SignalEmitter<'static>,
    ) -> fdo::Result<()> {
        self.ceremony
            .start(object_server, stopped_tx, cancel_rx, emitter)
            .await
    }

    async fn shutdown(
        object_server: &ObjectServer,
        session_handle: ObjectPath<'_>,
    ) -> zbus::Result<()> {
        let iface: InterfaceRef<CeremonySession> =
            match object_server.interface(&session_handle).await {
                Ok(iface) => iface,
                Err(zbus::Error::InterfaceNotFound) => {
                    tracing::warn!(%session_handle, "Session not found");
                    return Ok(());
                }
                Err(err) => {
                    return Err(err);
                }
            };
        // Emit the signal once.
        let session = iface.get().await;
        if session.emit_closed_signal.swap(false, Ordering::Relaxed)
            && let Err(err) = iface.closed().await
        {
            tracing::error!(%session_handle, %err, "Failed to emit Session::Closed signal");
        }

        match object_server.remove::<Self, _>(&session_handle).await {
            Ok(_) => Ok(()),
            Err(zbus::Error::InterfaceNotFound) => {
                tracing::warn!(%session_handle, "Session not found, may have already been cleaned up");
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}
