use std::sync::Arc;

use async_std::{
    channel::{self, Receiver, Sender},
    sync::Mutex as AsyncMutex,
    task::JoinHandle,
};
use futures_lite::{FutureExt, StreamExt};
use zbus::{
    Connection, ObjectServer,
    fdo::{self, DBusProxy},
    interface,
    message::Header,
    names::{BusName, OwnedUniqueName},
    object_server::SignalEmitter,
    zvariant::{ObjectPath, Optional, OwnedObjectPath},
};

use credentialsd_common::{
    model::{
        Device, Operation, PortalBackendOptions, RequestId, RequestingApplication,
        UserInteractedEvent,
    },
    server::{BackgroundEvent, ViewRequest, WindowHandle},
};

use crate::client::FlowControlClient;

pub struct CredentialPortalBackend {
    pub request_tx: Sender<(ViewRequest, Arc<AsyncMutex<FlowControlClient>>)>,
}

#[derive(Debug, Clone)]
pub(crate) struct UiContext {
    parent_window: Option<WindowHandle>,
    origin: String,
    r#type: Operation,
    request_id: RequestId,
    devices: Vec<Device>,
    app_id: String,
    app_display_name: String,
    app_pid: u32,
    app_path: String,
    options: PortalBackendOptions,
}

/// These methods are called by the credential service to control the UI.
#[interface(name = "org.freedesktop.impl.portal.experimental.Credential")]
impl CredentialPortalBackend {
    async fn initialize(
        &self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        handle: OwnedObjectPath,
        parent_window: Optional<WindowHandle>,
        origin: String,
        r#type: Operation,
        request_id: RequestId,
        devices: Vec<Device>,
        app_id: String,
        app_display_name: String,
        app_pid: u32,
        app_path: String,
        options: PortalBackendOptions,
    ) -> fdo::Result<()> {
        let Some(sender) = header.sender().map(|h| h.to_owned()) else {
            return Err(fdo::Error::BadAddress("Sender not found".to_string()));
        };

        // Set up cancellation background task.
        let (cancel_task, client_cancelled_tx, gui_stopped_tx) = {
            let sender = sender.clone();
            let object_path = handle.clone();
            let (client_cancelled_tx, client_cancelled_rx) = channel::bounded(1);
            let (gui_stopped_tx, gui_stopped_rx) = channel::bounded(1);
            let client_disconnected_rx =
                notify_on_disconnected(connection, sender.clone().into()).await?;
            let object_server = object_server.clone();
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

                // TODO: Signal GUI thread of cancellation
                if let Err(err) = object_server
                    .remove::<CeremonyObject, _>(&object_path)
                    .await
                {
                    tracing::warn!(%object_path, %err, "Failed to remove Ceremony request");
                }
                if let Err(err) = object_server
                    .remove::<CeremonyRequest, _>(&object_path)
                    .await
                {
                    tracing::warn!(%object_path, %err, "Failed to remove org.freedesktop.impl.portal.Request");
                }
            });
            (cancel_task, client_cancelled_tx, gui_stopped_tx)
        };

        let ui_context = UiContext {
            parent_window: parent_window.into(),
            origin,
            r#type,
            request_id,
            devices,
            app_id,
            app_display_name,
            app_pid,
            app_path,
            options,
        };
        let ui_events_forwarder_task = Arc::new(AsyncMutex::new(None));
        let mut ceremony = CeremonyObject {
            ui_context,
            request_tx: self.request_tx.clone(),
            return_address: sender.to_owned().into(),
            ui_events_forwarder_task: ui_events_forwarder_task.clone(),
            bg_events_tx: None,
        };
        let request = CeremonyRequest {
            ui_events_forwarder_task,
            cancel_task: Arc::new(AsyncMutex::new(Some(cancel_task))),
            client_cancelled_tx,
        };
        object_server.at(handle.clone(), request).await?;

        let emitter = SignalEmitter::new(connection, handle.clone())?;
        ceremony.start(gui_stopped_tx, emitter.to_owned()).await?;
        object_server.at(handle, ceremony).await?;

        tracing::debug!("Received UI launch request");
        Ok(())
    }
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
    pub request_tx: Sender<(ViewRequest, Arc<AsyncMutex<FlowControlClient>>)>,
    pub return_address: OwnedUniqueName,
    ui_events_forwarder_task: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
    bg_events_tx: Option<Sender<BackgroundEvent>>,
}

impl CeremonyObject {
    /// Start the UI ceremony with an initial set of available credential interfaces.
    /// Call this method after subscribing to the signals.
    async fn start(
        &mut self,
        stopped_tx: Sender<fdo::Result<()>>,
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
            .set_destination(BusName::Unique((&self.return_address).into()))
            .to_owned();
        *ui_events_task = Some(async_std::task::spawn(async move {
            while let Ok(ui_event) = ui_events_rx.recv().await {
                tracing::trace!(?ui_event, "Sending UI event signal to portal");
                if emitter.user_interacted(&ui_event).await.is_err() {
                    tracing::trace!("Failed to send UI event signal.");
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

        // Assuming this is a PublicKey request, require the rp_id
        let rp_id = self
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
            .to_string();
        let req = (
            ViewRequest {
                operation: self.ui_context.r#type.clone(),
                id: self.ui_context.request_id,
                rp_id,
                requesting_app: RequestingApplication {
                    path_or_app_id: self.ui_context.app_id.clone(),
                    name: Some(self.ui_context.app_display_name.clone()).into(),
                    pid: self.ui_context.app_pid,
                },
                initial_devices: self.ui_context.devices.clone(),
                window_handle: self.ui_context.parent_window.clone().into(),
            },
            Arc::new(AsyncMutex::new(flow_control_client)),
        );
        if self.request_tx.send(req).await.is_err() {
            tracing::error!("Received message to start flow, but GUI thread is not listening.");
            return Err(fdo::Error::Failed("Failed to start GUI".to_string()));
        }
        Ok(())
    }
}

#[interface(name = "org.freedesktop.impl.portal.experimental.Credential.Ceremony")]
impl CeremonyObject {
    async fn notify_state_changed(&self, event: BackgroundEvent) -> fdo::Result<()> {
        tracing::trace!(?event, "Received background event");
        if let Some(tx) = &self.bg_events_tx {
            if tx.send(event).await.is_ok() {
                return Ok(());
            }
            tracing::error!("Failed to send event to GUI thread");
        } else {
            tracing::error!("Flow was not properly initialized before receiving events.");
        }
        return Err(fdo::Error::Failed("Failed to handle event".to_string()));
    }

    #[zbus(signal)]
    async fn user_interacted(
        emitter: SignalEmitter<'_>,
        event: &UserInteractedEvent,
    ) -> zbus::Result<()>;
}

struct CeremonyRequest {
    ui_events_forwarder_task: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
    cancel_task: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
    client_cancelled_tx: Sender<fdo::Result<()>>,
}

#[interface(name = "org.freedesktop.impl.portal.Request")]
impl CeremonyRequest {
    async fn close(&mut self) -> fdo::Result<()> {
        tracing::debug!("Client requested cancellation");
        if let Some(task) = self.ui_events_forwarder_task.lock().await.take() {
            task.cancel().await;
        }
        if let Some(task) = self.cancel_task.lock().await.take() {
            task.cancel().await;
        }
        if self.client_cancelled_tx.send(Ok(())).await.is_err() {
            tracing::warn!("Request already cancelled");
        }
        Ok(())
    }
}
