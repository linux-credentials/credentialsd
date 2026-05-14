use std::sync::Arc;

use async_std::{
    channel::{self, Sender},
    sync::Mutex as AsyncMutex,
    task::JoinHandle,
};
use zbus::{
    ObjectServer, fdo, interface,
    message::Header,
    names::{BusName, OwnedUniqueName},
    object_server::SignalEmitter,
    zvariant::{ObjectPath, Optional},
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
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        handle: ObjectPath<'_>,
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
    ) -> fdo::Result<ObjectPath<'_>> {
        let Some(sender) = header.sender() else {
            return Err(fdo::Error::BadAddress("Sender not found".to_string()));
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
        let ceremony = CeremonyObject {
            ui_context,
            request_tx: self.request_tx.clone(),
            return_address: sender.to_owned().into(),
            ui_events_forwarder_task: ui_events_forwarder_task.clone(),
            bg_events_tx: None,
        };

        let request = CeremonyRequest {
            ui_events_forwarder_task,
        };
        object_server.at(handle.clone(), ceremony).await?;
        object_server.at(handle.clone(), request).await?;
        tracing::debug!("Received UI launch request");
        Ok(handle.into_owned())
    }
}

pub struct CeremonyObject {
    ui_context: UiContext,
    pub request_tx: Sender<(ViewRequest, Arc<AsyncMutex<FlowControlClient>>)>,
    pub return_address: OwnedUniqueName,
    ui_events_forwarder_task: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
    bg_events_tx: Option<Sender<BackgroundEvent>>,
}

#[interface(name = "org.freedesktop.impl.portal.experimental.Credential.Ceremony")]
impl CeremonyObject {
    /// Start the UI ceremony with an initial set of available credential interfaces.
    /// Call this method after subscribing to the signals.
    async fn start(
        &mut self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
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
        let ui_events_task = async_std::task::spawn(async move {
            while let Ok(ui_event) = ui_events_rx.recv().await {
                tracing::trace!(?ui_event, "Sending UI event signal to portal");
                if emitter.user_interacted(&ui_event).await.is_err() {
                    tracing::error!("Failed to send UI event signal.");
                    // TODO: we need to cancel the request here, so we need a
                    // channel back to the ceremony object to send the cancellation.
                    break;
                }
            }
        });
        self.ui_events_forwarder_task
            .lock()
            .await
            .insert(ui_events_task);

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
}

#[interface(name = "org.freedesktop.impl.portal.Request")]
impl CeremonyRequest {
    async fn close(
        &mut self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<()> {
        if let Some(task) = self.ui_events_forwarder_task.lock().await.take() {
            task.cancel().await;
        }
        if let Some(path) = header.path() {
            // TODO: Send clean up task to GUI thread.
            object_server.remove::<CeremonyObject, _>(path).await?;
            object_server.remove::<CeremonyRequest, _>(path).await?;
        }
        Ok(())
    }
}
