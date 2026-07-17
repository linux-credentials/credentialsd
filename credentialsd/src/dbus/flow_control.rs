//! This module implements the service to allow the user to control the flow of
//! the credential request through the trusted UI.

use std::{
    fmt::Debug,
    os::fd::OwnedFd,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use credentialsd_common::{
    memfd::read_secret,
    model::{
        BackgroundEvent, Error as CredentialServiceError, PortalBackendOptions,
        UserInteractedEvent, WindowHandle,
    },
};
use futures_lite::{Stream, StreamExt};
use tokio::sync::mpsc::Receiver;
use tokio::sync::oneshot;
use tokio::sync::{mpsc::Sender, Mutex as AsyncMutex};
use tokio::task::AbortHandle;
use zbus::connection::Connection;
use zbus::zvariant::OwnedObjectPath;

use crate::dbus::UiControlServiceClient;
use crate::{
    credential_service::UsbState,
    dbus::ui_control::UiController,
    model::{CredentialRequest, CredentialResponse},
};
use crate::{
    credential_service::{nfc::NfcState, DeviceStateUpdate, ManageDevice},
    model::ClientDetails,
};
use crate::{dbus::ui_control::Ceremony, gateway::WebAuthnError};

pub struct UiRequestContext {
    request: CredentialRequest,
    app: ClientDetails,
    /// Client window handle
    window_handle: Option<WindowHandle>,
    activation_token: Option<String>,
    response_channel: oneshot::Sender<Result<CredentialResponse, CredentialServiceError>>,
}

pub async fn start_flow_control_service<M: ManageDevice + Debug + Send + Sync + 'static>(
    conn: Connection,
    mut listener: Receiver<UiRequestContext>,
    device_manager: M,
) -> zbus::Result<AbortHandle> {
    let svc = Arc::new(AsyncMutex::new(device_manager));
    let svc2 = svc.clone();

    let task = tokio::spawn(async move {
        while let Some(ui_request_ctx) = listener.recv().await {
            let svc = svc2.clone();

            let ui_control_client = UiControlServiceClient::new(conn.clone());

            let UiRequestContext {
                request,
                app,
                window_handle,
                activation_token,
                response_channel,
            } = ui_request_ctx;

            let response = handle(
                svc,
                ui_control_client,
                request,
                app,
                window_handle,
                activation_token,
            )
            .await;

            if response_channel.send(response).is_err() {
                tracing::error!(
                    "Received response to credential request, but failed to forward it to gateway"
                );
            }
        }
    });
    Ok(task.abort_handle())
}

async fn handle<M: ManageDevice + Debug + Send + Sync + 'static, UC: UiController + Debug>(
    svc: Arc<AsyncMutex<M>>,
    ui_control_client: UC,
    msg: CredentialRequest,
    requesting_app: ClientDetails,
    window_handle: Option<WindowHandle>,
    activation_token: Option<String>,
) -> Result<CredentialResponse, CredentialServiceError> {
    let (request_tx, request_rx) = oneshot::channel();
    let request_id = svc.lock().await.init_request(&msg, request_tx).await?;
    let operation = msg.operation();
    let rp_id = msg.relying_party_id().to_string();

    let origin = msg.origin().to_string();

    let top_origin = msg.top_origin().map(|o| o.to_string());
    let initial_devices = svc
        .lock()
        .await
        .get_available_public_key_devices()
        .await
        .unwrap_or_default();

    let ClientDetails {
        app_id,
        pid: app_pid,
    } = requesting_app;
    let handle: OwnedObjectPath = format!(
        "/org/freedesktop/portal/desktop/session/CREDENTIALSD_{}",
        rand::random::<u32>()
    )
    .try_into()
    .expect("valid object path");
    let flow = match ui_control_client
        .create_session(
            handle,
            window_handle,
            origin,
            operation,
            initial_devices,
            app_id,
            app_pid,
            PortalBackendOptions {
                activation_token: activation_token.into(),
                top_origin: top_origin.into(),
                rp_id: Some(rp_id).into(),
            },
        )
        .await
    {
        Ok(rx) => rx,
        Err(err) => {
            tracing::error!("Failed to launch UI for credentials: {err}. Cancelling request.");
            return Err(CredentialServiceError::Internal(err.to_string()));
        }
    };
    tokio::spawn(async move {
        let client_pin_tx: Arc<Mutex<Option<Sender<String>>>> = Arc::new(Mutex::new(None));
        let cred_selector_tx = Arc::new(Mutex::new(None));
        while let Some(ui_request) = flow.receive_ui_event().await {
            match ui_request {
                UserInteractedEvent::DiscoveryRequested => {
                    let client_pin_tx = client_pin_tx.clone();
                    let cred_selector_tx = cred_selector_tx.clone();
                    let stream =
                        svc.lock()
                            .await
                            .start_discovery()
                            .await
                            .map(move |device_update| {
                                match &device_update {
                                    DeviceStateUpdate::Nfc(NfcState::NeedsPin {
                                        pin_tx, ..
                                    }) => {
                                        *client_pin_tx.lock().unwrap() = Some(pin_tx.clone());
                                    }

                                    DeviceStateUpdate::Usb(UsbState::NeedsPin {
                                        pin_tx, ..
                                    }) => {
                                        *client_pin_tx.lock().unwrap() = Some(pin_tx.clone());
                                    }
                                    DeviceStateUpdate::Usb(UsbState::SelectingCredential {
                                        cred_tx,
                                        ..
                                    }) => {
                                        *cred_selector_tx.lock().unwrap() = Some(cred_tx.clone());
                                    }
                                    _ => {}
                                }
                                device_update.into()
                            });
                    let flow = flow.clone();
                    forward_background_event_stream(flow, stream);
                }
                UserInteractedEvent::ClientPinEntered(pin_fd) => {
                    let pin_fd = OwnedFd::from(pin_fd);
                    let pin = match read_secret(pin_fd)
                        .map_err(|err| format!("Could not read from file descriptor: {err}"))
                        .and_then(|bytes| {
                            String::from_utf8(bytes).map_err(|err| {
                                format!("Invalid UTF-8 data retrieved from pin: {err}")
                            })
                        }) {
                        Ok(pin) => pin,
                        // TODO: need to send an error to the UI, cancel the request and terminate the loop.
                        Err(err) => {
                            tracing::error!(%err, "Failed to read client PIN. Stopping event loop. TODO: cancel the request");
                            break;
                        }
                    };
                    let tx = { client_pin_tx.lock().unwrap().take() };
                    if let Some(tx) = tx {
                        if tx.send(pin).await.is_err() {
                            tracing::error!("Failed to send client PIN to device");
                        }
                    } else {
                        tracing::error!(
                            "Invalid state: received a client PIN with no pending request."
                        );
                    }
                }
                UserInteractedEvent::CredentialSelected(id) => {
                    let tx = { cred_selector_tx.lock().unwrap().take() };
                    if let Some(tx) = tx {
                        if tx.send(id).await.is_err() {
                            tracing::error!("Failed to send credential selection to device");
                        }
                    } else {
                        tracing::error!(
                            "Invalid state: received a credential selection ID with no pending request."
                        );
                    }
                }
                UserInteractedEvent::RequestCancelled => {
                    tracing::debug!(%request_id, "Cancelling request");
                    svc.lock().await.cancel_request(request_id).await;
                }
            }
        }
    });
    tracing::debug!("Finished setting up request {request_id}");
    let cred_response = request_rx
        .await
        .expect("Credential service not to drop request channel before responding.");

    cred_response
}

fn forward_background_event_stream(
    flow: Ceremony,
    mut stream: impl Stream<Item = BackgroundEvent> + Send + Unpin + 'static,
) {
    tokio::spawn(async move {
        while let Some(event) = stream.next().await {
            let send_result = flow.send_state_update(event).await;
            if send_result.is_err() {
                tracing::error!("Failed to send state update event to backend. Stopping flow");
                break;
            }
        }
    });
}

/// Coordinates between user and various devices connected to the machine to
/// fulfill credential requests.
#[async_trait]
pub trait CredentialRequestController {
    async fn request_credential(
        &self,
        requesting_app: ClientDetails,
        request: CredentialRequest,
        window_handle: Option<WindowHandle>,
        activation_token: Option<String>,
    ) -> Result<CredentialResponse, WebAuthnError>;
}

pub struct CredentialRequestControllerClient {
    pub initiator: Sender<UiRequestContext>,
}

#[async_trait]
impl CredentialRequestController for CredentialRequestControllerClient {
    async fn request_credential(
        &self,
        app: ClientDetails,
        request: CredentialRequest,
        window_handle: Option<WindowHandle>,
        activation_token: Option<String>,
    ) -> Result<CredentialResponse, WebAuthnError> {
        let (tx, rx) = oneshot::channel();
        self.initiator
            .send(UiRequestContext {
                request,
                app,
                window_handle,
                activation_token,
                response_channel: tx,
            })
            .await
            .unwrap();
        let response = rx.await.map_err(|_| {
            tracing::error!("Credential response channel closed prematurely");
            WebAuthnError::NotAllowedError
        })?;
        // TODO: CredentialServiceError is returning the wrong errors types to the flow controller
        // We need to be able to bubble up the InvalidStateError, when the
        // selected authenticator has the credential known by the RP, and
        // the user wants to let the RP know.
        // All the other possible errors from the spec (AbortError,
        // ConstraintError, SecurityError, TypeError) should be handled
        // earlier by the gateway.
        // Every other error should be squashed into NotAllowed as a catch-all
        // For now, just squashing.
        response.map_err(|_| WebAuthnError::NotAllowedError)
    }
}
