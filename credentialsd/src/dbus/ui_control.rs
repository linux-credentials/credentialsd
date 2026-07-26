//! These methods are called by the flow controller to launch the trusted UI.

use std::{error::Error, future::Future, sync::Arc};

use tokio::sync::{
    Mutex as AsyncMutex,
    mpsc::{self, Receiver},
};
use tokio_stream::StreamExt;
use zbus::{
    Connection, MatchRule, MessageStream,
    fdo::{self, DBusProxy},
    names::OwnedUniqueName,
    proxy,
    zvariant::{ObjectPath, Optional, OwnedFd, OwnedObjectPath},
};

use credentialsd_common::model::{
    BACKGROUND_EVENT_ERROR_AUTHENTICATOR, BACKGROUND_EVENT_ERROR_CANCELLED,
    BACKGROUND_EVENT_ERROR_CREDENTIAL_EXCLUDED, BACKGROUND_EVENT_ERROR_INTERNAL,
    BACKGROUND_EVENT_ERROR_NO_CREDENTIALS, BACKGROUND_EVENT_ERROR_PIN_ATTEMPTS_EXHAUSTED,
    BACKGROUND_EVENT_ERROR_PIN_NOT_SET, BACKGROUND_EVENT_ERROR_TIMED_OUT, BackgroundEvent,
    ClientPinEnteredOptions, Credential, CredentialSelectedOptions, Device,
    DiscoveryRequestedOptions, NotifyHybridConnectedOptions, NotifyHybridConnectingOptions,
    NotifyHybridStartedOptions, NotifyNeedsPinOptions, NotifyNeedsUserPresenceOptions,
    NotifyNeedsUserVerificationOptions, NotifyNfcConnectedOptions,
    NotifySelectingCredentialOptions, NotifyUsbConnectedOptions, Operation, PortalBackendOptions,
    UserInteractedEvent, WindowHandle,
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

    #[zbus(no_reply)]
    async fn notify_needs_pin(
        &self,
        session_handle: ObjectPath<'_>,
        attempts_left: u32,
        _options: NotifyNeedsPinOptions,
    ) -> fdo::Result<()>;

    /// Emitted when the authenticator needs a user verification gesture.
    #[zbus(no_reply)]
    async fn notify_needs_user_verification(
        &self,
        session_handle: ObjectPath<'_>,
        attempts_left: u32,
        _options: NotifyNeedsUserVerificationOptions,
    ) -> fdo::Result<()>;

    /// Emitted when the authenticator needs a user presence gesture.
    #[zbus(no_reply)]
    async fn notify_needs_user_presence(
        &self,
        session_handle: ObjectPath<'_>,
        _options: NotifyNeedsUserPresenceOptions,
    ) -> fdo::Result<()>;

    /// Emitted when the authenticator detects multiple credentials matching
    /// credentials for a request.
    #[zbus(no_reply)]
    async fn notify_selecting_credential(
        &self,
        session_handle: ObjectPath<'_>,
        credentials: Vec<Credential>,
        _options: NotifySelectingCredentialOptions,
    ) -> fdo::Result<()>;

    /// Emitted when the platform begins scanning for CTAP2 hybrid advertisements.
    #[zbus(no_reply)]
    async fn notify_hybrid_started(
        &self,
        session_handle: ObjectPath<'_>,
        invocation_data: OwnedFd,
        _options: NotifyHybridStartedOptions,
    ) -> fdo::Result<()>;

    /// Emitted when the platform has received a CTAP2 hybrid advertisement and is
    /// establishing a channel.
    #[zbus(no_reply)]
    async fn notify_hybrid_connecting(
        &self,
        session_handle: ObjectPath<'_>,
        _options: NotifyHybridConnectingOptions,
    ) -> fdo::Result<()>;

    #[zbus(no_reply)]
    async fn notify_hybrid_connected(
        &self,
        session_handle: ObjectPath<'_>,
        _options: NotifyHybridConnectedOptions,
    ) -> fdo::Result<()>;

    #[zbus(no_reply)]
    async fn notify_nfc_connected(
        &self,
        session_handle: ObjectPath<'_>,
        _options: NotifyNfcConnectedOptions,
    ) -> fdo::Result<()>;

    #[zbus(no_reply)]
    async fn notify_usb_connected(
        &self,
        session_handle: ObjectPath<'_>,
        _options: NotifyUsbConnectedOptions,
    ) -> fdo::Result<()>;

    #[zbus(no_reply)]
    async fn notify_ceremony_completed(&self, session_handle: ObjectPath<'_>) -> fdo::Result<()>;

    #[zbus(no_reply)]
    async fn notify_error_occurred(
        &self,
        session_handle: ObjectPath<'_>,
        error: u32,
    ) -> fdo::Result<()>;

    #[zbus(signal)]
    async fn discovery_requested(
        &self,
        session_handle: ObjectPath<'_>,
        options: DiscoveryRequestedOptions,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn client_pin_entered(
        &self,
        session_handle: ObjectPath<'_>,
        pin_fd: OwnedFd,
        options: ClientPinEnteredOptions,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn credential_selected(
        &self,
        session_handle: ObjectPath<'_>,
        id: String,
        options: CredentialSelectedOptions,
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
        let response = match event {
            // TODO: Remove these events. They are no longer needed by backends, since the user
            // needs to select a device anyway.
            BackgroundEvent::NfcIdle
            | BackgroundEvent::NfcWaiting
            | BackgroundEvent::UsbIdle
            | BackgroundEvent::UsbSelectingDevice
            | BackgroundEvent::UsbWaiting => {
                return Ok(());
            }
            BackgroundEvent::NeedsPin { attempts_left } => {
                self.proxy
                    .notify_needs_pin(
                        self.session_handle.as_ref(),
                        attempts_left.unwrap_or(u32::MAX),
                        NotifyNeedsPinOptions {},
                    )
                    .await
            }
            BackgroundEvent::NeedsUserVerification { attempts_left } => {
                self.proxy
                    .notify_needs_user_verification(
                        self.session_handle.as_ref(),
                        attempts_left.unwrap_or(u32::MAX),
                        NotifyNeedsUserVerificationOptions {},
                    )
                    .await
            }
            BackgroundEvent::NeedsUserPresence => {
                self.proxy
                    .notify_needs_user_presence(
                        self.session_handle.as_ref(),
                        NotifyNeedsUserPresenceOptions {},
                    )
                    .await
            }
            BackgroundEvent::SelectingCredential { creds } => {
                self.proxy
                    .notify_selecting_credential(
                        self.session_handle.as_ref(),
                        creds,
                        NotifySelectingCredentialOptions {},
                    )
                    .await
            }
            BackgroundEvent::HybridIdle => todo!(),
            BackgroundEvent::HybridStarted(invocation_data_fd) => {
                self.proxy
                    .notify_hybrid_started(
                        self.session_handle.as_ref(),
                        invocation_data_fd,
                        NotifyHybridStartedOptions {},
                    )
                    .await
            }
            BackgroundEvent::HybridConnecting => {
                self.proxy
                    .notify_hybrid_connecting(
                        self.session_handle.as_ref(),
                        NotifyHybridConnectingOptions {},
                    )
                    .await
            }
            BackgroundEvent::HybridConnected => {
                self.proxy
                    .notify_hybrid_connected(
                        self.session_handle.as_ref(),
                        NotifyHybridConnectedOptions {},
                    )
                    .await
            }
            BackgroundEvent::NfcConnected => {
                self.proxy
                    .notify_nfc_connected(
                        self.session_handle.as_ref(),
                        NotifyNfcConnectedOptions {},
                    )
                    .await
            }
            BackgroundEvent::UsbConnected => {
                self.proxy
                    .notify_usb_connected(
                        self.session_handle.as_ref(),
                        NotifyUsbConnectedOptions {},
                    )
                    .await
            }
            BackgroundEvent::ErrorInternal => {
                let error = BACKGROUND_EVENT_ERROR_INTERNAL;
                self.proxy
                    .notify_error_occurred(self.session_handle.as_ref(), error)
                    .await
            }
            BackgroundEvent::ErrorTimedOut => {
                let error = BACKGROUND_EVENT_ERROR_TIMED_OUT;
                self.proxy
                    .notify_error_occurred(self.session_handle.as_ref(), error)
                    .await
            }
            BackgroundEvent::ErrorCancelled => {
                // TODO: Just call org.freedesktop.impl.portal.Session.Close()
                let error = BACKGROUND_EVENT_ERROR_CANCELLED;
                self.proxy
                    .notify_error_occurred(self.session_handle.as_ref(), error)
                    .await
            }
            BackgroundEvent::ErrorAuthenticator => {
                let error = BACKGROUND_EVENT_ERROR_AUTHENTICATOR;
                self.proxy
                    .notify_error_occurred(self.session_handle.as_ref(), error)
                    .await
            }
            BackgroundEvent::ErrorNoCredentials => {
                let error = BACKGROUND_EVENT_ERROR_NO_CREDENTIALS;
                self.proxy
                    .notify_error_occurred(self.session_handle.as_ref(), error)
                    .await
            }
            BackgroundEvent::ErrorCredentialExcluded => {
                let error = BACKGROUND_EVENT_ERROR_CREDENTIAL_EXCLUDED;
                self.proxy
                    .notify_error_occurred(self.session_handle.as_ref(), error)
                    .await
            }
            BackgroundEvent::ErrorPinAttemptsExhausted => {
                let error = BACKGROUND_EVENT_ERROR_PIN_ATTEMPTS_EXHAUSTED;
                self.proxy
                    .notify_error_occurred(self.session_handle.as_ref(), error)
                    .await
            }
            BackgroundEvent::ErrorPinNotSet => {
                let error = BACKGROUND_EVENT_ERROR_PIN_NOT_SET;
                self.proxy
                    .notify_error_occurred(self.session_handle.as_ref(), error)
                    .await
            }
            BackgroundEvent::CeremonyCompleted => {
                self.proxy
                    .notify_ceremony_completed(self.session_handle.as_ref())
                    .await
            }
        };

        if let Err(err) = response {
            tracing::error!(%err, "Failed to send update to backend");
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
                        .map(|_| UserInteractedEvent::DiscoveryRequested)
                }
                stringify!(ClientPinEntered) => {
                    ClientPinEntered::from_message(msg)?
                        .args().ok()
                        .map(|args| UserInteractedEvent::ClientPinEntered(args.pin_fd))
                }
                stringify!(CredentialSelected) => {
                    CredentialSelected::from_message(msg)?
                        .args().ok()
                        .map(|args| UserInteractedEvent::CredentialSelected(args.id))
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
