use std::{collections::HashMap, sync::Arc, time::Duration};

use async_stream::stream;
use base64::{self, Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_lite::Stream;
use libwebauthn::{
    UvUpdate,
    ops::webauthn::GetAssertionResponse,
    pin::PinNotSetReason,
    proto::CtapError,
    transport::{
        Channel, ChannelSettings, Device,
        hid::{HidDevice, channel::HidChannelHandle},
    },
    webauthn::{WebAuthn, error::WebAuthnError},
};
use tokio::sync::{
    Mutex as AsyncMutex, broadcast,
    mpsc::{self, Receiver, Sender, WeakSender},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use credentialsd_common::model::{BackgroundEvent, Credential, PinNotSetError};

use crate::model::{CredentialRequest, GetAssertionResponseInternal};

use super::{AuthenticatorResponse, CredentialResponse, CredentialServiceError};

pub(crate) trait UsbHandler {
    fn start(
        &self,
        request: &CredentialRequest,
        cancellation: CancellationToken,
    ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static;
}

#[derive(Debug)]
pub struct InProcessUsbHandler {}

impl InProcessUsbHandler {
    async fn process_idle_waiting(
        failures: &mut usize,
        prev_usb_state: &UsbStateInternal,
        cancellation: &CancellationToken,
    ) -> Result<UsbStateInternal, CredentialServiceError> {
        let list_device_fut = libwebauthn::transport::hid::list_devices();
        let Some(result) = cancellation.run_until_cancelled(list_device_fut).await else {
            tracing::debug!("USB idle polling cancelled");
            return Err(CredentialServiceError::RequestCancelled);
        };

        match result {
            Ok(hid_devices) => {
                if hid_devices.is_empty() {
                    super::cancellable_sleep(Duration::from_millis(50), cancellation).await?;
                    Ok(UsbStateInternal::Waiting)
                } else {
                    Ok(UsbStateInternal::SelectingDevice(hid_devices))
                }
            }
            Err(err) => {
                *failures += 1;
                if *failures == 5 {
                    Err(CredentialServiceError::Internal(format!(
                        "Failed to list USB authenticators: {:?}. Cancelling USB state updates.",
                        err
                    )))
                } else {
                    tracing::warn!(
                        "Failed to list USB authenticators: {:?}. Throttling USB state updates",
                        err
                    );
                    super::cancellable_sleep(Duration::from_secs(1), cancellation).await?;
                    Ok(prev_usb_state.clone())
                }
            }
        }
    }

    async fn process_selecting_device(
        hid_devices: &[HidDevice],
        cancellation: &CancellationToken,
    ) -> Result<UsbStateInternal, CredentialServiceError> {
        let expected_answers = hid_devices.len();
        let (blinking_tx, mut blinking_rx) =
            tokio::sync::mpsc::channel::<Option<usize>>(expected_answers);
        let mut channel_map = HashMap::new();
        let (setup_tx, mut setup_rx) =
            tokio::sync::mpsc::channel::<(usize, HidDevice, HidChannelHandle)>(expected_answers);
        for (idx, device) in hid_devices.iter().enumerate() {
            let stx = setup_tx.clone();
            let tx = blinking_tx.clone();
            let mut device = device.clone();
            tokio::spawn(async move {
                let dev = device.clone();

                let res = match device.channel(ChannelSettings::default()).await {
                    Ok(ref mut channel) => {
                        let cancel_handle = channel.get_handle();
                        stx.send((idx, dev, cancel_handle)).await.unwrap();
                        drop(stx);

                        let was_selected = channel
                            .blink_and_wait_for_user_presence(Duration::from_secs(300))
                            .await;
                        match was_selected {
                            Ok(true) => Ok(Some(idx)),
                            Ok(false) => Ok(None),
                            Err(err) => Err(format!(
                                "Failed to send wink request to authenticator: {:?}",
                                err
                            )),
                        }
                    }
                    Err(err) => Err(format!(
                        "Failed to create channel for USB authenticator: {:?}",
                        err
                    )),
                }
                .inspect_err(|err| tracing::warn!(err))
                .unwrap_or_default(); // In case of error, we also send `None`
                if let Err(err) = tx.send(res).await {
                    tracing::error!("Failed to send notification of wink response: {:?}", err,);
                }
            });
        }
        drop(setup_tx);
        // Receiving all cancel handles
        while let Some((idx, device, handle)) = setup_rx.recv().await {
            channel_map.insert(idx, (device, handle));
        }

        tracing::info!("Waiting for user interaction");
        drop(blinking_tx);
        let mut state = UsbStateInternal::Idle;

        loop {
            let maybe_msg_fut = blinking_rx.recv();
            let Some(maybe_msg) = cancellation.run_until_cancelled(maybe_msg_fut).await else {
                // The request was cancelled (e.g. another transport completed, or
                // the user cancelled). Stop all blinking devices. This interrupts
                // the blocking HID read within the transport (≤100ms) and sends a
                // CTAP CANCEL frame to each device.
                tracing::debug!("USB device selection cancelled");
                for (_key, (device, handle)) in channel_map.into_iter() {
                    tracing::info!("Cancelling blinking device {device:?}.");
                    handle.cancel_ongoing_operation().await;
                }
                return Err(CredentialServiceError::RequestCancelled);
            };

            let Some(msg) = maybe_msg else {
                // All blink tasks finished without a selection.
                break;
            };
            match msg {
                Some(idx) => {
                    let (device, _handle) = channel_map.remove(&idx).unwrap();
                    tracing::info!("User selected device {device:?}.");
                    for (_key, (device, handle)) in channel_map.into_iter() {
                        tracing::info!("Cancelling device {device:?}.");
                        handle.cancel_ongoing_operation().await;
                    }
                    state = UsbStateInternal::Connected(Arc::new(AsyncMutex::new(device)));
                    break;
                }
                None => {
                    continue;
                }
            }
        }
        Ok(state)
    }

    async fn process_select_credential(
        response: &GetAssertionResponse,
        cred_rx: &mut Receiver<String>,
    ) -> Result<UsbStateInternal, CredentialServiceError> {
        match cred_rx.recv().await {
            Some(cred_id) => {
                let assertion = response
                    .assertions
                    .iter()
                    .find(|c| {
                        c.credential_id
                            .as_ref()
                            .map(|c| {
                                // In order to not expose the credential ID to the untrusted UI component,
                                // we hashed it, before sending it. So we have to re-hash all our credential
                                // IDs to identify the selected one.
                                URL_SAFE_NO_PAD
                                    .encode(ring::digest::digest(&ring::digest::SHA256, &c.id))
                                    == cred_id
                            })
                            .unwrap_or_default()
                    })
                    .cloned();
                match assertion {
                    Some(assertion) => Ok(UsbStateInternal::Completed(
                        CredentialResponse::GetPublicKeyCredentialResponse(Box::new(
                            GetAssertionResponseInternal::new(
                                assertion,
                                "cross-platform".to_string(),
                            ),
                        )),
                    )),
                    None => Err(CredentialServiceError::NoCredentials),
                }
            }
            None => {
                tracing::debug!("cred channel closed before receiving cred from client.");
                Err(CredentialServiceError::Internal(
                    "Cred channel disconnected prematurely".to_string(),
                ))
            }
        }
    }

    async fn process_user_interaction(
        signal_rx: &mut Receiver<Result<UsbUvMessage, CredentialServiceError>>,
        cred_tx: &Sender<String>,
    ) -> Result<UsbStateInternal, CredentialServiceError> {
        match signal_rx.recv().await {
            Some(msg) => match msg {
                Ok(UsbUvMessage::NeedsPin {
                    attempts_left,
                    pin_tx,
                }) => Ok(UsbStateInternal::NeedsPin {
                    attempts_left,
                    pin_tx,
                }),
                Ok(UsbUvMessage::PinNotSet { reason, pin_tx }) => {
                    Ok(UsbStateInternal::PinNotSet { reason, pin_tx })
                }
                Ok(UsbUvMessage::NeedsUserVerification { attempts_left }) => {
                    Ok(UsbStateInternal::NeedsUserVerification { attempts_left })
                }
                Ok(UsbUvMessage::NeedsUserPresence) => Ok(UsbStateInternal::NeedsUserPresence),
                Ok(UsbUvMessage::ReceivedCredentials(response)) => match *response {
                    AuthenticatorResponse::CredentialCreated(make_credential_response) => Ok(
                        UsbStateInternal::Completed(CredentialResponse::from_make_credential(
                            &make_credential_response,
                            &["usb"],
                            "cross-platform",
                        )),
                    ),
                    AuthenticatorResponse::CredentialsAsserted(get_assertion_response) => {
                        if get_assertion_response.assertions.len() == 1 {
                            Ok(UsbStateInternal::Completed(
                                CredentialResponse::from_get_assertion(
                                    &get_assertion_response.assertions[0],
                                    "cross-platform",
                                ),
                            ))
                        } else {
                            Ok(UsbStateInternal::SelectCredential {
                                response: get_assertion_response,
                                cred_tx: cred_tx.clone(),
                            })
                        }
                    }
                },
                Err(err) => Err(err),
            },
            None => Err(CredentialServiceError::Internal(
                "USB UV handler channel closed".to_string(),
            )),
        }
    }

    async fn process(
        tx: Sender<UsbStateInternal>,
        cred_request: CredentialRequest,
        cancellation: CancellationToken,
    ) -> Result<(), CredentialServiceError> {
        let mut state = UsbStateInternal::Idle;
        let (signal_tx, mut signal_rx) = mpsc::channel(256);
        let (cred_tx, mut cred_rx) = mpsc::channel(1);
        debug!("polling for USB status");
        let mut failures = 0;
        // act on current USB USB state, send state changes to the stream, and
        // loop until a credential or error is returned.
        loop {
            tracing::trace!("current usb state: {:?}", state);
            let prev_usb_state = state;
            let select_next_usb_state_fut = async {
                match prev_usb_state {
                    UsbStateInternal::Idle | UsbStateInternal::Waiting => {
                        Self::process_idle_waiting(&mut failures, &prev_usb_state, &cancellation)
                            .await
                    }
                    UsbStateInternal::SelectingDevice(ref hid_devices) => {
                        Self::process_selecting_device(hid_devices.as_slice(), &cancellation).await
                    }
                    UsbStateInternal::Connected(ref device) => {
                        let device = std::sync::Arc::clone(device);
                        let signal_tx2 = signal_tx.clone();
                        let cred_request = cred_request.clone();
                        let cancellation = cancellation.clone();
                        tokio::spawn(async move {
                            handle_events(&cred_request, device.clone(), &signal_tx2, cancellation)
                                .await;
                        });
                        Self::process_user_interaction(&mut signal_rx, &cred_tx).await
                    }
                    UsbStateInternal::NeedsPin { .. }
                    | UsbStateInternal::PinNotSet { .. }
                    | UsbStateInternal::NeedsUserVerification { .. }
                    | UsbStateInternal::NeedsUserPresence => {
                        Self::process_user_interaction(&mut signal_rx, &cred_tx).await
                    }
                    UsbStateInternal::SelectCredential {
                        ref response,
                        cred_tx: _,
                    } => Self::process_select_credential(response, &mut cred_rx).await,
                    // Terminal states - preserve state unchanged, will break loop after sending
                    UsbStateInternal::Completed(_) | UsbStateInternal::Failed(_) => {
                        Ok(prev_usb_state.clone())
                    }
                }
            };

            let Some(next_usb_state) = cancellation
                .run_until_cancelled(select_next_usb_state_fut)
                .await
            else {
                tracing::debug!("USB handler cancelled, stopping processing");
                break Ok(());
            };

            // Guard: an inner future may have raced the cancellation token and
            // returned RequestCancelled as a value rather than the outer branch
            // firing. Treat it the same way — break cleanly without emitting a
            // spurious Failed state to the UI.
            if matches!(
                next_usb_state,
                Err(CredentialServiceError::RequestCancelled)
            ) {
                tracing::debug!("USB handler cancelled (inner path), stopping processing");
                break Ok(());
            }

            state = next_usb_state.unwrap_or_else(UsbStateInternal::Failed);
            // Usually, comparing the discriminant is enough, but PinNotSet/NeedsPin
            // can be repeated multiple times with different or the same error reasons
            // (PIN wrong, PIN too short, PIN too long, etc.)
            let state_changed = match (&state, &prev_usb_state) {
                (UsbStateInternal::PinNotSet { .. }, UsbStateInternal::PinNotSet { .. }) => true,
                (UsbStateInternal::NeedsPin { .. }, UsbStateInternal::NeedsPin { .. }) => true,
                (new_state, old_state) => {
                    std::mem::discriminant(new_state) != std::mem::discriminant(old_state)
                }
            };
            if state_changed {
                tracing::debug!("USB current state: {state:?}");
                tx.send(state.clone()).await.map_err(|_| {
                    CredentialServiceError::Internal(
                        "USB state channel receiver closed prematurely".to_string(),
                    )
                })?;
            }

            // Check for terminal states AFTER sending
            match state {
                UsbStateInternal::Completed(_) => break Ok(()),
                UsbStateInternal::Failed(err) => break Err(err),
                _ => {}
            }
        }
    }
}

async fn handle_events(
    cred_request: &CredentialRequest,
    device: Arc<AsyncMutex<HidDevice>>,
    signal_tx: &Sender<Result<UsbUvMessage, CredentialServiceError>>,
    cancellation: CancellationToken,
) {
    let mut device = device.lock().await;
    let device_debug = device.to_string();
    let channel = device
        .channel(ChannelSettings {
            persistent_token_store: Some(super::persistent_token_store()),
        })
        .await;
    match channel {
        Err(err) => {
            tracing::error!(
                "Failed to open channel to USB authenticator, cannot receive user verification events: {:?}",
                err
            );
        }
        Ok(mut channel) => {
            let cancel_handle = channel.get_handle();
            let signal_tx2 = signal_tx.clone().downgrade();
            let ux_updates_rx = channel.get_ux_update_receiver();
            tokio::spawn(async move {
                handle_usb_updates(&signal_tx2, ux_updates_rx).await;
                debug!("Reached end of USB update task");
            });
            tracing::debug!(
                "Polling for credential from USB authenticator {}",
                &device_debug
            );

            // Un-await-ed async-block
            let wait_for_cred_response_fut = async {
                loop {
                    let response = match cred_request {
                        CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request) => {
                            channel
                                .webauthn_make_credential(make_cred_request)
                                .await
                                .map(|response| {
                                    UsbUvMessage::ReceivedCredentials(Box::new(response.into()))
                                })
                        }
                        CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request) => {
                            channel
                                .webauthn_get_assertion(get_cred_request)
                                .await
                                .map(|response| {
                                    UsbUvMessage::ReceivedCredentials(Box::new(response.into()))
                                })
                        }
                    };
                    match response {
                        Ok(response) => {
                            tracing::debug!("Received credential from USB authenticator");
                            break Ok(response);
                        }
                        Err(WebAuthnError::Ctap(ctap_error))
                            if ctap_error.is_retryable_user_error() =>
                        {
                            warn!("Retrying WebAuthn credential operation");
                            continue;
                        }
                        Err(err) => {
                            tracing::warn!(
                                "Failed to make/get credential with USB authenticator: {:?}",
                                err
                            );
                            break Err(err);
                        }
                    }
                }
                .map_err(|err| match err {
                    WebAuthnError::Ctap(CtapError::PINAuthBlocked) => {
                        CredentialServiceError::PinAttemptsExhausted
                    }
                    WebAuthnError::Ctap(CtapError::NoCredentials) => {
                        CredentialServiceError::NoCredentials
                    }
                    WebAuthnError::Ctap(CtapError::CredentialExcluded) => {
                        CredentialServiceError::CredentialExcluded
                    }
                    _ => CredentialServiceError::AuthenticatorError,
                })
            };

            let response = match cancellation
                .run_until_cancelled(wait_for_cred_response_fut)
                .await
            {
                Some(resp) => resp,
                None => {
                    tracing::debug!("USB ceremony cancelled, interrupting authenticator operation");
                    cancel_handle.cancel_ongoing_operation().await;
                    Err(CredentialServiceError::RequestCancelled)
                }
            };

            if let Err(err) = signal_tx.send(response).await {
                tracing::error!("Failed to notify that ceremony completed: {:?}", err);
            }
        }
    }
}

impl UsbHandler for InProcessUsbHandler {
    fn start(
        &self,
        request: &CredentialRequest,
        cancellation: CancellationToken,
    ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static {
        let request = request.clone();
        let (tx, mut rx) = mpsc::channel(32);
        tokio::spawn(async move {
            if let Err(err) = InProcessUsbHandler::process(tx, request, cancellation).await {
                tracing::error!("Error getting credential from USB: {:?}", err);
            }
        });
        Box::pin(stream! {
            while let Some(state) = rx.recv().await {
                yield UsbEvent { state }
            }
        })
    }
}

// this exists to prevent making UsbStateInternal type public to the whole crate.
/// A message between USB handler and credential service
pub struct UsbEvent {
    pub(super) state: UsbStateInternal,
}

/// Used to share internal state between handler and credential service
#[derive(Clone, Debug, Default)]
pub(super) enum UsbStateInternal {
    /// Not polling for FIDO USB device.
    #[default]
    Idle,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

    /// When we encounter multiple devices, we let all of them blink and continue
    /// with the one that was tapped.
    SelectingDevice(Vec<HidDevice>),

    /// USB device connected, prompt user to tap
    Connected(Arc<AsyncMutex<HidDevice>>),

    /// The device needs the PIN to be entered.
    NeedsPin {
        attempts_left: Option<u32>,
        pin_tx: mpsc::Sender<String>,
    },

    /// The device needs the PIN to be entered.
    PinNotSet {
        reason: PinNotSetReason,
        pin_tx: mpsc::Sender<String>,
    },

    /// The device needs on-device user verification.
    NeedsUserVerification { attempts_left: Option<u32> },

    /// The device needs evidence of user presence (e.g. touch) to release the credential.
    NeedsUserPresence,

    /// Multiple credentials have been found and the user has to select which to use
    SelectCredential {
        response: GetAssertionResponse,
        cred_tx: mpsc::Sender<String>,
    },

    /// USB tapped, received credential
    Completed(CredentialResponse),

    /// There was an error while interacting with the authenticator.
    Failed(CredentialServiceError),
}

/// Used to share public state between  credential service and UI.
#[derive(Clone, Debug, Default)]
pub enum UsbState {
    /// Not polling for FIDO USB device.
    #[default]
    Idle,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

    // When we encounter multiple devices, we let all of them blink and continue
    // with the one that was tapped.
    SelectingDevice,

    /// USB device connected, prompt user to tap
    Connected,

    /// The device needs the PIN to be entered.
    NeedsPin {
        attempts_left: Option<u32>,
        pin_tx: mpsc::Sender<String>,
    },

    /// The device needs the PIN to be set.
    PinNotSet {
        reason: PinNotSetReason,
        pin_tx: mpsc::Sender<String>,
    },

    /// The device needs on-device user verification.
    NeedsUserVerification {
        attempts_left: Option<u32>,
    },

    /// The device needs evidence of user presence (e.g. touch) to release the credential.
    NeedsUserPresence,

    // Multiple credentials have been found and the user has to select which to use
    // List of user-identities to decide which to use.
    SelectingCredential {
        creds: Vec<Credential>,
        cred_tx: mpsc::Sender<String>,
    },

    /// USB tapped, received credential
    Completed,

    /// Interaction with the authenticator failed.
    Failed(CredentialServiceError),
}

impl From<UsbStateInternal> for UsbState {
    fn from(value: UsbStateInternal) -> Self {
        match value {
            UsbStateInternal::Idle => UsbState::Idle,
            UsbStateInternal::Waiting => UsbState::Waiting,
            UsbStateInternal::Connected(_) => UsbState::Connected,
            UsbStateInternal::NeedsPin {
                attempts_left,
                pin_tx,
            } => UsbState::NeedsPin {
                attempts_left,
                pin_tx,
            },
            UsbStateInternal::PinNotSet { reason, pin_tx } => {
                UsbState::PinNotSet { reason, pin_tx }
            }
            UsbStateInternal::NeedsUserVerification { attempts_left } => {
                UsbState::NeedsUserVerification { attempts_left }
            }
            UsbStateInternal::NeedsUserPresence => UsbState::NeedsUserPresence,
            UsbStateInternal::Completed(_) => UsbState::Completed,
            UsbStateInternal::SelectingDevice(_) => UsbState::SelectingDevice,
            UsbStateInternal::SelectCredential { response, cred_tx } => {
                UsbState::SelectingCredential {
                    creds: response
                        .assertions
                        .iter()
                        .map(|x| Credential {
                            id: x
                                .credential_id
                                .as_ref()
                                .map(|i| {
                                    // In order to not expose the credential ID to the untrusted UI components,
                                    // we hash and then encode it into a String.
                                    URL_SAFE_NO_PAD
                                        .encode(ring::digest::digest(&ring::digest::SHA256, &i.id))
                                })
                                .unwrap(),

                            name: x
                                .user
                                .as_ref()
                                .and_then(|u| u.name.clone())
                                .unwrap_or_else(|| String::from("<unknown>")),
                            username: x
                                .user
                                .as_ref()
                                .map(|u| u.display_name.clone())
                                .unwrap_or_default(),
                        })
                        .collect(),
                    cred_tx,
                }
            }
            UsbStateInternal::Failed(err) => UsbState::Failed(err),
        }
    }
}

impl From<&UsbState> for BackgroundEvent {
    fn from(value: &UsbState) -> Self {
        match value {
            UsbState::Idle => BackgroundEvent::UsbIdle,
            UsbState::Waiting => BackgroundEvent::UsbWaiting,
            UsbState::SelectingDevice => BackgroundEvent::UsbSelectingDevice,
            UsbState::Connected => BackgroundEvent::UsbConnected,
            UsbState::NeedsPin { attempts_left, .. } => BackgroundEvent::NeedsPin {
                attempts_left: *attempts_left,
            },
            UsbState::PinNotSet { reason, .. } => {
                let error = match reason {
                    PinNotSetReason::PinNotSet => PinNotSetError::PinNotSet,
                    PinNotSetReason::PinTooShort => PinNotSetError::PinTooShort,
                    PinNotSetReason::PinTooLong => PinNotSetError::PinTooLong,
                    PinNotSetReason::PinPolicyViolation => PinNotSetError::PinPolicyViolation,
                    PinNotSetReason::PinChangeRequired => PinNotSetError::PinChangeRequired,
                };
                BackgroundEvent::PinNotSet { error }
            }
            UsbState::NeedsUserVerification { attempts_left } => {
                BackgroundEvent::NeedsUserVerification {
                    attempts_left: *attempts_left,
                }
            }
            UsbState::NeedsUserPresence => BackgroundEvent::NeedsUserPresence,
            UsbState::SelectingCredential { creds, .. } => BackgroundEvent::SelectingCredential {
                creds: creds.to_vec(),
            },
            UsbState::Completed => BackgroundEvent::CeremonyCompleted,
            UsbState::Failed(CredentialServiceError::AuthenticatorError) => {
                BackgroundEvent::ErrorAuthenticator
            }
            UsbState::Failed(CredentialServiceError::NoCredentials) => {
                BackgroundEvent::ErrorNoCredentials
            }
            UsbState::Failed(CredentialServiceError::CredentialExcluded) => {
                BackgroundEvent::ErrorCredentialExcluded
            }
            UsbState::Failed(CredentialServiceError::PinAttemptsExhausted) => {
                BackgroundEvent::ErrorAuthenticator
            }
            UsbState::Failed(CredentialServiceError::RequestCancelled) => {
                BackgroundEvent::ErrorCancelled
            }
            UsbState::Failed(CredentialServiceError::Internal(_)) => BackgroundEvent::ErrorInternal,
        }
    }
}

async fn handle_usb_updates(
    signal_tx: &WeakSender<Result<UsbUvMessage, CredentialServiceError>>,
    mut state_rx: broadcast::Receiver<UvUpdate>,
) {
    while let Ok(msg) = state_rx.recv().await {
        let signal_tx = match signal_tx.upgrade() {
            Some(tx) => tx,
            None => break,
        };
        match msg {
            UvUpdate::UvRetry { attempts_left } => {
                if let Err(err) = signal_tx
                    .send(Ok(UsbUvMessage::NeedsUserVerification { attempts_left }))
                    .await
                {
                    tracing::error!(
                        "Authenticator requested user verficiation, but we cannot relay the message to credential service: {:?}",
                        err
                    );
                }
            }
            UvUpdate::PinRequired(pin_update) => {
                let (pin_tx, mut pin_rx) = mpsc::channel(1);
                if let Err(err) = signal_tx
                    .send(Ok(UsbUvMessage::NeedsPin {
                        pin_tx,
                        attempts_left: pin_update.attempts_left,
                    }))
                    .await
                {
                    tracing::error!(
                        "Authenticator requested a PIN from the user, but we cannot relay the message to the credential service: {:?}",
                        err
                    );
                }
                match pin_rx.recv().await {
                    Some(pin) => match pin_update.send_pin(&pin) {
                        Ok(()) => {}
                        Err(err) => tracing::error!("Error sending pin to device: {:?}", err),
                    },
                    None => tracing::debug!("Pin channel closed before receiving pin from client."),
                }
            }
            UvUpdate::PinNotSet(pin_update) => {
                let (pin_tx, mut pin_rx) = mpsc::channel(1);
                if let Err(err) = signal_tx
                    .send(Ok(UsbUvMessage::PinNotSet {
                        reason: pin_update.reason,
                        pin_tx,
                    }))
                    .await
                {
                    tracing::error!(
                        "Authenticator requested a PIN from the user, but we cannot relay the message to the credential service: {:?}",
                        err
                    );
                }
                match pin_rx.recv().await {
                    Some(pin) => match pin_update.set_pin(&pin) {
                        Ok(()) => {}
                        Err(err) => tracing::error!("Error sending pin to device: {:?}", err),
                    },
                    None => tracing::debug!("Pin channel closed before receiving pin from client."),
                }
            }
            UvUpdate::PresenceRequired => {
                if let Err(err) = signal_tx.send(Ok(UsbUvMessage::NeedsUserPresence)).await {
                    tracing::error!(
                        "Authenticator requested user presence, but we cannot relay the message to the credential service: {:?}",
                        err
                    );
                }
            }
        }
    }
    debug!("USB update channel closed.");
}

/// Messages sent between USB authenticator and handler for UV
enum UsbUvMessage {
    NeedsPin {
        attempts_left: Option<u32>,
        pin_tx: mpsc::Sender<String>,
    },
    PinNotSet {
        reason: PinNotSetReason,
        pin_tx: mpsc::Sender<String>,
    },
    NeedsUserVerification {
        attempts_left: Option<u32>,
    },
    NeedsUserPresence,
    ReceivedCredentials(Box<AuthenticatorResponse>),
}
