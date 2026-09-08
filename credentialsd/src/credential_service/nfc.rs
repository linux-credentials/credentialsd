use std::time::Duration;

use async_stream::stream;
use base64::{self, Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_lite::Stream;
use libwebauthn::{
    UvUpdate,
    ops::webauthn::GetAssertionResponse,
    pin::PinNotSetReason,
    proto::CtapError,
    transport::{Channel, ChannelSettings, Device, nfc::device::NfcDevice},
    webauthn::{WebAuthn, error::WebAuthnError},
};
use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, Receiver, Sender, WeakSender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use credentialsd_common::model::{BackgroundEvent, Credential, PinNotSetError};

use crate::model::{CredentialRequest, GetAssertionResponseInternal};

use super::{AuthenticatorResponse, CredentialResponse, CredentialServiceError};

pub(crate) trait NfcHandler {
    #[expect(unused)]
    fn start(
        &self,
        request: &CredentialRequest,
        cancellation: CancellationToken,
    ) -> impl Stream<Item = NfcEvent> + Send + Sized + Unpin + 'static;
}

#[derive(Debug)]
pub struct InProcessNfcHandler {}

impl InProcessNfcHandler {
    async fn process_idle_waiting(
        failures: &mut usize,
        prev_nfc_state: &NfcStateInternal,
        cancellation: &CancellationToken,
    ) -> Result<NfcStateInternal, CredentialServiceError> {
        let list_device_fut = libwebauthn::transport::nfc::get_nfc_device();
        let Some(result) = cancellation.run_until_cancelled(list_device_fut).await else {
            tracing::debug!("NFC idle polling cancelled");
            return Err(CredentialServiceError::RequestCancelled);
        };
        match result {
            Ok(Some(nfc_device)) => Ok(NfcStateInternal::Connected(nfc_device)),
            Ok(None) => {
                let state = NfcStateInternal::Waiting;
                Ok(state)
            }
            Err(err) => {
                *failures += 1;
                if *failures == 5 {
                    Err(CredentialServiceError::Internal(format!(
                        "Failed to list NFC authenticators: {:?}. Cancelling NFC state updates.",
                        err
                    )))
                } else {
                    tracing::warn!(
                        "Failed to list NFC authenticators: {:?}. Throttling NFC state updates",
                        err
                    );
                    super::cancellable_sleep(Duration::from_secs(1), cancellation).await?;
                    Ok(prev_nfc_state.clone())
                }
            }
        }
    }

    async fn process_select_credential(
        response: &GetAssertionResponse,
        cred_rx: &mut Receiver<String>,
    ) -> Result<NfcStateInternal, CredentialServiceError> {
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
                    Some(assertion) => Ok(NfcStateInternal::Completed(
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
        signal_rx: &mut Receiver<Result<NfcUvMessage, CredentialServiceError>>,
        cred_tx: &Sender<String>,
    ) -> Result<NfcStateInternal, CredentialServiceError> {
        match signal_rx.recv().await {
            Some(msg) => match msg {
                Ok(NfcUvMessage::NeedsPin {
                    attempts_left,
                    pin_tx,
                }) => Ok(NfcStateInternal::NeedsPin {
                    attempts_left,
                    pin_tx,
                }),
                Ok(NfcUvMessage::PinNotSet { reason, pin_tx }) => {
                    Ok(NfcStateInternal::PinNotSet { reason, pin_tx })
                }
                Ok(NfcUvMessage::NeedsUserVerification { attempts_left }) => {
                    Ok(NfcStateInternal::NeedsUserVerification { attempts_left })
                }
                Ok(NfcUvMessage::ReceivedCredentials(response)) => match *response {
                    AuthenticatorResponse::CredentialCreated(make_credential_response) => Ok(
                        NfcStateInternal::Completed(CredentialResponse::from_make_credential(
                            &make_credential_response,
                            &["nfc"],
                            "cross-platform",
                        )),
                    ),
                    AuthenticatorResponse::CredentialsAsserted(get_assertion_response) => {
                        if get_assertion_response.assertions.len() == 1 {
                            Ok(NfcStateInternal::Completed(
                                CredentialResponse::from_get_assertion(
                                    &get_assertion_response.assertions[0],
                                    "cross-platform",
                                ),
                            ))
                        } else {
                            Ok(NfcStateInternal::SelectCredential {
                                response: get_assertion_response,
                                cred_tx: cred_tx.clone(),
                            })
                        }
                    }
                },
                Err(err) => Err(err),
            },
            None => Err(CredentialServiceError::Internal(
                "NFC UV handler channel closed".to_string(),
            )),
        }
    }

    async fn process(
        tx: Sender<NfcStateInternal>,
        cred_request: CredentialRequest,
        cancellation: CancellationToken,
    ) -> Result<(), CredentialServiceError> {
        let mut state = NfcStateInternal::Idle;
        let (signal_tx, mut signal_rx) = mpsc::channel(256);
        let (cred_tx, mut cred_rx) = mpsc::channel(1);
        debug!("polling for NFC status");
        let mut failures = 0;
        // act on current NFC NFC state, send state changes to the stream, and
        // loop until a credential or error is returned.
        loop {
            tracing::debug!("current nfc state: {:?}", state);
            let prev_nfc_state = state;

            let select_next_nfc_state_fut = async {
                match prev_nfc_state {
                    NfcStateInternal::Idle | NfcStateInternal::Waiting => {
                        Self::process_idle_waiting(&mut failures, &prev_nfc_state, &cancellation)
                            .await
                    }
                    NfcStateInternal::Connected(ref device) => {
                        let device = device.clone();
                        let signal_tx2 = signal_tx.clone();
                        let cred_request = cred_request.clone();
                        let cancellation = cancellation.clone();
                        tokio::spawn(async move {
                            handle_events(&cred_request, device, &signal_tx2, cancellation).await;
                        });
                        Self::process_user_interaction(&mut signal_rx, &cred_tx).await
                    }
                    NfcStateInternal::NeedsPin { .. }
                    | NfcStateInternal::PinNotSet { .. }
                    | NfcStateInternal::NeedsUserVerification { .. } => {
                        Self::process_user_interaction(&mut signal_rx, &cred_tx).await
                    }
                    NfcStateInternal::SelectCredential {
                        ref response,
                        cred_tx: _,
                    } => Self::process_select_credential(response, &mut cred_rx).await,
                    // Terminal states - preserve state unchanged, will break loop after sending
                    NfcStateInternal::Completed(_) | NfcStateInternal::Failed(_) => {
                        Ok(prev_nfc_state.clone())
                    }
                }
            };

            let Some(next_nfc_state) = cancellation
                .run_until_cancelled(select_next_nfc_state_fut)
                .await
            else {
                tracing::debug!("NFC handler cancelled, stopping processing");
                break Ok(());
            };

            // Guard: inner future may have raced the cancellation token and returned
            // RequestCancelled. Break cleanly without emitting a spurious Failed state.
            if matches!(
                next_nfc_state,
                Err(CredentialServiceError::RequestCancelled)
            ) {
                tracing::debug!("NFC handler cancelled (inner path), stopping processing");
                break Ok(());
            }

            state = next_nfc_state.unwrap_or_else(NfcStateInternal::Failed);

            // Usually, comparing the discriminant is enough, but PinNotSet/NeedsPin
            // can be repeated multiple times with different or the same error reasons
            // (PIN wrong, PIN too short, PIN too long, etc.)
            let state_changed = match (&state, &prev_nfc_state) {
                (NfcStateInternal::PinNotSet { .. }, NfcStateInternal::PinNotSet { .. }) => true,
                (NfcStateInternal::NeedsPin { .. }, NfcStateInternal::NeedsPin { .. }) => true,
                (new_state, old_state) => {
                    std::mem::discriminant(new_state) != std::mem::discriminant(old_state)
                }
            };
            if state_changed {
                tracing::debug!("NFC current state: {state:?}");
                tx.send(state.clone()).await.map_err(|_| {
                    CredentialServiceError::Internal(
                        "NFC state channel receiver closed prematurely".to_string(),
                    )
                })?;
            }

            // Check for terminal states AFTER sending
            match state {
                NfcStateInternal::Completed(_) => break Ok(()),
                NfcStateInternal::Failed(err) => break Err(err),
                _ => {}
            }
        }
    }
}

async fn handle_events(
    cred_request: &CredentialRequest,
    mut device: NfcDevice,
    signal_tx: &Sender<Result<NfcUvMessage, CredentialServiceError>>,
    cancellation: CancellationToken,
) {
    let device_debug = device.to_string();
    match device
        .channel(ChannelSettings {
            persistent_token_store: Some(super::persistent_token_store()),
        })
        .await
    {
        Err(err) => {
            tracing::error!(
                "Failed to open channel to NFC authenticator, cannot receive user verification events: {:?}",
                err
            );
        }
        Ok(mut channel) => {
            let signal_tx2 = signal_tx.clone().downgrade();
            let ux_updates_rx = channel.get_ux_update_receiver();
            tokio::spawn(async move {
                handle_nfc_updates(&signal_tx2, ux_updates_rx).await;
                debug!("Reached end of NFC update task");
            });
            tracing::debug!(
                "Polling for credential from NFC authenticator {}",
                &device_debug
            );

            // Un-awaited async block
            let wait_for_cred_response_fut = async {
                loop {
                    let response = match cred_request {
                        CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request) => {
                            channel
                                .webauthn_make_credential(make_cred_request)
                                .await
                                .map(|response| {
                                    NfcUvMessage::ReceivedCredentials(Box::new(response.into()))
                                })
                        }
                        CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request) => {
                            channel
                                .webauthn_get_assertion(get_cred_request)
                                .await
                                .map(|response| {
                                    NfcUvMessage::ReceivedCredentials(Box::new(response.into()))
                                })
                        }
                    };
                    match response {
                        Ok(response) => {
                            tracing::debug!("Received credential from NFC authenticator");
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
                                "Failed to make/get credential with NFC authenticator: {:?}",
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
                    tracing::debug!("NFC ceremony cancelled, stopping authenticator operation");
                    // Unlike USB, NfcChannelHandle::cancel_ongoing_operation() is a no-op
                    // because libwebauthn drops _handle_rx in NfcChannel::new(). Cancellation
                    // takes effect at the next inter-APDU .await point when the future is
                    // dropped; NFC exchanges are short so the latency is acceptable.
                    Err(CredentialServiceError::RequestCancelled)
                }
            };

            if let Err(err) = signal_tx.send(response).await {
                tracing::error!("Failed to notify that ceremony completed: {:?}", err);
            }
        }
    }
}

impl NfcHandler for InProcessNfcHandler {
    fn start(
        &self,
        request: &CredentialRequest,
        cancellation: CancellationToken,
    ) -> impl Stream<Item = NfcEvent> + Send + Sized + Unpin + 'static {
        let request = request.clone();
        let (tx, mut rx) = mpsc::channel(32);
        tokio::spawn(async move {
            // TODO: instead of logging error here, push the errors into the
            // stream so credential service can handle/forward them to the UI
            if let Err(err) = InProcessNfcHandler::process(tx, request, cancellation).await {
                tracing::error!("Error getting credential from NFC: {:?}", err);
            }
        });
        Box::pin(stream! {
            while let Some(state) = rx.recv().await {
                yield NfcEvent { state }
            }
        })
    }
}

// this exists to prevent making NfcStateInternal type public to the whole crate.
/// A message between NFC handler and credential service
#[expect(unused)]
pub struct NfcEvent {
    pub(super) state: NfcStateInternal,
}

/// Used to share internal state between handler and credential service
#[expect(unused)]
#[derive(Clone, Debug, Default)]
pub(super) enum NfcStateInternal {
    /// Not polling for FIDO NFC device.
    #[default]
    Idle,

    /// Awaiting FIDO NFC device to be plugged in.
    Waiting,

    /// NFC device connected, prompt user to tap
    Connected(NfcDevice),

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
    NeedsUserVerification { attempts_left: Option<u32> },

    /// Multiple credentials have been found and the user has to select which to use
    SelectCredential {
        response: GetAssertionResponse,
        cred_tx: mpsc::Sender<String>,
    },

    /// NFC tapped, received credential
    Completed(CredentialResponse),

    /// There was an error while interacting with the authenticator.
    Failed(CredentialServiceError),
}

/// Used to share public state between  credential service and UI.
#[derive(Clone, Debug, Default)]
pub enum NfcState {
    /// Not polling for FIDO NFC device.
    #[default]
    Idle,

    /// Awaiting FIDO NFC device to be plugged in.
    Waiting,

    /// NFC device connected, prompt user to tap
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
    NeedsUserVerification { attempts_left: Option<u32> },

    // Multiple credentials have been found and the user has to select which to use
    // List of user-identities to decide which to use.
    SelectingCredential {
        creds: Vec<Credential>,
        cred_tx: mpsc::Sender<String>,
    },

    /// NFC tapped, received credential
    Completed,

    /// Interaction with the authenticator failed.
    Failed(CredentialServiceError),
}

impl From<NfcStateInternal> for NfcState {
    fn from(value: NfcStateInternal) -> Self {
        match value {
            NfcStateInternal::Idle => NfcState::Idle,
            NfcStateInternal::Waiting => NfcState::Waiting,
            NfcStateInternal::Connected(_) => NfcState::Connected,
            NfcStateInternal::NeedsPin {
                attempts_left,
                pin_tx,
            } => NfcState::NeedsPin {
                attempts_left,
                pin_tx,
            },
            NfcStateInternal::PinNotSet { reason, pin_tx } => {
                NfcState::PinNotSet { reason, pin_tx }
            }
            NfcStateInternal::NeedsUserVerification { attempts_left } => {
                NfcState::NeedsUserVerification { attempts_left }
            }
            NfcStateInternal::Completed(_) => NfcState::Completed,
            NfcStateInternal::SelectCredential { response, cred_tx } => {
                NfcState::SelectingCredential {
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
            NfcStateInternal::Failed(err) => NfcState::Failed(err),
        }
    }
}

impl From<&NfcState> for BackgroundEvent {
    fn from(value: &NfcState) -> Self {
        match value {
            NfcState::Idle => BackgroundEvent::NfcIdle,
            NfcState::Waiting => BackgroundEvent::NfcWaiting,
            NfcState::Connected => BackgroundEvent::NfcConnected,
            NfcState::NeedsPin { attempts_left, .. } => BackgroundEvent::NeedsPin {
                attempts_left: *attempts_left,
            },
            NfcState::PinNotSet { reason, .. } => {
                let error = match reason {
                    PinNotSetReason::PinNotSet => PinNotSetError::PinNotSet,
                    PinNotSetReason::PinTooShort => PinNotSetError::PinTooShort,
                    PinNotSetReason::PinTooLong => PinNotSetError::PinTooLong,
                    PinNotSetReason::PinPolicyViolation => PinNotSetError::PinPolicyViolation,
                    PinNotSetReason::PinChangeRequired => PinNotSetError::PinChangeRequired,
                };
                BackgroundEvent::PinNotSet { error }
            }
            NfcState::NeedsUserVerification { attempts_left } => {
                BackgroundEvent::NeedsUserVerification {
                    attempts_left: *attempts_left,
                }
            }
            NfcState::SelectingCredential { creds, .. } => BackgroundEvent::SelectingCredential {
                creds: creds.to_vec(),
            },
            NfcState::Completed => BackgroundEvent::CeremonyCompleted,
            NfcState::Failed(CredentialServiceError::AuthenticatorError) => {
                BackgroundEvent::ErrorAuthenticator
            }
            NfcState::Failed(CredentialServiceError::NoCredentials) => {
                BackgroundEvent::ErrorNoCredentials
            }
            NfcState::Failed(CredentialServiceError::CredentialExcluded) => {
                BackgroundEvent::ErrorCredentialExcluded
            }
            NfcState::Failed(CredentialServiceError::PinAttemptsExhausted) => {
                BackgroundEvent::ErrorAuthenticator
            }
            NfcState::Failed(CredentialServiceError::RequestCancelled) => {
                BackgroundEvent::ErrorCancelled
            }
            NfcState::Failed(CredentialServiceError::Internal(_)) => BackgroundEvent::ErrorInternal,
        }
    }
}

async fn handle_nfc_updates(
    signal_tx: &WeakSender<Result<NfcUvMessage, CredentialServiceError>>,
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
                    .send(Ok(NfcUvMessage::NeedsUserVerification { attempts_left }))
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
                    .send(Ok(NfcUvMessage::NeedsPin {
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
                    .send(Ok(NfcUvMessage::PinNotSet {
                        pin_tx,
                        reason: pin_update.reason,
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
                tracing::debug!(
                    "Authenticator requested user presence, but that makes no sense for NFC. Skipping"
                );
            }
        }
    }
    debug!("NFC update channel closed.");
}

/// Messages sent between NFC authenticator and handler for UV
enum NfcUvMessage {
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
    ReceivedCredentials(Box<AuthenticatorResponse>),
}
