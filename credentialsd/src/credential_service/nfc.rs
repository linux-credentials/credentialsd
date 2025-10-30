use std::time::Duration;

use async_stream::stream;
use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_lite::Stream;
use libwebauthn::{
    ops::webauthn::GetAssertionResponse,
    proto::CtapError,
    transport::{nfc::device::NfcDevice, Channel, Device},
    webauthn::{Error as WebAuthnError, WebAuthn},
    UvUpdate,
};
use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, Receiver, Sender, WeakSender};
use tracing::{debug, warn};

use credentialsd_common::model::{
    Credential, CredentialRequest, Error, GetAssertionResponseInternal,
};

use super::{AuthenticatorResponse, CredentialResponse};

pub(crate) trait NfcHandler {
    fn start(
        &self,
        request: &CredentialRequest,
    ) -> impl Stream<Item = NfcEvent> + Send + Sized + Unpin + 'static;
}

#[derive(Debug)]
pub struct InProcessNfcHandler {}

impl InProcessNfcHandler {
    async fn process_idle_waiting(
        failures: &mut usize,
        prev_nfc_state: &NfcStateInternal,
    ) -> Result<NfcStateInternal, Error> {
        match libwebauthn::transport::nfc::get_nfc_device().await {
            Ok(None) => Ok(NfcStateInternal::Waiting),
            Ok(Some(hid_device)) => Ok(NfcStateInternal::Connected(hid_device)),
            Err(err) => {
                *failures += 1;
                if *failures == 5 {
                    Err(Error::Internal(format!(
                        "Failed to list NFC authenticators: {:?}. Cancelling NFC state updates.",
                        err
                    )))
                } else {
                    tracing::warn!(
                        "Failed to list NFC authenticators: {:?}. Throttling NFC state updates",
                        err
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok(prev_nfc_state.clone())
                }
            }
        }
    }

    async fn process_select_credential(
        response: GetAssertionResponse,
        cred_rx: &mut Receiver<String>,
    ) -> Result<NfcStateInternal, Error> {
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
                    None => Err(Error::NoCredentials),
                }
            }
            None => {
                tracing::debug!("cred channel closed before receiving cred from client.");
                Err(Error::Internal(
                    "Cred channel disconnected prematurely".to_string(),
                ))
            }
        }
    }

    async fn process_user_interaction(
        signal_rx: &mut Receiver<Result<NfcUvMessage, Error>>,
        cred_tx: &Sender<String>,
    ) -> Result<NfcStateInternal, Error> {
        match signal_rx.recv().await {
            Some(msg) => match msg {
                Ok(NfcUvMessage::NeedsPin {
                    attempts_left,
                    pin_tx,
                }) => Ok(NfcStateInternal::NeedsPin {
                    attempts_left,
                    pin_tx,
                }),
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
            None => Err(Error::Internal("NFC UV handler channel closed".to_string())),
        }
    }

    async fn process(
        tx: Sender<NfcStateInternal>,
        cred_request: CredentialRequest,
    ) -> Result<(), Error> {
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
            let next_nfc_state = match prev_nfc_state {
                NfcStateInternal::Idle | NfcStateInternal::Waiting => {
                    Self::process_idle_waiting(&mut failures, &prev_nfc_state).await
                }
                NfcStateInternal::Connected(device) => {
                    let signal_tx2 = signal_tx.clone();
                    let cred_request = cred_request.clone();
                    tokio::spawn(async move {
                        handle_events(&cred_request, device, &signal_tx2).await;
                    });
                    Self::process_user_interaction(&mut signal_rx, &cred_tx).await
                }
                NfcStateInternal::NeedsPin { .. }
                | NfcStateInternal::NeedsUserVerification { .. } => {
                    Self::process_user_interaction(&mut signal_rx, &cred_tx).await
                }
                NfcStateInternal::SelectCredential {
                    response,
                    cred_tx: _,
                } => Self::process_select_credential(response, &mut cred_rx).await,
                NfcStateInternal::Completed(_) => break Ok(()),
                NfcStateInternal::Failed(err) => break Err(err),
            };
            state = next_nfc_state.unwrap_or_else(NfcStateInternal::Failed);
            tx.send(state.clone()).await.map_err(|_| {
                Error::Internal("NFC state channel receiver closed prematurely".to_string())
            })?;
        }
    }
}

async fn handle_events(
    cred_request: &CredentialRequest,
    mut device: NfcDevice,
    signal_tx: &Sender<Result<NfcUvMessage, Error>>,
) {
    let device_debug = device.to_string();
    match device.channel().await {
        Err(err) => {
            tracing::error!("Failed to open channel to NFC authenticator, cannot receive user verification events: {:?}", err);
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
            let response: Result<NfcUvMessage, Error> = loop {
                let response = match cred_request {
                    CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request) => {
                        channel
                            .webauthn_make_credential(make_cred_request)
                            .await
                            .map(|response| {
                                NfcUvMessage::ReceivedCredentials(Box::new(response.into()))
                            })
                    }
                    CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request) => channel
                        .webauthn_get_assertion(get_cred_request)
                        .await
                        .map(|response| {
                            NfcUvMessage::ReceivedCredentials(Box::new(response.into()))
                        }),
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
                WebAuthnError::Ctap(CtapError::PINAuthBlocked) => Error::PinAttemptsExhausted,
                WebAuthnError::Ctap(CtapError::NoCredentials) => Error::NoCredentials,
                WebAuthnError::Ctap(CtapError::CredentialExcluded) => Error::CredentialExcluded,
                _ => Error::AuthenticatorError,
            });
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
    ) -> impl Stream<Item = NfcEvent> + Send + Sized + Unpin + 'static {
        let request = request.clone();
        let (tx, mut rx) = mpsc::channel(32);
        tokio::spawn(async move {
            // TODO: instead of logging error here, push the errors into the
            // stream so credential service can handle/forward them to the UI
            if let Err(err) = InProcessNfcHandler::process(tx, request).await {
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
pub struct NfcEvent {
    pub(super) state: NfcStateInternal,
}

/// Used to share internal state between handler and credential service
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
    Failed(Error),
    // TODO: implement cancellation
    // This isn't actually sent from the server.
    //UserCancelled,
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

    /// The device needs on-device user verification.
    NeedsUserVerification { attempts_left: Option<u32> },
    // TODO: implement cancellation
    // This isn't actually sent from the server.
    //UserCancelled,

    // Multiple credentials have been found and the user has to select which to use
    // List of user-identities to decide which to use.
    SelectCredential {
        creds: Vec<Credential>,
        cred_tx: mpsc::Sender<String>,
    },

    /// NFC tapped, received credential
    Completed,

    /// Interaction with the authenticator failed.
    Failed(Error),
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
            NfcStateInternal::NeedsUserVerification { attempts_left } => {
                NfcState::NeedsUserVerification { attempts_left }
            }
            NfcStateInternal::Completed(_) => NfcState::Completed,
            // NfcStateInternal::UserCancelled => NfcState:://UserCancelled,
            NfcStateInternal::SelectCredential { response, cred_tx } => {
                NfcState::SelectCredential {
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

impl From<NfcState> for credentialsd_common::model::NfcState {
    fn from(value: NfcState) -> Self {
        Self::from(&value)
    }
}
impl From<&NfcState> for credentialsd_common::model::NfcState {
    fn from(value: &NfcState) -> Self {
        match value {
            NfcState::Idle => credentialsd_common::model::NfcState::Idle,
            NfcState::Waiting => credentialsd_common::model::NfcState::Waiting,
            NfcState::Connected => credentialsd_common::model::NfcState::Connected,
            NfcState::NeedsPin { attempts_left, .. } => {
                credentialsd_common::model::NfcState::NeedsPin {
                    attempts_left: *attempts_left,
                }
            }
            NfcState::NeedsUserVerification { attempts_left } => {
                credentialsd_common::model::NfcState::NeedsUserVerification {
                    attempts_left: *attempts_left,
                }
            }
            NfcState::SelectCredential { creds, .. } => {
                credentialsd_common::model::NfcState::SelectCredential {
                    creds: creds.to_owned(),
                }
            }
            NfcState::Completed => credentialsd_common::model::NfcState::Completed,
            NfcState::Failed(err) => credentialsd_common::model::NfcState::Failed(err.to_owned()),
        }
    }
}

async fn handle_nfc_updates(
    signal_tx: &WeakSender<Result<NfcUvMessage, Error>>,
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
                    tracing::error!("Authenticator requested user verficiation, but we cannot relay the message to credential service: {:?}", err);
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
                    tracing::error!("Authenticator requested a PIN from the user, but we cannot relay the message to the credential service: {:?}", err);
                }
                match pin_rx.recv().await {
                    Some(pin) => match pin_update.send_pin(&pin) {
                        Ok(()) => {}
                        Err(err) => tracing::error!("Error sending pin to device: {:?}", err),
                    },
                    None => tracing::debug!("Pin channel closed before receiving pin from client."),
                }
            }
            UvUpdate::PresenceRequired => {
                tracing::debug!("Authenticator requested user presence, but that makes no sense for NFC. Skipping");
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
    NeedsUserVerification {
        attempts_left: Option<u32>,
    },
    ReceivedCredentials(Box<AuthenticatorResponse>),
}
