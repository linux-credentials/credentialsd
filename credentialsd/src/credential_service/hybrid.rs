use core::panic;
use std::fmt::Debug;

use async_stream::stream;
use futures_lite::Stream;
use libwebauthn::{
    proto::CtapError,
    transport::{
        Channel, ChannelSettings, Device,
        cable::{
            channel::{CableUpdate, CableUxUpdate},
            qr_code_device::{CableQrCodeDevice, CableTransports, QrCodeOperationHint},
        },
    },
    webauthn::{WebAuthn, error::WebAuthnError},
};
use tokio::sync::{
    broadcast,
    mpsc::{self, Sender},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use super::CredentialServiceError;
use credentialsd_common::{memfd::write_secret, model::BackgroundEvent};

use crate::model::{CredentialRequest, CredentialResponse};

pub(crate) trait HybridHandler {
    fn start(
        &self,
        request: &CredentialRequest,
        cancellation: CancellationToken,
    ) -> impl Stream<Item = HybridEvent> + Unpin + Send + Sized + 'static;
}

#[derive(Debug)]
pub struct InternalHybridHandler {}
impl InternalHybridHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl HybridHandler for InternalHybridHandler {
    fn start(
        &self,
        request: &CredentialRequest,
        cancellation: CancellationToken,
    ) -> impl Stream<Item = HybridEvent> + Unpin + Send + Sized + 'static {
        tracing::debug!("Starting hybrid operation");
        let request = request.clone();
        let (tx, mut rx) = mpsc::channel(16);
        tokio::spawn(async move {
            let hint = match request {
                CredentialRequest::CreatePublicKeyCredentialRequest(_) => {
                    QrCodeOperationHint::MakeCredential
                }
                CredentialRequest::GetPublicKeyCredentialRequest(_) => {
                    QrCodeOperationHint::GetAssertionRequest
                }
            };
            let hybrid_transports = if std::env::var("CREDSD_ENABLE_HYBRID_BLE_TRANSPORT")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or_default()
            {
                CableTransports::CloudAssistedOrLocal
            } else {
                CableTransports::CloudAssistedOnly
            };

            // Outer retry loop: re-issues QR on non-terminating failures.
            // Each iteration creates a fresh CableQrCodeDevice (the previous one
            // is consumed by channel()), so the old QR secret is discarded.
            loop {
                let mut device = match CableQrCodeDevice::new_transient(hint, hybrid_transports) {
                    Ok(device) => device,
                    Err(err) => {
                        tracing::error!("Failed to create caBLE QR code device: {:?}", err);
                        // Device creation failure cannot be retried meaningfully —
                        // break to avoid a tight error loop.
                        let _ = tx
                            .send(HybridStateInternal::Failed(
                                CredentialServiceError::Internal(format!(
                                    "Failed to create caBLE device: {err:?}"
                                )),
                            ))
                            .await;
                        break;
                    }
                };

                let qr_code = device.qr_code.to_string();
                if let Err(err) = tx.send(HybridStateInternal::Init(qr_code)).await {
                    tracing::error!("Failed to send caBLE update: {:?}", err);
                    break;
                }

                // Run the ceremony awaited directly (not in a nested spawn) so that
                // the retry loop is sequential and no orphaned tasks can arise.
                let response =
                    run_hybrid_ceremony(&mut device, &request, &tx, cancellation.clone()).await;

                match response {
                    Ok(auth_response) => {
                        let _ = tx.send(HybridStateInternal::Completed(auth_response)).await;
                        break;
                    }
                    Err(err) if super::is_ceremony_terminating(&err) => {
                        // Terminating errors (CredentialExcluded, NonTerminatingCancellation
                        // from a winning transport, etc.) stop the loop.
                        // NonTerminatingCancellation exits silently; others surface as Failed.
                        if !matches!(err, CredentialServiceError::NonTerminatingCancellation) {
                            let _ = tx.send(HybridStateInternal::Failed(err)).await;
                        } else {
                            tracing::debug!("Hybrid handler cancelled, exiting silently");
                        }
                        break;
                    }
                    Err(err) => {
                        // Non-terminating: notify the UI that a restart is in progress
                        // so it can navigate back to the start page, then reissue a
                        // fresh QR on the next iteration.
                        tracing::warn!(?err, "Hybrid error, reissuing QR");
                        let _ = tx.send(HybridStateInternal::Restarting).await;
                        continue;
                    }
                }
            }
        });
        Box::pin(stream! {
            while let Some(state) = rx.recv().await {
                yield HybridEvent { state }
            }
        })
    }
}

/// Used to communicate privileged state between handler and credential service.
#[derive(Clone, Debug)]
pub(super) enum HybridStateInternal {
    /// Awaiting BLE advert from phone. Content is the FIDO string to be
    /// displayed to the user, which contains QR secret and public key.
    Init(String),

    /// BLE advertisement has been received from phone, tunnel is being established
    Connecting,

    /// Hybrid tunnel has been established
    Connected,

    /// Authenticator data
    Completed(CredentialResponse),

    Failed(CredentialServiceError),

    /// The ceremony was interrupted by a non-terminating error. A fresh QR code
    /// is about to be issued on the next iteration.
    Restarting,
}

// this is here to prevent making HybridStateInternal public to the whole crate.
/// Messages between hybrid handler and credential service.
pub struct HybridEvent {
    pub(super) state: HybridStateInternal,
}

/// Used to communicate privileged state between credential service and UI.
#[derive(Clone, Debug)]
pub enum HybridState {
    /// Awaiting BLE advert from phone. Content is the FIDO string to be displayed to the user, which contains QR secret
    /// and public key.
    Init(String),

    /// BLE advertisement has been received from phone, tunnel is being established
    Connecting,

    /// Tunnel is established, waiting for user to release credential on their device.
    Connected,

    /// Authenticator data has been received
    Completed,

    /// Hybrid operation failed.
    Failed(CredentialServiceError),

    /// The ceremony was interrupted by a non-terminating error and a new QR
    /// code is being issued. The UI should navigate back to the start page.
    Restarting,
}

impl From<HybridStateInternal> for HybridState {
    fn from(value: HybridStateInternal) -> Self {
        match value {
            HybridStateInternal::Init(qr_code) => HybridState::Init(qr_code),
            HybridStateInternal::Connecting => HybridState::Connecting,
            HybridStateInternal::Connected => HybridState::Connected,
            HybridStateInternal::Completed(_) => HybridState::Completed,
            HybridStateInternal::Failed(err) => HybridState::Failed(err),
            HybridStateInternal::Restarting => HybridState::Restarting,
        }
    }
}

impl From<&HybridState> for BackgroundEvent {
    fn from(value: &HybridState) -> Self {
        match value {
            HybridState::Init(qr_code) => {
                let fd = match write_secret(qr_code.clone().into_bytes()) {
                    Ok(fd) => fd,
                    Err(err) => {
                        tracing::error!(%err, "Failed to write QR code secret");
                        panic!("Failed to write QR code secret");
                    }
                };
                BackgroundEvent::HybridStarted(fd.into())
            }

            HybridState::Connecting => BackgroundEvent::HybridConnecting,
            HybridState::Connected => BackgroundEvent::HybridConnected,
            HybridState::Completed => BackgroundEvent::CeremonyCompleted,
            HybridState::Restarting => BackgroundEvent::HybridRestarting,
            HybridState::Failed(CredentialServiceError::AuthenticatorError) => {
                BackgroundEvent::ErrorAuthenticator
            }
            HybridState::Failed(CredentialServiceError::NoCredentials) => {
                BackgroundEvent::ErrorNoCredentials
            }
            HybridState::Failed(CredentialServiceError::CredentialExcluded) => {
                BackgroundEvent::ErrorCredentialExcluded
            }
            HybridState::Failed(CredentialServiceError::PinAttemptsExhausted) => {
                BackgroundEvent::ErrorAuthenticator
            }
            // This should currently never be reached, but we'll likely use it in future refactoring
            HybridState::Failed(CredentialServiceError::NonTerminatingCancellation) => {
                BackgroundEvent::ErrorCancelled
            }
            HybridState::Failed(CredentialServiceError::Internal(_)) => {
                BackgroundEvent::ErrorInternal
            }
        }
    }
}

/// Runs a single hybrid ceremony attempt: opens the caBLE channel, spawns the UX
/// update forwarder, and drives the `webauthn_make_credential` / `webauthn_get_assertion`
/// retry loop until a terminal result or cancellation.
///
/// Returns `Ok(CredentialResponse)` on success, or `Err(CredentialServiceError)` on
/// failure. `NonTerminatingCancellation` is returned when the cancellation token fires.
async fn run_hybrid_ceremony(
    device: &mut CableQrCodeDevice,
    request: &CredentialRequest,
    tx: &Sender<HybridStateInternal>,
    cancellation: CancellationToken,
) -> Result<CredentialResponse, CredentialServiceError> {
    let mut channel = match device.channel(ChannelSettings::default()).await {
        Ok(channel) => channel,
        Err(e) => {
            tracing::error!("Failed to open hybrid channel: {:?}", e);
            return Err(CredentialServiceError::AuthenticatorError);
        }
    };

    let state_sender_clone = tx.clone();
    let ux_updates_rx = channel.get_ux_update_receiver();
    tokio::spawn(async move {
        handle_hybrid_updates(&state_sender_clone, ux_updates_rx).await;
        debug!("Reached end of Hybrid updates stream.");
    });

    let wait_for_response_fut = async {
        loop {
            let response: Result<CredentialResponse, _> = match request {
                CredentialRequest::CreatePublicKeyCredentialRequest(make_request) => {
                    channel.webauthn_make_credential(make_request).await.map(
                        |make_credential_response| {
                            CredentialResponse::from_make_credential(
                                &make_credential_response,
                                &["hybrid"],
                                "cross-platform",
                            )
                        },
                    )
                }
                CredentialRequest::GetPublicKeyCredentialRequest(get_request) => {
                    channel.webauthn_get_assertion(get_request).await.map(
                        |get_assertion_response| {
                            CredentialResponse::from_get_assertion(
                                // When doing hybrid, the authenticator is capable of
                                // displaying its own UI, so we assume it only ever
                                // returns one assertion. If this doesn't hold true,
                                // credential selection must be implemented here, as
                                // done for USB.
                                &get_assertion_response.assertions[0],
                                "cross-platform",
                            )
                        },
                    )
                }
            };
            match response {
                Ok(response) => {
                    tracing::debug!("Received credential from hybrid authenticator");
                    break Ok(response);
                }
                Err(WebAuthnError::Ctap(ctap_error)) if ctap_error.is_retryable_user_error() => {
                    tracing::debug!(%ctap_error, "Retrying WebAuthn operation");
                    continue;
                }
                Err(err) => {
                    tracing::error!(%err, "Failed to make/get credential with hybrid authenticator");
                    break Err(err);
                }
            }
        }
        .map_err(|err| match err {
            WebAuthnError::Ctap(CtapError::PINAuthBlocked) => {
                CredentialServiceError::PinAttemptsExhausted
            }
            WebAuthnError::Ctap(CtapError::NoCredentials) => CredentialServiceError::NoCredentials,
            WebAuthnError::Ctap(CtapError::CredentialExcluded) => {
                CredentialServiceError::CredentialExcluded
            }
            _ => CredentialServiceError::AuthenticatorError,
        })
    };

    tracing::debug!("Polling hybrid channel for updates.");
    match cancellation
        .run_until_cancelled(wait_for_response_fut)
        .await
    {
        Some(resp) => resp,
        None => {
            tracing::debug!("Hybrid handler cancelled, stopping processing");
            Err(CredentialServiceError::NonTerminatingCancellation)
        }
    }
}

async fn handle_hybrid_updates(
    state_sender: &Sender<HybridStateInternal>,
    mut ux_update_receiver: broadcast::Receiver<CableUxUpdate>,
) {
    while let Ok(msg) = ux_update_receiver.recv().await {
        debug!(?msg, "Received hybrid update");
        let new_state: Option<HybridStateInternal> = match msg {
            CableUxUpdate::UvUpdate(uv_update) => {
                error!(
                    "Received unexpected UV update in hybrid handler: {:?}",
                    uv_update
                );
                None
            }
            CableUxUpdate::CableUpdate(cable_update) => match cable_update {
                CableUpdate::ProximityCheck => None,
                CableUpdate::Connecting => Some(HybridStateInternal::Connecting),
                CableUpdate::Authenticating => Some(HybridStateInternal::Connecting),
                CableUpdate::Connected => Some(HybridStateInternal::Connected),
                CableUpdate::Error(transport_error) => {
                    error!(?transport_error, "Hybrid transport error");
                    Some(HybridStateInternal::Failed(
                        CredentialServiceError::AuthenticatorError,
                    ))
                }
            },
        };
        if let Some(state) = new_state
            && let Err(err) = state_sender.send(state.clone()).await
        {
            error!({ ?err, ?state }, "Failed to send hybrid update");
        }
    }
}
