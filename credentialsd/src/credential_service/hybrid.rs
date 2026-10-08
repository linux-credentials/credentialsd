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
use credentialsd_common::{
    memfd::write_secret,
    model::{BackgroundEvent, TransportRestartReason},
};

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
            // Consecutive failures before the phone connected; reset once it does.
            let mut pre_active_failures = 0;
            loop {
                // Reset the active flag for each ceremony attempt. run_hybrid_ceremony
                // sets it if libwebauthn reported the phone's BLE advert
                // (`CableUpdate::Connecting`), i.e. the QR code was scanned.
                let mut active = false;

                let mut device = match CableQrCodeDevice::new_transient(hint, hybrid_transports) {
                    Ok(device) => device,
                    Err(err) => {
                        tracing::error!("Failed to create caBLE QR code device: {:?}", err);
                        // Device creation failure cannot be retried meaningfully —
                        // give up on hybrid for this request; other transports go on.
                        let _ = tx
                            .send(HybridStateInternal::Failed(
                                CredentialServiceError::UnrecoverableTransportError,
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
                let response = run_hybrid_ceremony(
                    &mut device,
                    &request,
                    &tx,
                    cancellation.clone(),
                    &mut active,
                )
                .await;

                match response {
                    Ok(auth_response) => {
                        let _ = tx.send(HybridStateInternal::Completed(auth_response)).await;
                        break;
                    }
                    // Must come before is_ceremony_terminating(), which returns false for
                    // cancellation (poll_next must not complete_request() twice).
                    Err(CredentialServiceError::NonTerminatingCancellation) => {
                        tracing::debug!("Hybrid handler cancelled, exiting silently");
                        break;
                    }
                    Err(err) if super::is_ceremony_terminating(&err) => {
                        let _ = tx.send(HybridStateInternal::Failed(err)).await;
                        break;
                    }
                    Err(err) => {
                        if active {
                            // Post-active: the phone was engaged — surface the error
                            // via the Restarting signal so the UI navigates back to
                            // start_page, then reissue a fresh QR.
                            let reason = match err {
                                CredentialServiceError::NoCredentials => {
                                    TransportRestartReason::NoCredentials
                                }
                                CredentialServiceError::PinAttemptsExhausted => {
                                    TransportRestartReason::PinAttemptsExhausted
                                }
                                _ => TransportRestartReason::Interrupted,
                            };
                            tracing::warn!(?err, "Hybrid post-active error, reissuing QR");
                            let _ = tx.send(HybridStateInternal::Restarting(reason)).await;
                            pre_active_failures = 0;
                        } else {
                            // Pre-active: the attempt failed before the phone's BLE advert
                            // arrived (e.g. the advert scan itself failed). Reissue
                            // silently, but give up after MAX_PRE_ACTIVE_FAILURES in a row.
                            pre_active_failures += 1;
                            if pre_active_failures >= super::MAX_PRE_ACTIVE_FAILURES {
                                tracing::warn!(
                                    ?err,
                                    "Hybrid failed {pre_active_failures} times before the phone connected, giving up"
                                );
                                let _ = tx
                                    .send(HybridStateInternal::Failed(
                                        CredentialServiceError::UnrecoverableTransportError,
                                    ))
                                    .await;
                                break;
                            }
                            tracing::debug!(?err, "Hybrid pre-active error, reissuing QR silently");
                        }
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
    Restarting(TransportRestartReason),
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
    Restarting(TransportRestartReason),
}

impl From<HybridStateInternal> for HybridState {
    fn from(value: HybridStateInternal) -> Self {
        match value {
            HybridStateInternal::Init(qr_code) => HybridState::Init(qr_code),
            HybridStateInternal::Connecting => HybridState::Connecting,
            HybridStateInternal::Connected => HybridState::Connected,
            HybridStateInternal::Completed(_) => HybridState::Completed,
            HybridStateInternal::Failed(err) => HybridState::Failed(err),
            HybridStateInternal::Restarting(reason) => HybridState::Restarting(reason),
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
            HybridState::Restarting(reason) => {
                BackgroundEvent::HybridRestarting { reason: *reason }
            }
            HybridState::Failed(CredentialServiceError::AuthenticatorError) => {
                BackgroundEvent::ErrorAuthenticator
            }
            HybridState::Failed(CredentialServiceError::CredentialExcluded) => {
                BackgroundEvent::ErrorCredentialExcluded
            }
            // This should currently never be reached, but we'll likely use it in future refactoring
            HybridState::Failed(CredentialServiceError::NonTerminatingCancellation) => {
                BackgroundEvent::ErrorCancelled
            }
            HybridState::Failed(CredentialServiceError::Internal(_))
            | HybridState::Failed(CredentialServiceError::NoCredentials)
            | HybridState::Failed(CredentialServiceError::PinAttemptsExhausted) => {
                BackgroundEvent::ErrorInternal
            }
            // Hybrid stopped for this request; the UI stops offering it.
            HybridState::Failed(CredentialServiceError::UnrecoverableTransportError) => {
                BackgroundEvent::HybridRestarting {
                    reason: TransportRestartReason::TransportUnavailable,
                }
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
    active: &mut bool,
) -> Result<CredentialResponse, CredentialServiceError> {
    let Some(result) = cancellation
        .run_until_cancelled(device.channel(ChannelSettings::default()))
        .await
    else {
        tracing::debug!("Hybrid handler cancelled while opening channel");
        return Err(CredentialServiceError::NonTerminatingCancellation);
    };
    let mut channel = match result {
        Ok(channel) => channel,
        Err(e) => {
            tracing::error!("Failed to open hybrid channel: {:?}", e);
            return Err(CredentialServiceError::AuthenticatorError);
        }
    };

    // `channel()` returns right away: the proximity check (waiting for the phone's
    // BLE advert), tunnel connection and handshake run in the background. This
    // receiver is drained after the attempt to learn whether the phone engaged.
    let mut progress_rx = channel.get_ux_update_receiver();

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
    let result = match cancellation
        .run_until_cancelled(wait_for_response_fut)
        .await
    {
        Some(resp) => resp,
        None => {
            tracing::debug!("Hybrid handler cancelled, stopping processing");
            Err(CredentialServiceError::NonTerminatingCancellation)
        }
    };
    *active = phone_engaged(&mut progress_rx);
    result
}

/// Whether the phone got past the QR scan in this attempt. libwebauthn reports
/// `Connecting` once it has received the phone's BLE advert, which only happens
/// after the QR code was scanned. Every update sent before the attempt ended is
/// already queued in `rx` when this is called.
fn phone_engaged(rx: &mut broadcast::Receiver<CableUxUpdate>) -> bool {
    while let Ok(update) = rx.try_recv() {
        match update {
            // Before (or without) the phone's BLE advert, e.g. the advert scan failed.
            CableUxUpdate::CableUpdate(CableUpdate::ProximityCheck | CableUpdate::Error(_)) => {}
            // Everything else only happens once the phone's advert arrived.
            _ => return true,
        }
    }
    false
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
                    // Not forwarded: the failed attempt also ends the webauthn call
                    // with an error, which the retry loop handles (restart or give up).
                    error!(?transport_error, "Hybrid transport error");
                    None
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

#[cfg(test)]
mod tests {
    use libwebauthn::transport::cable::error::CableError;

    use super::*;

    fn cable(update: CableUpdate) -> CableUxUpdate {
        CableUxUpdate::CableUpdate(update)
    }

    #[test]
    fn test_phone_engaged() {
        let (tx, mut rx) = broadcast::channel(16);
        tx.send(cable(CableUpdate::ProximityCheck)).unwrap();
        assert!(!phone_engaged(&mut rx), "QR shown, never scanned");

        tx.send(cable(CableUpdate::ProximityCheck)).unwrap();
        tx.send(cable(CableUpdate::Error(CableError::ConnectionFailed)))
            .unwrap();
        assert!(!phone_engaged(&mut rx), "advert scan failed before a scan");

        tx.send(cable(CableUpdate::ProximityCheck)).unwrap();
        tx.send(cable(CableUpdate::Connecting)).unwrap();
        tx.send(cable(CableUpdate::Error(CableError::ConnectionFailed)))
            .unwrap();
        assert!(phone_engaged(&mut rx), "failed after the phone's advert");
    }
}
