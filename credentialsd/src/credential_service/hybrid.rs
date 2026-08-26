use core::panic;
use std::fmt::Debug;

use async_stream::stream;
use futures_lite::Stream;
use tokio::sync::{
    broadcast,
    mpsc::{self, Sender},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use libwebauthn::transport::cable::qr_code_device::{
    CableQrCodeDevice, CableTransports, QrCodeOperationHint,
};
use libwebauthn::transport::{Channel, ChannelSettings, Device};
use libwebauthn::webauthn::{WebAuthn, error::WebAuthnError};
use libwebauthn::{
    proto::CtapError,
    transport::cable::channel::{CableUpdate, CableUxUpdate},
};

use credentialsd_common::{
    memfd::write_secret,
    model::{BackgroundEvent, Error},
};

use crate::model::CredentialRequest;

use super::AuthenticatorResponse;

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
            let mut device = match CableQrCodeDevice::new_transient(hint, hybrid_transports) {
                Ok(device) => device,
                Err(err) => {
                    tracing::error!("Failed to create caBLE QR code device: {:?}", err);
                    return;
                }
            };
            let qr_code = device.qr_code.to_string();
            if let Err(err) = tx.send(HybridStateInternal::Init(qr_code)).await {
                tracing::error!("Failed to send caBLE update: {:?}", err);
                return;
            };
            tokio::spawn(async move {
                let mut channel = match device.channel(ChannelSettings::default()).await {
                    Ok(channel) => channel,
                    Err(e) => {
                        tracing::error!("Failed to open hybrid channel: {:?}", e);
                        panic!();
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
                        let response: Result<AuthenticatorResponse, _> = match &request {
                            CredentialRequest::CreatePublicKeyCredentialRequest(make_request) => {
                                channel
                                    .webauthn_make_credential(make_request)
                                    .await
                                    .map(|response| response.into())
                            }
                            CredentialRequest::GetPublicKeyCredentialRequest(get_request) => {
                                channel
                                    .webauthn_get_assertion(get_request)
                                    .await
                                    .map(|response| response.into())
                            }
                        };
                        match response {
                            Ok(response) => {
                                tracing::debug!("Received credential from hybrid authenticator");
                                break Ok(response);
                            }
                            Err(WebAuthnError::Ctap(ctap_error))
                                if ctap_error.is_retryable_user_error() =>
                            {
                                tracing::debug!(%ctap_error, "Retrying WebAuthn operation");
                                continue;
                            }
                            Err(err) => {
                                tracing::error!(%err,
                                    "Failed to make/get credential with hybrid authenticator"
                                );
                                break Err(err);
                            }
                        }
                    }
                    .map_err(|err| match err {
                        WebAuthnError::Ctap(CtapError::PINAuthBlocked) => {
                            Error::PinAttemptsExhausted
                        }
                        WebAuthnError::Ctap(CtapError::NoCredentials) => Error::NoCredentials,
                        WebAuthnError::Ctap(CtapError::CredentialExcluded) => {
                            Error::CredentialExcluded
                        }
                        _ => Error::AuthenticatorError,
                    })
                };

                tracing::debug!("Polling hybrid channel for updates.");
                let response = match cancellation
                    .run_until_cancelled(wait_for_response_fut)
                    .await
                {
                    Some(resp) => resp,
                    None => {
                        tracing::debug!("Hybrid handler cancelled, stopping processing");
                        Err(Error::Internal("Request cancelled".to_string()))
                    }
                };

                let terminal_state = match response {
                    Ok(auth_response) => HybridStateInternal::Completed(Box::new(auth_response)),
                    Err(_) => HybridStateInternal::Failed,
                };
                if let Err(err) = tx.send(terminal_state).await {
                    tracing::error!("Failed to send caBLE update: {:?}", err)
                }
            });
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
    Completed(Box<AuthenticatorResponse>),

    Failed,
    // TODO(cancellation)
    // This isn't actually sent from the server.
    #[allow(dead_code)]
    UserCancelled,
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
    Failed,

    // This isn't actually sent from the server.
    UserCancelled,
}

impl From<HybridStateInternal> for HybridState {
    fn from(value: HybridStateInternal) -> Self {
        match value {
            HybridStateInternal::Init(qr_code) => HybridState::Init(qr_code),
            HybridStateInternal::Connecting => HybridState::Connecting,
            HybridStateInternal::Connected => HybridState::Connected,
            HybridStateInternal::Completed(_) => HybridState::Completed,
            HybridStateInternal::UserCancelled => HybridState::UserCancelled,
            HybridStateInternal::Failed => HybridState::Failed,
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
            HybridState::UserCancelled => BackgroundEvent::ErrorCancelled,
            HybridState::Failed => BackgroundEvent::ErrorAuthenticator,
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
                    Some(HybridStateInternal::Failed)
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
