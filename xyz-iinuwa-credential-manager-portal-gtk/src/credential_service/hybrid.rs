use core::panic;
use std::fmt::Debug;
use std::sync::Arc;

use crate::credential_service::store::{KnownDevice, KnownDeviceId, KnownHybridDeviceStore};
use crate::dbus::CredentialRequest;
use async_stream::stream;
use futures_lite::Stream;
use libwebauthn::transport::cable::known_devices::{CableKnownDevice, ClientPayloadHint};
use libwebauthn::transport::cable::Cable;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, Sender};
use tracing::{debug, error, instrument};

use libwebauthn::transport::cable::channel::{CableChannel, CableUpdate, CableUxUpdate};
use libwebauthn::transport::cable::qr_code_device::{CableQrCodeDevice, QrCodeOperationHint};
use libwebauthn::transport::{Channel, Device};
use libwebauthn::webauthn::{Error as WebAuthnError, WebAuthn};

use super::{AuthenticatorResponse, Error};

pub(crate) trait HybridHandler {
    fn start(
        &self,
        request: &CredentialRequest,
        known_device_id: Option<KnownDeviceId>,
    ) -> impl Stream<Item = HybridEvent> + Unpin + Send + Sized + 'static;
    fn known_hybrid_devices(&self) -> Arc<KnownHybridDeviceStore>;
}

#[derive(Debug)]
pub struct InternalHybridHandler {
    pub(crate) known_hybrid_devices: Arc<KnownHybridDeviceStore>,
}

impl InternalHybridHandler {
    pub async fn new() -> Self {
        let known_hybrid_devices = KnownHybridDeviceStore::new("known_devices.json")
            .await
            .expect("Failed to open known devices store");
        Self {
            known_hybrid_devices: Arc::new(known_hybrid_devices),
        }
    }
}

impl HybridHandler for InternalHybridHandler {
    fn start(
        &self,
        request: &CredentialRequest,
        known_device_id: Option<KnownDeviceId>,
    ) -> impl Stream<Item = HybridEvent> + Unpin + Send + Sized + 'static {
        debug!("Starting hybrid operation");
        let request = request.clone();
        let (tx, mut rx) = mpsc::channel(16);
        let store = self.known_hybrid_devices();
        tokio::spawn(async move {
            let mut channel: CableChannel = match known_device_id {
                Some(known_device_id) => {
                    let hint = match request {
                        CredentialRequest::CreatePublicKeyCredentialRequest(_) => {
                            ClientPayloadHint::MakeCredential
                        }
                        CredentialRequest::GetPublicKeyCredentialRequest(_) => {
                            ClientPayloadHint::GetAssertion
                        }
                    };
                    let known_device_info = store
                        .get_known_device(&known_device_id)
                        .await
                        .map_err(|_| {
                            error!("Failed to retrieve known devices from store");
                            panic!();
                        })
                        .unwrap()
                        .ok_or_else(|| {
                            error!("No known device found with ID: {:?}", known_device_id);
                            panic!();
                        })
                        .unwrap();
                    let mut device = CableKnownDevice::new(hint, &known_device_info, store.clone())
                        .await
                        .unwrap();
                    device.channel().await.unwrap()
                }
                None => {
                    let hint = match request {
                        CredentialRequest::CreatePublicKeyCredentialRequest(_) => {
                            QrCodeOperationHint::MakeCredential
                        }
                        CredentialRequest::GetPublicKeyCredentialRequest(_) => {
                            QrCodeOperationHint::GetAssertionRequest
                        }
                    };
                    let mut device = CableQrCodeDevice::new_persistent(hint, store);
                    let qr_code: String = device.qr_code.to_string();
                    if let Err(err) = tx.send(HybridStateInternal::Init(qr_code)).await {
                        error!("Failed to send caBLE update: {:?}", err);
                        return;
                    };
                    device.channel().await.unwrap()
                }
            };

            let state_sender_clone = tx.clone();
            let ux_updates_rx = channel.get_ux_update_receiver();
            tokio::spawn(async move {
                handle_hybrid_updates(&state_sender_clone, ux_updates_rx).await;
                debug!("Reached end of Hybrid updates stream.");
            });

            tracing::debug!("Polling hybrid channel for updates.");
            let response: Result<AuthenticatorResponse, Error> = loop {
                match &request {
                    CredentialRequest::CreatePublicKeyCredentialRequest(make_request) => {
                        match channel.webauthn_make_credential(make_request).await {
                            Ok(response) => break Ok(response.into()),
                            Err(WebAuthnError::Ctap(ctap_error)) => {
                                if ctap_error.is_retryable_user_error() {
                                    tracing::debug!("Retrying credential creation operation because of CTAP error: {:?}", ctap_error);
                                    continue;
                                } else {
                                    tracing::error!(
                                        "Received CTAP unrecoverable CTAP error: {:?}",
                                        ctap_error
                                    );
                                    break Err(Error::AuthenticatorError);
                                }
                            }
                            Err(err) => {
                                tracing::error!(
                                    "Received unrecoverable error from authenticator: {:?}",
                                    err
                                );
                                break Err(Error::AuthenticatorError);
                            }
                        };
                    }
                    CredentialRequest::GetPublicKeyCredentialRequest(get_request) => {
                        match channel.webauthn_get_assertion(get_request).await {
                            Ok(response) => break Ok(response.into()),
                            Err(WebAuthnError::Ctap(ctap_error)) => {
                                if ctap_error.is_retryable_user_error() {
                                    tracing::debug!(
                                        "Retrying assertion operation because of CTAP error: {:?}",
                                        ctap_error
                                    );
                                    continue;
                                } else {
                                    tracing::error!(
                                        "Received CTAP unrecoverable CTAP error: {:?}",
                                        ctap_error
                                    );
                                    break Err(Error::AuthenticatorError);
                                }
                            }
                            Err(err) => {
                                tracing::error!(
                                    "Received unrecoverable error from authenticator: {:?}",
                                    err
                                );
                                break Err(Error::AuthenticatorError);
                            }
                        };
                    }
                }
            };
            let terminal_state = match response {
                Ok(auth_response) => HybridStateInternal::Completed(auth_response),
                Err(_) => HybridStateInternal::Failed,
            };
            if let Err(err) = tx.send(terminal_state).await {
                tracing::error!("Failed to send caBLE update: {:?}", err)
            }
        });
        Box::pin(stream! {
            while let Some(state) = rx.recv().await {
                yield HybridEvent { state }
            }
        })
    }

    fn known_hybrid_devices(&self) -> Arc<KnownHybridDeviceStore> {
        self.known_hybrid_devices.clone()
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
    Completed(AuthenticatorResponse),

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
        if let Some(state) = new_state {
            if let Err(err) = state_sender.send(state.clone()).await {
                error!({ ?err, ?state }, "Failed to send hybrid update");
            }
        }
    }
}

#[cfg(test)]
pub(super) mod test {
    use std::task::Poll;

    use futures_lite::Stream;
    use libwebauthn::{
        fido::{AuthenticatorData, AuthenticatorDataFlags},
        ops::webauthn::{Assertion, GetAssertionResponse},
        proto::ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2Transport},
    };

    use crate::dbus::CredentialRequest;

    use super::{HybridEvent, HybridHandler, HybridStateInternal};
    #[derive(Debug)]
    pub struct DummyHybridHandler {
        stream: DummyHybridStateStream,
    }

    impl DummyHybridHandler {
        #[cfg(test)]
        pub fn new(states: Vec<HybridStateInternal>) -> Self {
            Self {
                stream: DummyHybridStateStream { states },
            }
        }
    }

    impl Default for DummyHybridHandler {
        fn default() -> Self {
            Self {
                stream: DummyHybridStateStream::default(),
            }
        }
    }
    impl HybridHandler for DummyHybridHandler {
        fn start(
            &self,
            _request: &CredentialRequest,
        ) -> impl Stream<Item = HybridEvent> + Send + Sized + Unpin + 'static {
            self.stream.clone()
        }
    }

    #[derive(Clone, Debug)]
    pub struct DummyHybridStateStream {
        states: Vec<HybridStateInternal>,
    }

    impl Default for DummyHybridStateStream {
        fn default() -> Self {
            let qr_code = String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332");
            // SHA256("webauthn.io")
            let rp_id_hash = [
                0x74, 0xa6, 0xea, 0x92, 0x13, 0xc9, 0x9c, 0x2f, 0x74, 0xb2, 0x24, 0x92, 0xb3, 0x20,
                0xcf, 0x40, 0x26, 0x2a, 0x94, 0xc1, 0xa9, 0x50, 0xa0, 0x39, 0x7f, 0x29, 0x25, 0xb,
                0x60, 0x84, 0x1e, 0xf0,
            ];

            let auth_data = AuthenticatorData {
                rp_id_hash,
                flags: AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::USER_VERIFIED,
                signature_count: 1,
                attested_credential: None,
                extensions: None,
            };

            let assertion = Assertion {
                credential_id: Some(Ctap2PublicKeyCredentialDescriptor {
                    id: vec![0xca, 0xb1, 0xe].into(),
                    r#type: libwebauthn::proto::ctap2::Ctap2PublicKeyCredentialType::PublicKey,
                    transports: Some(vec![Ctap2Transport::Hybrid]),
                }),
                authenticator_data: auth_data,
                signature: Vec::new(),
                user: None,
                credentials_count: Some(1),
                user_selected: None,
                large_blob_key: None,
                unsigned_extensions_output: None,
                enterprise_attestation: None,
                attestation_statement: None,
            };
            let response = GetAssertionResponse {
                assertions: vec![assertion],
            };
            DummyHybridStateStream {
                states: vec![
                    HybridStateInternal::Init(qr_code),
                    HybridStateInternal::Connecting,
                    HybridStateInternal::Completed(response.into()),
                ],
            }
        }
    }

    impl Stream for DummyHybridStateStream {
        type Item = HybridEvent;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            if self.states.len() == 0 {
                Poll::Ready(None)
            } else {
                let state = (self.get_mut()).states.remove(0);
                Poll::Ready(Some(HybridEvent { state }))
            }
        }
    }
}
