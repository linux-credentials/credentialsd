use std::{fmt::Display, sync::Arc, time::Duration};

use async_trait::async_trait;
use credentialsd_common::model::{MakeCredentialRequest, MakeCredentialResponse};
use libwebauthn::{
    pin::PinRequestReason,
    proto::{
        ctap1::apdu::{ApduRequest, ApduResponse},
        ctap2::{
            cbor::{CborRequest, CborResponse},
            Ctap2CommandCode,
        },
        CtapError,
    },
    transport::{
        device::SupportedProtocols, AuthTokenData, Channel, ChannelStatus, Ctap2AuthTokenStore,
        Device, Transport,
    },
    webauthn::{Error, PlatformError, TransportError},
    PinRequiredUpdate, UvUpdate,
};
use passkey_authenticator::{Authenticator, UserCheck, UserValidationMethod};
use passkey_types::{
    ctap2::{Aaguid, Ctap2Error},
    Passkey,
};
use tokio::sync::{broadcast, mpsc, Mutex as AsyncMutex};

fn create_passkey(
    request: &MakeCredentialRequest,
) -> Result<MakeCredentialResponse, Box<dyn std::error::Error>> {
    request;
    todo!()
}

pub struct InternalTransport;
impl Transport for InternalTransport {}
impl Display for InternalTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Internal")
    }
}

/// A reference to the authenticator
pub struct PlatformAuthenticator {}
#[async_trait]
impl<'d> Device<'d, InternalTransport, PlatformAuthenticatorChannel<'d>> for PlatformAuthenticator {
    async fn channel(&'d mut self) -> Result<PlatformAuthenticatorChannel<'d>, Error> {
        let (sender, _) = broadcast::channel(256);
        let (ctap_responder_tx, ctap_responder_rx) = mpsc::channel(1);
        let authenticator = Authenticator::new(
            Aaguid::new_empty(),
            None,
            UserValidationHandler {
                update_tx: sender.clone(),
            },
        );
        Ok(PlatformAuthenticatorChannel {
            device: self,
            ux_update_sender: sender,
            auth_token_data: None,
            responder_rx: Arc::new(AsyncMutex::new(ctap_responder_rx)),
            response_handle: Arc::new(AsyncMutex::new((authenticator, ctap_responder_tx))),
        })
    }
}

impl Display for PlatformAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Platform Authenticator")
    }
}

pub struct PlatformAuthenticatorChannel<'a> {
    device: &'a PlatformAuthenticator,
    ux_update_sender: broadcast::Sender<PlatformUxUpdate>,
    auth_token_data: Option<AuthTokenData>,
    responder_rx: Arc<AsyncMutex<mpsc::Receiver<CborResponse>>>,
    response_handle: Arc<
        AsyncMutex<(
            Authenticator<Option<Passkey>, UserValidationHandler>,
            mpsc::Sender<CborResponse>,
        )>,
    >,
}

impl PlatformAuthenticatorChannel<'_> {
    fn get_ux_update_receiver(&self) -> broadcast::Receiver<PlatformUxUpdate> {
        self.ux_update_sender.subscribe()
    }
}

#[async_trait]
impl Channel for PlatformAuthenticatorChannel<'_> {
    type UxUpdate = PlatformUxUpdate;

    fn get_ux_update_sender(&self) -> &broadcast::Sender<Self::UxUpdate> {
        &self.ux_update_sender
    }

    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        Ok(SupportedProtocols {
            u2f: false,
            fido2: true,
        })
    }

    async fn status(&self) -> ChannelStatus {
        ChannelStatus::Ready
    }

    async fn close(&mut self) {
        todo!()
    }

    async fn apdu_send(&self, _request: &ApduRequest, _timeout: Duration) -> Result<(), Error> {
        Err(Error::Platform(PlatformError::NotSupported))
    }

    async fn apdu_recv(&self, _timeout: Duration) -> Result<ApduResponse, Error> {
        Err(Error::Platform(PlatformError::NotSupported))
    }

    async fn cbor_send(&mut self, request: &CborRequest, timeout: Duration) -> Result<(), Error> {
        tracing::debug!("cbor_send called: {request:?}");
        let response_handle = self.response_handle.clone();
        let request = request.clone();
        tokio::task::spawn(async move {
            let mut response_handle = response_handle.lock().await;
            let (ref mut authenticator, ref responder_tx) = *response_handle;
            let response = handle_request(authenticator, &request).await;
            responder_tx.send(response).await.unwrap();
        });
        Ok(())
    }

    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, Error> {
        tracing::debug!("cbor_recv called");
        tokio::time::timeout(timeout, async move {
            if let Some(response) = self.responder_rx.lock().await.recv().await {
                tracing::debug!("received response from handler, sending {response:?}");
                Ok(response)
            } else {
                Err(Error::Platform(PlatformError::InvalidDeviceResponse))
            }
        })
        .await
        .map_err(|_| Error::Transport(TransportError::Timeout))
        .and_then(|response| response)
    }
}

async fn handle_request(
    authenticator: &mut Authenticator<Option<Passkey>, UserValidationHandler>,
    request: &CborRequest,
) -> CborResponse {
    match request.command {
        Ctap2CommandCode::AuthenticatorGetInfo => {
            let info = authenticator.get_info().await;
            let data = serde_cbor_2::to_vec(&info).unwrap();
            CborResponse {
                status_code: CtapError::Ok,
                data: Some(data),
            }
        }
        Ctap2CommandCode::AuthenticatorMakeCredential => {
            let make_request: passkey_types::ctap2::make_credential::Request =
                serde_cbor_2::from_slice(&request.encoded_data).unwrap();
            let make_response = authenticator.make_credential(make_request).await.unwrap();
            CborResponse {
                status_code: CtapError::Ok,
                data: Some(serde_cbor_2::to_vec(&make_response).unwrap()),
            }
        }
        Ctap2CommandCode::AuthenticatorGetAssertion => {
            let get_request = serde_cbor_2::from_slice(&request.encoded_data).unwrap();
            let get_response = authenticator.get_assertion(get_request).await.unwrap();
            CborResponse {
                status_code: CtapError::Ok,
                data: Some(serde_cbor_2::to_vec(&get_response).unwrap()),
            }
        }
        Ctap2CommandCode::AuthenticatorGetNextAssertion => {
            todo!()
        }
        Ctap2CommandCode::AuthenticatorSelection => {
            todo!()
        }
        Ctap2CommandCode::AuthenticatorClientPin => {
            todo!()
        }

        _ => CborResponse {
            status_code: CtapError::InvalidCommand,
            data: None,
        },
    }
}

impl Display for PlatformAuthenticatorChannel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.device, f)
    }
}

impl Ctap2AuthTokenStore for PlatformAuthenticatorChannel<'_> {
    fn store_auth_data(&mut self, auth_token_data: AuthTokenData) {
        self.auth_token_data = Some(auth_token_data);
    }

    fn get_auth_data(&self) -> Option<&AuthTokenData> {
        self.auth_token_data.as_ref()
    }

    fn clear_uv_auth_token_store(&mut self) {
        self.auth_token_data = None;
    }
}

#[derive(Debug, Clone)]
pub enum PlatformUxUpdate {
    PinRequired(PinRequiredUpdate),
    Error(TransportError),
}

impl From<UvUpdate> for PlatformUxUpdate {
    fn from(value: UvUpdate) -> Self {
        match value {
            UvUpdate::PinRequired(pin_request) => Self::PinRequired(pin_request),
            UvUpdate::UvRetry { .. } => {
                todo!("Platform authentication non-client PIN user verification is not currently implemented.")
            }
            UvUpdate::PresenceRequired => {
                unreachable!("Platform authenticator does not expect a separate authorization gesture for test of user presence.");
            }
        }
    }
}

struct UserValidationHandler {
    update_tx: broadcast::Sender<PlatformUxUpdate>,
}

#[async_trait]
impl UserValidationMethod for UserValidationHandler {
    type PasskeyItem = Passkey;

    async fn check_user<'a>(
        &self,
        _credential: Option<&'a Self::PasskeyItem>,
        presence: bool,
        verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        if presence || verification {
            let client_pin = "1234";
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.update_tx
                .send(PlatformUxUpdate::PinRequired(PinRequiredUpdate {
                    reply_to: Arc::new(tx),
                    reason: PinRequestReason::RelyingPartyRequest,
                    attempts_left: None,
                }))
                .map_err(|_| Ctap2Error::ActionTimeout)?;
            let pin = rx.await.map_err(|_| Ctap2Error::UserActionTimeout)?;
            if pin == client_pin {
                Ok(UserCheck {
                    presence: true,
                    verification: true,
                })
            } else {
                Err(Ctap2Error::PinInvalid)
            }
        } else {
            Ok(UserCheck {
                presence: false,
                verification: false,
            })
        }
    }

    fn is_presence_enabled(&self) -> bool {
        false
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        None
    }
}
