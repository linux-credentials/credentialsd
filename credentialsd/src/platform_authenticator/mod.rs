use std::{fmt::Display, time::Duration};

use async_trait::async_trait;
use credentialsd_common::model::{MakeCredentialRequest, MakeCredentialResponse};
use libwebauthn::{
    proto::{
        ctap1::apdu::{ApduRequest, ApduResponse},
        ctap2::cbor::{CborRequest, CborResponse},
    },
    transport::{
        device::SupportedProtocols, AuthTokenData, Channel, ChannelStatus, Ctap2AuthTokenStore,
        Device, Transport,
    },
    webauthn::{Error, PlatformError, TransportError},
    PinRequiredUpdate, UvUpdate,
};
use tokio::sync::broadcast;

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
        Ok(PlatformAuthenticatorChannel {
            device: self,
            ux_update_sender: sender,
            auth_token_data: None,
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
        Err(Error::Platform(PlatformError::InvalidDeviceResponse))
    }

    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, Error> {
        tracing::debug!("cbor_send called");
        Err(Error::Platform(PlatformError::InvalidDeviceResponse))
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
