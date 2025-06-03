use std::fmt::Debug;
use std::task::Poll;

use async_std::channel::Receiver;
use futures_lite::{FutureExt, Stream};
use libwebauthn::fido::{AuthenticatorData, AuthenticatorDataFlags};
use libwebauthn::ops::webauthn::{Assertion, GetAssertionResponse};
use libwebauthn::proto::ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2Transport};
use libwebauthn::transport::cable::qr_code_device::{CableQrCodeDevice, QrCodeOperationHint};
use libwebauthn::transport::Device;
use libwebauthn::webauthn::{Error as WebAuthnError, WebAuthn};

use crate::{dbus::CredentialRequest, tokio_runtime};

use super::AuthenticatorResponse;

pub(crate) trait HybridHandler {
    type Stream: Stream<Item = HybridStateInternal>;
    fn start(&self, request: &CredentialRequest) -> Self::Stream;
}

#[derive(Debug)]
pub struct InternalHybridHandler {}
impl InternalHybridHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl HybridHandler for InternalHybridHandler {
    type Stream = InternalHybridStream;

    fn start(&self, request: &CredentialRequest) -> Self::Stream {
        let request = request.clone();
        let (tx, rx) = async_std::channel::unbounded();
        async_std::task::spawn(async move {
            let hint = match request {
                CredentialRequest::CreatePublicKeyCredentialRequest(_) => {
                    QrCodeOperationHint::MakeCredential
                }
                CredentialRequest::GetPublicKeyCredentialRequest(_) => {
                    QrCodeOperationHint::GetAssertionRequest
                }
            };
            let mut device = CableQrCodeDevice::new_transient(hint);
            let qr_code = device.qr_code.to_string();
            if let Err(err) = tx.send(HybridStateInternal::Init(qr_code)).await {
                tracing::error!("Failed to send caBLE update: {:?}", err);
                return;
            };
            tokio_runtime::get().spawn(async move {
                let (mut channel, _) = device.channel().await.unwrap();
                let response: AuthenticatorResponse = loop {
                    match &request {
                        CredentialRequest::CreatePublicKeyCredentialRequest(make_request) => {
                            match channel.webauthn_make_credential(&make_request).await {
                                Ok(response) => break Ok(response.into()),
                                Err(WebAuthnError::Ctap(ctap_error)) => {
                                    if ctap_error.is_retryable_user_error() {
                                        tracing::debug!("Oops, try again! Error: {}", ctap_error);
                                        continue;
                                    }
                                    break Err(WebAuthnError::Ctap(ctap_error));
                                }
                                Err(err) => break Err(err),
                            };
                        }
                        CredentialRequest::GetPublicKeyCredentialRequest(get_request) => {
                            match channel.webauthn_get_assertion(&get_request).await {
                                Ok(response) => break Ok(response.into()),
                                Err(WebAuthnError::Ctap(ctap_error)) => {
                                    if ctap_error.is_retryable_user_error() {
                                        println!("Oops, try again! Error: {}", ctap_error);
                                        continue;
                                    }
                                    break Err(WebAuthnError::Ctap(ctap_error));
                                }
                                Err(err) => break Err(err),
                            };
                        }
                    }
                }
                .unwrap();
                if let Err(err) = tx.send(HybridStateInternal::Completed(response)).await {
                    tracing::error!("Failed to send caBLE update: {:?}", err)
                }
            });
        });
        InternalHybridStream { rx }
    }
}

pub struct InternalHybridStream {
    rx: Receiver<HybridStateInternal>,
}

impl Stream for InternalHybridStream {
    type Item = HybridStateInternal;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.rx.recv().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(state)) => Poll::Ready(Some(state)),
            Poll::Ready(Err(_)) => Poll::Ready(None),
        }
    }
}

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
    type Stream = DummyHybridStateStream;

    fn start(&self, _request: &CredentialRequest) -> Self::Stream {
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
                HybridStateInternal::Waiting,
                HybridStateInternal::Connecting,
                HybridStateInternal::Completed(response.into()),
            ],
        }
    }
}

impl Stream for DummyHybridStateStream {
    type Item = HybridStateInternal;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if self.states.len() == 0 {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some((self.get_mut()).states.remove(0)))
        }
    }
}

#[derive(Clone, Debug)]
pub enum HybridStateInternal {
    /// The FIDO string to be displayed to the user, which contains QR secret
    /// and public key.
    Init(String),

    /// Awaiting BLE advert from phone.
    Waiting,
    /// BLE advertisement has been received from phone, tunnel is being established
    Connecting,

    /// Authenticator data
    Completed(AuthenticatorResponse),

    // This isn't actually sent from the server.
    UserCancelled,
}

#[derive(Clone, Debug)]
pub enum HybridState {
    /// The FIDO string to be displayed to the user, which contains QR secret
    /// and public key.
    Init(String),

    /// Awaiting BLE advert from phone.
    Waiting,
    /// BLE advertisement has been received from phone, tunnel is being established
    Connecting,

    /// Authenticator data
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,
}

impl From<HybridStateInternal> for HybridState {
    fn from(value: HybridStateInternal) -> Self {
        match value {
            HybridStateInternal::Init(qr_code) => HybridState::Init(qr_code),
            HybridStateInternal::Waiting => HybridState::Waiting,
            HybridStateInternal::Connecting => HybridState::Connecting,
            HybridStateInternal::Completed(_) => HybridState::Completed,
            HybridStateInternal::UserCancelled => HybridState::UserCancelled,
        }
    }
}
