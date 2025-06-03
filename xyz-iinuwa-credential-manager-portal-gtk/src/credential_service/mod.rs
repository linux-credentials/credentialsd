pub mod hybrid;
pub mod usb;

use std::{
    fmt::Debug, future::Future, pin::Pin, sync::{Arc, Mutex}, task::Poll, time::Duration
};

use futures_lite::{FutureExt, Stream, StreamExt};
use libwebauthn::{
    self,
    ops::webauthn::{GetAssertionResponse, MakeCredentialResponse},
    transport::{hid::HidDevice, Device as _},
    webauthn::{Error as WebAuthnError, WebAuthn},
    UxUpdate,
};

use async_std::{
    sync::{Arc as AsyncArc, Mutex as AsyncMutex},
};
use tracing::{debug, warn};

use crate::{
    dbus::{
        CredentialRequest, CredentialResponse, GetAssertionResponseInternal,
        MakeCredentialResponseInternal,
    },
    tokio_runtime,
    view_model::{Device, Transport},
};

use hybrid::{HybridHandler, HybridState, HybridStateInternal};
use usb::UsbUvHandler;
pub use usb::UsbState;

#[derive(Debug)]
pub struct CredentialService<H: HybridHandler> {
    devices: Vec<Device>,

    usb_state: AsyncArc<AsyncMutex<UsbState>>,
    usb_uv_handler: UsbUvHandler,

    cred_request: CredentialRequest,
    // Place to store data to be returned to the caller
    cred_response: Arc<Mutex<Option<CredentialResponse>>>,

    hybrid_handler: H,
}

impl <H: HybridHandler + Debug> CredentialService<H> {
    pub fn new(
        cred_request: CredentialRequest,
        cred_response: Arc<Mutex<Option<CredentialResponse>>>,
        hybrid_handler: H,
    ) -> Self {
        let devices = vec![
            Device {
                id: String::from("0"),
                transport: Transport::Usb,
            },
            Device {
                id: String::from("1"),
                transport: Transport::HybridQr,
            },
        ];
        let usb_state = AsyncArc::new(AsyncMutex::new(UsbState::Idle));
        Self {
            devices,

            usb_state: usb_state.clone(),
            usb_uv_handler: UsbUvHandler::new(),

            cred_request,
            cred_response,

            hybrid_handler,
        }
    }
}

pub trait CredentialServiceClient
where {
     async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()>;

     async fn poll_device_discovery_usb(&mut self) -> Result<UsbState, String>;

     async fn cancel_device_discovery_usb(&mut self) -> Result<(), String>;

     async fn validate_usb_device_pin(&mut self, pin: &str) -> Result<(), ()>;

     fn complete_auth(&mut self);

     fn get_hybrid_credential(&self) -> Pin<Box<dyn Stream<Item = HybridState> + Send>>;
}

impl<H: HybridHandler + Debug, U: UsbHandler + Debug> CredentialServiceClient
    for CredentialService<H, U>
where
    <H as HybridHandler>::Stream: Unpin + Send + 'static,
    <U as UsbHandler>::Stream: Unpin + Send + 'static,
{
    async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        Ok(self.devices.to_owned())
    }

     async fn poll_device_discovery_usb(&mut self) -> Result<UsbState, String> {
    }

     fn complete_auth(&mut self) {
        // let mut data = self.output_data.lock().unwrap();
        // data.replace((self.cred_response));
    }

    fn get_hybrid_credential(&self) -> Pin<Box<dyn Stream<Item = HybridState> + Send + 'static>> {
        let stream = self.hybrid_handler.start(&self.cred_request);
        Box::pin(HybridStateStream {
            inner: stream,
            cred_response: self.cred_response.clone(),
        })
    }
}

pub struct HybridStateStream<H> {
    inner: H,
    cred_response: Arc<Mutex<Option<CredentialResponse>>>,
}

impl<H> Stream for HybridStateStream<H>
where
    H: Stream<Item = HybridStateInternal> + Unpin + Sized,
{
    type Item = HybridState;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let cred_response = &self.cred_response.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(state)) => {
                if let HybridStateInternal::Completed(hybrid_response) = &state {
                    let response = match hybrid_response {
                        AuthenticatorResponse::CredentialCreated(make_response) => {
                            CredentialResponse::CreatePublicKeyCredentialResponse(
                                MakeCredentialResponseInternal::new(
                                    make_response.clone(),
                                    vec![String::from("hybrid")],
                                    String::from("cross-platform"),
                                ),
                            )
                        }

                        AuthenticatorResponse::CredentialsAsserted(GetAssertionResponse {
                            assertions,
                        }) if assertions.len() == 1 => {
                            CredentialResponse::GetPublicKeyCredentialResponse(
                                GetAssertionResponseInternal::new(
                                    assertions[0].clone(),
                                    String::from("cross-platform"),
                                ),
                            )
                        }
                        AuthenticatorResponse::CredentialsAsserted(GetAssertionResponse {
                            assertions,
                        }) => {
                            assert!(!assertions.is_empty());
                            todo!("need to support selection from multiple credentials");
                        }
                    };
                    let mut cred_response = cred_response.lock().unwrap();
                    cred_response.replace(response);
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}


#[derive(Debug, Clone)]
enum AuthenticatorResponse {
    CredentialCreated(MakeCredentialResponse),
    CredentialsAsserted(GetAssertionResponse),
}

impl From<MakeCredentialResponse> for AuthenticatorResponse {
    fn from(value: MakeCredentialResponse) -> Self {
        Self::CredentialCreated(value)
    }
}

impl From<GetAssertionResponse> for AuthenticatorResponse {
    fn from(value: GetAssertionResponse) -> Self {
        Self::CredentialsAsserted(value)
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};

    use async_std::stream::StreamExt;

    use crate::dbus::{
        CreateCredentialRequest, CreatePublicKeyCredentialRequest, CredentialRequest,
    };

    use super::{
        hybrid::{DummyHybridHandler, HybridStateInternal},
        AuthenticatorResponse, CredentialService, CredentialServiceClient
    };

    #[test]
    fn test_hybrid_sets_credential() {
        let request = create_credential_request();
        let response = Arc::new(Mutex::new(None));
        let qr_code = String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332");
        let authenticator_response = create_authenticator_response();

        let hybrid_handler = DummyHybridHandler::new(vec![
            HybridStateInternal::Init(qr_code),
            HybridStateInternal::Waiting,
            HybridStateInternal::Connecting,
            HybridStateInternal::Completed(authenticator_response),
        ]);
        let cred_service = CredentialService::new(request, response, hybrid_handler);
        let mut stream = cred_service.get_hybrid_credential();
        async_std::task::block_on(async move { while let Some(_) = stream.next().await {} });
        assert!(cred_service.cred_response.lock().unwrap().is_some());
    }

    fn create_credential_request() -> CredentialRequest {
        let request_json = r#"
        {
            "rp": {
                "name": "webauthn.io",
                "id": "webauthn.io"
            },
            "user": {
                "id": "d2ViYXV0aG5pby0xMjM4OTF5",
                "name": "123891y",
                "displayName": "123891y"
            },
            "challenge": "Ox0AXQz7WUER7BGQFzvVrQbReTkS3sepVGj26qfUhhrWSarkDbGF4T4NuCY1aAwHYzOzKMJJ2YRSatetl0D9bQ",
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -8
                },
                {
                    "type": "public-key",
                    "alg": -7
                },
                {
                    "type": "public-key",
                    "alg": -257
                }
            ],
            "timeout": 60000,
            "excludeCredentials": [],
            "authenticatorSelection": {
                "residentKey": "preferred",
                "requireResidentKey": false,
                "userVerification": "preferred"
            },
            "attestation": "none",
            "hints": [],
            "extensions": {
                "credProps": true
            }
        }"#.to_string();
        let (req, _) = CreateCredentialRequest {
            origin: Some("webauthn.io".to_string()),
            is_same_origin: Some(true),
            r#type: "public-key".to_string(),
            public_key: Some(CreatePublicKeyCredentialRequest {
                request_json: request_json,
            }),
        }
        .try_into_ctap2_request()
        .unwrap();
        CredentialRequest::CreatePublicKeyCredentialRequest(req)
    }

    fn create_authenticator_response() -> AuthenticatorResponse {
        use libwebauthn::{
            fido::{AuthenticatorData, AuthenticatorDataFlags},
            ops::webauthn::{Assertion, GetAssertionResponse},
            proto::ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2Transport},
        };
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
        GetAssertionResponse {
            assertions: vec![assertion],
        }
        .into()
    }
}
