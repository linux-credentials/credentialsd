pub mod hybrid;
mod server;
pub mod usb;

use std::{
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
};

use futures_lite::{FutureExt, Stream, StreamExt};
use libwebauthn::{
    self,
    ops::webauthn::{GetAssertionResponse, MakeCredentialResponse},
};
use tokio::sync::oneshot::Sender;

use creds_lib::{
    model::{
        CredentialRequest, CredentialResponse, Device, Error as CredentialServiceError, Operation,
        Transport,
    },
    server::ViewRequest,
};

use crate::credential_service::{hybrid::HybridEvent, usb::UsbEvent};

use self::{
    hybrid::{HybridHandler, HybridState, HybridStateInternal},
    usb::{UsbHandler, UsbStateInternal},
};

pub use {
    server::{CredentialManagementClient, UiController},
    usb::UsbState,
};

type RequestContext = (
    CredentialRequest,
    Sender<Result<CredentialResponse, CredentialServiceError>>,
);

#[derive(Debug)]
pub struct CredentialService<H: HybridHandler, U: UsbHandler, UC: UiController> {
    devices: Vec<Device>,

    /// Current request and channel to respond to caller.
    ctx: Arc<Mutex<Option<RequestContext>>>,

    hybrid_handler: H,
    usb_handler: U,

    ui_control_client: UC,
}

impl<H: HybridHandler + Debug, U: UsbHandler + Debug, UC: UiController + Debug>
    CredentialService<H, U, UC>
{
    pub fn new(hybrid_handler: H, usb_handler: U, ui_control_client: UC) -> Self {
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
        Self {
            devices,

            ctx: Arc::new(Mutex::new(None)),

            hybrid_handler,
            usb_handler,

            ui_control_client,
        }
    }

    pub async fn init_request(
        &self,
        request: &CredentialRequest,
        tx: Sender<Result<CredentialResponse, CredentialServiceError>>,
    ) {
        {
            let mut cred_request = self.ctx.lock().unwrap();
            if cred_request.is_some() {
                tx.send(Err(CredentialServiceError::Internal(
                    "Already a request in progress.".to_string(),
                )))
                .expect("Send to local receiver to succeed");
                return;
            } else {
                _ = cred_request.insert((request.clone(), tx));
            }
        };
        let operation = match &request {
            CredentialRequest::CreatePublicKeyCredentialRequest(_) => Operation::Create,
            CredentialRequest::GetPublicKeyCredentialRequest(_) => Operation::Get,
        };
        let view_request = ViewRequest { operation };

        let launch_ui_response = self
            .ui_control_client
            .launch_ui(view_request)
            .await
            .map_err(|err| err.to_string());
        if let Err(err) = launch_ui_response {
            tracing::error!("Failed to launch UI for credentials: {err}. Cancelling request.");
            _ = self.ctx.lock().unwrap().take();
            let err = Err(CredentialServiceError::Internal(err));
            let (_, tx) = self.ctx.lock().unwrap().take().unwrap();
            tx.send(err).expect("Request handler to be listening");
        }
    }

    pub async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        Ok(self.devices.to_owned())
    }

    pub fn get_hybrid_credential(
        &self,
    ) -> Pin<Box<dyn Stream<Item = HybridState> + Send + 'static>> {
        let guard = self.ctx.lock().unwrap();
        if let Some((ref cred_request, _)) = *guard {
            let stream = self.hybrid_handler.start(&cred_request);
            let ctx = self.ctx.clone();
            Box::pin(HybridStateStream { inner: stream, ctx })
        } else {
            tracing::error!(
                "Attempted to start hybrid credential flow, but no request context was found."
            );
            todo!("Handle error when context is not set up.")
        }
    }

    pub fn get_usb_credential(&self) -> Pin<Box<dyn Stream<Item = UsbState> + Send + 'static>> {
        let guard = self.ctx.lock().unwrap();
        if let Some((ref cred_request, _)) = *guard {
            let stream = self.usb_handler.start(&cred_request);
            let ctx = self.ctx.clone();
            Box::pin(UsbStateStream { inner: stream, ctx })
        } else {
            tracing::error!(
                "Attempted to start hybrid credential flow, but no request context was found."
            );
            todo!("Handle error when context is not set up.")
        }
    }
}

pub struct HybridStateStream<H> {
    inner: H,
    ctx: Arc<Mutex<Option<RequestContext>>>,
}

impl<H> Stream for HybridStateStream<H>
where
    H: Stream<Item = HybridEvent> + Unpin + Sized,
{
    type Item = HybridState;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let ctx = &self.ctx.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(HybridEvent { state })) => {
                if let HybridStateInternal::Completed(hybrid_response) = &state {
                    let response = match hybrid_response {
                        AuthenticatorResponse::CredentialCreated(make_credential_response) => {
                            CredentialResponse::from_make_credential(
                                make_credential_response,
                                &["hybrid"],
                                "cross-platform",
                            )
                        }
                        AuthenticatorResponse::CredentialsAsserted(get_assertion_response) => {
                            CredentialResponse::from_get_assertion(
                                // When doing hybrid, the authenticator is capable of displaying it's own UI.
                                // So we assume here, it only ever returns one assertion.
                                // In case this doesn't hold true, we have to implement credential selection here,
                                // as is done for USB.
                                &get_assertion_response.assertions[0],
                                "cross-platform",
                            )
                        }
                    };
                    complete_request(ctx, response.clone());
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

struct UsbStateStream<H> {
    inner: H,
    ctx: Arc<Mutex<Option<RequestContext>>>,
}

impl<H> Stream for UsbStateStream<H>
where
    H: Stream<Item = UsbEvent> + Unpin + Sized,
{
    type Item = UsbState;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let ctx = &self.ctx.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(UsbEvent { state })) => {
                if let UsbStateInternal::Completed(response) = &state {
                    complete_request(ctx, response.clone());
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

fn complete_request(ctx: &Mutex<Option<RequestContext>>, response: CredentialResponse) {
    if let Some((_, responder)) = ctx.lock().unwrap().take() {
        if responder.send(Ok(response)).is_err() {
            tracing::error!(
                "Attempted to send credential response to caller, but channel was closed."
            );
        }
    } else {
        tracing::error!("Tried to consume context to respond to caller, but none was found.")
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
    use std::sync::Arc;

    use futures_lite::stream::StreamExt;

    use crate::credential_service::usb::InProcessUsbHandler;
    use creds_lib::{
        model::CredentialRequest,
        server::{CreateCredentialRequest, CreatePublicKeyCredentialRequest},
    };

    use super::{
        hybrid::{test::DummyHybridHandler, HybridStateInternal},
        AuthenticatorResponse, CredentialService,
    };

    /*
    #[test]
    fn test_hybrid_sets_credential() {
        let request = create_credential_request();
        let qr_code = String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332");
        let authenticator_response = create_authenticator_response();

        let hybrid_handler = DummyHybridHandler::new(vec![
            HybridStateInternal::Init(qr_code),
            HybridStateInternal::Connecting,
            HybridStateInternal::Completed(authenticator_response),
        ]);
        let usb_handler = InProcessUsbHandler {};
        let cred_service = Arc::new(CredentialService::new(hybrid_handler, usb_handler));
        cred_service.init_request(&request).unwrap();
        let mut stream = cred_service.get_hybrid_credential();
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async move { while let Some(_) = stream.next().await {} });
        let cred_service = Arc::try_unwrap(cred_service).unwrap();
        assert!(cred_service.complete_auth().is_some());
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

        let (req, _) = crate::dbus::model::create_credential_request_try_into_ctap2(
            &CreateCredentialRequest {
                origin: Some("webauthn.io".to_string()),
                is_same_origin: Some(true),
                r#type: "public-key".to_string(),
                public_key: Some(CreatePublicKeyCredentialRequest { request_json }),
            },
        )
        .unwrap();
        CredentialRequest::CreatePublicKeyCredentialRequest(req)
    }
    */

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
