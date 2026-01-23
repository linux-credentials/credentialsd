pub mod hybrid;
pub mod nfc;
pub mod usb;

use std::{
    error::Error,
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
};

use futures_lite::{FutureExt, Stream, StreamExt};
use libwebauthn::{
    self,
    ops::webauthn::{GetAssertionResponse, MakeCredentialResponse},
};
use nfc::{NfcEvent, NfcHandler, NfcState, NfcStateInternal};
use tokio::sync::oneshot::Sender;

use credentialsd_common::{
    model::{Device, Error as CredentialServiceError, Operation, RequestingApplication, Transport},
    server::{RequestId, ViewRequest, WindowHandle},
};

use crate::{
    credential_service::{hybrid::HybridEvent, usb::UsbEvent},
    model::{CredentialRequest, CredentialResponse},
};

use self::{
    hybrid::{HybridHandler, HybridState, HybridStateInternal},
    usb::{UsbHandler, UsbStateInternal},
};

pub use usb::UsbState;

/// Used by the credential service to control the UI.
pub trait UiController {
    fn launch_ui(
        &self,
        request: ViewRequest,
    ) -> impl Future<Output = std::result::Result<(), Box<dyn Error>>> + Send;
}

#[derive(Debug)]
struct RequestContext {
    request: CredentialRequest,
    response_channel: Sender<Result<CredentialResponse, CredentialServiceError>>,
    request_id: RequestId,
}

impl RequestContext {
    fn send_response(self, response: Result<CredentialResponse, CredentialServiceError>) {
        if self.response_channel.send(response).is_err() {
            tracing::error!(
                "Attempted to send credential response to caller, but channel was closed."
            );
        }
    }
}

#[derive(Debug)]
pub struct CredentialService<H: HybridHandler, U: UsbHandler, N: NfcHandler, UC: UiController> {
    /// Current request and channel to respond to caller.
    ctx: Arc<Mutex<Option<RequestContext>>>,

    hybrid_handler: H,
    usb_handler: U,
    nfc_handler: N,

    ui_control_client: Arc<UC>,
}

impl<
        H: HybridHandler + Debug,
        U: UsbHandler + Debug,
        N: NfcHandler + Debug,
        UC: UiController + Debug,
    > CredentialService<H, U, N, UC>
{
    pub fn new(
        hybrid_handler: H,
        usb_handler: U,
        nfc_handler: N,
        ui_control_client: Arc<UC>,
    ) -> Self {
        Self {
            ctx: Arc::new(Mutex::new(None)),

            hybrid_handler,
            usb_handler,
            nfc_handler,

            ui_control_client,
        }
    }

    pub async fn init_request(
        &self,
        request: &CredentialRequest,
        requesting_app: Option<RequestingApplication>,
        window_handle: Option<WindowHandle>,
        tx: Sender<Result<CredentialResponse, CredentialServiceError>>,
    ) {
        let request_id = {
            let mut cred_request = self.ctx.lock().unwrap();
            if cred_request.is_some() {
                tx.send(Err(CredentialServiceError::Internal(
                    "Already a request in progress.".to_string(),
                )))
                .expect("Send to local receiver to succeed");
                return;
            } else {
                let request_id: RequestId = rand::random();
                let ctx = RequestContext {
                    request: request.clone(),
                    response_channel: tx,
                    request_id,
                };
                _ = cred_request.insert(ctx);
                request_id
            }
        };
        let operation = match &request {
            CredentialRequest::CreatePublicKeyCredentialRequest(_) => Operation::Create,
            CredentialRequest::GetPublicKeyCredentialRequest(_) => Operation::Get,
        };
        let rp_id = match &request {
            CredentialRequest::CreatePublicKeyCredentialRequest(r) => r.relying_party.id.clone(),
            CredentialRequest::GetPublicKeyCredentialRequest(r) => r.relying_party_id.clone(),
        };
        let view_request = ViewRequest {
            operation,
            id: request_id,
            rp_id,
            requesting_app: requesting_app.unwrap_or_default(), // We can't send Options, so we send an empty string instead, if we don't know the peer
            window_handle: window_handle.into(),
        };

        let launch_ui_response = self
            .ui_control_client
            .launch_ui(view_request)
            .await
            .map_err(|err| err.to_string());
        if let Err(err) = launch_ui_response {
            tracing::error!("Failed to launch UI for credentials: {err}. Cancelling request.");
            _ = self.ctx.lock().unwrap().take();
            let err = Err(CredentialServiceError::Internal(err));
            let ctx = self.ctx.lock().unwrap().take().unwrap();
            ctx.response_channel
                .send(err)
                .expect("Request handler to be listening");
        }
        tracing::debug!("Finished setting up request {request_id}");
    }

    pub async fn cancel_request(&self, request_id: RequestId) {
        let mut guard = self.ctx.lock().expect("Lock to be taken");
        if let Some(ctx) = guard.take_if(|ctx| ctx.request_id == request_id) {
            if request_id == ctx.request_id {
                tracing::debug!("Cancelling request {request_id}");
                // TODO: cancel sub-tasks: hybrid and USB streams.

                // It's fine if the requestor is no longer listening for the response.
                // TODO: create Cancelled variant
                _ = ctx
                    .response_channel
                    .send(Err(CredentialServiceError::Internal(format!(
                        "Cancelled request {request_id}."
                    ))));
            }
        }
    }

    pub async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        // We create the list new for each call, in case someone plugs in
        // an NFC-reader in the middle of an auth-flow
        let mut devices = vec![
            Device {
                id: String::from("0"),
                transport: Transport::Usb,
            },
            Device {
                id: String::from("1"),
                transport: Transport::HybridQr,
            },
        ];
        if libwebauthn::transport::nfc::is_nfc_available() {
            devices.push(Device {
                id: String::from("2"),
                transport: Transport::Nfc,
            });
        }
        Ok(devices)
    }

    pub fn get_hybrid_credential(
        &self,
    ) -> Pin<Box<dyn Stream<Item = HybridState> + Send + 'static>> {
        let guard = self.ctx.lock().unwrap();
        if let Some(RequestContext { ref request, .. }) = *guard {
            let stream = self.hybrid_handler.start(request);
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
        if let Some(RequestContext { ref request, .. }) = *guard {
            let stream = self.usb_handler.start(request);
            let ctx = self.ctx.clone();
            Box::pin(UsbStateStream { inner: stream, ctx })
        } else {
            tracing::error!(
                "Attempted to start usb credential flow, but no request context was found."
            );
            todo!("Handle error when context is not set up.")
        }
    }

    pub fn get_nfc_credential(&self) -> Pin<Box<dyn Stream<Item = NfcState> + Send + 'static>> {
        let guard = self.ctx.lock().unwrap();
        if let Some(RequestContext { ref request, .. }) = *guard {
            let stream = self.nfc_handler.start(request);
            let ctx = self.ctx.clone();
            Box::pin(NfcStateStream { inner: stream, ctx })
        } else {
            tracing::error!(
                "Attempted to start nfc credential flow, but no request context was found."
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
                    let response = match &**hybrid_response {
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

struct NfcStateStream<H> {
    inner: H,
    ctx: Arc<Mutex<Option<RequestContext>>>,
}

impl<H> Stream for NfcStateStream<H>
where
    H: Stream<Item = NfcEvent> + Unpin + Sized,
{
    type Item = NfcState;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let ctx = &self.ctx.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(NfcEvent { state })) => {
                if let NfcStateInternal::Completed(response) = &state {
                    complete_request(ctx, response.clone());
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

fn complete_request(ctx: &Mutex<Option<RequestContext>>, response: CredentialResponse) {
    if let Some(ctx) = ctx.lock().unwrap().take() {
        ctx.send_response(Ok(response));
    } else {
        tracing::error!("Tried to consume context to respond to caller, but none was found.")
    }
}

#[derive(Debug, Clone)]
enum AuthenticatorResponse {
    CredentialCreated(Box<MakeCredentialResponse>),
    CredentialsAsserted(GetAssertionResponse),
}

impl From<MakeCredentialResponse> for AuthenticatorResponse {
    fn from(value: MakeCredentialResponse) -> Self {
        Self::CredentialCreated(Box::new(value))
    }
}

impl From<GetAssertionResponse> for AuthenticatorResponse {
    fn from(value: GetAssertionResponse) -> Self {
        Self::CredentialsAsserted(value)
    }
}

#[cfg(test)]
mod test {
    use std::{sync::Arc, time::Duration};

    use libwebauthn::{
        ops::webauthn::{
            MakeCredentialRequest, ResidentKeyRequirement, UserVerificationRequirement,
        },
        proto::ctap2::{
            Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialRpEntity,
            Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
        },
    };
    use tokio::sync::{oneshot, Mutex as AsyncMutex};

    use crate::{
        credential_service::usb::InProcessUsbHandler,
        dbus::test::{DummyFlowServer, DummyUiServer},
        model::CredentialRequest,
        webauthn,
    };
    use credentialsd_common::model::Operation;

    use super::{
        hybrid::{test::DummyHybridHandler, HybridStateInternal},
        nfc::InProcessNfcHandler,
        AuthenticatorResponse, CredentialService,
    };

    #[test]
    fn test_hybrid_sets_credential() {
        tracing_subscriber::fmt::init();
        let request = create_credential_request();
        let qr_code = String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332");
        let authenticator_response = create_authenticator_response();

        let (request_tx, request_rx) = oneshot::channel();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let hybrid_handler = DummyHybridHandler::new(vec![
                    HybridStateInternal::Init(qr_code),
                    HybridStateInternal::Connecting,
                    HybridStateInternal::Completed(Box::new(authenticator_response)),
                ]);
                let usb_handler = InProcessUsbHandler {};
                let nfc_handler = InProcessNfcHandler {};
                let (ui_server, ui_client) = DummyUiServer::new(Vec::new());
                let ui_server = Arc::new(ui_server);
                let user = ui_server.clone();
                let cred_service = Arc::new(AsyncMutex::new(CredentialService::new(
                    hybrid_handler,
                    usb_handler,
                    nfc_handler,
                    Arc::new(ui_client),
                )));
                let (mut flow_server, flow_client) = DummyFlowServer::new(cred_service.clone());
                ui_server.init(flow_client).await;

                tokio::spawn(async move { ui_server.run().await });
                tokio::spawn(async move { flow_server.run().await });
                cred_service
                    .lock()
                    .await
                    .init_request(&request, None, None, request_tx)
                    .await;
                user.request_hybrid_credential().await;
                tokio::time::timeout(Duration::from_secs(5), request_rx)
                    .await
                    .expect("request to complete")
                    .expect("response to be sent")
                    .expect("a credential to be returned");
            });
    }

    fn create_credential_request() -> CredentialRequest {
        let challenge = "Ox0AXQz7WUER7BGQFzvVrQbReTkS3sepVGj26qfUhhrWSarkDbGF4T4NuCY1aAwHYzOzKMJJ2YRSatetl0D9bQ";
        let origin = "webauthn.io".to_string();
        let is_cross_origin = false;
        let client_data_json = webauthn::format_client_data_json(
            Operation::Create,
            challenge,
            &origin,
            is_cross_origin,
        );
        let client_data_hash = webauthn::create_client_data_hash(&client_data_json);
        let make_request = MakeCredentialRequest {
            hash: client_data_hash,
            origin: "webauthn.io".to_string(),
            relying_party: Ctap2PublicKeyCredentialRpEntity {
                id: "webauthn.io".to_string(),
                name: Some("webauthn.io".to_string()),
            },
            user: Ctap2PublicKeyCredentialUserEntity {
                id: "d2ViYXV0aG5pby0xMjM4OTF5".as_bytes().to_vec().into(),
                name: Some("123891y".to_string()),
                display_name: Some("123891y".to_string()),
            },
            resident_key: Some(ResidentKeyRequirement::Preferred),
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![
                Ctap2CredentialType {
                    algorithm: Ctap2COSEAlgorithmIdentifier::ES256,
                    public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
                },
                Ctap2CredentialType {
                    algorithm: Ctap2COSEAlgorithmIdentifier::EDDSA,
                    public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
                },
            ],
            exclude: None,
            extensions: None,
            timeout: Duration::from_secs(60),
        };

        CredentialRequest::CreatePublicKeyCredentialRequest(make_request)
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
