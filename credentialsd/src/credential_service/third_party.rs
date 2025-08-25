use std::{
    fmt::Display,
    io::Write,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};

use async_stream::stream;
use async_trait::async_trait;
use credentialsd_common::model::{CredentialRequest, CredentialResponse};
use futures_lite::{FutureExt, Stream, StreamExt};
use libwebauthn::{
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
        Device, Transport as TransportMarker,
    },
    webauthn::{Error, PlatformError, TransportError, WebAuthn},
    UvUpdate,
};
use tokio::{
    net::UnixDatagram,
    sync::{broadcast, mpsc, Mutex as AsyncMutex},
    task::AbortHandle,
};

use crate::{
    cbor::CborWriter,
    credential_service::{AuthenticatorResponse, RequestContext},
};

pub trait HandleThirdParty {
    fn start(
        &self,
        path: PathBuf,
        request: &CredentialRequest,
    ) -> impl Stream<Item = ThirdPartyEvent> + Unpin + Send + Sized + 'static;
}

#[derive(Debug)]
pub struct ThirdPartyHandler {
    task: Mutex<Option<AbortHandle>>,
}

impl ThirdPartyHandler {
    pub fn new() -> Self {
        Self {
            task: Mutex::new(None),
        }
    }
}
impl HandleThirdParty for ThirdPartyHandler {
    fn start(
        &self,
        path: PathBuf,
        request: &CredentialRequest,
    ) -> impl Stream<Item = ThirdPartyEvent> + Unpin + Send + Sized + 'static {
        let (tx, mut rx) = mpsc::channel(256);
        let request = request.clone();
        let task = tokio::spawn(async move {
            tracing::debug!("Starting platform authenticator operation");
            if let Err(err) = execute_flow(path, &request, tx).await {
                tracing::error!("Failed to run platform authenticator flow to completion: {err}");
            }
        })
        .abort_handle();
        if let Some(prev_task) = self.task.lock().unwrap().replace(task) {
            prev_task.abort();
        }
        Box::pin(stream! {
            while let Some(state) = rx.recv().await {
                yield ThirdPartyEvent { state }
            }
        })
    }
}

async fn execute_flow(
    path: PathBuf,
    request: &CredentialRequest,
    tx: mpsc::Sender<ThirdPartyStateInternal>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut device = ThirdPartyAuthenticator::new(path);
    let mut channel = device.channel().await?;
    let state_tx = tx.clone();
    let mut ux_updates_rx = channel.get_ux_update_receiver();
    tokio::spawn(async move {
        handle_updates(&state_tx, &mut ux_updates_rx).await;
        tracing::trace!("Reached end of platform authenticator updates stream");
    });

    tracing::debug!("Polling platform authenticator channel for updates");
    let authenticator_response: Result<AuthenticatorResponse, credentialsd_common::model::Error> = loop {
        match &request {
            CredentialRequest::CreatePublicKeyCredentialRequest(make_request) => {
                match channel.webauthn_make_credential(make_request).await {
                    Ok(response) => break Ok(response.into()),
                    Err(libwebauthn::webauthn::Error::Ctap(CtapError::CredentialExcluded)) => {
                        break Err(credentialsd_common::model::Error::CredentialExcluded);
                    }
                    Err(libwebauthn::webauthn::Error::Ctap(ctap_error))
                        if ctap_error.is_retryable_user_error() =>
                    {
                        tracing::debug!(
                            "Retrying credential creation operation because of CTAP error: {:?}",
                            ctap_error
                        );
                        continue;
                    }
                    Err(err) => {
                        tracing::error!(
                            "Received unrecoverable error from authenticator: {:?}",
                            err
                        );
                        break Err(credentialsd_common::model::Error::AuthenticatorError);
                    }
                };
            }
            CredentialRequest::GetPublicKeyCredentialRequest(get_request) => {
                match channel.webauthn_get_assertion(get_request).await {
                    Ok(response) => break Ok(response.into()),
                    Err(libwebauthn::webauthn::Error::Ctap(CtapError::NoCredentials)) => {
                        break Err(credentialsd_common::model::Error::NoCredentials);
                    }
                    Err(libwebauthn::webauthn::Error::Ctap(ctap_error))
                        if ctap_error.is_retryable_user_error() =>
                    {
                        tracing::debug!(
                            "Retrying assertion operation because of CTAP error: {:?}",
                            ctap_error
                        );
                        continue;
                    }
                    Err(err) => {
                        tracing::error!(
                            "Received unrecoverable error from authenticator: {:?}",
                            err
                        );
                        break Err(credentialsd_common::model::Error::AuthenticatorError);
                    }
                };
            }
        }
    };

    let terminal_state = match authenticator_response {
        Ok(AuthenticatorResponse::CredentialCreated(make_credential_response)) => {
            ThirdPartyStateInternal::Completed(CredentialResponse::from_make_credential(
                &make_credential_response,
                &["internal"],
                "platform",
            ))
        }
        Ok(AuthenticatorResponse::CredentialsAsserted(get_assertion_response))
            if get_assertion_response.assertions.len() == 1 =>
        {
            ThirdPartyStateInternal::Completed(CredentialResponse::from_get_assertion(
                &get_assertion_response.assertions[0],
                "platform",
            ))
        }

        Ok(AuthenticatorResponse::CredentialsAsserted(_)) => {
            unimplemented!("Third party authenticators should send back a single credential");
        }
        Err(err) => ThirdPartyStateInternal::Failed(err),
    };
    tx.send(terminal_state).await?;
    Ok(())
}

async fn handle_updates(
    state_tx: &mpsc::Sender<ThirdPartyStateInternal>,
    update_rx: &mut broadcast::Receiver<ThirdPartyUxUpdate>,
) {
    while let Ok(msg) = update_rx.recv().await {
        let state = match msg {
            ThirdPartyUxUpdate::NeedsUnlock => ThirdPartyStateInternal::NeedsUnlock,
        };
        if let Err(err) = state_tx.send(state.clone()).await {
            tracing::error!({ ?err, ?state }, "Failed to send platform update");
        }
    }
}

#[derive(Debug, Clone)]
pub enum ThirdPartyState {
    NeedsUnlock,
    Failed(credentialsd_common::model::Error),
    Completed,
}

#[derive(Debug, Clone)]
pub enum ThirdPartyStateInternal {
    NeedsUnlock,
    Failed(credentialsd_common::model::Error),
    Completed(CredentialResponse),
}

impl From<ThirdPartyStateInternal> for ThirdPartyState {
    fn from(value: ThirdPartyStateInternal) -> Self {
        match value {
            ThirdPartyStateInternal::NeedsUnlock => Self::NeedsUnlock,
            ThirdPartyStateInternal::Failed(err) => Self::Failed(err),
            ThirdPartyStateInternal::Completed(_) => Self::Completed,
        }
    }
}

// this is here to prevent making ThirdPartyStateInternal public to the whole crate.
/// Messages between hybrid handler and credential service.
pub struct ThirdPartyEvent {
    pub(super) state: ThirdPartyStateInternal,
}

pub struct ThirdPartyTransport;
impl TransportMarker for ThirdPartyTransport {}
impl Display for ThirdPartyTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ThirdParty")
    }
}
/// A reference to the authenticator
pub struct ThirdPartyAuthenticator {
    socket_path: PathBuf,
}

impl ThirdPartyAuthenticator {
    pub fn new<P>(socket_path: P) -> Self
    where
        PathBuf: From<P>,
    {
        Self {
            socket_path: PathBuf::from(socket_path),
        }
    }
}

#[async_trait]
impl<'d> Device<'d, ThirdPartyTransport, ThirdPartyChannel<'d>> for ThirdPartyAuthenticator {
    async fn channel(&'d mut self) -> Result<ThirdPartyChannel<'d>, libwebauthn::webauthn::Error> {
        let (sender, _) = broadcast::channel(256);
        let (ctap_responder_tx, ctap_responder_rx) = mpsc::channel(1);
        let socket = UnixDatagram::bind(&self.socket_path).map_err(|err| {
            tracing::error!(
                "Failed to connect to socket at {:?}: {err}",
                self.socket_path
            );
            Error::Transport(TransportError::ConnectionFailed)
        })?;

        Ok(ThirdPartyChannel {
            device: self,
            ux_update_sender: sender,
            // auth_token_data: None,
            responder_rx: Arc::new(AsyncMutex::new(ctap_responder_rx)),
            response_handle: Arc::new(AsyncMutex::new((socket, ctap_responder_tx))),
        })
    }
}

impl Display for ThirdPartyAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Third Party Authenticator")
    }
}

struct ThirdPartyChannel<'d> {
    device: &'d ThirdPartyAuthenticator,
    ux_update_sender: broadcast::Sender<ThirdPartyUxUpdate>,
    responder_rx: Arc<AsyncMutex<mpsc::Receiver<CborResponse>>>,
    response_handle: Arc<AsyncMutex<(UnixDatagram, mpsc::Sender<CborResponse>)>>,
}

impl ThirdPartyChannel<'_> {
    fn get_ux_update_receiver(&self) -> broadcast::Receiver<ThirdPartyUxUpdate> {
        self.ux_update_sender.subscribe()
    }
}

#[async_trait]
impl Channel for ThirdPartyChannel<'_> {
    type UxUpdate = ThirdPartyUxUpdate;

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

    async fn apdu_send(
        &self,
        _request: &ApduRequest,
        _timeout: Duration,
    ) -> Result<(), libwebauthn::webauthn::Error> {
        Err(Error::Platform(PlatformError::NotSupported))
    }

    async fn apdu_recv(
        &self,
        _timeout: Duration,
    ) -> Result<ApduResponse, libwebauthn::webauthn::Error> {
        Err(Error::Platform(PlatformError::NotSupported))
    }

    async fn cbor_send(
        &mut self,
        request: &CborRequest,
        timeout: Duration,
    ) -> Result<(), libwebauthn::webauthn::Error> {
        tracing::debug!("cbor_send called: {request:?}");
        let response_handle = self.response_handle.clone();
        let request = request.clone();
        let task = async move {
            let mut response_handle = response_handle.lock().await;
            let (ref mut authenticator, ref responder_tx) = *response_handle;
            let response = handle_request(authenticator, &request).await;
            responder_tx.send(response).await.unwrap();
        };
        tokio::time::timeout(timeout, task)
            .await
            .map_err(|_| Error::Transport(TransportError::Timeout))?;
        Ok(())
    }

    async fn cbor_recv(
        &mut self,
        timeout: Duration,
    ) -> Result<CborResponse, libwebauthn::webauthn::Error> {
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

    fn supports_preflight() -> bool {
        false
    }
}

impl Display for ThirdPartyChannel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.device, f)
    }
}

impl Ctap2AuthTokenStore for ThirdPartyChannel<'_> {
    fn store_auth_data(&mut self, auth_token_data: AuthTokenData) {
        unimplemented!("We shouldn't need to store Auth tokens for third-party providers");
    }

    fn get_auth_data(&self) -> Option<&AuthTokenData> {
        unimplemented!("We shouldn't need to store Auth tokens for third-party providers");
    }

    fn clear_uv_auth_token_store(&mut self) {
        unimplemented!("We shouldn't need to store Auth tokens for third-party providers");
    }
}

async fn handle_request(socket: &mut UnixDatagram, request: &CborRequest) -> CborResponse {
    match request.command {
        Ctap2CommandCode::AuthenticatorGetInfo => {
            let mut buf = Vec::new();
            let mut writer = CborWriter::new(&mut buf);
            writer.write_map_start(3);
            writer.write_number(0x01); // versions
            writer.write_array_start(1);
            writer.write_text("FIDO_2_0");
            writer.write_number(0x03); // AAGUID
            writer.write_bytes(b"this_is_a_aaguid");
            writer.write_number(0x04); // options
            writer.write_map_start(2);
            writer.write_text("rp");
            writer.write_bool(true);
            writer.write_text("uv");
            writer.write_bool(true);

            CborResponse {
                status_code: CtapError::Ok,
                data: Some(buf),
            }
        }
        Ctap2CommandCode::AuthenticatorMakeCredential => {
            let mut buf = vec![b'\x10'];
            let len: u32 = (request.encoded_data.len() + 1).try_into().unwrap();
            buf.write_all(&len.to_be_bytes()).unwrap();
            buf.write(b"\x01").unwrap(); // makeCredential
            buf.write_all(&request.encoded_data).unwrap();
            socket.send(&buf);
            buf.clear();
            socket.recv(&mut buf);
            assert_eq!(b'\x10', buf[0]);
            let (len_bytes, _) = buf[1..].split_at(4);
            let response_len = u32::from_be_bytes(len_bytes.try_into().unwrap());
            let status_code = buf[5].try_into().unwrap();
            return CborResponse {
                status_code,
                data: if response_len > 1 {
                    Some(buf[6..].to_vec())
                } else {
                    None
                },
            };
        }
        Ctap2CommandCode::AuthenticatorGetAssertion => {
            todo!()
            /*
            let get_request = serde_cbor_2::from_slice(&request.encoded_data).unwrap();
            match authenticator.get_assertion(get_request).await {
                Ok(get_response) => CborResponse {
                    status_code: CtapError::Ok,
                    data: Some(serde_cbor_2::to_vec(&get_response).unwrap()),
                },
                Err(StatusCode::Ctap2(Ctap2Code::Known(Ctap2Error::NoCredentials))) => {
                    CborResponse {
                        status_code: CtapError::NoCredentials,
                        data: None,
                    }
                }
                Err(err) => {
                    tracing::error!("Received unknown CTAP2 error from authenticator: {:?}", err);
                    CborResponse {
                        status_code: CtapError::Other,
                        data: None,
                    }
                }
            }
            */
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

#[derive(Debug, Clone)]
pub enum ThirdPartyUxUpdate {
    NeedsUnlock,
}

impl From<UvUpdate> for ThirdPartyUxUpdate {
    fn from(value: UvUpdate) -> Self {
        unreachable!("We don't need UV updates");
    }
}

pub struct ThirdPartyStateStream<P> {
    inner: P,
    ctx: Arc<Mutex<Option<RequestContext>>>,
}

impl<P> ThirdPartyStateStream<P>
where
    P: Stream<Item = ThirdPartyEvent> + Unpin + Sized,
{
    pub(super) fn new(stream: P, ctx: Arc<Mutex<Option<RequestContext>>>) -> Self {
        Self { inner: stream, ctx }
    }
}

impl<P> Stream for ThirdPartyStateStream<P>
where
    P: Stream<Item = ThirdPartyEvent> + Unpin + Sized,
{
    type Item = ThirdPartyState;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let ctx = &self.ctx.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(ThirdPartyEvent { state })) => {
                if let ThirdPartyStateInternal::Completed(response) = &state {
                    super::complete_request(ctx, response.clone());
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
pub mod test {
    use async_stream::stream;
    use credentialsd_common::model::{Assertion, CredentialResponse, GetAssertionResponseInternal};
    use futures_lite::Stream;
    use libwebauthn::fido::{AuthenticatorData, AuthenticatorDataFlags};

    use super::{HandleThirdParty, ThirdPartyEvent, ThirdPartyStateInternal};

    #[derive(Debug)]
    pub struct DummyThirdPartyHandler {}
    impl HandleThirdParty for DummyThirdPartyHandler {
        fn start(
            &self,
            path: std::path::PathBuf,
            request: &credentialsd_common::model::CredentialRequest,
        ) -> impl Stream<Item = ThirdPartyEvent> + Unpin + Send + Sized + 'static {
            Box::pin(stream! {
                yield ThirdPartyEvent { state: ThirdPartyStateInternal::NeedsUnlock };
                let response = GetAssertionResponseInternal {
                    ctap: Assertion {
                        credential_id: None,
                        authenticator_data: AuthenticatorData {
                            rp_id_hash: *b"0123456789abcedf0123456789abcdef",
                            flags: AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::USER_VERIFIED,
                            signature_count: 1,
                            attested_credential: None,
                            extensions: None
                        },
                        signature: b"abcdef123457".to_vec(),
                        user: None,
                        credentials_count: None,
                        user_selected: None,
                        large_blob_key: None,
                        unsigned_extensions_output: None,
                        enterprise_attestation: None,
                        attestation_statement: None
                    },
                    attachment_modality: "cross-platform".to_string(),
                };
                yield ThirdPartyEvent {
                    state: ThirdPartyStateInternal::Completed(CredentialResponse::GetPublicKeyCredentialResponse(Box::new(response)))
                }
            })
        }
    }
}
