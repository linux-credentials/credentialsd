use std::{
    error::Error,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
};

use async_stream::stream;
use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use credentialsd_common::model::{Assertion, Credential, CredentialRequest, CredentialResponse};
use futures_lite::{FutureExt, Stream, StreamExt};
use libwebauthn::{
    ops::webauthn::GetAssertionResponse,
    transport::{Channel, Device},
    webauthn::WebAuthn,
};
use tokio::{
    sync::{broadcast, mpsc},
    task::AbortHandle,
};

use crate::{
    credential_service::{AuthenticatorResponse, RequestContext},
    platform_authenticator::{PlatformAuthenticator, PlatformUxUpdate},
};

pub trait PlatformHandler {
    fn start(
        &self,
        request: &CredentialRequest,
    ) -> impl Stream<Item = PlatformEvent> + Unpin + Send + Sized + 'static;
}

#[derive(Debug)]
pub struct InMemoryPlatformHandler {
    task: Mutex<Option<AbortHandle>>,
}

impl InMemoryPlatformHandler {
    pub fn new() -> Self {
        Self {
            task: Mutex::new(None),
        }
    }
}

impl PlatformHandler for InMemoryPlatformHandler {
    fn start(
        &self,
        request: &CredentialRequest,
    ) -> impl Stream<Item = PlatformEvent> + Unpin + Send + Sized + 'static {
        let (tx, mut rx) = mpsc::channel(256);
        let request = request.clone();
        let task = tokio::spawn(async move {
            tracing::debug!("Starting platform authenticator operation");
            if let Err(err) = execute_flow(tx, &request).await {
                tracing::error!("Failed to run platform authenticator flow to completion: {err}");
            }
        })
        .abort_handle();
        if let Some(prev_task) = self.task.lock().unwrap().replace(task) {
            prev_task.abort();
        }
        Box::pin(stream! {
            while let Some(state) = rx.recv().await {
                yield PlatformEvent { state }
            }
        })
    }
}

async fn execute_flow(
    tx: mpsc::Sender<PlatformStateInternal>,
    request: &CredentialRequest,
) -> Result<(), Box<dyn Error>> {
    let mut device = PlatformAuthenticator {};
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
                    Err(libwebauthn::webauthn::Error::Ctap(ctap_error)) => {
                        if ctap_error.is_retryable_user_error() {
                            tracing::debug!("Retrying credential creation operation because of CTAP error: {:?}", ctap_error);
                            continue;
                        } else {
                            tracing::error!(
                                "Received CTAP unrecoverable CTAP error: {:?}",
                                ctap_error
                            );
                            break Err(credentialsd_common::model::Error::AuthenticatorError);
                        }
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
                    Err(libwebauthn::webauthn::Error::Ctap(ctap_error)) => {
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
                            break Err(credentialsd_common::model::Error::AuthenticatorError);
                        }
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
            PlatformStateInternal::Completed(CredentialResponse::from_make_credential(
                &make_credential_response,
                &["internal"],
                "platform",
            ))
        }
        Ok(AuthenticatorResponse::CredentialsAsserted(get_assertion_response))
            if get_assertion_response.assertions.len() == 1 =>
        {
            PlatformStateInternal::Completed(CredentialResponse::from_get_assertion(
                &get_assertion_response.assertions[0],
                "platform",
            ))
        }
        Ok(AuthenticatorResponse::CredentialsAsserted(get_assertion_response)) => {
            process_credential_selection(get_assertion_response, &tx).await?
        }
        Err(err) => PlatformStateInternal::Failed(err),
    };
    tx.send(terminal_state).await?;
    Ok(())
}

async fn handle_updates(
    state_tx: &mpsc::Sender<PlatformStateInternal>,
    update_rx: &mut broadcast::Receiver<PlatformUxUpdate>,
) {
    let mut pin_wait_task = None;
    while let Ok(msg) = update_rx.recv().await {
        let state = match msg {
            PlatformUxUpdate::PinRequired(pin_request) => {
                let (pin_tx, mut pin_rx): (mpsc::Sender<String>, mpsc::Receiver<String>) =
                    mpsc::channel(1);
                let attempts_left = pin_request.attempts_left.clone();
                let task = tokio::task::spawn(async move {
                    match pin_rx.recv().await {
                        Some(pin) => match pin_request.send_pin(&pin) {
                            Ok(()) => {}
                            Err(err) => tracing::error!("Received a PIN from the user, but failed to send it to the authenticator: {err}"),
                        },
                        None => tracing::warn!("Authenticator requested a PIN, but we did not receive one.")
                    }
                });
                if let Some(prev_task) = pin_wait_task.replace(task) {
                    prev_task.abort();
                }
                PlatformStateInternal::NeedsPin {
                    attempts_left,
                    pin_tx,
                }
            }
            PlatformUxUpdate::Error(err) => PlatformStateInternal::Failed(
                credentialsd_common::model::Error::Internal(err.to_string()),
            ),
        };
        if let Err(err) = state_tx.send(state.clone()).await {
            tracing::error!({ ?err, ?state }, "Failed to send hybrid update");
        }
    }
    if let Some(task) = pin_wait_task.take() {
        task.abort();
    }
}

async fn process_credential_selection(
    response: GetAssertionResponse,
    tx: &mpsc::Sender<PlatformStateInternal>,
) -> Result<PlatformStateInternal, Box<dyn Error>> {
    let (cred_tx, mut cred_rx) = mpsc::channel(1);
    tx.send(PlatformStateInternal::SelectingCredential {
        response: response.clone(),
        cred_tx,
    })
    .await?;
    if let Some(cred_id) = cred_rx.recv().await {
        if let Some(assertion) =
            find_assertion_by_masked_credential_id(&response.assertions, cred_id)
        {
            Ok(PlatformStateInternal::Completed(
                CredentialResponse::from_get_assertion(&assertion, "platform"),
            ))
        } else {
            Ok(PlatformStateInternal::Failed(
                credentialsd_common::model::Error::NoCredentials,
            ))
        }
    } else {
        tracing::debug!("cred channel closed before receiving cred from client.");
        Ok(PlatformStateInternal::Failed(
            credentialsd_common::model::Error::Internal(
                "Cred channel disconnected prematurely".to_string(),
            ),
        ))
    }
}

#[derive(Debug, Clone)]
pub(super) enum PlatformStateInternal {
    NeedsPin {
        attempts_left: Option<u32>,
        pin_tx: mpsc::Sender<String>,
    },
    SelectingCredential {
        response: GetAssertionResponse,
        cred_tx: mpsc::Sender<String>,
    },
    Failed(credentialsd_common::model::Error),
    Completed(CredentialResponse),
}

#[derive(Debug, Clone)]
pub enum PlatformState {
    NeedsPin {
        attempts_left: Option<u32>,
        pin_tx: mpsc::Sender<String>,
    },
    SelectingCredential {
        creds: Vec<Credential>,
        cred_tx: mpsc::Sender<String>,
    },
    Failed(credentialsd_common::model::Error),
    Completed,
}

impl From<PlatformStateInternal> for PlatformState {
    fn from(value: PlatformStateInternal) -> Self {
        match value {
            PlatformStateInternal::NeedsPin {
                attempts_left,
                pin_tx,
            } => Self::NeedsPin {
                attempts_left,
                pin_tx,
            },
            PlatformStateInternal::SelectingCredential { response, cred_tx } => {
                Self::SelectingCredential {
                    creds: assertions_to_metadata(&response.assertions),
                    cred_tx,
                }
            }

            PlatformStateInternal::Failed(err) => Self::Failed(err),
            PlatformStateInternal::Completed(_) => Self::Completed,
        }
    }
}

impl From<&PlatformState> for credentialsd_common::model::PlatformState {
    fn from(value: &PlatformState) -> Self {
        match value {
            PlatformState::NeedsPin { attempts_left, .. } => {
                credentialsd_common::model::PlatformState::NeedsPin {
                    attempts_left: attempts_left.clone(),
                }
            }
            PlatformState::SelectingCredential { creds, .. } => {
                credentialsd_common::model::PlatformState::SelectingCredential {
                    creds: creds.clone(),
                }
            }
            PlatformState::Completed => credentialsd_common::model::PlatformState::Completed,
            PlatformState::Failed(error) => {
                credentialsd_common::model::PlatformState::Failed(error.clone().into())
            }
        }
    }
}

// TODO: Extract this to shared module where USB can access it.
// TODO: Add a separate type for Credential that ensures we're using a masked credential ID.
fn assertions_to_metadata(assertions: &[Assertion]) -> Vec<Credential> {
    assertions
        .iter()
        .map(|x| Credential {
            id: x
                .credential_id
                .as_ref()
                .map(|i| {
                    // In order to not expose the credential ID to the untrusted UI components,
                    // we hash and then encode it into a String.
                    URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, &i.id))
                })
                .unwrap(),
            name: x
                .user
                .as_ref()
                .and_then(|u| u.name.clone())
                .unwrap_or_else(|| String::from("<unknown>")),
            username: x
                .user
                .as_ref()
                .map(|u| u.display_name.clone())
                .unwrap_or_default(),
        })
        .collect()
}

fn find_assertion_by_masked_credential_id(
    assertions: &[Assertion],
    cred_id: String,
) -> Option<Assertion> {
    assertions
        .iter()
        .find(|c| {
            c.credential_id
                .as_ref()
                .map(|c| {
                    // In order to not expose the credential ID to the untrusted UI component,
                    // we hashed it, before sending it. So we have to re-hash all our credential
                    // IDs to identify the selected one.
                    URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, &c.id))
                        == cred_id
                })
                .unwrap_or_default()
        })
        .cloned()
}

// this is here to prevent making HybridStateInternal public to the whole crate.
/// Messages between hybrid handler and credential service.
pub struct PlatformEvent {
    pub(super) state: PlatformStateInternal,
}

pub struct PlatformStateStream<P> {
    inner: P,
    ctx: Arc<Mutex<Option<RequestContext>>>,
}

impl<P> PlatformStateStream<P>
where
    P: Stream<Item = PlatformEvent> + Unpin + Sized,
{
    pub(super) fn new(stream: P, ctx: Arc<Mutex<Option<RequestContext>>>) -> Self {
        Self { inner: stream, ctx }
    }
}

impl<P> Stream for PlatformStateStream<P>
where
    P: Stream<Item = PlatformEvent> + Unpin + Sized,
{
    type Item = PlatformState;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let ctx = &self.ctx.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(PlatformEvent { state })) => {
                if let PlatformStateInternal::Completed(response) = &state {
                    super::complete_request(ctx, response.clone());
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}
