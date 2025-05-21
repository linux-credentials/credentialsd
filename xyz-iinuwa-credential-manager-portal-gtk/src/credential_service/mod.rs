use std::sync::{Arc, Mutex, OnceLock};

use libwebauthn::{
    self,
    ops::webauthn::{GetAssertionResponse, MakeCredentialResponse},
    transport::Device as _,
    webauthn::{Error as WebAuthnError, WebAuthn},
    UxUpdate,
};

use async_std::{
    channel::TryRecvError,
    sync::{Arc as AsyncArc, Mutex as AsyncMutex},
};
use tokio::runtime::Runtime;
use tracing::{debug, warn};

use crate::{
    dbus::{
        CredentialRequest, CredentialResponse, GetAssertionResponseInternal,
        MakeCredentialResponseInternal,
    },
    view_model::{Device, Transport},
};

#[derive(Debug)]
pub struct CredentialService {
    devices: Vec<Device>,

    usb_state: AsyncArc<AsyncMutex<UsbState>>,
    usb_uv_handler: UsbUvHandler,

    cred_request: CredentialRequest,
    // Place to store data to be returned to the caller
    cred_response: Arc<Mutex<Option<CredentialResponse>>>,
}

impl CredentialService {
    pub fn new(
        cred_request: CredentialRequest,
        cred_response: Arc<Mutex<Option<CredentialResponse>>>,
    ) -> Self {
        let devices = vec![Device {
            id: String::from("0"),
            transport: Transport::Usb,
        }];
        let usb_state = AsyncArc::new(AsyncMutex::new(UsbState::Idle));
        Self {
            devices,

            usb_state: usb_state.clone(),
            usb_uv_handler: UsbUvHandler::new(),

            cred_request,
            cred_response,
        }
    }

    pub async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        Ok(self.devices.to_owned())
    }

    pub(crate) async fn poll_device_discovery_usb(&mut self) -> Result<UsbState, String> {
        debug!("polling for USB status");
        let prev_usb_state = self.usb_state.lock().await.clone();
        let next_usb_state = match prev_usb_state {
            UsbState::Idle | UsbState::Waiting => {
                let devices = libwebauthn::transport::hid::list_devices().await.unwrap();
                if devices.is_empty() {
                    let state = UsbState::Waiting;
                    *self.usb_state.lock().await = state;
                    return Ok(state);
                }
                if devices.is_empty() {
                    Ok(UsbState::Waiting)
                } else {
                    Ok(UsbState::Connected)
                }
            }
            UsbState::Connected => {
                // TODO: I'm not sure how we want to handle multiple usb devices
                // just take the first one found for now.
                // TODO: store this device reference, perhaps in the enum itself
                let handler = self.usb_uv_handler.clone();
                let cred_request = self.cred_request.clone();
                let signal_tx = self.usb_uv_handler.signal_tx.clone();
                let pin_rx = self.usb_uv_handler.pin_rx.clone();
                tokio().spawn(async move {
                    let mut devices = libwebauthn::transport::hid::list_devices().await.unwrap();
                    let device = devices.first_mut().unwrap();
                    let (mut channel, state_rx) = device.channel().await.unwrap();
                    tokio().spawn(async move {
                        handle_usb_updates(signal_tx, pin_rx, state_rx).await;
                        debug!("Reached end of USB update task");
                    });
                    match cred_request {
                        CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request) => {
                            loop {
                                match channel.webauthn_make_credential(&make_cred_request).await {
                                    Ok(response) => {
                                        handler
                                            .notify_ceremony_completed(
                                                AuthenticatorResponse::CredentialCreated(response),
                                            )
                                            .await;
                                        break;
                                    }
                                    Err(WebAuthnError::Ctap(ctap_error))
                                        if ctap_error.is_retryable_user_error() =>
                                    {
                                        warn!("Retrying WebAuthn make credential operation");
                                        continue;
                                    }
                                    Err(err) => {
                                        handler.notify_ceremony_failed(err.to_string()).await;
                                        break;
                                    }
                                };
                            }
                        }
                        CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request) => {
                            loop {
                                match channel.webauthn_get_assertion(&get_cred_request).await {
                                    Ok(response) => {
                                        handler
                                            .notify_ceremony_completed(
                                                AuthenticatorResponse::CredentialsAsserted(
                                                    response,
                                                ),
                                            )
                                            .await;
                                        break;
                                    }
                                    Err(WebAuthnError::Ctap(ctap_error))
                                        if ctap_error.is_retryable_user_error() =>
                                    {
                                        warn!("Retrying WebAuthn get credential operation");
                                        continue;
                                    }
                                    Err(err) => {
                                        handler.notify_ceremony_failed(err.to_string()).await;
                                        break;
                                    }
                                };
                            }
                        }
                    };
                });
                match self.usb_uv_handler.wait_for_notification().await {
                    Ok(UsbUvMessage::NeedsPin { attempts_left }) => {
                        Ok(UsbState::NeedsPin { attempts_left })
                    }
                    Ok(UsbUvMessage::NeedsUserVerification { attempts_left }) => {
                        Ok(UsbState::NeedsUserVerification { attempts_left })
                    }
                    Ok(UsbUvMessage::NeedsUserPresence) => Ok(UsbState::NeedsUserPresence),
                    Ok(UsbUvMessage::ReceivedCredential(response)) => {
                        match response {
                            AuthenticatorResponse::CredentialCreated(r) => {
                                let mut cred_response = self.cred_response.lock().unwrap();
                                cred_response.replace(
                                    CredentialResponse::CreatePublicKeyCredentialResponse(
                                        MakeCredentialResponseInternal::new(
                                            r,
                                            vec![String::from("usb")],
                                            String::from("cross-platform"),
                                        ),
                                    ),
                                );
                                Ok(UsbState::Completed)
                            }
                            AuthenticatorResponse::CredentialsAsserted(r) => {
                                // at least one credential is returned from the authenticator
                                assert!(!r.assertions.is_empty());
                                if r.assertions.len() == 1 {
                                    let mut cred_response = self.cred_response.lock().unwrap();
                                    cred_response.replace(
                                        CredentialResponse::GetPublicKeyCredentialResponse(
                                            GetAssertionResponseInternal::new(
                                                r.assertions[0].clone(),
                                                String::from("cross-platform"),
                                            ),
                                        ),
                                    );
                                    Ok(UsbState::Completed)
                                } else {
                                    todo!("need to support selection from multiple credentials");
                                }
                            }
                        }
                    }
                    Err(err) => Err(err),
                }
            }
            UsbState::NeedsPin {
                attempts_left: Some(attempts_left),
            } if attempts_left <= 1 => Err("No more USB attempts left".to_string()),
            UsbState::NeedsUserVerification {
                attempts_left: Some(attempts_left),
            } if attempts_left <= 1 => {
                Err("No more on-device user device attempts left".to_string())
            }
            UsbState::NeedsPin { .. }
            | UsbState::NeedsUserVerification { .. }
            | UsbState::NeedsUserPresence => {
                match self.usb_uv_handler.check_notification().await? {
                    Some(UsbUvMessage::NeedsPin { attempts_left }) => {
                        Ok(UsbState::NeedsPin { attempts_left })
                    }
                    Some(UsbUvMessage::NeedsUserVerification { attempts_left }) => {
                        Ok(UsbState::NeedsUserVerification { attempts_left })
                    }
                    Some(UsbUvMessage::NeedsUserPresence) => Ok(UsbState::NeedsUserPresence),
                    Some(UsbUvMessage::ReceivedCredential(response)) => {
                        match response {
                            AuthenticatorResponse::CredentialCreated(r) => {
                                let mut cred_response = self.cred_response.lock().unwrap();
                                cred_response.replace(
                                    CredentialResponse::CreatePublicKeyCredentialResponse(
                                        MakeCredentialResponseInternal::new(
                                            r,
                                            vec![String::from("usb")],
                                            String::from("cross-platform"),
                                        ),
                                    ),
                                );
                                Ok(UsbState::Completed)
                            }
                            AuthenticatorResponse::CredentialsAsserted(r) => {
                                // at least one credential is returned from the authenticator
                                assert!(!r.assertions.is_empty());
                                if r.assertions.len() == 1 {
                                    let mut cred_response = self.cred_response.lock().unwrap();
                                    cred_response.replace(
                                        CredentialResponse::GetPublicKeyCredentialResponse(
                                            GetAssertionResponseInternal::new(
                                                r.assertions[0].clone(),
                                                String::from("cross-platform"),
                                            ),
                                        ),
                                    );
                                    Ok(UsbState::Completed)
                                } else {
                                    todo!("need to support selection from multiple credentials");
                                }
                            }
                        }
                    }
                    None => Ok(prev_usb_state),
                }
            }
            UsbState::Completed => Ok(prev_usb_state),
            UsbState::UserCancelled => Ok(prev_usb_state),
        }?;

        *self.usb_state.lock().await = next_usb_state;
        Ok(next_usb_state)
    }

    pub(crate) async fn cancel_device_discovery_usb(&mut self) -> Result<(), String> {
        *self.usb_state.lock().await = UsbState::Idle;
        println!("frontend: Cancel USB request");
        Ok(())
    }

    pub(crate) async fn validate_usb_device_pin(&mut self, pin: &str) -> Result<(), ()> {
        let current_state = self.usb_state.lock().await.clone();
        match current_state {
            UsbState::NeedsPin {
                attempts_left: Some(attempts_left),
            } if attempts_left > 1 => {
                self.usb_uv_handler.send_pin(pin).await;
                Ok(())
            }
            _ => Err(()),
        }
    }

    pub(crate) fn complete_auth(&mut self) {
        // let mut data = self.output_data.lock().unwrap();
        // data.replace((self.cred_response));
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub enum UsbState {
    /// Not polling for FIDO USB device.
    #[default]
    Idle,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

    /// USB device connected, prompt user to tap
    Connected,

    /// The device needs the PIN to be entered.
    NeedsPin {
        attempts_left: Option<u32>,
    },

    /// The device needs on-device user verification.
    NeedsUserVerification {
        attempts_left: Option<u32>,
    },

    /// The device needs evidence of user presence (e.g. touch) to release the credential.
    NeedsUserPresence,

    /// USB tapped, received credential
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,
}

#[derive(Clone, Debug)]
pub struct UsbUvHandler {
    signal_tx: async_std::channel::Sender<Result<UsbUvMessage, String>>,
    signal_rx: async_std::channel::Receiver<Result<UsbUvMessage, String>>,
    pin_tx: async_std::channel::Sender<String>,
    pin_rx: async_std::channel::Receiver<String>,
}

impl UsbUvHandler {
    fn new() -> Self {
        let (signal_tx, signal_rx) = async_std::channel::unbounded();
        let (pin_tx, pin_rx) = async_std::channel::unbounded();
        UsbUvHandler {
            signal_tx,
            signal_rx,
            pin_tx,
            pin_rx,
        }
    }

    async fn notify_ceremony_completed(&self, response: AuthenticatorResponse) {
        self.signal_tx
            .send(Ok(UsbUvMessage::ReceivedCredential(response)))
            .await
            .unwrap();
    }

    async fn notify_ceremony_failed(&self, err: String) {
        self.signal_tx.send(Err(err)).await.unwrap();
    }

    async fn send_pin(&self, pin: &str) {
        self.pin_tx.send(pin.to_owned()).await.unwrap();
    }

    async fn wait_for_notification(&self) -> Result<UsbUvMessage, String> {
        match self.signal_rx.recv().await {
            Ok(msg) => msg,
            Err(err) => Err(err.to_string()),
        }
    }

    async fn check_notification(&self) -> Result<Option<UsbUvMessage>, String> {
        match self.signal_rx.try_recv() {
            Ok(msg) => Ok(Some(msg?)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Closed) => Err("USB UV handler channel closed".to_string()),
        }
    }
}

async fn handle_usb_updates(
    signal_tx: async_std::channel::Sender<Result<UsbUvMessage, String>>,
    pin_rx: async_std::channel::Receiver<String>,
    mut state_rx: tokio::sync::mpsc::Receiver<UxUpdate>,
) {
    while let Some(msg) = state_rx.recv().await {
        match msg {
            UxUpdate::UvRetry { attempts_left } => {
                signal_tx
                    .send(Ok(UsbUvMessage::NeedsUserVerification { attempts_left }))
                    .await
                    .unwrap();
            }
            UxUpdate::PinRequired(pin_update) => {
                if pin_update.attempts_left.map_or(false, |num| num <= 1) {
                    // TODO: cancel authenticator operation
                    signal_tx.send(Err("No more PIN attempts allowed. Select a different authenticator or try again later.".to_string())).await.unwrap();
                    continue;
                }
                signal_tx
                    .send(Ok(UsbUvMessage::NeedsPin {
                        attempts_left: pin_update.attempts_left,
                    }))
                    .await
                    .unwrap();
                if let Ok(pin) = pin_rx.recv().await {
                    pin_update.send_pin(&pin).unwrap();
                } else {
                    debug!("PIN channel closed.");
                }
            }
            UxUpdate::PresenceRequired => {
                signal_tx
                    .send(Ok(UsbUvMessage::NeedsUserPresence))
                    .await
                    .unwrap();
            }
        }
    }
    debug!("USB update channel closed.");
}

enum UsbUvMessage {
    NeedsPin { attempts_left: Option<u32> },
    NeedsUserVerification { attempts_left: Option<u32> },
    NeedsUserPresence,
    ReceivedCredential(AuthenticatorResponse),
}
fn tokio() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().expect("Tokio runtime to start"))
}

enum AuthenticatorResponse {
    CredentialCreated(MakeCredentialResponse),
    CredentialsAsserted(GetAssertionResponse),
}
