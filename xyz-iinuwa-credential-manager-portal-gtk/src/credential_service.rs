use std::{
    ops::Add,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use libwebauthn::{self, ops::webauthn::{GetAssertionResponse, MakeCredentialResponse}, pin::{PinRequestReason, UvProvider}, transport::Device as _, webauthn::{Error as WebAuthnError, WebAuthn}};

use async_std::{channel::TryRecvError, sync::{Arc as AsyncArc, Mutex as AsyncMutex}, task};
use tokio::runtime::Runtime;
use tracing::warn;

use crate::{dbus::{CredentialRequest, CredentialResponse}, view_model::{Device, InternalPinState, Transport}};

#[derive(Debug)]
pub struct CredentialService {
    devices: Vec<Device>,

    usb_state: AsyncArc<AsyncMutex<UsbState>>,
    usb_uv_handler: UsbUvHandler,

    internal_device_credentials: Vec<CredentialMetadata>,
    internal_device_state: InternalDeviceState,
    internal_pin_attempts_left: u32,
    internal_pin_unlock_time: Option<SystemTime>,


    cred_request: CredentialRequest,
    // Place to store data to be returned to the caller
    cred_response: Arc<Mutex<Option<CredentialResponse>>>,
}

impl CredentialService {
    pub fn new(cred_request: CredentialRequest, cred_response: Arc<Mutex<Option<(CredentialResponse)>>>) -> Self {
        let devices = vec![
            Device {
                id: String::from("0"),
                transport: Transport::Usb,
            },
            Device {
                id: String::from("1"),
                transport: Transport::Internal,
            },
        ];
        let internal_device_credentials = vec![
            CredentialMetadata {
                id: String::from("0"),
                origin: String::from("foo.example.com"),
                display_name: String::from("Foo"),
                username: String::from("joecool"),
            },
            CredentialMetadata {
                id: String::from("1"),
                origin: String::from("bar.example.org"),
                display_name: String::from("Bar"),
                username: String::from("cooliojoe"),
            },
        ];
        let usb_state = AsyncArc::new(AsyncMutex::new(UsbState::Idle));
        Self {
            devices,

            usb_state: usb_state.clone(),
            usb_uv_handler: UsbUvHandler::new(),

            internal_device_credentials,
            internal_device_state: InternalDeviceState::Idle,
            internal_pin_attempts_left: 5,
            internal_pin_unlock_time: None,

            cred_request,
            cred_response,

        }
    }

    pub async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        Ok(self.devices.to_owned())
    }

    pub(crate) async fn start_device_discovery_usb(&mut self) -> Result<(), String> {
        println!("frontend: Start USB flow");
        if *self.usb_state.lock().await != UsbState::Idle {
            return Err("Ongoing USB request already happening.".to_owned());
        }
        Ok(())
    }

    pub(crate) async fn poll_device_discovery_usb(&mut self) -> Result<UsbState, String> {
        let devices = libwebauthn::transport::hid::list_devices().await.unwrap();
        if devices.is_empty() {
            let state = UsbState::Waiting;
            *self.usb_state.lock().await = state;
            return Ok(state);
        }

        let prev_usb_state = self.usb_state.lock().await.clone();
        let next_usb_state = match prev_usb_state {
            UsbState::Idle => {
                if devices.is_empty() {
                    Ok(UsbState::Waiting)
                }
                else {
                    Ok(UsbState::Connected)
                }
            },
            UsbState::Waiting => {
                if devices.is_empty() {
                    Ok(UsbState::Waiting)
                }
                else {
                    Ok(UsbState::Connected)
                }
            },
            UsbState::Connected => {
                if devices.is_empty() {
                    Ok(UsbState::Waiting)
                }
                else {
                    // TODO: I'm not sure how we want to handle multiple usb devices
                    // just take the first one found for now.
                    // TODO: store this device reference, perhaps in the enum itself
                    let handler = self.usb_uv_handler.clone();
                    let pin_provider: Box<dyn UvProvider> = Box::new(self.usb_uv_handler.clone());
                    let cred_request = self.cred_request.clone();
                    tokio().spawn( async move {
                         match cred_request {
                            CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request) => {
                                let mut devices = libwebauthn::transport::hid::list_devices().await.unwrap();
                                let device = devices.first_mut().unwrap();
                                let mut channel = device.channel().await.unwrap();
                                loop {
                                     match channel
                                        .webauthn_make_credential(&make_cred_request, &pin_provider)
                                        .await
                                    {
                                        Ok(response) => {
                                            handler.notify_ceremony_completed(AuthenticatorResponse::CredentialCreated(response)).await;
                                            break
                                        },
                                        Err(WebAuthnError::Ctap(ctap_error)) if ctap_error.is_retryable_user_error() => {
                                            warn!("Retrying WebAuthn make credential operation");
                                            continue;
                                        },
                                        Err(err) => {
                                            handler.notify_ceremony_failed(err.to_string()).await;
                                            break;
                                        }
                                    };
                                };
                            },
                            CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request) => {
                                let mut devices = libwebauthn::transport::hid::list_devices().await.unwrap();
                                let device = devices.first_mut().unwrap();
                                let mut channel = device.channel().await.unwrap();
                                loop {
                                     match channel
                                        .webauthn_get_assertion(&get_cred_request, &pin_provider)
                                        .await
                                    {
                                        Ok(response) => {
                                            handler.notify_ceremony_completed(AuthenticatorResponse::CredentialsAsserted(response)).await;
                                            break
                                        },
                                        Err(WebAuthnError::Ctap(ctap_error)) if ctap_error.is_retryable_user_error() => {
                                            warn!("Retrying WebAuthn make credential operation");
                                            continue;
                                        },
                                        Err(err) => {
                                            handler.notify_ceremony_failed(err.to_string()).await;
                                            break;
                                        }
                                    };
                                };

                            }
                        };
                    });
                    match self.usb_uv_handler.wait_for_notification().await {
                        Ok(UsbUvMessage::NeedsPin { attempts_left }) => {
                            Ok(UsbState::NeedsPin { attempts_left})
                        },
                        Ok(UsbUvMessage::NeedsUv { attempts_left }) => {
                            Ok(UsbState::NeedsUv { attempts_left})
                        },
                        Ok(UsbUvMessage::ReceivedCredential(response)) => {
                            match response {
                                AuthenticatorResponse::CredentialCreated(r) => {
                                    let mut cred_response = self.cred_response.lock().unwrap();
                                    cred_response.replace(CredentialResponse::CreatePublicKeyCredentialResponse(r));
                                    Ok(UsbState::Completed)

                                },
                                AuthenticatorResponse::CredentialsAsserted(r) => {
                                    // at least one credential is returned from the authenticator
                                    assert!(!r.assertions.is_empty());
                                    if r.assertions.len() == 1 {
                                        let mut cred_response = self.cred_response.lock().unwrap();
                                        cred_response.replace(CredentialResponse::GetPublicKeyCredentialResponse(r.assertions[0].clone()));
                                        Ok(UsbState::Completed)
                                    }
                                    else {
                                        todo!("need to support selection from multiple credentials");
                                    }
                                },
                            }
                        },
                        Err(err) => Err(err),

                    }
                }
            }
            UsbState::NeedsPin{ attempts_left: Some(attempts_left) } if attempts_left <= 1 => {
                Err("No more USB attempts left".to_string())
            },
            UsbState::NeedsUv{ attempts_left: Some(attempts_left) } if attempts_left <= 1 => {
                Err("No more on-device user device attempts left".to_string())
            },
            UsbState::NeedsPin { .. } | UsbState::NeedsUv { .. } => {
                match self.usb_uv_handler.check_notification().await? {
                    Some(UsbUvMessage::NeedsPin { attempts_left }) => {
                        Ok(UsbState::NeedsPin { attempts_left })
                    },
                    Some(UsbUvMessage::NeedsUv { attempts_left }) => {
                        Ok(UsbState::NeedsUv { attempts_left })
                    },
                    Some(UsbUvMessage::ReceivedCredential(response)) => {
                        match response {
                            AuthenticatorResponse::CredentialCreated(r) => {
                                let mut cred_response = self.cred_response.lock().unwrap();
                                cred_response.replace(CredentialResponse::CreatePublicKeyCredentialResponse(r));
                                Ok(UsbState::Completed)

                            },
                            AuthenticatorResponse::CredentialsAsserted(r) => {
                                // at least one credential is returned from the authenticator
                                assert!(!r.assertions.is_empty());
                                if r.assertions.len() == 1 {
                                    let mut cred_response = self.cred_response.lock().unwrap();
                                    cred_response.replace(CredentialResponse::GetPublicKeyCredentialResponse(r.assertions[0].clone()));
                                    Ok(UsbState::Completed)
                                }
                                else {
                                    todo!("need to support selection from multiple credentials");
                                }
                            },
                        }
                    },
                    None => Ok(prev_usb_state),
                }
            }
            UsbState::Completed => {
                Ok(prev_usb_state)
            }
            UsbState::UserCancelled => {
                Ok(prev_usb_state)
            }
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
            UsbState::NeedsPin { attempts_left: Some(attempts_left) } if attempts_left > 1 => {
                self.usb_uv_handler.send_pin(pin).await;
                Ok(())
            }
            _ => Err(())
        }
    }

    pub(crate) async fn get_internal_device_credentials(
        &self,
    ) -> Result<&Vec<CredentialMetadata>, ()> {
        Ok(&self.internal_device_credentials)
    }

    pub(crate) async fn validate_internal_device_pin(
        &mut self,
        pin: &str,
        cred_id: &str,
    ) -> Result<InternalPinState, ()> {
        // TODO: Should this have the selected credential ID included with it to make sure the
        // frontend and backend are talking about the same credential?
        let now = SystemTime::now();
        if let Some(unlock_time) = self.internal_pin_unlock_time {
            if unlock_time < now {
                let t = unlock_time.duration_since(UNIX_EPOCH).unwrap();
                return Ok(InternalPinState::LockedOut { unlock_time: t });
            } else {
                self.internal_pin_unlock_time = None;
            }
        }
        if pin == "123456" {
            let device = self
                .devices
                .iter()
                .find(|d| d.transport == Transport::Internal)
                .unwrap()
                .clone();
            self.internal_device_state = InternalDeviceState::Completed {
                device,
                cred_id: cred_id.to_owned(),
            };
            Ok(InternalPinState::PinCorrect {
                completion_token: "pin".to_string(),
            })
        } else {
            self.internal_device_state = InternalDeviceState::NeedsPin;
            self.internal_pin_attempts_left -= 1;
            if self.internal_pin_attempts_left > 0 {
                Ok(InternalPinState::PinIncorrect {
                    attempts_left: self.internal_pin_attempts_left,
                })
            } else {
                let t = now.add(Duration::from_secs(10));
                self.internal_pin_unlock_time = Some(t);
                Ok(InternalPinState::LockedOut {
                    unlock_time: t.duration_since(UNIX_EPOCH).unwrap(),
                })
            }
        }
    }

    pub(crate) async fn start_device_discovery_internal(
        &mut self,
    ) -> Result<InternalDeviceState, String> {
        println!("frontend: Start Internal flow");
        if let InternalDeviceState::Idle = self.internal_device_state {
            self.internal_device_state = InternalDeviceState::NeedsPin;
            Ok(self.internal_device_state.clone())
        } else {
            Err(format!(
                "Invalid state to begin discovery: {:?}",
                self.internal_device_state
            ))
        }
    }

    pub(crate) async fn poll_device_discovery_internal(
        &mut self,
    ) -> Result<InternalDeviceState, String> {
        task::sleep(Duration::from_millis(5)).await;

        if let InternalDeviceState::Idle = self.internal_device_state {
            return Err(String::from("Internal polling not started."));
        }

        Ok(self.internal_device_state.clone())
    }

    pub(crate) async fn cancel_device_discovery_internal(&mut self) -> Result<(), String> {
        self.internal_device_state = InternalDeviceState::Idle;
        Ok(())
    }

    pub(crate) fn complete_auth(&mut self) {
        // let mut data = self.output_data.lock().unwrap();
        // data.replace((self.cred_response));
    }
}

#[derive(Clone, Copy)]
pub(crate) struct UsbPollResponse {
    pub state: UsbState,
    poll_count: i32,
    needs_pin: bool,
    pin_entered: bool,
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
    NeedsPin { attempts_left: Option<u32> },

    /// The device needs on-device user verification.
    NeedsUv { attempts_left: Option<u32> },

    /// USB tapped, received credential
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum InternalDeviceState {
    /// Not awaiting for internal FIDO device.
    #[default]
    Idle,

    /// The device needs the PIN to be entered.
    NeedsPin,

    /// Internal device credentials
    Completed {
        device: Device,
        cred_id: String,
    },

    // This isn't actually sent from the server.
    UserCancelled,
}

pub enum PinResponse {
    Correct,
    /// Incorrect PIN given, contains time (in seconds since Unix epoch) when
    /// the user can retry.
    // TODO: Should we show how many retries are left?
    Incorrect(usize),

    /// PIN locked out, contains time (in seconds since Unix epoch) when
    /// the user can retry.
    Locked(Duration),
}

#[derive(Debug)]
pub(crate) struct CredentialMetadata {
    /// ID of credential, to be used in `SelectCredential()`.
    pub(crate) id: String,

    /// Origin of credential.
    // TODO: Does this need to be multiple origins?
    pub(crate) origin: String,

    /// User-chosen name for the credential.
    pub(crate) display_name: String,

    /// Username of credential, if any.
    pub(crate) username: String,
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
            pin_rx
        }
    }

    async fn notify_ceremony_completed(&self, response: AuthenticatorResponse) {
        self.signal_tx.send(Ok(UsbUvMessage::ReceivedCredential(response))).await.unwrap();
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

#[async_trait]
impl UvProvider for UsbUvHandler {
    async fn provide_pin(&self, attempts_left:Option<u32>, request_reason: PinRequestReason) -> Option<String> {
        let _ = self.signal_tx.send(Ok(UsbUvMessage::NeedsPin { attempts_left })).await;
        if attempts_left.map_or(false, |num| num <= 1) {
            return None;
        }
        if let Ok(pin) = self.pin_rx.recv().await {
            Some(pin)
        } else { None }
    }

    async fn prompt_uv_retry(&self, attempts_left: Option<u32>) {
        todo!("UV retry not implemented");
    }
}

enum UsbUvMessage {
    NeedsPin { attempts_left: Option<u32> },
    NeedsUv { attempts_left: Option<u32> },
    ReceivedCredential(AuthenticatorResponse),
}
fn tokio() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        Runtime::new().expect("Tokio runtime to start")
    })
}

enum AuthenticatorResponse {
    CredentialCreated(MakeCredentialResponse),
    CredentialsAsserted(GetAssertionResponse),
}
