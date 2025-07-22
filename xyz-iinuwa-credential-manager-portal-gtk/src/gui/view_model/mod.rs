pub mod gtk;

use std::sync::Arc;

use async_std::prelude::*;
use async_std::{
    channel::{Receiver, Sender},
    sync::Mutex as AsyncMutex,
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::credential_service::CredentialServiceClient;
use crate::model::{
    BackgroundEvent, Credential, Device, Error, HybridState, Operation, Transport, UsbState,
    ViewUpdate,
};

#[derive(Debug)]
pub(crate) struct ViewModel<C>
where
    C: CredentialServiceClient + Send,
{
    credential_service: Arc<AsyncMutex<C>>,
    tx_update: Sender<ViewUpdate>,
    rx_event: Receiver<ViewEvent>,
    bg_event: Receiver<BackgroundEvent>,
    title: String,
    operation: Operation,

    // This includes devices like platform authenticator, USB, hybrid
    devices: Vec<Device>,
    selected_device: Option<Device>,

    // providers: Vec<Provider>,
    usb_cred_tx: Option<Arc<AsyncMutex<mpsc::Sender<String>>>>,

    hybrid_qr_state: HybridState,
    hybrid_qr_code_data: Option<Vec<u8>>,
    // hybrid_linked_state: HybridState,
}

impl<C: CredentialServiceClient + Send> ViewModel<C> {
    pub(crate) fn new(
        operation: Operation,
        credential_service: Arc<AsyncMutex<C>>,
        rx_event: Receiver<ViewEvent>,
        tx_update: Sender<ViewUpdate>,
    ) -> Self {
        let (bg_update, bg_event) = async_std::channel::unbounded::<BackgroundEvent>();
        Self {
            credential_service,
            rx_event,
            tx_update,
            bg_event,
            operation,
            title: String::default(),
            devices: Vec::new(),
            selected_device: None,
            usb_cred_tx: None,
            hybrid_qr_state: HybridState::default(),
            hybrid_qr_code_data: None,
        }
    }

    async fn update_title(&mut self) {
        self.title = match self.operation {
            Operation::Create { .. } => "Create new credential",
            Operation::Get { .. } => "Use a credential",
        }
        .to_string();
        self.tx_update
            .send(ViewUpdate::SetTitle(self.title.to_string()))
            .await
            .unwrap();
    }

    async fn update_devices(&mut self) {
        let devices = self
            .credential_service
            .lock()
            .await
            .get_available_public_key_devices()
            .await
            .unwrap();
        self.devices = devices;
        self.tx_update
            .send(ViewUpdate::SetDevices(self.devices.to_owned()))
            .await
            .unwrap();
    }

    pub(crate) async fn select_device(&mut self, id: &str) {
        let device = self.devices.iter().find(|d| d.id == id).unwrap();
        tracing::debug!("Device selected: {:?}", device);

        // Handle previous device
        if let Some(prev_device) = self.selected_device.replace(device.clone()) {
            if *device == prev_device {
                return;
            }
            match prev_device.transport {
                Transport::Usb => {
                    todo!("Implement cancellation for USB");
                }
                Transport::HybridQr => {
                    todo!("Implement cancellation for Hybrid QR");
                }
                _ => {
                    todo!();
                }
            };
        }

        // start discovery for newly selected device
        match device.transport {
            Transport::Usb => {
                let mut cred_service = self.credential_service.lock().await;
                (*cred_service).get_usb_credential().await.unwrap();
            }
            Transport::HybridQr => {
                let mut cred_service = self.credential_service.lock().await;
                cred_service.get_hybrid_credential().await.unwrap();
            }
            _ => {
                todo!()
            }
        }

        self.tx_update
            .send(ViewUpdate::WaitingForDevice(device.clone()))
            .await
            .unwrap();
    }

    pub(crate) async fn start_event_loop(&mut self) {
        let view_events = self.rx_event.clone().map(Event::View);
        let bg_events = {
            let mut cred_service = self.credential_service.lock().await;
            cred_service.initiate_event_stream().await.unwrap()
        };
        let mut all_events = view_events.merge(bg_events.map(Event::Background));
        while let Some(event) = all_events.next().await {
            match event {
                Event::View(ViewEvent::Initiated) => {
                    self.update_title().await;
                    self.update_devices().await;
                }
                Event::View(ViewEvent::DeviceSelected(id)) => {
                    self.select_device(&id).await;
                    println!("Selected device {id}");
                }
                Event::View(ViewEvent::UsbPinEntered(pin)) => {
                    let mut cred_service = self.credential_service.lock().await;
                    if cred_service.enter_client_pin(pin).await.is_err() {
                        error!("Failed to send pin to device");
                    }
                }
                Event::View(ViewEvent::CredentialSelected(cred_id)) => {
                    println!(
                        "Credential selected: {:?}. Current Device: {:?}",
                        cred_id, self.selected_device
                    );

                    if let Some(cred_tx) = self.usb_cred_tx.take() {
                        if cred_tx.lock().await.send(cred_id.clone()).await.is_err() {
                            error!("Failed to send selected credential to device");
                        }
                    }
                }

                Event::Background(BackgroundEvent::UsbStateChanged(state)) => {
                    match state {
                        UsbState::Connected => {
                            info!("Found USB device")
                        }

                        UsbState::NeedsPin { attempts_left } => {
                            self.tx_update
                                .send(ViewUpdate::UsbNeedsPin { attempts_left })
                                .await
                                .unwrap();
                        }
                        UsbState::NeedsUserVerification { attempts_left } => {
                            self.tx_update
                                .send(ViewUpdate::UsbNeedsUserVerification { attempts_left })
                                .await
                                .unwrap();
                        }
                        UsbState::NeedsUserPresence => {
                            self.tx_update
                                .send(ViewUpdate::UsbNeedsUserPresence)
                                .await
                                .unwrap();
                        }
                        UsbState::Completed => {
                            self.tx_update.send(ViewUpdate::Completed).await.unwrap();
                        }
                        UsbState::SelectingDevice => {
                            self.tx_update
                                .send(ViewUpdate::SelectingDevice)
                                .await
                                .unwrap();
                        }
                        UsbState::Idle | UsbState::Waiting => {}
                        UsbState::SelectCredential { creds } => {
                            self.tx_update
                                .send(ViewUpdate::SetCredentials(creds))
                                .await
                                .unwrap();
                        }
                        // TODO: Provide more specific error messages using the wrapped Error.
                        UsbState::Failed(err) => {
                            let error_msg = String::from(match err {
                                Error::NoCredentials => "No matching credentials found on this authenticator.",
                                Error::PinAttemptsExhausted => "No more PIN attempts allowed. Try removing your device and plugging it back in.",
                                Error::AuthenticatorError | Error::Internal(_) => "Something went wrong while retrieving a credential. Please try again later or use a different authenticator.",
                            });
                            self.tx_update
                                .send(ViewUpdate::Failed(error_msg))
                                .await
                                .unwrap()
                        }
                    }
                }
                Event::Background(BackgroundEvent::HybridQrStateChanged(state)) => {
                    self.hybrid_qr_state = state.clone();
                    tracing::debug!("Received HybridQrState::{:?}", &state);
                    match state {
                        HybridState::Idle => {
                            self.hybrid_qr_code_data = None;
                        }
                        HybridState::Started(qr_code) => {
                            self.hybrid_qr_code_data = Some(qr_code.clone().into_bytes());
                            self.tx_update
                                .send(ViewUpdate::HybridNeedsQrCode(qr_code))
                                .await
                                .unwrap();
                        }
                        HybridState::Connecting => {
                            self.hybrid_qr_code_data = None;
                            self.tx_update
                                .send(ViewUpdate::HybridConnecting)
                                .await
                                .unwrap();
                        }
                        HybridState::Connected => {
                            self.hybrid_qr_code_data = None;
                            self.tx_update
                                .send(ViewUpdate::HybridConnected)
                                .await
                                .unwrap();
                        }
                        HybridState::Completed => {
                            self.hybrid_qr_code_data = None;
                            self.tx_update.send(ViewUpdate::Completed).await.unwrap();
                        }
                        HybridState::UserCancelled => {
                            self.hybrid_qr_code_data = None;
                        }
                        HybridState::Failed => {
                            self.hybrid_qr_code_data = None;
                            self.tx_update.send(ViewUpdate::Failed(String::from("Something went wrong. Try again later or use a different authenticator."))).await.unwrap();
                        }
                    };
                }
            };
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum ViewEvent {
    Initiated,
    DeviceSelected(String),
    CredentialSelected(String),
    UsbPinEntered(String),
}

pub enum Event {
    Background(BackgroundEvent),
    View(ViewEvent),
}

impl From<crate::credential_service::hybrid::HybridState> for HybridState {
    fn from(value: crate::credential_service::hybrid::HybridState) -> Self {
        match value {
            crate::credential_service::hybrid::HybridState::Init(qr_code) => {
                HybridState::Started(qr_code)
            }
            crate::credential_service::hybrid::HybridState::Connecting => HybridState::Connecting,
            crate::credential_service::hybrid::HybridState::Connected => HybridState::Connected,
            crate::credential_service::hybrid::HybridState::Completed => HybridState::Completed,
            crate::credential_service::hybrid::HybridState::UserCancelled => {
                HybridState::UserCancelled
            }
            crate::credential_service::hybrid::HybridState::Failed => HybridState::Failed,
        }
    }
}
