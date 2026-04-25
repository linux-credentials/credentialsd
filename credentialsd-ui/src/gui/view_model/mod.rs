pub mod gtk;

use std::sync::Arc;

use async_std::prelude::*;
use async_std::{
    channel::{Receiver, Sender},
    sync::Mutex as AsyncMutex,
};
use credentialsd_common::model::RequestingApplication;
use credentialsd_common::server::{BackgroundEvent, Credential, ViewRequest};
use gettextrs::gettext;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use credentialsd_common::{
    client::FlowController,
    model::{Device, Error, HybridState, NfcState, Operation, Transport, UsbState, ViewUpdate},
};

#[derive(Debug)]
pub(crate) struct ViewModel<F>
where
    F: FlowController + Send,
{
    flow_controller: Arc<AsyncMutex<F>>,
    tx_update: Sender<ViewUpdate>,
    rx_event: Receiver<ViewEvent>,
    title: String,
    subtitle: String,
    operation: Operation,
    rp_id: String,
    app_name: String,
    app_path_or_id: String,
    app_pid: u32,

    // This includes devices like platform authenticator, USB, hybrid
    devices: Vec<Device>,
    selected_device: Option<Device>,

    // providers: Vec<Provider>,
    hybrid_qr_state: HybridState,
    hybrid_qr_code_data: Option<Vec<u8>>,
    // hybrid_linked_state: HybridState,
}

impl<F: FlowController + Send> ViewModel<F> {
    pub(crate) fn new(
        request: ViewRequest,
        flow_controller: Arc<AsyncMutex<F>>,
        rx_event: Receiver<ViewEvent>,
        tx_update: Sender<ViewUpdate>,
    ) -> Self {
        let RequestingApplication {
            name: app_name,
            path_or_app_id: path,
            pid,
        } = request.requesting_app;

        let app_name: Option<String> = app_name.into();
        let devices = request.initial_devices;
        Self {
            flow_controller,
            rx_event,
            tx_update,
            operation: request.operation,
            rp_id: request.rp_id,
            app_name: app_name.unwrap_or_else(|| gettext("unknown application")),
            app_path_or_id: path,
            app_pid: pid,
            title: String::default(),
            subtitle: String::default(),
            devices,
            selected_device: None,
            hybrid_qr_state: HybridState::default(),
            hybrid_qr_code_data: None,
        }
    }

    async fn update_title(&mut self) {
        let mut title = match self.operation {
            Operation::Create => {
                // TRANSLATORS: %s1 is the "relying party" (think: domain name) where the request is coming from
                gettext("Create a passkey for %s1")
            }
            Operation::Get => {
                // TRANSLATORS: %s1 is the "relying party" (think: domain name) where the request is coming from
                gettext("Use a passkey for %s1")
            }
        }
        .to_string();
        title = title.replace("%s1", &self.rp_id);

        let mut subtitle = match self.operation {
            Operation::Create => {
                // TRANSLATORS: %s1 is the "relying party" (e.g.: domain name) where the request is coming from
                // TRANSLATORS: %s2 is the application name (e.g.: firefox) where the request is coming from, <b></b> must be left untouched to make the name bold
                // TRANSLATORS: %i1 is the process ID of the requesting application
                // TRANSLATORS: %s3 is the absolute path (think: /usr/bin/firefox) of the requesting application
                gettext("<b>\"%s2\"</b> (process ID: %i1, binary: %s3) is asking to create a credential to register at \"%s1\". Only proceed if you trust this process.")
            }
            Operation::Get => {
                // TRANSLATORS: %s1 is the "relying party" (think: domain name) where the request is coming from
                // TRANSLATORS: %s2 is the application name (e.g.: firefox) where the request is coming from, <b></b> must be left untouched to make the name bold
                // TRANSLATORS: %i1 is the process ID of the requesting application
                // TRANSLATORS: %s3 is the absolute path (think: /usr/bin/firefox) of the requesting application
                gettext("<b>\"%s2\"</b> (process ID: %i1, binary: %s3) is asking to use a credential to sign in to \"%s1\". Only proceed if you trust this process.")
            }
        }
        .to_string();
        subtitle = subtitle.replace("%s1", &self.rp_id);
        subtitle = subtitle.replace("%i1", &format!("{}", self.app_pid));
        subtitle = subtitle.replace("%s2", &self.app_name);
        subtitle = subtitle.replace("%s3", &self.app_path_or_id);
        self.title = title;
        self.subtitle = subtitle;
        self.tx_update
            .send(ViewUpdate::SetTitle((
                self.title.to_string(),
                self.subtitle.to_string(),
            )))
            .await
            .unwrap();
    }

    async fn update_devices(&mut self, devices: Vec<Device>) {
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
                Transport::Nfc => {
                    todo!("Implement cancellation for NFC");
                }
                _ => {
                    todo!();
                }
            };
        }

        // start discovery for newly selected device
        match device.transport {
            Transport::Usb => {
                let mut cred_service = self.flow_controller.lock().await;
                (*cred_service).get_usb_credential().await.unwrap();
            }
            Transport::Nfc => {
                let mut cred_service = self.flow_controller.lock().await;
                (*cred_service).get_nfc_credential().await.unwrap();
            }
            Transport::HybridQr => {
                let mut cred_service = self.flow_controller.lock().await;
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
            let mut cred_service = self.flow_controller.lock().await;
            cred_service.subscribe().await.unwrap()
        };
        let mut all_events = view_events.merge(bg_events.map(Event::Background));
        while let Some(event) = all_events.next().await {
            match event {
                Event::View(ViewEvent::Initiated) => {
                    self.update_title().await;
                    self.update_devices(self.devices.clone()).await;
                }
                Event::View(ViewEvent::DeviceSelected(id)) => {
                    self.select_device(&id).await;
                    println!("Selected device {id}");
                }
                Event::View(ViewEvent::PinEntered(pin)) => {
                    let mut cred_service = self.flow_controller.lock().await;
                    if cred_service.enter_client_pin(pin).await.is_err() {
                        error!("Failed to send pin to device");
                    }
                }
                Event::View(ViewEvent::CredentialSelected(cred_id)) => {
                    println!(
                        "Credential selected: {:?}. Current Device: {:?}",
                        cred_id, self.selected_device
                    );

                    if self
                        .flow_controller
                        .lock()
                        .await
                        .select_credential(cred_id)
                        .await
                        .is_err()
                    {
                        tracing::error!("Failed to select credential from device.");
                        self.tx_update
                            .send(ViewUpdate::Failed(gettext(
                                "Failed to select credential from device.",
                            )))
                            .await
                            .unwrap();
                    }
                }
                Event::View(ViewEvent::UserCancelled) => {
                    break;
                }

                Event::Background(BackgroundEvent::UsbConnected) => {
                    info!("Found USB device")
                }

                Event::Background(BackgroundEvent::NeedsPin { attempts_left }) => {
                    // TODO: UsbNeedsPin just needs to be NeedsPing
                    self.tx_update
                        .send(ViewUpdate::UsbNeedsPin { attempts_left })
                        .await
                        .unwrap();
                }
                Event::Background(BackgroundEvent::NeedsUserVerification { attempts_left }) => {
                    self.tx_update
                        .send(ViewUpdate::UsbNeedsUserVerification { attempts_left })
                        .await
                        .unwrap();
                }
                Event::Background(BackgroundEvent::NeedsUserPresence) => {
                    self.tx_update
                        .send(ViewUpdate::UsbNeedsUserPresence)
                        .await
                        .unwrap();
                }
                Event::Background(BackgroundEvent::CeremonyCompleted) => {
                    self.tx_update.send(ViewUpdate::Completed).await.unwrap();
                }
                Event::Background(BackgroundEvent::UsbSelectingDevice) => {
                    self.tx_update
                        .send(ViewUpdate::SelectingDevice)
                        .await
                        .unwrap();
                }
                Event::Background(BackgroundEvent::UsbIdle)
                | Event::Background(BackgroundEvent::UsbWaiting) => {}
                Event::Background(BackgroundEvent::SelectingCredential { creds }) => {
                    self.tx_update
                        .send(ViewUpdate::SetCredentials(creds))
                        .await
                        .unwrap();
                }
                Event::Background(BackgroundEvent::ErrorNoCredentials) => {
                    let error_msg = gettext("No matching credentials found on this authenticator.");
                    self.tx_update
                        .send(ViewUpdate::Failed(error_msg))
                        .await
                        .unwrap()
                }
                Event::Background(BackgroundEvent::ErrorPinAttemptsExhausted) => {
                    let error_msg = gettext(
                        "No more PIN attempts allowed. Try removing your device and plugging it back in.",
                    );
                    self.tx_update
                        .send(ViewUpdate::Failed(error_msg))
                        .await
                        .unwrap()
                }
                Event::Background(BackgroundEvent::ErrorPinNotSet) => {
                    let error_msg = gettext(
                        "This server requires your device to have additional protection like a PIN, which is not set. Please set a PIN for this device and try again.",
                    );
                    self.tx_update
                        .send(ViewUpdate::Failed(error_msg))
                        .await
                        .unwrap()
                }
                Event::Background(BackgroundEvent::ErrorTimedOut) => {
                    let error_msg = gettext("The credential request timed out. Please try again.");
                    self.tx_update
                        .send(ViewUpdate::Failed(error_msg))
                        .await
                        .unwrap()
                }
                Event::Background(
                    BackgroundEvent::ErrorAuthenticator | BackgroundEvent::ErrorInternal,
                ) => {
                    let error_msg = gettext(
                        "Something went wrong while retrieving a credential. Please try again later or use a different authenticator.",
                    );
                    self.tx_update
                        .send(ViewUpdate::Failed(error_msg))
                        .await
                        .unwrap()
                }
                Event::Background(BackgroundEvent::ErrorCredentialExcluded) => {
                    let error_msg =
                        gettext("This credential is already registered on this authenticator.");
                    self.tx_update
                        .send(ViewUpdate::Failed(error_msg))
                        .await
                        .unwrap()
                }
                Event::Background(BackgroundEvent::NfcConnected) => {
                    info!("Found NFC device")
                }

                Event::Background(BackgroundEvent::NfcIdle | BackgroundEvent::NfcWaiting) => {}
                Event::Background(BackgroundEvent::HybridIdle) => {
                    self.hybrid_qr_code_data = None;
                }
                Event::Background(BackgroundEvent::HybridStarted(qr_code)) => {
                    self.hybrid_qr_code_data = Some(qr_code.clone().into_bytes());
                    self.tx_update
                        .send(ViewUpdate::HybridNeedsQrCode(qr_code))
                        .await
                        .unwrap();
                }
                Event::Background(BackgroundEvent::HybridConnecting) => {
                    self.hybrid_qr_code_data = None;
                    self.tx_update
                        .send(ViewUpdate::HybridConnecting)
                        .await
                        .unwrap();
                }
                Event::Background(BackgroundEvent::HybridConnected) => {
                    self.hybrid_qr_code_data = None;
                    self.tx_update
                        .send(ViewUpdate::HybridConnected)
                        .await
                        .unwrap();
                }
                Event::Background(BackgroundEvent::ErrorCancelled) => {
                    self.hybrid_qr_code_data = None;
                    break;
                } /*
                  Event::Background(BackgroundEvent::RequestCancelled(request_id)) => {
                      break;
                  }
                  */
            };
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum ViewEvent {
    Initiated,
    DeviceSelected(String),
    CredentialSelected(String),
    PinEntered(String),
    UserCancelled,
}

pub enum Event {
    Background(BackgroundEvent),
    View(ViewEvent),
}
