use async_std::{
    channel::{Receiver, Sender},
    sync::Mutex as AsyncMutex,
};
use credentialsd_common::{model::UserInteractedEvent, server::BackgroundEvent};

#[derive(Debug)]
pub struct FlowControlClient {
    pub tx: Sender<UserInteractedEvent>,
    pub rx: AsyncMutex<Option<Receiver<BackgroundEvent>>>,
}

impl FlowControlClient {
    pub async fn discover_hybrid_authenticators(&self) -> Result<(), ()> {
        self.send(UserInteractedEvent::HybridDiscoveryRequested)
            .await
    }

    pub async fn discover_nfc_authenticators(&mut self) -> Result<(), ()> {
        self.send(UserInteractedEvent::NfcDiscoveryRequested).await
    }

    pub async fn discover_usb_authenticators(&mut self) -> Result<(), ()> {
        self.send(UserInteractedEvent::UsbDiscoveryRequested).await
    }

    pub async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
        self.send(UserInteractedEvent::ClientPinEntered(pin)).await
    }

    pub async fn select_credential(&self, credential_id: String) -> Result<(), ()> {
        self.send(UserInteractedEvent::CredentialSelected(credential_id))
            .await
    }

    pub async fn cancel_request(&self) -> Result<(), ()> {
        self.send(UserInteractedEvent::RequestCancelled).await
    }

    /// Returns a channel for background events.
    /// Can only be called once; returns an error if the subscription has already been taken.
    pub async fn subscribe(&mut self) -> Result<Receiver<BackgroundEvent>, ()> {
        self.rx.lock().await.take().ok_or_else(|| {
            tracing::error!("Subscribe has already been called.");
        })
    }

    async fn send(&self, request: UserInteractedEvent) -> Result<(), ()> {
        match self.tx.send(request).await {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}
