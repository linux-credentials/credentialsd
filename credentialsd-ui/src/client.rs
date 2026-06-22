use async_std::{
    channel::{Receiver, Sender},
    sync::Mutex as AsyncMutex,
};

use credentialsd_common::{
    memfd::write_secret, model::UserInteractedEvent, server::BackgroundEvent,
};

const CTAP_CLIENT_SECRET_MAX_LEN: usize = 63;

#[derive(Debug)]
pub struct FlowControlClient {
    pub tx: Sender<UserInteractedEvent>,
    pub rx: AsyncMutex<Option<Receiver<BackgroundEvent>>>,
}

impl FlowControlClient {
    pub async fn discover_authenticators(&self) -> Result<(), ()> {
        self.send(UserInteractedEvent::DiscoveryRequested).await
    }

    pub async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
        if pin.len() > CTAP_CLIENT_SECRET_MAX_LEN {
            tracing::error!("PIN is too long");
            return Err(());
        }
        let fd = match write_secret(pin.into_bytes()) {
            Ok(fd) => fd,
            Err(err) => {
                tracing::error!(%err, "Failed to write secret to file descriptor");
                // TODO: need to send a message back to GUI thread that there was an error.
                _ = self.cancel_request().await;
                return Err(());
            }
        };
        self.send(UserInteractedEvent::ClientPinEntered(fd.into()))
            .await
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
