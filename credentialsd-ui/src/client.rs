use async_std::{
    channel::{Receiver, Sender},
    stream::Stream,
    sync::Mutex as AsyncMutex,
};
use credentialsd_common::{
    client::FlowController,
    model::{BackendRequest, BackgroundEvent, RequestId},
};
use futures_lite::StreamExt;
use zbus::Connection;

use crate::dbus::FlowControlServiceProxy;

pub struct DbusCredentialClient {
    conn: Connection,
}

impl DbusCredentialClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
    async fn proxy(&self) -> std::result::Result<FlowControlServiceProxy<'_>, ()> {
        FlowControlServiceProxy::new(&self.conn)
            .await
            .map_err(|err| tracing::error!("Failed to communicate with D-Bus service: {err}"))
    }
}

impl FlowController for DbusCredentialClient {
    async fn get_available_public_key_devices(
        &self,
    ) -> std::result::Result<Vec<credentialsd_common::model::Device>, ()> {
        self.proxy()
            .await?
            .get_available_public_key_devices()
            .await
            .map_err(|err| {
                tracing::error!("Failed to retrieve available devices/transports: {err}")
            })
    }

    async fn get_hybrid_credential(&mut self) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .get_hybrid_credential()
            .await
            .inspect_err(|err| tracing::error!("Failed to start hybrid credential flow: {err}"))
            .map_err(|_| ())
    }

    async fn get_usb_credential(&mut self) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .get_usb_credential()
            .await
            .inspect_err(|err| tracing::error!("Failed to start USB credential flow: {err}"))
            .map_err(|_| ())
    }

    async fn get_nfc_credential(&mut self) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .get_nfc_credential()
            .await
            .inspect_err(|err| tracing::error!("Failed to start NFC credential flow: {err}"))
            .map_err(|_| ())
    }

    async fn subscribe(
        &mut self,
    ) -> std::result::Result<
        std::pin::Pin<
            Box<dyn Stream<Item = credentialsd_common::model::BackgroundEvent> + Send + 'static>,
        >,
        (),
    > {
        let stream = self
            .proxy()
            .await?
            .receive_state_changed()
            .await
            .map_err(|err| tracing::error!("Failed to initalize event stream: {err}"))?
            .filter_map(|msg| {
                msg.args()
                    .map(|args| args.update)
                    .inspect_err(|err| tracing::warn!("Failed to parse StateChanged signal: {err}"))
                    .ok()
            })
            .boxed();
        self.proxy()
            .await?
            .subscribe()
            .await
            .map_err(|err| tracing::error!("Failed to initialize event stream: {err}"))
            .map(|_| stream)
    }

    async fn enter_client_pin(&mut self, pin: String) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .enter_client_pin(pin)
            .await
            .map_err(|err| tracing::error!("Failed to send PIN to authenticator: {err}"))
    }

    async fn select_credential(&self, credential_id: String) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .select_credential(credential_id)
            .await
            .map_err(|err| tracing::error!("Failed to select credential: {err}"))
    }

    async fn cancel_request(&self, request_id: RequestId) -> Result<(), ()> {
        if self
            .proxy()
            .await?
            .cancel_request(request_id)
            .await
            .is_err()
        {
            tracing::warn!("Failed to cancel request {request_id}");
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct FlowControlClient {
    pub tx: Sender<BackendRequest>,
    pub rx: AsyncMutex<Option<Receiver<BackgroundEvent>>>,
}

impl FlowControlClient {
    pub async fn discover_hybrid_authenticators(&self) -> Result<(), ()> {
        self.send(BackendRequest::StartHybridDiscovery).await
    }

    pub async fn discover_nfc_authenticators(&mut self) -> Result<(), ()> {
        self.send(BackendRequest::StartNfcDiscovery).await
    }

    pub async fn discover_usb_authenticators(&mut self) -> Result<(), ()> {
        self.send(BackendRequest::StartUsbDiscovery).await
    }

    pub async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
        self.send(BackendRequest::EnterClientPin(pin)).await
    }

    pub async fn select_credential(&self, credential_id: String) -> Result<(), ()> {
        self.send(BackendRequest::SelectCredential(credential_id))
            .await
    }

    pub async fn cancel_request(&self) -> Result<(), ()> {
        self.send(BackendRequest::CancelRequest).await
    }

    /// Returns a channel for background events.
    /// Can only be called once; returns an error if the subscription has already been taken.
    pub async fn subscribe(&mut self) -> Result<Receiver<BackgroundEvent>, ()> {
        self.rx.lock().await.take().ok_or_else(|| {
            tracing::error!("Subscribe has already been called.");
        })
    }

    async fn send(&self, request: BackendRequest) -> Result<(), ()> {
        match self.tx.send(request).await {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}
