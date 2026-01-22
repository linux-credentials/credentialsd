use async_std::stream::Stream;
use credentialsd_common::{client::FlowController, server::RequestId};
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
        let dbus_devices = self
            .proxy()
            .await?
            .get_available_public_key_devices()
            .await
            .map_err(|err| {
                tracing::error!("Failed to retrieve available devices/transports: {err}")
            })?;
        dbus_devices.into_iter().map(|d| d.try_into()).collect()
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
