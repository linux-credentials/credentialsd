use async_std::stream::Stream;
use credentialsd_common::{client::FlowController, server::RequestId};
use futures_lite::StreamExt;
use zbus::{Connection, zvariant};

use crate::dbus::FlowControlServiceProxy;

pub struct DbusCredentialClient {
    conn: Connection,
}

impl DbusCredentialClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
    async fn proxy(&self) -> std::result::Result<FlowControlServiceProxy, ()> {
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

    async fn get_platform_credential(&mut self) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .get_platform_credential()
            .await
            .inspect_err(|err| tracing::error!("Failed to start platform credential flow: {err}"))
            .map_err(|_| ())
    }

    async fn initiate_event_stream(
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
                    .and_then(|args| {
                        args.update
                            .try_into()
                            .map_err(|err: zvariant::Error| err.into())
                    })
                    .inspect_err(|err| tracing::warn!("Failed to parse StateChanged signal: {err}"))
                    .ok()
            })
            .boxed();
        self.proxy()
            .await?
            .initiate_event_stream()
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

    // TODO: Instead of making this a separate method, have the server keep track of state and send a request ID to client to return.
    async fn enter_platform_client_pin(&mut self, pin: String) -> std::result::Result<(), ()> {
        self.proxy()
            .await?
            .enter_platform_client_pin(pin)
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
