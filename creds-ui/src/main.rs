#[rustfmt::skip]
mod config;
mod dbus;
mod gui;

use std::error::Error;

use async_std::{
    channel::{Receiver, Sender},
    stream::Stream,
};
use creds_lib::client::CredentialServiceClient;
use futures_lite::StreamExt;
use zbus::{Connection, zvariant};

use crate::dbus::{InternalServiceProxy, UiControlService};

fn main() -> Result<(), Box<dyn Error>> {
    async_std::task::block_on(run())
}

async fn run() -> Result<(), Box<dyn Error>> {
    print!("Starting GUI thread...\t");
    let (request_tx, request_rx) = async_std::channel::bounded(2);
    // this allows the D-Bus service to signal to the GUI to draw a window for
    // executing the credential flow.
    let conn = zbus::connection::Builder::session()?.build().await?;
    let cred_client = DbusCredentialClient::new(conn);
    let handle = gui::start_gui_thread(request_rx, cred_client)?;
    println!(" ✅");
    handle.join();

    let interface = UiControlService { request_tx };
    let path = "/xyz/iinuwa/credentials/UiControl";
    let service = "xyz.iinuwa.credentials.UiControl";
    let _server_conn = zbus::connection::Builder::session()?
        .name(service)?
        .serve_at(path, interface)?
        .build()
        .await?;
    loop {
        std::future::pending::<()>().await;
    }
    #[allow(unreachable_code)]
    Ok(())
}

pub struct DbusCredentialClient {
    conn: Connection,
}

impl DbusCredentialClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
    async fn proxy(&self) -> std::result::Result<InternalServiceProxy, ()> {
        InternalServiceProxy::new(&self.conn)
            .await
            .map_err(|err| tracing::error!("Failed to communicate with D-Bus service: {err}"))
    }
}

impl CredentialServiceClient for DbusCredentialClient {
    async fn get_available_public_key_devices(
        &self,
    ) -> std::result::Result<Vec<creds_lib::model::Device>, ()> {
        let dbus_devices = self
            .proxy()
            .await?
            .get_available_public_key_devices()
            .await
            .map_err(|_| ())?;
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
            .get_hybrid_credential()
            .await
            .inspect_err(|err| tracing::error!("Failed to start USB credential flow: {err}"))
            .map_err(|_| ())
    }

    async fn initiate_event_stream(
        &mut self,
    ) -> std::result::Result<
        std::pin::Pin<Box<dyn Stream<Item = creds_lib::model::BackgroundEvent> + Send + 'static>>,
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
            .and_then(|_| Ok(stream))
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
}
