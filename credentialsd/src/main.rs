mod credential_service;
mod dbus;
mod gateway;
mod model;
mod webauthn;

use std::{error::Error, sync::Arc};

use credential_service::nfc::InProcessNfcHandler;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use zbus::zvariant::OwnedObjectPath;

use crate::{
    credential_service::{
        CredentialService, hybrid::InternalHybridHandler, usb::InProcessUsbHandler,
    },
    dbus::CredentialRequestControllerClient,
};

pub const DBUS_SERVICE_NAME: &str = "xyz.iinuwa.credentialsd.Credentials";

#[tokio::main]
async fn main() {
    // Initialize logger
    tracing_subscriber::fmt::init();

    println!("Starting...");
    run().await.unwrap();
}

async fn run() -> Result<(), Box<dyn Error>> {
    print!("Starting D-Bus public client service...");
    let (incoming_request_tx, incoming_request_rx) = mpsc::channel(2);
    let request_controller = CredentialRequestControllerClient {
        initiator: incoming_request_tx,
    };
    let dbus_conn = gateway::start_gateway(request_controller).await?;
    println!(" ✅");

    // initialize client to interact with UI
    let credential_service = CredentialService::new(
        InternalHybridHandler::new(),
        InProcessNfcHandler {},
        InProcessUsbHandler {},
    );
    let flow_control_svc = dbus::start_flow_control_service(
        dbus_conn.clone(),
        incoming_request_rx,
        credential_service,
    )
    .await?;

    print!("Starting credentialsd service...");
    let credentialsd = {
        let svc = CredentialService::new(
            InternalHybridHandler::new(),
            InProcessNfcHandler {},
            InProcessUsbHandler {},
        );

        gateway::Credentialsd {
            svc: Arc::new(AsyncMutex::new(svc)),
        }
    };
    let object_path: OwnedObjectPath = "/xyz/iinuwa/credentialsd/Manager"
        .try_into()
        .expect("valid object path");
    dbus_conn
        .object_server()
        .at(object_path, credentialsd)
        .await?;
    println!(" ✅");

    println!("Waiting for messages...");
    tokio::signal::ctrl_c()
        .await
        .map_err(|err| format!("Failed to wait for shutdown signals: {err}. Shutting down"))?;

    flow_control_svc.abort();
    Ok(())
}
