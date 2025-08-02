mod cbor;
mod cose;
mod credential_service;
mod dbus;
// mod model;
mod serde;
mod webauthn;

use std::{error::Error, sync::Arc};

use crate::{
    credential_service::{
        hybrid::InternalHybridHandler, usb::InProcessUsbHandler, CredentialService, InProcessServer,
    },
    dbus::UiControlServiceClient,
};

#[tokio::main]
async fn main() {
    // Initialize logger
    tracing_subscriber::fmt::init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    println!("Starting...");
    run().await.unwrap();
}

async fn run() -> Result<(), Box<dyn Error>> {
    print!("Connecting to D-Bus as client...\t");
    let dbus_client_conn = zbus::connection::Builder::session()?.build().await?;
    println!(" ✅");

    print!("Starting D-Bus public client service...");
    let service_name = "xyz.iinuwa.credentials.CredentialManagerUi";
    let path = "/xyz/iinuwa/credentials/CredentialManagerUi";
    let _conn = dbus::start_service(service_name, path, cred_mgr).await?;
    println!(" ✅");

    print!("Starting D-Bus UI -> Credential control service...");
    let ui_controller = UiControlServiceClient::new(dbus_client_conn);
    let credential_service = CredentialService::new(
        InternalHybridHandler::new(),
        InProcessUsbHandler {},
        ui_controller,
    );
    let internal_service_name = "xyz.iinuwa.credentials.CredentialManagerInternal";
    let internal_path = "/xyz/iinuwa/credentials/CredentialManagerInternal";
    let _internal_service =
        dbus::start_internal_service(internal_service_name, internal_path, credential_service)
            .await?;
    println!(" ✅");

    println!("Waiting for messages...");
    loop {
        // wait forever, handle D-Bus in the background
        std::future::pending::<()>().await;
    }
}
