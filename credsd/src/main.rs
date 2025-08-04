mod cbor;
mod cose;
mod credential_service;
mod dbus;
// mod model;
mod serde;
mod webauthn;

use std::error::Error;

use crate::{
    credential_service::{
        hybrid::InternalHybridHandler, usb::InProcessUsbHandler, CredentialService,
    },
    dbus::{CredentialRequestControllerClient, UiControlServiceClient},
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
    let dbus_client_conn = zbus::connection::Builder::session()?
        .name("xyz.iinuwa.credentials.Credsd")?
        .build()
        .await?;
    println!(" ✅");

    print!("Starting D-Bus UI -> Credential control service...");
    let ui_controller = UiControlServiceClient::new(dbus_client_conn);
    let credential_service = CredentialService::new(
        InternalHybridHandler::new(),
        InProcessUsbHandler {},
        ui_controller,
    );
    let (_flow_control_conn, initiator) =
        dbus::start_flow_control_service(credential_service).await?;
    println!(" ✅");

    print!("Starting D-Bus public client service...");
    let initiator = CredentialRequestControllerClient { initiator };
    let _gateway_conn = dbus::start_gateway(initiator).await?;
    println!(" ✅");

    println!("Waiting for messages...");
    loop {
        // wait forever, handle D-Bus in the background
        std::future::pending::<()>().await;
    }
}
