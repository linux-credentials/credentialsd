mod application;
mod cbor;
#[rustfmt::skip]
mod config;
mod cose;
mod credential_service;
mod dbus;
mod gui;
mod serde;
#[allow(dead_code)]
mod view_model;
mod webauthn;
mod window;

use std::{error::Error, sync::Arc};

use crate::credential_service::{
    hybrid::InternalHybridHandler, usb::InProcessUsbHandler, CredentialService, InProcessServer,
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
    let credential_service =
        CredentialService::new(InternalHybridHandler::new(), InProcessUsbHandler {});
    print!("Starting credential service...\t");
    let (mut cred_server, cred_mgr, cred_client) = InProcessServer::new(credential_service);
    tokio::spawn(async move {
        cred_server.run().await;
    });
    println!(" ✅");

    print!("Starting GUI thread...\t");
    // this allows the D-Bus service to signal to the GUI to draw a window for
    // executing the credential flow.
    let (dbus_to_gui_tx, dbus_to_gui_rx) = async_std::channel::unbounded();
    gui::start_gui_thread(dbus_to_gui_rx, Arc::new(cred_client));
    println!(" ✅");

    print!("Starting D-Bus service...");
    let service_name = "xyz.iinuwa.credentials.CredentialManagerUi";
    let path = "/xyz/iinuwa/credentials/CredentialManagerUi";
    let _conn = dbus::start_service(service_name, path, dbus_to_gui_tx, cred_mgr).await?;
    println!(" ✅");
    println!("Waiting for messages...");
    loop {
        // wait forever, handle D-Bus in the background
        std::future::pending::<()>().await;
    }
}
