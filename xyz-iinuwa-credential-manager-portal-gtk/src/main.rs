mod application;
mod cbor;
#[rustfmt::skip]
mod config;
mod cose;
mod credential_service;
mod dbus;
mod serde;
#[allow(dead_code)]
mod view_model;
mod webauthn;
mod window;

use std::error::Error;

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
    let service_name = "xyz.iinuwa.credentials.CredentialManagerUi";
    let path = "/xyz/iinuwa/credentials/CredentialManagerUi";
    let _conn = dbus::start_service(service_name, path).await?;
    println!("Started");
    loop {
        // wait forever, handle D-Bus in the background
        std::future::pending::<()>().await;
    }
}
