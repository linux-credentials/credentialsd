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

use async_std::task;

fn main() {
    // Initialize logger
    tracing_subscriber::fmt::init();
    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");

    println!("Starting...");
    task::block_on(run()).unwrap();
}

async fn run() -> Result<(), Box<dyn Error>> {
    let service_name = "xyz.iinuwa.credentials.CredentialManagerUi";
    let path = "/xyz/iinuwa/credentials/CredentialManagerUi";
    let _conn = dbus::start_service(service_name, path).await?;
    // store::initialize();
    // let _conn = dbus::start_service(service_name, path, seed_key).await?;
    println!("Started");
    loop {
        // do something else, wait forever or timeout here:
        // handling D-Bus messages is done in the background

        std::future::pending::<()>().await;
    }
}
