mod client;
#[rustfmt::skip]
mod config;
mod dbus;
mod gui;

use std::error::Error;

use crate::{client::DbusCredentialClient, dbus::UiControlService};

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    tracing::debug!("Starting credentials UI service");
    async_std::task::block_on(run())
}

async fn run() -> Result<(), Box<dyn Error>> {
    print!("Starting GUI thread...\t");
    let (request_tx, request_rx) = async_std::channel::bounded(2);
    // this allows the D-Bus service to signal to the GUI to draw a window for
    // executing the credential flow.
    let conn = zbus::connection::Builder::session()?.build().await?;
    let cred_client = DbusCredentialClient::new(conn);
    let _handle = gui::start_gui_thread(request_rx, cred_client)?;
    println!(" ✅");

    print!("Starting UI Control listener...\t");
    let interface = UiControlService { request_tx };
    let path = "/xyz/iinuwa/credentials/UiControl";
    let service = "xyz.iinuwa.credentials.UiControl";
    let _server_conn = zbus::connection::Builder::session()?
        .name(service)?
        .serve_at(path, interface)?
        .build()
        .await?;
    println!(" ✅");
    loop {
        std::future::pending::<()>().await;
    }
    #[allow(unreachable_code)]
    {
        _ = _handle.join();
        Ok(())
    }
}
