mod client;
#[rustfmt::skip]
mod config;
mod dbus;
mod gui;

use std::error::Error;

use credentialsd_common::model::{Device, Operation, RequestId};
use credentialsd_common::server::WindowHandle;

use crate::dbus::CredentialPortalBackend;

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
    let _handle = gui::start_gui_thread(request_rx)?;
    println!(" ✅");

    print!("Starting UI Control listener...\t");
    let portal_backend_interface = CredentialPortalBackend { request_tx };
    let service = "xyz.iinuwa.credentialsd.UiControl";
    let _server_conn = zbus::connection::Builder::session()?
        .name(service)?
        .serve_at("/org/freedesktop/portal/desktop", portal_backend_interface)?
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

/// Details about the calling application to be displayed in the UI.
#[derive(Debug, Default, Clone)]
pub struct RequestingApplication {
    /// The App ID (if called on the portal interface) or path (if called on the
    /// internal interface).
    pub path_or_app_id: String,

    /// The display name of the application.
    pub name: String,

    /// The PID of the application
    pub pid: u32,
}

#[derive(Clone, Debug)]
pub struct ViewRequest {
    pub operation: Operation,

    /// ID of the request.
    pub id: RequestId,

    /// The RP ID
    pub rp_id: String,

    /// Details about the application requesting credentials.
    pub requesting_app: RequestingApplication,

    /// Initial list of device interfaces that may provide credentials.
    pub initial_devices: Vec<Device>,

    /// Client window handle.
    pub window_handle: Option<WindowHandle>,
}
