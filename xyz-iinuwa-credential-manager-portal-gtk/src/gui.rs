use std::thread;

use async_std::channel::Receiver;
use gettextrs::{gettext, LocaleCategory};
use gtk::{gio, glib};
use tokio::sync::oneshot;

use crate::application::ExampleApplication;
use crate::config::{GETTEXT_PACKAGE, LOCALEDIR, RESOURCES_FILE};
use crate::{
    credential_service::CredentialServiceClient,
    view_model::{self, Operation, ViewEvent, ViewUpdate},
};

pub struct ViewRequest {
    pub operation: Operation,
    pub signal: oneshot::Sender<()>,
}

pub(super) fn start_gui_thread<C: CredentialServiceClient + Send + Sync + Clone + 'static>(
    rx: Receiver<ViewRequest>,
    client: C,
) {
    thread::Builder::new()
        .name("gui".into())
        .spawn(move || {
            // D-Bus received a request and needs a window open
            while let Ok(view_request) = rx.recv_blocking() {
                run_gui(client.clone(), view_request);
            }
        })
        .unwrap();
}

fn run_gui<C: CredentialServiceClient + Send + Sync + 'static>(client: C, request: ViewRequest) {
    let ViewRequest {
        operation,
        signal: response_tx,
    } = request;
    let (tx_update, rx_update) = async_std::channel::unbounded::<ViewUpdate>();
    let (tx_event, rx_event) = async_std::channel::unbounded::<ViewEvent>();
    let event_loop = async_std::task::spawn(async move {
        let mut vm = view_model::ViewModel::new(operation, client, rx_event, tx_update);
        vm.start_event_loop().await;
        println!("event loop ended?");
    });

    start_gtk_app(tx_event, rx_update);

    async_std::task::block_on(event_loop.cancel());
    response_tx.send(()).unwrap();
}

fn start_gtk_app(
    tx_event: async_std::channel::Sender<ViewEvent>,
    rx_update: async_std::channel::Receiver<ViewUpdate>,
) {
    // Prepare i18n
    gettextrs::setlocale(LocaleCategory::LcAll, "");
    gettextrs::bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR).expect("Unable to bind the text domain");
    gettextrs::textdomain(GETTEXT_PACKAGE).expect("Unable to switch to the text domain");

    if glib::application_name().is_none() {
        glib::set_application_name(&gettext("Credential Manager"));
    }
    let res = gio::Resource::load(RESOURCES_FILE).expect("Could not load gresource file");
    gio::resources_register(&res);

    let app = ExampleApplication::new(tx_event, rx_update);
    app.run();
}
