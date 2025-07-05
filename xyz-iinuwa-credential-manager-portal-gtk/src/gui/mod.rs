pub mod view_model;

use std::thread;

use async_std::channel::Receiver;
use tokio::sync::oneshot;

use crate::credential_service::CredentialServiceClient;

use view_model::{Operation, ViewEvent, ViewUpdate};

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

    view_model::gtk::start_gtk_app(tx_event, rx_update);

    async_std::task::block_on(event_loop.cancel());
    response_tx.send(()).unwrap();
}
