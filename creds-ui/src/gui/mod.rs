pub mod view_model;

use std::thread;
use std::{sync::Arc, thread::JoinHandle};

use async_std::{channel::Receiver, sync::Mutex as AsyncMutex};

use creds_lib::server::ViewRequest;
use creds_lib::{client::CredentialServiceClient, model::ViewUpdate};

use view_model::ViewEvent;

pub(super) fn start_gui_thread<C: CredentialServiceClient + Send + Sync + 'static>(
    rx: Receiver<ViewRequest>,
    client: C,
) -> Result<JoinHandle<()>, std::io::Error> {
    thread::Builder::new().name("gui".into()).spawn(move || {
        let client = Arc::new(AsyncMutex::new(client));
        // D-Bus received a request and needs a window open
        while let Ok(view_request) = rx.recv_blocking() {
            run_gui(client.clone(), view_request);
        }
    })
}

fn run_gui<C: CredentialServiceClient + Send + Sync + 'static>(
    client: Arc<AsyncMutex<C>>,
    request: ViewRequest,
) {
    let operation = request.operation;
    let (tx_update, rx_update) = async_std::channel::unbounded::<ViewUpdate>();
    let (tx_event, rx_event) = async_std::channel::unbounded::<ViewEvent>();
    let event_loop = async_std::task::spawn(async move {
        let mut vm = view_model::ViewModel::new(operation, client, rx_event, tx_update);
        vm.start_event_loop().await;
        println!("event loop ended?");
    });

    view_model::gtk::start_gtk_app(tx_event, rx_update);

    async_std::task::block_on(event_loop.cancel());
}
