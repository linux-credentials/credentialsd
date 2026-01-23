pub mod view_model;

use std::thread;
use std::{sync::Arc, thread::JoinHandle};

use async_std::{channel::Receiver, sync::Mutex as AsyncMutex};

use credentialsd_common::server::{ViewRequest, WindowHandle};
use credentialsd_common::{client::FlowController, model::ViewUpdate};

use view_model::ViewEvent;

pub(super) fn start_gui_thread<F: FlowController + Send + Sync + 'static>(
    rx: Receiver<ViewRequest>,
    flow_controller: F,
) -> Result<JoinHandle<()>, std::io::Error> {
    thread::Builder::new().name("gui".into()).spawn(move || {
        let flow_controller = Arc::new(AsyncMutex::new(flow_controller));
        // D-Bus received a request and needs a window open
        while let Ok(view_request) = rx.recv_blocking() {
            run_gui(flow_controller.clone(), view_request);
        }
    })
}

fn run_gui<F: FlowController + Send + Sync + 'static>(
    flow_controller: Arc<AsyncMutex<F>>,
    request: ViewRequest,
) {
    let parent_window: Option<WindowHandle> = request.window_handle.as_ref().and_then(|h| {
        h.to_string()
            .try_into()
            .inspect_err(|err| tracing::warn!("Failed to parse parent window handle: {err}"))
            .ok()
    });

    let (tx_update, rx_update) = async_std::channel::unbounded::<ViewUpdate>();
    let (tx_event, rx_event) = async_std::channel::unbounded::<ViewEvent>();
    let event_loop = async_std::task::spawn(async move {
        let request_id = request.id;
        let mut vm =
            view_model::ViewModel::new(request, flow_controller.clone(), rx_event, tx_update);
        vm.start_event_loop().await;
        tracing::debug!("Finishing user request.");
        // If cancellation fails, that's fine.
        let _ = flow_controller
            .lock()
            .await
            .cancel_request(request_id)
            .await;
    });

    view_model::gtk::start_gtk_app(parent_window, tx_event, rx_update);

    async_std::task::block_on(event_loop.cancel());
}
