//! These methods are called by the flow controller to launch the trusted UI.

use std::error::Error;

use zbus::{fdo, proxy, Connection};

use credentialsd_common::server::{RequestId, ViewRequest};

use crate::credential_service::UiController;

#[proxy(
    gen_blocking = false,
    interface = "xyz.iinuwa.credentialsd.UiControl1",
    default_service = "xyz.iinuwa.credentialsd.UiControl",
    default_path = "/xyz/iinuwa/credentialsd/UiControl"
)]
trait UiControlService {
    fn launch_ui(&self, request: ViewRequest) -> fdo::Result<()>;
    fn cancel_request(&self, request_id: RequestId) -> fdo::Result<()>;
}

#[derive(Debug)]
pub struct UiControlServiceClient {
    conn: Connection,
}

impl UiControlServiceClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    async fn proxy(&self) -> Result<UiControlServiceProxy, zbus::Error> {
        UiControlServiceProxy::new(&self.conn).await
    }
}
impl UiController for UiControlServiceClient {
    async fn launch_ui(&self, request: ViewRequest) -> Result<(), Box<dyn Error>> {
        self.proxy()
            .await?
            .launch_ui(request)
            .await
            .map_err(|err| err.into())
    }
}

#[cfg(test)]
pub mod test {
    use std::{
        fmt::Debug,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    use credentialsd_common::{
        client::FlowController, model::BackgroundEvent, server::ViewRequest,
    };
    use futures_lite::StreamExt;
    use tokio::sync::{
        mpsc::{self, Receiver, Sender},
        Mutex as AsyncMutex, Notify,
    };

    use super::UiController;

    #[derive(Debug)]
    pub struct DummyUiClient {
        tx: Sender<ViewRequest>,
    }

    impl UiController for DummyUiClient {
        async fn launch_ui(&self, request: ViewRequest) -> Result<(), Box<dyn std::error::Error>> {
            tracing::debug!(
                target: "DummyUiClient",
                "Sending launch_ui() request"
            );
            self.tx.send(request).await.unwrap();
            tracing::debug!(
                target: "DummyUiClient",
                "Finish launch_ui() request"
            );
            Ok(())
        }
    }

    pub struct DummyUiServer<F>
    where
        F: FlowController + Debug,
    {
        rx: AsyncMutex<Receiver<ViewRequest>>,
        svc: Arc<AsyncMutex<Option<F>>>,
        events: Arc<AsyncMutex<Vec<BackgroundEvent>>>,
        stream_initialized: AtomicBool,
        stream_initialized_notifier: Notify,
    }
    impl<F: FlowController + Debug + Send + Sync + 'static> DummyUiServer<F> {
        pub fn new(events: Vec<BackgroundEvent>) -> (Self, DummyUiClient) {
            let (tx, rx) = mpsc::channel(32);
            let server = Self {
                rx: AsyncMutex::new(rx),
                svc: Arc::new(AsyncMutex::new(None)),
                events: Arc::new(AsyncMutex::new(events)),
                stream_initialized: AtomicBool::new(false),
                stream_initialized_notifier: Notify::new(),
            };
            let client = DummyUiClient { tx };
            (server, client)
        }

        pub async fn init(&self, flow_controller: F) {
            _ = self.svc.lock().await.insert(flow_controller);
        }

        pub async fn run(&self) {
            tracing::debug!(
                target: "DummyUiServer",
                "Starting launch_ui() request listener"
            );
            let mut rx = self.rx.lock().await;
            while let Some(request) = rx.recv().await {
                self.launch_ui(request).await.unwrap();
            }
        }

        pub async fn request_hybrid_credential(&self) {
            tracing::debug!(
                target: "DummyUiServer",
                "Received request_hybrid_credential() request"
            );
            loop {
                if !self.stream_initialized.load(Ordering::Relaxed) {
                    self.stream_initialized_notifier.notified().await;
                } else {
                    break;
                }
            }
            self.svc
                .lock()
                .await
                .as_mut()
                .unwrap()
                .get_hybrid_credential()
                .await
                .unwrap()
        }

        pub async fn request_usb_credential(&self) {
            tracing::debug!(
                target: "DummyUiServer",
                "Received request_usb_credential() request"
            );
            loop {
                if !self.stream_initialized.load(Ordering::Relaxed) {
                    self.stream_initialized_notifier.notified().await;
                } else {
                    break;
                }
            }
            self.svc
                .lock()
                .await
                .as_mut()
                .unwrap()
                .get_usb_credential()
                .await
                .unwrap()
        }

        pub async fn enter_client_pin(&self, pin: String) {
            tracing::debug!(
                target: "DummyUiServer",
                "Received enter_client_pin() request"
            );
            self.svc
                .lock()
                .await
                .as_mut()
                .unwrap()
                .enter_client_pin(pin)
                .await
                .unwrap();
        }

        pub async fn select_credential(&self, _cred_id: String) {
            tracing::debug!(
                target: "DummyUiServer",
                "Received select_credential() request"
            );
        }

        async fn launch_ui(&self, request: ViewRequest) -> Result<(), Box<dyn std::error::Error>> {
            tracing::debug!(
                target: "DummyUiServer",
                "Received launch_ui() request"
            );
            println!("Starting {:?} request UI", request.operation);
            let events = self.events.clone();
            let mut stream = self
                .svc
                .lock()
                .await
                .as_mut()
                .unwrap()
                .subscribe()
                .await
                .unwrap();
            self.stream_initialized.store(true, Ordering::Release);
            self.stream_initialized_notifier.notify_waiters();
            tokio::spawn(async move {
                tracing::debug!(target: "DummyUiServer", "Starting background event stream");
                while let Some(event) = stream.next().await {
                    tracing::debug!(
                        target: "DummyUiServer",
                        "Received background event: {event:?}"
                    );
                    events.lock().await.push(event);
                }
            });
            self.svc
                .lock()
                .await
                .as_ref()
                .unwrap()
                .get_available_public_key_devices()
                .await
                .unwrap();
            tracing::debug!(
                target: "DummyUiServer",
                "Finished launch_ui() request"
            );
            Ok(())
        }
    }
}
