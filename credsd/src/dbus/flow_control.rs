pub struct InternalService<H: HybridHandler, U: UsbHandler, UC: UiController> {
    signal_state: Arc<AsyncMutex<SignalState>>,
    svc: Arc<AsyncMutex<CredentialService<H, U, UC>>>,
    usb_pin_tx: Arc<AsyncMutex<Option<Sender<String>>>>,
    usb_event_forwarder_task: Arc<AsyncMutex<Option<AbortHandle>>>,
    hybrid_event_forwarder_task: Arc<AsyncMutex<Option<AbortHandle>>>,
}

/// The following methods are for communication between the [trusted]
/// UI and the credential service, and should not be called by arbitrary
/// clients.
#[interface(
    name = "xyz.iinuwa.credentials.CredentialManagerInternal1",
    proxy(
        gen_blocking = false,
        default_path = "/xyz/iinuwa/credentials/CredentialManagerInternal",
        default_service = "xyz.iinuwa.credentials.CredentialManagerInternal",
    )
)]
impl<H, U, UC> InternalService<H, U, UC>
where
    H: HybridHandler + Debug + Send + Sync + 'static,
    U: UsbHandler + Debug + Send + Sync + 'static,
    UC: UiController + Debug + Send + Sync + 'static,
{
    async fn initiate_event_stream(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        let mut signal_state = self.signal_state.lock().await;
        match *signal_state {
            SignalState::Idle => {}
            SignalState::Pending(ref mut pending) => {
                for msg in pending.iter_mut() {
                    emitter.state_changed(msg.clone()).await?;
                }
            }
            SignalState::Active => {}
        };
        *signal_state = SignalState::Active;
        Ok(())
    }

    async fn get_available_public_key_devices(&self) -> fdo::Result<Vec<Device>> {
        let devices = self
            .svc
            .lock()
            .await
            .get_available_public_key_devices()
            .await
            .map_err(|_| {
                fdo::Error::Failed("Failed to get retrieve available devices".to_string())
            })?;
        Ok(devices.into_iter().map(Device::from).collect())
    }

    async fn get_hybrid_credential(
        &self,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<()> {
        let svc = self.svc.lock().await;
        let mut stream = svc.get_hybrid_credential();
        let signal_state = self.signal_state.clone();
        let object_server = object_server.clone();
        let task = tokio::spawn(async move {
            let interface: zbus::Result<InterfaceRef<InternalService<H, U, UC>>> = object_server
                .interface("/xyz/iinuwa/credentials/CredentialManagerInternal")
                .await;

            let emitter = match interface {
                Ok(ref i) => i.signal_emitter(),
                Err(err) => {
                    tracing::error!("Failed to get connection to D-Bus to send signals: {err}");
                    return;
                }
            };
            while let Some(state) = stream.next().await {
                let event =
                    creds_lib::model::BackgroundEvent::HybridQrStateChanged(state.clone().into())
                        .try_into();
                match event {
                    Err(err) => {
                        tracing::error!("Failed to serialize state update: {err}");
                        break;
                    }
                    Ok(event) => match send_state_update(&emitter, &signal_state, event).await {
                        Ok(_) => {}
                        Err(err) => {
                            tracing::error!("Failed to send state update to UI: {err}");
                            break;
                        }
                    },
                }
                match state {
                    HybridState::Completed | HybridState::Failed => {
                        break;
                    }
                    _ => {}
                };
            }
        })
        .abort_handle();
        if let Some(prev_task) = self.hybrid_event_forwarder_task.lock().await.replace(task) {
            prev_task.abort();
        }
        Ok(())
    }

    async fn get_usb_credential(
        &self,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> fdo::Result<()> {
        let mut stream = self.svc.lock().await.get_usb_credential();
        let usb_pin_tx = self.usb_pin_tx.clone();
        let signal_state = self.signal_state.clone();
        let object_server = object_server.clone();
        let task = tokio::spawn(async move {
            let interface: zbus::Result<InterfaceRef<InternalService<H, U, UC>>> = object_server
                .interface("/xyz/iinuwa/credentials/CredentialManagerInternal")
                .await;

            let emitter = match interface {
                Ok(ref i) => i.signal_emitter(),
                Err(err) => {
                    tracing::error!("Failed to get connection to D-Bus to send signals: {err}");
                    return;
                }
            };
            while let Some(state) = stream.next().await {
                match creds_lib::model::BackgroundEvent::UsbStateChanged((&state).into()).try_into()
                {
                    Err(err) => {
                        tracing::error!("Failed to serialize state update: {err}");
                        break;
                    }
                    Ok(event) => match send_state_update(&emitter, &signal_state, event).await {
                        Ok(_) => {}
                        Err(err) => {
                            tracing::error!("Failed to send state update to UI: {err}");
                            break;
                        }
                    },
                };
                match state {
                    UsbState::NeedsPin { pin_tx, .. } => {
                        let mut usb_pin_tx = usb_pin_tx.lock().await;
                        let _ = usb_pin_tx.insert(pin_tx);
                    }
                    UsbState::Completed | UsbState::Failed(_) => {
                        break;
                    }
                    _ => {}
                };
            }
        })
        .abort_handle();
        if let Some(prev_task) = self.usb_event_forwarder_task.lock().await.replace(task) {
            prev_task.abort();
        }
        Ok(())
    }

    async fn select_device(&self, device_id: String) -> fdo::Result<()> {
        todo!()
    }

    async fn enter_client_pin(&self, pin: String) -> fdo::Result<()> {
        if let Some(pin_tx) = self.usb_pin_tx.lock().await.take() {
            pin_tx.send(pin).await.unwrap();
        }
        Ok(())
    }

    async fn select_credential(&self, credential_id: String) -> fdo::Result<()> {
        todo!()
    }

    #[zbus(signal)]
    async fn state_changed(
        emitter: &SignalEmitter<'_>,
        update: BackgroundEvent,
    ) -> zbus::Result<()>;
}
async fn send_state_update(
    emitter: &SignalEmitter<'_>,
    signal_state: &Arc<AsyncMutex<SignalState>>,
    update: BackgroundEvent,
) -> fdo::Result<()> {
    let mut signal_state = signal_state.lock().await;
    match *signal_state {
        SignalState::Idle => {
            let pending = VecDeque::from([update]);
            *signal_state = SignalState::Pending(pending);
        }
        SignalState::Pending(ref mut pending) => {
            pending.push_back(update);
        }
        SignalState::Active => {
            emitter.state_changed(update).await?;
        }
    };
    Ok(())
}

pub struct CredentialControlServiceClient {
    conn: Connection,
}

impl CredentialControlServiceClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    async fn proxy(&self) -> zbus::Result<InternalServiceProxy> {
        InternalServiceProxy::new(&self.conn).await
    }
}

impl CredentialManagementClient for CredentialControlServiceClient {
    async fn init_request(
        &self,
        cred_request: CredentialRequest,
    ) -> Receiver<Result<CredentialResponse, creds_lib::model::Error>> {
        // TODO: Start here
        self.proxy().await.unwrap().
    }

    async fn complete_auth(&self) -> Result<CredentialResponse, String> {
        todo!()
    }

    async fn get_available_public_key_devices(
        &self,
    ) -> Result<Vec<creds_lib::model::Device>, Box<dyn Error>> {
        let devices: Result<Vec<creds_lib::model::Device>, String> = self
            .proxy()
            .await?
            .get_available_public_key_devices()
            .await?
            .into_iter()
            .map(|d| d.try_into().map_err(|_| "Failed".to_string()))
            .collect();
        Ok(devices?)
    }

    async fn get_hybrid_credential(&mut self) -> Result<(), ()> {
        todo!()
    }

    async fn get_usb_credential(&mut self) -> Result<(), ()> {
        todo!()
    }

    async fn initiate_event_stream(
        &mut self,
    ) -> Result<Pin<Box<dyn Stream<Item = creds_lib::model::BackgroundEvent> + Send + 'static>>, ()>
    {
        todo!()
    }

    async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
        if let Err(err) = self.proxy().await.unwrap().enter_client_pin(pin).await {
            tracing::error!("Failed to send client pin: {err}");
            return Err(());
        }
        Ok(())
    }

    async fn select_credential(&self, credential_id: String) -> Result<(), ()> {
        todo!()
    }
}
