pub(crate) async fn start_service<C: CredentialManagementClient + Send + Sync + 'static>(
    service_name: &str,
    path: &str,
    manager_client: C,
) -> zbus::Result<Connection> {
    let lock = Arc::new(AsyncMutex::new(()));
    connection::Builder::session()?
        .name(service_name)?
        .serve_at(
            path,
            CredentialManager {
                app_lock: lock,
                manager_client,
            },
        )?
        .build()
        .await
}

struct CredentialRequestController<H: HybridHandler, U: UsbHandler, UC: UiController> {
    svc: Arc<AsyncMutex<CredentialService<H, U, UC>>>,
}

#[interface(name = "xyz.iinuwa.credentials.impl.Credentials")]
impl<H, U, UC> CredentialRequestController<H, U, UC>
where
    H: HybridHandler + Debug + Send + Sync + 'static,
    U: UsbHandler + Debug + Send + Sync + 'static,
    UC: UiController + Debug + Send + Sync + 'static,
{
    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
    ) -> fdo::Result<CreateCredentialResponse> {
        match create_credential_request_try_into_ctap2(&request) {
            Ok((make_request, client_data_json)) => {
                let mut rx = {
                    let rx: Receiver<Result<CredentialResponse, creds_lib::model::Error>> = self
                        .svc
                        .lock()
                        .await
                        .init_request(&CredentialRequest::CreatePublicKeyCredentialRequest(
                            make_request,
                        ))
                        .await;
                    rx
                };
                let msg = rx.recv().await.ok_or_else(|| {
                    tracing::error!("Credential service shutdown response channel prematurely");
                    fdo::Error::Failed("Credential service shutdown".to_string())
                })?;
                match msg {
                    Ok(CredentialResponse::CreatePublicKeyCredentialResponse(cred_response)) => {
                        let public_key_response = create_credential_response_try_from_ctap2(
                            &cred_response,
                            client_data_json,
                        )?;
                        Ok(public_key_response.into())
                    }
                    // We should be returning the correct kind of response, so this shouldn't happen.
                    Ok(_) => Err(fdo::Error::Failed("Internal error occurred".to_string())),
                    Err(_) => Err(fdo::Error::Failed(
                        "Failed to create credential".to_string(),
                    )),
                }
            }
            Err(_) => Err(fdo::Error::InvalidArgs(
                "Unable to parse create credential request".to_string(),
            )),
        }
    }

    async fn get_credential(
        &self,
        request: GetCredentialRequest,
    ) -> fdo::Result<GetCredentialResponse> {
        match get_credential_request_try_into_ctap2(&request) {
            Ok((get_request, client_data_json)) => {
                let mut rx = {
                    let rx: Receiver<Result<CredentialResponse, creds_lib::model::Error>> = self
                        .svc
                        .lock()
                        .await
                        .init_request(&CredentialRequest::GetPublicKeyCredentialRequest(
                            get_request,
                        ))
                        .await;
                    rx
                };
                let msg = rx.recv().await.ok_or_else(|| {
                    tracing::error!("Credential service shutdown response channel prematurely");
                    fdo::Error::Failed("Credential service shutdown".to_string())
                })?;
                match msg {
                    Ok(CredentialResponse::GetPublicKeyCredentialResponse(cred_response)) => {
                        let public_key_response = get_credential_response_try_from_ctap2(
                            &cred_response,
                            client_data_json,
                        )?;
                        Ok(public_key_response.into())
                    }
                    // We should be returning the correct kind of response, so this shouldn't happen.
                    Ok(_) => Err(fdo::Error::Failed("Internal error occurred".to_string())),
                    Err(_) => Err(fdo::Error::Failed("Failed to get credential".to_string())),
                }
            }
            Err(_) => Err(fdo::Error::InvalidArgs(
                "Unable to parse get credential request".to_string(),
            )),
        }
    }
}

async fn execute_flow<C: CredentialManagementClient>(
    // TODO: Replace this with UiControlClient
    // gui_tx: &async_std::channel::Sender<ViewRequest>,
    manager_client: &C,
    cred_request: &CredentialRequest,
) -> zbus::Result<CredentialResponse> {
    let mut signal_rx = manager_client.init_request(cred_request.clone()).await;
    let rsp = signal_rx
        .recv()
        .await
        .ok_or(fdo::Error::Failed(
            "Credential service unexpectedly interrupted".to_string(),
        ))?
        .map_err(|err| fdo::Error::Failed(err.to_string()))?;
    Ok(rsp)

    /*
    // start GUI
    let operation = match &cred_request {
        CredentialRequest::CreatePublicKeyCredentialRequest(_) => Operation::Create,
        CredentialRequest::GetPublicKeyCredentialRequest(_) => Operation::Get,
    };
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
    let view_request = ViewRequest {
        operation,
        signal: signal_tx,
    };
    // TODO: Replace this with a UiControlClient
    // gui_tx.send(view_request).await.unwrap();
    // wait for gui to complete
    signal_rx.await.map_err(|_| {
        zbus::Error::Failure("GUI channel closed before completing request.".to_string())
    })?;

    // finish up
    manager_client.complete_auth().await.map_err(|err| {
        tracing::error!("Error retrieving credential: {:?}", err);
        zbus::Error::Failure("Error retrieving credential".to_string())
    })
    */
}
