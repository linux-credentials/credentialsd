use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use async_std::channel::{Receiver, Sender};
use async_std::sync::Mutex as AsyncMutex;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use gettextrs::{gettext, LocaleCategory};
use gtk::{gio, glib};

use libwebauthn::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse, UserVerificationRequirement};
use libwebauthn::proto::ctap2::{Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity};
use zbus::zvariant::{DeserializeDict, SerializeDict, Type};
use zbus::{fdo, interface, connection::{self, Connection}, Result};

use crate::application::ExampleApplication;
use crate::config::{GETTEXT_PACKAGE, LOCALEDIR, RESOURCES_FILE};
use crate::credential_service::CredentialService;
use crate::store;
use crate::view_model::CredentialType;
use crate::view_model::Operation;
use crate::view_model::{self, ViewEvent, ViewUpdate};
use crate::webauthn::{self, PublicKeyCredentialParameters};
use ring::digest;
// use crate::store;
// use crate::webauthn;

pub(crate) async fn start_service(service_name: &str, path: &str) -> Result<Connection> {
    let (gui_tx, gui_rx) = async_std::channel::bounded(1);
    let lock: Arc<AsyncMutex<Sender<(CredentialRequest, Sender<CredentialResponse>)>>> = Arc::new(AsyncMutex::new(gui_tx));
    start_gui_thread(gui_rx);
    connection::Builder::session()?
        .name(service_name)?
        .serve_at(path, CredentialManager { app_lock: lock })?
        .build()
        .await
}

fn start_gui_thread(rx: Receiver<(CredentialRequest, Sender<CredentialResponse>)>) {
    thread::Builder::new()
        .name("gui".into())
        .spawn(move || {
            while let Ok((cred_request, response_tx)) = rx.recv_blocking() {
                let (tx_update, rx_update) = async_std::channel::unbounded::<ViewUpdate>();
                let (tx_event, rx_event) = async_std::channel::unbounded::<ViewEvent>();
                let data = Arc::new(Mutex::new(None));
                let credential_service = CredentialService::new(cred_request, data.clone());
                let event_loop = async_std::task::spawn(async move {
                    let operation = Operation::Create {
                        cred_type: CredentialType::Passkey,
                    };
                    let mut vm = view_model::ViewModel::new(
                        operation,
                        credential_service,
                        rx_event,
                        tx_update,
                    );
                    vm.start_event_loop().await;
                    println!("event loop ended?");
                });
                start_gtk_app(tx_event, rx_update);

                async_std::task::block_on(event_loop.cancel());
                let lock = data.lock().unwrap();
                let response = lock.as_ref().unwrap().clone();
                response_tx.send_blocking(response).unwrap();
            }
        })
        .unwrap();
}

fn start_gtk_app(tx_event: Sender<ViewEvent>, rx_update: Receiver<ViewUpdate>) {
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

struct CredentialManager {
    app_lock: Arc<AsyncMutex<Sender<(CredentialRequest, Sender<CredentialResponse>)>>>,
}

#[interface(name = "xyz.iinuwa.credentials.CredentialManagerUi1")]
impl CredentialManager {
    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
    ) -> fdo::Result<CreateCredentialResponse> {
        if let Some(tx) = self.app_lock.try_lock() {
            let origin = request
                .origin
                .clone()
                .unwrap_or("xyz.iinuwa.credentials.CredentialManager:local".to_string());
            let response = match (
                request.r#type.as_ref(),
                &request.password,
                &request.public_key,
            ) {
                ("password", Some(password_request), _) => {
                    let password_response = create_password(&origin, password_request).await?;
                    Ok(password_response.into())
                }
                ("publicKey", _, Some(passkey_request)) => {
                    let make_cred_request = request.clone().try_into().map_err(|_| fdo::Error::Failed("Could not parse passkey creation request.".to_owned()))?;
                    let request = CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request);
                    let (data_tx, data_rx) = async_std::channel::bounded(1);
                    tx.send((request, data_tx)).await.unwrap();
                    let data_rx = Arc::new(data_rx);
                    if let CredentialResponse::CreatePublicKeyCredentialResponse(cred_response) = data_rx.recv().await.unwrap() {
                        let id = cred_response.authenticator_data.attested_credential.unwrap().credential_id;
                        let registration_response_json = webauthn::CreatePublicKeyCredentialResponse::new(
                            id,
                            vec![],
                            vec![],
                            "{\"type\":\"webauthn.create\", /* BOGUS */}".to_string(),
                            Some(vec!["usb".to_string()]),
                            None,
                        ).to_json();
                        let response = CreatePublicKeyCredentialResponse {
                            registration_response_json,
                        };
                        Ok(response.into())
                    }
                    else {
                        Err(fdo::Error::Failed("Failed to create passkey".to_string()))
                    }
                }
                _ => Err(fdo::Error::Failed(
                    "Unknown credential request type".to_string(),
                )),
            };
            response
        } else {
            tracing::debug!("Window already open");
            Err(fdo::Error::ObjectPathInUse(
                "WebAuthn session already open.".into(),
            ))
        }
    }
}

async fn create_password(
    origin: &str,
    request: &CreatePasswordCredentialRequest,
) -> fdo::Result<CreatePasswordCredentialResponse> {
    /*
    store::store_password(&request.origin, &request.id, &request.password).await
        .map(|_| CreatePasswordCredentialResponse{})
        .map_err(|_| fdo::Error::Failed("Failed to store password".to_string()));
    */
    let contents = format!(
        "id={}&password={}",
        request.id.replace('%', "%25").replace('&', "%26"),
        request.password.replace('%', "%25").replace('&', "%26")
    );
    let display_name = format!("Password for {origin}"); // TODO
    store::store_secret(
        &[origin],
        &display_name,
        &request.id,
        "secret/password",
        None,
        contents.as_bytes(),
    )
    .await
    .map_err(|_| fdo::Error::Failed("".to_string()))?;
    Ok(CreatePasswordCredentialResponse {})
}

async fn create_passkey(
    origin: &str,
    request: &CreatePublicKeyCredentialRequest,
) -> fdo::Result<CreatePublicKeyCredentialResponse> {
    let (response, cred_source, user) =
        webauthn::create_credential(origin, &request.request_json, true).map_err(|_| {
            fdo::Error::Failed("Failed to create public key credential".to_string())
        })?;

    let mut contents = String::new();
    contents.push_str("type=public-key"); // TODO: Don't hardcode public-key?
    contents.push_str("&id=");
    URL_SAFE_NO_PAD.encode_string(cred_source.id, &mut contents);
    contents.push_str("&key=");
    URL_SAFE_NO_PAD.encode_string(cred_source.private_key, &mut contents);
    contents.push_str("&rp_id=");
    contents.push_str(&cred_source.rp_id);
    if let Some(user_handle) = &cred_source.user_handle {
        contents.push_str("&user_handle=");
        URL_SAFE_NO_PAD.encode_string(user_handle, &mut contents);
    }

    if let Some(other_ui) = cred_source.other_ui {
        contents.push_str("&other_ui=");
        contents.push_str(&other_ui);
    }
    let content_type = "secret/public-key";
    let display_name = "test"; // TODO
    store::store_secret(
        &[origin],
        display_name,
        &user.display_name,
        content_type,
        None,
        contents.as_bytes(),
    )
    .await
    .map_err(|_| fdo::Error::Failed("Failed to save passkey to storage".to_string()))?;

    Ok(CreatePublicKeyCredentialResponse {
        registration_response_json: response.to_json(),
    })
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialRequest {
    origin: Option<String>,
    #[zvariant(rename = "type")]
    r#type: String,
    password: Option<CreatePasswordCredentialRequest>,
    #[zvariant(rename = "publicKey")]
    public_key: Option<CreatePublicKeyCredentialRequest>,
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePasswordCredentialRequest {
    id: String,
    password: String,
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialRequest {
    pub(crate) request_json: String,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialResponse {
    #[zvariant(rename = "type")]
    r#type: String,
    password: Option<CreatePasswordCredentialResponse>,
    public_key: Option<CreatePublicKeyCredentialResponse>,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePasswordCredentialResponse {}

impl From<CreatePasswordCredentialResponse> for CreateCredentialResponse {
    fn from(response: CreatePasswordCredentialResponse) -> Self {
        CreateCredentialResponse {
            r#type: "password".to_string(),
            password: Some(response),
            public_key: None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum CredentialRequest {
    CreatePublicKeyCredentialRequest(MakeCredentialRequest),
}


#[derive(Clone, Debug)]
pub(crate) enum CredentialResponse {
    CreatePublicKeyCredentialResponse(MakeCredentialResponse),
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialResponse {
    registration_response_json: String,
}

impl From<CreatePublicKeyCredentialResponse> for CreateCredentialResponse {
    fn from(response: CreatePublicKeyCredentialResponse) -> Self {
        CreateCredentialResponse {
            // TODO: Decide on camelCase or kebab-case for cred types
            r#type: "public-key".to_string(),
            public_key: Some(response),
            password: None,
        }
    }
}

impl TryFrom<CreateCredentialRequest> for MakeCredentialRequest {
    type Error = crate::webauthn::Error;

    fn try_from(value: CreateCredentialRequest) -> std::result::Result<Self, Self::Error> {
        MakeCredentialRequest::try_from(&value)
    }
}
impl TryFrom<&CreateCredentialRequest> for MakeCredentialRequest {
    type Error = crate::webauthn::Error;

    fn try_from(value: &CreateCredentialRequest) -> std::result::Result<Self, Self::Error> {
        if value.public_key.is_none() {
            return Err(Self::Error::NotSupported);
        }
        let options = value.public_key.as_ref().unwrap();
        let request_value = serde_json::from_str::<serde_json::Value>(&options.request_json)
            .map_err(|_| Self::Error::Internal("Invalid request JSON".to_string()))?;
        let json = request_value
            .as_object()
            .ok_or_else(|| Self::Error::Internal("Invalid request JSON".to_string()))?;
        let challenge = json
            .get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| Self::Error::Internal("JSON missing `challenge` field".to_string()))?
            .to_owned();
        let rp = json
            .get("rp")
            .and_then(|val| serde_json::from_str::<Ctap2PublicKeyCredentialRpEntity>(&val.to_string()).ok())
            .ok_or_else(|| Self::Error::Internal("JSON missing `rp` field".to_string()))?;
        let user = json
            .get("user")
            .ok_or(Self::Error::Internal("JSON missing `user` field".to_string()))
            .and_then(|val| {
                serde_json::from_str::<Ctap2PublicKeyCredentialUserEntity>(&val.to_string()).map_err(|e| {
                    let msg = format!("JSON missing `user` field: {e}");
                    Self::Error::Internal(msg)
                })
            })?;
        let other_options = serde_json::from_str::<webauthn::MakeCredentialOptions>(&request_value.to_string())
            .map_err(|_| Self::Error::Internal("Invalid request JSON".to_string()))?;
        let (require_resident_key, user_verification) =
            if let Some(authenticator_selection) = other_options.authenticator_selection {
                let is_authenticator_storage_capable = true;
                let require_resident_key = authenticator_selection.resident_key.map_or_else(
                    || false,
                    |r| r == "required" || (r == "preferred" && is_authenticator_storage_capable),
                ); // fallback to authenticator_selection.require_resident_key == true for WebAuthn Level 1?

                let user_verification = authenticator_selection.user_verification.map(|uv| match uv.as_ref() {
                    "required" => UserVerificationRequirement::Required,
                    "preferred" => UserVerificationRequirement::Preferred,
                    "discouraged" => UserVerificationRequirement::Discouraged,
                    _ => todo!("This should be fixed in the future"),
                }).unwrap_or(UserVerificationRequirement::Preferred);

                (require_resident_key, user_verification)
            } else {
                (false, UserVerificationRequirement::Preferred)
            };
        let extensions = None;
        let credential_parameters = request_value
            .clone()
            .get("pubKeyCredParams")
            .ok_or_else(|| {
                Self::Error::Internal("Request JSON missing or invalid `pubKeyCredParams` key".to_string())
            })
            .and_then(|val| -> std::result::Result<Vec<_>, webauthn::Error> {
                serde_json::from_str::<Vec<PublicKeyCredentialParameters>>(&val.to_string()).map_err(
                    |e| {
                        Self::Error::Internal(format!(
                            "Request JSON missing or invalid `pubKeyCredParams` key: {e}"
                        ))
                    },
                )
            })?;
        let algorithms = credential_parameters.iter().filter_map(|p| p.try_into().ok()).collect();
        let exclude = other_options.excluded_credentials
            .map(|v|
                v.iter().map(|e| e.try_into())
                    .filter_map(|e| e.ok())
                    .collect());
        let origin = value.origin.as_ref().map_or_else(|| "xyz.iinuwa.credentials.CredentialManager:local", |s| &s).to_string();
        let cross_origin = true;
        let cross_origin_str = if cross_origin { "true" } else { "false" };
        let client_data_json = format!("{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":{cross_origin_str}}}");
        let client_data_hash = digest::digest(&digest::SHA256, client_data_json.as_bytes())
            .as_ref()
            .to_owned();
        Ok(MakeCredentialRequest {
            hash: client_data_hash,
            origin,

            relying_party: rp,
            user,
            require_resident_key,
            user_verification,
            algorithms,
            exclude,
            extensions,
            timeout: other_options.timeout.unwrap_or(Duration::from_secs(300)),

        })
    }
}
