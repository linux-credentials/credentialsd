use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use async_std::channel::{Receiver, Sender};
use async_std::sync::Mutex as AsyncMutex;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use gettextrs::{gettext, LocaleCategory};
use gtk::{gio, glib};

use libwebauthn::fido::AuthenticatorDataFlags;
use libwebauthn::ops::webauthn::{Assertion, GetAssertionRequest, MakeCredentialRequest, MakeCredentialResponse, UserVerificationRequirement};
use libwebauthn::proto::ctap2::{Ctap2AttestationStatement, Ctap2COSEAlgorithmIdentifier, Ctap2MakeCredentialResponse, Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity};
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
        mut request: CreateCredentialRequest,
    ) -> fdo::Result<CreateCredentialResponse> {
        if let Some(tx) = self.app_lock.try_lock() {
            let origin = request
                .origin
                .clone()
                .unwrap_or("xyz.iinuwa.credentials.CredentialManager:local".to_string());
            let is_same_origin = request.is_same_origin.unwrap_or(false);
            let response = match (
                request.r#type.as_ref(),
                &request.password,
                &request.public_key,
            ) {
                ("password", Some(password_request), _) => {
                    let password_response = create_password(&origin, is_same_origin, password_request).await?;
                    Ok(password_response.into())
                }
                ("publicKey", _, Some(passkey_request)) => {
                    _ = request.origin.get_or_insert("xyz.iinuwa.credentials.CredentialManager:local".to_string());
                    let (make_cred_request, client_data_json) = request.clone().try_into_ctap2_request().map_err(|_| fdo::Error::Failed("Could not parse passkey creation request.".to_owned()))?;
                    let request = CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request);
                    let (data_tx, data_rx) = async_std::channel::bounded(1);
                    tx.send((request, data_tx)).await.unwrap();
                    let data_rx = Arc::new(data_rx);
                    if let CredentialResponse::CreatePublicKeyCredentialResponse(cred_response) = data_rx.recv().await.unwrap() {
                        let public_key_response = CreatePublicKeyCredentialResponse::try_from_ctap2_response(&cred_response, client_data_json)?;
                        Ok(public_key_response.into())
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
            tracing::info!("Window already open");
            Err(fdo::Error::ObjectPathInUse(
                "WebAuthn session already open.".into(),
            ))
        }
    }

    async fn get_credential(
        &self,
        mut request: GetCredentialRequest,
    ) -> fdo::Result<GetCredentialResponse> {
        if let Some(tx) = self.app_lock.try_lock() {
            let origin = request
                .origin
                .clone()
                .unwrap_or("xyz.iinuwa.credentials.CredentialManager:local".to_string());
            let is_same_origin = request.is_same_origin.unwrap_or(false);
            let response = match (
                request.r#type.as_ref(),
                &request.password,
                &request.public_key,
            ) {
                ("password", Some(password_request), _) => {
                    let password_response = get_password(&origin, is_same_origin, password_request).await?;
                    Ok(password_response.into())
                }
                ("publicKey", _, Some(passkey_request)) => {
                    _ = request.origin.get_or_insert("xyz.iinuwa.credentials.CredentialManager:local".to_string());
                    // TODO: assert that RP ID is bound to origin:
                    // - if RP ID is not set, set the RP ID to the origin's effective domain
                    // - if RP ID is set, assert that it matches origin's effective domain
                    // - if RP ID is set, but origin's effective domain doesn't match
                    //    - query for related origins, if supported
                    //    - fail if not supported, or if RP ID doesn't match any related origins.
                    let (get_cred_request, client_data_json) = request.clone().try_into_ctap2_request().map_err(|_| fdo::Error::Failed("Could not parse passkey assertion request.".to_owned()))?;
                    let request = CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request);
                    let (data_tx, data_rx) = async_std::channel::bounded(1);
                    tx.send((request, data_tx)).await.unwrap();
                    let data_rx = Arc::new(data_rx);
                    match data_rx.recv().await {
                        Ok(CredentialResponse::GetPublicKeyCredentialResponse(cred_response)) => {
                            let public_key_response = GetPublicKeyCredentialResponse::try_from_ctap2_response(&cred_response, client_data_json)?;
                            Ok(public_key_response.into())
                        },
                        Ok(_) => Err(fdo::Error::Failed("Invalid credential response received from authenticator".to_string())),
                        Err(_) => Err(fdo::Error::Failed("User cancelled operation".to_string())),
                    }
                }
                _ => Err(fdo::Error::Failed(
                    "Unknown credential request type".to_string(),
                )),
            };
            response
        } else {
            tracing::info!("Window already open");
            Err(fdo::Error::ObjectPathInUse(
                "WebAuthn session already open.".into(),
            ))
        }
    }
}

async fn create_password(
    origin: &str,
    is_same_origin: bool,
    request: &CreatePasswordCredentialRequest,
) -> fdo::Result<CreatePasswordCredentialResponse> {
    if !is_same_origin {
        return Err(fdo::Error::AccessDenied("Passwords may only be requested from same-origin contexts".to_string()));
    }
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

async fn get_password(origin: &str, is_same_origin: bool, request: &GetPasswordCredentialRequest) -> Result<GetPasswordCredentialResponse>{
    todo!()
}

async fn create_passkey(
    origin: &str,
    is_same_origin: bool,
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
// D-Bus <-> internal types
#[derive(Clone, Debug)]
pub(crate) enum CredentialRequest {
    CreatePublicKeyCredentialRequest(MakeCredentialRequest),
    GetPublicKeyCredentialRequest(GetAssertionRequest),
}

#[derive(Clone, Debug)]
pub(crate) enum CredentialResponse {
    CreatePublicKeyCredentialResponse(MakeCredentialResponse),
    GetPublicKeyCredentialResponse(Assertion)
}

// D-Bus <-> Client types
#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialRequest {
    origin: Option<String>,
    is_same_origin: Option<bool>,
    #[zvariant(rename = "type")]
    r#type: String,
    password: Option<CreatePasswordCredentialRequest>,
    #[zvariant(rename = "publicKey")]
    public_key: Option<CreatePublicKeyCredentialRequest>,
}

impl CreateCredentialRequest {
    fn try_into_ctap2_request(&self) -> std::result::Result<(MakeCredentialRequest, String), webauthn::Error> {
        if self.public_key.is_none() {
            return Err(webauthn::Error::NotSupported);
        }
        let options = self.public_key.as_ref().unwrap();
        let request_value = serde_json::from_str::<serde_json::Value>(&options.request_json)
            .map_err(|_| webauthn::Error::Internal("Invalid request JSON".to_string()))?;
        let json = request_value
            .as_object()
            .ok_or_else(|| webauthn::Error::Internal("Invalid request JSON".to_string()))?;
        let challenge = json
            .get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| webauthn::Error::Internal("JSON missing `challenge` field".to_string()))?
            .to_owned();
        let rp = json
            .get("rp")
            .and_then(|val| serde_json::from_str::<Ctap2PublicKeyCredentialRpEntity>(&val.to_string()).ok())
            .ok_or_else(|| webauthn::Error::Internal("JSON missing `rp` field".to_string()))?;
        let user = json
            .get("user")
            .ok_or(webauthn::Error::Internal("JSON missing `user` field".to_string()))
            .and_then(|val| {
                serde_json::from_str::<Ctap2PublicKeyCredentialUserEntity>(&val.to_string()).map_err(|e| {
                    let msg = format!("JSON missing `user` field: {e}");
                    webauthn::Error::Internal(msg)
                })
            })?;
        let other_options = serde_json::from_str::<webauthn::MakeCredentialOptions>(&request_value.to_string())
            .map_err(|_| webauthn::Error::Internal("Invalid request JSON".to_string()))?;
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
                webauthn::Error::Internal("Request JSON missing or invalid `pubKeyCredParams` key".to_string())
            })
            .and_then(|val| -> std::result::Result<Vec<_>, webauthn::Error> {
                serde_json::from_str::<Vec<PublicKeyCredentialParameters>>(&val.to_string()).map_err(
                    |e| {
                        webauthn::Error::Internal(format!(
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
        let (origin, is_cross_origin) = match (self.origin.as_ref(), self.is_same_origin.as_ref()) {
            (Some(origin), Some(is_same_origin)) => (origin.to_string(), !is_same_origin),
            (Some(origin), None) => (origin.to_string(), true),
            // origin should always be set on request either by client or D-Bus service,
            // so this shouldn't be called
            (None, _) => {
                return Err(webauthn::Error::Internal("Error reading origin from request".to_string()));
            }
        };
        let client_data_json = format_client_data_json(Operation::Create { cred_type: CredentialType::Passkey }, &challenge, &origin, is_cross_origin);
        let client_data_hash = digest::digest(&digest::SHA256, client_data_json.as_bytes())
            .as_ref()
            .to_owned();
        Ok((MakeCredentialRequest {
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

        }, client_data_json))
    }
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

impl CreatePublicKeyCredentialResponse {
    fn try_from_ctap2_response(response: &Ctap2MakeCredentialResponse, client_data_json: String) -> std::result::Result<Self, fdo::Error> {
        let auth_data = &response.authenticator_data;
        let attested_credential = auth_data.attested_credential.as_ref().ok_or_else(|| fdo::Error::Failed("Invalid credential received from authenticator".to_string()))?;
        let public_key = encode_public_key(&attested_credential.credential_public_key)?;
        let attested_credential_data =
            webauthn::create_attested_credential_data(&attested_credential.credential_id, &public_key, &attested_credential.aaguid).unwrap();

        let authenticator_data_blob = create_authenticator_data(
            &auth_data.rp_id_hash,
            &auth_data.flags,
            (&auth_data).signature_count,
            Some(&attested_credential_data),
            // TODO: what's the format for extensions... JSON?
            auth_data.extensions.as_ref().map(|e| serde_json::to_vec(&e).unwrap()).as_deref(),
        );
        let attestation_object = create_attestation_object(
            &authenticator_data_blob,
            &response.attestation_statement,
            response.enterprise_attestation.unwrap_or(false),
        )?;
        // do we need to check that the client_data_hash is the same?
        let registration_response_json = webauthn::CreatePublicKeyCredentialResponse::new(
            attested_credential.credential_id.clone(),
            attestation_object,
            authenticator_data_blob,
            client_data_json,
            Some(vec!["usb".to_string()]),
            None,
        ).to_json();
        let response = CreatePublicKeyCredentialResponse {
            registration_response_json,
        };
        Ok(response.into())
    }
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

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetCredentialRequest {
    origin: Option<String>,
    is_same_origin: Option<bool>,
    #[zvariant(rename = "type")]
    r#type: String,
    password: Option<GetPasswordCredentialRequest>,
    #[zvariant(rename = "publicKey")]
    public_key: Option<GetPublicKeyCredentialRequest>,
}

impl GetCredentialRequest {
    fn try_into_ctap2_request(&self) -> std::result::Result<(GetAssertionRequest, String), webauthn::Error> {
        if self.public_key.is_none() {
            return Err(webauthn::Error::NotSupported);
        }
        let options = self.public_key.as_ref().unwrap();
        let request: webauthn::GetCredentialOptions = serde_json::from_str(&options.request_json)
            .map_err(|e| webauthn::Error::Internal(format!("Invalid request JSON: {:?}", e)))?;
        let allow = request.allow_credentials.iter()
            .filter_map(|cred| {
                if cred.cred_type != "public-key" { None }
                else { cred.try_into().ok() }
            })
            .collect();
        let (origin, is_cross_origin) = match (self.origin.as_ref(), self.is_same_origin.as_ref()) {
            (Some(origin), Some(is_same_origin)) => (origin.to_string(), !is_same_origin),
            (Some(origin), None) => (origin.to_string(), true),
            // origin should always be set on request either by client or D-Bus service,
            // so this shouldn't be called
            (None, _) => {
                return Err(webauthn::Error::Internal("Error reading origin from request".to_string()));
            }
        };
        let client_data_json = format_client_data_json(Operation::Get { cred_types: vec![CredentialType::Passkey] }, &request.challenge, &origin, is_cross_origin);
        let client_data_hash = digest::digest(&digest::SHA256, client_data_json.as_bytes())
            .as_ref()
            .to_owned();
        // TODO: actually calculate correct effective domain, and use fallback to related origin requests to fill this in. For now, just default to origin.
        let user_verification = match request.user_verification.unwrap_or_else(|| String::from("preferred")).as_ref() {
            "required" => UserVerificationRequirement::Required,
            "preferred" => UserVerificationRequirement::Preferred,
            "discouraged" => UserVerificationRequirement::Discouraged,
            _ => return Err(webauthn::Error::Internal("Invalid user verification requirement specified".to_string()))
        };
        let relying_party_id = request.rp_id.unwrap_or_else(|| {
            let (_, effective_domain) = origin.rsplit_once('/').unwrap();
            effective_domain.to_string()
        });
        // TODO(extensions-support)
        let extensions = None;
        Ok((GetAssertionRequest {
            hash: client_data_hash,

            relying_party_id,
            user_verification,
            allow,
            extensions,
            timeout: request.timeout.unwrap_or(Duration::from_secs(300)),

        }, client_data_json))
    }
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPasswordCredentialRequest {
    id: String,
    password: String,
}


#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPublicKeyCredentialRequest {
    pub(crate) request_json: String,
}

impl GetPublicKeyCredentialResponse {
    fn try_from_ctap2_response(response: &Assertion, client_data_json: String) -> std::result::Result<Self, fdo::Error> {
        let auth_data = &response.authenticator_data;
        let attested_credential_data = match &auth_data.attested_credential {
            None => None,
            Some(att) => {
                let public_key = encode_public_key(&att.credential_public_key)?;
                let data = webauthn::create_attested_credential_data(&att.credential_id, &public_key, &att.aaguid)
                    .map_err(|_| zbus::Error::Failure("Failed to parse attested credential data".to_string()))?;
                Some(data)
            },
        };

        // TODO: what's the format for extensions... CBOR?
        // let ext = auth_data.extensions.as_ref().map(|e| serde_json::to_vec(&e).unwrap()).as_deref();
        let extensions = None;

        let authenticator_data_blob = create_authenticator_data(
            &auth_data.rp_id_hash,
            &auth_data.flags,
            (&auth_data).signature_count,
            attested_credential_data.as_deref(),
            extensions,
        );

        let registration_response_json = webauthn::GetPublicKeyCredentialResponse::new(
            client_data_json,
            response.credential_id.as_ref().map(|c| c.id.clone().into_vec()),
            authenticator_data_blob,
            response.signature.clone(),
            response.user.as_ref().map(|u| u.id.clone().into_vec()),
        ).to_json();
        let response = GetPublicKeyCredentialResponse {
            registration_response_json,
        };
        Ok(response.into())
    }
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetCredentialResponse {
    #[zvariant(rename = "type")]
    r#type: String,
    password: Option<GetPasswordCredentialResponse>,
    public_key: Option<GetPublicKeyCredentialResponse>,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPasswordCredentialResponse {}

impl From<GetPasswordCredentialResponse> for GetCredentialResponse {
    fn from(response: GetPasswordCredentialResponse) -> Self {
        GetCredentialResponse {
            r#type: "password".to_string(),
            password: Some(response),
            public_key: None,
        }
    }
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPublicKeyCredentialResponse {
    registration_response_json: String,
}

impl From<GetPublicKeyCredentialResponse> for GetCredentialResponse {
    fn from(response: GetPublicKeyCredentialResponse) -> Self {
        GetCredentialResponse {
            // TODO: Decide on camelCase or kebab-case for cred types
            r#type: "public-key".to_string(),
            public_key: Some(response),
            password: None,
        }
    }
}

fn format_client_data_json(op: Operation, challenge: &str, origin: &str, is_cross_origin: bool) -> String {
    let op_str = match op {
        Operation::Create { .. } => "webauthn.create",
        Operation::Get  { .. }=> "webauthn.get",
    };
    let cross_origin_str = if is_cross_origin { "true" } else { "false" };
    format!("{{\"type\":\"{op_str}\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":{cross_origin_str}}}")
}

/// returns CTAP2-serialized public key and algorithm
fn encode_public_key(public_key: &cosey::PublicKey) -> Result<Vec<u8>> {
    match public_key {
            cosey::PublicKey::P256Key(p256_key) => {
            let mut cose_key: Vec<u8> = Vec::new();
            cose_key.push(0b101_00101); // map with 5 items
            cose_key.extend([0b000_00001, 0b000_00010]); // kty (1): EC2 (2)
            cose_key.extend([0b000_00011, 0b001_00110]); // alg (3): ECDSA-SHA256 (-7)
            cose_key.extend([0b001_00000, 0b000_00001]); // crv (-1): P256 (1)
            cose_key.extend([0b001_00001, 0b010_11000, 0b0010_0000]); // x (-2): <32-byte string>
            cose_key.extend(p256_key.x.clone());
            cose_key.extend([0b001_00010, 0b010_11000, 0b0010_0000]); // y (-3): <32-byte string>
            cose_key.extend(p256_key.y.clone());
            Ok(cose_key)
        },
        cosey::PublicKey::Ed25519Key(ed25519_key) => {
            // TODO: Check this
            let mut cose_key: Vec<u8> = Vec::new();
            cose_key.push(0b101_00100); // map with 4 items
            cose_key.extend([0b000_00001, 0b000_00001]); // kty (1): OKP (1)
            cose_key.extend([0b000_00011, 0b001_00111]); // alg (3): EdDSA (-8)
            cose_key.extend([0b001_00000, 0b000_00110]); // crv (-1): ED25519 (6)
            cose_key.extend([0b001_00001, 0b010_11000, 0b0010_0000]); // x (-2): <32-byte string>
            cose_key.extend(ed25519_key.x.clone());
            Ok(cose_key)
        },
        _ => return Err(zbus::Error::Failure(format!("Cannot serialize unknown key type {:?}", public_key))),
    }
}

fn create_authenticator_data(rp_id_hash: &[u8], flags: &AuthenticatorDataFlags, signature_counter: u32, attested_credential_data: Option<&[u8]>, extensions: Option<&[u8]>) -> Vec<u8> {
    let mut authenticator_data: Vec<u8> = Vec::new();
    authenticator_data.extend(rp_id_hash);

    authenticator_data.push(flags.bits());

    authenticator_data.extend(signature_counter.to_be_bytes());

    if let Some(attested_credential_data) = attested_credential_data {
        authenticator_data.extend(attested_credential_data);
    }

    if extensions.is_some() {
        todo!("Implement processed extensions");
        // TODO: authenticator_data.append(processed_extensions.to_bytes());
    }
    authenticator_data
}

fn create_attestation_object(
    authenticator_data: &[u8],
    attestation_statement:&Ctap2AttestationStatement,
    _enterprise_attestation_possible: bool,
) -> Result<Vec<u8>> {
    let mut attestation_object = Vec::new();
    let mut cbor_writer = crate::cbor::CborWriter::new(&mut attestation_object);
    cbor_writer.write_map_start(3).unwrap();
    cbor_writer.write_text("fmt").unwrap();
    match attestation_statement {
        Ctap2AttestationStatement::PackedOrAndroid(att_stmt) => {
            cbor_writer.write_text("packed").unwrap();
            cbor_writer.write_text("attStmt").unwrap();
            let len = if att_stmt.certificates.is_empty() { 2 } else { 3 };
            cbor_writer.write_map_start(len).unwrap();
            cbor_writer.write_text("alg").unwrap();
            let alg = match att_stmt.algorithm {
                Ctap2COSEAlgorithmIdentifier::ES256 => -7,
                Ctap2COSEAlgorithmIdentifier::EDDSA => -8,
                // TODO: What's this?
                Ctap2COSEAlgorithmIdentifier::TOPT => return Err(zbus::Error::Failure(format!("Unknown public key algorithm type: {:?}", att_stmt.algorithm))),
            };
            cbor_writer.write_number(alg).unwrap();
            cbor_writer.write_text("sig").unwrap();
            cbor_writer.write_bytes(att_stmt.signature.as_ref()).unwrap();
            if !att_stmt.certificates.is_empty() {
                cbor_writer.write_text("x5c").unwrap();
                cbor_writer.write_array_start(att_stmt.certificates.len()).unwrap();
                for cert in att_stmt.certificates.iter() {
                    cbor_writer.write_bytes(cert).unwrap();
                }
            }
        },
        Ctap2AttestationStatement::None(_) => {
            cbor_writer.write_text("none").unwrap();
            cbor_writer.write_text("attStmt").unwrap();
            cbor_writer.write_map_start(0).unwrap();
        }
        _ => return Err(zbus::Error::Failure(format!("Unsupported attestation type: {:?}", attestation_statement))),
    };

    cbor_writer.write_text("authData").unwrap();
    cbor_writer.write_bytes(authenticator_data).unwrap();

    Ok(attestation_object)
}
