use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD};

use libwebauthn::ops::webauthn::{
    Assertion, CredentialProtectionExtension, GetAssertionHmacOrPrfInput,
    GetAssertionLargeBlobExtension, GetAssertionRequest, GetAssertionRequestExtensions,
    MakeCredentialHmacOrPrfInput, MakeCredentialRequest, MakeCredentialResponse,
    MakeCredentialsRequestExtensions, UserVerificationRequirement,
};
use libwebauthn::proto::ctap2::{
    Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
use ring::digest;
use tokio::sync::Mutex as AsyncMutex;
use zbus::{
    connection::{self, Connection},
    fdo, interface,
    zvariant::{DeserializeDict, SerializeDict, Type},
    Result,
};

use crate::credential_service::CredentialManagementClient;
use crate::gui::ViewRequest;
use crate::view_model::{CredentialType, Operation};
use crate::webauthn::{
    self, GetPublicKeyCredentialUnsignedExtensionsResponse, PublicKeyCredentialParameters,
};

pub(crate) async fn start_service<C: CredentialManagementClient + Send + Sync + 'static>(
    service_name: &str,
    path: &str,
    gui_tx: async_std::channel::Sender<ViewRequest>,
    manager_client: C,
) -> Result<Connection> {
    let lock: Arc<AsyncMutex<async_std::channel::Sender<ViewRequest>>> =
        Arc::new(AsyncMutex::new(gui_tx));
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

struct CredentialManager<C: CredentialManagementClient> {
    app_lock: Arc<AsyncMutex<async_std::channel::Sender<ViewRequest>>>,
    manager_client: C,
}

#[interface(name = "xyz.iinuwa.credentials.CredentialManagerUi1")]
impl<C: CredentialManagementClient + Send + Sync + 'static> CredentialManager<C> {
    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
    ) -> fdo::Result<CreateCredentialResponse> {
        if let Ok(tx) = self.app_lock.try_lock() {
            if request.origin.is_none() {
                todo!("Implicit caller-origin binding not yet implemented.")
            };
            let is_same_origin = request.is_same_origin.unwrap_or(false);
            let response = match (request.r#type.as_ref(), &request.public_key) {
                ("publicKey", Some(_)) => {
                    if !is_same_origin {
                        return Err(fdo::Error::AccessDenied(String::from(
                            "Cross-origin public-key credentials are not allowed.",
                        )));
                    }
                    let (make_cred_request, client_data_json) =
                        request.clone().try_into_ctap2_request().map_err(|e| {
                            fdo::Error::Failed(format!(
                                "Could not parse passkey creation request: {e:?}"
                            ))
                        })?;
                    let cred_request =
                        CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request);

                    let response = execute_flow(&tx, &self.manager_client, &cred_request).await?;

                    if let CredentialResponse::CreatePublicKeyCredentialResponse(cred_response) =
                        response
                    {
                        let public_key_response =
                            CreatePublicKeyCredentialResponse::try_from_ctap2_response(
                                &cred_response,
                                client_data_json,
                            )?;
                        Ok(public_key_response.into())
                    } else {
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
        request: GetCredentialRequest,
    ) -> fdo::Result<GetCredentialResponse> {
        if let Ok(tx) = self.app_lock.try_lock() {
            if request.origin.is_none() {
                todo!("Implicit caller-origin binding is not yet implemented.");
            }
            let is_same_origin = request.is_same_origin.unwrap_or(false);
            let response = match (request.r#type.as_ref(), &request.public_key) {
                ("publicKey", Some(_)) => {
                    if !is_same_origin {
                        return Err(fdo::Error::AccessDenied(String::from(
                            "Cross-origin public-key credentials are not allowed.",
                        )));
                    }
                    // Setup request

                    // TODO: assert that RP ID is bound to origin:
                    // - if RP ID is not set, set the RP ID to the origin's effective domain
                    // - if RP ID is set, assert that it matches origin's effective domain
                    // - if RP ID is set, but origin's effective domain doesn't match
                    //    - query for related origins, if supported
                    //    - fail if not supported, or if RP ID doesn't match any related origins.
                    let (get_cred_request, client_data_json) =
                        request.clone().try_into_ctap2_request().map_err(|_| {
                            fdo::Error::Failed(
                                "Could not parse passkey assertion request.".to_owned(),
                            )
                        })?;
                    let cred_request =
                        CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request);

                    let response = execute_flow(&tx, &self.manager_client, &cred_request).await?;

                    match response {
                        CredentialResponse::GetPublicKeyCredentialResponse(cred_response) => {
                            let public_key_response =
                                GetPublicKeyCredentialResponse::try_from_ctap2_response(
                                    &cred_response,
                                    client_data_json,
                                )?;
                            Ok(public_key_response.into())
                        }
                        _ => Err(fdo::Error::Failed(
                            "Invalid credential response received from authenticator".to_string(),
                        )),
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

    async fn get_client_capabilities(&self) -> fdo::Result<GetClientCapabilitiesResponse> {
        Ok(GetClientCapabilitiesResponse {
            conditional_create: false,
            conditional_get: false,
            hybrid_transport: false,
            passkey_platform_authenticator: false,
            user_verifying_platform_authenticator: false,
            related_origins: false,
            signal_all_accepted_credentials: false,
            signal_current_user_details: false,
            signal_unknown_credential: false,
        })
    }
}

async fn execute_flow<C: CredentialManagementClient>(
    gui_tx: &async_std::channel::Sender<ViewRequest>,
    manager_client: &C,
    cred_request: &CredentialRequest,
) -> Result<CredentialResponse> {
    manager_client
        .init_request(cred_request.clone())
        .await
        .map_err(|_| fdo::Error::Failed("Request already running".to_string()))?;

    // start GUI
    let operation = match &cred_request {
        CredentialRequest::CreatePublicKeyCredentialRequest(_) => Operation::Create {
            cred_type: CredentialType::Passkey,
        },
        CredentialRequest::GetPublicKeyCredentialRequest(_) => Operation::Get {
            cred_types: vec![CredentialType::Passkey],
        },
    };
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
    let view_request = ViewRequest {
        operation,
        signal: signal_tx,
    };
    gui_tx.send(view_request).await.unwrap();

    // wait for gui to complete
    signal_rx.await.map_err(|_| {
        zbus::Error::Failure("GUI channel closed before completing request.".to_string())
    })?;

    // finish up
    manager_client.complete_auth().await.map_err(|err| {
        tracing::error!("Error retrieving credential: {:?}", err);
        zbus::Error::Failure("Error retrieving credential".to_string())
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
    CreatePublicKeyCredentialResponse(MakeCredentialResponseInternal),
    GetPublicKeyCredentialResponse(GetAssertionResponseInternal),
}

#[derive(Clone, Debug)]
pub(crate) struct MakeCredentialResponseInternal {
    ctap: MakeCredentialResponse,
    transport: Vec<String>,
    attachment_modality: String,
}

impl MakeCredentialResponseInternal {
    pub(crate) fn new(
        response: MakeCredentialResponse,
        transport: Vec<String>,
        attachment_modality: String,
    ) -> Self {
        Self {
            ctap: response,
            transport,
            attachment_modality,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GetAssertionResponseInternal {
    ctap: Assertion,
    attachment_modality: String,
}

impl GetAssertionResponseInternal {
    pub(crate) fn new(ctap: Assertion, attachment_modality: String) -> Self {
        Self {
            ctap,
            attachment_modality,
        }
    }
}

// D-Bus <-> Client types
#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialRequest {
    pub(crate) origin: Option<String>,
    pub(crate) is_same_origin: Option<bool>,
    #[zvariant(rename = "type")]
    pub(crate) r#type: String,
    #[zvariant(rename = "publicKey")]
    pub(crate) public_key: Option<CreatePublicKeyCredentialRequest>,
}

impl CreateCredentialRequest {
    pub(crate) fn try_into_ctap2_request(
        &self,
    ) -> std::result::Result<(MakeCredentialRequest, String), webauthn::Error> {
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
            .and_then(|val| {
                serde_json::from_str::<Ctap2PublicKeyCredentialRpEntity>(&val.to_string()).ok()
            })
            .ok_or_else(|| webauthn::Error::Internal("JSON missing `rp` field".to_string()))?;
        let user = json
            .get("user")
            .ok_or(webauthn::Error::Internal(
                "JSON missing `user` field".to_string(),
            ))
            .and_then(|val| {
                serde_json::from_str::<Ctap2PublicKeyCredentialUserEntity>(&val.to_string())
                    .map_err(|e| {
                        let msg = format!("JSON missing `user` field: {e}");
                        webauthn::Error::Internal(msg)
                    })
            })?;
        let other_options =
            serde_json::from_str::<webauthn::MakeCredentialOptions>(&request_value.to_string())
                .map_err(|_| webauthn::Error::Internal("Invalid request JSON".to_string()))?;
        let (require_resident_key, user_verification) =
            if let Some(authenticator_selection) = other_options.authenticator_selection {
                let is_authenticator_storage_capable = true;
                let require_resident_key = authenticator_selection.resident_key.map_or_else(
                    || false,
                    |r| r == "required" || (r == "preferred" && is_authenticator_storage_capable),
                ); // fallback to authenticator_selection.require_resident_key == true for WebAuthn Level 1?

                let user_verification = authenticator_selection
                    .user_verification
                    .map(|uv| match uv.as_ref() {
                        "required" => UserVerificationRequirement::Required,
                        "preferred" => UserVerificationRequirement::Preferred,
                        "discouraged" => UserVerificationRequirement::Discouraged,
                        _ => todo!("This should be fixed in the future"),
                    })
                    .unwrap_or(UserVerificationRequirement::Preferred);

                (require_resident_key, user_verification)
            } else {
                (false, UserVerificationRequirement::Preferred)
            };
        let extensions = if let Some(incoming_extensions) = other_options.extensions {
            let extensions = MakeCredentialsRequestExtensions {
                cred_props: incoming_extensions.cred_props,
                cred_blob: incoming_extensions
                    .cred_blob
                    .and_then(|x| URL_SAFE_NO_PAD.decode(x).ok()),
                min_pin_length: incoming_extensions.min_pin_length,
                cred_protect: match incoming_extensions.credential_protection_policy {
                    Some(cred_prot_policy) => Some(CredentialProtectionExtension {
                        policy: cred_prot_policy,
                        enforce_policy: incoming_extensions
                            .enforce_credential_protection_policy
                            .unwrap_or_default(),
                    }),
                    None => None,
                },
                large_blob: incoming_extensions
                    .large_blob
                    .map(|x| x.support.unwrap_or_default())
                    .unwrap_or_default(),
                hmac_or_prf: if incoming_extensions.prf.is_some() {
                    // CTAP currently doesn't support PRF queries at credentials.create()
                    // So we ignore any potential value set in the request and only mark this
                    // credential to activate HMAC for future PRF queries using credentials.get()
                    MakeCredentialHmacOrPrfInput::Prf
                } else {
                    // MakeCredentialHmacOrPrfInput::Hmac is not used directly by webauthn
                    MakeCredentialHmacOrPrfInput::None
                },
            };
            Some(extensions)
        } else {
            None
        };

        let credential_parameters = request_value
            .clone()
            .get("pubKeyCredParams")
            .ok_or_else(|| {
                webauthn::Error::Internal(
                    "Request JSON missing or invalid `pubKeyCredParams` key".to_string(),
                )
            })
            .and_then(|val| -> std::result::Result<Vec<_>, webauthn::Error> {
                serde_json::from_str::<Vec<PublicKeyCredentialParameters>>(&val.to_string())
                    .map_err(|e| {
                        webauthn::Error::Internal(format!(
                            "Request JSON missing or invalid `pubKeyCredParams` key: {e}"
                        ))
                    })
            })?;
        let algorithms = credential_parameters
            .iter()
            .filter_map(|p| p.try_into().ok())
            .collect();
        let exclude = other_options.excluded_credentials.map(|v| {
            v.iter()
                .map(|e| e.try_into())
                .filter_map(|e| e.ok())
                .collect()
        });
        let (origin, is_cross_origin) = match (self.origin.as_ref(), self.is_same_origin.as_ref()) {
            (Some(origin), Some(is_same_origin)) => (origin.to_string(), !is_same_origin),
            (Some(origin), None) => (origin.to_string(), true),
            // origin should always be set on request either by client or D-Bus service,
            // so this shouldn't be called
            (None, _) => {
                return Err(webauthn::Error::Internal(
                    "Error reading origin from request".to_string(),
                ));
            }
        };
        let client_data_json = format_client_data_json(
            Operation::Create {
                cred_type: CredentialType::Passkey,
            },
            &challenge,
            &origin,
            is_cross_origin,
        );
        let client_data_hash = digest::digest(&digest::SHA256, client_data_json.as_bytes())
            .as_ref()
            .to_owned();
        Ok((
            MakeCredentialRequest {
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
            },
            client_data_json,
        ))
    }
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialRequest {
    pub(crate) request_json: String,
}

impl CreatePublicKeyCredentialResponse {
    fn try_from_ctap2_response(
        response: &MakeCredentialResponseInternal,
        client_data_json: String,
    ) -> std::result::Result<Self, fdo::Error> {
        let auth_data = &response.ctap.authenticator_data;
        let attested_credential = auth_data.attested_credential.as_ref().ok_or_else(|| {
            fdo::Error::Failed("Invalid credential received from authenticator".to_string())
        })?;

        let unsigned_extensions =
            serde_json::to_string(&response.ctap.unsigned_extensions_output).unwrap();
        let authenticator_data_blob = auth_data.to_response_bytes().unwrap();
        let attestation_statement =
            (&response.ctap.attestation_statement)
                .try_into()
                .map_err(|_| {
                    fdo::Error::Failed("Could not serialize attestation statement".to_string())
                })?;
        let attestation_object = webauthn::create_attestation_object(
            &authenticator_data_blob,
            &attestation_statement,
            response.ctap.enterprise_attestation.unwrap_or(false),
        )
        .map_err(|_| zbus::Error::Failure("Failed to create attestation object".to_string()))?;
        // do we need to check that the client_data_hash is the same?
        let registration_response_json = webauthn::CreatePublicKeyCredentialResponse::new(
            attested_credential.credential_id.clone(),
            attestation_object,
            client_data_json,
            Some(response.transport.clone()),
            unsigned_extensions,
            response.attachment_modality.clone(),
        )
        .to_json();
        let response = CreatePublicKeyCredentialResponse {
            registration_response_json,
        };
        Ok(response)
    }
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialResponse {
    #[zvariant(rename = "type")]
    r#type: String,
    public_key: Option<CreatePublicKeyCredentialResponse>,
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
    #[zvariant(rename = "publicKey")]
    public_key: Option<GetPublicKeyCredentialRequest>,
}

impl GetCredentialRequest {
    fn try_into_ctap2_request(
        &self,
    ) -> std::result::Result<(GetAssertionRequest, String), webauthn::Error> {
        if self.public_key.is_none() {
            return Err(webauthn::Error::NotSupported);
        }
        let options = self.public_key.as_ref().unwrap();
        let request: webauthn::GetCredentialOptions =
            serde_json::from_str(&options.request_json)
                .map_err(|e| webauthn::Error::Internal(format!("Invalid request JSON: {:?}", e)))?;
        let mut allow: Vec<Ctap2PublicKeyCredentialDescriptor> = request
            .allow_credentials
            .iter()
            .filter_map(|cred| {
                if cred.cred_type == "public-key" {
                    cred.try_into().ok()
                } else {
                    None
                }
            })
            .collect();
        // TODO: The allow is returning an empty list instead of either None or a list of transports.
        // This should be investigated, but this is just a UI hint and isn't necessary to pass to the authenticator.
        // Just removing it for now.
        for c in allow.iter_mut() {
            c.transports = None;
        }
        let (origin, is_cross_origin) = match (self.origin.as_ref(), self.is_same_origin.as_ref()) {
            (Some(origin), Some(is_same_origin)) => (origin.to_string(), !is_same_origin),
            (Some(origin), None) => (origin.to_string(), true),
            // origin should always be set on request either by client or D-Bus service,
            // so this shouldn't be called
            (None, _) => {
                return Err(webauthn::Error::Internal(
                    "Error reading origin from request".to_string(),
                ));
            }
        };
        let client_data_json = format_client_data_json(
            Operation::Get {
                cred_types: vec![CredentialType::Passkey],
            },
            &request.challenge,
            &origin,
            is_cross_origin,
        );
        let client_data_hash = digest::digest(&digest::SHA256, client_data_json.as_bytes())
            .as_ref()
            .to_owned();
        // TODO: actually calculate correct effective domain, and use fallback to related origin requests to fill this in. For now, just default to origin.
        let user_verification = match request
            .user_verification
            .unwrap_or_else(|| String::from("preferred"))
            .as_ref()
        {
            "required" => UserVerificationRequirement::Required,
            "preferred" => UserVerificationRequirement::Preferred,
            "discouraged" => UserVerificationRequirement::Discouraged,
            _ => {
                return Err(webauthn::Error::Internal(
                    "Invalid user verification requirement specified".to_string(),
                ))
            }
        };
        let relying_party_id = request.rp_id.unwrap_or_else(|| {
            let (_, effective_domain) = origin.rsplit_once('/').unwrap();
            effective_domain.to_string()
        });

        let extensions = if let Some(incoming_extensions) = request.extensions {
            let extensions = GetAssertionRequestExtensions {
                cred_blob: incoming_extensions.get_cred_blob,
                hmac_or_prf: incoming_extensions
                    .prf
                    .and_then(|x| {
                        x.eval.map(|eval| {
                            let eval = Some(eval.decode());
                            let mut eval_by_credential = HashMap::new();
                            if let Some(incoming_eval) = x.eval_by_credential {
                                for (key, val) in incoming_eval.iter() {
                                    eval_by_credential.insert(key.clone(), val.decode());
                                }
                            }
                            GetAssertionHmacOrPrfInput::Prf {
                                eval,
                                eval_by_credential,
                            }
                        })
                    })
                    .unwrap_or_default(),
                large_blob: incoming_extensions
                    .large_blob
                    // TODO: Implement GetAssertionLargeBlobExtension::Write, once libwebauthn supports it
                    .filter(|x| x.read == Some(true))
                    .map(|_| GetAssertionLargeBlobExtension::Read)
                    .unwrap_or(GetAssertionLargeBlobExtension::None),
            };
            Some(extensions)
        } else {
            None
        };

        Ok((
            GetAssertionRequest {
                hash: client_data_hash,
                relying_party_id,
                user_verification,
                allow,
                extensions,
                timeout: request.timeout.unwrap_or(Duration::from_secs(300)),
            },
            client_data_json,
        ))
    }
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPublicKeyCredentialRequest {
    pub(crate) request_json: String,
}

impl GetPublicKeyCredentialResponse {
    fn try_from_ctap2_response(
        response: &GetAssertionResponseInternal,
        client_data_json: String,
    ) -> std::result::Result<Self, fdo::Error> {
        let authenticator_data_blob = response
            .ctap
            .authenticator_data
            .to_response_bytes()
            .unwrap();

        // We can't just do this here, because we need encode all byte arrays for the JS-communication:
        // let unsigned_extensions = response
        //     .ctap
        //     .unsigned_extensions_output
        //     .as_ref()
        //     .map(|extensions| serde_json::to_string(&extensions).unwrap());
        let unsigned_extensions = response
            .ctap
            .unsigned_extensions_output
            .as_ref()
            .map(GetPublicKeyCredentialUnsignedExtensionsResponse::from);

        let authentication_response_json = webauthn::GetPublicKeyCredentialResponse::new(
            client_data_json,
            response
                .ctap
                .credential_id
                .as_ref()
                .map(|c| c.id.clone().into_vec()),
            authenticator_data_blob,
            response.ctap.signature.clone(),
            response.ctap.user.as_ref().map(|u| u.id.clone().into_vec()),
            response.attachment_modality.clone(),
            unsigned_extensions,
        )
        .to_json();

        let response = GetPublicKeyCredentialResponse {
            authentication_response_json,
        };
        Ok(response)
    }
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetCredentialResponse {
    #[zvariant(rename = "type")]
    r#type: String,
    public_key: Option<GetPublicKeyCredentialResponse>,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPublicKeyCredentialResponse {
    authentication_response_json: String,
}

impl From<GetPublicKeyCredentialResponse> for GetCredentialResponse {
    fn from(response: GetPublicKeyCredentialResponse) -> Self {
        GetCredentialResponse {
            // TODO: Decide on camelCase or kebab-case for cred types
            r#type: "public-key".to_string(),
            public_key: Some(response),
        }
    }
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict", rename_all = "camelCase")]
pub struct GetClientCapabilitiesResponse {
    conditional_create: bool,
    conditional_get: bool,
    hybrid_transport: bool,
    passkey_platform_authenticator: bool,
    user_verifying_platform_authenticator: bool,
    related_origins: bool,
    signal_all_accepted_credentials: bool,
    signal_current_user_details: bool,
    signal_unknown_credential: bool,
}

fn format_client_data_json(
    op: Operation,
    challenge: &str,
    origin: &str,
    is_cross_origin: bool,
) -> String {
    let op_str = match op {
        Operation::Create { .. } => "webauthn.create",
        Operation::Get { .. } => "webauthn.get",
    };
    let cross_origin_str = if is_cross_origin { "true" } else { "false" };
    format!("{{\"type\":\"{op_str}\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":{cross_origin_str}}}")
}
