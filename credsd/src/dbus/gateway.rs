//! Implements the service that public clients can connect to. Responsible for
//! authorizing clients for origins and validating request parameters.

use std::sync::Arc;

use creds_lib::{
    model::{CredentialRequest, CredentialResponse, GetClientCapabilitiesResponse, WebAuthnError},
    server::{
        CreateCredentialRequest, CreateCredentialResponse, GetCredentialRequest,
        GetCredentialResponse,
    },
};
use tokio::sync::Mutex as AsyncMutex;
use zbus::{fdo, interface};

use crate::dbus::{
    create_credential_request_try_into_ctap2, create_credential_response_try_from_ctap2,
    get_credential_request_try_into_ctap2,
};

struct CredentialGateway<C: CredentialRequestController> {
    controller: Arc<AsyncMutex<C>>,
}

/// These are public methods that can be called by arbitrary clients to begin a credential flow.
#[interface(name = "xyz.iinuwa.credentials.Credentials1")]
impl<C: CredentialRequestController + Send + Sync + 'static> CredentialGateway<C> {
    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
    ) -> fdo::Result<CreateCredentialResponse> {
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
                    create_credential_request_try_into_ctap2(&request).map_err(|e| {
                        fdo::Error::Failed(format!(
                            "Could not parse passkey creation request: {e:?}"
                        ))
                    })?;
                let cred_request =
                    CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request);

                let response = execute_flow(/* &tx, */ &self.manager_client, &cred_request).await?;

                if let CredentialResponse::CreatePublicKeyCredentialResponse(cred_response) =
                    response
                {
                    let public_key_response = create_credential_response_try_from_ctap2(
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
    }

    async fn get_credential(
        &self,
        request: GetCredentialRequest,
    ) -> fdo::Result<GetCredentialResponse> {
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
                    get_credential_request_try_into_ctap2(&request).map_err(|_| {
                        fdo::Error::Failed("Could not parse passkey assertion request.".to_owned())
                    })?;
                let cred_request =
                    CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request);

                let response = execute_flow(/* &tx, */ &self.manager_client, &cred_request).await?;

                match response {
                    CredentialResponse::GetPublicKeyCredentialResponse(cred_response) => {
                        let public_key_response = get_credential_response_try_from_ctap2(
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
    }

    async fn get_client_capabilities(&self) -> fdo::Result<GetClientCapabilitiesResponse> {
        Ok(GetClientCapabilitiesResponse {
            conditional_create: false,
            conditional_get: false,
            hybrid_transport: true,
            passkey_platform_authenticator: false,
            user_verifying_platform_authenticator: false,
            related_origins: false,
            signal_all_accepted_credentials: false,
            signal_current_user_details: false,
            signal_unknown_credential: false,
        })
    }
}

trait CredentialRequestController {
    async fn request_credential(
        request: CredentialRequest,
    ) -> Result<CredentialResponse, WebAuthnError>;
}
