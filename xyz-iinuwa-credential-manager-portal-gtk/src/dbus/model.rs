//! This module contains types used for serializing data to and from D-Bus method calls.
//!
//! Types shared between components within this service belong in crate::model.

use std::{collections::HashMap, time::Duration};

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use zbus::{
    fdo,
    zvariant::{self, DeserializeDict, OwnedValue, SerializeDict, Type, Value, LE},
};

use crate::model::{
    CredentialType, GetAssertionResponseInternal, MakeCredentialResponseInternal, Operation,
    ViewUpdate,
};
use crate::webauthn::{
    self, CredentialProtectionExtension, Ctap2PublicKeyCredentialDescriptor,
    Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity,
    GetAssertionHmacOrPrfInput, GetAssertionLargeBlobExtension, GetAssertionRequest,
    GetAssertionRequestExtensions, GetPublicKeyCredentialUnsignedExtensionsResponse,
    MakeCredentialHmacOrPrfInput, MakeCredentialRequest, MakeCredentialsRequestExtensions,
    PublicKeyCredentialParameters, ResidentKeyRequirement, UserVerificationRequirement,
};

// D-Bus <-> Client types
#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub(super) enum BackgroundEvent {
    UsbStateChanged(OwnedValue),
    HybridStateChanged(OwnedValue),
}

impl TryFrom<BackgroundEvent> for crate::model::BackgroundEvent {
    type Error = zvariant::Error;

    fn try_from(value: BackgroundEvent) -> Result<Self, Self::Error> {
        let ret = match value {
            BackgroundEvent::HybridStateChanged(hybrid_state_val) => {
                HybridState::try_from(Value::<'_>::from(hybrid_state_val))
                    .and_then(crate::model::HybridState::try_from)
                    .map(crate::model::BackgroundEvent::HybridQrStateChanged)
            }
            BackgroundEvent::UsbStateChanged(usb_state_val) => {
                UsbState::try_from(Value::<'_>::from(usb_state_val))
                    .and_then(crate::model::UsbState::try_from)
                    .map(crate::model::BackgroundEvent::UsbStateChanged)
            }
        }?;
        Ok(ret)
    }
}

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
        let (resident_key, user_verification) =
            if let Some(authenticator_selection) = other_options.authenticator_selection {
                let resident_key = match authenticator_selection.resident_key.as_deref() {
                    Some("required") => Some(ResidentKeyRequirement::Required),
                    Some("preferred") => Some(ResidentKeyRequirement::Preferred),
                    Some("discouraged") => Some(ResidentKeyRequirement::Discouraged),
                    Some(_) => None,
                    // legacy webauthn-1 member
                    None if authenticator_selection.require_resident_key == Some(true) => {
                        Some(ResidentKeyRequirement::Required)
                    }
                    None => None,
                };

                let user_verification = authenticator_selection
                    .user_verification
                    .map(|uv| match uv.as_ref() {
                        "required" => UserVerificationRequirement::Required,
                        "preferred" => UserVerificationRequirement::Preferred,
                        "discouraged" => UserVerificationRequirement::Discouraged,
                        _ => todo!("This should be fixed in the future"),
                    })
                    .unwrap_or(UserVerificationRequirement::Preferred);

                (resident_key, user_verification)
            } else {
                (None, UserVerificationRequirement::Preferred)
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
        let client_data_json = webauthn::format_client_data_json(
            Operation::Create {
                cred_type: CredentialType::Passkey,
            },
            &challenge,
            &origin,
            is_cross_origin,
        );
        let client_data_hash = webauthn::create_client_data_hash(&client_data_json);
        Ok((
            MakeCredentialRequest {
                hash: client_data_hash,
                origin,

                relying_party: rp,
                user,
                resident_key,
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

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialResponse {
    #[zvariant(rename = "type")]
    r#type: String,
    public_key: Option<CreatePublicKeyCredentialResponse>,
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialRequest {
    pub(crate) request_json: String,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialResponse {
    registration_response_json: String,
}

impl CreatePublicKeyCredentialResponse {
    pub(super) fn try_from_ctap2_response(
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
    pub(super) origin: Option<String>,
    pub(super) is_same_origin: Option<bool>,
    #[zvariant(rename = "type")]
    pub(super) r#type: String,
    #[zvariant(rename = "publicKey")]
    pub(super) public_key: Option<GetPublicKeyCredentialRequest>,
}

impl GetCredentialRequest {
    pub(super) fn try_into_ctap2_request(
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
        let client_data_json = webauthn::format_client_data_json(
            Operation::Get {
                cred_types: vec![CredentialType::Passkey],
            },
            &request.challenge,
            &origin,
            is_cross_origin,
        );
        let client_data_hash = webauthn::create_client_data_hash(&client_data_json);
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

impl GetPublicKeyCredentialResponse {
    pub(super) fn try_from_ctap2_response(
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

impl From<GetPublicKeyCredentialResponse> for GetCredentialResponse {
    fn from(response: GetPublicKeyCredentialResponse) -> Self {
        GetCredentialResponse {
            // TODO: Decide on camelCase or kebab-case for cred types
            r#type: "public-key".to_string(),
            public_key: Some(response),
        }
    }
}

/// Updates to send to the client
#[derive(Serialize, Deserialize, Type)]
pub enum ClientUpdate {
    SetTitle(OwnedValue),
    SetDevices(OwnedValue),
    SetCredentials(OwnedValue),

    WaitingForDevice(OwnedValue),
    SelectingDevice(OwnedValue),

    UsbNeedsPin(OwnedValue),
    UsbNeedsUserVerification(OwnedValue),
    UsbNeedsUserPresence(OwnedValue),

    HybridNeedsQrCode(OwnedValue),
    HybridConnecting(OwnedValue),
    HybridConnected(OwnedValue),

    Completed(OwnedValue),
    Failed(OwnedValue),
}

impl TryFrom<ClientUpdate> for ViewUpdate {
    type Error = zbus::zvariant::Error;
    fn try_from(value: ClientUpdate) -> std::result::Result<ViewUpdate, Self::Error> {
        match value {
            ClientUpdate::SetTitle(v) => v.try_into().map(Self::SetTitle),
            ClientUpdate::SetDevices(v) => {
                let dbus_devices: Vec<Device> = Value::<'_>::from(v).try_into()?;
                let devices: std::result::Result<Vec<crate::model::Device>, zbus::zvariant::Error> =
                    dbus_devices
                        .into_iter()
                        .map(|d| {
                            d.try_into().map_err(|_| {
                                zbus::zvariant::Error::Message(
                                    "Could not deserialize devices".to_string(),
                                )
                            })
                        })
                        .collect();
                Ok(Self::SetDevices(devices?))
            }
            ClientUpdate::SetCredentials(v) => {
                let dbus_credentials: Vec<Credential> = Value::<'_>::from(v).try_into()?;
                let credentials: std::result::Result<
                    Vec<crate::model::Credential>,
                    zbus::zvariant::Error,
                > = dbus_credentials
                    .into_iter()
                    .map(|creds| Ok(creds.into()))
                    .collect();
                Ok(Self::SetCredentials(credentials?))
            }

            ClientUpdate::WaitingForDevice(v) => {
                let dbus_device: Device = Value::<'_>::from(v).try_into()?;
                let device: crate::model::Device = dbus_device.try_into().map_err(|_| {
                    zbus::zvariant::Error::Message("Could not deserialize device".to_string())
                })?;
                Ok(Self::WaitingForDevice(device))
            }
            ClientUpdate::SelectingDevice(_) => Ok(Self::SelectingDevice),

            ClientUpdate::UsbNeedsPin(v) => v.try_into().map(|x: i32| {
                let attempts_left = if x == -1 { None } else { Some(x as u32) };
                Self::UsbNeedsPin { attempts_left }
            }),
            ClientUpdate::UsbNeedsUserVerification(v) => v.try_into().map(|x: i32| {
                let attempts_left = if x == -1 { None } else { Some(x as u32) };
                Self::UsbNeedsUserVerification { attempts_left }
            }),
            ClientUpdate::UsbNeedsUserPresence(_) => Ok(Self::UsbNeedsUserPresence),

            ClientUpdate::HybridNeedsQrCode(v) => v.try_into().map(Self::HybridNeedsQrCode),
            ClientUpdate::HybridConnecting(_) => Ok(Self::HybridConnecting),
            ClientUpdate::HybridConnected(_) => Ok(Self::HybridConnected),

            ClientUpdate::Completed(_) => Ok(Self::Completed),
            ClientUpdate::Failed(v) => v.try_into().map(Self::Failed),
        }
    }
}

#[derive(SerializeDict, DeserializeDict, Type)]
pub(super) struct Credential {
    id: String,
    name: String,
    username: String,
}

impl From<Credential> for crate::model::Credential {
    fn from(value: Credential) -> Self {
        Self {
            id: value.id,
            name: value.name,
            username: if value.username.is_empty() {
                None
            } else {
                Some(value.username)
            },
        }
    }
}

impl TryFrom<Value<'_>> for Credential {
    type Error = zbus::zvariant::Error;
    fn try_from(value: Value<'_>) -> std::result::Result<Self, Self::Error> {
        let ctx = zbus::zvariant::serialized::Context::new_dbus(LE, 0);
        let encoded = zbus::zvariant::to_bytes(ctx, &value)?;
        let credential: Credential = encoded.deserialize()?.0;
        Ok(credential)
    }
}

#[derive(SerializeDict, DeserializeDict, Type)]
pub(super) struct Device {
    id: String,
    transport: String,
}

impl TryFrom<Value<'_>> for Device {
    type Error = zbus::zvariant::Error;
    fn try_from(value: Value<'_>) -> std::result::Result<Self, Self::Error> {
        let ctx = zbus::zvariant::serialized::Context::new_dbus(LE, 0);
        let encoded = zbus::zvariant::to_bytes(ctx, &value)?;
        let device: Device = encoded.deserialize()?.0;
        Ok(device)
    }
}

impl TryFrom<Device> for crate::model::Device {
    type Error = ();
    fn try_from(value: Device) -> std::result::Result<Self, Self::Error> {
        let transport = value.transport.try_into().map_err(|_| ())?;
        Ok(Self {
            id: value.id,
            transport,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub(super) enum HybridState {
    /// Default state, not listening for hybrid transport.
    Idle(OwnedValue),

    /// QR code flow is starting, awaiting QR code scan and BLE advert from phone.
    Started(OwnedValue),

    /// BLE advert received, connecting to caBLE tunnel with shared secret.
    Connecting(OwnedValue),

    /// Connected to device via caBLE tunnel.
    Connected(OwnedValue),

    /// Credential received over tunnel.
    Completed(OwnedValue),

    // This isn't actually sent from the server.
    UserCancelled(OwnedValue),

    /// Failed to receive a credential
    Failed(OwnedValue),
}

impl TryFrom<HybridState> for crate::model::HybridState {
    type Error = zbus::zvariant::Error;
    fn try_from(value: HybridState) -> std::result::Result<Self, Self::Error> {
        match value {
            HybridState::Idle(_) => Ok(Self::Idle),
            HybridState::Started(value) => value.try_into().map(Self::Started),
            HybridState::Connecting(_) => Ok(Self::Connecting),
            HybridState::Connected(_) => Ok(Self::Connected),
            HybridState::Completed(_) => Ok(Self::Completed),
            HybridState::UserCancelled(_) => Ok(Self::UserCancelled),
            HybridState::Failed(_) => Ok(Self::Failed),
        }
    }
}

impl TryFrom<Value<'_>> for HybridState {
    type Error = zbus::zvariant::Error;
    fn try_from(value: Value<'_>) -> std::result::Result<Self, Self::Error> {
        let ctx = zbus::zvariant::serialized::Context::new_dbus(LE, 0);
        let encoded = zbus::zvariant::to_bytes(ctx, &value)?;
        let obj: Self = encoded.deserialize()?.0;
        Ok(obj)
    }
}

#[derive(Serialize, Deserialize, Type)]
pub(super) enum ServiceError {
    /// Some unknown error with the authenticator occurred.
    AuthenticatorError,

    /// No matching credentials were found on the device.
    NoCredentials,

    /// Too many incorrect PIN attempts, and authenticator must be removed and
    /// reinserted to continue any more PIN attempts.
    ///
    /// Note that this is different than exhausting the PIN count that fully
    /// locks out the device.
    PinAttemptsExhausted,

    // TODO: We may want to hide the details on this variant from the public API.
    /// Something went wrong with the credential service itself, not the authenticator.
    Internal,
}

impl TryFrom<Value<'_>> for ServiceError {
    type Error = zbus::zvariant::Error;
    fn try_from(value: Value<'_>) -> std::result::Result<Self, Self::Error> {
        let ctx = zbus::zvariant::serialized::Context::new_dbus(LE, 0);
        let encoded = zbus::zvariant::to_bytes(ctx, &value)?;
        let obj: Self = encoded.deserialize()?.0;
        Ok(obj)
    }
}

impl From<ServiceError> for crate::model::Error {
    fn from(value: ServiceError) -> Self {
        match value {
            ServiceError::AuthenticatorError => Self::AuthenticatorError,
            ServiceError::NoCredentials => Self::NoCredentials,
            ServiceError::PinAttemptsExhausted => Self::PinAttemptsExhausted,
            // TODO: this is bogus, we should refactor to remove the tuple field
            // and let the client decide how to render the error.
            ServiceError::Internal => {
                Self::Internal("Something went wrong. Please try again later.".to_string())
            }
        }
    }
}

/// Used to de-/serialize state D-Bus and model::UsbState.
#[derive(Serialize, Deserialize, Type)]
pub(super) enum UsbState {
    Idle(OwnedValue),
    Waiting(OwnedValue),
    SelectingDevice(OwnedValue),
    Connected(OwnedValue),
    NeedsPin(OwnedValue), /* {
                              attempts_left: Option<u32>,
                          },
                          */
    NeedsUserVerification(OwnedValue), /* {
                                           attempts_left: Option<u32>,
                                       },*/

    NeedsUserPresence(OwnedValue),
    //UserCancelled,
    SelectCredential(OwnedValue), /* {
                                      creds: Vec<Credential>,
                                  },*/
    Completed(OwnedValue),
    // Failed(crate::credential_service::Error),
    Failed(OwnedValue),
}

impl TryFrom<UsbState> for crate::model::UsbState {
    type Error = zbus::zvariant::Error;
    fn try_from(value: UsbState) -> std::result::Result<Self, Self::Error> {
        let ret = match value {
            UsbState::Idle(_) => Ok(Self::Idle),
            UsbState::Waiting(_) => Ok(Self::Waiting),
            UsbState::SelectingDevice(_) => Ok(Self::SelectingDevice),
            UsbState::Connected(_) => Ok(Self::Connected),
            UsbState::NeedsPin(value) => value.try_into().map(|attempts_left: i32| {
                let attempts_left = if attempts_left < 0 {
                    None
                } else {
                    Some(u32::try_from(attempts_left).unwrap())
                };
                Self::NeedsPin { attempts_left }
            }),
            UsbState::NeedsUserVerification(value) => value.try_into().map(|attempts_left: i32| {
                let attempts_left = if attempts_left < 0 {
                    None
                } else {
                    Some(u32::try_from(attempts_left).unwrap())
                };
                Self::NeedsUserVerification { attempts_left }
            }),
            UsbState::NeedsUserPresence(_) => Ok(Self::NeedsUserPresence),
            UsbState::SelectCredential(value) => value
                .try_into()
                .map(|creds: Vec<Credential>| {
                    creds
                        .into_iter()
                        .map(crate::model::Credential::from)
                        .collect()
                })
                .map(|creds| Self::SelectCredential { creds }),
            UsbState::Completed(_) => Ok(Self::Completed),
            UsbState::Failed(value) => {
                ServiceError::try_from(Value::<'_>::from(value)).map(|err| Self::Failed(err.into()))
            }
        }?;
        Ok(ret)
    }
}

impl TryFrom<Value<'_>> for UsbState {
    type Error = zbus::zvariant::Error;
    fn try_from(value: Value<'_>) -> std::result::Result<Self, Self::Error> {
        let ctx = zbus::zvariant::serialized::Context::new_dbus(LE, 0);
        let encoded = zbus::zvariant::to_bytes(ctx, &value)?;
        let obj: Self = encoded.deserialize()?.0;
        Ok(obj)
    }
}
