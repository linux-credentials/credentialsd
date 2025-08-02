use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zbus::{
    fdo,
    object_server::SignalEmitter,
    proxy,
    zvariant::{self, DeserializeDict, LE, Optional, OwnedValue, SerializeDict, Type, Value},
};

use crate::model::{Operation, ViewUpdate};

#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub enum BackgroundEvent {
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

impl TryFrom<crate::model::BackgroundEvent> for BackgroundEvent {
    type Error = zvariant::Error;
    fn try_from(value: crate::model::BackgroundEvent) -> Result<Self, Self::Error> {
        let event = match value {
            crate::model::BackgroundEvent::HybridQrStateChanged(state) => {
                let state: HybridState = state.into();
                let value = Value::new(state)
                    .try_to_owned()
                    .expect("non-file descriptor value to succeed");
                BackgroundEvent::HybridStateChanged(value)
            }
            crate::model::BackgroundEvent::UsbStateChanged(state) => {
                let state: UsbState = state.into();
                let value = Value::new(state)
                    .try_to_owned()
                    .expect("non-file descriptor value to succeed");

                BackgroundEvent::UsbStateChanged(value)
            }
        };
        Ok(event)
    }
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreateCredentialRequest {
    pub origin: Option<String>,
    pub is_same_origin: Option<bool>,
    #[zvariant(rename = "type")]
    pub r#type: String,
    #[zvariant(rename = "publicKey")]
    pub public_key: Option<CreatePublicKeyCredentialRequest>,
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
    pub request_json: String,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct CreatePublicKeyCredentialResponse {
    pub registration_response_json: String,
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
    type Error = zvariant::Error;
    fn try_from(value: ClientUpdate) -> std::result::Result<ViewUpdate, Self::Error> {
        match value {
            ClientUpdate::SetTitle(v) => v.try_into().map(Self::SetTitle),
            ClientUpdate::SetDevices(v) => {
                let dbus_devices: Vec<Device> = Value::<'_>::from(v).try_into()?;
                let devices: std::result::Result<Vec<crate::model::Device>, zvariant::Error> =
                    dbus_devices
                        .into_iter()
                        .map(|d| {
                            d.try_into().map_err(|_| {
                                zvariant::Error::Message(
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
                    zvariant::Error,
                > = dbus_credentials
                    .into_iter()
                    .map(|creds| Ok(creds.into()))
                    .collect();
                Ok(Self::SetCredentials(credentials?))
            }

            ClientUpdate::WaitingForDevice(v) => {
                let dbus_device: Device = Value::<'_>::from(v).try_into()?;
                let device: crate::model::Device = dbus_device.try_into().map_err(|_| {
                    zvariant::Error::Message("Could not deserialize device".to_string())
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

#[derive(SerializeDict, DeserializeDict, Type, Value)]
#[zvariant(signature = "dict")]
pub struct Credential {
    id: String,
    name: String,
    username: Optional<String>,
}

impl From<Credential> for crate::model::Credential {
    fn from(value: Credential) -> Self {
        Self {
            id: value.id,
            name: value.name,
            username: value.username.into(),
        }
    }
}

impl From<crate::model::Credential> for Credential {
    fn from(value: crate::model::Credential) -> Self {
        Self {
            id: value.id,
            name: value.name,
            username: value.username.into(),
        }
    }
}

/*
impl TryFrom<Value<'_>> for Credential {
    type Error = zvariant::Error;
    fn try_from(value: Value<'_>) -> std::result::Result<Self, Self::Error> {
        let ctx = zvariant::serialized::Context::new_dbus(LE, 0);
        let encoded = zvariant::to_bytes(ctx, &value)?;
        let credential: Credential = encoded.deserialize()?.0;
        Ok(credential)
    }
}
    */

#[derive(SerializeDict, DeserializeDict, Type)]
pub struct Device {
    id: String,
    transport: String,
}

impl TryFrom<Value<'_>> for Device {
    type Error = zvariant::Error;
    fn try_from(value: Value<'_>) -> std::result::Result<Self, Self::Error> {
        let ctx = zvariant::serialized::Context::new_dbus(LE, 0);
        let encoded = zvariant::to_bytes(ctx, &value)?;
        let device: Device = encoded.deserialize()?.0;
        Ok(device)
    }
}

impl From<crate::model::Device> for Device {
    fn from(value: crate::model::Device) -> Self {
        Device {
            id: value.id,
            transport: value.transport.as_str().to_owned(),
        }
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

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetCredentialRequest {
    pub origin: Option<String>,
    pub is_same_origin: Option<bool>,
    #[zvariant(rename = "type")]
    pub r#type: String,
    #[zvariant(rename = "publicKey")]
    pub public_key: Option<GetPublicKeyCredentialRequest>,
}

#[derive(Clone, Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct GetPublicKeyCredentialRequest {
    pub request_json: String,
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
    pub authentication_response_json: String,
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

#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub enum HybridState {
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

impl From<crate::model::HybridState> for HybridState {
    fn from(value: crate::model::HybridState) -> Self {
        match value {
            crate::model::HybridState::Idle => HybridState::Idle(OwnedValue::from(false)),
            crate::model::HybridState::Started(qr_code) => {
                HybridState::Idle(value_to_owned(Value::from(qr_code)))
            }
            crate::model::HybridState::Connecting => HybridState::Idle(OwnedValue::from(false)),
            crate::model::HybridState::Connected => HybridState::Idle(OwnedValue::from(false)),
            crate::model::HybridState::Completed => HybridState::Idle(OwnedValue::from(false)),
            crate::model::HybridState::UserCancelled => HybridState::Idle(OwnedValue::from(false)),
            crate::model::HybridState::Failed => HybridState::Idle(OwnedValue::from(false)),
        }
    }
}
impl TryFrom<HybridState> for crate::model::HybridState {
    type Error = zvariant::Error;
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
    type Error = zvariant::Error;
    fn try_from(value: Value<'_>) -> std::result::Result<Self, Self::Error> {
        let ctx = zvariant::serialized::Context::new_dbus(LE, 0);
        let encoded = zvariant::to_bytes(ctx, &value)?;
        let obj: Self = encoded.deserialize()?.0;
        Ok(obj)
    }
}

impl From<HybridState> for Value<'_> {
    fn from(value: HybridState) -> Self {
        let mut fields = HashMap::new();
        match value {
            HybridState::Idle(owned_value) => {
                fields.insert("type", value_to_owned(Value::from("IDLE")));
                fields.insert("value", owned_value);
            }
            HybridState::Started(owned_value) => {
                fields.insert("type", value_to_owned(Value::from("STARTED")));
                fields.insert("value", owned_value);
            }
            HybridState::Connecting(owned_value) => {
                fields.insert("type", value_to_owned(Value::from("CONNECTING")));
                fields.insert("value", owned_value);
            }
            HybridState::Connected(owned_value) => {
                fields.insert("type", value_to_owned(Value::from("CONNECTED")));
                fields.insert("value", owned_value);
            }
            HybridState::Completed(owned_value) => {
                fields.insert("type", value_to_owned(Value::from("COMPLETED")));
                fields.insert("value", owned_value);
            }
            HybridState::UserCancelled(owned_value) => {
                fields.insert("type", value_to_owned(Value::from("USER_CANCELLED")));
                fields.insert("value", owned_value);
            }
            HybridState::Failed(owned_value) => {
                fields.insert("type", value_to_owned(Value::from("FAILED")));
                fields.insert("value", owned_value);
            }
        }
        Value::from(fields)
    }
}

#[derive(Serialize, Deserialize, Type)]
pub enum ServiceError {
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
    type Error = zvariant::Error;
    fn try_from(value: Value<'_>) -> std::result::Result<Self, Self::Error> {
        let ctx = zvariant::serialized::Context::new_dbus(LE, 0);
        let encoded = zvariant::to_bytes(ctx, &value)?;
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
pub enum UsbState {
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
    type Error = zvariant::Error;
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

impl From<crate::model::UsbState> for UsbState {
    fn from(value: crate::model::UsbState) -> Self {
        match value {
            crate::model::UsbState::Idle => UsbState::Idle(OwnedValue::from(false)),
            crate::model::UsbState::Waiting => UsbState::Waiting(OwnedValue::from(false)),
            crate::model::UsbState::SelectingDevice => {
                UsbState::SelectingDevice(OwnedValue::from(false))
            }
            crate::model::UsbState::Connected => UsbState::Connected(OwnedValue::from(false)),
            crate::model::UsbState::NeedsPin { attempts_left } => {
                let num = match attempts_left {
                    Some(num) => num as i32,
                    None => -1,
                };
                UsbState::NeedsPin(OwnedValue::from(num))
            }
            crate::model::UsbState::NeedsUserVerification { attempts_left } => {
                let num = match attempts_left {
                    Some(num) => num as i32,
                    None => -1,
                };
                UsbState::NeedsPin(OwnedValue::from(num))
            }
            crate::model::UsbState::NeedsUserPresence => {
                UsbState::NeedsUserPresence(OwnedValue::from(false))
            }
            crate::model::UsbState::SelectCredential { creds } => {
                let creds: Vec<Credential> = creds.into_iter().map(Credential::from).collect();
                let value = Value::new(creds)
                    .try_to_owned()
                    .expect("All non-file descriptors to convert to OwnedValue successfully");
                UsbState::SelectCredential(value)
            }
            crate::model::UsbState::Completed => UsbState::Completed(OwnedValue::from(false)),
            crate::model::UsbState::Failed(error) => UsbState::Failed(
                Value::<'_>::from(error.to_string())
                    .try_to_owned()
                    .expect("non-file descriptor value to convert"),
            ),
        }
    }
}

impl TryFrom<Value<'_>> for UsbState {
    type Error = zvariant::Error;
    fn try_from(value: Value<'_>) -> std::result::Result<Self, Self::Error> {
        let ctx = zvariant::serialized::Context::new_dbus(LE, 0);
        let encoded = zvariant::to_bytes(ctx, &value)?;
        let obj: Self = encoded.deserialize()?.0;
        Ok(obj)
    }
}

impl From<UsbState> for Value<'_> {
    fn from(value: UsbState) -> Self {
        let mut fields = HashMap::new();
        match value {
            UsbState::Idle(owned_value) => {
                fields.insert(
                    "type",
                    Value::from("IDLE")
                        .try_to_owned()
                        .expect("non-file descriptor fields to succeed"),
                );
                fields.insert("value", owned_value);
            }
            UsbState::Waiting(owned_value) => {
                fields.insert(
                    "type",
                    Value::from("WAITING")
                        .try_to_owned()
                        .expect("non-file descriptor fields to succeed"),
                );
                fields.insert("value", owned_value);
            }
            UsbState::SelectingDevice(owned_value) => {
                fields.insert(
                    "type",
                    Value::from("SELECTING_DEVICE")
                        .try_to_owned()
                        .expect("non-file descriptor fields to succeed"),
                );
                fields.insert("value", owned_value);
            }
            UsbState::Connected(owned_value) => {
                fields.insert(
                    "type",
                    Value::from("CONNECTED")
                        .try_to_owned()
                        .expect("non-file descriptor fields to succeed"),
                );
                fields.insert("value", owned_value);
            }
            UsbState::NeedsPin(owned_value) => {
                fields.insert(
                    "type",
                    Value::from("NEEDS_PIN")
                        .try_to_owned()
                        .expect("non-file descriptor fields to succeed"),
                );
                fields.insert("value", owned_value);
            }
            UsbState::NeedsUserVerification(owned_value) => {
                fields.insert(
                    "type",
                    Value::from("NEEDS_USER_VERIFICATION")
                        .try_to_owned()
                        .expect("non-file descriptor fields to succeed"),
                );
                fields.insert("value", owned_value);
            }
            UsbState::NeedsUserPresence(owned_value) => {
                fields.insert(
                    "type",
                    Value::from("NEEDS_USER_PRESENCE")
                        .try_to_owned()
                        .expect("non-file descriptor fields to succeed"),
                );
                fields.insert("value", owned_value);
            }
            UsbState::SelectCredential(owned_value) => {
                fields.insert(
                    "type",
                    Value::from("SELECT_CREDENTIAL")
                        .try_to_owned()
                        .expect("non-file descriptor fields to succeed"),
                );
                fields.insert("value", owned_value);
            }
            UsbState::Completed(owned_value) => {
                fields.insert(
                    "type",
                    Value::from("COMPLETED")
                        .try_to_owned()
                        .expect("non-file descriptor fields to succeed"),
                );
                fields.insert("value", owned_value);
            }
            UsbState::Failed(owned_value) => {
                fields.insert(
                    "type",
                    Value::from("FAILED")
                        .try_to_owned()
                        .expect("non-file descriptor fields to succeed"),
                );
                fields.insert("value", owned_value);
            }
        };
        Value::from(fields)
    }
}

#[derive(Serialize, Deserialize, Type)]
pub struct ViewRequest {
    pub operation: Operation,
}

fn value_to_owned(value: Value<'_>) -> OwnedValue {
    value
        .try_to_owned()
        .expect("non-file descriptor values to succeed")
}
