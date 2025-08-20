//! Types for serializing across D-Bus instances

use std::collections::HashMap;

use serde::{
    Deserialize, Serialize,
    de::{DeserializeSeed, Error, SeqAccess, Visitor},
    ser::{Error as _, SerializeTuple},
};
use zvariant::{
    self, DeserializeDict, DynamicDeserialize, LE, Optional, OwnedValue, SerializeDict, Signature,
    Structure, StructureBuilder, Type, Value, signature::Fields,
};

use crate::model::Operation;

#[derive(Clone, Debug)]

pub enum BackgroundEvent {
    UsbStateChanged(UsbState),
    HybridStateChanged(crate::model::HybridState),
}

const TAG_VALUE_SIGNATURE: &'static Signature = &Signature::Structure(Fields::Static {
    fields: &[&Signature::U8, &Signature::Variant],
});

impl Type for BackgroundEvent {
    const SIGNATURE: &'static Signature = TAG_VALUE_SIGNATURE;
}

impl Serialize for BackgroundEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut tuple = serializer.serialize_tuple(3)?;
        match self {
            Self::UsbStateChanged(state) => {
                tuple.serialize_element(&0x01_u8)?;
                tuple.serialize_element(state)?;
            }
            Self::HybridStateChanged(state) => {
                tuple.serialize_element(&0x02_u8)?;
                let structure: Structure<'_> = state.try_into().map_err(|err| {
                    S::Error::custom(format!(
                        "could not convert HybridState to a structure: {err}"
                    ))
                })?;
                tuple.serialize_element(&Value::Structure(structure))?;
            }
        };
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for BackgroundEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TupleVisitor;
        impl<'de> Visitor<'de> for TupleVisitor {
            type Value = BackgroundEvent;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("enum BackgroundEvent")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<BackgroundEvent, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let tag = seq
                    .next_element::<u8>()?
                    .ok_or_else(|| V::Error::custom("missing tag"))?;
                match tag {
                    0x01 => {
                        let value = seq
                            .next_element::<OwnedValue>()?
                            .ok_or_else(|| V::Error::custom("enum value not found"))?;
                        Ok(BackgroundEvent::UsbStateChanged(
                            Value::<'_>::from(value).try_into().map_err(|err| {
                                V::Error::custom(format!("could not deserialize UsbState: {err}"))
                            })?,
                        ))
                    }
                    0x02 => Ok(BackgroundEvent::HybridStateChanged(
                        seq.next_element::<crate::model::HybridState>()?
                            .ok_or_else(|| V::Error::custom("could not deserialize HybridState"))?,
                    )),
                    _ => Err(V::Error::custom(format!(
                        "Unknown BackgroundEvent tag: {tag}"
                    ))),
                }
            }
        }

        deserializer.deserialize_tuple(2, TupleVisitor)
    }
}

impl TryFrom<BackgroundEvent> for crate::model::BackgroundEvent {
    type Error = zvariant::Error;

    fn try_from(value: BackgroundEvent) -> Result<Self, Self::Error> {
        let ret = match value {
            BackgroundEvent::HybridStateChanged(hybrid_state_val) => Ok(
                crate::model::BackgroundEvent::HybridQrStateChanged(hybrid_state_val),
            ),
            BackgroundEvent::UsbStateChanged(usb_state_val) => {
                UsbState::try_from(Value::<'_>::from(usb_state_val))
                    .and_then(crate::model::UsbState::try_from)
                    .map(crate::model::BackgroundEvent::UsbStateChanged)
            }
        }?;
        Ok(ret)
    }
}

impl From<crate::model::BackgroundEvent> for BackgroundEvent {
    fn from(value: crate::model::BackgroundEvent) -> Self {
        match value {
            crate::model::BackgroundEvent::HybridQrStateChanged(state) => {
                BackgroundEvent::HybridStateChanged(state.into())
            }
            crate::model::BackgroundEvent::UsbStateChanged(state) => {
                BackgroundEvent::UsbStateChanged(state.into())
                /*
                let state: UsbState = state.into();
                let value = Value::new(state)
                    .try_to_owned()
                    .expect("non-file descriptor value to succeed");
                */
            }
        }
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

#[derive(SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "a{sv}")]
pub struct Device {
    pub id: String,
    pub transport: String,
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

#[derive(Clone, Debug, Deserialize, Type)]
#[zvariant(signature = "(yv)")]
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
                HybridState::Started(value_to_owned(&Value::from(qr_code)))
            }
            crate::model::HybridState::Connecting => {
                HybridState::Connecting(OwnedValue::from(false))
            }
            crate::model::HybridState::Connected => HybridState::Connected(OwnedValue::from(false)),
            crate::model::HybridState::Completed => HybridState::Completed(OwnedValue::from(false)),
            crate::model::HybridState::UserCancelled => {
                HybridState::UserCancelled(OwnedValue::from(false))
            }
            crate::model::HybridState::Failed => HybridState::Failed(OwnedValue::from(false)),
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
        if &value.value_signature() != &TAG_VALUE_SIGNATURE {
            return Err(zvariant::Error::SignatureMismatch(
                value.value_signature().clone(),
                format!("expected {TAG_VALUE_SIGNATURE}"),
            ));
        }
        if let Value::Structure(structure) = value {
            let fields = structure.into_fields();
            let tag: u8 = fields[0].downcast_ref()?;
            let value = &fields[1];
            return match tag {
                0x01 => Ok(Self::Idle(value_to_owned(value))),
                0x02 => Ok(Self::Started(value_to_owned(value))),
                0x03 => Ok(Self::Connecting(value_to_owned(value))),
                0x04 => Ok(Self::Connected(value_to_owned(value))),
                0x05 => Ok(Self::Completed(value_to_owned(value))),
                0x06 => Ok(Self::UserCancelled(value_to_owned(value))),
                0x07 => Ok(Self::Failed(value_to_owned(value))),
                _ => Err(zvariant::Error::Message(format!(
                    "Invalid HybridState type passed: {tag}"
                ))),
            };
        } else {
            return Err(zvariant::Error::IncorrectType);
        }
    }
}

impl From<HybridState> for Value<'_> {
    fn from(state: HybridState) -> Self {
        let (tag, value) = match state {
            HybridState::Idle(v) => (0x01_u8, v),
            HybridState::Started(v) => (0x02, v),
            HybridState::Connecting(v) => (0x03, v),
            HybridState::Connected(v) => (0x04, v),
            HybridState::Completed(v) => (0x05, v),
            HybridState::UserCancelled(v) => (0x06, v),
            HybridState::Failed(v) => (0x07, v),
        };
        let builder = StructureBuilder::new()
            .add_field(tag)
            .add_field(value)
            .build();
        Value::from(builder.unwrap())
    }
}

impl Serialize for crate::model::HybridState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let structure: Structure = self.try_into().map_err(|err| {
            S::Error::custom(format!(
                "failed to read HybridState as D-Bus structure: {err}"
            ))
        })?;
        structure.serialize(serializer)
    }
}

impl From<&crate::model::HybridState> for Structure<'_> {
    fn from(value: &crate::model::HybridState) -> Self {
        let (tag, value) = match value {
            crate::model::HybridState::Idle => (&0x01_u8, None),
            crate::model::HybridState::Started(value) => (&0x02_u8, Some(Value::Str(value.into()))),
            crate::model::HybridState::Connecting => (&0x03_u8, None),
            crate::model::HybridState::Connected => (&0x04_u8, None),
            crate::model::HybridState::Completed => (&0x05_u8, None),
            crate::model::HybridState::UserCancelled => (&0x06_u8, None),
            crate::model::HybridState::Failed => (&0x07_u8, None),
        };
        StructureBuilder::new()
            .add_field(*tag)
            .append_field(
                value
                    .unwrap_or_else(|| Value::new(Value::U8(0)))
                    .try_to_owned()
                    .unwrap()
                    .into(),
            )
            .build()
            .expect("create a struct")
    }
}

impl TryFrom<&Structure<'_>> for crate::model::HybridState {
    type Error = zvariant::Error;

    fn try_from(structure: &Structure<'_>) -> Result<Self, Self::Error> {
        let fields = structure.fields();
        let tag: u8 = fields
            .get(0)
            .ok_or_else(|| zvariant::Error::IncorrectType)?
            .downcast_ref()?;
        let value = &fields
            .get(1)
            .ok_or_else(|| zvariant::Error::IncorrectType)?;
        return match tag {
            0x01 => Ok(Self::Idle),
            0x02 => {
                let qr_code: &str = value.downcast_ref()?;
                Ok(Self::Started(qr_code.to_string()))
            }
            0x03 => Ok(Self::Connecting),
            0x04 => Ok(Self::Connected),
            0x05 => Ok(Self::Completed),
            0x06 => Ok(Self::UserCancelled),
            0x07 => Ok(Self::Failed),
            _ => Err(zvariant::Error::Message(format!(
                "Invalid HybridState type passed: {tag}"
            ))),
        };
    }
}

impl<'de> Deserialize<'de> for crate::model::HybridState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let d = Value::deserializer_for_signature(&Signature::Variant)
            .map_err(|err| D::Error::custom(format!("could not create deserializer: {err}")))?;
        let variant = d.deserialize(deserializer)?;
        let structure: Structure<'_> = variant.downcast_ref().unwrap();
        let tag: u8 = structure.fields()[0].downcast_ref().map_err(|err| {
            D::Error::custom(format!(
                "invalid tag `{}` received: {err}",
                structure.fields()[0]
            ))
        })?;
        let value = &structure.fields()[1];
        match tag {
            0x01 => Ok(Self::Idle),
            0x02 => Ok(Self::Started(value.try_into().map_err(|err| {
                D::Error::custom(format!("could not deserialize HybridState: {err}"))
            })?)),
            0x03 => Ok(Self::Connecting),
            0x04 => Ok(Self::Connected),
            0x05 => Ok(Self::Completed),
            0x06 => Ok(Self::UserCancelled),
            0x07 => Ok(Self::Failed),
            _ => Err(D::Error::custom(format!("Unknown HybridState tag: {tag}"))),
        }
    }
}

impl Type for crate::model::HybridState {
    const SIGNATURE: &'static Signature = TAG_VALUE_SIGNATURE;
}

/// Identifier for a request to be used for cancellation.
pub type RequestId = u32;

#[derive(Serialize, Deserialize, Type)]
pub enum ServiceError {
    /// Some unknown error with the authenticator occurred.
    AuthenticatorError,

    /// No matching credentials were found on the device.
    NoCredentials,

    /// Credential was already registered with this device (credential ID contained in excludeCredentials)
    CredentialExcluded,

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
            ServiceError::CredentialExcluded => Self::CredentialExcluded,
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
#[derive(Clone, Debug, Serialize, Deserialize, Type)]
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
                let error_code: String = Value::<'_>::from(value).try_into()?;
                Ok(Self::Failed(
                    match error_code.as_ref() {
                        "AuthenticatorError" => ServiceError::AuthenticatorError,
                        "NoCredentials" => ServiceError::NoCredentials,
                        "CredentialExcluded" => ServiceError::CredentialExcluded,
                        "PinAttemptsExhausted" => ServiceError::PinAttemptsExhausted,
                        _ => ServiceError::Internal,
                    }
                    .into(),
                ))
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
        let fields: HashMap<String, Value<'_>> = value.try_into()?;
        let tag = fields
            .get("type")
            .ok_or(zvariant::Error::Message(
                "Expected a dictionary with `type` key".to_string(),
            ))
            .and_then(|t| t.try_into())?;
        let value = fields.get("value").ok_or(zvariant::Error::Message(
            "Expected a dictionary with `value` key".to_string(),
        ))?;
        match tag {
            "IDLE" => Ok(Self::Idle(value_to_owned(value))),
            "WAITING" => Ok(Self::Waiting(value_to_owned(value))),
            "SELECTING_DEVICE" => Ok(Self::SelectingDevice(value_to_owned(value))),
            "CONNECTED" => Ok(Self::SelectingDevice(value_to_owned(value))),
            "NEEDS_PIN" => Ok(Self::NeedsPin(value_to_owned(value))),
            "NEEDS_USER_VERIFICATION" => Ok(Self::NeedsUserVerification(value_to_owned(value))),
            "NEEDS_USER_PRESENCE" => Ok(Self::NeedsUserPresence(value_to_owned(value))),
            "SELECT_CREDENTIAL" => Ok(Self::SelectCredential(value_to_owned(value))),
            "COMPLETED" => Ok(Self::Completed(value_to_owned(value))),
            "FAILED" => Ok(Self::Failed(value_to_owned(value))),
            _ => Err(zvariant::Error::Message(format!(
                "Invalid UsbState type passed: {tag}"
            ))),
        }
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
    pub id: RequestId,
}

fn value_to_owned(value: &Value<'_>) -> OwnedValue {
    value
        .try_to_owned()
        .expect("non-file descriptor values to succeed")
}

#[cfg(test)]
mod test {
    use zvariant::{
        Type,
        serialized::{Context, Data, Format},
    };

    use crate::server::BackgroundEvent;

    #[test]
    fn test_serialize_hybrid_state() {
        let state = crate::model::HybridState::Completed;
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        let data = zvariant::to_bytes(ctx, &state).unwrap();
        assert_eq!("(yv)", crate::model::HybridState::SIGNATURE.to_string());
        assert_eq!(&[5, 1, b'y', 0, 0], data.bytes());
    }

    #[test]
    fn test_serialize_background_hybrid_event() {
        let state = crate::model::HybridState::Completed;
        let event = BackgroundEvent::HybridStateChanged(state);
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        assert_eq!("(yv)", BackgroundEvent::SIGNATURE.to_string());
        let data = zvariant::to_bytes(ctx, &event).unwrap();
        let expected = b"\x02\x04(yv)\0\0\x05\x01y\0\0";
        assert_eq!(expected, data.bytes());
    }

    #[test]
    fn test_deserialize_background_hybrid_event() {
        let data = Data::new(
            b"\x02\x04(yv)\0\0\x05\x01y\0\0",
            Context::new(Format::DBus, zvariant::BE, 0),
        );
        let event: BackgroundEvent = data.deserialize().unwrap().0;
        assert!(matches!(
            event,
            BackgroundEvent::HybridStateChanged(crate::model::HybridState::Completed)
        ));
    }

    #[test]
    fn test_round_trip_background_hybrid_event() {
        let event = BackgroundEvent::HybridStateChanged(crate::model::HybridState::Started(
            String::from("FIDO:/1234"),
        ));
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        let data = zvariant::to_bytes(ctx, &event).unwrap();
        let bytes = data.bytes();
        let data2 = Data::new(bytes, Context::new(Format::DBus, zvariant::BE, 0));
        let event_2: BackgroundEvent = data2.deserialize().unwrap().0;
        assert!(matches!(
            event_2,
            BackgroundEvent::HybridStateChanged(crate::model::HybridState::Started(ref f)) if f == "FIDO:/1234"
        ));
    }
}
