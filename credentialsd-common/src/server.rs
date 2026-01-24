//! Types for serializing across D-Bus instances

use std::{collections::HashMap, fmt::Display};

use serde::{
    Deserialize, Serialize,
    de::{DeserializeSeed, Error, Visitor},
};
use zvariant::{
    self, Array, DeserializeDict, DynamicDeserialize, LE, NoneValue, Optional, OwnedValue,
    SerializeDict, Signature, Structure, StructureBuilder, Type, Value, signature::Fields,
};

use crate::model::{BackgroundEvent, Operation, RequestingApplication};

const TAG_VALUE_SIGNATURE: &Signature = &Signature::Structure(Fields::Static {
    fields: &[&Signature::U8, &Signature::Variant],
});

impl Type for BackgroundEvent {
    const SIGNATURE: &'static Signature = TAG_VALUE_SIGNATURE;
}

impl From<&BackgroundEvent> for Structure<'_> {
    fn from(value: &BackgroundEvent) -> Self {
        match value {
            BackgroundEvent::UsbStateChanged(state) => {
                tag_value_to_struct(0x01, Some(Value::Structure(state.into())))
            }
            BackgroundEvent::HybridQrStateChanged(state) => {
                tag_value_to_struct(0x02, Some(Value::Structure(state.into())))
            }
            BackgroundEvent::NfcStateChanged(state) => {
                tag_value_to_struct(0x03, Some(Value::Structure(state.into())))
            }
        }
    }
}

impl TryFrom<&Structure<'_>> for BackgroundEvent {
    type Error = zvariant::Error;

    fn try_from(value: &Structure<'_>) -> Result<Self, Self::Error> {
        let (tag, value) = parse_tag_value_struct(value)?;

        match tag {
            0x01 => {
                let structure: Structure = value.downcast_ref()?;
                Ok(BackgroundEvent::UsbStateChanged((&structure).try_into()?))
            }
            0x02 => {
                let structure: Structure = value.downcast_ref()?;
                Ok(BackgroundEvent::HybridQrStateChanged(
                    (&structure).try_into()?,
                ))
            }
            0x03 => {
                let structure: Structure = value.downcast_ref()?;
                Ok(BackgroundEvent::NfcStateChanged((&structure).try_into()?))
            }
            _ => Err(zvariant::Error::Message(format!(
                "Unknown BackgroundEvent tag : {tag}"
            ))),
        }
    }
}

impl Serialize for BackgroundEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let structure: Structure = self.into();
        structure.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BackgroundEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let d = Structure::deserializer_for_signature(TAG_VALUE_SIGNATURE).map_err(|err| {
            D::Error::custom(format!(
                "could not create deserializer for tag-value struct: {err}"
            ))
        })?;
        let structure = d.deserialize(deserializer)?;
        (&structure).try_into().map_err(|err| {
            D::Error::custom(format!(
                "could not deserialize structure into BackgroundEvent: {err}"
            ))
        })
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

impl NoneValue for CreateCredentialResponse {
    type NoneType = HashMap<String, OwnedValue>;

    fn null_value() -> Self::NoneType {
        HashMap::new()
    }
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

impl From<&Credential> for crate::model::Credential {
    fn from(value: &Credential) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            username: value.username.clone().into(),
        }
    }
}

impl From<Credential> for crate::model::Credential {
    fn from(value: Credential) -> Self {
        Self::from(&value)
    }
}

impl From<&crate::model::Credential> for Credential {
    fn from(value: &crate::model::Credential) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            username: value.username.clone().into(),
        }
    }
}

impl From<crate::model::Credential> for Credential {
    fn from(value: crate::model::Credential) -> Self {
        Self::from(&value)
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

impl TryFrom<&Value<'_>> for crate::model::Error {
    type Error = zvariant::Error;

    fn try_from(value: &Value<'_>) -> Result<Self, Self::Error> {
        let err_code: &str = value.downcast_ref()?;
        let err = match err_code {
            "AuthenticatorError" => crate::model::Error::AuthenticatorError,
            "PinNotSet" => crate::model::Error::PinNotSet,
            "NoCredentials" => crate::model::Error::NoCredentials,
            "CredentialExcluded" => crate::model::Error::CredentialExcluded,
            "PinAttemptsExhausted" => crate::model::Error::PinAttemptsExhausted,
            s => crate::model::Error::Internal(String::from(s)),
        };
        Ok(err)
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

impl NoneValue for GetCredentialResponse {
    type NoneType = HashMap<String, OwnedValue>;

    fn null_value() -> Self::NoneType {
        HashMap::new()
    }
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

impl Serialize for crate::model::HybridState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let structure: Structure = self.into();
        structure.serialize(serializer)
    }
}

impl From<&crate::model::HybridState> for Structure<'_> {
    fn from(value: &crate::model::HybridState) -> Self {
        let (tag, value): (u8, Option<Value>) = match value {
            crate::model::HybridState::Idle => (0x01, None),
            crate::model::HybridState::Started(value) => (0x02, Some(Value::Str(value.into()))),
            crate::model::HybridState::Connecting => (0x03, None),
            crate::model::HybridState::Connected => (0x04, None),
            crate::model::HybridState::Completed => (0x05, None),
            crate::model::HybridState::UserCancelled => (0x06, None),
            crate::model::HybridState::Failed => (0x07, None),
        };
        tag_value_to_struct(tag, value)
    }
}

impl TryFrom<&Structure<'_>> for crate::model::HybridState {
    type Error = zvariant::Error;

    fn try_from(structure: &Structure<'_>) -> Result<Self, Self::Error> {
        let (tag, value) = parse_tag_value_struct(structure)?;
        match tag {
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
        }
    }
}

impl TryFrom<Structure<'_>> for crate::model::HybridState {
    type Error = zvariant::Error;

    fn try_from(structure: Structure<'_>) -> Result<Self, Self::Error> {
        Self::try_from(&structure)
    }
}

impl<'de> Deserialize<'de> for crate::model::HybridState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_tag_value(deserializer)
    }
}

impl Type for crate::model::HybridState {
    const SIGNATURE: &'static Signature = TAG_VALUE_SIGNATURE;
}

/// Identifier for a request to be used for cancellation.
pub type RequestId = u32;

impl Type for crate::model::UsbState {
    const SIGNATURE: &'static Signature = TAG_VALUE_SIGNATURE;
}

impl Type for crate::model::NfcState {
    const SIGNATURE: &'static Signature = TAG_VALUE_SIGNATURE;
}

impl From<&crate::model::UsbState> for Structure<'_> {
    fn from(value: &crate::model::UsbState) -> Self {
        let (tag, value): (u8, Option<Value>) = match value {
            crate::model::UsbState::Idle => (0x01, None),
            crate::model::UsbState::Waiting => (0x02, None),
            crate::model::UsbState::SelectingDevice => (0x03, None),
            crate::model::UsbState::Connected => (0x04, None),
            // TODO: Add pin request reason to this struct
            crate::model::UsbState::NeedsPin { attempts_left } => {
                let num = match attempts_left {
                    Some(num) => *num as i32,
                    None => -1,
                };
                (0x05, Some(Value::I32(num)))
            }
            crate::model::UsbState::NeedsUserVerification { attempts_left } => {
                let num = match attempts_left {
                    Some(num) => *num as i32,
                    None => -1,
                };
                (0x06, Some(Value::I32(num)))
            }
            crate::model::UsbState::NeedsUserPresence => (0x07, None),
            crate::model::UsbState::SelectingCredential { creds } => {
                let creds: Vec<Credential> = creds.iter().map(Credential::from).collect();
                let value = Value::new(creds);
                (0x08, Some(value))
            }
            crate::model::UsbState::Completed => (0x09, None),
            crate::model::UsbState::Failed(error) => {
                let value = Value::<'_>::from(error.to_string());
                (0x0A, Some(value))
            }
        };
        tag_value_to_struct(tag, value)
    }
}

impl TryFrom<&Structure<'_>> for crate::model::UsbState {
    type Error = zvariant::Error;

    fn try_from(structure: &Structure<'_>) -> Result<Self, Self::Error> {
        let (tag, value) = parse_tag_value_struct(structure)?;
        match tag {
            0x01 => Ok(Self::Idle),
            0x02 => Ok(Self::Waiting),
            0x03 => Ok(Self::SelectingDevice),
            0x04 => Ok(Self::Connected),
            0x05 => {
                let attempts_left: i32 = value.downcast_ref()?;
                let attempts_left = if attempts_left == -1 {
                    None
                } else {
                    Some(attempts_left as u32)
                };
                Ok(Self::NeedsPin { attempts_left })
            }
            0x06 => {
                let attempts_left: i32 = value.downcast_ref()?;
                let attempts_left = if attempts_left == -1 {
                    None
                } else {
                    Some(attempts_left as u32)
                };
                Ok(Self::NeedsUserVerification { attempts_left })
            }
            0x07 => Ok(Self::NeedsUserPresence),
            0x08 => {
                let creds: Array = value.downcast_ref()?;
                let creds: Result<Vec<crate::model::Credential>, zvariant::Error> = creds
                    .iter()
                    .map(|v| v.try_to_owned().unwrap())
                    .map(|v| {
                        let cred: Result<crate::model::Credential, zvariant::Error> =
                            Value::from(v)
                                .downcast::<Credential>()
                                .map(crate::model::Credential::from);
                        cred
                    })
                    .collect();
                Ok(Self::SelectingCredential { creds: creds? })
            }
            0x09 => Ok(Self::Completed),
            0x0A => {
                let err_code: &str = value.downcast_ref()?;
                let err = match err_code {
                    "AuthenticatorError" => crate::model::Error::AuthenticatorError,
                    "PinNotSet" => crate::model::Error::PinNotSet,
                    "NoCredentials" => crate::model::Error::NoCredentials,
                    "CredentialExcluded" => crate::model::Error::CredentialExcluded,
                    "PinAttemptsExhausted" => crate::model::Error::PinAttemptsExhausted,
                    s => crate::model::Error::Internal(String::from(s)),
                };
                Ok(Self::Failed(err))
            }
            _ => Err(zvariant::Error::IncorrectType),
        }
    }
}

impl TryFrom<Structure<'_>> for crate::model::UsbState {
    type Error = zvariant::Error;

    fn try_from(structure: Structure<'_>) -> Result<Self, Self::Error> {
        Self::try_from(&structure)
    }
}

impl Serialize for crate::model::UsbState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let structure: Structure = self.into();
        structure.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for crate::model::UsbState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_tag_value(deserializer)
    }
}

impl From<&crate::model::NfcState> for Structure<'_> {
    fn from(value: &crate::model::NfcState) -> Self {
        let (tag, value): (u8, Option<Value>) = match value {
            crate::model::NfcState::Idle => (0x01, None),
            crate::model::NfcState::Waiting => (0x02, None),
            crate::model::NfcState::Connected => (0x04, None),
            // TODO: Add pin request reason to this struct
            crate::model::NfcState::NeedsPin { attempts_left } => {
                let num = match attempts_left {
                    Some(num) => *num as i32,
                    None => -1,
                };
                (0x05, Some(Value::I32(num)))
            }
            crate::model::NfcState::NeedsUserVerification { attempts_left } => {
                let num = match attempts_left {
                    Some(num) => *num as i32,
                    None => -1,
                };
                (0x06, Some(Value::I32(num)))
            }
            crate::model::NfcState::SelectingCredential { creds } => {
                let creds: Vec<Credential> = creds.iter().map(Credential::from).collect();
                let value = Value::new(creds);
                (0x08, Some(value))
            }
            crate::model::NfcState::Completed => (0x09, None),
            crate::model::NfcState::Failed(error) => {
                let value = Value::<'_>::from(error.to_string());
                (0x0A, Some(value))
            }
        };
        tag_value_to_struct(tag, value)
    }
}

impl TryFrom<&Structure<'_>> for crate::model::NfcState {
    type Error = zvariant::Error;

    fn try_from(structure: &Structure<'_>) -> Result<Self, Self::Error> {
        let (tag, value) = parse_tag_value_struct(structure)?;
        match tag {
            0x01 => Ok(Self::Idle),
            0x02 => Ok(Self::Waiting),
            0x04 => Ok(Self::Connected),
            0x05 => {
                let attempts_left: i32 = value.downcast_ref()?;
                let attempts_left = if attempts_left == -1 {
                    None
                } else {
                    Some(attempts_left as u32)
                };
                Ok(Self::NeedsPin { attempts_left })
            }
            0x06 => {
                let attempts_left: i32 = value.downcast_ref()?;
                let attempts_left = if attempts_left == -1 {
                    None
                } else {
                    Some(attempts_left as u32)
                };
                Ok(Self::NeedsUserVerification { attempts_left })
            }
            0x08 => {
                let creds: Array = value.downcast_ref()?;
                let creds: Result<Vec<crate::model::Credential>, zvariant::Error> = creds
                    .iter()
                    .map(|v| v.try_to_owned().unwrap())
                    .map(|v| {
                        let cred: Result<crate::model::Credential, zvariant::Error> =
                            Value::from(v)
                                .downcast::<Credential>()
                                .map(crate::model::Credential::from);
                        cred
                    })
                    .collect();
                Ok(Self::SelectingCredential { creds: creds? })
            }
            0x09 => Ok(Self::Completed),
            0x0A => {
                let err_code: &str = value.downcast_ref()?;
                let err = match err_code {
                    "AuthenticatorError" => crate::model::Error::AuthenticatorError,
                    "PinNotSet" => crate::model::Error::PinNotSet,
                    "NoCredentials" => crate::model::Error::NoCredentials,
                    "CredentialExcluded" => crate::model::Error::CredentialExcluded,
                    "PinAttemptsExhausted" => crate::model::Error::PinAttemptsExhausted,
                    s => crate::model::Error::Internal(String::from(s)),
                };
                Ok(Self::Failed(err))
            }
            _ => Err(zvariant::Error::IncorrectType),
        }
    }
}

impl TryFrom<Structure<'_>> for crate::model::NfcState {
    type Error = zvariant::Error;

    fn try_from(structure: Structure<'_>) -> Result<Self, Self::Error> {
        Self::try_from(&structure)
    }
}

impl Serialize for crate::model::NfcState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let structure: Structure = self.into();
        structure.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for crate::model::NfcState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_tag_value(deserializer)
    }
}

fn deserialize_tag_value<'a, 'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: TryFrom<Structure<'a>>,
    <T as TryFrom<Structure<'a>>>::Error: std::fmt::Display,
    D: serde::Deserializer<'de>,
    'de: 'a,
{
    let d = Structure::deserializer_for_signature(TAG_VALUE_SIGNATURE).map_err(|err| {
        D::Error::custom(format!(
            "could not create deserializer for structure: {err}",
        ))
    })?;
    let structure = d.deserialize(deserializer)?;
    structure
        .try_into()
        .map_err(|err| D::Error::custom(format!("could not deserialize from structure: {err}")))
}

#[derive(Serialize, Deserialize, Type)]
pub struct ViewRequest {
    pub operation: Operation,
    pub id: RequestId,
    pub rp_id: String,
    pub requesting_app: RequestingApplication,

    /// Client window handle.
    pub window_handle: Optional<WindowHandle>,
}

#[derive(Type, PartialEq, Debug)]
#[zvariant(signature = "s")]
pub enum WindowHandle {
    Wayland(String),
    X11(String),
}

impl NoneValue for WindowHandle {
    type NoneType = String;

    fn null_value() -> Self::NoneType {
        String::new()
    }
}

impl Serialize for WindowHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for WindowHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(WindowHandleVisitor {})
    }
}

struct WindowHandleVisitor;

impl<'de> Visitor<'de> for WindowHandleVisitor {
    type Value = WindowHandle;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "a window handle formatted as `<window system>:<handle value>`"
        )
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        v.try_into().map_err(E::custom)
    }
}

impl TryFrom<String> for WindowHandle {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        WindowHandle::try_from(value.as_ref())
    }
}

impl TryFrom<&str> for WindowHandle {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.split_once(':') {
            Some(("x11", handle)) => Ok(Self::X11(handle.to_string())),
            Some(("wayland", xid)) => Ok(Self::Wayland(xid.to_string())),
            Some((window_system, _)) => Err(format!("Unknown windowing system: {window_system}")),
            None => Err("Invalid window handle string format".to_string()),
        }
    }
}

impl Display for WindowHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wayland(handle) => write!(f, "wayland:{handle}"),
            Self::X11(xid) => write!(f, "x11:{xid}"),
        }
    }
}

fn value_to_owned(value: &Value<'_>) -> OwnedValue {
    value
        .try_to_owned()
        .expect("non-file descriptor values to succeed")
}

fn parse_tag_value_struct<'a>(s: &'a Structure) -> Result<(u8, Value<'a>), zvariant::Error> {
    if s.signature() != TAG_VALUE_SIGNATURE {
        return Err(zvariant::Error::SignatureMismatch(
            s.signature().clone(),
            TAG_VALUE_SIGNATURE.to_string(),
        ));
    }
    let tag: u8 = s
        .fields()
        .first()
        .ok_or_else(|| {
            zvariant::Error::SignatureMismatch(
                Signature::U8,
                "expected a single-byte tag".to_string(),
            )
        })
        .and_then(|f| f.downcast_ref())?;
    let value = s
        .fields()
        .get(1)
        .ok_or_else(|| {
            zvariant::Error::SignatureMismatch(
                Signature::Variant,
                "expected a variant value".to_string(),
            )
        })?
        .clone();
    Ok((tag, value))
}

fn tag_value_to_struct(tag: u8, value: Option<Value<'_>>) -> Structure<'static> {
    StructureBuilder::new()
        .add_field(tag)
        .append_field(Value::new(value_to_owned(
            &value.unwrap_or_else(|| Value::U8(0)),
        )))
        .build()
        .expect("create a struct")
}

#[cfg(test)]
mod test {
    use zvariant::{
        Type,
        serialized::{Context, Data, Format},
    };

    use crate::model::{BackgroundEvent, HybridState, UsbState};

    #[test]
    fn test_serialize_hybrid_state() {
        let state = HybridState::Completed;
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        let data = zvariant::to_bytes(ctx, &state).unwrap();
        assert_eq!("(yv)", HybridState::SIGNATURE.to_string());
        assert_eq!(&[5, 1, b'y', 0, 0], data.bytes());
    }

    #[test]
    fn test_serialize_background_hybrid_event() {
        let state = HybridState::Started("FIDO:/1234".to_string());
        let event = BackgroundEvent::HybridQrStateChanged(state);
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        assert_eq!("(yv)", BackgroundEvent::SIGNATURE.to_string());
        let data = zvariant::to_bytes(ctx, &event).unwrap();
        let expected = b"\x02\x04(yv)\0\0\x02\x01s\0\0\0\0\x0aFIDO:/1234\0";
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
            BackgroundEvent::HybridQrStateChanged(crate::model::HybridState::Completed)
        ));
    }

    #[test]
    fn test_round_trip_background_hybrid_event() {
        let event =
            BackgroundEvent::HybridQrStateChanged(HybridState::Started(String::from("FIDO:/1234")));
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        let data = zvariant::to_bytes(ctx, &event).unwrap();
        let bytes = data.bytes();
        let data2 = Data::new(bytes, Context::new(Format::DBus, zvariant::BE, 0));
        let event_2: BackgroundEvent = data2.deserialize().unwrap().0;
        assert!(matches!(
            event_2,
            BackgroundEvent::HybridQrStateChanged(HybridState::Started(ref f)) if f == "FIDO:/1234"
        ));
    }

    #[test]
    fn test_serialize_usb_state() {
        let creds = vec![
            crate::model::Credential {
                id: "a1b2c3".to_string(),
                name: "user 1".to_string(),
                username: Some("u1@example.com".to_string()),
            },
            crate::model::Credential {
                id: "321".to_string(),
                name: "User 2".to_string(),
                username: None,
            },
        ];
        let state = UsbState::SelectingCredential { creds };
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        let data = zvariant::to_bytes(ctx, &state).unwrap();
        assert_eq!("(yv)", UsbState::SIGNATURE.to_string());

        #[rustfmt::skip]
        let expected = [
            8, // UsbState::SelectingCredential
            6, 97, 97, 123, 115, 118, 125, 0, 0, 0, 0, // Signature aa{sv} + padding
            0, 0, 0, 165, // array(struct) data length
                0, 0, 0, 83, 0, 0, 0, 0, // element 1(struct) length, + padding(4)
                    0, 0, 0, 2, 105, 100, 0, // string[2] "id"
                        1, 115, 0, 0, 0, // Signature s + padding
                        0, 0, 0, 6, 97, 49, 98, 50, 99, 51, 0, 0, // String, len 6, "a1b2c3" + padding(1)
                    0, 0, 0, 4, 110, 97, 109, 101, 0, // String, len 4, "name"
                        1, 115, 0, // Signature s + padding
                        0, 0, 0, 6, 117, 115, 101, 114, 32, 49, 0, 0, // String, len 6, "user 1" + padding(1)
                    0, 0, 0, 8, 117, 115, 101, 114, 110, 97, 109, 101, 0, // String, len 8, "username"
                        1, 115, 0, // Signature s
                        0, 0, 0, 14, 117, 49, 64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0, 0, // String, len 14, "u1@example.com" + padding(1)

            0, 0, 0, 69, // element 2, length 69
                0, 0, 0, 2, 105, 100, 0, // string, len 2, "id"
                    1, 115, 0, 0, 0, // Signature s + padding(2)
                    0, 0, 0, 3, 51, 50, 49, 0, 0, 0, 0, 0, // string, len 3, "321" + padding(4)
                0, 0, 0, 4, 110, 97, 109, 101, 0, // String, len 4, "name"
                    1, 115, 0, // Signature s
                    0, 0, 0, 6, 85, 115, 101, 114, 32, 50, 0, 0, // String, len 6, "User 2" + padding(1)
                0, 0, 0, 8, 117, 115, 101, 114, 110, 97, 109, 101, 0, // string, len 8, "username"
                    1, 115, 0, 0, // Signature s + padding(1)
                    0, 0, 0, 0, // string, len 0, ""
        ];
        assert_eq!(expected, data.bytes());
    }

    #[test]
    fn test_deserialize_usb_state() {
        #[rustfmt::skip]
        let input = [
            8, // UsbState::SelectingCredential
            6, 97, 97, 123, 115, 118, 125, 0, 0, 0, 0, // Signature aa{sv} + padding
            0, 0, 0, 165, // array(struct) data length
                0, 0, 0, 83, 0, 0, 0, 0, // element 1(struct) length, + padding(4)
                    0, 0, 0, 2, 105, 100, 0, // string[2] "id"
                        1, 115, 0, 0, 0, // Signature s + padding
                        0, 0, 0, 6, 97, 49, 98, 50, 99, 51, 0, 0, // String, len 6, "a1b2c3" + padding(1)
                    0, 0, 0, 4, 110, 97, 109, 101, 0, // String, len 4, "name"
                        1, 115, 0, // Signature s + padding
                        0, 0, 0, 6, 117, 115, 101, 114, 32, 49, 0, 0, // String, len 6, "user 1" + padding(1)
                    0, 0, 0, 8, 117, 115, 101, 114, 110, 97, 109, 101, 0, // String, len 8, "username"
                        1, 115, 0, // Signature s
                        0, 0, 0, 14, 117, 49, 64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0, 0, // String, len 14, "u1@example.com" + padding(1)

            0, 0, 0, 69, // element 2, length 69
                0, 0, 0, 2, 105, 100, 0, // string, len 2, "id"
                    1, 115, 0, 0, 0, // Signature s + padding(2)
                    0, 0, 0, 3, 51, 50, 49, 0, 0, 0, 0, 0, // string, len 3, "321" + padding(4)
                0, 0, 0, 4, 110, 97, 109, 101, 0, // String, len 4, "name"
                    1, 115, 0, // Signature s
                    0, 0, 0, 6, 85, 115, 101, 114, 32, 50, 0, 0, // String, len 6, "User 2" + padding(1)
                0, 0, 0, 8, 117, 115, 101, 114, 110, 97, 109, 101, 0, // string, len 8, "username"
                    1, 115, 0, 0, // Signature s + padding(1)
                    0, 0, 0, 0, // string, len 0, ""
        ];
        let ctx = Context::new(Format::DBus, zvariant::BE, 0);
        let data = Data::new(&input, ctx);
        let state: UsbState = data.deserialize().unwrap().0;
        match state {
            UsbState::SelectingCredential { creds } => {
                assert_eq!(2, creds.len());
                assert_eq!("a1b2c3", creds[0].id,);
                assert_eq!("user 1", creds[0].name,);
                assert_eq!("u1@example.com", creds[0].username.as_ref().unwrap());
                assert_eq!("321", creds[1].id,);
                assert_eq!("User 2", creds[1].name,);
                assert_eq!(None, creds[1].username,);
            }
            _ => panic!(""),
        }
    }

    #[test]
    fn test_serialize_background_usb_event() {
        let state = UsbState::NeedsPin {
            attempts_left: Some(254),
        };
        let event = BackgroundEvent::UsbStateChanged(state);
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        assert_eq!("(yv)", BackgroundEvent::SIGNATURE.to_string());
        let data = zvariant::to_bytes(ctx, &event).unwrap();
        let expected = b"\x01\x04(yv)\0\0\x05\x01i\0\0\0\0\xfe";
        assert_eq!(expected, data.bytes());
    }

    #[test]
    fn test_round_trip_background_usb_event() {
        let event = BackgroundEvent::UsbStateChanged(UsbState::NeedsUserVerification {
            attempts_left: None,
        });
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        let data = zvariant::to_bytes(ctx, &event).unwrap();
        let bytes = data.bytes();
        let data2 = Data::new(bytes, Context::new(Format::DBus, zvariant::BE, 0));
        let event_2: BackgroundEvent = data2.deserialize().unwrap().0;
        assert!(matches!(
            event_2,
            BackgroundEvent::UsbStateChanged(UsbState::NeedsUserVerification{ ref attempts_left }) if attempts_left.is_none()
        ));
    }

    #[test]
    fn test_zvariant() {
        let input = b"\x01y\0\xdd";
        let ctx = Context::new(Format::DBus, zvariant::BE, 0);
        let data = Data::new(input, ctx);
        let value: zvariant::Value = data.deserialize().unwrap().0;
        assert!(matches!(value, zvariant::Value::U8(b) if b == b'\xdd'))
    }

    #[test]
    fn test_zvariant_array() {
        #[rustfmt::skip]
        let input = [
            2, b'a', b's', 0, // Signature aa{sv}
            0, 0, 0, 7, // array(string) data length
            0, 0, 0, 2, b'y', b'o', 0 // string, len 2, 'yo'
        ];
        let ctx = Context::new(Format::DBus, zvariant::BE, 0);
        let data = Data::new(&input, ctx);
        let value: zvariant::Value = data.deserialize().unwrap().0;
        match value {
            zvariant::Value::Array(arr) => {
                let s = arr.get::<zvariant::Str>(0).unwrap().unwrap();
                assert_eq!("yo", s.as_str());
            }
            _ => panic!(),
        };
    }
}
