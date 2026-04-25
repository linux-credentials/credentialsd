//! Types for serializing across D-Bus instances

use std::{collections::HashMap, fmt::Display};

use serde::{
    Deserialize, Serialize,
    de::{DeserializeSeed, Error, Visitor},
};
use zvariant::{
    self, Array, DeserializeDict, DynamicDeserialize, NoneValue, Optional, OwnedValue,
    SerializeDict, Signature, Structure, StructureBuilder, Type, Value, signature::Fields,
};

use crate::model::{Device, Operation, RequestingApplication};

const TAG_VALUE_SIGNATURE: &Signature = &Signature::Structure(Fields::Static {
    fields: &[&Signature::U32, &Signature::Variant],
});

/// Ceremony completed successfully
const BACKGROUND_EVENT_CEREMONY_COMPLETED: u32 = 0x01;
/// Device needs the client PIN to be entered. The backend should collect the
/// PIN and send it back with `EnterClientPin` event of `UserInteracted` signal.
const BACKGROUND_EVENT_NEEDS_PIN: u32 = 0x10;
const BACKGROUND_EVENT_NEEDS_USER_VERIFICATION: u32 = 0x11;
const BACKGROUND_EVENT_NEEDS_USER_PRESENCE: u32 = 0x12;
const BACKGROUND_EVENT_SELECTING_CREDENTIAL: u32 = 0x13;

const BACKGROUND_EVENT_HYBRID_IDLE: u32 = 0x20;
const BACKGROUND_EVENT_HYBRID_STARTED: u32 = 0x21;
const BACKGROUND_EVENT_HYBRID_CONNECTING: u32 = 0x22;
const BACKGROUND_EVENT_HYBRID_CONNECTED: u32 = 0x23;

const BACKGROUND_EVENT_NFC_IDLE: u32 = 0x30;
const BACKGROUND_EVENT_NFC_WAITING: u32 = 0x31;
const BACKGROUND_EVENT_NFC_CONNECTED: u32 = 0x32;

const BACKGROUND_EVENT_USB_IDLE: u32 = 0x40;
const BACKGROUND_EVENT_USB_WAITING: u32 = 0x41;
const BACKGROUND_EVENT_USB_SELECTING_DEVICE: u32 = 0x42;
const BACKGROUND_EVENT_USB_CONNECTED: u32 = 0x43;

const BACKGROUND_EVENT_ERROR_INTERNAL: u32 = 0x80000001;
const BACKGROUND_EVENT_ERROR_TIMED_OUT: u32 = 0x80000002;
const BACKGROUND_EVENT_ERROR_CANCELLED: u32 = 0x80000003;
const BACKGROUND_EVENT_ERROR_AUTHENTICATOR: u32 = 0x80000004;
const BACKGROUND_EVENT_ERROR_NO_CREDENTIALS: u32 = 0x80000005;
const BACKGROUND_EVENT_ERROR_CREDENTIAL_EXCLUDED: u32 = 0x80000006;
const BACKGROUND_EVENT_ERROR_PIN_ATTEMPTS_EXHAUSTED: u32 = 0x80000007;
const BACKGROUND_EVENT_ERROR_PIN_NOT_SET: u32 = 0x80000008;

/// Flattened enum BackgroundEvent for sending across D-Bus.
#[derive(Debug, Clone, PartialEq)]
pub enum BackgroundEvent {
    CeremonyCompleted,
    NeedsPin { attempts_left: Option<u32> },
    NeedsUserVerification { attempts_left: Option<u32> },
    NeedsUserPresence,
    SelectingCredential { creds: Vec<Credential> },

    HybridIdle,
    HybridStarted(String),
    HybridConnecting,
    HybridConnected,

    NfcIdle,
    NfcWaiting,
    NfcConnected,

    UsbIdle,
    UsbWaiting,
    UsbSelectingDevice,
    UsbConnected,

    ErrorInternal,
    ErrorTimedOut,
    ErrorCancelled,
    ErrorAuthenticator,
    ErrorNoCredentials,
    ErrorCredentialExcluded,
    ErrorPinAttemptsExhausted,
    ErrorPinNotSet,
}

impl BackgroundEvent {
    fn tag(&self) -> u32 {
        match self {
            Self::CeremonyCompleted => BACKGROUND_EVENT_CEREMONY_COMPLETED,
            Self::NeedsPin { .. } => BACKGROUND_EVENT_NEEDS_PIN,
            Self::NeedsUserVerification { .. } => BACKGROUND_EVENT_NEEDS_USER_VERIFICATION,
            Self::NeedsUserPresence => BACKGROUND_EVENT_NEEDS_USER_PRESENCE,
            Self::SelectingCredential { .. } => BACKGROUND_EVENT_SELECTING_CREDENTIAL,

            Self::HybridIdle => BACKGROUND_EVENT_HYBRID_IDLE,
            Self::HybridStarted(_) => BACKGROUND_EVENT_HYBRID_STARTED,
            Self::HybridConnecting => BACKGROUND_EVENT_HYBRID_CONNECTING,
            Self::HybridConnected => BACKGROUND_EVENT_HYBRID_CONNECTED,

            Self::NfcIdle => BACKGROUND_EVENT_NFC_IDLE,
            Self::NfcWaiting => BACKGROUND_EVENT_NFC_WAITING,
            Self::NfcConnected => BACKGROUND_EVENT_NFC_CONNECTED,

            Self::UsbIdle => BACKGROUND_EVENT_USB_IDLE,
            Self::UsbWaiting => BACKGROUND_EVENT_USB_WAITING,
            Self::UsbSelectingDevice => BACKGROUND_EVENT_USB_SELECTING_DEVICE,
            Self::UsbConnected => BACKGROUND_EVENT_USB_CONNECTED,

            Self::ErrorInternal => BACKGROUND_EVENT_ERROR_INTERNAL,
            Self::ErrorTimedOut => BACKGROUND_EVENT_ERROR_TIMED_OUT,
            Self::ErrorCancelled => BACKGROUND_EVENT_ERROR_CANCELLED,
            Self::ErrorAuthenticator => BACKGROUND_EVENT_ERROR_AUTHENTICATOR,
            Self::ErrorNoCredentials => BACKGROUND_EVENT_ERROR_NO_CREDENTIALS,
            Self::ErrorCredentialExcluded => BACKGROUND_EVENT_ERROR_CREDENTIAL_EXCLUDED,
            Self::ErrorPinAttemptsExhausted => BACKGROUND_EVENT_ERROR_PIN_ATTEMPTS_EXHAUSTED,
            Self::ErrorPinNotSet => BACKGROUND_EVENT_ERROR_PIN_NOT_SET,
        }
    }
}

impl Type for BackgroundEvent {
    const SIGNATURE: &'static Signature = TAG_VALUE_SIGNATURE;
}

impl From<&BackgroundEvent> for Structure<'_> {
    fn from(value: &BackgroundEvent) -> Self {
        let tag = value.tag();
        let payload = match value {
            // States with payloads
            BackgroundEvent::NeedsPin { attempts_left } => {
                Some(Value::U32(attempts_left.map(u32::from).unwrap_or(u32::MAX)))
            }
            BackgroundEvent::NeedsUserVerification { attempts_left } => {
                Some(Value::U32(attempts_left.map(u32::from).unwrap_or(u32::MAX)))
            }
            BackgroundEvent::SelectingCredential { creds } => Some(Value::Array(creds.into())),
            BackgroundEvent::HybridStarted(qr_data) => Some(Value::Str(qr_data.into())),
            // Empty
            BackgroundEvent::CeremonyCompleted => None,
            BackgroundEvent::NeedsUserPresence => None,
            BackgroundEvent::HybridIdle => None,
            BackgroundEvent::HybridConnecting => None,
            BackgroundEvent::HybridConnected => None,
            BackgroundEvent::NfcIdle => None,
            BackgroundEvent::NfcWaiting => None,
            BackgroundEvent::NfcConnected => None,
            BackgroundEvent::UsbIdle => None,
            BackgroundEvent::UsbWaiting => None,
            BackgroundEvent::UsbSelectingDevice => None,
            BackgroundEvent::UsbConnected => None,
            BackgroundEvent::ErrorInternal => None,
            BackgroundEvent::ErrorTimedOut => None,
            BackgroundEvent::ErrorCancelled => None,
            BackgroundEvent::ErrorAuthenticator => None,
            BackgroundEvent::ErrorNoCredentials => None,
            BackgroundEvent::ErrorCredentialExcluded => None,
            BackgroundEvent::ErrorPinAttemptsExhausted => None,
            BackgroundEvent::ErrorPinNotSet => None,
        };
        tag_value_to_struct(tag, payload)
    }
}

impl TryFrom<&Structure<'_>> for BackgroundEvent {
    type Error = zvariant::Error;

    fn try_from(value: &Structure<'_>) -> Result<Self, Self::Error> {
        let (tag, value) = parse_tag_value_struct(value)?;

        match tag {
            BACKGROUND_EVENT_CEREMONY_COMPLETED => Ok(Self::CeremonyCompleted),
            BACKGROUND_EVENT_NEEDS_PIN => value.downcast::<u32>().map(|attempts_left| {
                if attempts_left == u32::MAX {
                    Self::NeedsPin {
                        attempts_left: None,
                    }
                } else {
                    Self::NeedsPin {
                        attempts_left: Some(attempts_left),
                    }
                }
            }),
            BACKGROUND_EVENT_NEEDS_USER_VERIFICATION => {
                value.downcast::<u32>().map(|attempts_left| {
                    if attempts_left == u32::MAX {
                        Self::NeedsUserVerification {
                            attempts_left: None,
                        }
                    } else {
                        Self::NeedsUserVerification {
                            attempts_left: Some(attempts_left),
                        }
                    }
                })
            }
            BACKGROUND_EVENT_NEEDS_USER_PRESENCE => Ok(Self::NeedsUserPresence),
            BACKGROUND_EVENT_SELECTING_CREDENTIAL => {
                let creds: Array = value.downcast_ref()?;
                let creds: Result<Vec<Credential>, zvariant::Error> = creds
                    .iter()
                    .map(|v| v.try_to_owned().unwrap())
                    .map(|v| {
                        let cred: Result<Credential, zvariant::Error> = Value::from(v)
                            .downcast::<Credential>()
                            .map(Credential::from);
                        cred
                    })
                    .collect();
                Ok(Self::SelectingCredential { creds: creds? })
            }

            BACKGROUND_EVENT_HYBRID_IDLE => Ok(Self::HybridIdle),
            BACKGROUND_EVENT_HYBRID_STARTED => {
                let qr_data = value.downcast_ref::<&str>()?;
                Ok(Self::HybridStarted(qr_data.to_string()))
            }
            BACKGROUND_EVENT_HYBRID_CONNECTING => Ok(Self::HybridConnecting),
            BACKGROUND_EVENT_HYBRID_CONNECTED => Ok(Self::HybridConnected),

            BACKGROUND_EVENT_NFC_IDLE => Ok(Self::NfcIdle),
            BACKGROUND_EVENT_NFC_WAITING => Ok(Self::NfcWaiting),
            BACKGROUND_EVENT_NFC_CONNECTED => Ok(Self::NfcConnected),

            BACKGROUND_EVENT_USB_IDLE => Ok(Self::UsbIdle),
            BACKGROUND_EVENT_USB_WAITING => Ok(Self::UsbWaiting),
            BACKGROUND_EVENT_USB_SELECTING_DEVICE => Ok(Self::UsbSelectingDevice),
            BACKGROUND_EVENT_USB_CONNECTED => Ok(Self::UsbConnected),

            BACKGROUND_EVENT_ERROR_AUTHENTICATOR => Ok(Self::ErrorAuthenticator),
            BACKGROUND_EVENT_ERROR_NO_CREDENTIALS => Ok(Self::ErrorNoCredentials),
            BACKGROUND_EVENT_ERROR_PIN_ATTEMPTS_EXHAUSTED => Ok(Self::ErrorPinAttemptsExhausted),
            BACKGROUND_EVENT_ERROR_INTERNAL => Ok(Self::ErrorInternal),
            BACKGROUND_EVENT_ERROR_TIMED_OUT => Ok(Self::ErrorTimedOut),
            BACKGROUND_EVENT_ERROR_CANCELLED => Ok(Self::ErrorCancelled),
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

#[derive(Debug, Clone, SerializeDict, DeserializeDict, PartialEq, Type, Value)]
#[zvariant(signature = "dict")]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
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

/// Identifier for a request to be used for cancellation.
pub type RequestId = u32;

#[derive(Serialize, Deserialize, Type)]
pub struct ViewRequest {
    pub operation: Operation,

    /// ID of the request.
    pub id: RequestId,

    /// The RP ID
    pub rp_id: String,

    /// Details about the application requesting credentials.
    pub requesting_app: RequestingApplication,

    /// Initial list of device interfaces that may provide credentials.
    pub initial_devices: Vec<Device>,

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

fn parse_tag_value_struct<'a>(s: &'a Structure) -> Result<(u32, Value<'a>), zvariant::Error> {
    if s.signature() != TAG_VALUE_SIGNATURE {
        return Err(zvariant::Error::SignatureMismatch(
            s.signature().clone(),
            TAG_VALUE_SIGNATURE.to_string(),
        ));
    }
    let tag: u32 = s
        .fields()
        .first()
        .ok_or_else(|| {
            zvariant::Error::SignatureMismatch(Signature::U32, "expected a u32 tag".to_string())
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

fn tag_value_to_struct(tag: u32, value: Option<Value<'_>>) -> Structure<'static> {
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

    use super::{BackgroundEvent, Credential};

    #[test]
    fn test_round_trip_completed_event() {
        let event1 = BackgroundEvent::CeremonyCompleted;
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        let data = zvariant::to_bytes(ctx, &event1).unwrap();
        assert_eq!("(uv)", BackgroundEvent::SIGNATURE.to_string());
        assert_eq!(&[0, 0, 0, 1, 1, b'y', 0, 0], data.bytes());
        let event2 = data.deserialize().unwrap().0;
        assert_eq!(event1, event2);
    }

    #[test]
    fn test_round_trip_background_hybrid_event() {
        let event1 = BackgroundEvent::HybridStarted("FIDO:/1234".to_string());
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        assert_eq!("(uv)", BackgroundEvent::SIGNATURE.to_string());
        let data = zvariant::to_bytes(ctx, &event1).unwrap();
        let expected = b"\x00\x00\x00\x21\x01s\0\0\0\0\0\x0aFIDO:/1234\0";
        assert_eq!(expected, data.bytes());
        let event2 = data.deserialize().unwrap().0;
        assert_eq!(event1, event2);
    }

    #[test]
    fn test_deserialize_background_hybrid_event() {
        let bytes = b"\x00\x00\x00\x21\x01s\0\0\0\0\0\x0aFIDO:/1234\0";
        let data = Data::new(bytes, Context::new(Format::DBus, zvariant::BE, 0));
        let event: BackgroundEvent = data.deserialize().unwrap().0;
        assert!(matches!(
            event,
            BackgroundEvent::HybridStarted(ref s) if s == "FIDO:/1234"
        ));
    }

    #[test]
    fn test_round_trip_selecting_credential_state() {
        let creds = vec![
            Credential {
                id: "a1b2c3".to_string(),
                name: "user 1".to_string(),
                username: Some("u1@example.com".to_string()),
            },
            Credential {
                id: "321".to_string(),
                name: "User 2".to_string(),
                username: None,
            },
        ];
        let event1 = BackgroundEvent::SelectingCredential { creds };
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::BE, 0);
        let data = zvariant::to_bytes(ctx, &event1).unwrap();
        assert_eq!("(uv)", BackgroundEvent::SIGNATURE.to_string());

        #[rustfmt::skip]
        let expected = [
            0, 0, 0, 0x13, // BACKGROUND_EVENT_SELECTING_CREDENTIAL
            6, b'a', b'a', b'{', b's', b'v', b'}', 0, // Signature aa{sv} + padding(1)
            0, 0, 0, 143, // array(struct) data length
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

            0, 0, 0, 47, // element 2, length 69
                0, 0, 0, 2, 105, 100, 0, // string, len 2, "id"
                    1, 115, 0, 0, 0, // Signature s + padding(2)
                    0, 0, 0, 3, 51, 50, 49, 0, 0, 0, 0, 0, // string, len 3, "321" + padding(4)
                0, 0, 0, 4, 110, 97, 109, 101, 0, // String, len 4, "name"
                    1, 115, 0, // Signature s
                    0, 0, 0, 6, 85, 115, 101, 114, 32, 50, 0, // String, len 6, "User 2" + padding(1)
                    // username omitted
        ];
        assert_eq!(expected, data.bytes());
        let event2: BackgroundEvent = data.deserialize().unwrap().0;
        assert_eq!(event1, event2);
    }
}
