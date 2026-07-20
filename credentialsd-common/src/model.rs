use std::fmt::Display;

use serde::{Deserialize, Serialize, de::Visitor};

use zvariant::{self, DeserializeDict, NoneValue, Optional, OwnedFd, SerializeDict, Type, Value};

pub const BACKGROUND_EVENT_ERROR_INTERNAL: u32 = 0x80000001;
pub const BACKGROUND_EVENT_ERROR_TIMED_OUT: u32 = 0x80000002;
pub const BACKGROUND_EVENT_ERROR_CANCELLED: u32 = 0x80000003;
pub const BACKGROUND_EVENT_ERROR_AUTHENTICATOR: u32 = 0x80000004;
pub const BACKGROUND_EVENT_ERROR_NO_CREDENTIALS: u32 = 0x80000005;
pub const BACKGROUND_EVENT_ERROR_CREDENTIAL_EXCLUDED: u32 = 0x80000006;
pub const BACKGROUND_EVENT_ERROR_PIN_ATTEMPTS_EXHAUSTED: u32 = 0x80000007;
pub const BACKGROUND_EVENT_ERROR_PIN_NOT_SET: u32 = 0x80000008;

/// Credential service events intended to inform the UI.
#[derive(Debug, PartialEq)]
pub enum BackgroundEvent {
    CeremonyCompleted,
    NeedsPin { attempts_left: Option<u32> },
    NeedsUserVerification { attempts_left: Option<u32> },
    NeedsUserPresence,
    SelectingCredential { creds: Vec<Credential> },

    HybridIdle,
    HybridStarted(OwnedFd),
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

/// Emitted when a client enters a PIN for the selected authenticator.
#[derive(Debug, SerializeDict, DeserializeDict, PartialEq, Type)]
#[zvariant(signature = "dict")]
pub struct ClientPinEnteredOptions {}

#[derive(Clone, Debug, Default, SerializeDict, DeserializeDict, PartialEq, Type, Value)]
#[zvariant(signature = "dict")]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
}

/// Emitted when an an authenticator presents multiple matching credentials, and
/// the user selects one of them.
#[derive(Clone, Debug, PartialEq, SerializeDict, DeserializeDict, Type)]
pub struct CredentialSelectedOptions {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Type)]
pub struct Device {
    pub id: String,
    pub transport: Transport,
}

/// Emitted when the backend is ready to start credential discovery.
#[derive(Debug, PartialEq, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct DiscoveryRequestedOptions {}

impl From<DiscoveryRequestedOptions> for UserInteractedEvent {
    fn from(_: DiscoveryRequestedOptions) -> Self {
        UserInteractedEvent::DiscoveryRequested
    }
}

#[derive(Debug, Clone)]
pub enum Error {
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
    /// The RP requires user verification, but the device has no PIN/Biometrics set.
    PinNotSet,
    // TODO: We may want to hide the details on this variant from the public API.
    /// Something went wrong with the credential service itself, not the authenticator.
    Internal(String),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticatorError => f.write_str("AuthenticatorError"),
            Self::PinNotSet => f.write_str("PinNotSet"),
            Self::NoCredentials => f.write_str("NoCredentials"),
            Self::CredentialExcluded => f.write_str("CredentialExcluded"),
            Self::PinAttemptsExhausted => f.write_str("PinAttemptsExhausted"),
            Self::Internal(s) => write!(f, "InternalError: {s}"),
        }
    }
}

impl TryFrom<&Value<'_>> for Error {
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

#[derive(Debug, PartialEq, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct NotifyNeedsPinOptions {}

#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct NotifyNeedsUserVerificationOptions {}

#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct NotifyNeedsUserPresenceOptions {}

#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct NotifySelectingCredentialOptions {}

#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct NotifyHybridStartedOptions {}

#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct NotifyHybridConnectingOptions {}

/// Emitted
#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct NotifyHybridConnectedOptions {}

#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct NotifyNfcConnectedOptions {}

#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct NotifyUsbConnectedOptions {}

#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub enum Operation {
    PublicKeyCreate,
    PublicKeyGet,
}

#[derive(Clone, Debug, PartialEq, SerializeDict, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub struct PortalBackendOptions {
    /// A token that can be used to activate the UI window.
    pub activation_token: Optional<String>,

    /// Top-level origin of the request if different from the origin.
    pub top_origin: Optional<String>,

    /// RP ID of the request. Required for WebAuthn/PublicKey requests.
    pub rp_id: Optional<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Type)]
#[zvariant(signature = "s")]
pub enum Transport {
    Ble,
    HybridLinked,
    HybridQr,
    Internal,
    Nfc,
    Usb,
}

impl TryInto<Transport> for String {
    type Error = String;

    fn try_into(self) -> Result<Transport, String> {
        let value: &str = self.as_ref();
        value.try_into()
    }
}

impl TryInto<Transport> for &str {
    type Error = String;

    fn try_into(self) -> Result<Transport, String> {
        match self {
            "Ble" => Ok(Transport::Ble),
            "HybridLinked" => Ok(Transport::HybridLinked),
            "HybridQr" => Ok(Transport::HybridQr),
            "Internal" => Ok(Transport::Internal),
            "Nfc" => Ok(Transport::Nfc),
            "Usb" => Ok(Transport::Usb),
            _ => Err(format!("Unrecognized transport: {}", self.to_owned())),
        }
    }
}

impl From<Transport> for String {
    fn from(val: Transport) -> Self {
        val.as_str().to_string()
    }
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Ble => "Ble",
            Transport::HybridLinked => "HybridLinked",
            Transport::HybridQr => "HybridQr",
            Transport::Internal => "Internal",
            Transport::Nfc => "Nfc",
            Transport::Usb => "Usb",
        }
    }
}

pub enum UserInteractedEvent {
    /// Start discovery
    DiscoveryRequested,

    /// Send client PIN. Length of the PIN MUST not be greater than 63 bytes.
    /// File descriptor must be memory-mapped to be read.
    ClientPinEntered(OwnedFd),

    /// Select a credential by credential ID
    CredentialSelected(String),

    RequestCancelled,
}

impl std::fmt::Debug for UserInteractedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DiscoveryRequested => write!(f, stringify!(DiscoveryRequested)),
            Self::ClientPinEntered(_) => f
                .debug_tuple(stringify!(ClientPinEntered))
                .field(&"******".to_string())
                .finish(),
            Self::CredentialSelected(arg0) => f
                .debug_tuple(stringify!(CredentialSelected))
                .field(arg0)
                .finish(),
            Self::RequestCancelled => write!(f, stringify!(RequestCancelled)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Type)]
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
