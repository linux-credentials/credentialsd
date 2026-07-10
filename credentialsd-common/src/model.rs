use std::fmt::Display;

use serde::{Deserialize, Serialize};
use zvariant::{DeserializeDict, Optional, OwnedFd, SerializeDict, Type};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Type)]
pub struct Device {
    pub id: String,
    pub transport: Transport,
}

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
    #[serde(rename = "BLE")]
    Ble,
    HybridLinked,
    HybridQr,
    Internal,
    #[serde(rename = "NFC")]
    Nfc,
    #[serde(rename = "USB")]
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
            "BLE" => Ok(Transport::Ble),
            "HybridLinked" => Ok(Transport::HybridLinked),
            "HybridQr" => Ok(Transport::HybridQr),
            "Internal" => Ok(Transport::Internal),
            "NFC" => Ok(Transport::Nfc),
            "USB" => Ok(Transport::Usb),
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
            Transport::Ble => "BLE",
            Transport::HybridLinked => "HybridLinked",
            Transport::HybridQr => "HybridQr",
            Transport::Internal => "Internal",
            Transport::Nfc => "NFC",
            Transport::Usb => "USB",
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
