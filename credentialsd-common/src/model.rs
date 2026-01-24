use std::fmt::Display;

use serde::{Deserialize, Serialize};
use zvariant::{Optional, SerializeDict, Type};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
}

#[derive(SerializeDict, Type)]
#[zvariant(signature = "dict", rename_all = "camelCase")]
pub struct GetClientCapabilitiesResponse {
    pub conditional_create: bool,
    pub conditional_get: bool,
    pub hybrid_transport: bool,
    pub passkey_platform_authenticator: bool,
    pub user_verifying_platform_authenticator: bool,
    pub related_origins: bool,
    pub signal_all_accepted_credentials: bool,
    pub signal_current_user_details: bool,
    pub signal_unknown_credential: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CredentialType {
    Passkey,
    // Password,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub transport: Transport,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub enum Operation {
    Create,
    Get,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Default, Clone, Serialize, Deserialize, Type)]
pub struct RequestingApplication {
    pub path_or_app_id: String,
    pub name: Optional<String>,
    pub pid: u32,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Type)]
pub struct RequestingParty {
    pub rp_id: String,
    pub origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViewUpdate {
    SetTitle((String, String)),
    SetDevices(Vec<Device>),
    SetCredentials(Vec<Credential>),

    WaitingForDevice(Device),
    SelectingDevice,

    UsbNeedsPin { attempts_left: Option<u32> },
    UsbNeedsUserVerification { attempts_left: Option<u32> },
    UsbNeedsUserPresence,

    NfcNeedsPin { attempts_left: Option<u32> },
    NfcNeedsUserVerification { attempts_left: Option<u32> },

    HybridNeedsQrCode(String),
    HybridConnecting,
    HybridConnected,

    Completed,
    Cancelled,
    Failed(String),
}

#[derive(Clone, Debug, Default)]
pub enum HybridState {
    /// Default state, not listening for hybrid transport.
    #[default]
    Idle,

    /// QR code flow is starting, awaiting QR code scan and BLE advert from phone.
    Started(String),

    /// BLE advert received, connecting to caBLE tunnel with shared secret.
    Connecting,

    /// Connected to device via caBLE tunnel.
    Connected,

    /// Credential received over tunnel.
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,

    /// Failed to receive a credential
    Failed,
}

/// Used to share public state between credential service and UI.
#[derive(Clone, Debug, Default)]
pub enum UsbState {
    /// Not polling for FIDO USB device.
    #[default]
    Idle,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

    // When we encounter multiple devices, we let all of them blink and continue
    // with the one that was tapped.
    SelectingDevice,

    /// USB device connected, prompt user to tap
    Connected,

    /// The device needs the PIN to be entered.
    NeedsPin {
        attempts_left: Option<u32>,
    },

    /// The device needs on-device user verification.
    NeedsUserVerification {
        attempts_left: Option<u32>,
    },

    /// The device needs evidence of user presence (e.g. touch) to release the credential.
    NeedsUserPresence,
    // TODO: implement cancellation
    // This isn't actually sent from the server.
    //UserCancelled,
    /// Multiple credentials have been found and the user has to select which to use
    SelectingCredential {
        /// List of user-identities to decide which to use.
        creds: Vec<Credential>,
    },

    /// USB tapped, received credential
    Completed,

    /// Interaction with the authenticator failed.
    Failed(Error),
}

/// Used to share public state between credential service and UI.
#[derive(Clone, Debug, Default)]
pub enum NfcState {
    /// Not polling for FIDO NFC device.
    #[default]
    Idle,

    /// Awaiting FIDO NFC device to connect.
    Waiting,

    /// USB device connected, prompt user to tap
    Connected,

    /// The device needs the PIN to be entered.
    NeedsPin { attempts_left: Option<u32> },

    /// The device needs on-device user verification.
    NeedsUserVerification { attempts_left: Option<u32> },

    // TODO: implement cancellation
    // This isn't actually sent from the server.
    //UserCancelled,
    /// Multiple credentials have been found and the user has to select which to use
    SelectingCredential {
        /// List of user-identities to decide which to use.
        creds: Vec<Credential>,
    },

    /// NFC tapped, received credential
    Completed,

    /// Interaction with the authenticator failed.
    Failed(Error),
}

#[derive(Clone, Debug)]
pub enum BackgroundEvent {
    UsbStateChanged(UsbState),
    HybridQrStateChanged(HybridState),
    NfcStateChanged(NfcState),
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

#[derive(Debug)]
pub enum WebAuthnError {
    /// The ceremony was cancelled by an AbortController. See § 5.6 Abort
    /// Operations with AbortSignal and § 1.3.4 Aborting Authentication
    /// Operations.
    AbortError,

    /// Either `residentKey` was set to required and no available authenticator
    /// supported resident keys, or `userVerification` was set to required and no
    /// available authenticator could perform user verification.
    ConstraintError,

    /// The authenticator used in the ceremony recognized an entry in
    /// `excludeCredentials` after the user consented to registering a credential.
    InvalidStateError,

    /// No entry in `pubKeyCredParams` had a type property of `public-key`, or the
    /// authenticator did not support any of the signature algorithms specified
    /// in `pubKeyCredParams`.
    NotSupportedError,

    /// The effective domain was not a valid domain, or `rp.id` was not equal to
    /// or a registrable domain suffix of the effective domain. In the latter
    /// case, the client does not support related origin requests or the related
    /// origins validation procedure failed.
    SecurityError,

    /// A catch-all error covering a wide range of possible reasons, including
    /// common ones like the user canceling out of the ceremony. Some of these
    /// causes are documented throughout this spec, while others are
    /// client-specific.
    NotAllowedError,

    /// The options argument was not a valid `CredentialCreationOptions` value, or
    /// the value of `user.id` was empty or was longer than 64 bytes.
    TypeError,
}

impl std::error::Error for WebAuthnError {}

impl Display for WebAuthnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            WebAuthnError::AbortError => "Operation was aborted by client.",
            WebAuthnError::ConstraintError => "Resident key or user verification requirement was not able to be met.",
            WebAuthnError::InvalidStateError => "A user consented to create a new credential after trying to use an authenticator with a previously registered credential.",
            WebAuthnError::NotSupportedError => "Operation parameters are not supported.",
            WebAuthnError::SecurityError => "Validation of the client context for given RP ID failed.",
            WebAuthnError::NotAllowedError => "An unspecified error occurred, and the operation is not allowed to continue.",
            WebAuthnError::TypeError => "Invalid parameters specified.",
        })
    }
}
