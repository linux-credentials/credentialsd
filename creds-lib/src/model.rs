use std::fmt::Display;

use serde::{Deserialize, Serialize};
use zbus::zvariant::{SerializeDict, Type};

pub use libwebauthn::ops::webauthn::{
    Assertion, GetAssertionRequest, MakeCredentialRequest, MakeCredentialResponse,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
}

#[derive(Clone, Debug)]
pub enum CredentialRequest {
    CreatePublicKeyCredentialRequest(MakeCredentialRequest),
    GetPublicKeyCredentialRequest(GetAssertionRequest),
}

#[derive(Clone, Debug)]
pub enum CredentialResponse {
    CreatePublicKeyCredentialResponse(MakeCredentialResponseInternal),
    GetPublicKeyCredentialResponse(GetAssertionResponseInternal),
}

impl CredentialResponse {
    pub fn from_make_credential(
        response: &MakeCredentialResponse,
        transports: &[&str],
        modality: &str,
    ) -> CredentialResponse {
        CredentialResponse::CreatePublicKeyCredentialResponse(MakeCredentialResponseInternal::new(
            response.clone(),
            transports.iter().map(|s| s.to_string()).collect(),
            modality.to_string(),
        ))
    }

    pub fn from_get_assertion(assertion: &Assertion, modality: &str) -> CredentialResponse {
        CredentialResponse::GetPublicKeyCredentialResponse(GetAssertionResponseInternal::new(
            assertion.clone(),
            modality.to_string(),
        ))
    }
}

#[derive(Clone, Debug)]
pub struct MakeCredentialResponseInternal {
    pub ctap: MakeCredentialResponse,
    pub transport: Vec<String>,
    pub attachment_modality: String,
}

impl MakeCredentialResponseInternal {
    pub fn new(
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
pub struct GetAssertionResponseInternal {
    pub ctap: Assertion,
    pub attachment_modality: String,
}

impl GetAssertionResponseInternal {
    pub fn new(ctap: Assertion, attachment_modality: String) -> Self {
        Self {
            ctap,
            attachment_modality,
        }
    }
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

#[derive(Serialize, Deserialize)]
pub enum ViewUpdate {
    SetTitle(String),
    SetDevices(Vec<Device>),
    SetCredentials(Vec<Credential>),

    WaitingForDevice(Device),
    SelectingDevice,

    UsbNeedsPin { attempts_left: Option<u32> },
    UsbNeedsUserVerification { attempts_left: Option<u32> },
    UsbNeedsUserPresence,

    HybridNeedsQrCode(String),
    HybridConnecting,
    HybridConnected,

    Completed,
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
    SelectCredential {
        /// List of user-identities to decide which to use.
        creds: Vec<Credential>,
    },

    /// USB tapped, received credential
    Completed,

    /// Interaction with the authenticator failed.
    Failed(Error),
}

pub enum BackgroundEvent {
    UsbStateChanged(UsbState),
    HybridQrStateChanged(HybridState),
}

#[derive(Debug, Clone)]
pub enum Error {
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
    Internal(String),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticatorError => f.write_str("AuthenticatorError"),
            Self::NoCredentials => f.write_str("NoCredentials"),
            Self::PinAttemptsExhausted => f.write_str("PinAttemptsExhausted"),
            Self::Internal(s) => write!(f, "InternalError: {s}"),
        }
    }
}
