use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Credential {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) username: Option<String>,
}

#[derive(Debug)]
pub enum CredentialType {
    Passkey,
    // Password,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub transport: Transport,
}

#[derive(Debug)]
pub enum Operation {
    Create { cred_type: CredentialType },
    Get { cred_types: Vec<CredentialType> },
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

    // Multiple credentials have been found and the user has to select which to use
    // List of user-identities to decide which to use.
    SelectCredential {
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
