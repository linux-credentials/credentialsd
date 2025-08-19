use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::FileExt,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use coset::{CborSerializable, CoseKey};
use credentialsd_common::model::{MakeCredentialRequest, MakeCredentialResponse};
use libwebauthn::{
    pin::PinRequestReason,
    proto::{
        ctap1::apdu::{ApduRequest, ApduResponse},
        ctap2::{
            cbor::{CborRequest, CborResponse},
            Ctap2CommandCode,
        },
        CtapError,
    },
    transport::{
        device::SupportedProtocols, AuthTokenData, Channel, ChannelStatus, Ctap2AuthTokenStore,
        Device, Transport,
    },
    webauthn::{Error, PlatformError, TransportError},
    PinRequiredUpdate, UvUpdate,
};
use passkey_authenticator::{
    Authenticator, CredentialStore, StoreInfo, UserCheck, UserValidationMethod,
};
use passkey_types::{
    ctap2::{
        get_assertion::Options,
        make_credential::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity},
        Aaguid, Ctap2Code, Ctap2Error, StatusCode, VendorError,
    },
    webauthn::PublicKeyCredentialDescriptor,
    Bytes, CredentialExtensions, Passkey,
};
use tokio::sync::{broadcast, mpsc, Mutex as AsyncMutex};

fn create_passkey(
    request: &MakeCredentialRequest,
) -> Result<MakeCredentialResponse, Box<dyn std::error::Error>> {
    request;
    todo!()
}

pub struct InternalTransport;
impl Transport for InternalTransport {}
impl Display for InternalTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Internal")
    }
}

/// A reference to the authenticator
pub struct PlatformAuthenticator {
    uid: u32,
}

impl PlatformAuthenticator {
    pub fn new(uid: u32) -> Self {
        Self { uid }
    }
}

#[async_trait]
impl<'d> Device<'d, InternalTransport, PlatformAuthenticatorChannel<'d>> for PlatformAuthenticator {
    async fn channel(&'d mut self) -> Result<PlatformAuthenticatorChannel<'d>, Error> {
        let (sender, _) = broadcast::channel(256);
        let (ctap_responder_tx, ctap_responder_rx) = mpsc::channel(1);
        let base_dir = {
            let mut dir = match std::env::var("XDG_DATA_HOME") {
                Ok(data_home) => PathBuf::from(data_home),
                Err(_) => {
                    let mut path = PathBuf::from(std::env::var("HOME").unwrap());
                    path.push(".local/state");
                    path
                }
            };
            dir.push("credentialsd");
            dir.push(self.uid.to_string());
            dir.push("creds");
            dir
        };

        let authenticator = Authenticator::new(
            Aaguid::new_empty(),
            FileCredentialStore { base_dir },
            UserValidationHandler {
                update_tx: sender.clone(),
            },
        );
        Ok(PlatformAuthenticatorChannel {
            device: self,
            ux_update_sender: sender,
            auth_token_data: None,
            responder_rx: Arc::new(AsyncMutex::new(ctap_responder_rx)),
            response_handle: Arc::new(AsyncMutex::new((authenticator, ctap_responder_tx))),
        })
    }
}

impl Display for PlatformAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Platform Authenticator")
    }
}

pub struct PlatformAuthenticatorChannel<'a> {
    device: &'a PlatformAuthenticator,
    ux_update_sender: broadcast::Sender<PlatformUxUpdate>,
    auth_token_data: Option<AuthTokenData>,
    responder_rx: Arc<AsyncMutex<mpsc::Receiver<CborResponse>>>,
    response_handle: Arc<
        AsyncMutex<(
            Authenticator<FileCredentialStore, UserValidationHandler>,
            mpsc::Sender<CborResponse>,
        )>,
    >,
}

impl PlatformAuthenticatorChannel<'_> {
    fn get_ux_update_receiver(&self) -> broadcast::Receiver<PlatformUxUpdate> {
        self.ux_update_sender.subscribe()
    }
}

#[async_trait]
impl Channel for PlatformAuthenticatorChannel<'_> {
    type UxUpdate = PlatformUxUpdate;

    fn get_ux_update_sender(&self) -> &broadcast::Sender<Self::UxUpdate> {
        &self.ux_update_sender
    }

    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        Ok(SupportedProtocols {
            u2f: false,
            fido2: true,
        })
    }

    async fn status(&self) -> ChannelStatus {
        ChannelStatus::Ready
    }

    async fn close(&mut self) {
        todo!()
    }

    async fn apdu_send(&self, _request: &ApduRequest, _timeout: Duration) -> Result<(), Error> {
        Err(Error::Platform(PlatformError::NotSupported))
    }

    async fn apdu_recv(&self, _timeout: Duration) -> Result<ApduResponse, Error> {
        Err(Error::Platform(PlatformError::NotSupported))
    }

    async fn cbor_send(&mut self, request: &CborRequest, timeout: Duration) -> Result<(), Error> {
        tracing::debug!("cbor_send called: {request:?}");
        let response_handle = self.response_handle.clone();
        let request = request.clone();
        let task = async move {
            let mut response_handle = response_handle.lock().await;
            let (ref mut authenticator, ref responder_tx) = *response_handle;
            let response = handle_request(authenticator, &request).await;
            responder_tx.send(response).await.unwrap();
        };
        tokio::time::timeout(timeout, task)
            .await
            .map_err(|_| Error::Transport(TransportError::Timeout))?;
        Ok(())
    }

    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, Error> {
        tracing::debug!("cbor_recv called");
        tokio::time::timeout(timeout, async move {
            if let Some(response) = self.responder_rx.lock().await.recv().await {
                tracing::debug!("received response from handler, sending {response:?}");
                Ok(response)
            } else {
                Err(Error::Platform(PlatformError::InvalidDeviceResponse))
            }
        })
        .await
        .map_err(|_| Error::Transport(TransportError::Timeout))
        .and_then(|response| response)
    }

    fn supports_preflight() -> bool {
        false
    }
}

async fn handle_request(
    authenticator: &mut Authenticator<FileCredentialStore, UserValidationHandler>,
    request: &CborRequest,
) -> CborResponse {
    match request.command {
        Ctap2CommandCode::AuthenticatorGetInfo => {
            let info = authenticator.get_info().await;
            let data = serde_cbor_2::to_vec(&info).unwrap();
            CborResponse {
                status_code: CtapError::Ok,
                data: Some(data),
            }
        }
        Ctap2CommandCode::AuthenticatorMakeCredential => {
            let make_request: passkey_types::ctap2::make_credential::Request =
                serde_cbor_2::from_slice(&request.encoded_data).unwrap();
            let make_response = authenticator.make_credential(make_request).await.unwrap();
            CborResponse {
                status_code: CtapError::Ok,
                data: Some(serde_cbor_2::to_vec(&make_response).unwrap()),
            }
        }
        Ctap2CommandCode::AuthenticatorGetAssertion => {
            let get_request = serde_cbor_2::from_slice(&request.encoded_data).unwrap();
            match authenticator.get_assertion(get_request).await {
                Ok(get_response) => CborResponse {
                    status_code: CtapError::Ok,
                    data: Some(serde_cbor_2::to_vec(&get_response).unwrap()),
                },
                Err(StatusCode::Ctap2(Ctap2Code::Known(Ctap2Error::NoCredentials))) => {
                    CborResponse {
                        status_code: CtapError::NoCredentials,
                        data: None,
                    }
                }
                Err(err) => {
                    tracing::error!("Received unknown CTAP2 error from authenticator: {:?}", err);
                    CborResponse {
                        status_code: CtapError::Other,
                        data: None,
                    }
                }
            }
        }
        Ctap2CommandCode::AuthenticatorGetNextAssertion => {
            todo!()
        }
        Ctap2CommandCode::AuthenticatorSelection => {
            todo!()
        }
        Ctap2CommandCode::AuthenticatorClientPin => {
            todo!()
        }

        _ => CborResponse {
            status_code: CtapError::InvalidCommand,
            data: None,
        },
    }
}

impl Display for PlatformAuthenticatorChannel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.device, f)
    }
}

impl Ctap2AuthTokenStore for PlatformAuthenticatorChannel<'_> {
    fn store_auth_data(&mut self, auth_token_data: AuthTokenData) {
        self.auth_token_data = Some(auth_token_data);
    }

    fn get_auth_data(&self) -> Option<&AuthTokenData> {
        self.auth_token_data.as_ref()
    }

    fn clear_uv_auth_token_store(&mut self) {
        self.auth_token_data = None;
    }
}

#[derive(Debug, Clone)]
pub enum PlatformUxUpdate {
    PinRequired(PinRequiredUpdate),
    Error(TransportError),
}

impl From<UvUpdate> for PlatformUxUpdate {
    fn from(value: UvUpdate) -> Self {
        match value {
            UvUpdate::PinRequired(pin_request) => Self::PinRequired(pin_request),
            UvUpdate::UvRetry { .. } => {
                todo!("Platform authentication non-client PIN user verification is not currently implemented.")
            }
            UvUpdate::PresenceRequired => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                Self::PinRequired(PinRequiredUpdate {
                    reply_to: Arc::new(tx),
                    reason: PinRequestReason::RelyingPartyRequest,
                    attempts_left: None,
                })
                // unreachable!("Platform authenticator does not expect a separate authorization gesture for test of user presence.");
            }
        }
    }
}

struct UserValidationHandler {
    update_tx: broadcast::Sender<PlatformUxUpdate>,
}

#[async_trait]
impl UserValidationMethod for UserValidationHandler {
    type PasskeyItem = Passkey;

    async fn check_user<'a>(
        &self,
        _credential: Option<&'a Self::PasskeyItem>,
        presence: bool,
        verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        if presence || verification {
            let client_pin = "1234";
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.update_tx
                .send(PlatformUxUpdate::PinRequired(PinRequiredUpdate {
                    reply_to: Arc::new(tx),
                    reason: PinRequestReason::RelyingPartyRequest,
                    attempts_left: None,
                }))
                .map_err(|_| Ctap2Error::ActionTimeout)?;
            let pin = rx.await.map_err(|_| Ctap2Error::UserActionTimeout)?;
            if pin == client_pin {
                Ok(UserCheck {
                    presence: true,
                    verification: true,
                })
            } else {
                Err(Ctap2Error::PinInvalid)
            }
        } else {
            Ok(UserCheck {
                presence: false,
                verification: false,
            })
        }
    }

    fn is_presence_enabled(&self) -> bool {
        false
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        None
    }
}

struct FileCredentialStore {
    base_dir: PathBuf,
}

impl FileCredentialStore {
    fn get_rp_path(&self, rp_id: &str) -> PathBuf {
        let rp_id_hash = URL_SAFE_NO_PAD.encode(ring::digest::digest(
            &ring::digest::SHA256,
            &rp_id.as_bytes(),
        ));
        let mut rp_path = self.base_dir.clone();
        rp_path.push(rp_id_hash);
        rp_path
    }

    fn get_cred_path(&self, rp_id: &str, cred_id: &[u8]) -> PathBuf {
        let cred_id_encoded = URL_SAFE_NO_PAD.encode(cred_id);
        let mut cred_path = self.get_rp_path(rp_id);
        cred_path.push(cred_id_encoded);
        cred_path
    }

    fn get_cred_ids_for_rp(&self, rp_id: &str) -> Result<HashSet<Vec<u8>>, std::io::Error> {
        let path = self.get_rp_path(rp_id);
        let dir_entries = path.read_dir();
        match dir_entries {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HashSet::new()),
            Ok(dir_entries) => {
                let mut cred_ids = HashSet::new();
                for entry in dir_entries {
                    let e = entry?;
                    if e.file_type()?.is_file() {
                        let cred_id = e.file_name().into_string().map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidFilename,
                                "Filename is not a valid credential ID.".to_string(),
                            )
                        })?;

                        let raw_cred_id = URL_SAFE_NO_PAD.decode(&cred_id).map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidFilename,
                                format!("Filename is not a valid credential ID: {cred_id}"),
                            )
                        })?;

                        cred_ids.insert(raw_cred_id);
                    }
                }
                Ok(cred_ids)
            }
            Err(err) => Err(err),
        }
    }
}

#[async_trait]
impl CredentialStore for FileCredentialStore {
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        let cred_ids_for_rp = self.get_cred_ids_for_rp(rp_id).map_err(|_| {
            StatusCode::Ctap2(Ctap2Code::Vendor(VendorError::try_from(0xF0).unwrap()))
        })?;

        let existing_cred_ids: Vec<&[u8]> = ids
            .unwrap()
            .into_iter()
            .map(|cd| cd.id.as_slice())
            .filter(|cred_id| cred_ids_for_rp.contains(*cred_id))
            .collect();
        let passkeys: Vec<Passkey> = existing_cred_ids.iter()
            .filter_map(|cred_id| {
                    let path = self.get_cred_path(rp_id, cred_id);
                    let mut file = fs::File::open(&path).unwrap();
                    let mut header_buf = [0; 6];
                    file.read_exact(&mut header_buf).unwrap();
                    if &header_buf[..4] != b"CRED" {
                        tracing::warn!(
                            "Unrecognized file type {:?} encountered for {}, not reading key.",
                            &header_buf[..4],
                            path.to_str().unwrap()
                        );
                        return None;
                    } else if header_buf[4] != 1
                    /* public-key */
                    {
                        tracing::warn!(
                            "Unrecognized credential type {} encountered for {}, not reading key.",
                            header_buf[4],
                            path.to_str().unwrap()
                        );
                        return None;
                    } else if header_buf[5] != 1
                    /* public-key version 1 */
                    {
                        tracing::warn!(
                            "Unrecognized public key format version {} encountered for {}, not reading key.",
                            header_buf[5],
                            path.to_str().unwrap()
                        );
                        return None;
                    }
                    let counter_buf = &mut header_buf[..4];
                    file.read_exact(counter_buf).unwrap();
                    let counter = u32::from_be_bytes(counter_buf.try_into().unwrap());

                    let mut data = String::new();
                    file.read_to_string(&mut data).unwrap();
                    decode_credential_record(counter, data).ok()
            })
            .collect();
        Ok(passkeys)
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: PublicKeyCredentialUserEntity,
        rp: PublicKeyCredentialRpEntity,
        options: Options,
    ) -> Result<(), StatusCode> {
        match encode_credential_record(&cred, &rp, &user, &options) {
            Err(err) => {
                tracing::error!("Failed to encode credential record: {}", err);
                return Err(StatusCode::Ctap2(Ctap2Code::Vendor(
                    VendorError::try_from(0xF0).unwrap(),
                )));
            }
            Ok(data) => {
                let path = self.get_cred_path(&rp.id, cred.credential_id.as_slice());
                let parent_dir = path.parent().unwrap();
                if !parent_dir.is_dir() {
                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                }
                fs::write(path, data).unwrap();
                Ok(())
            }
        }
    }

    async fn update_credential(&mut self, cred: Passkey) -> Result<(), StatusCode> {
        // data we allow mutating is the counter.
        if let Some(counter) = cred.counter {
            let path = self.get_cred_path(&cred.rp_id, &cred.credential_id);
            match fs::File::options().write(true).open(path) {
                Err(err) => {
                    tracing::error!("Could not open credential file for update: {err}");
                    return Err(StatusCode::Ctap2(Ctap2Code::Vendor(
                        VendorError::try_from(0xF0).unwrap(),
                    )));
                }
                Ok(file) => {
                    // "CRED" |cred type | cred type version |
                    // | 0 -3 | 4        | 5                 |
                    file.write_at(&counter.to_be_bytes(), 6).unwrap();
                }
            }
        }
        Ok(())
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: passkey_authenticator::DiscoverabilitySupport::ForcedDiscoverable,
        }
    }
}

fn decode_credential_record(
    counter: u32,
    data: String,
) -> Result<Passkey, Box<dyn std::error::Error>> {
    let pairs: HashMap<_, _> = data
        .split('&')
        .map(|kv| {
            let (key, value) = kv.split_once('=').unwrap();
            (key, value)
        })
        .collect();
    let id = URL_SAFE_NO_PAD.decode(pairs["id"]).unwrap().into();
    let rp_id = pairs
        .get("rp_id")
        .ok_or_else(|| "No RP ID found".to_string())?
        .to_string();

    let user_handle = pairs
        .get("user_handle")
        .and_then(|h| URL_SAFE_NO_PAD.decode(h).ok())
        .map(Bytes::from);
    let hmac_secret = pairs
        .get("hmac_secret")
        .and_then(|b64| URL_SAFE_NO_PAD.decode(b64).ok())
        .map(|secret| passkey_types::StoredHmacSecret {
            cred_with_uv: secret,
            cred_without_uv: None,
        });
    let key = CoseKey::from_slice(&URL_SAFE_NO_PAD.decode(pairs["key"]).unwrap()).unwrap();
    /*
    let kid = URL_SAFE_NO_PAD.decode(pairs["kid"]).unwrap();
    let kty = iana::KeyType::from_i64(pairs["kty"].parse::<i64>().unwrap()).unwrap();
    if kty != iana::KeyType::EC2 {
        panic!("Unsupported key type");
    };
    let alg = iana::Algorithm::from_i64(pairs.get("alg").unwrap().parse::<i64>().unwrap()).unwrap();
    if alg != iana::Algorithm::ES256 {
        panic!("Unsupported algorithm type");
    };
    let x = URL_SAFE_NO_PAD.decode(pairs["x"]).unwrap();
    let y = URL_SAFE_NO_PAD.decode(pairs["y"]).unwrap();
    let d = URL_SAFE_NO_PAD.decode(pairs["d"]).unwrap();
    let key = CoseKeyBuilder::new_ec2_priv_key(iana::EllipticCurve::P_256, x, y, d)
        .key_id(kid)
        .add_key_op(iana::KeyOperation::Sign)
        .build();
    */
    Ok(Passkey {
        key,
        credential_id: id,
        rp_id,
        user_handle,
        counter: Some(counter),
        extensions: CredentialExtensions {
            hmac_secret: hmac_secret,
        },
    })
}

fn encode_credential_record(
    passkey: &Passkey,
    rp: &PublicKeyCredentialRpEntity,
    user: &PublicKeyCredentialUserEntity,
    options: &Options,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut pairs: HashMap<&str, String> = HashMap::new();
    pairs.insert(
        "id",
        URL_SAFE_NO_PAD.encode(passkey.credential_id.as_slice()),
    );
    pairs.insert("rp_id", passkey.rp_id.clone());
    if let Some(name) = &rp.name {
        pairs.insert("rp_name", name.clone());
    }

    if let Some(user_handle) = &passkey.user_handle {
        pairs.insert(
            "user_handle",
            URL_SAFE_NO_PAD.encode(user_handle.as_slice()),
        );
    }
    if let Some(username) = &user.name {
        pairs.insert("user_name", username.to_string());
    }
    if let Some(display_name) = &user.display_name {
        pairs.insert("user_display_name", display_name.to_string());
    }
    if let Some(url) = &user.icon_url {
        pairs.insert("user_icon_url", url.to_string());
    }
    if let Some(hmac_secret) = &passkey.extensions.hmac_secret {
        pairs.insert(
            "hmac_secret",
            URL_SAFE_NO_PAD.encode(&hmac_secret.cred_with_uv),
        );
    }
    pairs.insert("rk", options.rk.to_string());
    pairs.insert("up", options.up.to_string());
    pairs.insert("uv", options.uv.to_string());
    pairs.insert(
        "key",
        URL_SAFE_NO_PAD.encode(&passkey.key.clone().to_vec().unwrap()),
    );
    /*
    passkey.key.to_cbor_value()
    pairs["kid"] = URL_SAFE_NO_PAD.encode(passkey.key.key_id);
    pairs["kty"] = passkey.key.kty.
    pairs["alg"]
    */
    let mut buf = Vec::new();
    buf.write_all(b"CRED\x01\x01").unwrap(); // Credential file format, public-key, v1
    buf.write_all(&passkey.counter.unwrap_or(0).to_be_bytes())
        .unwrap();
    let mut count = pairs.len() - 1;
    for (k, v) in pairs.iter() {
        buf.write_all(k.as_bytes()).unwrap();
        buf.write(b"=").unwrap();
        let encoded = v.replace("%", "%25").replace("&", "%26");
        buf.write(encoded.as_bytes()).unwrap();
        if count > 0 {
            buf.write(b"&").unwrap();
            count -= 1;
        }
    }
    Ok(buf)
}
