use std::time::Duration;

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use libwebauthn::{fido::AuthenticatorDataFlags, proto::ctap2::{Ctap2AttestationStatement, Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType, Ctap2Transport}};
use ring::digest;
use serde::Deserialize;
use serde_json::json;
use tracing::debug;
use zbus::zvariant::{DeserializeDict, Type};

use crate::cose::{CoseKeyAlgorithmIdentifier, CoseKeyType};

#[derive(Debug)]
pub enum Error {
    Unknown,
    NotSupported,
    InvalidState,
    NotAllowed,
    Constraint,
    Internal(String),
}


pub(crate) fn create_attested_credential_data(
    credential_id: &[u8],
    public_key: &[u8],
    aaguid: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut attested_credential_data: Vec<u8> = Vec::new();
    if aaguid.len() != 16 {
        return Err(Error::Unknown);
    }
    attested_credential_data.extend(aaguid);
    let cred_length: u16 = TryInto::<u16>::try_into(credential_id.len()).unwrap();
    let cred_length_bytes: Vec<u8> = cred_length.to_be_bytes().to_vec();
    attested_credential_data.extend(&cred_length_bytes);
    attested_credential_data.extend(credential_id);
    attested_credential_data.extend(public_key);
    Ok(attested_credential_data)
}

pub (crate) fn create_authenticator_data(
    rp_id_hash: &[u8],
    flags: &AuthenticatorDataFlags,
    signature_counter: u32,
    attested_credential_data: Option<&[u8]>,
    processed_extensions: Option<&[u8]>,
) -> Vec<u8> {
    let mut authenticator_data: Vec<u8> = Vec::new();
    authenticator_data.extend(rp_id_hash);

    authenticator_data.push(flags.bits());

    authenticator_data.extend(signature_counter.to_be_bytes());

    if let Some(attested_credential_data) = attested_credential_data {
        authenticator_data.extend(attested_credential_data);
    }

    if processed_extensions.is_some() {
        todo!("Implement processed extensions");
        // TODO: authenticator_data.append(processed_extensions.to_bytes());
    }
    authenticator_data
}

pub(crate) fn create_attestation_object(
    authenticator_data: &[u8],
    attestation_statement:&AttestationStatement,
    _enterprise_attestation_possible: bool,
) -> Result<Vec<u8>, Error> {
    let mut attestation_object = Vec::new();
    let mut cbor_writer = crate::cbor::CborWriter::new(&mut attestation_object);
    cbor_writer.write_map_start(3).unwrap();
    cbor_writer.write_text("fmt").unwrap();
    match attestation_statement {
        AttestationStatement::Packed { algorithm, signature, certificates }  => {
            cbor_writer.write_text("packed").unwrap();
            cbor_writer.write_text("attStmt").unwrap();
            let len = if certificates.is_empty() { 2 } else { 3 };
            cbor_writer.write_map_start(len).unwrap();
            cbor_writer.write_text("alg").unwrap();
            cbor_writer.write_number((*algorithm).into()).unwrap();
            cbor_writer.write_text("sig").unwrap();
            cbor_writer.write_bytes(signature).unwrap();
            if !certificates.is_empty() {
                cbor_writer.write_text("x5c").unwrap();
                cbor_writer.write_array_start(certificates.len()).unwrap();
                for cert in certificates.iter() {
                    cbor_writer.write_bytes(cert).unwrap();
                }
            }
        },
        AttestationStatement::None => {
            cbor_writer.write_text("none").unwrap();
            cbor_writer.write_text("attStmt").unwrap();
            cbor_writer.write_map_start(0).unwrap();
        }
    };

    cbor_writer.write_text("authData").unwrap();
    cbor_writer.write_bytes(authenticator_data).unwrap();

    Ok(attestation_object)
}


#[derive(Deserialize)]
pub(crate) struct RelyingParty {
    pub name: String,
    pub id: String,
}

/// https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params
#[derive(Deserialize)]
pub(crate) struct User {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

struct Assertion {}

/*
#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub(crate) struct ClientData {
    client_data_type: String,
    challenge: String,
    origin: String,
    cross_origin: bool,
    token_binding: Option<TokenBinding>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub(crate) struct TokenBinding {
    status: String,
    id: Option<String>,
}
*/

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub(crate) struct AssertionOptions {
    user_verification: Option<bool>,
    user_presence: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct MakeCredentialOptions {
    /// Timeout in milliseconds
    pub timeout: Option<Duration>,
    #[serde(rename = "excludedCredentials")]
    pub excluded_credentials: Option<Vec<CredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// https://www.w3.org/TR/webauthn-3/#enum-attestation-convey
    pub attestation: Option<String>,
    /// extensions input as a JSON object
    #[serde(rename = "extensionData")]
    pub extension_data: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct GetCredentialOptions {
    /// Challenge bytes in base64url-encoding with no padding.
    pub(crate) challenge: String,

    #[serde(deserialize_with = "crate::serde::duration::from_opt_ms")]
    #[serde(default)]
    pub(crate) timeout: Option<Duration>,

    /// Relying Party ID.
    /// If not set, the request origin's effective domain will be used instead.
    #[serde(rename = "rpId")]
    pub(crate) rp_id: Option<String>,

    /// An list of allowed credentials, in descending order of RP preference.
    /// If empty, then any credential that can fulfill the request is allowed.
    #[serde(rename = "allowCredentials")]
    #[serde(default)]
    pub(crate) allow_credentials: Vec<CredentialDescriptor>,

    /// Defaults to `preferred`
    #[serde(rename = "userVerification")]
    pub(crate) user_verification: Option<String>,

    /// Contextual information from the RP to help the client guide the user
    /// through the authentication ceremony.
    #[serde(default)]
    pub(crate) hints: Vec<String>,

    extensions: Option<()>,
}


// pub(crate) struct CredentialList(Vec<CredentialDescriptor>);


#[derive(Deserialize, Type)]
#[zvariant(signature = "dict")]
/// https://www.w3.org/TR/webauthn-3/#dictionary-credential-descriptor
pub(crate) struct CredentialDescriptor {
    /// Type of the public key credential the caller is referring to.
    ///
    /// The value SHOULD be a member of PublicKeyCredentialType but client
    /// platforms MUST ignore any PublicKeyCredentialDescriptor with an unknown
    /// type.
    #[serde(rename = "type")]
    pub(crate) cred_type: String,
    /// Credential ID of the public key credential the caller is referring to.
    #[serde(with = "crate::serde::b64")]
    pub(crate) id: Vec<u8>,
    pub(crate) transports: Option<Vec<String>>,
}

impl TryFrom<&CredentialDescriptor> for Ctap2PublicKeyCredentialDescriptor {
    type Error = Error;
    fn try_from(value: &CredentialDescriptor) -> Result<Self, Self::Error> {
        let transports = value.transports.as_ref().filter(|t| !t.is_empty());
        let transports =  match transports {
            Some(transports) => {
                let mut transport_list = transports.iter().map(|t| match t.as_ref() {
                    "ble" => Some(Ctap2Transport::BLE),
                    "nfc" => Some(Ctap2Transport::NFC),
                    "usb" => Some(Ctap2Transport::USB),
                    "internal" => Some(Ctap2Transport::INTERNAL),
                    _ => None,
                });
                if transport_list.any(|t| t.is_none()) {
                    return Err(Error::Internal("Invalid transport type specified".to_owned()));
                }
                transport_list.collect()
            },
            None => None,
        };
        Ok(Self {
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            id: value.id.clone().into(),
            transports,
        })
    }
}
impl TryFrom<CredentialDescriptor> for Ctap2PublicKeyCredentialDescriptor {
    type Error = Error;
    fn try_from(value: CredentialDescriptor) -> Result<Self, Self::Error> {
        Ctap2PublicKeyCredentialDescriptor::try_from(&value)
    }
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
/// https://www.w3.org/TR/webauthn-3/#dictionary-authenticatorSelection
pub(crate) struct AuthenticatorSelectionCriteria {
    /// https://www.w3.org/TR/webauthn-3/#enum-attachment
    #[zvariant(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,

    /// https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement
    #[zvariant(rename = "residentKey")]
    pub resident_key: Option<String>,

    // Implied by resident_key == "required", deprecated in webauthn
    // https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement
    // #[zvariant(rename = "requireResidentKey")]
    // require_resident_key: Option<bool>,
    /// https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement
    #[zvariant(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Clone, Deserialize)]
/// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters
pub(crate) struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i64,
}

impl PublicKeyCredentialParameters {
    pub(crate) fn new(alg: i64) -> Self {
        Self { cred_type: "public-key".to_string(), alg }
    }
}

impl TryFrom<&PublicKeyCredentialParameters> for Ctap2CredentialType {
    type Error = Error;

    fn try_from(value: &PublicKeyCredentialParameters) -> Result<Self, Self::Error> {
        let algorithm = match value.alg {
            -7 => libwebauthn::proto::ctap2::Ctap2COSEAlgorithmIdentifier::ES256,
            -8 => libwebauthn::proto::ctap2::Ctap2COSEAlgorithmIdentifier::EDDSA,
            // TODO: we should still pass on the raw value to the authenticator and let it decide whether it's supported.
            _ => return Err(Error::Internal("Invalid algorithm passed for new credential".to_owned())),
        };
        Ok(Self {
            public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
            algorithm,
        })
    }
}

impl TryFrom<&PublicKeyCredentialParameters> for CoseKeyType {
    type Error = String;
    fn try_from(value: &PublicKeyCredentialParameters) -> Result<Self, Self::Error> {
        match value.alg {
            -7 => Ok(CoseKeyType::ES256_P256),
            -8 => Ok(CoseKeyType::EDDSA_ED25519),
            -257 => Ok(CoseKeyType::RS256),
            _ => Err("Invalid or unsupported algorithm specified".to_owned()),
        }
    }
}

impl TryFrom<PublicKeyCredentialParameters> for CoseKeyType {
    type Error = String;
    fn try_from(value: PublicKeyCredentialParameters) -> Result<Self, Self::Error> {
        CoseKeyType::try_from(&value)
    }
}

#[derive(Clone)]
pub struct CredentialSource {
    pub cred_type: PublicKeyCredentialType,

    /// A probabilistically-unique byte sequence identifying a public key
    /// credential source and its authentication assertions.
    pub id: Vec<u8>,

    /// The credential private key
    pub private_key: Vec<u8>,

    pub key_parameters: PublicKeyCredentialParameters,

    /// The Relying Party Identifier, for the Relying Party this public key
    /// credential source is scoped to.
    pub rp_id: String,

    /// The user handle is specified by a Relying Party, as the value of
    /// `user.id`, and used to map a specific public key credential to a specific
    /// user account with the Relying Party. Authenticators in turn map RP IDs
    /// and user handle pairs to public key credential sources.
    ///
    /// A user handle is an opaque byte sequence with a maximum size of 64
    /// bytes, and is not meant to be displayed to the user.
    pub user_handle: Option<Vec<u8>>,

    // Any other information the authenticator chooses to include.
    /// other information used by the authenticator to inform its UI. For
    /// example, this might include the user’s displayName. otherUI is a
    /// mutable item and SHOULD NOT be bound to the public key credential
    /// source in a way that prevents otherUI from being updated.
    pub other_ui: Option<String>,
}

impl CredentialSource {
    pub(crate) fn rp_id_hash<'a> (&'a self) -> Vec<u8> {
        let hash = digest::digest(&digest::SHA256, self.rp_id.as_bytes());
        hash.as_ref().to_owned()
    }
}

#[derive(Clone)]
pub(crate) enum PublicKeyCredentialType {
    PublicKey,
}

#[derive(Debug, PartialEq)]
pub(crate) enum AttestationStatementFormat {
    None,
    Packed,
}


#[derive(Debug, PartialEq)]
pub(crate) enum AttestationStatement {
    None,
    Packed {
        algorithm: CoseKeyAlgorithmIdentifier,
        signature: Vec<u8>,
        certificates: Vec<Vec<u8>>,
    },
}

impl TryFrom<&Ctap2AttestationStatement> for AttestationStatement {
    type Error = Error;

    fn try_from(value: &Ctap2AttestationStatement) -> Result<Self, Self::Error> {
        match value {
            Ctap2AttestationStatement::None(_) => Ok(AttestationStatement::None),
            Ctap2AttestationStatement::PackedOrAndroid(att_stmt) => {
                let alg = att_stmt.algorithm.try_into().map_err(|_| Error::NotSupported)?;
                Ok(Self::Packed {
                    algorithm: alg,
                    signature: att_stmt.signature.as_ref().to_vec(),
                    certificates: att_stmt.certificates.iter().map(|c| c.as_ref().to_vec()).collect()
                })
            }
            _ => {
                debug!("Unsupported attestation type: {:?}", value);
                return Err(Error::NotSupported);
            }
        }
    }
}
pub struct CreatePublicKeyCredentialResponse {
    cred_type: String,

    /// Raw bytes of credential ID.
    raw_id: Vec<u8>,

    response: AttestationResponse,

    /// JSON string of extension output
    extensions: Option<String>,
}


/// Returned from a creation of a new public key credential.
pub struct AttestationResponse {
    /// clientDataJSON.
    client_data_json: String,

    /// Bytes containing authenticator data and an attestation statement.
    attestation_object: Vec<u8>,

    /// Transports that the authenticator is believed to support, or an
    /// empty sequence if the information is unavailable.
    ///
    /// Should be one of
    /// - `usb`
    /// - `nfc`
    /// - `ble`
    /// - `internal`
    ///
    /// but others may be specified.
    transports: Vec<String>,

    /// Encodes contextual bindings made by the authenticator. These bindings
    /// are controlled by the authenticator itself.
    authenticator_data: Vec<u8>,
}

impl CreatePublicKeyCredentialResponse {
    pub fn new(
        id: Vec<u8>,
        attestation_object: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data_json: String,
        transports: Option<Vec<String>>,
        extension_output_json: Option<String>,
    ) -> Self {
        Self {
            cred_type: "public-key".to_string(),
            raw_id: id,
            response: AttestationResponse {
                client_data_json,
                attestation_object,
                transports: transports.unwrap_or_default(),
                authenticator_data,
            },
            extensions: extension_output_json,
        }
    }

    pub fn get_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.raw_id)
    }

    pub fn to_json(&self) -> String {
        let response = json!({
            "clientDataJSON": self.response.client_data_json,
            "attestationObject": URL_SAFE_NO_PAD.encode(&self.response.attestation_object),
            "transports": self.response.transports,
        });
        let mut output = json!({
            "id": self.get_id(),
            "rawId": self.get_id(),
            "response": response
        });
        if let Some(extensions) = &self.extensions {
            let extension_value =
                serde_json::from_str(extensions).expect("Extensions json to be formatted properly");
            output
                .as_object_mut()
                .unwrap()
                .insert("clientExtensionResults".to_string(), extension_value);
        }
        output.to_string()
    }
}

pub struct GetPublicKeyCredentialResponse {
    pub(crate) cred_type: String,

    /// clientDataJSON.
    pub(crate) client_data_json: String,

    /// Raw bytes of credential ID. Not returned if only one descriptor was
    /// passed in the allow credentials list.
    pub(crate) raw_id: Option<Vec<u8>>,

    /// Encodes contextual bindings made by the authenticator. These bindings
    /// are controlled by the authenticator itself.
    pub(crate) authenticator_data: Vec<u8>,

    pub(crate) signature: Vec<u8>,

    /// The user handle associated when this public key credential source was
    /// created. This item is nullable, however user handle MUST always be
    /// populated for discoverable credentials.
    pub(crate) user_handle: Option<Vec<u8>>,
}

impl GetPublicKeyCredentialResponse {
    pub(crate) fn new(client_data_json: String, id: Option<Vec<u8>>, authenticator_data: Vec<u8>, signature: Vec<u8>, user_handle: Option<Vec<u8>>) -> Self {
        Self {
            cred_type: "public-key".to_string(),
            client_data_json,
            raw_id: id,
            authenticator_data,
            signature,
            user_handle,
        }
    }
    pub fn to_json(&self) -> String {
        let response = json!({
            "clientDataJSON": self.client_data_json,
            "authenticatorData": URL_SAFE_NO_PAD.encode(&self.authenticator_data),
            "signature": URL_SAFE_NO_PAD.encode(&self.signature),
            "userHandle": self.user_handle.as_ref().map(|h| URL_SAFE_NO_PAD.encode(h))
        });
        // TODO: I believe this optional since authenticators may omit sending the credential ID if it was
        // unambiguously specified in the request. As a convenience, we should
        // always return a credential ID, even if the authenticator doesn't.
        // This means we'll have to remember the ID on the request if the allow-list has exactly one
        // credential descriptor, then we'll need. This should probably be done in libwebauthn.
        let id = self.raw_id.as_ref().map(|id| URL_SAFE_NO_PAD.encode(id));
        // TODO: Fix for platorm authenticator
        let attachment = "cross-platform";
        let output = json!({
            "id": id,
            "rawId": id,
            "authenticatorAttachment": attachment,
            "response": response
        });
        // TODO: support client extensions
        /*
        if let Some(extensions) = &self.extensions {
            let extension_value =
                serde_json::from_str(extensions).expect("Extensions json to be formatted properly");
            output
                .as_object_mut()
                .unwrap()
                .insert("clientExtensionResults".to_string(), extension_value);
        }
        */
        output.to_string()
    }
}
