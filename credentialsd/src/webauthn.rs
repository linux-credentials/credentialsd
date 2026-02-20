use std::{collections::HashMap, fmt::Display, str::FromStr, time::Duration};

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use libwebauthn::{
    ops::webauthn::{CredentialProtectionPolicy, MakeCredentialLargeBlobExtension},
    proto::ctap2::{
        Ctap2AttestationStatement, Ctap2CredentialType, Ctap2PublicKeyCredentialType,
        Ctap2Transport,
    },
};
use ring::digest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;

use credentialsd_common::model::Operation;

use crate::cose::{CoseKeyAlgorithmIdentifier, CoseKeyType};

pub use libwebauthn::ops::webauthn::{
    CredentialProtectionExtension, GetAssertionHmacOrPrfInput, GetAssertionLargeBlobExtension,
    GetAssertionRequest, GetAssertionRequestExtensions, MakeCredentialHmacOrPrfInput,
    MakeCredentialRequest, MakeCredentialsRequestExtensions, ResidentKeyRequirement,
    UserVerificationRequirement,
};
pub use libwebauthn::proto::ctap2::{
    Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};

#[derive(Debug)]
pub enum Error {
    Unknown,
    NotSupported,
    InvalidState,
    NotAllowed,
    Constraint,
    Internal(String),
}

pub(crate) fn create_attestation_object(
    authenticator_data: &[u8],
    attestation_statement: &AttestationStatement,
    _enterprise_attestation_possible: bool,
) -> Result<Vec<u8>, Error> {
    let mut attestation_object = Vec::new();
    let mut cbor_writer = crate::cbor::CborWriter::new(&mut attestation_object);
    cbor_writer.write_map_start(3).unwrap();
    cbor_writer.write_text("fmt").unwrap();
    match attestation_statement {
        AttestationStatement::Packed {
            algorithm,
            signature,
            certificates,
        } => {
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
        }
        AttestationStatement::U2F {
            signature,
            certificate,
        } => {
            cbor_writer.write_text("fido-u2f").unwrap();
            cbor_writer.write_text("attStmt").unwrap();
            cbor_writer.write_map_start(2).unwrap();
            cbor_writer.write_text("x5c").unwrap();
            cbor_writer.write_array_start(1).unwrap();
            cbor_writer.write_bytes(certificate).unwrap();
            cbor_writer.write_text("sig").unwrap();
            cbor_writer.write_bytes(signature).unwrap();
        }
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

#[derive(Debug, Deserialize)]
pub(crate) struct MakeCredentialOptions {
    /// Timeout in milliseconds
    #[serde(deserialize_with = "crate::serde::duration::from_opt_ms")]
    #[serde(default)]
    pub timeout: Option<Duration>,
    #[serde(rename = "excludeCredentials")]
    pub excluded_credentials: Option<Vec<CredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// https://www.w3.org/TR/webauthn-3/#enum-attestation-convey
    #[allow(dead_code)]
    pub attestation: Option<String>,
    /// extensions input as a JSON object
    pub extensions: Option<MakeCredentialExtensions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MakeCredentialExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_protection_policy: Option<CredentialProtectionPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_credential_protection_policy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlobExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<Prf>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct LargeBlobExtension {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support: Option<MakeCredentialLargeBlobExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    #[allow(dead_code)] // TODO: Not currently used, but we should eventually implement
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Prf {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) eval: Option<PRFValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) eval_by_credential: Option<HashMap<String, PRFValue>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PRFValue {
    // base64 encoded data
    pub first: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second: Option<String>,
}

impl PRFValue {
    pub(crate) fn decode(&self) -> libwebauthn::ops::webauthn::PRFValue {
        let mut res = libwebauthn::ops::webauthn::PRFValue::default();
        let first = URL_SAFE_NO_PAD.decode(&self.first).unwrap();
        let len_to_copy = std::cmp::min(first.len(), 32); // Determine how many bytes to copy
        res.first[..len_to_copy].copy_from_slice(&first[..len_to_copy]);
        if let Some(second) = self
            .second
            .as_ref()
            .map(|second| URL_SAFE_NO_PAD.decode(second).unwrap())
        {
            let len_to_copy = std::cmp::min(second.len(), 32); // Determine how many bytes to copy
            let mut res_second = [0u8; 32];
            res_second[..len_to_copy].copy_from_slice(&second[..len_to_copy]);
            res.second = Some(res_second);
        }
        res
    }
}

#[derive(Debug, Deserialize)]
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
    #[allow(dead_code)] // TODO: Not currently used, but we should eventually implement support for hints.
    #[serde(default)]
    pub(crate) hints: Vec<String>,

    pub(crate) extensions: Option<GetCredentialExtensions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetCredentialExtensions {
    // TODO: appid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_cred_blob: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlobExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<Prf>,
}

#[derive(Debug, Deserialize)]
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
        let transports = match transports {
            Some(transports) => {
                let mut transport_list = transports.iter().map(|t| match t.as_ref() {
                    "ble" => Some(Ctap2Transport::Ble),
                    "nfc" => Some(Ctap2Transport::Nfc),
                    "usb" => Some(Ctap2Transport::Usb),
                    "internal" => Some(Ctap2Transport::Internal),
                    _ => None,
                });
                if transport_list.any(|t| t.is_none()) {
                    return Err(Error::Internal(
                        "Invalid transport type specified".to_owned(),
                    ));
                }
                transport_list.collect()
            }
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

#[derive(Debug, Deserialize)]
/// https://www.w3.org/TR/webauthn-3/#dictionary-authenticatorSelection
pub(crate) struct AuthenticatorSelectionCriteria {
    // /// https://www.w3.org/TR/webauthn-3/#enum-attachment
    // #[zvariant(rename = "authenticatorAttachment")]
    // pub authenticator_attachment: Option<String>,
    //
    /// https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement
    #[serde(rename = "residentKey")]
    pub resident_key: Option<String>,

    // Implied by resident_key == "required", deprecated in webauthn
    // https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,

    /// https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Clone, Deserialize)]
/// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters
pub(crate) struct PublicKeyCredentialParameters {
    pub alg: i64,
}

impl TryFrom<&PublicKeyCredentialParameters> for Ctap2CredentialType {
    type Error = Error;

    fn try_from(value: &PublicKeyCredentialParameters) -> Result<Self, Self::Error> {
        let algorithm = match value.alg {
            -7 => libwebauthn::proto::ctap2::Ctap2COSEAlgorithmIdentifier::ES256,
            -8 => libwebauthn::proto::ctap2::Ctap2COSEAlgorithmIdentifier::EDDSA,
            // TODO: we should still pass on the raw value to the authenticator and let it decide whether it's supported.
            _ => {
                return Err(Error::Internal(
                    "Invalid algorithm passed for new credential".to_owned(),
                ))
            }
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
            -7 => Ok(CoseKeyType::Es256P256),
            -8 => Ok(CoseKeyType::EddsaEd25519),
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

#[derive(Debug, PartialEq)]
pub(crate) enum AttestationStatement {
    None,
    U2F {
        signature: Vec<u8>,
        certificate: Vec<u8>,
    },
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
                let alg = att_stmt
                    .algorithm
                    .try_into()
                    .map_err(|_| Error::NotSupported)?;
                Ok(Self::Packed {
                    algorithm: alg,
                    signature: att_stmt.signature.as_ref().to_vec(),
                    certificates: att_stmt
                        .certificates
                        .iter()
                        .map(|c| c.as_ref().to_vec())
                        .collect(),
                })
            }
            Ctap2AttestationStatement::FidoU2F(att_stmt) => Ok(Self::U2F {
                signature: att_stmt.signature.as_ref().to_vec(),
                certificate: att_stmt.certificate.to_vec(),
            }),
            _ => {
                debug!("Unsupported attestation type: {:?}", value);
                Err(Error::NotSupported)
            }
        }
    }
}

pub struct CreatePublicKeyCredentialResponse {
    /// Raw bytes of credential ID.
    raw_id: Vec<u8>,

    response: AttestationResponse,

    /// JSON string of extension output
    extensions: String,

    /// If the device used is builtin ("platform") or removable ("cross-platform", aka "roaming")
    attachment_modality: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPropertiesOutput {
    /// This OPTIONAL property, known abstractly as the resident key credential property (i.e., client-side discoverable credential property), is a Boolean value indicating whether the PublicKeyCredential returned as a result of a registration ceremony is a client-side discoverable credential. If rk is true, the credential is a discoverable credential. if rk is false, the credential is a server-side credential. If rk is not present, it is not known whether the credential is a discoverable credential or a server-side credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsLargeBlobOutputs {
    /// true if, and only if, the created credential supports storing large blobs. Only present in registration outputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    /// The opaque byte string that was associated with the credential identified by rawId. Only valid if read was true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<Vec<u8>>,
    /// A boolean that indicates that the contents of write were successfully stored on the authenticator, associated with the specified credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsPRFValues {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsPRFOutputs {
    /// true if, and only if, the one or two PRFs are available for use with the created credential. This is only reported during registration and is not present in the case of authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// The results of evaluating the PRF for the inputs given in eval or evalByCredential. Outputs may not be available during registration; see comments in eval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<AuthenticationExtensionsPRFValues>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePublicKeyExtensionsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredentialPropertiesOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<AuthenticationExtensionsLargeBlobOutputs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<AuthenticationExtensionsPRFOutputs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,
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
}

impl CreatePublicKeyCredentialResponse {
    pub fn new(
        id: Vec<u8>,
        attestation_object: Vec<u8>,
        client_data_json: String,
        transports: Option<Vec<String>>,
        extension_output_json: String,
        attachment_modality: String,
    ) -> Self {
        Self {
            raw_id: id,
            response: AttestationResponse {
                client_data_json,
                attestation_object,
                transports: transports.unwrap_or_default(),
            },
            extensions: extension_output_json,
            attachment_modality,
        }
    }

    pub fn get_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.raw_id)
    }

    pub fn to_json(&self) -> String {
        let response = json!({
            "clientDataJSON": URL_SAFE_NO_PAD.encode(self.response.client_data_json.as_bytes()),
            "attestationObject": URL_SAFE_NO_PAD.encode(&self.response.attestation_object),
            "transports": self.response.transports,
        });
        let extensions: serde_json::Value = serde_json::from_str(&self.extensions)
            .expect("Extensions json to be formatted properly");
        let output = json!({
            "id": self.get_id(),
            "rawId": self.get_id(),
            "response": response,
            "authenticatorAttachment": self.attachment_modality,
            "clientExtensionResults": extensions,
        });
        output.to_string()
    }
}

pub struct GetPublicKeyCredentialResponse {
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

    /// Whether the used device is "cross-platform" (aka "roaming", i.e.: can be
    /// removed from the platform) or is built-in ("platform").
    pub(crate) attachment_modality: String,

    /// Unsigned extension output
    /// Unlike CreatePublicKey, we can't use a directly serialized JSON string here,
    /// because we have to encode/decode the byte arrays for the JavaScript-communication
    pub(crate) extensions: Option<GetPublicKeyCredentialUnsignedExtensionsResponse>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPublicKeyCredentialHMACGetSecretOutput {
    // base64-encoded bytestring
    pub output1: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    // base64-encoded bytestring
    pub output2: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct GetPublicKeyCredentialLargeBlobOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    // base64-encoded bytestring
    pub blob: Option<String>,
    // Not yet supported
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub written: Option<bool>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct GetPublicKeyCredentialPrfOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<GetPublicKeyCredentialPRFValue>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct GetPublicKeyCredentialPRFValue {
    // base64-encoded bytestring
    pub first: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    // base64-encoded bytestring
    pub second: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct GetPublicKeyCredentialUnsignedExtensionsResponse {
    pub hmac_get_secret: Option<GetPublicKeyCredentialHMACGetSecretOutput>,
    pub large_blob: Option<GetPublicKeyCredentialLargeBlobOutput>,
    pub prf: Option<GetPublicKeyCredentialPrfOutput>,
}

// Unlike CreatePublicKey, for GetPublicKey, we have a lot of Byte arrays,
// so we need a lot of de/constructions, instead of serializing it directly
impl From<&libwebauthn::ops::webauthn::GetAssertionResponseUnsignedExtensions>
    for GetPublicKeyCredentialUnsignedExtensionsResponse
{
    fn from(value: &libwebauthn::ops::webauthn::GetAssertionResponseUnsignedExtensions) -> Self {
        Self {
            hmac_get_secret: value.hmac_get_secret.as_ref().map(|x| {
                GetPublicKeyCredentialHMACGetSecretOutput {
                    output1: URL_SAFE_NO_PAD.encode(x.output1),
                    output2: x.output2.map(|output2| URL_SAFE_NO_PAD.encode(output2)),
                }
            }),
            large_blob: value
                .large_blob
                .as_ref()
                .map(|x| GetPublicKeyCredentialLargeBlobOutput {
                    blob: x.blob.as_ref().map(|blob| URL_SAFE_NO_PAD.encode(blob)),
                }),
            prf: value.prf.as_ref().map(|x| GetPublicKeyCredentialPrfOutput {
                results: x
                    .results
                    .as_ref()
                    .map(|results| GetPublicKeyCredentialPRFValue {
                        first: URL_SAFE_NO_PAD.encode(results.first),
                        second: results.second.map(|second| URL_SAFE_NO_PAD.encode(second)),
                    }),
            }),
        }
    }
}

impl GetPublicKeyCredentialResponse {
    pub(crate) fn new(
        client_data_json: String,
        id: Option<Vec<u8>>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Option<Vec<u8>>,
        attachment_modality: String,
        extensions: Option<GetPublicKeyCredentialUnsignedExtensionsResponse>,
    ) -> Self {
        Self {
            client_data_json,
            raw_id: id,
            authenticator_data,
            signature,
            user_handle,
            attachment_modality,
            extensions,
        }
    }
    pub fn to_json(&self) -> String {
        let response = json!({
            "clientDataJSON": URL_SAFE_NO_PAD.encode(self.client_data_json.as_bytes()),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&self.authenticator_data),
            "signature": URL_SAFE_NO_PAD.encode(&self.signature),
            "userHandle": self.user_handle.as_ref().map(|h| URL_SAFE_NO_PAD.encode(h))
        });
        // TODO: I believe this optional since authenticators may omit sending the credential ID if it was
        // unambiguously specified in the request. As a convenience, we should
        // always return a credential ID, even if the authenticator doesn't.
        // This means we'll have to remember the ID on the request if the allow-list has exactly one
        // credential descriptor. This should probably be done in libwebauthn.
        let id = self.raw_id.as_ref().map(|id| URL_SAFE_NO_PAD.encode(id));

        let output = json!({
            "id": id,
            "rawId": id,
            "authenticatorAttachment": self.attachment_modality,
            "response": response,
            "clientExtensionResults": self.extensions,
        });
        output.to_string()
    }
}

pub fn create_client_data_hash(json: &str) -> Vec<u8> {
    digest::digest(&digest::SHA256, json.as_bytes())
        .as_ref()
        .to_owned()
}

pub fn format_client_data_json(
    op: Operation,
    challenge: &str,
    origin: &NavigationContext,
) -> String {
    let op_str = match op {
        Operation::Create => "webauthn.create",
        Operation::Get => "webauthn.get",
    };
    let mut client_data_json = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}""#,
        op_str,
        challenge,
        origin.origin()
    );
    if let Some(top_origin) = origin.top_origin() {
        client_data_json.push_str(&format!(
            r#","crossOrigin":true,"topOrigin":"{top_origin}"}}"#
        ));
    } else {
        client_data_json.push_str(r#","crossOrigin":false}"#);
    }
    client_data_json
}

/// An application ID conforming to the
/// [XDG desktop entry syntax][xdg-desktop-entry-name].
///
/// [xdg-desktop-entry-name]: https://specifications.freedesktop.org/desktop-entry/latest/file-naming.html
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AppId(String);

impl AsRef<str> for AppId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for AppId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // This algorithm could be made more efficient, but this is fairly readable.

        // begins with a letter
        match s.chars().nth(0) {
            Some(c) if c.is_ascii_alphabetic() => {}
            _ => return Err(()),
        };

        // alphanumeric and labels separated by dots
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(());
        }

        // All labels must be non-empty.
        if s.contains("..") {
            return Err(());
        }

        // ends with a valid label
        if s.ends_with('.') {
            return Err(());
        }
        Ok(AppId(s.to_string()))
    }
}

/// The origin of the client for the request.
#[derive(Debug, PartialEq)]
pub(crate) enum Origin {
    Https { host: String, port: Option<u16> },
    AppId(AppId),
}

impl Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::Https { host, port } => {
                write!(f, "https://{}", host)?;
                if let Some(port) = port {
                    write!(f, ":{port}")?;
                }
            }
            Origin::AppId(app_id) => write!(f, "app:{}", app_id.0)?,
        }
        Ok(())
    }
}

impl FromStr for Origin {
    type Err = OriginParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("https://") {
            let (host_candidate, port_candidate): (&str, Option<&str>) = rest
                .split_once(':')
                .map(|(h, p)| (h, Some(p)))
                .unwrap_or((rest, None));

            // begins with a letter
            match host_candidate.chars().nth(0) {
                Some(c) if c.is_ascii_alphabetic() => {}
                _ => return Err(OriginParseError::InvalidHost),
            };
            // alphanumeric with hyphens and labels separated by dots
            if !host_candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            {
                return Err(OriginParseError::InvalidHost);
            }
            // ends with a valid label
            if host_candidate.ends_with('.') {
                return Err(OriginParseError::InvalidHost);
            }
            let host = host_candidate.to_ascii_lowercase();

            let Ok(port) = port_candidate.map(|p| p.parse()).transpose() else {
                return Err(OriginParseError::InvalidPort);
            };

            Ok(Origin::Https { host, port })
        } else if let Some(app_id_candidate) = s.strip_prefix("app:") {
            let app_id = app_id_candidate
                .parse()
                .map_err(|_| OriginParseError::InvalidHost)?;
            Ok(Origin::AppId(app_id))
        } else {
            Err(OriginParseError::InvalidScheme)
        }
    }
}

/// The origin of the request, and its top-level origin, if it is cross-origin.
#[derive(Debug)]
pub(crate) enum NavigationContext {
    /// Represents a client context with a single origin is presented to the user.
    SameOrigin(Origin),

    /// Represents a client context where the origin of the request is nested within
    /// another parent context with a different origin.
    CrossOrigin((Origin, Origin)),
}

impl NavigationContext {
    /// Retrieve the origin from the context.
    pub(crate) fn origin(&self) -> &Origin {
        match self {
            NavigationContext::SameOrigin(origin) => origin,
            NavigationContext::CrossOrigin((origin, _)) => origin,
        }
    }

    /// Retrieves the top origin from the context, if any.
    pub(crate) fn top_origin(&self) -> Option<&Origin> {
        match self {
            NavigationContext::SameOrigin(_) => None,
            NavigationContext::CrossOrigin((_, ref top_origin)) => Some(top_origin),
        }
    }
}

#[derive(Debug)]
pub(crate) enum OriginParseError {
    InvalidScheme,
    InvalidHost,
    InvalidPort,
}

impl std::error::Error for OriginParseError {}

impl Display for OriginParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidScheme => f.write_str("Invalid scheme"),
            Self::InvalidHost => f.write_str("Invalid host"),
            Self::InvalidPort => f.write_str("Invalid port"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::webauthn::{Origin, OriginParseError};

    use super::{format_client_data_json, NavigationContext, Operation};
    #[test]
    fn test_same_origin_client_data_json_str() {
        let expected = r#"{"type":"webauthn.create","challenge":"abcd","origin":"https://example.com","crossOrigin":false}"#;
        let json = format_client_data_json(
            Operation::Create,
            "abcd",
            &NavigationContext::SameOrigin("https://example.com".parse().unwrap()),
        );
        assert_eq!(expected, json);
    }

    #[test]
    fn test_cross_origin_client_data_json_str() {
        let expected = r#"{"type":"webauthn.create","challenge":"abcd","origin":"https://example.com","crossOrigin":true,"topOrigin":"https://example.org"}"#;
        let json = format_client_data_json(
            Operation::Create,
            "abcd",
            &NavigationContext::CrossOrigin((
                "https://example.com".parse().unwrap(),
                "https://example.org".parse().unwrap(),
            )),
        );
        assert_eq!(expected, json);
    }

    fn check_https_origin(origin: &str, expected_host: &str, expected_port: Option<u16>) {
        let Origin::Https { host, port }: Origin = origin.parse().unwrap() else {
            panic!("Not an https origin");
        };
        assert_eq!(expected_host, host);
        assert_eq!(expected_port, port);
    }

    #[test]
    fn test_origin_parse_when_http_fails() {
        let err = "http://example.com".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::InvalidScheme));
    }

    #[test]
    fn test_origin_parse_https_origin_without_port_succeeds() {
        check_https_origin("https://example.com", "example.com", None);
    }

    #[test]
    fn test_origin_parse_https_with_port_succeeds() {
        check_https_origin("https://example.org:8443", "example.org", Some(8443));
    }

    #[test]
    fn test_origin_parse_with_trailing_slash_fails() {
        let err = "https://example.org/".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::InvalidHost));
    }

    #[test]
    fn test_origin_parse_with_port_and_path_fails() {
        let err = "https://example.org:8443/".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::InvalidPort));
    }

    #[test]
    fn test_origin_parse_with_invalid_characters_fails() {
        let err = "https://😭.edu:1234".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::InvalidHost));
    }

    #[test]
    fn test_origin_parse_app_id_succeeds() {
        let Origin::AppId(app_id) = "app:com.example.ExampleApp".parse::<Origin>().unwrap() else {
            panic!("not an app origin");
        };
        assert_eq!("com.example.ExampleApp", app_id.0);
    }
}
