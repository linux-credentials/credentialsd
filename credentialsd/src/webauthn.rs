use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use libwebauthn::proto::ctap2::Ctap2AttestationStatement;
use serde::Serialize;
use serde_json::json;
use tracing::debug;

use crate::cose::CoseKeyAlgorithmIdentifier;

// Re-exports from libwebauthn
pub use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, RelyingPartyId, WebAuthnIDL,
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
                certificate: att_stmt
                    .certificates
                    .first()
                    .map(|c| c.as_ref().to_vec())
                    .unwrap_or_default(),
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

#[derive(Debug)]
pub(crate) enum Origin {
    AppId(String),
    SameOrigin(String),
    CrossOrigin((String, String)),
}

impl Origin {
    pub(crate) fn origin(&self) -> &str {
        &match self {
            Origin::AppId(app_id) => app_id,
            Origin::SameOrigin(origin) => origin,
            Origin::CrossOrigin((origin, _)) => origin,
        }
    }

    pub(crate) fn top_origin(&self) -> Option<&str> {
        match self {
            Origin::AppId(_) => None,
            Origin::SameOrigin(_) => None,
            Origin::CrossOrigin((_, ref top_origin)) => Some(top_origin),
        }
    }
}
