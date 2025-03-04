use std::{collections::HashMap, time::Duration};

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cose::{CoseKeyAlgorithmIdentifier, CoseKeyType, encode_public_key};
use libwebauthn::proto::ctap2::{Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType, Ctap2Transport};
use openssl::{pkey::PKey, rsa::Rsa};
use ring::{
    digest::{self, digest},
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, RsaKeyPair,
        ECDSA_P256_SHA256_ASN1_SIGNING, RSA_PKCS1_SHA256,
    },
};
use serde::Deserialize;
use serde_json::json;
use zbus::zvariant::{DeserializeDict, Type};

use crate::{cbor::CborWriter, store};

static P256: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_ASN1_SIGNING;
// static RNG: &Box<dyn SecureRandom> = &Box::new(SystemRandom::new());

const CAN_CREATE_DISCOVERABLE_CREDENTIAL: bool = true;

#[derive(Debug)]
pub enum Error {
    Unknown,
    NotSupported,
    InvalidState,
    NotAllowed,
    Constraint,
    Internal(String),
}

pub(crate) fn create_credential(
    origin: &str,
    options: &str,
    same_origin: bool,
) -> Result<(CreatePublicKeyCredentialResponse, CredentialSource, User), Error> {
    let request_value = serde_json::from_str::<serde_json::Value>(options)
        .map_err(|_| Error::Internal("Invalid request JSON".to_string()))?;
    let json = request_value
        .as_object()
        .ok_or_else(|| Error::Internal("Invalid request JSON".to_string()))?;
    let challenge = json
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or_else(|| Error::Internal("JSON missing `challenge` field".to_string()))?
        .to_owned();
    let rp = json
        .get("rp")
        .and_then(|val| serde_json::from_str::<RelyingParty>(&val.to_string()).ok())
        .ok_or_else(|| Error::Internal("JSON missing `rp` field".to_string()))?;
    let user = json
        .get("user")
        .ok_or(Error::Internal("JSON missing `user` field".to_string()))
        .and_then(|val| {
            serde_json::from_str::<User>(&val.to_string()).map_err(|e| {
                let msg = format!("JSON missing `user` field: {e}");
                Error::Internal(msg)
            })
        })?;
    let other_options = serde_json::from_str::<MakeCredentialOptions>(&request_value.to_string())
        .map_err(|_| Error::Internal("Invalid request JSON".to_string()))?;
    let (require_resident_key, require_user_verification) =
        if let Some(authenticator_selection) = other_options.authenticator_selection {
            let is_authenticator_storage_capable = true;
            let require_resident_key = authenticator_selection.resident_key.map_or_else(
                || false,
                |r| r == "required" || (r == "preferred" && is_authenticator_storage_capable),
            ); // fallback to authenticator_selection.require_resident_key == true for WebAuthn Level 1?

            let authenticator_can_verify_users = true;
            let require_user_verification = authenticator_selection.user_verification.map_or_else(
                || false,
                |r| r == "required" || (r == "preferred" && authenticator_can_verify_users),
            );

            (require_resident_key, require_user_verification)
        } else {
            (false, false)
        };
    let require_user_presence = true;
    let enterprise_attestation_possible = false;
    let extensions = None;
    let credential_parameters = request_value
        .clone()
        .get("pubKeyCredParams")
        .ok_or_else(|| {
            Error::Internal("Request JSON missing or invalid `pubKeyCredParams` key".to_string())
        })
        .and_then(|val| {
            serde_json::from_str::<Vec<PublicKeyCredentialParameters>>(&val.to_string()).map_err(
                |e| {
                    Error::Internal(format!(
                        "Request JSON missing or invalid `pubKeyCredParams` key: {e}"
                    ))
                },
            )
        })?;
    let excluded_credentials = other_options.excluded_credentials.unwrap_or(Vec::new());

    super::webauthn::make_credential(
        challenge,
        origin,
        !same_origin,
        rp,
        &user,
        require_resident_key,
        require_user_presence,
        require_user_verification,
        credential_parameters,
        excluded_credentials,
        enterprise_attestation_possible,
        extensions,
    )
    .map(|(response, cred_source)| (response, cred_source, user))
}

pub(crate) fn make_credential(
    challenge: String,
    origin: &str,
    cross_origin: bool,
    rp_entity: RelyingParty,
    user_entity: &User,
    require_resident_key: bool,
    require_user_presence: bool,
    require_user_verification: bool,
    cred_pub_key_algs: Vec<PublicKeyCredentialParameters>,
    exclude_credential_descriptor_list: Vec<CredentialDescriptor>,
    enterprise_attestation_possible: bool,
    extensions: Option<()>,
) -> Result<(CreatePublicKeyCredentialResponse, CredentialSource), Error> {
    // Before performing this operation, all other operations in progress in the authenticator session MUST be aborted by running the authenticatorCancel operation.
    // TODO:
    let supported_algorithms: [CoseKeyType; 3] = [
        CoseKeyType::ES256_P256,
        CoseKeyType::EdDSA_Ed25519,
        CoseKeyType::RS256,
    ];

    // When this operation is invoked, the authenticator MUST perform the following procedure:
    // Check if all the supplied parameters are syntactically well-formed and of the correct length. If not, return an error code equivalent to "UnknownError" and terminate the operation.
    let cross_origin_str = if cross_origin { "true" } else { "false" };
    let client_data_json = format!("{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":{cross_origin_str}}}");
    let client_data_hash = digest::digest(&digest::SHA256, client_data_json.as_bytes())
        .as_ref()
        .to_owned();
    if client_data_hash.len() != 32 {
        return Err(Error::Unknown);
    }
    if rp_entity.id.is_empty() || rp_entity.name.is_empty() {
        return Err(Error::Unknown);
    }
    if user_entity.id.is_empty() || user_entity.name.is_empty() {
        return Err(Error::Unknown);
    }

    // Check if at least one of the specified combinations of PublicKeyCredentialType and cryptographic parameters in credTypesAndPubKeyAlgs is supported. If not, return an error code equivalent to "NotSupportedError" and terminate the operation.
    let cred_pub_key_parameters = match cred_pub_key_algs
        .iter()
        .filter(|p| p.cred_type == "public-key")
        .find(|p| if let Ok(ref key_type) = (*p).try_into() {
            supported_algorithms.contains(key_type)
         } else {
            false
         })
    {
        Some(cred_pub_key_parameters) => cred_pub_key_parameters,
        None => return Err(Error::NotSupported),
    };

    // For each descriptor of excludeCredentialDescriptorList:
    for cd in exclude_credential_descriptor_list.iter() {
        // If looking up descriptor.id in this authenticator returns non-null,
        // and the returned item's RP ID and type match rpEntity.id and
        // excludeCredentialDescriptorList.type respectively, then collect an
        // authorization gesture confirming user consent for creating a new
        // credential. The authorization gesture MUST include a test of user
        // presence.
        if let Some((found, rp)) = lookup_stored_credentials(&cd.id) {
            if rp.id == rp_entity.id && found.cred_type == cd.cred_type {
                let has_consent: bool = ask_disclosure_consent();
                // If the user confirms consent to create a new credential
                if has_consent {
                    // return an error code equivalent to "InvalidStateError" and terminate the operation.
                    return Err(Error::InvalidState);
                }
                // does not consent to create a new credential
                else {
                    // return an error code equivalent to "NotAllowedError" and terminate the operation.
                    return Err(Error::NotAllowed);
                }
                // Note: The purpose of this authorization gesture is not to proceed with creating a credential, but for privacy reasons to authorize disclosure of the fact that descriptor.id is bound to this authenticator. If the user consents, the client and Relying Party can detect this and guide the user to use a different authenticator. If the user does not consent, the authenticator does not reveal that descriptor.id is bound to it, and responds as if the user simply declined consent to create a credential.
            }
        }
    }

    // If requireResidentKey is true and the authenticator cannot store a client-side discoverable public key credential source, return an error code equivalent to "ConstraintError" and terminate the operation.
    if require_resident_key && !CAN_CREATE_DISCOVERABLE_CREDENTIAL {
        return Err(Error::Constraint);
    }

    // If requireUserVerification is true and the authenticator cannot perform user verification, return an error code equivalent to "ConstraintError" and terminate the operation.
    if require_user_verification && !is_user_verification_available() {
        return Err(Error::Constraint);
    }
    // Collect an authorization gesture confirming user consent for creating a
    // new credential. The prompt for the authorization gesture is shown by the
    // authenticator if it has its own output capability, or by the user agent
    // otherwise. The prompt SHOULD display rpEntity.id, rpEntity.name,
    // userEntity.name and userEntity.displayName, if possible.
    // If requireUserVerification is true, the authorization gesture MUST include user verification.

    // If requireUserPresence is true, the authorization gesture MUST include a test of user presence.
    if collect_authorization_gesture(require_user_verification, require_user_presence).is_err() {
        // If the user does not consent or if user verification fails, return an error code equivalent to "NotAllowedError" and terminate the operation.
        return Err(Error::NotAllowed);
    }

    // Once the authorization gesture has been completed and user consent has been obtained, generate a new credential object:
    // Let (publicKey, privateKey) be a new pair of cryptographic keys using the combination of PublicKeyCredentialType and cryptographic parameters represented by the first item in credTypesAndPubKeyAlgs that is supported by this authenticator.
    let key_type = cred_pub_key_parameters.try_into().map_err(|_| Error::Unknown)?;
    let key_pair = create_key_pair(key_type)?;
    // Let userHandle be userEntity.id.
    let user_handle = URL_SAFE_NO_PAD
        .decode(user_entity.id.clone())
        .map_err(|_| Error::Unknown)?;

    // If requireResidentKey is true or the authenticator chooses to create a client-side discoverable public key credential source:
    // Let credentialId be a new credential id.
    // Note: We'll always create a discoverable credential, so generate a random credential ID.
    let credential_id: Vec<u8> = ring::rand::generate::<[u8; 16]>(&SystemRandom::new())
        .map_err(|_e| Error::Unknown)?
        .expose()
        .into();

    // Let credentialSource be a new public key credential source with the fields:
    let credential_source = CredentialSource {
        // type
        // public-key.
        cred_type: PublicKeyCredentialType::PublicKey,
        // Set credentialSource.id to credentialId.
        id: credential_id.to_vec(),
        // privateKey
        // privateKey
        private_key: key_pair.clone(),
        key_parameters: cred_pub_key_parameters.clone(),
        // rpId
        // rpEntity.id
        rp_id: rp_entity.id,
        // userHandle
        // userHandle
        user_handle: Some(user_handle),
        // otherUI
        // Any other information the authenticator chooses to include.
        other_ui: None,
    };

    // If any error occurred while creating the new credential object, return an error code equivalent to "UnknownError" and terminate the operation.

    // Let processedExtensions be the result of authenticator extension processing for each supported extension identifier → authenticator extension input in extensions.
    if let Some(extensions) = extensions {
        process_authenticator_extensions(extensions)
            .expect("Extension processing not yet supported");
    };

    // If the authenticator:

    let counter_type = WebAuthnDeviceCounterType::PerCredential;
    let signature_counter: u32 = match counter_type {
        // is a U2F device
        // let the signature counter value for the new credential be zero. (U2F devices may support signature counters but do not return a counter when making a credential. See [FIDO-U2F-Message-Formats].)
        WebAuthnDeviceCounterType::U2F => 0,
        // supports a global signature counter
        // Use the global signature counter's actual value when generating authenticator data.
        WebAuthnDeviceCounterType::Global => todo!(), // authenticator.sign_count
        // supports a per credential signature counter

        // allocate the counter, associate it with the new credential, and initialize the counter value as zero.
        WebAuthnDeviceCounterType::PerCredential => 0,
        // does not support a signature counter

        // let the signature counter value for the new credential be constant at zero.
        WebAuthnDeviceCounterType::Unsupported => 0,
    };

    // Let attestedCredentialData be the attested credential data byte array including the credentialId and publicKey.
    let aaguid = vec![0_u8; 16];
    let public_key = encode_public_key(key_type, &key_pair).map_err(|_| Error::Unknown)?;
    let attested_credential_data =
        create_attested_credential_data(&credential_id, &public_key, &aaguid)?;

    // Let authenticatorData be the byte array specified in § 6.1 Authenticator Data, including attestedCredentialData as the attestedCredentialData and processedExtensions, if any, as the extensions.
    let authenticator_data = create_authenticator_data(
        &credential_source,
        signature_counter,
        Some(&attested_credential_data),
        None,
    );

    // Create an attestation object for the new credential using the procedure specified in § 6.5.4 Generating an Attestation Object, using an authenticator-chosen attestation statement format, authenticatorData, and hash, as well as taking into account the value of enterpriseAttestationPossible. For more details on attestation, see § 6.5 Attestation.
    // TODO: attestation not supported for now
    let signature = sign_attestation(
        &authenticator_data,
        &client_data_hash,
        &key_pair,
        &key_type,
    )?;
    let attestation_object = create_attestation_object(
        key_type.algorithm(),
        &authenticator_data,
        &signature,
        enterprise_attestation_possible,
    )?;

    // On successful completion of this operation, the authenticator returns the attestation object to the client.
    let response = CreatePublicKeyCredentialResponse::new(
        credential_id,
        attestation_object,
        authenticator_data,
        client_data_json,
        None,
        None,
    );
    Ok((response, credential_source))
}

fn get_credential(

    rp_entity: RelyingParty,

    challenge: String,
    origin: &str,
    cross_origin: bool,
    top_origin: Option<String>,
    allow_credential_descriptor_list: Option<Vec<CredentialDescriptor>>,
    require_user_presence: bool,
    require_user_verification: bool,
    enterprise_attestation_possible: bool,
    attestation_formats: Vec<AttestationStatementFormat>,
    stored_credentials: HashMap<Vec<u8>, CredentialSource>,

    extensions: Option<()>,
) -> Result<GetPublicKeyCredentialResponse, Error> {
    // Note: Before performing this operation, all other operations in progress in the authenticator session MUST be aborted by running the authenticatorCancel operation.

    // When this method is invoked, the authenticator MUST perform the following procedure:

    // Check if all the supplied parameters are syntactically well-formed and of the correct length. If not, return an error code equivalent to "UnknownError" and terminate the operation.
    let cross_origin_str = if cross_origin { "true" } else { "false" };
    let client_data_json = format!("{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":{cross_origin_str}}}");
    let client_data_hash = digest::digest(&digest::SHA256, client_data_json.as_bytes())
        .as_ref()
        .to_owned();
    if client_data_hash.len() != 32 {
        return Err(Error::Unknown);
    }

    // Let credentialOptions be a new empty set of public key credential sources.
    // If allowCredentialDescriptorList was supplied, then for each descriptor of allowCredentialDescriptorList:
    let credential_options: Vec<&CredentialSource> = if let Some(ref allowed_credentials) = allow_credential_descriptor_list {
        // Let credSource be the result of looking up descriptor.id in this authenticator.
        // If credSource is not null, append it to credentialOptions.
        allowed_credentials.iter()
            .filter_map(|cred| stored_credentials.get(&cred.id))
            // Remove any items from credentialOptions whose rpId is not equal to rpId.
            .filter(|cred_source| cred_source.rp_id == rp_entity.id)
            .collect()
    }
    else {
        // Otherwise (allowCredentialDescriptorList was not supplied), for each key → credSource of this authenticator’s credentials map, append credSource to credentialOptions.
        stored_credentials
            .values()
            // Remove any items from credentialOptions whose rpId is not equal to rpId.
            .filter(|cred_source| cred_source.rp_id == rp_entity.id)
            .collect()
    };


    // If credentialOptions is now empty, return an error code equivalent to "NotAllowedError" and terminate the operation.
    if credential_options.is_empty() {
        return Err(Error::NotAllowed);
    }
    // Prompt the user to select a public key credential source selectedCredential from credentialOptions. Collect an authorization gesture confirming user consent for using selectedCredential. The prompt for the authorization gesture may be shown by the authenticator if it has its own output capability, or by the user agent otherwise.
        // TODO, already done? Move up to D-Bus call
        // If requireUserVerification is true, the authorization gesture MUST include user verification.
        // If requireUserPresence is true, the authorization gesture MUST include a test of user presence.
        // If the user does not consent, return an error code equivalent to "NotAllowedError" and terminate the operation.
    // TODO: pass selected_credential to this method
    let selected_credential = credential_options[0];
    // Let processedExtensions be the result of authenticator extension processing for each supported extension identifier → authenticator extension input in extensions.
    if let Some(extensions) = extensions {
        // TODO: support extensions
        process_authenticator_extensions(extensions)
            .expect("Processing extensions not supported yet.");
    }

    // Increment the credential associated signature counter or the global signature counter value, depending on which approach is implemented by the authenticator, by some positive value. If the authenticator does not implement a signature counter, let the signature counter value remain constant at zero.
    let signature_counter = 0;
    /*  TODO
    let counter_type = WebAuthnDeviceCounterType::PerCredential;
    let signature_counter: u32 = match counter_type {
        // is a U2F device
        // let the signature counter value for the new credential be zero. (U2F devices may support signature counters but do not return a counter when making a credential. See [FIDO-U2F-Message-Formats].)
        WebAuthnDeviceCounterType::U2F => 0,
        // supports a global signature counter
        // Use the global signature counter's actual value when generating authenticator data.
        WebAuthnDeviceCounterType::Global => todo!(), // authenticator.sign_count
        // supports a per credential signature counter

        // allocate the counter, associate it with the new credential, and initialize the counter value as zero.
        WebAuthnDeviceCounterType::PerCredential => cred_source.,
        // does not support a signature counter

        // let the signature counter value for the new credential be constant at zero.
        WebAuthnDeviceCounterType::Unsupported => 0,
    };
    */

    // If attestationFormats:
    // is not empty
    //     let attestationFormat be the first supported attestation statement format from attestationFormats, taking into account enterpriseAttestationPossible. If none are supported, fallthrough to:
    // is empty
    //     let attestationFormat be the attestation statement format most preferred by this authenticator. If it does not support attestation during assertion then let this be none.
    let supported_formats = [AttestationStatementFormat::Packed];
    let preferred_format = AttestationStatementFormat::None;
    let attestation_format = attestation_formats.iter().find(|f| supported_formats.contains(f)).unwrap_or(&preferred_format);

    let key_type = (&selected_credential.key_parameters).try_into().map_err(|_| Error::Unknown)?;
    let public_key = encode_public_key(key_type, &selected_credential.private_key).map_err(|_| Error::Unknown)?;

    // TODO: Assign AAGUID?
    let aaguid = vec![0_u8; 16];
    let attested_credential_data = if *attestation_format != AttestationStatementFormat::None { create_attested_credential_data(&selected_credential.id, &public_key, &aaguid).ok() } else { None };
    // Let authenticatorData be the byte array specified in § 6.1 Authenticator Data including processedExtensions, if any, as the extensions and excluding attestedCredentialData. This authenticatorData MUST include attested credential data if, and only if, attestationFormat is not none.
    let authenticator_data = create_authenticator_data(selected_credential, signature_counter, attested_credential_data.as_deref(), None);
    // Let signature be the assertion signature of the concatenation authenticatorData || hash using the privateKey of selectedCredential as shown in Figure , below. A simple, undelimited concatenation is safe to use here because the authenticator data describes its own length. The hash of the serialized client data (which potentially has a variable length) is always the last element.
    let signature = sign_attestation(
        &authenticator_data,
        &client_data_hash,
        &selected_credential.private_key,
        &key_type,
    )?;

    // The attestationFormat is not none then create an attestation object for the new credential using the procedure specified in § 6.5.5 Generating an Attestation Object, the attestation statement format attestationFormat, and the values authenticatorData and hash, as well as taking into account the value of enterpriseAttestationPossible. For more details on attestation, see § 6.5 Attestation.
    let attestation_object = if *attestation_format != AttestationStatementFormat::None {
        Some(create_attestation_object(key_type.algorithm(), &authenticator_data, &signature, enterprise_attestation_possible)?)
    } else {
        None
    };

    // If any error occurred then return an error code equivalent to "UnknownError" and terminate the operation.
    // Return to the user agent:
    let response = GetPublicKeyCredentialResponse {
        cred_type: "public-key".to_string(),
        client_data_json,

        // selectedCredential.id, if either a list of credentials (i.e., allowCredentialDescriptorList) of length 2 or greater was supplied by the client, or no such list was supplied.
        // Note: If, within allowCredentialDescriptorList, the client supplied exactly one credential and it was successfully employed, then its credential ID is not returned since the client already knows it. This saves transmitting these bytes over what may be a constrained connection in what is likely a common case.
        raw_id: if allow_credential_descriptor_list.map_or(true,  |l| l.len() > 1) {
            Some(selected_credential.id.clone())
        } else {
            None
        },

        // authenticatorData
        authenticator_data,
        // signature
        signature,


        // The attestation object, if an attestation object was created for this assertion.
        attestation_object: attestation_object,

        // selectedCredential.userHandle
        // Note: In cases where allowCredentialDescriptorList was supplied the returned userHandle value may be null, see: userHandleResult.
        user_handle: selected_credential.user_handle.clone(),
    };
    Ok(response)
    // If the authenticator cannot find any credential corresponding to the specified Relying Party that matches the specified criteria, it terminates the operation and returns an error.
}

fn create_key_pair(parameters: CoseKeyType) -> Result<Vec<u8>, Error> {
    let rng = &SystemRandom::new();
    let key_pair = match parameters {
        CoseKeyType::ES256_P256 => EcdsaKeyPair::generate_pkcs8(P256, rng).map(|d| d.as_ref().to_vec()),
        CoseKeyType::EdDSA_Ed25519 => Ed25519KeyPair::generate_pkcs8(rng).map(|d| d.as_ref().to_vec()),
        CoseKeyType::RS256 => {
            let rsa_key = Rsa::generate(2048).unwrap();
            let private_key = PKey::from_rsa(rsa_key).unwrap();
            let pkcs8 = private_key.private_key_to_pkcs8().unwrap();
            Ok(pkcs8.to_vec())
        }
        _ => todo!("Unknown signature algorithm given pair generated"),
    };
    key_pair.map_err(|_e| Error::Unknown)
}

fn lookup_stored_credentials(id: &[u8]) -> Option<(CredentialDescriptor, RelyingParty)> {
    todo!()
}

fn ask_disclosure_consent() -> bool {
    todo!();
}

fn is_user_verification_available() -> bool {
    todo!();
}

fn collect_authorization_gesture(
    _require_user_presence: bool,
    _require_user_verification: bool,
) -> Result<(), Error> {
    // todo!();
    Ok(())
}

fn process_authenticator_extensions(_extensions: ()) -> Result<(), Error> {
    todo!();
}

fn sign_attestation(
    authenticator_data: &[u8],
    client_data_hash: &[u8],
    key_pair: &[u8],
    key_type: &CoseKeyType,
) -> Result<Vec<u8>, Error> {
    let signed_data: Vec<u8> = [authenticator_data, client_data_hash].concat();
    let rng = &SystemRandom::new();
    match key_type {
        CoseKeyType::ES256_P256 => {
            let ecdsa = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key_pair, &SystemRandom::new()).unwrap();
            Ok(ecdsa.sign(rng, &signed_data).unwrap().as_ref().to_vec())
        }
        CoseKeyType::EdDSA_Ed25519 => {
            let eddsa = Ed25519KeyPair::from_pkcs8(key_pair).unwrap();
            Ok(eddsa.sign(&signed_data).as_ref().to_vec())
        }
        CoseKeyType::RS256 => {
            let rsa = RsaKeyPair::from_pkcs8(key_pair).unwrap();
            let mut signature = vec![0; rsa.public_modulus_len()];
            let _ = rsa.sign(&RSA_PKCS1_SHA256, rng, &signed_data, &mut signature);
            Ok(signature)
        }
        _ => Err(Error::NotSupported),
    }
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
fn create_authenticator_data(
    credential_source: &CredentialSource,
    signature_counter: u32,
    attested_credential_data: Option<&[u8]>,
    processed_extensions: Option<()>,
) -> Vec<u8> {
    let mut authenticator_data: Vec<u8> = Vec::new();
    let rp_id_hash = digest(&digest::SHA256, credential_source.rp_id.as_bytes());
    authenticator_data.extend(rp_id_hash.as_ref());

    if attested_credential_data.is_some() {
        authenticator_data.push(0b0100_0101); // UP, UV, AT
    } else {
        authenticator_data.push(0b0000_0101); // UP, UV
    }

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
    algorithm: CoseKeyAlgorithmIdentifier,
    authenticator_data: &[u8],
    signature: &[u8],
    _enterprise_attestation_possible: bool,
) -> Result<Vec<u8>, Error> {
    let mut attestation_object = Vec::new();
    let mut cbor_writer = CborWriter::new(&mut attestation_object);
    cbor_writer.write_map_start(3).unwrap();

    cbor_writer.write_text("fmt").unwrap();
    cbor_writer.write_text("packed").unwrap();

    cbor_writer.write_text("attStmt").unwrap();
    cbor_writer.write_map_start(2).unwrap();
    cbor_writer.write_text("alg").unwrap();
    cbor_writer.write_number(algorithm.into()).unwrap();
    cbor_writer.write_text("sig").unwrap();
    cbor_writer.write_bytes(signature).unwrap();

    cbor_writer.write_text("authData").unwrap();
    cbor_writer.write_bytes(authenticator_data).unwrap();

    Ok(attestation_object)
}


#[cfg(test)]
mod test {
    use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ring::{
        digest::{digest, SHA256},
        rand::{SecureRandom, SystemRandom},
        signature::{
            EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, KeyPair, RsaKeyPair,
            ECDSA_P256_SHA256_ASN1_SIGNING, RSA_PKCS1_SHA256,
        },
    };

    use crate::webauthn::cose::{CoseKeyAlgorithmIdentifier, CoseKeyParameters, CoseKeyType};

    use super::{
        cose::encode_public_key, create_attestation_object, create_attested_credential_data,
        create_authenticator_data, sign_attestation, CredentialSource,
        PublicKeyCredentialParameters, PublicKeyCredentialType,
    };

    #[test]
    fn test_rsa_key_pair() {
        let f = std::fs::read("rsa-2048-private-key.pk8").unwrap();
        let key_pair = RsaKeyPair::from_pkcs8(&f).unwrap();
        // println!(key_pair.public_key().as_ref().iter().map(|b| format!("{b:2x}").to_string()).collect::<Vec<String>>().join(""));
        for b in key_pair.public_key().as_ref().to_vec() {
            print!("{b:02x}");
        }
        println!();
    }

    #[test]
    fn test_attestation() {
        let key_file = std::fs::read("private-key1.pk8").unwrap();
        // let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key_file, &SystemRandom::new()).unwrap();
        let key_parameters = PublicKeyCredentialParameters {
            alg: -7,
            cred_type: "public-key".to_string(),
        };
        let key_type = (&key_parameters).try_into().unwrap();
        let public_key = encode_public_key(key_type, &key_file).unwrap();
        let signature_counter = 1u32;
        let credential_id = [
            0x92, 0x11, 0xb7, 0x6d, 0x8b, 0x19, 0xf9, 0x50, 0x6c, 0x2d, 0x75, 0x2f, 0x09, 0xc4,
            0x3c, 0x5a, 0xeb, 0xf3, 0x36, 0xf6, 0xba, 0x89, 0x66, 0xdc, 0x6e, 0x71, 0x93, 0x52,
            0x08, 0x72, 0x1d, 0x16,
        ]
        .to_vec();
        let aaguid = [
            01, 02, 03, 04, 05, 06, 07, 08, 01, 02, 03, 04, 05, 06, 07, 08,
        ];
        let attested_credential_data =
            create_attested_credential_data(&credential_id, &public_key, &aaguid).unwrap();
        let user_handle = [
            0x64, 0x47, 0x56, 0x7a, 0x64, 0x47, 0x46, 0x69, 0x65, 0x6e, 0x6f,
        ]
        .to_vec();
        let credential_source = CredentialSource {
            cred_type: PublicKeyCredentialType::PublicKey,
            id: credential_id,
            private_key: key_file.clone(),
            key_parameters: PublicKeyCredentialParameters::new(key_type.algorithm().into()),
            rp_id: "webauthn.io".to_string(),
            user_handle: Some(user_handle),
            other_ui: None,
        };

        let authenticator_data = create_authenticator_data(
            &credential_source,
            signature_counter,
            Some(&attested_credential_data),
            None,
        );
        let client_data_encoded = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWWlReFY0VWhjZk9pUmZBdkF4bWpEakdhaUVXbkYtZ0ZFcWxndmdEaWsyakZiSGhoaVlxUGJqc0F5Q0FrbDlMUGQwRGRQaHNNb2luY0cxckV5cFlXUVEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ";
        let client_data = URL_SAFE_NO_PAD.decode(client_data_encoded).unwrap();
        let client_data_hash = digest(&SHA256, &client_data).as_ref().to_vec();
        let signature = sign_attestation(
            &authenticator_data,
            &client_data_hash,
            &key_file,
            &key_type,
        )
        .unwrap();
        let attestation_object =
            create_attestation_object(key_type.algorithm(), &authenticator_data, &signature, false)
                .unwrap();
        let expected = std::fs::read("output.bin").unwrap();
        assert_eq!(expected, attestation_object);
    }
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

// pub(crate) struct CredentialList(Vec<CredentialDescriptor>);

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
/// https://www.w3.org/TR/webauthn-3/#dictionary-credential-descriptor
pub(crate) struct CredentialDescriptor {
    /// Type of the public key credential the caller is referring to.
    ///
    /// The value SHOULD be a member of PublicKeyCredentialType but client
    /// platforms MUST ignore any PublicKeyCredentialDescriptor with an unknown
    /// type.
    #[zvariant(rename = "type")]
    cred_type: String,
    /// Credential ID of the public key credential the caller is referring to.
    id: Vec<u8>,
    transports: Vec<String>,
}

impl TryFrom<&CredentialDescriptor> for Ctap2PublicKeyCredentialDescriptor {
    type Error = Error;
    fn try_from(value: &CredentialDescriptor) -> Result<Self, Self::Error> {
        let transports = if value.transports.is_empty() {
            None
        } else {
            let mut t = value.transports.iter().map(|t| match t.as_ref() {
                "ble" => Some(Ctap2Transport::BLE),
                "nfc" => Some(Ctap2Transport::NFC),
                "usb" => Some(Ctap2Transport::USB),
                "internal" => Some(Ctap2Transport::INTERNAL),
                _ => None,
            });
            if t.any(|t| t.is_none()) {
                return Err(Error::Internal("Invalid transport type specified".to_owned()));
            }
            t.collect()
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
    fn new(alg: i64) -> Self {
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
            -8 => Ok(CoseKeyType::EdDSA_Ed25519),
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

#[derive(Clone)]
enum PublicKeyCredentialType {
    PublicKey,
}

enum WebAuthnDeviceCounterType {
    /// Authenticator is a U2F device (and therefore does not support a counter
    /// on registration and may or may not support a counter on assertion).
    U2F,
    /// Authenticator supports a global signature counter.
    Global,
    /// Authenticator supports a per credential signature counter.
    PerCredential,
    /// Authenticator does not support a signature counter.
    Unsupported,
}

#[derive(PartialEq)]
enum AttestationStatementFormat {
    None,
    Packed,
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
    cred_type: String,

    /// clientDataJSON.
    client_data_json: String,

    /// Raw bytes of credential ID. Not returned if only one descriptor was
    /// passed in the allow credentials list.
    raw_id: Option<Vec<u8>>,

    /// Encodes contextual bindings made by the authenticator. These bindings
    /// are controlled by the authenticator itself.
    authenticator_data: Vec<u8>,

    signature: Vec<u8>,

    /// Bytes containing authenticator data and an attestation statement.
    attestation_object: Option<Vec<u8>>,

    /// The user handle associated when this public key credential source was
    /// created. This item is nullable, however user handle MUST always be
    /// populated for discoverable credentials.
    user_handle: Option<Vec<u8>>,
}

mod cose {
    use ring::{
        agreement::PublicKey, digest::{self, digest}, rand::SystemRandom, signature::{
            EcdsaKeyPair, EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm, Ed25519KeyPair, KeyPair,
            RsaKeyPair, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING,
            RSA_PKCS1_SHA256,
        }
    };

    #[derive(Clone, Copy, Debug, PartialEq)]
    #[repr(i64)]
    pub(super) enum CoseKeyType {
        ES256_P256,
        EdDSA_Ed25519,
        RS256,
    }

    impl CoseKeyType {
        pub fn algorithm(&self) -> CoseKeyAlgorithmIdentifier {
            let params: CoseKeyParameters = (*self).into();
            params.algorithm()
        }
    }

    impl CoseKeyType {
        pub fn curve(&self) -> Option<CoseEllipticCurveIdentifier> {
            let params: CoseKeyParameters = (*self).into();
            params.curve()
        }
    }

    pub(super) struct CoseKeyParameters {
        alg: CoseKeyAlgorithmIdentifier,
        crv: Option<CoseEllipticCurveIdentifier>,
    }

    impl CoseKeyParameters {
        pub fn algorithm(&self) -> CoseKeyAlgorithmIdentifier {
            self.alg
        }

        pub fn curve(&self) -> Option<CoseEllipticCurveIdentifier> {
            self.crv
        }
    }

    impl From<CoseKeyType> for CoseKeyParameters {
        fn from(value: CoseKeyType) -> Self {
            match value {
                CoseKeyType::ES256_P256 => CoseKeyParameters { alg: CoseKeyAlgorithmIdentifier::ES256, crv: Some(CoseEllipticCurveIdentifier::P256) },
                CoseKeyType::EdDSA_Ed25519 => CoseKeyParameters { alg: CoseKeyAlgorithmIdentifier::EdDSA, crv: Some(CoseEllipticCurveIdentifier::Ed25519) },
                CoseKeyType::RS256 => CoseKeyParameters { alg: CoseKeyAlgorithmIdentifier::RS256, crv: None, },
            }
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    pub enum CoseKeyAlgorithmIdentifier {
        ES256,
        EdDSA,
        RS256,
    }

    impl From<CoseKeyAlgorithmIdentifier> for i64 {
        fn from(value: CoseKeyAlgorithmIdentifier) -> Self {
            match value {
                CoseKeyAlgorithmIdentifier::ES256 => -7,
                CoseKeyAlgorithmIdentifier::EdDSA => -8,
                CoseKeyAlgorithmIdentifier::RS256 => -257,
            }
        }
    }

    impl From<CoseKeyAlgorithmIdentifier> for i128 {
        fn from(value: CoseKeyAlgorithmIdentifier) -> Self {
            match value {
                CoseKeyAlgorithmIdentifier::ES256 => -7,
                CoseKeyAlgorithmIdentifier::EdDSA => -8,
                CoseKeyAlgorithmIdentifier::RS256 => -257,
            }
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    pub enum CoseEllipticCurveIdentifier {
        /// P-256 Elliptic Curve using uncompressed points.
        P256,
        /// P-384 Elliptic Curve using uncompressed points.
        P384,
        /// P-521 Elliptic Curve using uncompressed points.
        P521,
        /// Ed25519 Elliptic Curve using compressed points.
        Ed25519,
    }

    impl From<CoseEllipticCurveIdentifier> for i64 {
        fn from(value: CoseEllipticCurveIdentifier) -> Self {
            match value {
                CoseEllipticCurveIdentifier::P256 => 1,
                CoseEllipticCurveIdentifier::P384 => 2,
                CoseEllipticCurveIdentifier::P521 => 3,
                CoseEllipticCurveIdentifier::Ed25519 => 6,
            }
        }
    }

    #[derive(Debug)]
    pub enum Error {
        InvalidKey,
    }
    pub(super) fn encode_public_key(
        key_type: CoseKeyType,
        pkcs8_key: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match key_type {
            CoseKeyType::ES256_P256 => {
                let key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_ASN1_SIGNING,
                    pkcs8_key,
                    &SystemRandom::new(),
                )
                .unwrap();
                let public_key = key_pair.public_key().as_ref();
                // ring outputs public keys with uncompressed 32-byte x and y coordinates
                if public_key.len() != 65 || public_key[0] != 0x04 {
                    return Err(Error::InvalidKey);
                }
                let (x, y) = public_key[1..].split_at(32);
                let mut cose_key: Vec<u8> = Vec::new();
                cose_key.push(0b101_00101); // map with 5 items
                cose_key.extend([0b000_00001, 0b000_00010]); // kty (1): EC2 (2)
                cose_key.extend([0b000_00011, 0b001_00110]); // alg (3): ECDSA-SHA256 (-7)
                cose_key.extend([0b001_00000, 0b000_00001]); // crv (-1): P256 (1)
                cose_key.extend([0b001_00001, 0b010_11000, 0b0010_0000]); // x (-2): <32-byte string>
                cose_key.extend(x);
                cose_key.extend([0b001_00010, 0b010_11000, 0b0010_0000]); // y (-3): <32-byte string>
                cose_key.extend(y);
                Ok(cose_key)
            }
            CoseKeyType::EdDSA_Ed25519 => {
                // TODO: Check this
                let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_key).map_err(|_| Error::InvalidKey)?;
                let public_key = key_pair.public_key().as_ref();
                let mut cose_key: Vec<u8> = Vec::new();
                cose_key.push(0b101_00100); // map with 4 items
                cose_key.extend([0b000_00001, 0b000_00001]); // kty (1): OKP (1)
                cose_key.extend([0b000_00011, 0b001_00111]); // alg (3): EdDSA (-8)
                cose_key.extend([0b001_00000, 0b000_00110]); // crv (-1): ED25519 (6)
                cose_key.extend([0b001_00001, 0b010_11000, 0b0010_0000]); // x (-2): <32-byte string>
                cose_key.extend(public_key);
                Ok(cose_key)
            }
            CoseKeyType::RS256 => {
                let key_pair = RsaKeyPair::from_pkcs8(pkcs8_key).map_err(|_| Error::InvalidKey)?;
                let public_key = key_pair.public_key().as_ref();
                // TODO: This is ASN.1 with DER encoding. We could parse this to extract
                // the modulus and exponent properly, but the key length will
                // probably not change, so we're winging it
                // https://stackoverflow.com/a/12750816/11931787
                let n = &public_key[9..(9 + 256)];
                let e = &public_key[public_key.len() - 3..];
                debug_assert_eq!(n.len(), key_pair.public_modulus_len());
                let mut cose_key: Vec<u8> = Vec::new();
                cose_key.push(0b101_00100); // map with 4 items
                cose_key.extend([0b000_00001, 0b000_00010]); // kty (1): RSA (3)
                cose_key.extend([0b000_00011, 0b001_00110]); // alg (3): RSASSA-PKCS1-v1_5 using SHA-256 (-257)
                cose_key.extend([0b001_00000, 0b010_11001, 0b0000_0001, 0b0000_0000]); // n (-1): <256-byte string>
                cose_key.extend(n);
                cose_key.extend([0b001_00001, 0b010_00011]); // e (-2): <3-byte string>
                cose_key.extend(e);
                Ok(cose_key)
            }
            _ => todo!(),
        }
    }
}
