use credentialsd_common::model::Operation;
use libwebauthn::ops::webauthn::{
    Assertion, GetAssertionRequest, MakeCredentialRequest, MakeCredentialResponse,
};

#[derive(Clone, Debug)]
pub enum CredentialRequest {
    CreatePublicKeyCredentialRequest(MakeCredentialRequest),
    GetPublicKeyCredentialRequest(GetAssertionRequest),
}

impl CredentialRequest {
    pub fn operation(&self) -> Operation {
        match self {
            Self::CreatePublicKeyCredentialRequest(_) => Operation::PublicKeyCreate,
            Self::GetPublicKeyCredentialRequest(_) => Operation::PublicKeyGet,
        }
    }

    pub fn relying_party_id(&self) -> &str {
        match self {
            Self::CreatePublicKeyCredentialRequest(r) => r.relying_party.id.as_str(),
            Self::GetPublicKeyCredentialRequest(r) => r.relying_party_id.as_str(),
        }
    }

    pub fn origin(&self) -> &str {
        match self {
            Self::CreatePublicKeyCredentialRequest(r) => r.origin.as_str(),
            Self::GetPublicKeyCredentialRequest(r) => r.origin.as_str(),
        }
    }

    pub fn top_origin(&self) -> Option<&str> {
        match self {
            Self::CreatePublicKeyCredentialRequest(r) => r.top_origin.as_deref(),
            Self::GetPublicKeyCredentialRequest(r) => r.top_origin.as_deref(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum CredentialResponse {
    CreatePublicKeyCredentialResponse(Box<MakeCredentialResponseInternal>),
    GetPublicKeyCredentialResponse(Box<GetAssertionResponseInternal>),
}

impl CredentialResponse {
    pub fn from_make_credential(
        response: &MakeCredentialResponse,
        transports: &[&str],
        modality: &str,
    ) -> CredentialResponse {
        CredentialResponse::CreatePublicKeyCredentialResponse(Box::new(
            MakeCredentialResponseInternal::new(
                response.clone(),
                transports.iter().map(|s| s.to_string()).collect(),
                modality.to_string(),
            ),
        ))
    }

    pub fn from_get_assertion(assertion: &Assertion, modality: &str) -> CredentialResponse {
        CredentialResponse::GetPublicKeyCredentialResponse(Box::new(
            GetAssertionResponseInternal::new(assertion.clone(), modality.to_string()),
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

pub struct ClientDetails {
    pub app_id: String,
    pub pid: u32,
}
