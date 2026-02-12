use libwebauthn::ops::webauthn::{
    Assertion, GetAssertionRequest, MakeCredentialRequest, MakeCredentialResponse,
};

#[derive(Clone, Debug)]
pub enum CredentialRequest {
    CreatePublicKeyCredentialRequest(MakeCredentialRequest),
    GetPublicKeyCredentialRequest(GetAssertionRequest),
    SetDevicePinRequest(String),
}

#[derive(Clone, Debug)]
pub enum CredentialResponse {
    CreatePublicKeyCredentialResponse(Box<MakeCredentialResponseInternal>),
    GetPublicKeyCredentialResponse(Box<GetAssertionResponseInternal>),
    SetDevicePinSuccessRespone,
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
