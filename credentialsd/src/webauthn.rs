//! WebAuthn types re-exported from libwebauthn.
//!
//! This module re-exports the types needed for WebAuthn request parsing
//! and response serialization from the libwebauthn crate.

// Re-exports from libwebauthn
pub use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, RelyingPartyId, WebAuthnIDL, WebAuthnIDLResponse,
};

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
