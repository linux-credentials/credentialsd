//! WebAuthn types re-exported from libwebauthn.
//!
//! This module re-exports the types needed for WebAuthn request parsing
//! and response serialization from the libwebauthn crate.

// Re-exports from libwebauthn
pub use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, RelyingPartyId, WebAuthnIDL, WebAuthnIDLResponse,
};
