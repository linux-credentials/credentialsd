//! This module hosts the D-Bus endpoints needed for this service.
//!
//! There are two services that run in this process: the gateway and the flow
//! controller.
//!
//! The gateway is accessed by public clients and initiates new requests.
//!
//! The flow controller launches a UI and receives user interaction events.
//!
//! There is also a client to reach out to the UI controller hosted by the trusted UI.

mod flow_control;
mod gateway;
mod model;
mod ui_control;

use self::model::{
    create_credential_request_try_into_ctap2, create_credential_response_try_from_ctap2,
    get_credential_request_try_into_ctap2, get_credential_response_try_from_ctap2,
};

pub use self::{
    flow_control::{
        start_flow_control_service, CredentialRequestController, CredentialRequestControllerClient,
    },
    gateway::start_gateway,
    ui_control::UiControlServiceClient,
};
