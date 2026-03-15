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
mod ui_control;

pub use self::{
    flow_control::{
        start_flow_control_service, CredentialRequestController, CredentialRequestControllerClient,
    },
    ui_control::UiControlServiceClient,
};

#[cfg(test)]
pub mod test {
    pub use super::flow_control::test::DummyFlowServer;
    pub use super::ui_control::test::DummyUiServer;
}
