//! This module hosts the D-Bus endpoints needed for this service.
//!
//! The D-Bus endpoints are structured to allow sandboxing with small component processes connected with a central broker.
//! # Broker:
//! The broker's main responsibility is to enforce permissions between the various components.
//! To do that, the broker has a bunch of seemingly redundant methods that forwards to the actual
//! implementations.
//!
//! The internal components should sandboxed only to have access to resources needed to fulfill the request.
//!
//! ## Client -> pub service -> broker -> Cred Service:
//! These methods are called by the pub service on behalf of a client requesting credentials.
//! The pub service must pass appropriate context for the broker to determine the client's permissions.
//! - get_cred(options)
//! - create_cred(options)
//! - get_client_capabilities()
//!
//! ## UI -> broker -> Cred service:
//! These methods are called by the trusted UI to interact with the credential service.
//! - initialize_event_stream()
//! - get_hybrid_credential()
//! - get_usb_credential()
//! - get_available_devices() # a device is a discrete authenticator or a group of potential authenticators accessible via a particular transport, or a credential?
//! - send_pin()
//! - select_credential()
//! - cancel_request()
//!
//! ## Cred Service -> broker -> UI:
//! - launch UI
//! - send_state_changed()

mod broker;
mod flow_control;
mod gateway;
mod model;
mod ui_control;

use std::pin::Pin;
use std::{collections::VecDeque, error::Error, fmt::Debug, sync::Arc};

use creds_lib::model::MakeCredentialRequest;
use creds_lib::server::{CreateCredentialRequest, CreatePublicKeyCredentialRequest, ViewRequest};
use futures_lite::{Stream, StreamExt};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::AbortHandle;
use zbus::object_server::{InterfaceRef, SignalEmitter};
use zbus::{
    connection::{self, Connection},
    fdo, interface,
};
use zbus::{proxy, ObjectServer};

use creds_lib::{
    client::CredentialServiceClient,
    model::{
        CredentialRequest, CredentialResponse, CredentialType, GetClientCapabilitiesResponse,
        Operation,
    },
    server::{
        BackgroundEvent, CreateCredentialResponse, CreatePublicKeyCredentialResponse, Device,
        GetCredentialRequest, GetCredentialResponse, GetPublicKeyCredentialResponse,
    },
};

use self::model::{
    create_credential_request_try_into_ctap2, create_credential_response_try_from_ctap2,
    get_credential_request_try_into_ctap2, get_credential_response_try_from_ctap2,
};
use crate::credential_service::hybrid::{HybridHandler, HybridState};
use crate::credential_service::usb::UsbHandler;
use crate::credential_service::{
    CredentialManagementClient, CredentialService, UiController, UsbState,
};

pub use self::{
    flow_control::{
        start_flow_control_service, CredentialRequestController, CredentialRequestControllerClient,
        SERVICE_NAME as FLOW_CONTROL_SERVICE_NAME, SERVICE_PATH as FLOW_CONTROL_SERVICE_PATH,
    },
    gateway::start_gateway,
    ui_control::UiControlServiceClient,
};
