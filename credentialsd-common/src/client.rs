use std::pin::Pin;

use futures_lite::Stream;

use crate::{
    model::{BackgroundEvent, Device},
    server::RequestId,
};

/// Used for communication from trusted UI to credential service
pub trait FlowController {
    fn get_available_public_key_devices(
        &self,
    ) -> impl Future<Output = Result<Vec<Device>, ()>> + Send;

    fn get_hybrid_credential(&mut self) -> impl Future<Output = Result<(), ()>> + Send;
    fn get_usb_credential(&mut self) -> impl Future<Output = Result<(), ()>> + Send;
    fn get_nfc_credential(&mut self) -> impl Future<Output = Result<(), ()>> + Send;
    fn subscribe(
        &mut self,
    ) -> impl Future<
        Output = Result<Pin<Box<dyn Stream<Item = BackgroundEvent> + Send + 'static>>, ()>,
    > + Send;
    fn enter_client_pin(&mut self, pin: String) -> impl Future<Output = Result<(), ()>> + Send;
    fn select_credential(
        &self,
        credential_id: String,
    ) -> impl Future<Output = Result<(), ()>> + Send;
    fn cancel_request(&self, request_id: RequestId) -> impl Future<Output = Result<(), ()>> + Send;
}
