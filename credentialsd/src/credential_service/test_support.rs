//! Scripted credential transports used by unit tests.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use futures_lite::Stream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio_util::sync::CancellationToken;

use super::{
    CredentialRequest, CredentialResponse, CredentialServiceError,
    hybrid::{HybridEvent, HybridHandler, HybridStateInternal},
    nfc::{NfcEvent, NfcHandler, NfcStateInternal},
    usb::{UsbEvent, UsbHandler, UsbStateInternal},
};

/// A transport that never emits an event.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct EmptyTransport;

impl UsbHandler for EmptyTransport {
    fn start(
        &self,
        _request: &CredentialRequest,
        _cancellation: CancellationToken,
    ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static {
        futures::stream::empty()
    }
}

impl HybridHandler for EmptyTransport {
    fn start(
        &self,
        _request: &CredentialRequest,
        _cancellation: CancellationToken,
    ) -> impl Stream<Item = HybridEvent> + Send + Sized + Unpin + 'static {
        futures::stream::empty()
    }
}

impl NfcHandler for EmptyTransport {
    fn start(
        &self,
        _request: &CredentialRequest,
        _cancellation: CancellationToken,
    ) -> impl Stream<Item = NfcEvent> + Send + Sized + Unpin + 'static {
        futures::stream::empty()
    }
}

/// Test-side control handle for a [`ScriptedTransport`].
#[derive(Clone)]
pub(super) struct ScriptedTransportController<T> {
    tx: UnboundedSender<T>,
    cancelled: Arc<AtomicBool>,
}

impl<T> ScriptedTransportController<T> {
    /// Emit the next internal transport state.
    pub(super) fn emit(&self, state: T) {
        assert!(
            self.tx.send(state).is_ok(),
            "scripted transport stream has already stopped"
        );
    }

    /// Whether the scripted transport observed its cancellation token.
    pub(super) fn was_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

pub(super) trait ScriptedState {
    fn completed(response: CredentialResponse) -> Self;
    fn failed(error: CredentialServiceError) -> Self;
}

impl ScriptedState for UsbStateInternal {
    fn completed(response: CredentialResponse) -> Self {
        Self::Completed(response)
    }

    fn failed(error: CredentialServiceError) -> Self {
        Self::Failed(error)
    }
}

impl ScriptedState for HybridStateInternal {
    fn completed(response: CredentialResponse) -> Self {
        Self::Completed(response)
    }

    fn failed(error: CredentialServiceError) -> Self {
        Self::Failed(error)
    }
}

impl ScriptedState for NfcStateInternal {
    fn completed(response: CredentialResponse) -> Self {
        Self::Completed(response)
    }

    fn failed(error: CredentialServiceError) -> Self {
        Self::Failed(error)
    }
}

impl<T: ScriptedState> ScriptedTransportController<T> {
    /// Complete the active credential request successfully.
    pub(super) fn complete(&self, response: CredentialResponse) {
        self.emit(T::completed(response));
    }

    /// Fail the active credential request.
    pub(super) fn fail(&self, error: CredentialServiceError) {
        self.emit(T::failed(error));
    }
}

/// A push-based mock transport with deterministic cancellation tracking.
pub(super) struct ScriptedTransport<T> {
    rx: Mutex<Option<UnboundedReceiver<T>>>,
    cancelled: Arc<AtomicBool>,
}

impl<T> std::fmt::Debug for ScriptedTransport<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptedTransport")
            .field("cancelled", &self.cancelled.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl<T> ScriptedTransport<T> {
    pub(super) fn new() -> (Self, ScriptedTransportController<T>) {
        let (tx, rx) = unbounded_channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        (
            Self {
                rx: Mutex::new(Some(rx)),
                cancelled: cancelled.clone(),
            },
            ScriptedTransportController { tx, cancelled },
        )
    }

    /// Build a stream that prioritizes cancellation over queued events.
    fn start_with<E>(
        &self,
        cancellation: CancellationToken,
        wrap: impl Fn(T) -> E + Send + 'static,
    ) -> impl Stream<Item = E> + Send + Unpin + 'static
    where
        T: Send + 'static,
        E: Send + 'static,
    {
        let mut rx = self
            .rx
            .lock()
            .unwrap()
            .take()
            .expect("ScriptedTransport can only be started once");
        let cancelled = self.cancelled.clone();
        Box::pin(async_stream::stream! {
            loop {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        cancelled.store(true, Ordering::SeqCst);
                        break;
                    }
                    maybe = rx.recv() => match maybe {
                        Some(state) => yield wrap(state),
                        None => break,
                    }
                }
            }
        })
    }
}

impl UsbHandler for ScriptedTransport<UsbStateInternal> {
    fn start(
        &self,
        _request: &CredentialRequest,
        cancellation: CancellationToken,
    ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static {
        self.start_with(cancellation, |state| UsbEvent { state })
    }
}

impl HybridHandler for ScriptedTransport<HybridStateInternal> {
    fn start(
        &self,
        _request: &CredentialRequest,
        cancellation: CancellationToken,
    ) -> impl Stream<Item = HybridEvent> + Send + Sized + Unpin + 'static {
        self.start_with(cancellation, |state| HybridEvent { state })
    }
}

impl NfcHandler for ScriptedTransport<NfcStateInternal> {
    fn start(
        &self,
        _request: &CredentialRequest,
        cancellation: CancellationToken,
    ) -> impl Stream<Item = NfcEvent> + Send + Sized + Unpin + 'static {
        self.start_with(cancellation, |state| NfcEvent { state })
    }
}
