use std::{
    io::ErrorKind,
    os::{
        fd::{FromRawFd, OwnedFd},
        raw::c_void,
    },
};

use async_std::{
    channel::{Receiver, Sender},
    sync::Mutex as AsyncMutex,
};
use libc::{
    MAP_SHARED, O_CLOEXEC, PROT_READ, PROT_WRITE, SYS_memfd_secret, ftruncate, mmap, off_t,
};
use zeroize::Zeroize;

use credentialsd_common::{model::UserInteractedEvent, server::BackgroundEvent};

#[derive(Debug)]
pub struct FlowControlClient {
    pub tx: Sender<UserInteractedEvent>,
    pub rx: AsyncMutex<Option<Receiver<BackgroundEvent>>>,
}

impl FlowControlClient {
    pub async fn discover_authenticators(&self) -> Result<(), ()> {
        self.send(UserInteractedEvent::DiscoveryRequested).await
    }

    pub async fn enter_client_pin(&mut self, pin: String) -> Result<(), ()> {
        let fd = match write_secret(pin) {
            Ok(fd) => fd,
            Err(err) => {
                tracing::error!(%err, "Failed to write secret to file descriptor");
                // TODO: need to send a message back to GUI thread that there was an error.
                _ = self.cancel_request().await;
                return Err(());
            }
        };
        self.send(UserInteractedEvent::ClientPinEntered(fd.into()))
            .await
    }

    pub async fn select_credential(&self, credential_id: String) -> Result<(), ()> {
        self.send(UserInteractedEvent::CredentialSelected(credential_id))
            .await
    }

    pub async fn cancel_request(&self) -> Result<(), ()> {
        self.send(UserInteractedEvent::RequestCancelled).await
    }

    /// Returns a channel for background events.
    /// Can only be called once; returns an error if the subscription has already been taken.
    pub async fn subscribe(&mut self) -> Result<Receiver<BackgroundEvent>, ()> {
        self.rx.lock().await.take().ok_or_else(|| {
            tracing::error!("Subscribe has already been called.");
        })
    }

    async fn send(&self, request: UserInteractedEvent) -> Result<(), ()> {
        match self.tx.send(request).await {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

fn write_secret(secret: String) -> Result<OwnedFd, std::io::Error> {
    let mut bytes = secret.into_bytes();
    // CTAP pins are maximum of 63 bytes, so they should all fit in a u8.
    let bytes_len = if bytes.len() <= 63 {
        bytes.len() as u8
    } else {
        return Err(std::io::Error::new(
            ErrorKind::FileTooLarge,
            "value is too large",
        ));
    };

    // Open memfd_secret
    let ret: i64 = unsafe { libc::syscall(SYS_memfd_secret, O_CLOEXEC) };
    if ret == -1 {
        tracing::debug!("Failed to create memfd_secret");
        return Err(std::io::Error::last_os_error());
    }
    let fd = i32::try_from(ret).map_err(|_| std::io::Error::other("invalid file descriptor"))?;
    if unsafe { ftruncate(fd, bytes_len as off_t) } == -1 {
        tracing::debug!("Failed to ftruncate memfd_secret");
        return Err(std::io::Error::last_os_error());
    }

    let ptr = unsafe {
        let ptr = mmap(
            std::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        );
        if ptr == usize::MAX as *mut c_void {
            tracing::debug!("Failed to mmap memfd_secret");
            return Err(std::io::Error::last_os_error());
        }
        // ptr as *mut u8
        ptr
    };

    // Copy the data
    unsafe {
        ptr.copy_from_nonoverlapping(bytes.as_ptr().cast(), bytes.len());
    }

    // Cleanup
    if unsafe { libc::munmap(ptr, 4096) } == -1 {
        tracing::debug!("Failed to unmap memfd_secret");
        return Err(std::io::Error::last_os_error());
    }
    bytes.zeroize();
    drop(bytes);

    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(owned_fd)
}
