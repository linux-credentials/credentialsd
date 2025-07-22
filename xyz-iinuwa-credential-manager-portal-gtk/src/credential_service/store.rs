use std::sync::Arc;

use async_trait::async_trait;
use libwebauthn::transport::cable::known_devices::{
    CableKnownDeviceId, CableKnownDeviceInfo, CableKnownDeviceInfoStore,
};
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt as _, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, error, instrument, trace};
use tracing_subscriber::field::debug;

pub(crate) type KnownDeviceId = CableKnownDeviceId;

/// Serializable representation of a [CableKnownDeviceInfo].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KnownDevice {
    pub contact_id: Vec<u8>,
    pub link_id: Vec<u8>,
    pub link_secret: Vec<u8>,
    pub public_key: Vec<u8>,
    pub name: String,
    pub tunnel_domain: String,
}

impl From<CableKnownDeviceInfo> for KnownDevice {
    fn from(info: CableKnownDeviceInfo) -> Self {
        KnownDevice {
            contact_id: info.contact_id,
            link_id: info.link_id.to_vec(),
            link_secret: info.link_secret.to_vec(),
            public_key: info.public_key.to_vec(),
            name: info.name,
            tunnel_domain: info.tunnel_domain,
        }
    }
}

impl TryInto<CableKnownDeviceInfo> for KnownDevice {
    type Error = String;

    fn try_into(self) -> Result<CableKnownDeviceInfo, Self::Error> {
        Ok(CableKnownDeviceInfo {
            contact_id: self.contact_id,
            link_id: self
                .link_id
                .try_into()
                .map_err(|_| "Invalid link_id length")?,
            link_secret: self
                .link_secret
                .try_into()
                .map_err(|_| "Invalid link_secret length")?,
            public_key: self
                .public_key
                .try_into()
                .map_err(|_| "Invalid public_key length")?,
            name: self.name,
            tunnel_domain: self.tunnel_domain,
        })
    }
}

/// A store for known hybrid devices, backed by a JSON file.
/// This implementation is inefficient and insecure - it's intended for demo purposes only.
#[derive(Debug)]
pub(crate) struct KnownHybridDeviceStore {
    fd: Arc<Mutex<File>>,
}

impl KnownHybridDeviceStore {
    #[instrument(err)]
    pub async fn new(path: &str) -> Result<Self, std::io::Error> {
        debug!("Opening known devices store at path");
        let fd = File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .await?;
        Ok(Self {
            fd: Arc::new(Mutex::new(fd)),
        })
    }

    #[instrument(skip_all, err)]
    pub async fn get_all_known_devices(&self) -> Result<Vec<(KnownDeviceId, KnownDevice)>, String> {
        let mut fd = self.fd.lock().await;
        let devices = self.read(&mut fd).await?;
        Ok(devices)
    }

    #[instrument(skip_all, err)]
    pub async fn get_known_device(
        &self,
        device_id: &KnownDeviceId,
    ) -> Result<Option<CableKnownDeviceInfo>, String> {
        let mut fd = self.fd.lock().await;
        let devices = self.read(&mut fd).await?;
        for (id, device) in devices {
            if &id == device_id {
                return Ok(Some(device.try_into()?));
            }
        }
        Ok(None)
    }

    #[instrument(skip_all, err)]
    async fn read(&self, fd: &mut File) -> Result<Vec<(KnownDeviceId, KnownDevice)>, String> {
        let mut contents = String::new();
        fd.read_to_string(&mut contents).await.map_err(|e| {
            error!(?e, "Failed to read known devices");
            "Failed to read known devices".to_string()
        })?;
        trace!(?contents);

        if contents.is_empty() {
            debug!("No known devices found, returning empty list");
            return Ok(vec![]);
        }

        let devices: Vec<(KnownDeviceId, KnownDevice)> =
            serde_json::from_str(&contents).map_err(|e| {
                error!(?e, "Failed to parse known devices");
                "Failed to parse known devices".to_string()
            })?;

        // Reset the file cursor to the beginning for future reads & writes
        fd.seek(std::io::SeekFrom::Start(0)).await.map_err(|e| {
            error!(?e, "Failed to seek in known devices file");
            "Failed to seek in known devices file".to_string()
        })?;

        debug!(?devices, "Retrieved known devices");
        Ok(devices)
    }

    #[instrument(skip_all, err)]
    async fn write(
        &self,
        fd: &mut File,
        devices: &[(KnownDeviceId, KnownDevice)],
    ) -> Result<(), std::io::Error> {
        let new_contents = serde_json::to_string(devices).unwrap();
        fd.set_len(0).await?; // Clear the file
        fd.write_all(new_contents.as_bytes()).await?;
        fd.flush().await?;
        trace!(?new_contents, "Written known devices to file");

        // Reset the file cursor to the beginning for future reads & writes
        fd.seek(std::io::SeekFrom::Start(0)).await.map_err(|e| {
            error!(?e, "Failed to seek in known devices file after write");
            e
        })?;

        debug!(?devices, "Updated known devices store");
        Ok(())
    }
}

#[async_trait]
impl CableKnownDeviceInfoStore for KnownHybridDeviceStore {
    #[instrument(skip(self, device))]
    async fn put_known_device(
        &self,
        device_id: &CableKnownDeviceId,
        device: &CableKnownDeviceInfo,
    ) {
        let mut fd = self.fd.lock().await;
        let Ok(mut devices) = self.read(&mut fd).await else {
            error!("Failed to read known devices, unable to update device");
            return;
        };

        // Update or insert the device
        let known_device: KnownDevice = device.clone().into();
        if let Some(existing) = devices.iter_mut().find(|(id, _)| id == device_id) {
            existing.1 = known_device;
        } else {
            devices.push((device_id.clone(), known_device));
        }

        self.write(&mut fd, &devices).await.unwrap_or_else(|e| {
            error!(?e, "Failed to write known devices");
        });
    }

    #[instrument(skip_self)]
    async fn delete_known_device(&self, device_id: &CableKnownDeviceId) {
        let mut fd: tokio::sync::MutexGuard<'_, File> = self.fd.lock().await;
        let Ok(mut devices) = self.read(&mut fd).await else {
            error!("Failed to read known devices, unable to delete device");
            return;
        };

        // Remove the device
        devices.retain(|(id, _)| id != device_id);

        self.write(&mut fd, &devices).await.unwrap_or_else(|e| {
            error!(?e, "Failed to write known devices");
        });
    }
}
