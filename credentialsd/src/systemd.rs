use std::os::fd::BorrowedFd;

use zbus::{
    Connection, proxy,
    zvariant::{Fd, OwnedObjectPath},
};

pub struct Manager<'a> {
    proxy: Systemd1ManagerProxy<'a>,
}

impl<'a> Manager<'a> {
    pub async fn create(connection: &'a Connection) -> zbus::Result<Self> {
        let proxy = Systemd1ManagerProxy::new(connection).await?;
        Ok(Self { proxy })
    }

    /// Returns `true` if the process referred to by `pidfd` is part of the
    /// systemd unit identified by `name`.
    pub async fn match_unit_name_by_pidfd(
        &self,
        pidfd: BorrowedFd<'_>,
        name: &str,
    ) -> zbus::Result<bool> {
        let (path, _, _) = self
            .proxy
            .get_unit_by_pidfd(pidfd.into())
            .await
            .inspect_err(|err| tracing::error!(%err, "Failed to lookup unit by pidfd"))?;
        let conn = self.proxy.inner().connection();
        let systemd_unit = Systemd1UnitProxy::new(conn, path).await?;
        let unit_names = systemd_unit
            .names()
            .await
            .inspect_err(|err| tracing::error!(%err, "Failed to look up systemd unit names"))?;
        let is_match = unit_names.iter().any(|unit_name| unit_name == name);
        Ok(is_match)
    }
}

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait Systemd1Manager {
    #[zbus(name = "GetUnitByPIDFD")]
    fn get_unit_by_pidfd(&self, pidfd: Fd<'_>) -> zbus::Result<(OwnedObjectPath, String, Vec<u8>)>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
trait Systemd1Unit {
    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn names(&self) -> zbus::Result<Vec<String>>;
}
