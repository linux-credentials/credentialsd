//! Checks whether Bluetooth is actually usable, i.e. an adapter is powered on.
//!
//! libwebauthn only checks that an adapter exists, but BlueZ keeps adapters
//! around while Bluetooth is turned off.

use std::{collections::HashMap, time::Duration};

use zbus::{
    proxy::MethodFlags,
    zvariant::{OwnedObjectPath, OwnedValue},
};

type ManagedObjects = HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>>;

const ADAPTER_INTERFACE: &str = "org.bluez.Adapter1";

/// How long to wait for BlueZ before treating Bluetooth as unavailable, so a
/// stuck bluetoothd can't hold up a request.
const BLUEZ_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BluetoothState {
    /// At least one adapter is powered on.
    Powered,
    /// BlueZ has adapters, but none is powered on.
    Off,
    /// BlueZ isn't running, didn't answer in time, or has no adapters.
    Unavailable,
}

/// Asks BlueZ whether an adapter is powered on.
///
/// libwebauthn uses the first adapter btleplug reports, so on a machine with
/// several adapters, hybrid can still fail if that one is the one turned off.
pub(crate) async fn bluetooth_state() -> BluetoothState {
    match tokio::time::timeout(BLUEZ_TIMEOUT, managed_objects()).await {
        Ok(Ok(objects)) => adapter_state(&objects),
        Ok(Err(err)) => {
            tracing::debug!(%err, "Could not query BlueZ adapters");
            BluetoothState::Unavailable
        }
        Err(_) => {
            tracing::debug!("BlueZ did not answer in time");
            BluetoothState::Unavailable
        }
    }
}

/// Uses a new system bus connection for each check: they only happen at the
/// start of a request and every few seconds while a request waits for
/// Bluetooth, and a cached connection would be tied to the async runtime that
/// created it.
///
/// Doesn't start BlueZ if it isn't running.
async fn managed_objects() -> zbus::Result<ManagedObjects> {
    let connection = zbus::Connection::system().await?;
    let proxy = zbus::Proxy::new(
        &connection,
        "org.bluez",
        "/",
        "org.freedesktop.DBus.ObjectManager",
    )
    .await?;
    proxy
        .call_with_flags("GetManagedObjects", MethodFlags::NoAutoStart.into(), &())
        .await?
        .ok_or_else(|| zbus::Error::Failure("No reply from BlueZ".to_string()))
}

fn adapter_state(objects: &ManagedObjects) -> BluetoothState {
    let mut adapters = objects
        .values()
        .filter_map(|interfaces| interfaces.get(ADAPTER_INTERFACE))
        .peekable();
    if adapters.peek().is_none() {
        return BluetoothState::Unavailable;
    }
    let powered = adapters
        .filter_map(|props| props.get("Powered"))
        .any(|powered| matches!(**powered, zbus::zvariant::Value::Bool(true)));
    if powered {
        BluetoothState::Powered
    } else {
        BluetoothState::Off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn objects(adapters: &[(&str, Option<bool>)]) -> ManagedObjects {
        adapters
            .iter()
            .map(|(path, powered)| {
                let mut props = HashMap::new();
                if let Some(powered) = powered {
                    props.insert("Powered".to_string(), OwnedValue::from(*powered));
                }
                let interfaces = HashMap::from([("org.bluez.Adapter1".to_string(), props)]);
                (OwnedObjectPath::try_from(*path).unwrap(), interfaces)
            })
            .collect()
    }

    #[test]
    fn powered_adapter_is_usable() {
        assert_eq!(
            adapter_state(&objects(&[("/org/bluez/hci0", Some(true))])),
            BluetoothState::Powered
        );
    }

    #[test]
    fn powered_off_adapter_is_off() {
        assert_eq!(
            adapter_state(&objects(&[("/org/bluez/hci0", Some(false))])),
            BluetoothState::Off
        );
        assert_eq!(
            adapter_state(&objects(&[("/org/bluez/hci0", None)])),
            BluetoothState::Off
        );
    }

    #[test]
    fn no_adapter_is_unavailable() {
        assert_eq!(adapter_state(&HashMap::new()), BluetoothState::Unavailable);
    }

    #[test]
    fn any_powered_adapter_is_enough() {
        assert_eq!(
            adapter_state(&objects(&[
                ("/org/bluez/hci0", Some(false)),
                ("/org/bluez/hci1", Some(true)),
            ])),
            BluetoothState::Powered
        );
    }

    #[test]
    fn other_interfaces_are_ignored() {
        let mut objects = objects(&[]);
        let props = HashMap::from([("Powered".to_string(), OwnedValue::from(true))]);
        objects.insert(
            OwnedObjectPath::try_from("/org/bluez/hci0/dev_00").unwrap(),
            HashMap::from([("org.bluez.Device1".to_string(), props)]),
        );
        assert_eq!(adapter_state(&objects), BluetoothState::Unavailable);
    }
}
