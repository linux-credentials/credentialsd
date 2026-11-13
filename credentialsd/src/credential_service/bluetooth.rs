//! Checks whether Bluetooth is actually usable, i.e. an adapter is powered on.
//!
//! libwebauthn only checks that an adapter exists, but BlueZ keeps adapters
//! around while Bluetooth is turned off.

use std::collections::HashMap;

use zbus::zvariant::{OwnedObjectPath, OwnedValue};

type ManagedObjects = HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>>;

const ADAPTER_INTERFACE: &str = "org.bluez.Adapter1";

/// Returns true if BlueZ has at least one powered-on adapter. Returns false
/// if BlueZ is not running or can't be reached.
///
/// libwebauthn uses the first adapter btleplug reports, so on a machine with
/// several adapters, hybrid can still fail if that one is the one turned off.
pub(crate) async fn adapter_powered() -> bool {
    match managed_objects().await {
        Ok(objects) => any_adapter_powered(&objects),
        Err(err) => {
            tracing::debug!(%err, "Could not query BlueZ adapters");
            false
        }
    }
}

/// One system bus connection, reused because this is polled while a request
/// waits for Bluetooth.
static SYSTEM_BUS: tokio::sync::OnceCell<zbus::Connection> = tokio::sync::OnceCell::const_new();

async fn managed_objects() -> zbus::Result<ManagedObjects> {
    let connection = SYSTEM_BUS.get_or_try_init(zbus::Connection::system).await?;
    let reply = connection
        .call_method(
            Some("org.bluez"),
            "/",
            Some("org.freedesktop.DBus.ObjectManager"),
            "GetManagedObjects",
            &(),
        )
        .await?;
    reply.body().deserialize()
}

fn any_adapter_powered(objects: &ManagedObjects) -> bool {
    objects
        .values()
        .filter_map(|interfaces| interfaces.get(ADAPTER_INTERFACE))
        .filter_map(|props| props.get("Powered"))
        .any(|powered| matches!(**powered, zbus::zvariant::Value::Bool(true)))
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
        assert!(any_adapter_powered(&objects(&[(
            "/org/bluez/hci0",
            Some(true)
        )])));
    }

    #[test]
    fn powered_off_adapter_is_not_usable() {
        assert!(!any_adapter_powered(&objects(&[(
            "/org/bluez/hci0",
            Some(false)
        )])));
        assert!(!any_adapter_powered(&objects(&[("/org/bluez/hci0", None)])));
        assert!(!any_adapter_powered(&HashMap::new()));
    }

    #[test]
    fn any_powered_adapter_is_enough() {
        assert!(any_adapter_powered(&objects(&[
            ("/org/bluez/hci0", Some(false)),
            ("/org/bluez/hci1", Some(true)),
        ])));
    }

    #[test]
    fn other_interfaces_are_ignored() {
        let mut objects = objects(&[]);
        let props = HashMap::from([("Powered".to_string(), OwnedValue::from(true))]);
        objects.insert(
            OwnedObjectPath::try_from("/org/bluez/hci0/dev_00").unwrap(),
            HashMap::from([("org.bluez.Device1".to_string(), props)]),
        );
        assert!(!any_adapter_powered(&objects));
    }
}
