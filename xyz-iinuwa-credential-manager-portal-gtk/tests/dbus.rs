mod config;

use std::collections::HashMap;

use client::DbusClient;
use zbus::zvariant::Value;

#[test]
fn test_client_capabilities() {
    let client = DbusClient::new();
    let msg = client.call_method("GetClientCapabilities", &()).unwrap();
    let body = msg.body();
    let rsp: HashMap<String, Value> = body.deserialize().unwrap();

    let capabilities = HashMap::from([
        ("conditionalCreate", false),
        ("conditionalGet", false),
        ("hybridTransport", false),
        ("passkeyPlatformAuthenticator", false),
        ("userVerifyingPlatformAuthenticator", false),
        ("relatedOrigins", false),
        ("signalAllAcceptedCredentials", false),
        ("signalCurrentUserDetails", false),
        ("signalUnknownCredential", false),
    ]);
    for (key, expected) in capabilities.iter() {
        let value: &Value = rsp.get(*key).unwrap();
        assert_eq!(*expected, value.try_into().unwrap());
    }
}

mod client {
    use crate::config::{INTERFACE, PATH, SERVICE_DIR, SERVICE_NAME};
    use gtk::gio::{TestDBus, TestDBusFlags};
    use serde::Serialize;
    use zbus::{blocking::Connection, zvariant::DynamicType, Message};

    fn init_test_dbus() -> TestDBus {
        let dbus = TestDBus::new(TestDBusFlags::NONE);

        // assumes this runs in root of Cargo project.
        let current_dir = std::env::current_dir().unwrap();
        let service_dir = current_dir.join(SERVICE_DIR);
        println!("{:?}", service_dir);
        dbus.add_service_dir(service_dir.to_str().unwrap());

        dbus.up();
        dbus
    }

    pub(super) struct DbusClient {
        _bus: TestDBus,
    }

    impl DbusClient {
        pub fn new() -> Self {
            Self {
                _bus: init_test_dbus(),
            }
        }

        pub fn call_method<B>(&self, method_name: &str, body: &B) -> zbus::Result<Message>
        where
            B: Serialize + DynamicType,
        {
            let connection = Connection::session().unwrap();
            connection.call_method(Some(SERVICE_NAME), PATH, Some(INTERFACE), method_name, body)
        }
    }
}
