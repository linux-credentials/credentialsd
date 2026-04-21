#![expect(unused)]
#[rustfmt::skip]
mod config;

use std::collections::HashMap;

use client::DbusClient;
use zbus::zvariant::Value;

mod client {
    use crate::config::{INTERFACE, PATH, SERVICE_DIR, SERVICE_NAME};
    use gio::{TestDBus, TestDBusFlags};
    use serde::Serialize;
    use zbus::{blocking::Connection, zvariant::DynamicType, Message};

    pub(super) struct DbusClient {
        bus: TestDBus,
    }

    impl DbusClient {
        pub fn new() -> Self {
            let bus = TestDBus::new(TestDBusFlags::NONE);
            bus.add_service_dir(SERVICE_DIR);
            bus.up();
            Self { bus }
        }

        pub fn call_method<B>(&self, method_name: &str, body: &B) -> zbus::Result<Message>
        where
            B: Serialize + DynamicType,
        {
            let connection = Connection::session().unwrap();
            let message = connection.call_method(
                Some(SERVICE_NAME),
                PATH,
                Some(INTERFACE),
                method_name,
                body,
            );
            connection.close().unwrap();
            message
        }
    }
    impl Drop for DbusClient {
        fn drop(&mut self) {
            self.bus.stop();
        }
    }
}
