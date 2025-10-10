use std::cell::RefCell;

use gettextrs::gettext;
use glib::Object;
use gtk::glib;
use gtk::prelude::*;
use gtk::subclass::prelude::*;

use crate::gui::view_model::Transport;

mod imp {
    use super::*;

    #[derive(glib::Properties, Default)]
    #[properties(wrapper_type = super::DeviceObject)]
    pub struct DeviceObject {
        #[property(get, set)]
        pub id: RefCell<String>,

        #[property(get, set)]
        pub transport: RefCell<String>,

        #[property(get, set)]
        pub name: RefCell<String>,
    }

    // The central trait for subclassing a GObject
    #[glib::object_subclass]
    impl ObjectSubclass for DeviceObject {
        const NAME: &'static str = "CredentialManagerDevice";
        type Type = super::DeviceObject;
    }

    // Trait shared by all GObjects
    #[glib::derived_properties]
    impl ObjectImpl for DeviceObject {}
}

glib::wrapper! {
    pub struct DeviceObject(ObjectSubclass<imp::DeviceObject>);
}

impl DeviceObject {
    pub fn new(id: &str, transport: &Transport, name: &str) -> Self {
        //, label: &str, icon_name: &str) -> Self {
        let transport = transport.as_str();
        Object::builder()
            .property("id", id)
            .property("transport", transport)
            .property("name", name)
            .build()
    }
}

fn transport_name(transport: &Transport) -> String {
    match transport {
        Transport::Ble => gettext("A Bluetooth device"),
        Transport::Internal => gettext("This device"),
        Transport::HybridQr => gettext("A mobile device"),
        Transport::HybridLinked => gettext("Linked Device"),
        Transport::Nfc => gettext("An NFC device"),
        Transport::Usb => gettext("A security key"),
        // Transport::PasskeyProvider => ("symbolic-link-symbolic", "ACME Password Manager"),
    }
}
impl From<crate::gui::view_model::Device> for DeviceObject {
    fn from(value: crate::gui::view_model::Device) -> Self {
        let name = transport_name(&value.transport);
        Self::new(&value.id, &value.transport, &name)
    }
}

impl From<&crate::gui::view_model::Device> for DeviceObject {
    fn from(value: &crate::gui::view_model::Device) -> Self {
        let name = transport_name(&value.transport);
        Self::new(&value.id, &value.transport, &name)
    }
}

impl TryFrom<DeviceObject> for crate::gui::view_model::Device {
    type Error = String;

    fn try_from(value: DeviceObject) -> Result<Self, Self::Error> {
        let transport: Transport = value.transport().try_into()?;
        Ok(Self {
            id: value.id(),
            transport,
        })
    }
}
