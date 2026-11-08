use std::cell::RefCell;

use glib::Object;
use gtk::glib;
use gtk::prelude::*;
use gtk::subclass::prelude::*;

mod imp {
    use super::*;

    #[derive(glib::Properties, Default)]
    #[properties(wrapper_type = super::CredentialObject)]
    pub struct CredentialObject {
        #[property(get, set)]
        pub id: RefCell<String>,

        #[property(get, set)]
        pub name: RefCell<String>,

        #[property(get, set)]
        pub display_name: RefCell<Option<String>>,
    }

    // The central trait for subclassing a GObject
    #[glib::object_subclass]
    impl ObjectSubclass for CredentialObject {
        const NAME: &'static str = "CredentialManagerCredential";
        type Type = super::CredentialObject;
    }

    // Trait shared by all GObjects
    #[glib::derived_properties]
    impl ObjectImpl for CredentialObject {}
}

glib::wrapper! {
    pub struct CredentialObject(ObjectSubclass<imp::CredentialObject>);
}

impl CredentialObject {
    pub fn new(id: &str, name: &str, display_name: &Option<String>) -> Self {
        let mut builder = Object::builder().property("id", id).property("name", name);
        if let Some(display_name) = display_name {
            builder = builder.property("display-name", display_name);
        }
        builder.build()
    }
}

impl From<crate::gui::view_model::Credential> for CredentialObject {
    fn from(value: crate::gui::view_model::Credential) -> Self {
        Self::new(&value.id, &value.name, &value.display_name)
    }
}

impl From<&crate::gui::view_model::Credential> for CredentialObject {
    fn from(value: &crate::gui::view_model::Credential) -> Self {
        Self::new(&value.id, &value.name, &value.display_name)
    }
}

impl From<CredentialObject> for crate::gui::view_model::Credential {
    fn from(value: CredentialObject) -> Self {
        Self {
            id: value.id(),
            name: value.name(),
            display_name: value.display_name(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CredentialObject;
    use crate::gui::view_model::Credential;

    #[test]
    fn credential_object_round_trips_display_name() {
        let cred = Credential {
            id: String::from("abc"),
            name: String::from("alice@example.com"),
            display_name: Some(String::from("Alice")),
        };
        let obj = CredentialObject::from(&cred);
        assert_eq!(obj.name(), "alice@example.com");
        assert_eq!(obj.display_name().as_deref(), Some("Alice"));
        assert_eq!(Credential::from(obj), cred);
    }

    #[test]
    fn credential_object_allows_missing_display_name() {
        let cred = Credential {
            id: String::from("abc"),
            name: String::from("alice@example.com"),
            display_name: None,
        };
        assert_eq!(Credential::from(CredentialObject::from(&cred)), cred);
    }
}
