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
        pub username: RefCell<Option<String>>,
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
    pub fn new(id: &str, name: &str, username: &Option<String>) -> Self {
        let mut builder = Object::builder().property("id", id).property("name", name);
        if let Some(username) = username {
            builder = builder.property("username", username);
        }
        builder.build()
    }
}

impl From<crate::gui::view_model::Credential> for CredentialObject {
    fn from(value: crate::gui::view_model::Credential) -> Self {
        Self::new(&value.id, &value.name, &value.username)
    }
}

impl From<&crate::gui::view_model::Credential> for CredentialObject {
    fn from(value: &crate::gui::view_model::Credential) -> Self {
        Self::new(&value.id, &value.name, &value.username)
    }
}

impl From<CredentialObject> for crate::gui::view_model::Credential {
    fn from(value: CredentialObject) -> Self {
        Self {
            id: value.id(),
            name: value.name(),
            username: value.username(),
        }
    }
}
