use std::cell::RefCell;

use gtk::{gdk, gio, glib};

use gtk::subclass::prelude::*;

use gdk::Texture;
use glib::{Properties, clone};
use gtk::{Picture, prelude::*};

use super::application::CredentialsUi;
use super::{ViewModel, device::DeviceObject};
use crate::config::{APP_ID, PROFILE};
use crate::gui::view_model::Transport;

mod imp {
    use crate::gui::view_model::ViewEvent;

    use super::*;

    #[derive(Debug, Properties, gtk::CompositeTemplate)]
    #[properties(wrapper_type = super::CredentialsUiWindow)]
    #[template(resource = "/xyz/iinuwa/credentialsd/CredentialsUi/ui/window.ui")]
    pub struct CredentialsUiWindow {
        #[template_child]
        pub headerbar: TemplateChild<gtk::HeaderBar>,
        pub settings: gio::Settings,
        #[property(get, set)]
        pub view_model: RefCell<Option<ViewModel>>,

        #[template_child]
        pub stack: TemplateChild<gtk::Stack>,

        #[template_child]
        pub usb_nfc_pin_entry: TemplateChild<gtk::PasswordEntry>,

        #[template_child]
        pub new_pin_primary_entry: TemplateChild<gtk::PasswordEntry>,

        #[template_child]
        pub new_pin_confirm_entry: TemplateChild<gtk::PasswordEntry>,

        #[template_child]
        pub new_pin_btn_continue: TemplateChild<gtk::Button>,

        #[template_child]
        pub qr_code_pic: TemplateChild<Picture>,
    }

    #[gtk::template_callbacks]
    impl CredentialsUiWindow {
        #[template_callback]
        fn handle_usb_nfc_pin_entered(&self, entry: &gtk::PasswordEntry) {
            let view_model = &self.view_model.borrow();
            let view_model = view_model.as_ref().unwrap();
            let pin = entry.text().to_string();
            glib::spawn_future_local(clone!(
                #[weak]
                view_model,
                async move {
                    view_model.send_usb_nfc_device_pin(pin).await;
                }
            ));
        }

        #[template_callback]
        fn handle_start_setting_new_pin(&self) {
            let view_model = &self.view_model.borrow();
            let view_model = view_model.as_ref().unwrap();
            // This triggers visibility of the new pin stackpage
            view_model.set_pin_fields_match(false);
        }

        #[template_callback]
        fn handle_setting_pin_change(&self) {
            let pin1 = self.new_pin_primary_entry.text();
            let pin2 = self.new_pin_confirm_entry.text();
            let is_valid = !pin1.is_empty() && pin1 == pin2;
            // Unlock Button if both entries match (and are non-empty)
            self.new_pin_btn_continue.set_sensitive(is_valid);
        }

        #[template_callback]
        fn handle_close_window(&self) {
            self.close_request();
        }

        #[template_callback]
        fn handle_commit_new_pin(&self) {
            let view_model = &self.view_model.borrow();
            let view_model = view_model.as_ref().unwrap();
            let pin = self.new_pin_primary_entry.text().to_string();
            glib::spawn_future_local(clone!(
                #[weak]
                view_model,
                async move {
                    view_model.send_set_new_device_pin(pin).await;
                }
            ));
        }
    }

    impl Default for CredentialsUiWindow {
        fn default() -> Self {
            Self {
                headerbar: TemplateChild::default(),
                settings: gio::Settings::new(APP_ID),
                view_model: RefCell::default(),
                stack: TemplateChild::default(),
                usb_nfc_pin_entry: TemplateChild::default(),
                qr_code_pic: TemplateChild::default(),
                new_pin_primary_entry: TemplateChild::default(),
                new_pin_confirm_entry: TemplateChild::default(),
                new_pin_btn_continue: TemplateChild::default(),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for CredentialsUiWindow {
        const NAME: &'static str = "CredentialsUiWindow";
        type Type = super::CredentialsUiWindow;
        type ParentType = gtk::ApplicationWindow;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.bind_template_callbacks();
        }

        // You must call `Widget`'s `init_template()` within `instance_init()`.
        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    #[glib::derived_properties]
    impl ObjectImpl for CredentialsUiWindow {
        fn constructed(&self) {
            self.parent_constructed();
            let obj = self.obj();

            // Devel Profile
            if PROFILE == "Devel" {
                obj.add_css_class("devel");
            }

            // Load latest window state
            obj.load_window_size();
        }
    }

    impl WidgetImpl for CredentialsUiWindow {}
    impl WindowImpl for CredentialsUiWindow {
        // Save window state on delete event
        fn close_request(&self) -> glib::Propagation {
            if let Some(vm) = self.view_model.borrow().as_ref() {
                if vm
                    .get_sender()
                    .send_blocking(ViewEvent::UserCancelled)
                    .is_err()
                {
                    tracing::warn!(
                        "Failed to notify the backend service that the user cancelled the request."
                    );
                };
            }
            if let Err(err) = self.obj().save_window_size() {
                tracing::warn!("Failed to save window state, {}", &err);
            }

            // Pass close request on to the parent
            self.parent_close_request()
        }
    }

    impl ApplicationWindowImpl for CredentialsUiWindow {}
}

glib::wrapper! {
    pub struct CredentialsUiWindow(ObjectSubclass<imp::CredentialsUiWindow>)
        @extends gtk::Widget, gtk::Window, gtk::ApplicationWindow,
        @implements gtk::Accessible, gio::ActionMap, gio::ActionGroup, gtk::Buildable, gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;

}

impl CredentialsUiWindow {
    pub fn new(app: &CredentialsUi, view_model: ViewModel) -> Self {
        let window: CredentialsUiWindow = glib::Object::builder()
            .property("application", app)
            .property("view-model", view_model)
            .build();
        window.setup_callbacks();
        window
    }

    fn setup_callbacks(&self) {
        let view_model = &self.view_model();
        let view_model = view_model.as_ref().expect("view model to exist");
        let stack: &gtk::Stack = &self.imp().stack.get();
        let qr_code_pic: &Picture = &self.imp().qr_code_pic.get();
        view_model.connect_selected_device_notify(clone!(
            #[weak]
            stack,
            move |vm| {
                let d = vm.selected_device();
                let d = d
                    .and_downcast_ref::<DeviceObject>()
                    .expect("selected device to exist at notify");
                match d.transport().try_into() {
                    Ok(Transport::Usb) => stack.set_visible_child_name("usb_or_nfc"),
                    Ok(Transport::HybridQr) => stack.set_visible_child_name("hybrid_qr"),
                    Ok(Transport::Nfc) => stack.set_visible_child_name("usb_or_nfc"),
                    _ => {}
                };
            }
        ));

        view_model.connect_qr_code_paintable_notify(clone!(
            #[weak]
            qr_code_pic,
            move |vm| {
                let paintable = vm.qr_code_paintable();
                let paintable = paintable.and_downcast_ref::<Texture>();
                qr_code_pic.set_paintable(paintable);
            }
        ));

        view_model.connect_completed_notify(clone!(
            #[weak]
            stack,
            move |vm| {
                if vm.completed() {
                    stack.set_visible_child_name("completed");
                }
            }
        ));

        view_model.connect_failed_notify(clone!(
            #[weak]
            stack,
            move |vm| {
                if vm.failed() {
                    stack.set_visible_child_name("failed");
                }
            }
        ));

        view_model.connect_credentials_notify(clone!(
            #[weak]
            stack,
            move |_vm| {
                stack.set_visible_child_name("choose_credential");
            }
        ));

        view_model.connect_pin_fields_match_notify(clone!(
            #[weak]
            stack,
            move |_vm| {
                stack.set_visible_child_name("set_new_pin");
            }
        ));
    }

    fn save_window_size(&self) -> Result<(), glib::BoolError> {
        let imp = self.imp();

        let (width, height) = self.default_size();

        imp.settings.set_int("window-width", width)?;
        imp.settings.set_int("window-height", height)?;

        Ok(())
    }

    fn load_window_size(&self) {
        let imp = self.imp();

        let width = imp.settings.int("window-width");
        let height = imp.settings.int("window-height");

        self.set_default_size(width, height);
    }
}
