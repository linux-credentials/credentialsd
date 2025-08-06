use async_std::channel::{Receiver, Sender};
use gettextrs::gettext;
use tracing::{debug, info};

use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::{gdk, gio, glib};

use super::{ViewModel, window::CredentialsUiWindow};
use crate::config::{APP_ID, PKGDATADIR, PROFILE, VERSION};
use crate::gui::view_model::{ViewEvent, ViewUpdate};

mod imp {
    use crate::gui::view_model::gtk::ModelState;

    use super::*;
    use glib::{WeakRef, clone};
    use std::{
        cell::{OnceCell, RefCell},
        time::Duration,
    };

    #[derive(Debug, Default)]
    pub struct CredentialsUi {
        pub window: OnceCell<WeakRef<CredentialsUiWindow>>,

        pub(super) tx: RefCell<Option<Sender<ViewEvent>>>,
        pub(super) rx: RefCell<Option<Receiver<ViewUpdate>>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for CredentialsUi {
        const NAME: &'static str = "CredentialsUi";
        type Type = super::CredentialsUi;
        type ParentType = gtk::Application;
    }

    impl ObjectImpl for CredentialsUi {}

    impl ApplicationImpl for CredentialsUi {
        fn activate(&self) {
            debug!("GtkApplication<CredentialsUi>::activate");
            self.parent_activate();
            let app = self.obj();

            if let Some(window) = self.window.get() {
                let window = window.upgrade().unwrap();
                window.present();
                return;
            }

            let tx = self.tx.take().expect("sender to be initiated");
            let rx = self.rx.take().expect("receiver to be initiated");
            let view_model = ViewModel::new(tx, rx);
            let vm2 = view_model.clone();
            let window = CredentialsUiWindow::new(&app, view_model);
            let window2 = window.clone();
            vm2.clone().connect_completed_notify(move |vm| {
                if vm.completed() {
                    glib::spawn_future_local(clone!(
                        #[weak]
                        window2,
                        async move {
                            // Wait to show confirmation before closing.
                            async_std::task::sleep(Duration::from_millis(500)).await;
                            gtk::prelude::WidgetExt::activate_action(&window2, "window.close", None)
                                .unwrap()
                        }
                    ));
                }
            });
            let window3 = window.clone();
            // TODO: merge these state callbacks into a single function
            vm2.clone().connect_state_notify(move |vm| {
                if let ModelState::Cancelled = vm.state() {
                    glib::spawn_future_local(clone!(
                        #[weak]
                        window3,
                        async move {
                            gtk::prelude::WidgetExt::activate_action(&window3, "window.close", None)
                                .unwrap()
                        }
                    ));
                }
            });
            self.window
                .set(window.downgrade())
                .expect("Window already set.");

            app.main_window().present();
        }

        fn startup(&self) {
            debug!("GtkApplication<CredentialsUi>::startup");
            self.parent_startup();
            let app = self.obj();

            // Set icons for shell
            gtk::Window::set_default_icon_name(APP_ID);

            app.setup_css();
            app.setup_gactions();
            app.setup_accels();
        }
    }

    impl GtkApplicationImpl for CredentialsUi {}
}

glib::wrapper! {
    pub struct CredentialsUi(ObjectSubclass<imp::CredentialsUi>)
        @extends gio::Application, gtk::Application,
        @implements gio::ActionMap, gio::ActionGroup;
}

impl CredentialsUi {
    fn main_window(&self) -> CredentialsUiWindow {
        self.imp().window.get().unwrap().upgrade().unwrap()
    }

    fn setup_gactions(&self) {
        // Quit
        let action_quit = gio::ActionEntry::builder("quit")
            .activate(move |app: &Self, _, _| {
                // This is needed to trigger the delete event and saving the window state
                app.main_window().close();
                app.quit();
            })
            .build();

        // About
        let action_about = gio::ActionEntry::builder("about")
            .activate(|app: &Self, _, _| {
                app.show_about_dialog();
            })
            .build();
        self.add_action_entries([action_quit, action_about]);
    }

    // Sets up keyboard shortcuts
    fn setup_accels(&self) {
        self.set_accels_for_action("app.quit", &["<Control>q"]);
        self.set_accels_for_action("window.close", &["<Control>w"]);
    }

    fn setup_css(&self) {
        let provider = gtk::CssProvider::new();
        provider.load_from_resource("/xyz/iinuwa/credentialsd/CredentialsUi/style.css");
        if let Some(display) = gdk::Display::default() {
            gtk::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    }

    fn show_about_dialog(&self) {
        let dialog = gtk::AboutDialog::builder()
            .logo_icon_name(APP_ID)
            .license_type(gtk::License::Lgpl30Only)
            .website("https://github.com/linux-credentials/linux-webauthn-portal-api")
            .version(VERSION)
            .transient_for(&self.main_window())
            .translator_credits(gettext("translator-credits"))
            .modal(true)
            .authors(vec!["Isaiah Inuwa <isaiah.inuwa@gmail.com>"])
            .build();

        dialog.present();
    }

    pub fn run(&self) -> glib::ExitCode {
        info!("Credentials UI ({})", APP_ID);
        info!("Version: {} ({})", VERSION, PROFILE);
        info!("Datadir: {}", PKGDATADIR);

        ApplicationExtManual::run(self)
    }

    pub(crate) fn new(tx: Sender<ViewEvent>, rx: Receiver<ViewUpdate>) -> Self {
        let app: Self = glib::Object::builder()
            .property("application-id", APP_ID)
            .property(
                "resource-base-path",
                "/xyz/iinuwa/credentialsd/CredentialUI/",
            )
            .build();
        app.imp().tx.replace(Some(tx));
        app.imp().rx.replace(Some(rx));
        app
    }
}
