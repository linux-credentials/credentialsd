#!/usr/bin/env python3
import sys
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio, GObject, Gtk, Adw  # noqa: E402

res = Gio.Resource.load("build/resources.gresource")
Gio.resources_register(res)


@Gtk.Template(resource_path="/xyz/iinuwa/credentialsd/DemoCredentialsUi/window.ui")
class MainWindow(Gtk.ApplicationWindow):
    __gtype_name__ = "MyAppWindow"

    username = Gtk.Template.Child()
    make_credential_btn = Gtk.Template.Child()
    get_assertion_btn = Gtk.Template.Child()
    resident_credential_options_list = ["preferred", "required", "discouraged"]
    uv_prefs_dropdown = Gtk.Template.Child()

    def on_activate(self, app):
        # Create a Builder
        builder = Gtk.Builder()
        builder.add_from_file("build/window.ui")
        self.uv_prefs_list = Gtk.StringList()
        # Obtain and show the main window
        self.win = builder.get_object("main_window")
        self.win.set_application(
            self
        )  # Application will close once it no longer has active windows attached to it
        self.win.present()

    @Gtk.Template.Callback()
    def on_register(self, *args):
        print(f"register clicked: {args}")

    @Gtk.Template.Callback()
    def on_authenticate(self, *args):
        options = self._get_authentication_options()
        print(f"authenticate clicked: {options}")
        print()

    @GObject.Property(type=Gtk.StringList)
    def uv_prefs(self):
        model = Gtk.StringList()
        for o in ["preferred", "required", "discouraged"]:
            model.append(o)
        return model

    @GObject.Property(type=Gtk.StringList)
    def resident_credential_options(self):
        model = Gtk.StringList()
        for o in ["preferred", "required", "discouraged"]:
            model.append(o)
        return model

    def _get_authentication_options(self):
        return {
            "userVerification": self.uv_prefs_dropdown.get_selected_item().get_string()
        }


class MyApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connect("activate", self.on_activate)

    def on_activate(self, app):
        self.win = MainWindow(application=app)
        self.win.present()


app = MyApp(application_id="xyz.iinuwa.credentialsd.DemoCredentialsUi")
app.run(sys.argv)
