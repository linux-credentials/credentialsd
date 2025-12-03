#!/usr/bin/env python3
import json
import os
import secrets
import sys
from pprint import pprint

from dbus_next.glib import MessageBus, ProxyInterface
from dbus_next import DBusError, Message, MessageType, Variant

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio, GObject, Gtk, Adw  # noqa: E402

import main as api
import webauthn
import util

res = Gio.Resource.load(f"{os.path.dirname(os.path.realpath(__file__))}/resources.gresource")
Gio.resources_register(res)

bus = MessageBus().connect_sync()

with open(f"{os.path.dirname(os.path.realpath(__file__))}/xyz.iinuwa.credentialsd.Credentials.xml", "r") as f:
    introspection = f.read()

proxy_object = bus.get_proxy_object(
    "xyz.iinuwa.credentialsd.Credentials",
    "/xyz/iinuwa/credentialsd/Credentials",
    introspection,
)

INTERFACE = proxy_object.get_interface("xyz.iinuwa.credentialsd.Credentials1")



@Gtk.Template(resource_path="/xyz/iinuwa/credentialsd/DemoCredentialsUi/window.ui")
class MainWindow(Gtk.ApplicationWindow):
    __gtype_name__ = "MyAppWindow"

    username = Gtk.Template.Child()
    make_credential_btn = Gtk.Template.Child()
    get_assertion_btn = Gtk.Template.Child()
    resident_credential_options_list = ["preferred", "required", "discouraged"]
    uv_prefs_dropdown = Gtk.Template.Child()
    rp_id = "example.com"
    origin = "https://example.com"
    interface = None

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
        create_passkey(INTERFACE, self.origin, self.origin, options)

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
        user_verification = self.uv_prefs_dropdown.get_selected_item().get_string()
        username = self.username.get_text()
        user_handle = username.encode('utf-8')
        options = {
            "challenge": util.b64_encode(secrets.token_bytes(16)),
            "rp": {
                "name": "Example Org",
                "id": self.rp_id,
            },
            "user": {
                "id": util.b64_encode(user_handle),
                "name": username,
                "displayName": username,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257},
                {"type": "public-key", "alg": -8},
            ],
            "userVerification": user_verification,
        }

        return options



class MyApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connect("activate", self.on_activate)

    def on_activate(self, app):
        self.win = MainWindow(application=app)
        self.win.present()


def create_passkey(interface: ProxyInterface, origin, top_origin, options):
    is_same_origin = origin == top_origin
    print(
        f"Sending {'same' if is_same_origin else 'cross'}-origin request for {origin} using options:"
    )
    pprint(options)
    print()

    req_json = json.dumps(options)
    req = {
        "type": Variant("s", "publicKey"),
        "origin": Variant("s", origin),
        "is_same_origin": Variant("b", is_same_origin),
        "publicKey": Variant("a{sv}", {"request_json": Variant("s", req_json)}),
    }

    rsp = interface.call_create_credential_sync(req)

    print("Received response")
    pprint(rsp)
    if rsp["type"].value != "public-key":
        raise Exception(
            f"Invalid credential type received: expected 'public-key', received {rsp['type'.value]}"
        )

    response_json = json.loads(
        rsp["public_key"].value["registration_response_json"].value
    )
    return webauthn.verify_create_response(response_json, options, origin)

app = MyApp(application_id="xyz.iinuwa.credentialsd.DemoCredentialsUi")
app.run(sys.argv)
