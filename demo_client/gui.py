#!/usr/bin/env python3
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
from pprint import pprint

from dbus_next.glib import MessageBus, ProxyInterface
from dbus_next import DBusError, Message, MessageType, Variant

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio, GObject, Gtk, Adw  # noqa: E402

import webauthn  # noqa: E402
import util  # noqa: E402

INTERFACE = None
DB = None

RESOURCE_FILE = Gio.Resource.load(
    f"{os.path.dirname(os.path.realpath(__file__))}/resources.gresource"
)
Gio.resources_register(RESOURCE_FILE)


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
        options = self._get_registration_options()
        print(f"register clicked: {options}")
        auth_data = create_passkey(INTERFACE, self.origin, self.origin, options)
        cur = DB.cursor()
        cur.execute("""
            insert into user_passkeys
            (user_handle, cred_id, aaguid, sign_count, backup_eligible, backup_state, uv_initialized, cose_pub_key)
        """)
        auth_data

    @Gtk.Template.Callback()
    def on_authenticate(self, *args):
        options = self._get_registration_options()
        print(f"authenticate clicked: {options}")

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

    def _get_registration_options(self):
        user_verification = self.uv_prefs_dropdown.get_selected_item().get_string()
        username = self.username.get_text()
        user_handle = username.encode("utf-8")
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

    def _get_authentication_options(self, cred_ids):
        options = {
            "challenge": util.b64_encode(secrets.token_bytes(16)),
            "rpId": self.rp_id,
            "allowCredentials": [
                {"type": "public-key", "id": util.b64_encode(cred_id)}
                for cred_id in cred_ids
            ],
        }
        return options


class MyApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connect("activate", self.on_activate)

    def on_activate(self, app):
        self.win = MainWindow(application=app)
        self.win.present()


def create_passkey(
    interface: ProxyInterface, origin: str, top_origin: str, options: dict
) -> webauthn.AuthenticatorData:
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


def connect_to_bus():
    global INTERFACE
    bus = MessageBus().connect_sync()

    with open(
        f"{os.path.dirname(os.path.realpath(__file__))}/xyz.iinuwa.credentialsd.Credentials.xml",
        "r",
    ) as f:
        introspection = f.read()

    proxy_object = bus.get_proxy_object(
        "xyz.iinuwa.credentialsd.Credentials",
        "/xyz/iinuwa/credentialsd/Credentials",
        introspection,
    )
    INTERFACE = proxy_object.get_interface("xyz.iinuwa.credentialsd.Credentials1")


def setup_db():
    global DB
    # This is just for testing/temporary use, so put it in cache
    path = (
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "xyz.iinuwa.credentialsd.DemoCredentialsUi"
        / "users.db"
    )
    print(path)
    path.parent.mkdir(exist_ok=True)
    DB = sqlite3.connect(path)
    DB.execute("pragma foreign_keys = on")
    user_table_sql = """
        create table if not exists users (
              user_id integer primary key autoincrement
            , username text
            , user_handle blob unique
            , created_date integer not null
        )
        strict
    """
    passkey_table_sql = """
        create table if not exists user_passkeys (
              user_handle blob
            , cred_id blob
            , aaguid text not null
            , sign_count integer null
            , backup_eligible integer not null
            , backup_state integer not null
            , uv_initialized integer not null
            , cose_pub_key blob not null
            , created_time integer not null
            , updated_time integer
            , primary key (user_handle, cred_id)
        )
        strict
    """
    cur = DB.cursor()
    cur.execute(user_table_sql)
    cur.execute(passkey_table_sql)
    cur.close()


def main():
    connect_to_bus()
    setup_db()

    app = MyApp(application_id="xyz.iinuwa.credentialsd.DemoCredentialsUi")
    app.run(sys.argv)
    DB.close()


if __name__ == "__main__":
    main()
