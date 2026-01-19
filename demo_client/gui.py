#!/usr/bin/env python3
from contextlib import closing
import functools
import json
import math
import os
from pathlib import Path
from pprint import pprint
import secrets
import sqlite3
import sys
import time
from typing import Optional
import uuid

from dbus_next.glib import MessageBus, ProxyInterface
from dbus_next import DBusError, Message, MessageType, Variant

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("GdkWayland", "4.0")
gi.require_version("Adw", "1")
from gi.repository import GdkWayland, Gio, GObject, Gtk, Adw  # noqa: E402

import webauthn  # noqa: E402
import util  # noqa: E402


def dbus_error_from_message(msg: Message):
    assert msg.message_type == MessageType.ERROR
    return DBusError(msg.error_name, msg.body[0] if msg.body else None, reply=msg)


DBusError._from_message = dbus_error_from_message

INTERFACE = None
DB = None
KEY = None

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
    uv_pref_dropdown = Gtk.Template.Child()
    discoverable_cred_pref_dropdown = Gtk.Template.Child()
    rp_id = "example.com"
    origin = "https://example.com"
    interface = None

    def on_activate(self, app):
        # Create a Builder
        builder = Gtk.Builder()
        builder.add_from_file("build/window.ui")
        # Obtain and show the main window
        self.win = builder.get_object("main_window")
        self.win.set_application(
            self
        )  # Application will close once it no longer has active windows attached to it
        self.win.present()

    @Gtk.Template.Callback()
    def on_register(self, *args):
        print("register clicked")
        now = math.floor(time.time())
        cur = DB.cursor()
        username = self.username.get_text()
        if not username:
            print("Username is required")
            return
        cur.execute(
            "select user_id, user_handle from users where username = ?", (username,)
        )
        if row := cur.fetchone():
            user_id = row[0]
            user_handle = row[1]
            print(f"user found for {username}: <id: {user_id}, handle: {user_handle}>")
        else:
            user_handle = secrets.token_bytes(16)
            user_id = None
            print(
                f"user created for {username}: <id: {user_id}, handle: {user_handle}>"
            )
        options = self._get_registration_options(user_handle, username)
        print(f"registration options: {options}")
        def cb(user_id, toplevel, handle):
            cur = DB.cursor()
            window_handle = "wayland:{handle}"
            auth_data = create_passkey(INTERFACE, window_handle, self.origin, self.origin, options)
            if not user_id:
                cur.execute(
                    "insert into users (username, user_handle, created_time) values (?, ?, ?)",
                    (username, user_handle, now),
                )
                user_id = cur.lastrowid
            params = {
                "user_handle": user_handle,
                "cred_id": auth_data.cred_id,
                "aaguid": str(uuid.UUID(bytes=bytes(auth_data.aaguid))),
                "sign_count": None if auth_data.sign_count == 0 else auth_data.sign_count,
                "backup_eligible": 1 if "BE" in auth_data.flags else 0,
                "backup_state": 1 if "BS" in auth_data.flags else 0,
                "uv_initialized": 1 if "UV" in auth_data.flags else 0,
                "cose_pub_key": auth_data.pub_key_bytes,
                "created_time": now,
            }

            add_passkey_sql = """
                insert into user_passkeys
                (user_handle, cred_id, aaguid, sign_count, backup_eligible, backup_state, uv_initialized, cose_pub_key, created_time)
                values
                (:user_handle, :cred_id, :aaguid, :sign_count, :backup_eligible, :backup_state, :uv_initialized, :cose_pub_key, :created_time)
            """
            cur.execute(add_passkey_sql, params)
            print("Added passkey")
            DB.commit()
            cur.close()
        toplevel = self.get_surface()
        toplevel.export_handle(functools.partial(cb, user_id))
        cur.close()

    @Gtk.Template.Callback()
    def on_authenticate(self, *args):
        username = self.username.get_text()
        if username:
            print(f"Using username-flow: {username}")
            sql = """
            select p.user_handle, cred_id, backup_eligible, backup_state, cose_pub_key, sign_count
            from user_passkeys p
            inner join users u on u.user_handle = p.user_handle
            where u.username = ?
            """
            with closing(DB.cursor()) as cur:
                cur.execute(sql, (username,))
                user_creds = []
                for row in cur.fetchall():
                    [
                        user_handle,
                        cred_id,
                        backup_eligible,
                        backup_state,
                        pub_key,
                        sign_count,
                    ] = row
                    user_cred = {
                        "user_handle": user_handle,
                        "cred_id": cred_id,
                        "backup_eligible": backup_eligible,
                        "backup_state": backup_state,
                        "pub_key": pub_key,
                        "sign_count": sign_count,
                    }
                    user_creds.append(user_cred)
            cred_ids = [c["cred_id"] for c in user_creds]
        else:
            print("using username-less flow")
            cred_ids = []

        options = self._get_authentication_options(cred_ids)
        print(f"authenticate clicked: {options}")

        def retrieve_user_cred(
            user_handle: Optional[bytes], cred_id: bytes
        ) -> Optional[dict]:
            with closing(DB.cursor()) as cur:
                if username:
                    print("using cached user creds")
                    return next(
                        (
                            u
                            for u in user_creds
                            if u["cred_id"] == cred_id
                            and (user_handle is None or user_handle == u["user_handle"])
                        ),
                        None,
                    )
                else:
                    if not user_handle:
                        print("No user handle given, cannot look up user")
                        return None
                    sql = """
                        select user_handle, cred_id, backup_eligible, backup_state, cose_pub_key, sign_count
                        from user_passkeys
                        where user_handle = ? and cred_id = ?
                    """
                    cur.execute(sql, (user_handle, cred_id))
                    if row := cur.fetchone():
                        [
                            user_handle,
                            cred_id,
                            backup_eligible,
                            backup_state,
                            pub_key,
                            sign_count,
                        ] = row
                        user_cred = {
                            "user_handle": user_handle,
                            "cred_id": cred_id,
                            "backup_eligible": backup_eligible,
                            "backup_state": backup_state,
                            "pub_key": pub_key,
                            "sign_count": sign_count,
                        }
                        return user_cred
                    else:
                        return None
        def cb(toplevel, window_handle):
            print(f"received window handle: {window_handle}")
            window_handle = f"wayland:{window_handle}"

            auth_data = get_passkey(
                INTERFACE,
                window_handle,
                self.origin,
                self.origin,
                self.rp_id,
                cred_ids,
                retrieve_user_cred,
            )
            print("Received passkey:")
            pprint(auth_data)

        toplevel = self.get_surface()
        print(type(toplevel))
        toplevel.export_handle(cb)
        print("Waiting for handle to complete")
        # event.wait()

    @GObject.Property(type=Gtk.StringList)
    def uv_pref(self):
        model = Gtk.StringList()
        for o in ["preferred", "required", "discouraged"]:
            model.append(o)
        return model

    @GObject.Property(type=Gtk.StringList)
    def discoverable_cred_pref(self):
        model = Gtk.StringList()
        for o in ["preferred", "required", "discouraged"]:
            model.append(o)
        return model

    def _get_registration_options(self, user_handle: bytes, username: str):
        username = self.username.get_text()
        user_verification = self.uv_pref_dropdown.get_selected_item().get_string()
        resident_key = (
            self.discoverable_cred_pref_dropdown.get_selected_item().get_string()
        )
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
            "authenticatorSelection": {
                "residentKey": resident_key,
            },
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
    interface: ProxyInterface, window_handle: str, origin: str, top_origin: str, options: dict
) -> webauthn.AuthenticatorData:
    is_same_origin = origin == top_origin
    print(
        f"Sending {'same' if is_same_origin else 'cross'}-origin request for {origin} using options:"
    )
    # pprint(options)
    print()

    req_json = json.dumps(options)
    req = {
        "type": Variant("s", "publicKey"),
        "origin": Variant("s", origin),
        "is_same_origin": Variant("b", is_same_origin),
        "publicKey": Variant("a{sv}", {"request_json": Variant("s", req_json)}),
    }

    rsp = interface.call_create_credential_sync([window_handle, req])

    # print("Received response")
    # pprint(rsp)
    if rsp["type"].value != "public-key":
        raise Exception(
            f"Invalid credential type received: expected 'public-key', received {rsp['type'.value]}"
        )

    response_json = json.loads(
        rsp["public_key"].value["registration_response_json"].value
    )
    return webauthn.verify_create_response(response_json, options, origin)


def get_passkey(interface, window_handle, origin, top_origin, rp_id, cred_ids, cred_lookup_fn):
    is_same_origin = origin == top_origin
    options = {
        "challenge": util.b64_encode(secrets.token_bytes(16)),
        "rpId": rp_id,
        "allowCredentials": [
            {"type": "public-key", "id": util.b64_encode(c)} for c in cred_ids
        ],
    }

    print(
        f"Sending {'same' if is_same_origin else 'cross'}-origin request for {origin} using options:"
    )
    # pprint(options)
    print()

    req_json = json.dumps(options)
    req = {
        "type": Variant("s", "publicKey"),
        "origin": Variant("s", origin),
        "is_same_origin": Variant("b", is_same_origin),
        "publicKey": Variant("a{sv}", {"request_json": Variant("s", req_json)}),
    }

    rsp = interface.call_get_credential_sync([window_handle, req])
    # print("Received response")
    # pprint(rsp)
    if rsp["type"].value != "public-key":
        raise Exception(
            f"Invalid credential type received: expected 'public-key', received {rsp['type'.value]}"
        )

    response_json = json.loads(
        rsp["public_key"].value["authentication_response_json"].value
    )
    response_json["rawId"] = util.b64_decode(response_json["rawId"])
    if user_handle := response_json["response"].get("userHandle"):
        response_json["response"]["userHandle"] = util.b64_decode(user_handle)

    return webauthn.verify_get_response(response_json, options, origin, cred_lookup_fn)


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
    db_path = (
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "xyz.iinuwa.credentialsd.DemoCredentialsUi"
        / "users.db"
    )
    db_path.parent.mkdir(exist_ok=True)

    DB = sqlite3.connect(db_path)
    DB.execute("pragma foreign_keys = on")
    user_table_sql = """
        create table if not exists users (
              user_id integer primary key autoincrement
            , username text not null
            , user_handle blob unique not null
            , created_time integer not null
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
