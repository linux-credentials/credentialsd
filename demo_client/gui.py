#!/usr/bin/env python3
from asyncio.futures import Future
import asyncio
from contextlib import closing
import json
import math
import os
from pathlib import Path
from pprint import pprint
import secrets
import sqlite3
import sys
import threading
import time
from typing import Optional, Coroutine
import uuid

from dbus_next.aio import MessageBus, ProxyInterface
from dbus_next.constants import ErrorType
from dbus_next.proxy_object import BaseProxyInterface
from dbus_next import DBusError, Message, MessageType, Variant

import gi

from gi.events import GLibEventLoop

gi.require_version("Gtk", "4.0")
gi.require_version("GdkWayland", "4.0")
gi.require_version("Adw", "1")
from gi.repository import GdkWayland, Gio, GLib, GObject, Gtk, Adw  # noqa: E402,F401  # ty: ignore[unresolved-import]


import webauthn  # noqa: E402
import util  # noqa: E402


def dbus_error_from_message(msg: Message):
    assert msg.message_type == MessageType.ERROR
    return DBusError(msg.error_name, msg.body[0] if msg.body else None, reply=msg)


DBusError._from_message = dbus_error_from_message  # ty: ignore[invalid-assignment]


@staticmethod
def dbus_proxy_object_check_method_return(msg, signature=None):
    if msg.message_type == MessageType.ERROR:
        raise DBusError._from_message(msg)
    elif msg.message_type != MessageType.METHOD_RETURN:
        raise DBusError(
            ErrorType.CLIENT_ERROR, "method call didnt return a method return", msg
        )
    elif signature is not None and msg.signature != signature:
        raise DBusError(
            ErrorType.CLIENT_ERROR,
            f'method call returned unexpected signature: "{msg.signature}", expected {signature}',
            msg,
        )


BaseProxyInterface._check_method_return = dbus_proxy_object_check_method_return

APP_ID = "xyz.iinuwa.credentialsd.DemoCredentialsUi"
APP_NAME = "Demo UI"  # TODO: This should be looked up from .desktop file.
LOOP: asyncio.AbstractEventLoop = None  # ty: ignore[invalid-assignment]

INTERFACE: ProxyInterface = None  # ty: ignore[invalid-assignment]
DB: sqlite3.Connection = None  # ty: ignore[invalid-assignment]
RESOURCE_FILE = Gio.Resource.load(
    f"{os.path.dirname(os.path.realpath(__file__))}/resources.gresource"
)
Gio.resources_register(RESOURCE_FILE)


def task_spawn(coro: Coroutine, callback):
    fut = asyncio.run_coroutine_threadsafe(coro, LOOP)

    def call_when_done():
        if callback:
            callback(fut.result())
        else:
            fut.result()

    fut.add_done_callback(lambda _: GLib.idle_add(call_when_done))


async def get_surface_handle(toplevel) -> str:
    # Ensure it's a Wayland toplevel
    if not isinstance(toplevel, GdkWayland.WaylandToplevel):
        # X11 toplevel is synchronous
        return toplevel.export_handle()

    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def on_handle_exported(_toplevel, handle):
        loop.call_soon_threadsafe(future.set_result, handle)

    toplevel.export_handle(on_handle_exported)

    handle = await future
    return handle


class PortalRequest[T]:
    def __init__(self, token: str, fut: Future):
        self.token: str = token
        self._fut: Future = fut

    async def wait(self) -> T:
        return await self._fut


def create_portal_request_message_handler(bus: MessageBus) -> PortalRequest:
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    if not bus.connected or bus.unique_name is None:
        raise Exception("Bus is not connected")
    unique_name = bus.unique_name[1:].replace(".", "_")
    token = secrets.token_hex(16)
    object_path = f"/org/freedesktop/portal/desktop/request/{unique_name}/{token}"

    def message_handler(msg: Message):
        if future.done():
            return False

        message_matches = (
            msg.path == object_path
            and msg.message_type == MessageType.SIGNAL
            and msg.destination == bus.unique_name
            and msg.interface == "org.freedesktop.portal.Request"
            and msg.member == "Response"
        )
        if not message_matches:
            return False

        [code, value] = msg.body
        if code == 0:
            future.set_result(value)
        elif code == 1:
            future.set_exception(Exception("Portal request cancelled"))
            raise
        elif code == 2 and "error" in value:
            future.set_exception(
                Exception(f"Portal returned an error: {value['error'].value}")
            )
        else:
            future.set_exception(Exception("Portal returned an unknown error"))
        return True

    def when_done(_fut):
        bus.remove_message_handler(message_handler)

    future.add_done_callback(when_done)
    bus.add_message_handler(message_handler)
    print(f"Listening for {object_path}")
    return PortalRequest(token, future)


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

    def on_activate(self, _app):
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
        task_spawn(self.register_passkey(), None)

    async def register_passkey(self):
        now = math.floor(time.time())
        db = connect_db()
        cur = db.cursor()
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

        toplevel = self.get_surface()
        handle = await get_surface_handle(toplevel)

        window_handle = f"wayland:{handle}"
        print(window_handle)
        auth_data = await create_passkey(
            INTERFACE, window_handle, self.origin, self.origin, options
        )

        try:
            handle = window_handle[window_handle.find(":") + 1 :]
            toplevel.unexport_handle(handle)
        except Exception as err:
            print(err)

        if not user_id:
            cur.execute(
                "insert into users (username, user_handle, created_time) values (?, ?, ?)",
                (username, user_handle, now),
            )
            user_id = cur.lastrowid
        params = {
            "user_handle": user_handle,
            "cred_id": auth_data.cred_id,
            "aaguid": str(uuid.UUID(bytes=auth_data.aaguid)),
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
        db.commit()
        cur.close()

    @Gtk.Template.Callback()
    def on_authenticate(self, *args):
        print("authenticate clicked")
        task_spawn(self.assert_passkey(), None)

    async def assert_passkey(self):
        username = self.username.get_text()
        if username:
            print(f"Using username-flow: {username}")
            sql = """
            select p.user_handle, cred_id, backup_eligible, backup_state, cose_pub_key, sign_count
            from user_passkeys p
            inner join users u on u.user_handle = p.user_handle
            where u.username = ?
            """
            db = connect_db()
            with closing(db.cursor()) as cur:
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
            db = connect_db()
            with closing(db.cursor()) as cur:
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

        toplevel = self.get_surface()
        window_handle = await get_surface_handle(toplevel)

        print(f"received window handle: {window_handle}")
        window_handle = f"wayland:{window_handle}"
        print(window_handle)

        auth_data = await get_passkey(
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


async def create_passkey(
    interface: ProxyInterface,
    window_handle: str,
    origin: str,
    top_origin: str,
    options: dict,
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

    request_event = create_portal_request_message_handler(interface.bus)

    print("Calling D-Bus")
    rsp = await interface.call_create_credential(
        window_handle,
        origin,
        top_origin,
        req,
        {"handle_token": Variant("s", request_event.token)},
    )
    print(rsp)
    print("waiting for response")
    result = await request_event.wait()

    print("Received response")
    # pprint(rsp)
    # [code, value] = rsp
    # if code == 0:
    #     result = value
    # elif code == 1:
    #     raise Exception("Portal request cancelled")
    # elif code == 2 and "error" in value:
    #     raise Exception(f"Portal returned an error: {value['error'].value}")
    # else:
    #     raise Exception("Portal returned an unknown error")

    if result["type"].value != "public-key":
        raise Exception(
            f"Invalid credential type received: expected 'public-key', received {result['type'].value}"
        )

    response_json = json.loads(
        result["public_key"].value["registration_response_json"].value
    )
    return webauthn.verify_create_response(response_json, options, origin)


async def get_passkey(
    interface, window_handle, origin, top_origin, rp_id, cred_ids, cred_lookup_fn
):
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

    request_event = create_portal_request_message_handler(interface.bus)

    _ = await interface.call_get_credential(
        window_handle,
        origin,
        top_origin,
        req,
        {"handle_token": Variant("s", request_event.token)},
    )
    result = await request_event.wait()
    print("Received response")
    # pprint(rsp)

    response_json = json.loads(
        result["public_key"].value["authentication_response_json"].value
    )
    response_json["rawId"] = util.b64_decode(response_json["rawId"])
    if user_handle := response_json["response"].get("userHandle"):
        response_json["response"]["userHandle"] = util.b64_decode(user_handle)

    return webauthn.verify_get_response(response_json, options, origin, cred_lookup_fn)


async def connect_to_bus():
    global INTERFACE
    bus = await MessageBus().connect()

    with open(
        f"{os.path.dirname(os.path.realpath(__file__))}/xyz.iinuwa.credentialsd.Credentials.xml",
        "r",
    ) as f:
        introspection = f.read()

    service_name = "org.freedesktop.portal.Desktop"
    path = "/org/freedesktop/portal/desktop"
    interface = "org.freedesktop.portal.CredentialsX"
    proxy_object = bus.get_proxy_object(
        service_name,
        path,
        introspection,
    )
    INTERFACE = proxy_object.get_interface(interface)


def connect_db() -> sqlite3.Connection:
    # This is just for testing/temporary use, so put it in cache
    db_path = (
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "xyz.iinuwa.credentialsd.DemoCredentialsUi"
        / "users.db"
    )
    db_path.parent.mkdir(exist_ok=True)

    return sqlite3.connect(db_path)


def setup_db():
    global DB

    DB = connect_db()
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


async def main():
    setup_db()
    app = MyApp(application_id=APP_ID)
    app.run(sys.argv)
    DB.close()


if __name__ == "__main__":
    done = asyncio.Event()
    LOOP = GLibEventLoop(GLib.MainContext())
    LOOP.run_until_complete(connect_to_bus())

    def background_loop():
        LOOP.run_until_complete(done.wait())

    threading.Thread(target=background_loop, daemon=True).start()
    asyncio.run(main(), loop_factory=lambda: GLibEventLoop(GLib.MainContext()))
    done.set()
