#!/usr/bin/env python3

from dbus_next.errors import DBusError
from dbus_next.constants import MessageType
import asyncio
import json
import logging
import os
from pathlib import Path
import signal
import struct
import sys
from typing import Optional

from dbus_next import validators
from dbus_next.aio import MessageBus
from dbus_next.proxy_object import BaseProxyInterface
from dbus_next.message import Message

from __init__ import CredentialProtocol
from xdg_portal_v1 import XdgPortalV1
from xdg_portal_v2 import XdgPortalV2
from credentialsd_manager import CredentialsdV1


def dbus_error_from_message(msg: Message):
    assert msg.message_type == MessageType.ERROR
    return DBusError(msg.error_name, msg.body[0] if msg.body else None, reply=msg)


DBusError._from_message = dbus_error_from_message  # ty: ignore

validators.is_member_name_valid = lambda member: True  # ty: ignore[invalid-assignment]

logging.basicConfig(
    filename="/tmp/credential_manager_shim.log", encoding="utf-8", level=logging.DEBUG
)

APP_ID = "@APP_ID@"
INTERFACE: Optional[BaseProxyInterface] = None
INTERFACE_VERSION: Optional[str] = None


def getMessage():
    logging.debug("blocking on read")
    rawLength = sys.stdin.buffer.read(4)

    if len(rawLength) == 0:
        sys.exit(0)
    try:
        logging.debug(f"unpacking struct: {rawLength}")
        messageLength = struct.unpack("@I", rawLength)[0]
        logging.debug(f"reading {messageLength} bytes")
    except Exception as e:
        logging.error("Failed to convert rawLength to integer", exc_info=e)
    try:
        raw_msg = sys.stdin.buffer.read(messageLength)
        logging.debug(f"received bytes: {raw_msg}")
        message = raw_msg.decode("utf-8")
        logging.debug("received " + message)
        return json.loads(message)
    except Exception as e:
        logging.error("Failed to read message")
        raise e


# Encode a message for transmission,
# given its content.
def encodeMessage(messageContent):
    encodedContent = json.dumps(messageContent).encode("utf-8")
    encodedLength = struct.pack("@I", len(encodedContent))
    return {"length": encodedLength, "content": encodedContent}


# Send an encoded message to stdout
def sendMessage(encodedMessage):
    sys.stdout.buffer.write(encodedMessage["length"])
    sys.stdout.buffer.write(encodedMessage["content"])
    sys.stdout.buffer.flush()
    logging.debug(f"sent message: {encodedMessage}")


def discover_app_id():
    desktop_file_name = os.environ.get("GIO_LAUNCHED_DESKTOP_FILE")
    if not desktop_file_name:
        logging.debug("Browser was not launched from a desktop entry.")
        return None

    return Path(desktop_file_name).stem


async def get_service() -> CredentialProtocol:
    bus = await MessageBus(negotiate_unix_fd=True).connect()
    logging.debug("Connected to bus")

    logging.info(os.getcwd())

    app_id = discover_app_id() or APP_ID
    logging.info(f"Registering with the portal as {app_id}")

    msg = Message(
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.host.portal.Registry",
        "Register",
        signature="sa{sv}",
        body=[
            app_id,
            {},
        ],
    )
    await bus.call(msg)

    service_locations = [
        (
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.experimental.Credential",
            XdgPortalV1,
        ),
        (
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop/experimental",
            "org.freedesktop.portal.Credential.X1",
            XdgPortalV2,
        ),
        (
            "xyz.iinuwa.credentialsd.Credentials",
            "/xyz/iinuwa/credentialsd/Manager",
            "xyz.iinuwa.credentialsd.Manager",
            CredentialsdV1,
        ),
    ]
    for service_name, object_path, interface_name, clazz in service_locations:
        logging.debug(f"trying {interface_name} on {service_name} at {object_path}")
        introspection = await bus.introspect(service_name, object_path)
        logging.debug([str(i) for i in introspection.interfaces])
        if any(i.name == interface_name for i in introspection.interfaces):
            proxy_object = bus.get_proxy_object(
                service_name, object_path, introspection
            )
            interface = proxy_object.get_interface(interface_name)
            service = clazz(interface, app_id)  # ty: ignore[invalid-argument-type]
            logging.debug(
                f"Connected to interface {interface_name} at {interface.path}"
            )
            return service
    raise Exception("No service found to satisfy request")


async def run(service: CredentialProtocol, cmd, options, origin, top_origin):
    logging.debug("Executing command")

    if cmd == "create":
        if "publicKey" in options:
            return await service.create_credential(
                options["publicKey"], origin, top_origin
            )
        else:
            raise Exception(
                f"Could not create unknown credential type: {options.keys()[0]}"
            )
    elif cmd == "get":
        if "publicKey" in options:
            return await service.get_credential(
                options["publicKey"], origin, top_origin
            )
        else:
            raise Exception(
                f"Could not get unknown credential type: {options.keys()[0]}"
            )
    elif cmd == "getClientCapabilities":
        return await service.get_client_capabilities()
    else:
        raise Exception(f"unknown cmd: {cmd}")


quit = asyncio.Event()


async def main():
    logging.info("starting credential_manager_shim")
    cancel_task = asyncio.create_task(quit.wait())

    receivedMessage = getMessage()
    request_id = receivedMessage["requestId"]
    try:
        service = await get_service()
        cmd = receivedMessage["cmd"]
        options = receivedMessage.get("options", None)
        origin = receivedMessage["origin"]
        top_origin = receivedMessage["topOrigin"]
        credentialsd_task = asyncio.create_task(
            run(service, cmd, options, origin, top_origin)
        )
        timeout = options.get("timeout", 5 * 60 * 1000) // 1000
        done, pending = await asyncio.wait(
            {credentialsd_task, cancel_task},
            timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if credentialsd_task in done:
            logging.info("got a response from credentialsd")
            auth_data = credentialsd_task.result()
            sendMessage(encodeMessage({"requestId": request_id, "data": auth_data}))
        elif cancel_task in done:
            logging.info("cancelled")
            raise asyncio.CancelledError("Cancelled")
        else:
            logging.info("timed out")
            raise TimeoutError("Timed out")

    except Exception as e:
        logging.error("Failed to send message", exc_info=e)
        sendMessage(
            encodeMessage(
                {
                    "requestId": request_id,
                    "error": {"name": type(e).__name__, "message": str(e)},
                }
            )
        )
        logging.debug("Sent error message")
    logging.info("quitting credential_manager_shim")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda _, __: quit.set())
    asyncio.run(main())
