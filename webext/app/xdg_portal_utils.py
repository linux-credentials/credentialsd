from asyncio import Future
import asyncio
import logging
import re
import secrets

from dbus_next.aio import MessageBus
from dbus_next.constants import MessageType
from dbus_next.message import Message


class PortalError(Exception):
    def from_string(s: str):
        m = re.match(r"xyz.iinuwa.credentialsd.(\w+): (?:no description|(.*))", s)
        if m:
            (name, message) = m.groups()
            match name:
                case "AbortError":
                    return AbortError
                case "ConstraintError":
                    return ConstraintError
                case "InvalidStateError":
                    return InvalidStateError
                case "NotSupportedError":
                    return NotSupportedError
                case "SecurityError":
                    return SecurityError
                case "NotAllowedError":
                    return NotAllowedError
                case "TypeError":
                    return TypeError
                case _:
                    return PortalError()


class AbortError(PortalError):
    pass


class ConstraintError(PortalError):
    pass


class InvalidStateError(PortalError):
    pass


class NotSupportedError(PortalError):
    pass


class SecurityError(PortalError):
    pass


class NotAllowedError(PortalError):
    pass


class TypeError(PortalError):
    pass


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
            logging.error("Request cancelled")
            future.set_exception(AbortError())
            raise
        elif code == 2 and "error" in value:
            logging.error(value["error"].value)
            future.set_exception(PortalError.from_string(value["error"].value))
        else:
            logging.error("Portal returned an unknown error")
            future.set_exception(PortalError())
        return True

    def when_done(_fut):
        bus.remove_message_handler(message_handler)

    future.add_done_callback(when_done)
    bus.add_message_handler(message_handler)
    logging.debug(f"Listening for {object_path}")
    return PortalRequest(token, future)
