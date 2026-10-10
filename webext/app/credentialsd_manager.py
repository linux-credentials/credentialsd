from asyncio import Future
import mmap
import secrets
import asyncio
from typing import Literal, Protocol, Optional
from abc import abstractmethod
import fcntl
import json
import logging
import os

from dbus_next import Variant
from dbus_next.aio.proxy_object import ProxyInterface

from __init__ import ClientCapabilities, CredentialProtocol

CREDENTIALSD_SERVICE_NAME = "xyz.iinuwa.credentialsd.Credentials"
CREDENTIALSD_UI_SERVICE_NAME = "xyz.iinuwa.credentialsd.UiControl"
CREDENTIALSD_MANAGER_INTERFACE = "xyz.iinuwa.credentialsd.Manager"
CREDENTIALSD_SESSION_INTERFACE = "xyz.iinuwa.credentialsd.Session"


class CredentialsdManager(ProxyInterface):
    @abstractmethod
    async def call_create_public_key_credential(
        self, credential_fd: int, request_json: str, origin: str, top_origin: str
    ) -> str: ...

    @abstractmethod
    async def call_get_credential(
        self, credential_fd: int, origin: str, top_origin: str, options: dict
    ) -> str: ...


class CredentialsdSession(ProxyInterface):
    @abstractmethod
    async def call_create_public_key_credential(
        self, credential_fd: int, request_json: str, origin: str, top_origin: str
    ) -> str: ...

    @abstractmethod
    async def call_start(self) -> str: ...
    @abstractmethod
    async def call_enter_client_pin(self, pin_fd: int, options: dict[str, Variant]): ...

    @abstractmethod
    async def call_select_credential(self, id: int, options: dict[str, Variant]): ...

    class NeedsPinCallback(Protocol):
        def __call__(self, attempts_left: int, options: dict[str, Variant]): ...

    @abstractmethod
    def on_needs_pin(self, callback: NeedsPinCallback): ...

    class NeedsUserVerificationCallback(Protocol):
        def __call__(self, attempts_left: int, options: dict[str, Variant]): ...

    @abstractmethod
    def on_needs_user_verification(self, callback: NeedsUserVerificationCallback):
        """Emitted when the authenticator needs a user verification gesture."""
        ...

    class NeedsUserPresenceCallback(Protocol):
        def __call__(self, options: dict[str, Variant]): ...

    @abstractmethod
    def on_needs_user_presence(self, callback: NeedsUserPresenceCallback):
        """Emitted when the authenticator needs a user presence gesture."""
        ...

    class SelectingCredentialCallback(Protocol):
        def __call__(
            self, credentials: list[dict[str, Variant]], options: dict[str, Variant]
        ): ...

    @abstractmethod
    def on_selecting_credential(self, callback: SelectingCredentialCallback):
        """Emitted when the authenticator detects multiple credentials matching
        credentials for a request."""
        ...

    class HybridStartedCallback(Protocol):
        def __call__(self, options: dict[str, Variant]): ...

    @abstractmethod
    def on_hybrid_started(self, callback: HybridStartedCallback):
        """Emitted when the platform begins scanning for CTAP2 hybrid advertisements."""
        ...

    @abstractmethod
    async def call_get_hybrid_invocation_data(self) -> int:
        """Used to retrieve hybrid invocation data."""
        ...

    class HybridConnectingCallback(Protocol):
        def __call__(self, options: dict[str, Variant]): ...

    @abstractmethod
    def on_hybrid_connecting(self, callback: HybridConnectingCallback):
        """Emitted when the platform has received a CTAP2 hybrid advertisement and is
        establishing a channel."""
        ...

    class HybridConnectedCallback(Protocol):
        def __call__(self, options: dict[str, Variant]): ...

    @abstractmethod
    def on_hybrid_connected(self, callback: HybridConnectedCallback): ...

    class NfcConnectedCallback(Protocol):
        def __call__(self, options: dict[str, Variant]): ...

    @abstractmethod
    def on_nfc_connected(self, callback: NfcConnectedCallback): ...

    class UsbConnectedCallback(Protocol):
        def __call__(self, options: dict[str, Variant]): ...

    @abstractmethod
    def on_usb_connected(self, callback: UsbConnectedCallback): ...

    class CeremonyCompletedCallback(Protocol):
        def __call__(self, options: dict[str, Variant]): ...

    @abstractmethod
    def on_ceremony_completed(self, callback: CeremonyCompletedCallback): ...

    class ErrorOccurredCallback(Protocol):
        def __call__(self, error: int): ...

    @abstractmethod
    def on_error_occurred(self, callback: ErrorOccurredCallback): ...

    @abstractmethod
    async def get_devices(self) -> list[dict[str, Variant]]: ...

    @abstractmethod
    async def get_rp_id(self) -> str: ...


class CredentialPortalBackend(ProxyInterface):
    @abstractmethod
    async def call_create_session(
        self,
        session_handle: str,
        parent_window: str,
        origin: str,
        type: int,
        sources: list[dict[str, Variant]],
        app_id: str,
        app_pid: int,
        options: dict[str, Variant],
    ): ...
    @abstractmethod
    async def call_notify_needs_pin(
        self, session_handle: str, attempts_left: int, options: dict[str, Variant]
    ): ...

    async def call_notify_needs_user_verification(
        self, session_handle: str, attempts_left: int, options: dict[str, Variant]
    ): ...

    async def call_notify_needs_user_presence(
        self, session_handle: str, options: dict[str, Variant]
    ): ...

    async def call_notify_hybrid_started(
        self, session_handle: str, invocation_data_fd: int, options: dict[str, Variant]
    ): ...

    async def call_notify_hybrid_connecting(
        self, session_handle: str, options: dict[str, Variant]
    ): ...

    @abstractmethod
    async def call_notify_hybrid_connected(
        self, session_handle: str, options: dict[str, Variant]
    ): ...

    @abstractmethod
    async def call_notify_nfc_connected(
        self, session_handle: str, options: dict[str, Variant]
    ): ...

    @abstractmethod
    async def call_notify_usb_connected(
        self, session_handle: str, options: dict[str, Variant]
    ): ...

    @abstractmethod
    async def call_notify_selecting_credential(
        self,
        session_handle: str,
        credentials: list[dict[str, Variant]],
        options: dict[str, Variant],
    ): ...

    @abstractmethod
    async def call_notify_ceremony_completed(self, session_handle: str): ...

    @abstractmethod
    async def call_notify_error_occurred(self, session_handle: str, error: int): ...

    class DiscoveryRequestCallback(Protocol):
        def __call__(self, session_handle: str, options: dict[str, Variant]): ...

    @abstractmethod
    def on_discovery_requested(self, callback: DiscoveryRequestCallback): ...

    class ClientPinEnteredCallback(Protocol):
        def __call__(self, session_handle: str, options: dict[str, Variant]): ...

    @abstractmethod
    def on_client_pin_entered(self, callback: ClientPinEnteredCallback): ...

    @abstractmethod
    async def call_get_client_pin(self, session_handle: str) -> int: ...

    class CredentialSelectedCallback(Protocol):
        def __call__(
            self, session_handle: str, id: str, options: dict[str, Variant]
        ): ...

    @abstractmethod
    def on_credential_selected(self, callback: CredentialSelectedCallback): ...


class CredentialsdV1(CredentialProtocol):
    def __init__(self, interface: ProxyInterface, app_id: str):
        self.interface: CredentialsdManager = interface  # ty: ignore[invalid-assignment]
        self.app_id = app_id

    async def create_credential(self, options, origin, top_origin) -> dict:
        logging.debug("Creating passkey")
        req_json = json.dumps(options)
        logging.debug(req_json)

        logging.debug("Sending request to D-Bus API")
        return await self.handle_credential_request(
            "PUBLIC_KEY_CREATE", origin, top_origin, req_json
        )

    async def get_credential(self, options, origin, top_origin) -> dict:
        logging.debug("Getting passkey")
        req_json = json.dumps(options)
        logging.debug(req_json)
        req = {
            "public_key": Variant("s", req_json),
        }
        logging.debug("Sending request to D-Bus API")
        return await self.handle_credential_request(
            "PUBLIC_KEY_GET", origin, top_origin, req
        )

    async def handle_credential_request(
        self,
        operation: Literal["PUBLIC_KEY_CREATE", "PUBLIC_KEY_GET"],
        origin,
        top_origin,
        data,
    ) -> dict:
        fd = os.memfd_create(
            f"credentialsd_session_response_{secrets.token_hex(16)}",
            os.MFD_ALLOW_SEALING,
        )
        credsd_session: Optional[CredentialsdSession] = None
        backend_session: Optional[CredentialPortalBackend] = None
        try:
            os.ftruncate(fd, 16 * 1024)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW)
            if operation == "PUBLIC_KEY_CREATE":
                operation_type = 0
                request_json = data
                credsd_session_handle = (
                    await self.interface.call_create_public_key_credential(
                        fd,
                        request_json,
                        origin,
                        top_origin,
                    )
                )
            elif operation == "PUBLIC_KEY_GET":
                # TODO: make this a string PascalCase
                operation_type = 1
                credsd_session_handle = await self.interface.call_get_credential(
                    fd, origin, top_origin, data
                )
            else:
                raise Exception("Unknown operation type")

            introspection = await self.interface.bus.introspect(
                CREDENTIALSD_SERVICE_NAME, credsd_session_handle
            )
            proxy_object = self.interface.bus.get_proxy_object(
                CREDENTIALSD_SERVICE_NAME, credsd_session_handle, introspection
            )
            credsd_session: CredentialsdSession = proxy_object.get_interface(
                CREDENTIALSD_SESSION_INTERFACE
            )
            devices = await credsd_session.get_devices()
            rp_id = await credsd_session.get_rp_id()

            backend_introspection = await self.interface.bus.introspect(
                CREDENTIALSD_UI_SERVICE_NAME, "/org/freedesktop/portal/desktop"
            )
            backend_proxy_object = self.interface.bus.get_proxy_object(
                CREDENTIALSD_UI_SERVICE_NAME,
                "/org/freedesktop/portal/desktop",
                backend_introspection,
            )
            backend_session: CredentialPortalBackend = (
                backend_proxy_object.get_interface(
                    "org.freedesktop.impl.portal.Credential"
                )
            )
            backend_session_handle = credsd_session_handle

            # Register handlers for credentialsd and backend implementation
            #
            # In a real implementation, we'd clean up the registered
            # handlers, but this just runs for a single request and quits,
            # so we're not going to bother.
            loop = asyncio.get_running_loop()
            response_future = loop.create_future()
            self.register_handlers(
                credsd_session,
                backend_session,
                backend_session_handle,
                response_future,
            )

            window_handle = ""
            # TODO: Remove this
            pid = 0
            backend_options = {
                "rp_id": Variant("s", rp_id),
                # TODO: Make this optional instead of passing empty string
                "activation_token": Variant("s", ""),
            }
            if top_origin:
                backend_options["top_origin"] = Variant("s", top_origin)

            await backend_session.call_create_session(
                backend_session_handle,
                window_handle,
                origin,
                operation_type,
                devices,
                self.app_id,
                pid,
                backend_options,
            )
            response = await response_future
            # TODO: this should be PascalCase
            if response["type"].value != "publicKey":
                raise Exception(
                    f"Invalid credential type received: expected 'publicKey', received {response['type'].value}"
                )
            with mmap.mmap(fd, 0, access=mmap.ACCESS_READ) as mm:
                response_bytes = mm.read(mm.size())
                logging.debug(
                    f"Received response (raw): len, {mm.size()} {response_bytes}"
                )
                response_json = json.loads(response_bytes[: mm.size()])
                return response_json
        finally:
            os.close(fd)
            if credsd_session is not None:
                pass
                # TODO: add credsd session close
                # credsd_session.close()
            if backend_session is not None:
                pass

    def register_handlers(
        self,
        credsd_session: CredentialsdSession,
        backend_session: CredentialPortalBackend,
        backend_session_handle: str,
        response_future: Future,
    ):
        def discovery_requested_callback(session_handle, options):
            if session_handle == backend_session_handle:
                asyncio.create_task(credsd_session.call_start())

        backend_session.on_discovery_requested(discovery_requested_callback)

        def client_pin_entered_callback(session_handle, options):
            if session_handle == backend_session_handle:

                async def handle():
                    pin_fd = await backend_session.call_get_client_pin(
                        backend_session_handle
                    )
                    await credsd_session.call_enter_client_pin(pin_fd, {})

                asyncio.create_task(handle())

        backend_session.on_client_pin_entered(client_pin_entered_callback)

        def credential_selected_callback(session_handle, id, options):
            if session_handle == backend_session_handle:
                asyncio.create_task(credsd_session.call_select_credential(id, options))

        backend_session.on_credential_selected(credential_selected_callback)

        def needs_pin_callback(attempts_left, options):
            asyncio.create_task(
                backend_session.call_notify_needs_pin(
                    backend_session_handle, attempts_left, options
                )
            )

        credsd_session.on_needs_pin(needs_pin_callback)

        def needs_user_verification_callback(attempts_left, options):
            asyncio.create_task(
                backend_session.call_notify_needs_user_verification(
                    backend_session_handle, attempts_left, options
                )
            )

        credsd_session.on_needs_user_verification(needs_user_verification_callback)

        def needs_user_presence_callback(options):
            asyncio.create_task(
                backend_session.call_notify_needs_user_presence(
                    backend_session_handle, options
                )
            )

        credsd_session.on_needs_user_presence(needs_user_presence_callback)

        def selecting_credential_callback(credentials, options):
            asyncio.create_task(
                backend_session.call_notify_selecting_credential(
                    backend_session_handle, credentials, options
                )
            )

        credsd_session.on_selecting_credential(selecting_credential_callback)

        def hybrid_started_callback(options):
            async def handle():
                invocation_data_fd = (
                    await credsd_session.call_get_hybrid_invocation_data()
                )
                await backend_session.call_notify_hybrid_started(
                    backend_session_handle, invocation_data_fd, options
                )

            asyncio.create_task(handle())

        credsd_session.on_hybrid_started(hybrid_started_callback)

        def hybrid_connecting_callback(options):
            asyncio.create_task(
                backend_session.call_notify_hybrid_connecting(
                    backend_session_handle, options
                )
            )

        credsd_session.on_hybrid_connecting(hybrid_connecting_callback)

        def hybrid_connected_callback(options):
            asyncio.create_task(
                backend_session.call_notify_hybrid_connected(
                    backend_session_handle, options
                )
            )

        credsd_session.on_hybrid_connected(hybrid_connected_callback)

        def nfc_connected_callback(options):
            asyncio.create_task(
                backend_session.call_notify_nfc_connected(
                    backend_session_handle, options
                )
            )

        credsd_session.on_nfc_connected(nfc_connected_callback)

        def usb_connected_callback(options):
            asyncio.create_task(
                backend_session.call_notify_usb_connected(
                    backend_session_handle, options
                )
            )

        credsd_session.on_usb_connected(usb_connected_callback)

        def ceremony_completed_callback(options):
            async def handle():
                await backend_session.call_notify_ceremony_completed(
                    backend_session_handle
                )
                response_future.set_result(options)

            asyncio.create_task(handle())

        credsd_session.on_ceremony_completed(ceremony_completed_callback)

        def error_occurred_callback(error):
            async def handle():
                await backend_session.call_notify_error_occurred(
                    backend_session_handle, error
                )
                response_future.set_exception(error)

            asyncio.create_task(handle())

        credsd_session.on_error_occurred(error_occurred_callback)

    async def get_client_capabilities(self) -> ClientCapabilities:
        pass
