from abc import abstractmethod
import json
import logging

from dbus_next.aio import ProxyInterface
from dbus_next import Variant

from __init__ import ClientCapabilities, CredentialProtocol
from xdg_portal_utils import create_portal_request_message_handler


class CredentialPortalProxyProtocol(ProxyInterface):
    @abstractmethod
    async def call_create_credential(
        self, window_handle: str, origin: str, credential_type: str, req
    ) -> str: ...

    @abstractmethod
    async def call_get_credential(
        self, window_handle: str, origin: str, req
    ) -> str: ...

    @abstractmethod
    async def get_conditional_create(self) -> bool: ...

    @abstractmethod
    async def get_conditional_get(self) -> bool: ...

    @abstractmethod
    async def get_hybrid_transport(self) -> bool: ...

    @abstractmethod
    async def get_passkey_platform_authenticator(self) -> bool: ...

    @abstractmethod
    async def get_user_verifying_platform_authenticator(self) -> bool: ...

    @abstractmethod
    async def get_related_origins(self) -> bool: ...

    @abstractmethod
    async def get_signal_all_accepted_credentials(self) -> bool: ...

    @abstractmethod
    async def get_signal_current_user_details(self) -> bool: ...

    @abstractmethod
    async def get_signal_unknown_credential(self) -> bool: ...


class XdgPortalV1(CredentialProtocol):
    def __init__(self, interface: CredentialPortalProxyProtocol, _app_id: str):
        self.interface = interface

    async def create_credential(self, options, origin, top_origin) -> dict:
        logging.debug("Creating passkey")
        req_json = json.dumps(options)
        logging.debug(req_json)
        request_event = create_portal_request_message_handler(self.interface.bus)
        req = {
            "handle_token": Variant("s", request_event.token),
            "public_key": Variant("s", req_json),
        }
        if top_origin != origin:
            req["top_origin"] = Variant("s", top_origin)
        logging.debug("Sending request to D-Bus API")
        _rsp = await self.interface.call_create_credential("", origin, "publicKey", req)
        result = await request_event.wait()
        # TODO: this should be PascalCase: PublicKey
        if result["type"].value != "public-key":
            raise Exception(
                f"Invalid credential type received: expected 'public-key', received {result['type'].value}"
            )
        response_json = json.loads(
            result["public_key"].value["registration_response_json"].value
        )
        return response_json

    async def get_credential(self, options, origin, top_origin) -> dict:
        req_json = json.dumps(options)
        logging.debug(req_json)
        logging.debug("Sending request to D-Bus API")
        request_event = create_portal_request_message_handler(self.interface.bus)
        req = {
            "handle_token": Variant("s", request_event.token),
            "public_key": Variant("s", req_json),
        }
        if top_origin != origin:
            req["top_origin"] = Variant("s", top_origin)
        _rsp = await self.interface.call_get_credential("", origin, req)
        result = await request_event.wait()
        if result["type"].value != "public-key":
            raise Exception(
                f"Invalid credential type received: expected 'public-key', received {result['type'].value}"
            )

        response_json = json.loads(
            result["public_key"].value["authentication_response_json"].value
        )
        return response_json

    async def get_client_capabilities(self) -> ClientCapabilities:
        conditional_create = await self.interface.get_conditional_create()
        conditional_get = await self.interface.get_conditional_get()
        hybrid_transport = await self.interface.get_hybrid_transport()
        passkey_platform_authenticator = (
            await self.interface.get_passkey_platform_authenticator()
        )
        user_verifying_platform_authenticator = (
            await self.interface.get_user_verifying_platform_authenticator()
        )
        related_origins = await self.interface.get_related_origins()
        signal_all_accepted_credentials = (
            await self.interface.get_signal_all_accepted_credentials()
        )
        signal_current_user_details = (
            await self.interface.get_signal_current_user_details()
        )
        signal_unknown_credential = await self.interface.get_signal_unknown_credential()
        response: ClientCapabilities = {
            "conditional_create": conditional_create,
            "conditional_get": conditional_get,
            "hybrid_transport": hybrid_transport,
            "passkey_platform_authenticator": passkey_platform_authenticator,
            "user_verifying_platform_authenticator": user_verifying_platform_authenticator,
            "related_origins": related_origins,
            "signal_all_accepted_credentials": signal_all_accepted_credentials,
            "signal_current_user_details": signal_current_user_details,
            "signal_unknown_credential": signal_unknown_credential,
        }
        return response
