from typing import Protocol, TypedDict


class ClientCapabilities(TypedDict):
    conditional_create: bool
    conditional_get: bool
    hybrid_transport: bool
    passkey_platform_authenticator: bool
    user_verifying_platform_authenticator: bool
    related_origins: bool
    signal_all_accepted_credentials: bool
    signal_current_user_details: bool
    signal_unknown_credential: bool


class CredentialProtocol(Protocol):
    async def create_credential(self, options, origin, top_origin) -> dict:
        """Creates a public key credential and returns the parsed JSON output"""
        ...

    async def get_credential(self, options, origin, top_origin) -> dict:
        """Asserts a public key credential and returns the parsed JSON output"""
        ...

    async def get_client_capabilities(self) -> ClientCapabilities:
        """Gets the WebAuthn client capabilities provided by the service."""
        ...
