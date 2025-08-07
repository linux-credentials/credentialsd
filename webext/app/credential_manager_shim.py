#!/usr/bin/env python3

import asyncio
import base64
import codecs
from dataclasses import dataclass
from enum import Enum
import json
import logging
import struct
import sys
from typing import Optional

from dbus_next.aio import MessageBus
from dbus_next import Variant

logging.basicConfig(
    filename="/tmp/credential_manager_shim.log", encoding="utf-8", level=logging.DEBUG
)

DBUS_DOC_FILE = "@DBUS_DOC_FILE@"


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


def b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64_decode(s) -> bytes:
    padding = "=" * (len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


class MajorType(Enum):
    PositiveInteger = (0,)
    NegativeInteger = (1,)
    ByteString = (2,)
    TextString = (3,)
    Array = (4,)
    Map = (5,)
    Tag = (6,)
    SimpleOrFloat = (7,)


class CborParser:
    def __init__(self, cbor):
        self.data = memoryview(cbor).toreadonly()
        self.pos = 0

    def parse(self):
        value = self._read_value(self.data)
        return value

    def _read_value(self, buf):
        if len(buf) == 0:
            return None
        additional_info = buf[0] & 0b000_11111
        if additional_info < 24:
            argument = additional_info
            argument_len = 0
        elif additional_info == 24:
            argument_len = 1
            argument = struct.unpack(">B", buf[1 : 1 + argument_len])[0]
        elif additional_info == 25:
            argument_len = 2
            argument = struct.unpack(">H", buf[1 : 1 + argument_len])[0]
        elif additional_info == 26:
            argument_len = 4
            argument = struct.unpack(">I", buf[1 : 1 + argument_len])[0]
        elif additional_info == 27:
            argument_len = 8
            argument = struct.unpack(">Q", buf[1 : 1 + argument_len])[0]
        elif additional_info == 31:
            # Indefinite length for types 2-5
            argument = None
            argument_len = 0
        match buf[0] >> 5:
            case 0:
                major_type = MajorType.PositiveInteger
            case 1:
                major_type = MajorType.NegativeInteger
            case 2:
                major_type = MajorType.ByteString
            case 3:
                major_type = MajorType.TextString
            case 4:
                major_type = MajorType.Array
            case 5:
                major_type = MajorType.Map
            case 6:
                major_type = MajorType.Tag
            case 7:
                major_type = MajorType.SimpleOrFloat
        # advance beyond type info
        self.pos += 1
        self.pos += argument_len

        bytes_consumed = 0
        match major_type:
            case MajorType.PositiveInteger:
                value = argument

            case MajorType.NegativeInteger:
                value = -1 - argument

            case MajorType.ByteString:
                string_len = argument
                if string_len is None:
                    string_len = 0
                    # indefinite length
                    value = ""
                    while self.data[self.pos] != 0xFF:
                        val = self._read_value(self.data[self.pos :])[0]
                        value += val
                    string_len = 1
                else:
                    value = self.data[self.pos : self.pos + string_len]
                bytes_consumed = string_len

            case MajorType.TextString:
                string_len = argument
                if string_len is None:
                    # indefinite length
                    value = ""
                    while self.data[self.pos] != 0xFF:
                        val = self._read_value(self.data[self.pos :])
                        value += val
                    bytes_consumed = 1
                else:
                    value = codecs.utf_8_decode(
                        self.data[self.pos : self.pos + string_len]
                    )[0]
                    bytes_consumed = string_len

            case MajorType.Map:
                value = {}
                if argument is None:
                    argument = 0
                    value = {}
                    while self.data[self.pos] != 0xFF:
                        inner_key = self._read_value(self.data[self.pos :])
                        inner_value = self._read_value(self.data[self.pos :])
                        value[inner_key] = inner_value
                    bytes_consumed = 1
                else:
                    for _ in range(argument):
                        inner_key = self._read_value(self.data[self.pos :])
                        inner_value = self._read_value(self.data[self.pos :])
                        value[inner_key] = inner_value

            case MajorType.Array:
                value = []
                if argument is None:
                    argument = 0
                    value = []
                    while self.data[self.pos] != 0xFF:
                        inner_value = self._read_value(self.data[self.pos :])
                        value.append(inner_value)
                    bytes_consumed = 1
                else:
                    for _ in range(argument):
                        inner_value = self._read_value(self.data[self.pos :])
                        value.append(inner_value)

            case MajorType.Tag:
                raise Exception("Tag support not implemented")

            case MajorType.SimpleOrFloat:
                if argument == 20:
                    value = False
                elif argument == 21:
                    value = True
                elif argument == 22:
                    value = None
                elif argument == 23:
                    value = None
                else:
                    raise Exception("Float parsing not implemented")

        self.pos += bytes_consumed
        return value


def cbor_loads(data):
    parser = CborParser(data)
    return parser.parse()


def _parse_authenticator_data(auth_data):
    client_rp_id_hash = auth_data[:32]

    # Verify that the User Present bit of the flags in authData is set.
    flags = set()
    flag_byte = auth_data[32]
    bits = ["UP", "RFU1", "UV", "RFU2", "RFU2", "RFU2", "AT", "ED"]
    for i in range(8):
        if flag_byte & 0x01 == 1:
            flags.add(bits[i])
        flag_byte = flag_byte >> 1

    sign_count = struct.unpack(">I", auth_data[33:37])[0]

    if "AT" in flags:
        aaguid = auth_data[37 : 37 + 16]
        cred_id_length = struct.unpack(">H", auth_data[53:55])[0]
        cred_id = auth_data[55 : 55 + cred_id_length]
        parser = CborParser(auth_data[55 + cred_id_length :])
        _ = parser.parse()
        cose_key_bytes = parser.data[: parser.pos]
        cose_key_bytes_len = len(cose_key_bytes)
        assert len(cose_key_bytes) == parser.pos
        attested_cred_data_len = 55 + cred_id_length + cose_key_bytes_len

    else:
        attested_cred_data_len = 0
        aaguid = None
        cred_id = None
        cose_key_bytes = None

    if "ED" in flags:
        extensions = cbor_loads(auth_data[37 + attested_cred_data_len :])
    else:
        extensions = None
    return AuthenticatorData(
        rp_id_hash=client_rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        aaguid=aaguid,
        cred_id=cred_id,
        pub_key_bytes=cose_key_bytes,
        extensions=extensions,
    )


@dataclass
class AuthenticatorData:
    rp_id_hash: bytes
    flags: set
    sign_count: int
    aaguid: Optional[bytes]
    cred_id: Optional[bytes]
    pub_key_bytes: Optional[bytes]
    extensions: Optional[dict]

    def get_pub_key(self):
        if self.pub_key_bytes:
            return cbor_loads(self.pub_key_bytes)

    def has_flag(self, flag):
        return flag in self.flags


async def create_passkey(interface, options, origin, top_origin):
    logging.debug("Creating passkey")
    is_same_origin = origin == top_origin
    req_json = json.dumps(options)
    logging.debug(req_json)
    req = {
        "type": Variant("s", "publicKey"),
        "origin": Variant("s", origin),
        "is_same_origin": Variant("b", is_same_origin),
        "publicKey": Variant("a{sv}", {"request_json": Variant("s", req_json)}),
    }
    logging.debug("Sending request to D-Bus API")
    rsp = await interface.call_create_credential(req)
    if rsp["type"].value != "public-key":
        raise Exception(
            f"Invalid credential type received: expected 'public-key', received {rsp['type'.value]}"
        )
    response_json = json.loads(
        rsp["public_key"].value["registration_response_json"].value
    )
    attestation = cbor_loads(b64_decode(response_json["response"]["attestationObject"]))
    auth_data_view = attestation["authData"]
    response_json["response"]["authenticatorData"] = b64_encode(auth_data_view)
    auth_data = _parse_authenticator_data(auth_data_view)
    if auth_data.pub_key_bytes:
        # TODO: format this as SubjectPublicKeyInfo -_-
        response_json["response"]["publicKey"] = b64_encode(auth_data.pub_key_bytes)
        COSE_ALG = 3
        response_json["response"]["publicKeyAlgorithm"] = auth_data.get_pub_key()[
            COSE_ALG
        ]
    return response_json


async def get_passkey(interface, options, origin, top_origin):
    logging.debug("Authenticating with passkey")
    is_same_origin = origin == top_origin
    req_json = json.dumps(options)
    logging.debug(req_json)
    req = {
        "type": Variant("s", "publicKey"),
        "origin": Variant("s", origin),
        "is_same_origin": Variant("b", is_same_origin),
        "publicKey": Variant("a{sv}", {"request_json": Variant("s", req_json)}),
    }

    logging.debug("Sending request to D-Bus API")
    rsp = await interface.call_get_credential(req)
    if rsp["type"].value != "public-key":
        raise Exception(
            f"Invalid credential type received: expected 'public-key', received {rsp['type'.value]}"
        )

    response_json = json.loads(
        rsp["public_key"].value["authentication_response_json"].value
    )
    return response_json


async def run(cmd, options, origin, top_origin):
    logging.debug("Executing command")
    bus = await MessageBus().connect()
    logging.debug("Connected to bus")
    import os

    logging.info(os.getcwd())

    with open(DBUS_DOC_FILE, "r") as f:
        introspection = f.read()

    proxy_object = bus.get_proxy_object(
        "xyz.iinuwa.credentialsd.Credentials",
        "/xyz/iinuwa/credentialsd/Credentials",
        introspection,
    )

    interface = proxy_object.get_interface("xyz.iinuwa.credentialsd.Credentials1")
    logging.debug(f"Connected to interface at {interface.path}")

    if cmd == "create":
        if "publicKey" in options:
            return await create_passkey(
                interface, options["publicKey"], origin, top_origin
            )
        else:
            raise Exception(
                f"Could not create unknown credential type: {options.keys()[0]}"
            )
    elif cmd == "get":
        if "publicKey" in options:
            return await get_passkey(
                interface, options["publicKey"], origin, top_origin
            )
        else:
            raise Exception(
                f"Could not get unknown credential type: {options.keys()[0]}"
            )
    elif cmd == "getClientCapabilities":
        rsp = await interface.call_get_client_capabilities()
        response = {}
        for name, val in rsp.items():
            response[name] = val.value
        return response
    else:
        raise Exception(f"unknown cmd: {cmd}")


logging.info("starting credential_manager_shim")
while True:
    logging.debug("starting event loop message")
    receivedMessage = getMessage()
    request_id = receivedMessage["requestId"]
    try:
        cmd = receivedMessage["cmd"]

        options = None
        if "options" in receivedMessage:
            options = receivedMessage["options"]
        origin = receivedMessage["origin"]
        top_origin = receivedMessage["topOrigin"]
        loop = asyncio.get_event_loop()
        auth_data = loop.run_until_complete(run(cmd, options, origin, top_origin))
        sendMessage(encodeMessage({"requestId": request_id, "data": auth_data}))
    except Exception as e:
        logging.error("Failed to send message", exc_info=e)
        sendMessage(encodeMessage({"requestId": request_id, "error": str(e)}))
        logging.debug("Sent error message")
