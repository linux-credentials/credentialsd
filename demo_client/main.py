#!/usr/bin/env python3

import asyncio
import json
from pprint import pprint
import secrets
import sys
from typing import Optional
import unittest

from dbus_next.aio import MessageBus
from dbus_next import Variant

import util
import webauthn


async def run(cmd):
    bus = await MessageBus().connect()

    with open("../contrib/xyz.iinuwa.credentials.CredentialManager.xml", "r") as f:
        introspection = f.read()

    proxy_object = bus.get_proxy_object(
        "xyz.iinuwa.credentials.Credentials",
        "/xyz/iinuwa/credentials/Credentials",
        introspection,
    )

    interface = proxy_object.get_interface("xyz.iinuwa.credentials.Credentials1")

    rp_id = "example.com"
    origin = "https://example.com"
    top_origin = "https://example.com"
    user_handle = b"123abdsacddw"
    username = "user@example.com"

    if cmd == "create":
        auth_data = await create_passkey(
            interface, origin, top_origin, rp_id, user_handle, username
        )
        user_data = {
            "id": 1,
            "name": username,
            "user_handle": util.b64_encode(user_handle),
            "cred_id": util.b64_encode(auth_data.cred_id),
            "pub_key": util.b64_encode(auth_data.pub_key_bytes),
            "sign_count": auth_data.sign_count,
            "backup_eligible": auth_data.has_flag("BE"),
            "backup_state": auth_data.has_flag("BS"),
            "uv_initialized": auth_data.has_flag("UV"),
        }
        print("New credential data:")
        print(json.dumps(user_data))
        json.dump(user_data, open("./user.json", "w"))
    elif cmd == "get":
        user_data = json.load(open("./user.json", "r"))
        cred_id = util.b64_decode(user_data["cred_id"])
        auth_data = await get_passkey(
            interface, origin, top_origin, rp_id, cred_id, user_data
        )
        print(auth_data)
    else:
        print(f"unknown cmd: {cmd}")
        exit()
    # rsp = await create_password(interface)
    # print(rsp)
    # rsp = await get_password(interface)
    # print(rsp)
    # await bus.wait_for_disconnect()


async def create_password(interface):
    password_req = {
        "type": Variant("s", "password"),
        "password": Variant(
            "a{sv}",
            {
                "origin": Variant(
                    "s", "xyz.iinuwa.credentials.CredentialManager:local"
                ),
                "id": Variant("s", "test@example.com"),
                "password": Variant("s", "abc123"),
            },
        ),
    }
    rsp = await interface.call_create_credential(password_req)
    return rsp


async def get_password(interface):
    password_req = {
        "origin": Variant("s", "xyz.iinuwa.credentials.CredentialManager:local"),
        "options": Variant(
            "aa{sv}",
            [
                {
                    "type": Variant("s", "password"),
                    "password": Variant("a{sv}", {}),
                }
            ],
        ),
    }
    rsp = await interface.call_get_credential(password_req)
    if rsp["type"].value == "password":
        cred = rsp["password"].value
        id = cred["id"].value
        password = cred["password"].value
        return (id, password)
    return None


async def create_passkey(interface, origin, top_origin, rp_id, user_handle, username):
    is_same_origin = origin == top_origin
    options = {
        "challenge": util.b64_encode(secrets.token_bytes(16)),
        "rp": {
            "name": "Example Org",
            "id": rp_id,
        },
        "user": {
            "id": util.b64_encode(user_handle),
            "name": username,
            "displayName": "User 1",
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
            {"type": "public-key", "alg": -8},
        ],
    }

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

    rsp = await interface.call_create_credential(req)
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


async def get_passkey(
    interface, origin, top_origin, rp_id, cred_id, user: Optional[dict]
):
    is_same_origin = origin == top_origin
    options = {
        "challenge": util.b64_encode(secrets.token_bytes(16)),
        "rpId": rp_id,
        "allowCredentials": [
            {"type": "public-key", "id": util.b64_encode(cred_id)},
        ],
    }

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

    rsp = await interface.call_get_credential(req)
    print("Received response")
    pprint(rsp)
    if rsp["type"].value != "public-key":
        raise Exception(
            f"Invalid credential type received: expected 'public-key', received {rsp['type'.value]}"
        )

    response_json = json.loads(
        rsp["public_key"].value["authentication_response_json"].value
    )
    print(user)
    return webauthn.verify_get_response(response_json, options, origin, user, None)


def main():
    args = sys.argv[1:]
    if not args:
        print("No cmd given. Use 'get' or 'create'")
        exit()
    cmd = args[0]
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run(cmd))


if __name__ == "__main__":
    main()


class VerificationTests(unittest.TestCase):
    def test_create_credential(self):
        response = {
            "id": "owBYoufBWYDUOeNB9dZs9x6GlEPiS8ziKnI_9YVq9RpkwwYsxelm66HOP2usfy-SaV8NE5nJVWDIMvS0W-x9BYtN4AmHZVY33GW2rdfLpeBruuh4jDXgYdnHtZC0IyDIKZiOTzSzyoQih8F-VLcTmqQl7SVHgf-xAh-6TxAJMccROZyIsili1OOnv3WSE7374c2Sw9At0ILaSiTmvC7MtZfnj9hhnAFMFobCJvainepVBn3HAlDo22486wkPqW2D5N00XYXK",
            "rawId": "owBYoufBWYDUOeNB9dZs9x6GlEPiS8ziKnI_9YVq9RpkwwYsxelm66HOP2usfy-SaV8NE5nJVWDIMvS0W-x9BYtN4AmHZVY33GW2rdfLpeBruuh4jDXgYdnHtZC0IyDIKZiOTzSzyoQih8F-VLcTmqQl7SVHgf-xAh-6TxAJMccROZyIsili1OOnv3WSE7374c2Sw9At0ILaSiTmvC7MtZfnj9hhnAFMFobCJvainepVBn3HAlDo22486wkPqW2D5N00XYXK",
            "response": {
                "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgIQ1ReuY8bt2QPrmsZGqphT3hwTJ4Ar2zd3RevRXelHYCIQDiSKGGo5mUqsWP43B6TgxcWby0M1ucBkwOQTS4E6Dt-mN4NWOBWQKqMIICpjCCAkygAwIBAgIUfWe3F4mJfmOVopPF8mmAKxBb0igwCgYIKoZIzj0EAwIwLTERMA8GA1UECgwIU29sb0tleXMxCzAJBgNVBAYTAkNIMQswCQYDVQQDDAJGMTAgFw0yMTA1MjMwMDUyMDBaGA8yMDcxMDUxMTAwNTIwMFowgYMxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhTb2xvS2V5czEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjE9MDsGA1UEAww0U29sbyAyIE5GQytVU0ItQSA4NjUyQUJFOUZCRDg0ODEwQTg0MEQ2RkM0NDJBOEMyQyBCMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABArSyTVT7sDxX0rom6XoIcg8qwMStGV3SjoGRNMqHBSAh2sr4EllUzA1F8yEX5XvUPN_M6DQlqEFGw18UodOjBqjgfAwge0wHQYDVR0OBBYEFBiTdxTWyNCRuzSieBflmHPSJbS1MB8GA1UdIwQYMBaAFEFrtkvvohkN5GJf_SkElrmCKbT4MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL2kuczJwa2kubmV0L2YxLzAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8vYy5zMnBraS5uZXQvcjEvMCEGCysGAQQBguUcAQEEBBIEEIZSq-n72EgQqEDW_EQqjCwwEwYLKwYBBAGC5RwCAQEEBAMCBDAwCgYIKoZIzj0EAwIDSAAwRQIgMsLnUg5Px2FehxIUNiaey8qeT1FGtlJ1s3LEUGOks-8CIQDNEv5aupDvYxn2iqWSNysv4qpdoqSMytRQ7ctfuJDWN2hhdXRoRGF0YVkBJ6N5pvbur7mlXjeMEYA04nUeaC-rny0wqxPSElWGzhlHRQAAADmGUqvp-9hIEKhA1vxEKowsAMajAFii58FZgNQ540H11mz3HoaUQ-JLzOIqcj_1hWr1GmTDBizF6Wbroc4_a6x_L5JpXw0TmclVYMgy9LRb7H0Fi03gCYdlVjfcZbat18ul4Gu66HiMNeBh2ce1kLQjIMgpmI5PNLPKhCKHwX5UtxOapCXtJUeB_7ECH7pPEAkxxxE5nIiyKWLU46e_dZITvfvhzZLD0C3QgtpKJOa8Lsy1l-eP2GGcAUwWhsIm9qKd6lUGfccCUOjbbjzrCQ-pbYPk3TRdhcqkAQEDJyAGIVggzFQIxv1GYCb7CZXbKR8VRTWiRCbceHYcsBNx-lOg9Xk",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiai1keUY4WGN3NWxZMllGSjI2MHl3ZyIsIm9yaWdpbiI6Inh5ei5paW51d2EuY3JlZGVudGlhbHMuQ3JlZGVudGlhbE1hbmFnZXI6bG9jYWwiLCJjcm9zc09yaWdpbiI6dHJ1ZX0",
                "transports": ["usb"],
            },
        }
        challenge = "j-dyF8Xcw5lY2YFJ260ywg"
        create_options = {
            "challenge": challenge,
            "rp": {"id": "example.com"},
            "authenticatorSelection": {"userVerification": "required"},
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -8},
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257},
            ],
        }
        origin = "xyz.iinuwa.credentials.CredentialManager:local"

        auth_data = webauthn.verify_create_response(response, create_options, origin)
        self.assertEqual(response["id"], util.b64_encode(auth_data.cred_id))

    def test_get_credential(self):
        response = {
            "authenticatorAttachment": "cross-platform",
            "id": "owBYojOVzZU-pjscj82gQAHvhUDTMgzQtTcQjyBpzHT-bqLwtLF2OOJDoskE18lOn2-1-SV-b7nCvn5s5Uq2KhBt1Q9kFVBUsb8jBl959BY3KWTg2rgjpN9nB5uIWTEFXfAWo0qIYGGVhXLyEbvu72Lq_W0wlccoKlxWrP349qN9OG2RTaGrgNjxTo1LqnSVc9S6D1zD7mop5KQ_9FZEjA5jABAquwFMAuO4ongyujnpoAfyAlB6UZ_JDmDFCkuN598q_LAu",
            "rawId": "owBYojOVzZU-pjscj82gQAHvhUDTMgzQtTcQjyBpzHT-bqLwtLF2OOJDoskE18lOn2-1-SV-b7nCvn5s5Uq2KhBt1Q9kFVBUsb8jBl959BY3KWTg2rgjpN9nB5uIWTEFXfAWo0qIYGGVhXLyEbvu72Lq_W0wlccoKlxWrP349qN9OG2RTaGrgNjxTo1LqnSVc9S6D1zD7mop5KQ_9FZEjA5jABAquwFMAuO4ongyujnpoAfyAlB6UZ_JDmDFCkuN598q_LAu",
            "response": {
                "authenticatorData": "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcFAAAAXA",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWjE2T2hrVlB5d245Mjc2SjZ3dEdmZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6dHJ1ZX0",
                "signature": "9frQigpe0p8NGwWc9Ikve9RlOZbcmz6S-JVDaPde-dxS-sPRFLGDA3ekh0j294MqaejRudzTw5uggh1IU2lJCQ",
                "userHandle": None,
            },
        }

        user = {
            "id": 1,
            "name": "user@example.com",
            "user_handle": "MTIzYWJkc2FjZGR3",
            "cred_id": "owBYojOVzZU-pjscj82gQAHvhUDTMgzQtTcQjyBpzHT-bqLwtLF2OOJDoskE18lOn2-1-SV-b7nCvn5s5Uq2KhBt1Q9kFVBUsb8jBl959BY3KWTg2rgjpN9nB5uIWTEFXfAWo0qIYGGVhXLyEbvu72Lq_W0wlccoKlxWrP349qN9OG2RTaGrgNjxTo1LqnSVc9S6D1zD7mop5KQ_9FZEjA5jABAquwFMAuO4ongyujnpoAfyAlB6UZ_JDmDFCkuN598q_LAu",
            "pub_key": "pAEBAycgBiFYIE1iZTi4KhfSBhYRWMiP0_wD2cdkJ5sHoQG1zBgxfMaJ",
            "sign_count": 85,
            "backup_eligible": False,
            "backup_state": False,
            "uv_initialized": True,
        }
        options = {
            "challenge": "Z16OhkVPywn9276J6wtGfg",
            "rpId": "example.com",
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": (
                        "owBYojOVzZU-pjscj82gQAHvhUDTMgzQtTcQjyBpzHT-bqLwtLF2OOJDoskE18lO"
                        "n2-1-SV-b7nCvn5s5Uq2KhBt1Q9kFVBUsb8jBl959BY3KWTg2rgjpN9nB5uIWTEF"
                        "XfAWo0qIYGGVhXLyEbvu72Lq_W0wlccoKlxWrP349qN9OG2RTaGrgNjxTo1LqnSV"
                        "c9S6D1zD7mop5KQ_9FZEjA5jABAquwFMAuO4ongyujnpoAfyAlB6UZ_JDmDFCkuN"
                        "598q_LAu"
                    ),
                },
            ],
        }
        expected_origin = "https://example.com"

        auth_data = webauthn.verify_get_response(
            response, options, "https://example.com", user, None
        )
        self.assertTrue(auth_data.has_flag("UV"))
        self.assertFalse(auth_data.has_flag("BS"))
        self.assertTrue(auth_data.sign_count > user["sign_count"])

    def test_create_u2f_credential(self):
        response = {
            "authenticatorAttachment": "cross-platform",
            "clientExtensionResults": {},
            "id": "8Z2O7MxWhWcsq-zTyIR9OyoNA1ofnI_ziy9rlYozMXcASsPXQrqVUpXj1npkzWOIk6yOggjifTqmmR9ZA40m-6NbS839cCwGoT2cVmk4p3OWPlJihf3mUnSmzFF7pG2i",
            "rawId": "8Z2O7MxWhWcsq-zTyIR9OyoNA1ofnI_ziy9rlYozMXcASsPXQrqVUpXj1npkzWOIk6yOggjifTqmmR9ZA40m-6NbS839cCwGoT2cVmk4p3OWPlJihf3mUnSmzFF7pG2i",
            "response": {
                "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjeDVjgVkBajCCAWYwggELoAMCAQICCQDXlUm9GmcXTzAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxGVCBGSURPIDAyMDAwIBcNMTcwNjIwMDAwMDAwWhgPMjA0MDA1MDEwMDAwMDBaMB8xHTAbBgNVBAMMFEZUIEZJRE8gMDQzMDAxMzNDOEE4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwM5MKwCmMRqFZN566_vb0GTGXH0wheSKiFuW0RrZ4OiaJ54sWNwHk2T32_0bKNZoNpTVW-qdT20ct-7pSS4FAaM2MDQwHQYDVR0OBBYEFPS2SmjDNOkBuOI8bmbmhmwxkx9dMBMGCysGAQQBguUcAgEBBAQDAgQwMAoGCCqGSM49BAMCA0kAMEYCIQDBlBimyW9sqGmbrLVWd1_AZ8YI853FCCJqoQErPpycZwIhAI3TJELH-8dpmz2rMjiTj6GiAvADI8-66V7KQUU1pIbZY3NpZ1hHMEUCIF7uI9QLd_yXYO5kRPFeUoTT1tK0tG7QyLGhs8jJwDpwAiEAn5ziPC29usTomlIp0MTtfA2BBFG8m1a2AmbtMS9oUgxoYXV0aERhdGFY5MRs74KtG1Rkd1kdAIsIdZ7D5tLstPOUdL_qaWmSXQO3QQAAAAAAAAAAAAAAAAAAAAAAAAAAAGDxnY7szFaFZyyr7NPIhH07Kg0DWh-cj_OLL2uVijMxdwBKw9dCupVSlePWemTNY4iTrI6CCOJ9OqaZH1kDjSb7o1tLzf1wLAahPZxWaTinc5Y-UmKF_eZSdKbMUXukbaKlAQIDJiABIVggQkUpSzzmmP4dXgLiqF_pP21_VcZp67f9PI4hkW8LPYYiWCCRt8YKHemm81ciPROkIqAK7Q7HFQR-epQARhfKIx8aLw",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTFN3WFRJUnpMRnNMM2lTcmc3Z2owcm9selZ4bFVKMUd3Q3FEMHR1NnJ4ayIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
                "transports": ["usb"],
                "authenticatorData": "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v-ppaZJdA7dBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYPGdjuzMVoVnLKvs08iEfTsqDQNaH5yP84sva5WKMzF3AErD10K6lVKV49Z6ZM1jiJOsjoII4n06ppkfWQONJvujW0vN_XAsBqE9nFZpOKdzlj5SYoX95lJ0psxRe6RtoqUBAgMmIAEhWCBCRSlLPOaY_h1eAuKoX-k_bX9Vxmnrt_08jiGRbws9hiJYIJG3xgod6abzVyI9E6QioArtDscVBH56lABGF8ojHxov",
                "publicKey": "pQECAyYgASFYIEJFKUs85pj-HV4C4qhf6T9tf1XGaeu3_TyOIZFvCz2GIlggkbfGCh3ppvNXIj0TpCKgCu0OxxUEfnqUAEYXyiMfGi8",
                "publicKeyAlgorithm": -7,
            },
        }
        challenge = "LSwXTIRzLFsL3iSrg7gj0rolzVxlUJ1GwCqD0tu6rxk"
        create_options = {
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",
                "requireResidentKey": False,
                "residentKey": "discouraged",
                "userVerification": "discouraged",
            },
            "challenge": challenge,
            "excludeCredentials": [],
            "pubKeyCredParams": [
                {"alg": -7, "type": "public-key"},
                {"alg": -257, "type": "public-key"},
            ],
            "rp": {"id": "demo.yubico.com", "name": "Yubico Demo"},
            "timeout": 600000,
            "user": {
                "displayName": "qwelvy",
                "id": "NfF0j0oEdzdAkGD1kxrQCzw-X6ryVIpcAISt8RoToxU",
                "name": "qwelvy",
            },
        }

        origin = "https://demo.yubico.com"
        auth_data = webauthn.verify_create_response(response, create_options, origin)
        self.assertEqual(response["id"], util.b64_encode(auth_data.cred_id))
