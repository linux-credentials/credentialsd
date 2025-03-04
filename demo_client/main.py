#!/usr/bin/env python3

import asyncio
import base64
import hmac
import json
from pprint import pprint
import secrets
import struct
import hashlib
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from dbus_next.aio import MessageBus
from dbus_next import Variant

import cbor

async def run():
    bus = await MessageBus().connect()

    with open('xyz.iinuwa.credentials.CredentialManager.xml', 'r') as f:
        introspection = f.read()

    proxy_object = bus.get_proxy_object('xyz.iinuwa.credentials.CredentialManagerUi',
                                        '/xyz/iinuwa/credentials/CredentialManagerUi',
                                        introspection)

    interface = proxy_object.get_interface(
        'xyz.iinuwa.credentials.CredentialManagerUi1')

    rsp = await create_passkey(interface)
    pprint(rsp)
    # rsp = await create_password(interface)
    # print(rsp)
    # rsp = await get_password(interface)
    # print(rsp)
    # await bus.wait_for_disconnect()


async def create_password(interface):
    password_req = {
        "type": Variant('s', "password"),
        "password": Variant("a{sv}", {
            "origin": Variant('s', "xyz.iinuwa.credentials.CredentialManager:local"),
            "id": Variant('s', "test@example.com"),
            "password": Variant('s', "abc123"),
        })
    }
    rsp = await interface.call_create_credential(password_req)
    return rsp


async def get_password(interface):
    password_req = {
        "origin": Variant("s", "xyz.iinuwa.credentials.CredentialManager:local"),
        "options": Variant("aa{sv}", [
            {
                "type": Variant("s", "password"),
                "password": Variant("a{sv}", {}),
            }
        ])
    }
    rsp = await interface.call_get_credential(password_req)
    if rsp['type'].value == 'password':
        cred = rsp['password'].value
        id = cred['id'].value
        password = cred['password'].value
        return (id, password)
    return None


async def create_passkey(interface):
    options = {
        "challenge": base64.urlsafe_b64encode(secrets.token_bytes(16))
                           .rstrip(b'=').decode('ascii'),
        "rp": {
            "name": "Example Org",
            "id": "example.com",
        },
        "user": {
            "id": base64.urlsafe_b64encode(b"123abdsacddw").rstrip(b'=').decode('ascii'),
            "name": "user@example.com",
            "displayName": "User 1",
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
            {"type": "public-key", "alg": -8},
        ],
    }
    origin = "https://example.com"
    is_same_origin = False

    print(f"Sending {'same' if is_same_origin else 'cross'}-origin request for {origin} using options:")
    pprint(options)
    print()

    req_json = json.dumps(options)
    req = {
        "type": Variant('s', "publicKey"),
        "origin": Variant('s', origin),
        "is_same_origin": Variant('b', is_same_origin),
        "publicKey": Variant('a{sv}', {
            "request_json": Variant('s', req_json)
        })
    }

    rsp = await interface.call_create_credential(req)
    print("Received response")
    pprint(rsp)
    if rsp['type'].value != 'public-key':
        raise Exception(f"Invalid credential type received: expected 'public-key', received {rsp['type'.value]}")

    response_json = json.loads(rsp['public_key'].value['registration_response_json'].value)
    return verify_response(response_json, options, origin)


def verify_response(response, create_request, expected_origin):
    client_data = json.loads(response['response']['clientDataJSON'])
    if client_data['type'] != "webauthn.create":
        raise Exception(f"Invalid operation type received: {client_data['type']}")

    challenge_str = client_data['challenge']
    if challenge_str != create_request['challenge']:
        raise Exception(f"Challenge does not match original request. Rejecting.")

    origin = client_data['origin']
    if origin != expected_origin:
        raise Exception(f"Origin does not match original request. Rejecting.")

    client_data_hash = hashlib.sha256(response['response']['clientDataJSON'].encode('utf-8')).digest()
    # Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.

    remaining = len(response['response']['attestationObject']) % 4
    if remaining == 3:
        att_payload =  response['response']['attestationObject'] + "="
    elif remaining == 2:
        att_payload =  response['response']['attestationObject'] + "=="
    else:
        att_payload = response['response']['attestationObject']
    attestation = cbor.load(base64.urlsafe_b64decode(att_payload))
    auth_data = attestation["authData"]
    att_stmt = attestation["attStmt"]

    client_rp_id_hash = auth_data[:32]
    expected_rp_id_hash = hashlib.sha256(create_request['rp']['id'].encode('utf-8')).digest()

    if not hmac.compare_digest(client_rp_id_hash, expected_rp_id_hash):
        raise Exception("Relying party in authenticator data does not match request. Rejecting.")

    # Verify that the User Present bit of the flags in authData is set.
    flags = set()
    flag_byte = auth_data[32]
    cat = ["UP", "RFU1", "UV", "RFU2", "RFU2", "RFU2", "AT", "ED"]
    for i in range(8):
        if flag_byte & 0x01 == 1:
            flags.add(cat[i])
        flag_byte = flag_byte >> 1

    if 'UP' not in flags:
        raise Exception("User presence was not asserted by the authenticator. Rejecting.")

    if create_request.get('authenticatorSelection', {}).get('userVerification') == 'required' and 'UV' not in flags:
        raise Exception("User verification is required but was not asserted by the authenticator. Rejecting.")

    if 'AT' not in flags:
        raise Exception("Attested credential data not included in request. Rejecting.")

    aaguid = auth_data[37:37 + 16]
    attested_credential_data = auth_data[37:]

    cred_id_length = struct.unpack('>H', auth_data[53:55])[0]
    cred_id = auth_data[55:55+cred_id_length]

    if 'ED' not in flags:
        cred_pub_key_bytes = auth_data[55 + cred_id_length:]
    else:
        raise Exception("Parsing output with extensions is not implemented")
    cred_pub_key = cbor.load(cred_pub_key_bytes)

    COSE_KTY = 1
    COSE_KTY_OKP = 1
    COSE_KTY_EC2 = 2
    COSE_ALG = 3
    COSE_ALG_ECDSA = -7
    COSE_ALG_EDDSA = -8
    COSE_CRV = -1
    COSE_CRV_ED25519 = 6
    COSE_CRV_P256 = 1
    COSE_OKP_PUBLIC_KEY = -2
    kty = cred_pub_key[COSE_KTY]
    alg = cred_pub_key[COSE_ALG]
    # Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
    if alg not in (p['alg'] for p in create_request['pubKeyCredParams']):
        raise Exception("Public key algorithm not in list of accepted key types. Rejecting.")

    # testing explicitly for ECDSA algorithm
    if alg == COSE_ALG_ECDSA:
        if kty != COSE_KTY_EC2:
            raise Exception(f"Invalid key type specified: expected {COSE_KTY_EC2} (EC2), received {kty}")
    elif alg == COSE_ALG_EDDSA:
        if kty != COSE_KTY_OKP:
            raise Exception(f"Invalid key type specified: expected {COSE_KTY_OKP} (OKP), received {kty}")
        crv = cred_pub_key[COSE_CRV]
        if crv != COSE_CRV_ED25519:
            raise Exception(f"Unsupported EdDSA curve specified: {crv}")

    # Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
    # Note: Client platforms MAY enact local policy that sets additional authenticator extensions or client extensions and thus cause values to appear in the authenticator extension outputs or client extension outputs that were not originally specified as part of options.extensions. Relying Parties MUST be prepared to handle such situations, whether it be to ignore the unsolicited extensions or reject the attestation. The Relying Party can make this decision based on local policy and the extensions in use.
    # Note: Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST also be prepared to handle cases where none or not all of the requested extensions were acted upon.
    # Skip
    # if 'extensions' in create_request:
    #     # not implemented
    #     pass

    # Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
    supported_att_fmts = ['none', 'packed']
    fmt = attestation['fmt']
    if fmt not in supported_att_fmts:
        raise Exception(f"Unsupported attestation format: {fmt}")

    # Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
    if fmt == "none":
        pass
    elif fmt == "packed":
        att_payload = auth_data.tobytes() + client_data_hash
        sig = att_stmt['sig']
        att_alg = att_stmt['alg']
        if 'x5c' in att_stmt:
            if att_alg == COSE_ALG_ECDSA:
                signing_cert = x509.load_der_x509_certificate(att_stmt['x5c'][0].tobytes())
                assert(signing_cert.version == x509.Version.v3)
                try:
                    fido_oid = signing_cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"))
                    assert(fido_oid.critical == False)
                    cert_aaguid_der = fido_oid.value.value
                    # strip first two header bytes for OCTET STRING of length 16
                    assert(cert_aaguid_der[:2] == b'\x04\x10')
                    cert_aaguid = cert_aaguid_der[2:]
                    assert(aaguid.tobytes() == cert_aaguid)
                except x509.ExtensionNotFound:
                    # no FIDO OID found in cert.
                    pass
                assert(signing_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value.ca == False)
                signing_key = signing_cert.public_key()
                signing_key.verify(sig, att_payload, ec.ECDSA(hashes.SHA256()))
            if len(att_stmt['x5c']) > 1:
                raise Exception("CA verification is not supported")
        else:
            # authenticator is using self attestation
            if alg != att_alg:
                raise Exception("Self-attestation is in use, but credential algorithm and attestation algorithm do not match. Rejecting.")
            if alg == COSE_ALG_ECDSA:
                raise Exception("ECDSA self-attestation not implemented")
                pass
            elif alg == COSE_ALG_EDDSA:
                crv = cred_pub_key[COSE_CRV]
                if crv != COSE_CRV_ED25519:
                    raise Exception(f"Unsupported EdDSA curve specified: {crv}")
                pub_key_bytes = cred_pub_key[COSE_OKP_PUBLIC_KEY]
                signing_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes.tobytes())
                signing_key.verify(sig, att_payload)
    else:
        raise Exception("We shouldn't be able to get here")
    # Note: Each attestation statement format specifies its own verification procedure. See § 8 Defined Attestation Statement Formats for the initially-defined formats, and [IANA-WebAuthn-Registries] for the up-to-date list.
    # If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
    # Assess the attestation trustworthiness using the outputs of the verification procedure in step 19, as follows:
    #     If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
    #     If self attestation was used, verify that self attestation is acceptable under Relying Party policy.
    #     Otherwise, use the X.509 certificates returned as the attestation trust path from the verification procedure to verify that the attestation public key either correctly chains up to an acceptable root certificate, or is itself an acceptable certificate (i.e., it and the root certificate obtained in Step 20 may be the same).
    # Skip


    sign_count = struct.unpack('>I', auth_data[33:37])[0]
    return (base64.urlsafe_b64encode(cred_id).rstrip(b'='), cred_pub_key_bytes.tobytes(), sign_count)


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run())


if __name__ == "__main__":
    main()

class VerificationTests(unittest.TestCase):
    def test_1(self):
        response = {
            'id': 'owBYoufBWYDUOeNB9dZs9x6GlEPiS8ziKnI_9YVq9RpkwwYsxelm66HOP2usfy-SaV8NE5nJVWDIMvS0W-x9BYtN4AmHZVY33GW2rdfLpeBruuh4jDXgYdnHtZC0IyDIKZiOTzSzyoQih8F-VLcTmqQl7SVHgf-xAh-6TxAJMccROZyIsili1OOnv3WSE7374c2Sw9At0ILaSiTmvC7MtZfnj9hhnAFMFobCJvainepVBn3HAlDo22486wkPqW2D5N00XYXK',
            'rawId': 'owBYoufBWYDUOeNB9dZs9x6GlEPiS8ziKnI_9YVq9RpkwwYsxelm66HOP2usfy-SaV8NE5nJVWDIMvS0W-x9BYtN4AmHZVY33GW2rdfLpeBruuh4jDXgYdnHtZC0IyDIKZiOTzSzyoQih8F-VLcTmqQl7SVHgf-xAh-6TxAJMccROZyIsili1OOnv3WSE7374c2Sw9At0ILaSiTmvC7MtZfnj9hhnAFMFobCJvainepVBn3HAlDo22486wkPqW2D5N00XYXK',
            'response': {
                'attestationObject': 'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgIQ1ReuY8bt2QPrmsZGqphT3hwTJ4Ar2zd3RevRXelHYCIQDiSKGGo5mUqsWP43B6TgxcWby0M1ucBkwOQTS4E6Dt-mN4NWOBWQKqMIICpjCCAkygAwIBAgIUfWe3F4mJfmOVopPF8mmAKxBb0igwCgYIKoZIzj0EAwIwLTERMA8GA1UECgwIU29sb0tleXMxCzAJBgNVBAYTAkNIMQswCQYDVQQDDAJGMTAgFw0yMTA1MjMwMDUyMDBaGA8yMDcxMDUxMTAwNTIwMFowgYMxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhTb2xvS2V5czEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjE9MDsGA1UEAww0U29sbyAyIE5GQytVU0ItQSA4NjUyQUJFOUZCRDg0ODEwQTg0MEQ2RkM0NDJBOEMyQyBCMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABArSyTVT7sDxX0rom6XoIcg8qwMStGV3SjoGRNMqHBSAh2sr4EllUzA1F8yEX5XvUPN_M6DQlqEFGw18UodOjBqjgfAwge0wHQYDVR0OBBYEFBiTdxTWyNCRuzSieBflmHPSJbS1MB8GA1UdIwQYMBaAFEFrtkvvohkN5GJf_SkElrmCKbT4MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL2kuczJwa2kubmV0L2YxLzAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8vYy5zMnBraS5uZXQvcjEvMCEGCysGAQQBguUcAQEEBBIEEIZSq-n72EgQqEDW_EQqjCwwEwYLKwYBBAGC5RwCAQEEBAMCBDAwCgYIKoZIzj0EAwIDSAAwRQIgMsLnUg5Px2FehxIUNiaey8qeT1FGtlJ1s3LEUGOks-8CIQDNEv5aupDvYxn2iqWSNysv4qpdoqSMytRQ7ctfuJDWN2hhdXRoRGF0YVkBJ6N5pvbur7mlXjeMEYA04nUeaC-rny0wqxPSElWGzhlHRQAAADmGUqvp-9hIEKhA1vxEKowsAMajAFii58FZgNQ540H11mz3HoaUQ-JLzOIqcj_1hWr1GmTDBizF6Wbroc4_a6x_L5JpXw0TmclVYMgy9LRb7H0Fi03gCYdlVjfcZbat18ul4Gu66HiMNeBh2ce1kLQjIMgpmI5PNLPKhCKHwX5UtxOapCXtJUeB_7ECH7pPEAkxxxE5nIiyKWLU46e_dZITvfvhzZLD0C3QgtpKJOa8Lsy1l-eP2GGcAUwWhsIm9qKd6lUGfccCUOjbbjzrCQ-pbYPk3TRdhcqkAQEDJyAGIVggzFQIxv1GYCb7CZXbKR8VRTWiRCbceHYcsBNx-lOg9Xk',
                'clientDataJSON': '{"type":"webauthn.create","challenge":"j-dyF8Xcw5lY2YFJ260ywg","origin":"xyz.iinuwa.credentials.CredentialManager:local","crossOrigin":true}',
                'transports': ['usb']
            }
        }
        challenge = 'j-dyF8Xcw5lY2YFJ260ywg'
        create_options = {
            'challenge': challenge,
            'rp': {
                'id': 'example.com'
            },
            'authenticatorSelection': {
                'userVerification': 'required'
            },
            'pubKeyCredParams': [
                {
                    "type": "public-key",
                    "alg": -8
                },
                {
                    "type": "public-key",
                    "alg": -7
                },
                {
                    "type": "public-key",
                    "alg": -257
                }
            ]
        }
        origin = None

        cred_id, pub_key_bytes, sign_count = verify_response(response, create_options, "xyz.iinuwa.credentials.CredentialManager:local")
        self.assertEqual(response['id'].encode('ascii'), cred_id)

