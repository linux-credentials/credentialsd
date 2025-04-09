from dataclasses import dataclass
import hashlib
import hmac
import json
import struct
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import cbor
import util

COSE_KTY = 1
COSE_KTY_OKP = 1
COSE_KTY_EC2 = 2
COSE_ALG = 3
COSE_ALG_ECDSA = -7
COSE_ALG_EDDSA = -8
COSE_CRV_ED25519 = 6
COSE_CRV_P256 = 1
COSE_OKP_CRV = -1
COSE_OKP_PUBLIC_KEY = -2
COSE_EC2_CRV = -1
COSE_EC2_X = -2
COSE_EC2_Y = -3

def verify_create_response(response, create_request, expected_origin):
    client_data_bytes = util.b64_decode(response['response']['clientDataJSON'])
    client_data = json.loads(client_data_bytes.decode("utf-8"))
    if client_data['type'] != "webauthn.create":
        raise Exception(f"Invalid operation type received: {client_data['type']}")

    challenge_str = client_data['challenge']
    if challenge_str != create_request['challenge']:
        raise Exception(f"Challenge does not match original request. Rejecting.")

    origin = client_data['origin']
    if origin != expected_origin:
        raise Exception(f"Origin does not match original request. Rejecting.")

    client_data_hash = hashlib.sha256(client_data_bytes).digest()
    # Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.

    attestation = cbor.loads(util.b64_decode(response['response']['attestationObject']))
    auth_data_view = attestation["authData"]
    auth_data = _parse_authenticator_data(auth_data_view)
    att_stmt = attestation["attStmt"]

    expected_rp_id_hash = hashlib.sha256(create_request['rp']['id'].encode('utf-8')).digest()

    if not hmac.compare_digest(auth_data.rp_id_hash, expected_rp_id_hash):
        raise Exception("Relying party in authenticator data does not match request. Rejecting.")

    # Verify that the User Present bit of the flags in authData is set.
    if 'UP' not in auth_data.flags:
        raise Exception("User presence was not asserted by the authenticator. Rejecting.")

    if create_request.get('authenticatorSelection', {}).get('userVerification') == 'required' and 'UV' not in auth_data.flags:
        raise Exception("User verification is required but was not asserted by the authenticator. Rejecting.")

    if 'AT' not in auth_data.flags:
        raise Exception("Attested credential data not included in request. Rejecting.")

    cred_pub_key = auth_data.get_pub_key()

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
        crv = cred_pub_key[COSE_OKP_CRV]
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
        att_payload = auth_data_view.tobytes() + client_data_hash
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
                    assert(auth_data.aaguid.tobytes() == cert_aaguid)
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
                crv = cred_pub_key[COSE_OKP_CRV]
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

    return auth_data

def verify_get_response(credential, options, expected_origin, identified_user, users):
    assert(identified_user or users)
    # Let options be a new CredentialRequestOptions structure configured to the
    # Relying Party’s needs for the ceremony. Let pkOptions be
    # options.publicKey.

    # Call navigator.credentials.get() and pass options as the argument. Let
    # credential be the result of the successfully resolved promise. If the
    # promise is rejected, abort the ceremony with a user-visible error, or
    # otherwise guide the user experience as might be determinable from the
    # context available in the rejected promise. For information on different
    # error contexts and the circumstances leading to them, see § 6.3.3 The
    # authenticatorGetAssertion Operation.

    # Let response be credential.response. If response is not an instance of
    # AuthenticatorAssertionResponse, abort the ceremony with a user-visible
    # error.
    response = credential['response']

    # Let clientExtensionResults be the result of calling
    # credential.getClientExtensionResults().

    # If pkOptions.allowCredentials is not empty, verify that credential.id
    # identifies one of the public key credentials listed in
    # pkOptions.allowCredentials.
    if allow_credentials := options.get('allowCredentials'):
        if not any(c['id'] == credential['id'] for c in allow_credentials):
            raise Exception("Credential not in list of allowed credentials")

    # Identify the user being authenticated and let credentialRecord be the
    # credential record for the credential:

    # If the user was identified before the authentication ceremony was
    # initiated, e.g., via a username or cookie,
    user_handle = response['userHandle']
    if identified_user:
    #     verify that the identified user account contains a credential record
    #     whose id equals credential.rawId. Let credentialRecord be that
    #     credential record.
        credential['id'] == identified_user['cred_id']
    #     If response.userHandle is present, verify that it equals the user handle of the user account.
        if user_handle and user_handle != identified_user['user_handle']:
            raise Exception("Unexpected user handle received from credential")
    # If the user was not identified before the authentication ceremony was
    # initiated,
    elif user_handle:
    #     verify that response.userHandle is present. Verify that the user
    #     account identified by response.userHandle contains a credential record
    #     whose id equals credential.rawId. Let credentialRecord be that
    #     credential record.
        identified_user = next(u for u in users if u['user_handle'] == user_handle)
    else:
        raise Exception("User is unidentified and no user handle was returned by credential")

    # Let cData, authData and sig denote the value of response’s clientDataJSON,
    # authenticatorData, and signature respectively.
    client_data_json = util.b64_decode(response['clientDataJSON']).decode("utf-8")
    auth_data_bytes = util.b64_decode(response['authenticatorData'])
    auth_data = _parse_authenticator_data(auth_data_bytes)
    sig_bytes = util.b64_decode(response['signature'])

    # Let JSONtext be the result of running UTF-8 decode on the value of cData.
    # Note: Using any implementation of UTF-8 decode is acceptable as long as it
    # yields the same result as that yielded by the UTF-8 decode algorithm. In
    # particular, any leading byte order mark (BOM) must be stripped.
    # Let C, the client data claimed as used for the signature, be the result of
    # running an implementation-specific JSON parser on JSONtext.
    # Note: C may be any implementation-specific data structure representation,
    # as long as C’s components are referenceable, as required by this
    # algorithm.
    C = json.loads(client_data_json)

    # Verify that the value of C.type is the string webauthn.get.
    if C['type'] != 'webauthn.get':
        raise Exception(f"Invalid operation type asserted by credential: {C['type']}. Rejecting.")

    # Verify that the value of C.challenge equals the base64url encoding of
    # pkOptions.challenge.
    if C['challenge'] != options['challenge']:
        raise Exception("Invalid challenge received from authenticator. Rejecting.")
    # Verify that the value of C.origin is an origin
    # expected by the Relying Party. See § 13.4.9 Validating the origin of a
    # credential for guidance.
    if C['origin'] != expected_origin:
        raise Exception(f"Attested origin `{C['origin']}` does not match expected origin `{expected_origin}`")

    # If C.crossOrigin is present and set to true, verify that the Relying Party
    # expects this credential to be used within an iframe that is not
    # same-origin with its ancestors.
    if C.get('crossOrigin') == True:
        # TODO: pass cross-origin policy as parameter
        pass

    # If C.topOrigin is present:
    if C.get('topOrigin'):
    #     Verify that the Relying Party expects this credential to be used
    #     within an iframe that is not same-origin with its ancestors.
        # TODO: pass top-origin policy as parameter
    #     Verify that the value of C.topOrigin matches the origin of a page that
    #     the Relying Party expects to be sub-framed within. See § 13.4.9
    #     Validating the origin of a credential for guidance.
        # TODO: pass top-origin policy as parameter
        pass

    # Verify that the
    #     rpIdHash in authData is the SHA-256 hash of the RP ID expected by the
    #     Relying Party.
    expected_rp_id_hash = hashlib.sha256(options['rpId'].encode('utf-8')).digest()
    if not hmac.compare_digest(auth_data.rp_id_hash, expected_rp_id_hash):
        raise Exception("Relying party in authenticator data does not match request. Rejecting.")

    # Note: If using the appid extension, this step needs some special logic.
    # See § 10.1.1 FIDO AppID Extension (appid) for details.
    # TODO

    # Verify that the UP bit of the flags in authData is set.
    if not auth_data.has_flag('UP'):
        raise Exception("User presence was not asserted by the authenticator. Rejecting.")

    # Determine whether user verification is required for this assertion. User
    # verification SHOULD be required if, and only if,
    # pkOptions.userVerification is set to required.
    # If user verification was determined to be required, verify that the UV bit
    # of the flags in authData is set. Otherwise, ignore the value of the UV
    # flag.
    if options.get('userVerification') == 'required' and not auth_data.has_flag('UV'):
        raise Exception("User verification is required but was not asserted by the authenticator. Rejecting.")

    # If the BE bit of the flags in authData is not set, verify that the BS bit
    # is not set.
    if not auth_data.has_flag('BE') and auth_data.has_flag('BS'):
        raise Exception("Conflicted backup state: Authenticator reported to be backed up, but not backup-eligible. Rejecting.")

    # If the credential backup state is used as part of Relying Party business
    # logic or policy, let currentBe and currentBs be the values of the BE and
    # BS bits, respectively, of the flags in authData.
    current_be = auth_data.has_flag('BE')
    current_bs = auth_data.has_flag('BS')
    # Compare currentBe and
    # currentBs with credentialRecord.backupEligible and
    # credentialRecord.backupState:
    #     If credentialRecord.backupEligible is set, verify that currentBe is
    #     set.
    if identified_user['backup_eligible'] and not current_be:
        raise Exception("Authenticator previously reported that it was backup eligible on creation, but now does not. Rejecting.")
    #     If credentialRecord.backupEligible is not set, verify that currentBe
    #     is not set.
    elif not identified_user['backup_eligible'] and current_be:
        raise Exception("Authenticator attempted to upgrade to be backup eligible. Rejecting.")
    #     Apply Relying Party policy, if any.
    # Note: See § 6.1.3 Credential Backup State for examples of how a Relying
    # Party might process the BS flag values.
    # TODO: pass backup policy as parameter

    # Note that the WebAuthn spec recommends not to allow upgrading a credential
    # to become backup-eligible.
    # So if we implement a platform authenticator, without backup eligibility
    # and add it again later, we'll have to prompt users to create new
    # credentials in order for some RPs to recognize this.

    # Let hash be the result of computing a hash over the cData using SHA-256.
    client_data_hash = hashlib.sha256(client_data_json.encode('utf-8')).digest()

    # Using credentialRecord.publicKey, verify that sig is a valid signature
    # over the binary concatenation of authData and hash.
    # Note: This verification step is compatible with signatures generated by
    # FIDO U2F authenticators. See § 6.1.2 FIDO U2F Signature Format
    # Compatibility.
    pub_key = util.b64_decode(identified_user['pub_key'])
    _cose_verify(pub_key, sig_bytes, auth_data_bytes + client_data_hash)

    # If authData.signCount is nonzero or credentialRecord.signCount is nonzero,
    # then run the following sub-step:
    sc = auth_data.sign_count if auth_data.sign_count else 0
    user_sc = identified_user['sign_count'] if identified_user['sign_count'] else 0
    if sc > 0 or user_sc > 0:
    #     If authData.signCount is
    #     greater than credentialRecord.signCount: The signature counter is
    #     valid.
        if sc > user_sc:
            pass
    #     less than or equal to credentialRecord.signCount: This is a
    #     signal, but not proof, that the authenticator may be cloned. For
    #     example it might mean that:
    #           - Two or more copies of the credential private key may exist and
    #             are being used in parallel.
    #           - An authenticator is malfunctioning.
    #           - A race condition exists where the Relying Party is processing
    #             assertion responses in an order other than the order they were
    #             generated at the authenticator.
        else:
    #         Relying Parties should evaluate their own operational
    #         characteristics and incorporate this information into their risk
    #         scoring. Whether the Relying Party updates
    #         credentialRecord.signCount below in this case, or not, or fails
    #         the authentication ceremony or not, is Relying Party-specific.

    #         For more information on signature counter considerations, see
    #         § 6.1.1 Signature Counter Considerations.
            # TODO: add policy
            raise Exception("Authenticator signature count too low and the authenticator may have been cloned. Rejecting.")

    # Process the client extension outputs in clientExtensionResults and the
    # authenticator extension outputs in the extensions in authData as required
    # by the Relying Party. Depending on each extension, processing steps may be
    # concretely specified or it may be up to the Relying Party what to do with
    # extension outputs. The Relying Party MAY ignore any or all extension
    # outputs.

    # Clients MAY set additional authenticator extensions or client extensions
    # and thus cause values to appear in the authenticator extension outputs or
    # client extension outputs that were not requested by the Relying Party in
    # pkOptions.extensions. The Relying Party MUST be prepared to handle such
    # situations, whether by ignoring the unsolicited extensions or by rejecting
    # the assertion. The Relying Party can make this decision based on local
    # policy and the extensions in use.

    # Since all extensions are OPTIONAL for both the client and the
    # authenticator, the Relying Party MUST also be prepared to handle cases
    # where none or not all of the requested extensions were acted upon.

    # TODO: Support client and authenticator extensions

    # Update credentialRecord with new state values:
    #   - Update credentialRecord.signCount to the value of authData.signCount.
    #   - Update credentialRecord.backupState to the value of currentBs.
    #   - If credentialRecord.uvInitialized is false, update it to the value of
    #     the UV bit in the flags in authData. This change SHOULD require
    #     authorization by an additional authentication factor equivalent to
    #     WebAuthn user verification; if not authorized, skip this step.
    # If the Relying Party performs additional security checks beyond these
    # WebAuthn authentication ceremony steps, the above state updates SHOULD be
    # deferred to after those additional checks are completed successfully.

    # return auth_data instead of modifying record here

    # If all the above steps are successful, continue the authentication
    # ceremony as appropriate. Otherwise, fail the authentication ceremony.
    return auth_data


def _cose_verify(cose_key: bytes, signature: bytes, data: bytes):
    cred_pub_key = cbor.loads(cose_key)
    kty = cred_pub_key[COSE_KTY]
    cose_alg = cred_pub_key[COSE_ALG]

    if cose_alg == COSE_ALG_ECDSA:
        if kty != COSE_KTY_EC2:
            raise Exception(f"Invalid COSE key type specified for ECDSA: expected {COSE_KTY_EC2} (EC2), received {kty}")

        x = cred_pub_key[COSE_EC2_X]
        y = cred_pub_key[COSE_EC2_Y]

        cose_crv = cred_pub_key[COSE_EC2_CRV]
        if cose_crv == COSE_CRV_P256:
            crv = ec.SECP2561R1
            alg = ec.ECDSA(hashes.SHA256())
        else:
            raise Exception(f"Unsupported COSE ECDSA curve specified: {crv}")

        signing_key = ec.EllipticCurvePublicNumbers(crv, x, y).public_key()
        signing_key.verify(signature, data, alg)
    elif cose_alg == COSE_ALG_EDDSA:
        if kty != COSE_KTY_OKP:
            raise Exception(f"Invalid COSE key type specified for EdDSA: expected {COSE_KTY_OKP} (OKP), received {kty}")
        pub_key_bytes = cred_pub_key[COSE_OKP_PUBLIC_KEY].tobytes()

        crv = cred_pub_key[COSE_OKP_CRV]
        if crv == COSE_CRV_ED25519:
            signing_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        else:
            raise Exception(f"Unsupported COSE EdDSA curve specified: {crv}")

        signing_key.verify(signature, data)
    else:
        raise Exception(f"Unsupported COSE key algorithm specified: {cose_alg}")



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

    sign_count = struct.unpack('>I', auth_data[33:37])[0]

    if 'AT' in flags:
        aaguid = auth_data[37:37 + 16]
        cred_id_length = struct.unpack('>H', auth_data[53:55])[0]
        cred_id = auth_data[55:55+cred_id_length]
        parser = cbor.Parser(auth_data[55 + cred_id_length:])
        _ = parser.parse()
        cose_key_bytes = parser.data[:parser.pos]
        cose_key_bytes_len = len(cose_key_bytes)
        assert(len(cose_key_bytes) == parser.pos)
        attested_cred_data_len = 55 + cred_id_length + cose_key_bytes_len

    else:
        attested_cred_data_len = 0
        aaguid = None
        cred_id = None
        cose_key_bytes = None

    if 'ED' in flags:
        extensions = cbor.loads(auth_data[37 + attested_cred_data_len:])
    else:
        extensions = None
    return AuthenticatorData(
        rp_id_hash=client_rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        aaguid=aaguid,
        cred_id=cred_id,
        pub_key_bytes=cose_key_bytes,
        extensions=extensions
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
            return cbor.loads(self.pub_key_bytes)

    def has_flag(self, flag):
        return flag in self.flags


