# Flatpak portal design for credential management

User credentials

Forward-facing
- WebAuthn user agent developers (browsers) expect more from the platform.
  Spending more time incorporating Linux users will not be high on their
  priority list.

Security:
- shifting to device-bound/device-managed credentials
- Opens the door to platform authenticator
- Should provide user consent
- Enable sandboxed applications to access credentials
- Consistent interface for secrets on a device (makes for better security)
  x most users don't use multiple browsers
  x most users use the same browser across multiple operating systems
  - not for browsers only?
  x how many native desktop apps require authentication to a web service?

Usability:

Privacy:
  - should not require user to create account on third-party to have nice UI
    for credentials

# API

## Name

org.freedesktop.portal.Credential -- Portal for obtaining credentials

## Methods

CreatePublicKeyCredential (IN  a{sv}  rp,
                           IN  a{sv}  user,
                           IN  aa{sv} credential_parameters,
                           IN  s      client_data,
                           IN  a{sv}  options,
                           OUT o      handle);

## Method Details

### The CreatePublicKeyCredential() method

CreatePublicKeyCredential (IN  a{sv}  rp,
                           IN  a{sv}  user,
                           IN  aa{sv} credential_parameters,
                           IN  s      client_data,
                           IN  a{sv}  options,
                           OUT o      handle);

Requests a new public key credential from the device or connected devices.

IN rp a{sv}
    Vardict with following properties:
        id s
            The relying party ID.
        name s
            The human-readable relying party name to display to the user.

IN user a{sv}

    Vardict with following properties:
        id ay
            The raw user ID.
        displayName s
            The human-readable name, like a nickname, for the user account. E.g. Alex Mueller.
        name s
            The human-readable name, like a username, for the user account, used for disambiguating credentials with similar displayName. E.g. alex.mueller@example.com

IN credential_parameters aa{sv}

    Array of Vardicts with the following properties:
        type s
            The type of key. "public-key" is the only currently supported option.
        alg x
            Requested algorithm, as a COSE algorithm identifier.

IN client_data s

    A JSON string containing data to be signed by an authenticator.

IN options a{sv}

    Vardict with optional further information including:
        handle_token s
            A string that will be used as the last element of the handle. Must
            be a valid object path element. See the
            org.freedesktop.portal.Request documentation for more information
            about the handle.
        timeout t
            Hint for the time, in milliseconds, that the caller is willing to
            wait for the call to complete.
        excluded_credentials aa{sv}
            Array of Vardicts with the following properties:
                type s
                    The type of key to exclude. "public-key" is the only currently supported option.
                id ay
                    Credential ID of the public key credential the caller wishes to exclude.
                transports
                    Hints as to how the client might communicate with the authenticator. Supported values are `usb`, `nfc`, `ble`, and `internal`.
        authenticator_attachment s
            The type of attachment the created credential should have.
            `platform` and `cross-platform` are the currently supported values.
        resident_key s
            Expresses a preference for a discoverable credential. Currently supported values are `required`, `preferred` and `discouraged`. Defaults to `required`.
        user_verification s
            Expresses a preference for user verification. Currently support values are `required`, `preferred`, and `discouraged`. Defaults to `preferred`.
        attestation s
            Expresses a preference for receiving an attestation statement from the authenticator. Currently supported values are `none`, `indirect`, `direct` and `enterprise`. Defaults to `none`.
        extension_data s
            JSON object representing extension input

OUT o handle:

    Object path for the org.freedesktop.portal.Request object representing this call

The following results get returned via the "Response" signal:

    attestation_object_result ay
        Bytes of attestation object returned from authenticator.

    client_data ay
        Bytes of client data JSON object used by the authenticator during credential creation. Should be the same as `client_data` input parameter.

    attestation_preference s
        Attestation preference used by the authenticator during credential creation. Should be the same as `options.attestation` input parameter.

    extension_results s
        JSON string of extension results

### GetPublicKeyCredential()

GetPublicKeyCredential(IN s     origin
                       IN b     cross_origin
                       IN ay    challenge
                       IN a{sv} options
                       OUT o    handle);

IN origin s
    The relying party ID

IN b cross_origin
   true if and only if the caller’s environment settings object is same-origin with its ancestors. It is false if caller is cross-origin.
IN challenge ay
    Random bytes for the authenticator to sign


IN options a{sv}

    Vardict with optional further information including:
        handle_token s
            A string that will be used as the last element of the handle. Must
            be a valid object path element. See the
            org.freedesktop.portal.Request documentation for more information
            about the handle.
        timeout t
            Hint for the time, in milliseconds, that the caller is willing to
            wait for the call to complete.
        allow_credentials aa{sv}
            Array of Vardicts with the following properties:
                type s
                    The type of key to exclude. "public-key" is the only currently supported option.
                id ay
                    Credential ID of the public key credential the caller wishes to exclude.
                transports
                    Hints as to how the client might communicate with the authenticator. Supported values are `usb`, `nfc`, `ble`, and `internal`.
        rp_id s
            The relying party identifier claimed by the caller. If omitted, its value will be the value of the `origin` parameter.
        user_verification s
            Expresses a preference for user verification. Currently supported values are `required`, `preferred`, and `discouraged`. Defaults to `preferred`.
        extension_data s
            JSON object representing extension input

OUT o handle:

    Object path for the org.freedesktop.portal.Request object representing this call

The following results get returned via the "Response" signal:

    attestation_object_result ay
        Bytes of attestation object returned from authenticator.

    client_data ay
        Bytes of client data JSON object used by the authenticator during credential creation. Should be the same as `client_data` input parameter.

    attestation_preference s
        Attestation preference used by the authenticator during credential creation. Should be the same as `options.attestation` input parameter.

    extension_results s
        JSON string of extension results

## U2F Compatibility

Some applications may currently have U2F support but not full WebAuthn support.
Because WebAuthn is compatible with U2F, we will not implement U2F Register()
and Sign() methods.

Instead, developers who wish to integrate with the Credential portal and continue to support keys that were previously registered with the U2F protocol should be
encouraged to implement support for:
- the FIDO U2F Attestation Statement Format,
- the FIDO AppID extension, and
- the FIDO AppID Exclusion extension to support.

Note that registering new U2F keys only requires support for the FIDO U2F
Attestation Statement Format.

# Background Information

## Influences

- WebAuthn
- Credential Management API
- Windows Hello/WebAuthn API
- [dueno/fido2-proxy](https://gitlab.com/dueno/fido2-proxy)
- [AlfioEmanualeFresta/xdg-credentials-portal](https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/)
- Sigstore
- Digital Assets Links (Google)

## Philosophy

- Caller (client) should not have to have a CBOR parser. So CBOR objects will be parsed and broken out when necessary. This focuses on the client (browser, native app), rather than the relying party, which is usually a web service that can easily obtain a CBOR parser. So attestation objects will be returned as CBOR, while extension output will be JSON, for example.
- Move all required parameters from WebAuthn into top-level. Optional parameters go in the `options`

# Motivation and Scope

Properly managing credentials for online services are important for user security.

A credential management API for the Linux desktop is primarily motivated by the shift to device-bound or device-managed credentials using technology like smartcards, TPMs and especially FIDO2/WebAuthn credentials. Now that device credentials are coming to consumers, it has become more important to have programmatic access to those credentials. Up until this point, users could manage credentials themselves by memorizing passwords or by copying/pasting them. But by design, device credentials cannot be easily used directly by a user; a user agent must be involved.

Browsers have taken on the user agent role for device credentials on Linux. This has jumpstarted user adoption. However, this has a few weaknesses. WebAuthn designers expect platforms (operating systems) to take on more responsibility of managing device credentials. This has benefits, such as allowing the user to use their OS credentials to authentiate both to their device and to online services. Operating systems also have privileged access to hardware, which allows them to more easily and securely connect to the hardware required to authenticate (biometric sensors, USB devices, Bluetooth/NFC radios). As native apps also adopt device credentials, it can theoretically also give them a more consistent user interface for managing credentials in different contexts. More consistency leads to better usability which leads to better user security.

These benefits cause a push to implement these features in the platform rather than the browser itself. And while browser vendors are more motivated to implement these features on more widely-used operating systems, they are less motivated to do so for Linux desktops because of the small market share that they comprise. (Though we do get some crossover from ChromeOS devices.)

Furthermore, while supporting cross-platform credentials over USB may be within the browser vendors' interest, it is unlikely that browser vendors will desire or [be able to] invest in supporting other credential transports (Bluetooth or NFC) or supporting biometric sensors or TPM-backed credentials. With a credential management API, a platform authenticator could be developed as part of the implementation to bring those capabilities to Linux users.

Besides WebAuthn push toward platform-managed credentials, the Linux desktop application ecosystem is pushing toward sandboxed applications, like Flatpak and Snap. Currently in those environments, to allow access to device credentials, the sandbox must allow access to all devices, at least for each transport (USB, Bluetooth, etc.). That is a pretty large security hole, but with a portal API and permissions design, we can provide sandboxed applications finely-grained access to device credentials without giving access to the hardware directly.

A credential management API local to the desktop also provides other benefits, like having a built-in password/passkey manager on the device (rather than requiring the user to install separate software or subscribe to another third-party service). We can also seamlessly provide access to credentials while also retaining the ability to request user's consent for applications.

For these reasons, we should.

As mentioned above, much of this is driven by device credentials. Password credentials are still largely in use, and it would be useful, for example to provide access to password credentials in the same way that device credentials are presented (similar UI components, consent dialogs, etc.). It could also unify how username/password credentials per-origin are stored 9rather than each application having its own schema in the Secret Service API, for example.) For that reason, it would be good to implement. However, it will not be worth our time if no one adopts it. If not enough apps adopt it, then even the apps that do use it will have a strange UX compared to the majority which don't, defeating the purpose of the consistent UI. However, it would still be good to leave the door open to a password credential management API. So the design of the credential management API as a whole should take that into consideration, but more attention will be paid to device credential management.

## Other Ecosystem needs

- Password/passkey manager GUI tool (Could be updating GNOME Secrets app)
- Credential Autofill process/service (Look at Android/Jetpack CredentialManager API, Apple's ASAuthorizationPasswordProvider/SecAddSharedWebCredential)
  - Should include Credential Provider API to allow third-party password managers to provide credentials as well.
- GUI component (GNOME?) for displaying/marking a field as requiring a password/passkey authentication that initiates autofill
- Platform authenticator
  - Biometric authentication (how to authenticate fingerprint response to OS? How to bind biometric templates to credential key?)
  - PIN authentication
  - Hybrid support
