# API Overview

There are three main API defined by this specification:

- [Gateway API](#gateway-api)
- [Flow Control API](#flow-control-api)
- [UI Control API](#ui-control-api)

The **Gateway** is the entrypoint for clients to interact with. The Flow
Controller and UI Controller work together to guide the user through the
process of selecting an appropriate credential based on the request received by
the Gateway.

The **UI Control API** is used to launch a UI for the user to respond to
authenticator requests for user interaction. The **Flow Controller** mediates
authenticator requests for user interaction. The UI Controller and Flow
Controller pass user interaction request and action messages back and forth
until the authenticator releases the credential. Then, the Flow Controller
sends the credential to the Gateway, which relays the credential to the client.

Here is a diagram of the intended usage and interactions between the APIs.

```mermaid
sequenceDiagram
    participant C as Client
    participant G as Gateway
    participant U as UI Controller
    participant F as Flow Controller
    participant A as Authenticator

    C ->> +G: Initiate request
    G ->>  U: Launch UI
    U ->>  F: Subscribe to events
    loop
    F ->> +A: Send control messages
    A ->>  F: Request user interaction
    F ->>  U: Request user interaction
    U ->>  F: Respond with user interaction
    end
    A ->> -F: Release credential
    F ->>  G: Respond with credential
    G ->> -C: Respond with credential
```

# Revision History

## [unreleased]

### Breaking Changes

- (UI Controller): Renamed `InitiateEventStream()` to `Subscribe()`
- (UI Controller): Serialize enums (including BackgroundEvent, HybridState and UsbState) as (uv) structs instead for a{sv} dicts
- (Gateway): Flatten `request` parameters into options.
- (Gateway): Make `origin` and `type` a required method parameter.
- (Gateway): Flatten nested D-Bus struct with `request_json` on CreateCredential and GetCredential
- (Gateway): Remove Client Capabilities method from Gateway API until further notice.

### Improvements

- Document errors returned to gateway requests

## [0.1.0] - 2025-08-14

### Breaking Changes

### Improvements

- Initial release.

# Terminology

- _authenticator_: a device that securely stores and releases credentials
- _client_: a user agent requesting credentials for a relying party, for example, browsers or apps
- _credential_: a value that identifies a user to a relying party
- _gateway_: entrypoint for clients
- _privileged_ client: a client that is trusted to set any origin for its requests
- _relying party_: an entity wishing to authenticate a user
- _unprivileged client_: a client that is constrained to use a predetermined set of origin(s)

# General Notes

## Enum values

Generally, enums are serialized as a tag-value structure with a single-byte tag
and a variant as the value (`(uv)`, in D-Bus terms). The documentation for each
specific enum variant describes how to parse the values.

A single null byte (`\0`) is sent for unused enum values.

## D-Bus/JSON serialization

This API is modelled after the [Credential Management API][credman-api]. The
top-level fields corresponding to `navigator.credentials.create()` and `get()`
are passed as fields in D-Bus dictionaries using snake_case, according to D-Bus
convention.

So where Credential Management takes:

```json
{
  "origin": "example.com",
  "topOrigin": "example.com",
  "password": true
}
```

this API takes:

```
[a{sv}] {
    IN origin s = "https://example.com",
    IN type = "password",
    options a{sv} = {
        top_origin: Variant("https://example.com"), // topOrigin is changed to top_origin
        password: Variant(true),
    }
}
```

However, for the complex requests and responses in the WebAuthn `create()` and `get()`
methods, this API passes JSON-encoded data as a string. Field and enum values
inside the JSON string should remain in camelCase.

Additionally, `ArrayBuffer` objects, which are valid in JavaScript but cannot be
serialized in JSON, must be encoded as base64url strings with padding removed.

So if a client passed this in JavaScript:

```javascript
{
  "origin": "https://example.com",
  "topOrigin": "https://example.com",
  "publicKey": {
    "challenge": new Uint8Array([97, 32, 99, 104, 97, 108, 108, 101, 110, 103, 101]),
    "excludeCredentials": [
        {"type:" "public-key", "alg": -7}
    ],
    // ...
  }
}
```

it would pass this request to this API:

```
CreateCredential(
  // ...
  IN origin s = "https://example.com",
  IN type s = "publicKey",
  IN options a{sv} {
    top_origin: Variant("https://example.com"), // top-level fields topOrigin and publicKey are
                                                // changed to snake_case, JSON-encoded string
    public_key: [s] = "{                        // `public_key` is a JSON-encoded string, snake_case field name
        \"challenge\": \"YSBjaGFsbGVuZ2U\",     // "challenge" buffer is encoded as base64url without padding
        \"excludeCredentials\": [               // "excludeCredentials" is not changed to snake_case within the JSON
        {\"type\": \"public-key\", \"alg\": -7} // "public-key" is not changed to snake_case within the JSON string
        ]
        // ...
    }"
  }
}
```

## Window Identifiers

For window identifiers, we follow the same format as the
[XDG Desktop Portal conventions for window identifiers][xdg-window-identifiers].

Where a `parent_window` is specified, the value should be a string in the format:

`<window_system>:<handle>`

The supported window systems are `wayland` and `x11`.

If the client does not have a window or cannot access it, pass an empty string.

[xdg-window-identifiers]: https://flatpak.github.io/xdg-desktop-portal/docs/window-identifiers.html

# Gateway API

The Gateway is the entrypoint for public clients to retrieve and store
credentials and is modeled after the Web
[Credential Management API][credman-api].

It is responsible for authorizing client requests for specific origins and for
validating request parameters, for example, validating the binding between
origins and relying party IDs for public key credential requests.

[credman-api]: https://w3c.github.io/webappsec-credential-management/

## `CreateCredential(credRequest CreateCredentialRequest) -> CreateCredentialResponse`

`CreateCredential()` is the way that new credentials are created. The
`credRequest` parameter defines the client's context as well as the parameters
for what kind of credential the client would like to create.

### Request

```
CreateCredentialRequest(
    IN parent_window s,
    IN origin s,
    IN type CredentialType,
    IN options a{sv} {
        activation_token: s
        top_origin: s
        <type_specific_fields>
    },
    IN app_id s,
    IN app_display_name s
)
```

For information on `parent_window`, see [Window Identifiers](#window-identifiers).

> TODO: We should make this a tagged enum

```
CredentialType[s] [
    "publicKey"
]
```

#### Request context

> TODO: Define methods for safe comparison of hosts Punycode origins.

`origin` and `options.top_origin` define the request context. `origin` is required. A
request is considered to be a cross-origin request if `options.top_origin` is
specified. For certain credentials, cross-origin requests are not allowed and
will be denied.

At this time, only [web origins][web-origins] with HTTPS schemes are permitted
for the `origin`, for example, `https://example.com`. No Unicode characters or
Punyode are currently permitted.

The origin must be a registrable domain, not a top-level domain nor a public
suffix, as defined by the [Public Suffix List][PSL].

[web-origins]: https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-tuple
[PSL]: https://github.com/publicsuffix/list

#### Credential Request Types

##### WebAuthn Credential Request

Currently, there is only one supported type of `CreateCredentialRequest`,
`CreatePublicKeyCredentialRequest`, identified by `type: "publicKey"` and
corresponds to WebAuthn credentials. It extends the `options` parameter
with a field `public_key`, which is a string of JSON that corresponds to the
WebAuthn
[`PublicKeyCredentialCreationOptions`][def-pubkeycred-creation-options]
type.

    CreatePublicKeyCredentialRequest: CreateCredentialRequest (
        IN parent_window s,
        IN origin s,
        IN type s = "publicKey",
        options a{sv} {
            <other optional fields>,
            public_key: s  // WebAuthn credential attestation JSON
        },
        IN app_id s,
        IN app_display_name s
    )

### Response

> TODO: Should we group common types in their own section for reference?
> CredentialType will be referenced in the request and response of both create
> and get methods.

`CreateCredentialResponse` is a polymorphic type that depends on the type of
the request sent. Its `type` field is a string specifies what kind of
credential it is, and what `<type_specific_fields>` should be expected.

```
CreateCredentialResponse[a{sv}] {
    type: CredentialType
    <type_specific_fields>
}
```

`CredentialType` is defined above.

#### WebAuthn Credential Response

As the only supported request is `CreatePublicKeyCredentialRequest`, the only
type of response is `CreateCredentialResponse` is `CreatePublicKeyResponse`, also
denoted by `type: "publicKey"`:

    CreatePublicKeyResponse {
        type: s = "publicKey"
        registration_response_json: s
    }

`registration_response_json` is a JSON string that corresponds to the WebAuthn
[`PublicKeyCredential`][def-pubkeycred] with the `response` field set as an
[`AuthenticatorAttestationResponse`][def-attestation-response].

[def-pubkeycred]: https://www.w3.org/TR/webauthn-3/#publickeycredential
[def-pubkeycred-creation-options]: https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions
[def-attestation-response]: https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse

### Errors

- `AbortError`: Request cancelled by client.
- `SecurityError`: Security policies are not met, for example, requesting an RP credential whose origin does not match.
- `TypeError`: An invalid request is made.
- `NotAllowedError`: catch-all error.

## `GetCredential(credRequest: GetCredentialRequest) -> GetCredentialResponse`

`GetCredential()` is how credentials are retrieved. The `credRequest` parameter
defines the client's context as well as the parameters for what types of
credentials the client will accept.

### Request

```
GetCredentialRequest (
    IN parent_window s,
    IN origin s,
    IN options a{sv} {
        activation_token: s
        top_origin: s
        <type_specific_fields>
        public_key: s
    },
    IN app_id s,
    IN app_display_name s
)
```

For information on `parent_window`, see [Window Identifiers](#window-identifiers).

Note that while only one credential type can be specified in
`CreateCredential()`, credential types in this `GetCredential()` are not mutually
exclusive: as new credential types are added to the specification, a client may
request multiple different types of credentials at once, and it can expect the
returned credential to be any one of those credential types. Because of that,
there is no `type` field, and credential types are specified using the optional fields.


#### Request Context

The `GetCredential()` `origin` and `options.top_origin` have the same semantics and
restrictions as in `CreateCredential()` described above.

When multiple credential types are specified, the request context applies to
all credentials.

#### Credential Request Types

##### WebAuthn Credential Request

Currently, there is only one supported type of credential, a WebAuthn PublicKeyCredential. A WebAuthn credential can be requested using the `options.public_key` field, which is a string of JSON that corresponds to the WebAuthn
[`PublicKeyCredentialRequestOptions`][def-pubkeycred-request-options].

[def-pubkeycred-request-options]: https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions

### Response

> TODO: Should we group common types in their own section for reference?
> CredentialType will be referenced in the request and response of both create
> and get methods.

`GetCredentialResponse` is a polymorphic type that depends on the type of the
request sent. Its `type` field is a string specifies what kind of credential it
is, and what `<type_specific_fields>` should be expected.

```
GetCredentialResponse[a{sv}] {
    type: CredentialType
    <type_specific_fields>
}
```

`CredentialType` is defined above.


#### WebAuthn Credential Response

As the only supported request is `GetPublicKeyCredentialRequest`, the only
type of response is `GetCredentialResponse` is `GetPublicKeyCredentialResponse`, also
denoted by `type: "publicKey"`:

    GetPublicKeyCredentialRepsonse {
        type: s = "publicKey"
        authentication_response_json: s // WebAuthn credential assertion response JSON
    }

`authentication_response_json` is a JSON string that corresponds to the WebAuthn
[`PublicKeyCredential`][def-pubkeycred] with the `response` field set as an
[`AuthenticatorAssertionResponse`][def-assertion-response].

[def-pubkeycred]: https://www.w3.org/TR/webauthn-3/#publickeycredential
[def-pubkeycred-creation-options]: https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions
[def-assertion-response]: https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse

### Errors

- `AbortError`: Request cancelled by client.
- `SecurityError`: Security policies are not met, for example, requesting an RP credential whose origin does not match.
- `TypeError`: An invalid request is made.
- `NotAllowedError`: catch-all error.

# Flow Control API

The Flow Control API is used by the UI to pass user interactions through the
Flow Controller to the authenticator.

## Subscribe()

> TODO: Is a signal here safe? Do we need to have the client set up an
> endpoint to send a unicast message instead? The QR code in hybrid flow contains
> a shared secret, so it would be good to protect that for defense-in-depth.

> TODO: The signature is confusing here: the _client_ implements a signature
> that results in a BackgroundEvent stream, but in reality, the API itself
> requires multiple steps, and this method doesn't return anything at all.

Informs the server that the UI client is ready to receive events from the flow
controller (UI prompts, cancellation notification, etc.).

Immediately after being launched, the UI client should subscribe to
`StateChanged` signals, then call this method to receive events from the flow
controller .

When beginning to handle a request, the server should buffer requests to send
to the UI until it calls this method.

## StateChanged <- BackgroundEvent

Notification of authenticator state change.

```
BackgroundEvent[(uv)] [
    /// Ceremony completed successfully
    (0x01) CeremonyCompleted
    /// Device needs the client PIN to be entered. The backend should collect the
    /// PIN and send it back with `EnterClientPin` event of `UserInteracted` signal.
    (0x10) NeedsPin: u
    (0x11) NeedsUserVerification: u
    (0x12) NeedsUserPresence
    (0x13) SelectingCredential: aa{sv} u32 = 0x13;

    (0x20) HybridIdle
    (0x21) HybridStarted: s
    (0x22) HybridConnecting
    (0x23) HybridConnected

    (0x30) NfcIdle
    (0x31) NfcWaiting
    (0x32) NfcConnected

    (0x40) UsbIdle
    (0x41) UsbWaiting
    (0x42) UsbSelectingDevice: aa{sv}
    (0x43) UsbConnected

    (0x80000001) ErrorInternal
    (0x80000002) ErrorTimedOut
    (0x80000003) ErrorCancelled
    (0x80000004) ErrorAuthenticator
    (0x80000005) ErrorNoCredentials
    (0x80000006) ErrorCredentialExcluded
    (0x80000007) ErrorPinAttemptsExhausted
    (0x80000008) ErrorPinNotSet
]
```
### BackgroundEvent::CeremonyCompleted

Authenticator has released the credential, and the ceremony is complete.

`tag`: `0x01`

`value`: No associated value.


### BackgroundEvent::NeedsPin

> TODO: Implement cancellation of USB flow

The device needs PIN user verification: prompt the user to enter the pin. Send
the pin to the flow controller using the enter_client_pin() method.


`tag`: `0x10`

`value`: `[i]`, an integer indicating the number of PIN attempts remaining
before the device is locked out. If the value is `0xffffffff`, the number of attempts
left is unknown.

### BackgroundEvent::NeedsUserVerification

The device needs on-device user verification (likely biometrics, or can be
on-device PIN entry). Prompt the user to interact with the device.

`tag`: `0x11`

`value`: `[i]`, am integer indicating the number of user verification
attempts remaining before the user verification is disabled. Once disabled, only the client PIN can be used as a user verification method. If the value is 0xffffffff, the number of attempts left is unknown.

### BackgroundEvent::NeedsUserPresence

The device needs evidence of user presence (e.g. touch) to release the credential.

`tag`: `0x12`

`value`: No associated value.

### BackgroundEvent::SelectingCredential

> TODO: field names of Credential type are confusing: "name" is an ID, and
> "username" is a name. We should flip them.

Multiple credentials have been found and the user has to select which to use

`tag`: `0x13`

`value`: `[aa{sv}]`: A list of `Credential` objects.

```
Credential [a{sv}] {
    id: string. An opaque ID referring to the credential on the device.
    name: string. A human-readable identifier for the account.
    username: string. A human-readable name for the account, intended for display. May be empty.
}
```

To prevent CTAP credential IDs leaking to the UI, servers SHOULD make `id` an
opaque value known only to the implementation, for example, by hashing the
actual CTAP credential ID before sending it to the UI.

### BackgroundEvent::HybridIdle

Default state, not listening for hybrid transport.

`tag`: `0x20`

`value`: No associated value.

### BackgroundEvent::HybridStarted,

QR code flow is starting, awaiting QR code scan and BLE advert from phone.

`tag`: `0x21`

`value`: `[s]`. String to be encoded as a QR code and displayed to the user to scan.

### BackgroundEvent::HybridConnecting,

BLE advertisement received, connecting to caBLE tunnel with shared secret.

`tag`: `0x22`

`value`: No associated value

### BackgroundEvent::HybridConnected,

Connected to device via caBLE tunnel, waiting for user to release the
credential from their remote device.

`tag`: `0x23`

`value`: No associated value

### BackgroundEvent::NfcIdle

Not polling for FIDO NFC device.

`tag`: `0x30`

`value`: No associated value.

### BackgroundEvent::NfcWaiting

Awaiting FIDO NFC device to be detected.

`tag`: `0x31`

`value`: No associated value.

### BackgroundEvent::NfcConnected

NFC device connected, prompt user to tap. The device may require additional
user verification, but that might not be known until after the user taps the
device.

`tag`: `0x32`

`value`: No associated value.

### BackgroundEvent::UsbIdle

Not polling for FIDO USB device.

`tag`: `0x41`

`value`: No associated value.

### BackgroundEvent::UsbWaiting

Awaiting FIDO USB device to be plugged in.

`tag`: `0x42`

`value`: No associated value.

### BackgroundEvent::UsbSelectingDevice

Multiple USB devices have been detected and are blinking, prompt the user to
tap one to select it.

`tag`: `0x43`

`value`: No associated value.

### BackgroundEvent::UsbConnected

USB device connected, prompt user to tap. The device may require additional
user verification, but that might not be known until after the user taps the
device.

`tag`: `0x44`

`value`: No associated value.

### BackgroundEvent::ErrorInternal

Something went wrong with the credential service itself, not the authenticator.

`tag`: `0x80000001`

`value`: No associated value.

### BackgroundEvent::ErrorTimedOut

Request timed out.

`tag`: `0x80000002`

`value`: No associated value.

### BackgroundEvent::ErrorCancelled

User cancelled the request

`tag`: `0x80000003`

`value`: No associated value.

### BackgroundEvent::ErrorAuthenticator

Some unknown error with the authenticator occurred.

`tag`: `0x80000004`

`value`: No associated value.

### BackgroundEvent::NoCredentials

No matching credentials were found on the device.

`tag`: `0x80000005`

`value`: No associated value.

### BackgroundEvent::CredentialExcluded,

A credential matching the credential request already exists on the authenticator.

`tag`: `0x80000006`

`value`: No associated value.

### BackgroundEvent::PinAttemptsExhausted,

Too many incorrect PIN attempts, and authenticator must be removed and
reinserted to continue any more PIN attempts.

Note that this is different than exhausting the PIN count that fully
locks out the device.

`tag`: `0x80000007`

`value`: No associated value.

## GetAvailablePublicKeyDevices() -> CredentialMetadata[]

> TODO: Should we add displayName and username as optional fields for
> individual credential "devices"

> TODO: I don't like the term "devices" here, since many of these are not what
> you would normally think as devices. Maybe "sources" works better?

> TODO: CredentialMetadata is a bad name here, since this more corresponds to
> the "devices" or "sources" concept. Change to DeviceMetadata?

This retrieves the various "devices" that the user can choose from to fulfill
the request, filtered by the request origin and other request options.

The word "devices" is used broadly and can refer to individual authenticators
(like a locked passkey provider or linked hybrid device), a group of
authenticators on a transport (USB or hybrid QR code devices), or even an
individual credential (in the case of credentials supplied by unlocked passkey
providers).

    CredentialMetadata[a{sv}] {
        id: string,
        transport: Transport
    }

    Transport[s] [
        "ble",
        "hybrid_linked",
        "hybrid_qr",
        "internal",
        "nfc",
        "usb",
    ]

## GetHybridCredential()

Initializes a FIDO hybrid authenticator flow.

### Request

The UI client should subscribe to the `StateChanged` and call `Subscribe()` before calling this method.

### Response

None. Events are sent to `StateChanged` signal.

### Errors

TBD.

## GetUsbCredential()

Initializes a FIDO USB authenticator flow.

### Request

The UI client should subscribe to the `StateChanged` and call `Subscribe()` before calling this method.

### Response

None. Events are sent to `StateChanged` signal.

### Errors

TBD.

## EnterClientPin(pin: [s])

A method to send a client PIN to an authenticator in response to a `UsbState::NEEDS_PIN` event.

### Request

`pin`: Client PIN for the authenticator.

This should be sent in response to a `UsbState::NEEDS_PIN` event. If this
method is sent when the authenticator is not in a state to receive a client
PIN, this PIN will be discarded silently without sending it to the
authenticator.

### Response

None. Response will be sent via a `UsbStateChanged` event in `StateChanged`
signal.

For example, a `UsbState::NEEDS_USER_PRESENCE` will be sent if the PIN was
accepted by the authenticator, or another `UsbState::NEEDS_PIN` event will be
sent if it was incorrect. (Other events may be also sent.)

### Errors

TBD.

## SelectCredential(credential_id: [s])

When multiple credentials are found on a single authenticator, this method
selects which credential to release based on the authenticator.

### Request

`credential_id`: `[s]`. An opaque value referring to the credential chosen by the user.

### Response

None.

### Errors

TBD.

## CancelRequest(request_id: [u])

### Request

`request_id`: `[u]`. A request to cancel the given request ID.

### Response

None.

### Errors

None. If `request_id` is no longer active, the request will be silently
discarded.

# UI Control API

## LaunchUi(request: ViewRequest)

Send request context needed to display a UI to the user for interacting with
authenticators.

This method should be called when a new credential request begins.

### Request

`request`: `ViewRequest`. Request context needed for displaying the UI to the user.

```
ViewRequest: [a{sv}] {
    id: u,
    operation: Operation,
    rp_id: s,
    requesting_app: RequestingApplication,
    window_handle: s, // Optional
}
```

```
Operation[s] [
    "CREATE",
    "GET",
]
```

```
RequestingApplication {
    name: s, // Optional
    path_or_app_id: s,
    pid: u32,

}
```

### Response

None.

### Errors

TBD.

# Related Works

## Secret Service API

The Secret Service API is allows client applications to store secrets securely
in a service running in the user's login session. Secret data may be stored in
any format that the client application wishes. This makes secrets very flexible,
and applications can use them in many protocols like authentication (passwords,
JWT) or encryption (secure file or messages).

Credentials can be thought of as a subset of secrets that are constrained to a
particular format and protocol in order for users to authenticate to relying
parties interoperably. This way, relying parties do not need to create bespoke
authentication methods, and the user's device can offer a consistent user
interface.

So the Credentials API differs from the Secret Service API in two main ways:

- It supports specific credential formats (e.g. WebAuthn/FIDO2 credentials),
  rather than general secrets.
- It is primarily focused on authenticating to relying parties.
- It encourages interactive authentication and user intent, where Secret Service
  enables silent secret usage.
- It supports communicating with authenticators over several transports, not
  just secure storage.

So the two APIs are independently useful, but can work well together: for
example, an authenticator can be built using the Secret Service API.

## WebAuthn/Web Credential Management API

The Credential API mimics the Web Credential Management API which is used by
WebAuthn. It is the intent for the Credential API to support multiple types of
credentials, like passwords, TOTP, and digital credentials, but at this time
the specification only supports public key/WebAuthn credentials. in tur

The implementation of WebAuthn credentials is heavily inspired by the WebAuthn
API for Android.
