🚧 Excuse the mess, work in progress! 🚧

# Linux Credential Manager API

## How to run

### Build Requirements

This project uses Meson and Ninja.

Package requirements:

- GTK4
- gettext
- libdbus-1
- libssl/openssl
- libudev
- desktop-file-utils

For example, on Ubuntu:

```shell
sudo apt update && sudo apt install \
  # Build dependencies
  curl git build-essential \
  # Meson/Ninja dependencies
  python3 python3-pip python3-setuptools python3-wheel ninja-build \
  # project dependencies
  libgtk-4-dev gettext libdbus-1-dev libssl-dev libudev-dev \
  # packaging dependencies
  desktop-file-utils \
```

### Compiling

```shell
git clone https://github.com/linux-credentials/linux-webauthn-platform-api
cd linux-webauthn-platform-api
meson setup build -Dprofile=development
ninja -C build
```

### Running the server

```shell
# Run the server, with debug logging enabled
export GSETTINGS_SCHEMA_DIR=build/creds-ui/data
export RUST_LOG=credsd=debug,creds_ui=debug
./build/credsd/target/debug/credsd &
./build/creds-ui/target/debug/creds-ui
```

### Clients

There is a demo client in the `demo_client`. It mimics an RP, saving the created public keys to a local file and verifying assertions against it.

```shell
cd demo_client/
./main.py create
./main.py get
```

There is also a demo web extension that can be used to test the service in Firefox. Instructions are in [webext/README.md]().

## Goals

The goal of this repository is to define a spec for clients (apps, browsers,
etc.) to retrieve user credentials in a uniform way across Linux desktop
environments.

Some high-level goals:

- define an API to securely create and retrieve local credentials
  (passwords, passkeys, security keys)
- create and retrieve credentials on remote devices (e.g. via CTAP 2 BLE/hybrid
  transports)
- Provide a uniform interface for third-party credential providers
  (password/passkey managers like GNOME Secrets, Bitwarden, Keepass, LastPass,
  etc.) to hook into

Some nice-to-haves:

- Design a specification for a platform authenticator. I'm not sure whether this
  needs to be specified, or whether it could be considered and implemented as a
  first-party credential provider.

Some non-goals:

- Fully integrate with any specific desktop environment. Each desktop
  environment (GNOME, KDE, etc.) has its own UI and UX conventions, as well as
  system configuration methods (e.g., GNOME Settings), which this API will need to integrate with.
  Because of the variation, we intend to leave integration with these other
  components to developers more familiar with each of the desktop environments.
  For now, we are using bare GTK to build a UI for testing, but any UI
  implementation in this repository is for reference purposes. If anyone is willing to do some of this integration work, feel free to contact us!

- Create a full-featured password manager. Features like Password syncing,
  password generation, rotation, etc. is not part of this specficiation. Other
  password manager projects should be able to use this to make their credentials
  available to the user uniformly, though.

- BSD support. While we'd love to help out all open desktop environments, we don't
  know enough about any BSD to make it useful for them. Hopefully, the design
  process is transparent enough that someone else could design something that
  works for BSDs.

## Current Work

- April 2025: Added web extension for testing in Firefox.
- March 2025: Integrated libwebauthn to support USB authenticators.
- May 2024: Met with developers in GNOME and systemd to design internals for
  securely storing device credentials.
- Jan 2024: Defined the [scenarios](doc/scenarios.md) that we expect this
  API to cover. We are working on extracting [API methods](doc/api.md) required to
  implement the interactions between the client, portal frontend, portal backend,
  machine and mobile devices. Once that is done, I intend to convert the API into
  a [portal spec](doc/design-doc.md), making it fit normal D-Bus/portal patterns.

## Mockups

Here are some mockups of what this would look like for a user:

### Internal platform authenticator flow (device PIN)

![](images/register-start.png)
![](images/internal-pin-2.png)
![](images/end.png)

Alternatively, lock out the credential based on incorrect attempts.

![](images/internal-pin-3.png)
![](images/internal-pin-4.png)

### Hybrid credential flow

![](images/register-start.png)
![](images/qr-flow-2.png)
![](images/qr-flow-3.png)
![](images/end.png)

### Security key flow

![](images/register-start.png)
![](images/security-key-2.png)
![](images/security-key-3.png)
![](images/end.png)

## Related projects:

- https://github.com/linux-credentials/libwebauthn (previously https://github.com/AlfioEmanueleFresta/xdg-credentials-portal)
- authenticator-rs
- webauthn-rs
