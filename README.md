# credentialsd

A Linux Credential Manager API.

(Previously called `linux-webauthn-platform-api`.)

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

Using the web extension also requires `python3-dbus-next`.

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
git clone https://github.com/linux-credentials/credentialsd
cd credentialsd
meson setup build -Dprofile=development
ninja -C build
```

### Running the server

```shell
# Run the server, with debug logging enabled
export GSETTINGS_SCHEMA_DIR=build/credentialsd-ui/data
export RUST_LOG=credentialsd=debug,credentials_ui=debug
./build/credentialsd/target/debug/credentialsd &
./build/credentialsd-ui/target/debug/credentialsd-ui
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

The primary goal of this project is to provide a spec and reference
implementation of an API to mediate access to web credentials, initially local
and remote FIDO2 authenticators. See [GOALS.md](/GOALS.md) for more information.

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

# License

See the [LICENSE.md](LICENSE.md) file for license rights and limitations (LGPL-3.0-only).
