# Prerequisites

## Build system

This project uses Meson, Ninja, and Cargo.

We use Meson 1.5.0+. If your package manager has an older version, you can
install a new version [using the pip module][meson-pip-install].

There is currently no documented minimum support Rust version (MSRV), but 1.85+
should work.

[meson-pip-install]: https://mesonbuild.com/Quick-guide.html#installation-using-python

## Package requirements

To build, you need the following utility packages and development library packages.

- GTK4
- gettext
- libdbus-1
- libnfc
- libpcsclite
- libssl/openssl
- libudev

Using the web extension also requires `python3-dbus-next`.

## Examples

### Debian/Ubuntu

```shell
sudo apt update && sudo apt install \
  # Build dependencies
  curl git build-essential \
  # Meson/Ninja dependencies
  meson ninja-build \
  # project dependencies
  libgtk-4-dev gettext libdbus-1-dev libnfc-dev libpcsclite-dev libssl-dev libudev-dev \
  # web extension dependencies
  python3-dbus-next
```

### Fedora

```shell
# Build dependencies
sudo dnf groupinstall "Development Tools"
sudo dnf install \
  curl git \
  # Meson/Ninja dependencies
  meson ninja-build \
  # project dependencies
  gtk4-devel gettext dbus-devel libnfc-devel pcsc-lite-devel openssl-devel systemd-udev \
  # web extension dependencies
  python3-dbus-next
```

# For Installing/Testing

If you are interested in installing the program, you can use `meson install` to
install the details. (If you would like to test without installing, you can
follow the [build instructions for development](#for-development) below.)

## Installing credentialsd and credentialsd-ui
To install the daemon and UI binaries, do the following:

```shell
git clone https://github.com/linux-credentials/credentialsd
cd credentialsd
meson setup -Dprefix=/usr/local build-release
meson install -C build-release
```

Note that since Meson is installing to `/usr/local`, it will ask you to use
`sudo` to elevate privileges to install.

## Installing patched xdg-desktop-portal

credentialsd depends on integration with xdg-desktop-portal. Until this is
upstreamed, you must build the patch from our fork. Setting a prefix of
`/usr/local` should allow xdg-desktop-portal to find the portal configuration
files from credentialsd installed in the previous step.

Note that recent xdg-desktop-portal builds require very recent versions of some
dependencies, which may be difficult on some distros. For example, on Fedora,
you must be on Fedora 44 or greater. Other distributions may require you to
build the dependencies manually.

See the [official xdg-desktop-portal docs] for more information on building
xdg-desktop-portal.

```shell
git clone https://github.com/linux-credentials/xdg-desktop-portal
cd xdg-desktop-portal
meson setup --prefix /usr/local . _build
meson install -C _build
```

After installing, you should enable the feature flag to enable the Credential
portal. Use `systemctl --user edit xdg-desktop-portal.service` and add the
following contents:

```
[Service]
Environment="XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=credential"
Environment="G_MESSAGES_DEBUG=xdg-desktop-portal"
```

## Running the installed server

When using the installed server, systemd or D-Bus should take care of starting
the services on demand, so you don't need to start it manually.

The first time you install this, though, you must log out and log back in again
for the service activation files to take effect.

You can follow the logs with:

```shell
journalctl --user \
  --pager-end \
  --follow \
  --unit xdg-desktop-portal.service \
  --unit xyz.iinuwa.credentialsd.Credentials.service \
  --unit xyz.iinuwa.credentialsd.UiControl.service
```

## Testing installed builds with Firefox Web Add-On

Note: If you are testing the Firefox web extension, you will need to link the
native messaging manifest to your home directory, since Firefox does not read
from `/usr/local`:

```shell
mkdir -p ~/.mozilla/native-messaging-hosts/
ln -s /usr/local/lib64/mozilla/native-messaging-hosts/xyz.iinuwa.credentialsd_helper.json ~/.mozilla/native-messaging-hosts/
```

# For Development

## Building credentialsd and credentialsd-ui
```
git clone https://github.com/linux-credentials/credentialsd
cd credentialsd
meson setup -Dprofile=development build
ninja -C build
```

## Building patched xdg-desktop-portal

For more context on the patch, see the [instructions above](#installing-credentialsd-and-credentialsd-ui).

```shell
git clone https://github.com/linux-credentials/xdg-desktop-portal
cd xdg-desktop-portal
meson setup . _build
meson compile -C _build
```

## Running the server for development

To run the required services during development, you need to add some
environment variables.

```shell
# These paths must be absolute
XDP_REPO=/path/to/xdg-desktop-portal
CREDSD_REPO=/path/to/credentialsd

export XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=credential
XDP_BINARY="$XDP_REPO/build/desktop-portal/xdg-desktop-portal"
$XDP_BINARY &

# Run the server, with debug logging enabled, and configure the server to trust your xdg-desktop-portal
export CREDSD_TRUSTED_CALLERS=$XDP_BINARY
export RUST_LOG=credentialsd=debug,libwebauthn=debug
$CREDSD_REPO/build/credentialsd/src/credentialsd &

# Run the backend UI
export RUST_LOG=debug
export GSETTINGS_SCHEMA_DIR=$CREDS_REPO/build/credentialsd-ui/data
$CREDSD_REPO/build/credentialsd-ui/src/credentialsd-ui
```

## Testing development builds with Firefox Web Add-On

If you are using the Firefox add-on to test during development, follow the instructions for
development in [`webext/README.md`](/webext/README.md#for-development).

# For Packaging

There are a few Meson options to control the build that may be useful for packagers.

```
# list available options

> meson configure
# ...
Project options    Default Value        Possible Values      Description
-----------------  -------------        ---------------      -----------
cargo_home                                                   The directory to
                                                             store files
                                                             downloaded by
                                                             Cargo
cargo_offline      false                [true, false]        Whether to
                                                             perform an
                                                             offline build
                                                             with Cargo.
                                                             Defaults to false
                                                             to download
                                                             crates from
                                                             registries.
profile            default              [default,            The build profile
                                         development]        for Credential
                                                             Manager. One of
                                                             "default" or
                                                             "development".
```

> TODO: rename `default` profile to `release` to reduce confusion.

# Running Tests

Due to some unknown reason, tests hang unless you pass the `--interactive` flag to Meson, available since 1.5.0.

```
cd build
meson test --interactive
```
