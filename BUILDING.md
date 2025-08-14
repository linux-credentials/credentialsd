# Prerequisites

## Build system

This project uses Meson, Ninja, and Cargo.

We use Meson 1.5.0+. If your package manager has an older version, you can
install a new version [using the pip module][meson-pip-install].

There is currently no documented minimum support Rust version (MSRV), but 1.85+
should work.

[meson-pip-install]: https://mesonbuild.com/Quick-guide.html#installation-using-python

## Package requirements

- GTK4
- gettext
- libdbus-1
- libssl/openssl
- libudev
- desktop-file-utils

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
  libgtk-4-dev gettext libdbus-1-dev libssl-dev libudev-dev \
  # packaging dependencies
  desktop-file-utils \
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
  gtk4-devel gettext dbus-devel openssl-devel systemd-udev \
  # packaging dependencies
  desktop-file-utils \
  # web extension dependencies
  python3-dbus-next
```

# For Installing/Testing

If you are interested in installing the program, you can use `meson install` to
install the details. (If you would like to test without installing, you can
follow the [build instructions for development](#for-development) below.)

```shell
git clone https://github.com/linux-credentials/credentialsd
cd credentialsd
meson setup -Dprefix=/usr/local build-release
cd build-release
meson install
```

Note that since Meson is installing to `/usr/local`, it will ask you to use
`sudo` to elevate privileges to install.

## Running the installed server

When using the installed server, systemd or D-Bus should take care of starting
the services on demand, so you don't need to start it manually.

The first time you install this, though, you must log out and log back in again
for the service activation files to take effect.

## Testing installed builds with Firefox Web Add-On

Note: If you are testing the Firefox web extension, you will need to link the
native messaging manifest to your home directory, since Firefox does not read
from `/usr/local`:

```shell
mkdir -p ~/.mozilla/native-messaging-hosts/
ln -s /usr/local/lib64/mozilla/native-messaging-hosts/xyz.iinuwa.credentialsd_helper.json ~/.mozilla/native-messaging-hosts/
```

# For Development

```
git clone https://github.com/linux-credentials/credentialsd
cd credentialsd
meson setup -Dprofile=development build
ninja -C build
```

## Running the server for development

To run the required services during development, you need to add some
environment variables.

```shell
# Run the server, with debug logging enabled
export GSETTINGS_SCHEMA_DIR=build/credentialsd-ui/data
export RUST_LOG=credentialsd=debug,credentials_ui=debug
./build/credentialsd/target/debug/credentialsd &
./build/credentialsd-ui/target/debug/credentialsd-ui
```

## Testing development builds with Firefox Web Add-On

If you are using the Firefox add-on to build, follow the instructions for
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
