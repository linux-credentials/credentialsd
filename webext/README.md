This is a web extension that allows browsers to connect to the D-Bus service
provided by this project. It can be used for testing.

Currently, this is written only for Firefox; there will be some slight API tweaks required to make this work in Chrome.

This requires some setup to make it work:

# Prerequisites

Currently, this web extension relies on the `dbus-next` to interact with D-Bus
services. If you have that package installed in your system Python, this
should work. You can test using the following:

```shell
python3 -c 'import dbus_next; print("dbus-next is installed")'
```

If that completes without error, then you're good to go. Otherwise, you have a
couple of options:

- Install the system package for your operating system, for example:
  ```shell
  # Fedora
  dnf install python3-dbus-next
  # Debian/Ubuntu
  apt install python3-dbus-next
  # Arch
  pacman -S python-dbus-next
  ```
- Modify the shebang to point to a Python instance that does have the package installed.
  ```shell
  cd webext/
  python3 -m venv env
  source ./env/bin/activate
  pip3 install dbus-next
  echo "Change the first line in webext/app/credential_manager_shim.py to:"
  echo "#!$(readlink -f ./env/bin/python3)"
  # Update the shebang to point to the absolute path to webext/env/bin/python3
  ```

# Setup Instructions

(Note: Paths are relative to root of this repository)

1. Copy `webext/app/credential_manager_shim.json` to `~/.mozilla/native-messaging-hosts/credential_manager_shim.json`.
2. In the copied file, replace the `path` key with the absolute path to `webext/app/credential_manager_shim.py`
3. Open Firefox and go to `about:debugging`
4. Click "This Firefox" > Load Temporary Extension. Select `webext/add-on/manifest.json`
5. Build with `ninja -C ./build` and run the following binaries binary to start the D-Bus services.
   - `GSCHEMA_SCHEMA_DIR=build/credentialsd-ui/data ./build/credentialsd-ui/target/debug/credentialsd-ui`
   - `./build/credentialsd/target/debug/credentialsd`
6. Navigate to [https://webauthn.io]().
7. Run through the registration and creation process.
