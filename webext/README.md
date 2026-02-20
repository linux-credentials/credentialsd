This is a web extension that allows browsers to connect to the D-Bus service
provided by this project. It can be used for testing.

Two variants are provided:
- `add-on/` - Firefox (MV3, requires Firefox 140+)
- `add-on-edge/` - Edge/Chromium (MV3, requires Chrome 111+ or Edge 111+)

This requires some setup to make it work:

# Prerequisites

Currently, this web extension relies on the `dbus-next` Python package to
interact with D-Bus services. If you have that package installed in your system
Python, this should work. You can test using the following:

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
  ```

# Setup Instructions

## For Testing

1. Follow the instructions in the ["For Installing/Testing" section of `BUILDING.md`](/BUILDING.md#for-installing-testing).
2. Open Firefox and go to `about:debugging`.
3. Click "This Firefox" > Load Temporary Extension. Select `/usr/local/share/credentialsd/credentialsd-firefox-helper.xpi`.
4. Navigate to [https://webauthn.io]().
5. Run through the registration and creation process.

## For Development (Firefox)

(Note: Paths are relative to root of this repository)

1. Copy `webext/app/credential_manager_shim.json` to `~/.mozilla/native-messaging-hosts/xyz.iinuwa.credentialsd_helper.json`.
2. In `webext/app/credential_manager_shim.py`, point the `DBUS_DOC_FILE`
   variable to the absolute path to
   `doc/xyz.iinuwa.credentialsd.Credentials.xml`.
3. In the copied file, replace the `path` key with the absolute path to `webext/app/credential_manager_shim.py`
4. Open Firefox and go to `about:debugging`
5. Click "This Firefox" > Load Temporary Extension. Select `webext/add-on/manifest.json`
6. Build with `ninja -C ./build` and run the following binaries binary to start the D-Bus services.
   - `GSCHEMA_SCHEMA_DIR=build/credentialsd-ui/data ./build/credentialsd-ui/target/debug/credentialsd-ui`
   - `./build/credentialsd/target/debug/credentialsd`
7. Navigate to [https://webauthn.io]().
8. Run through the registration and creation process.

## For Development (Edge/Chromium)

(Note: Paths are relative to root of this repository)

1. In `webext/app/credential_manager_shim.py`, point the `DBUS_DOC_FILE`
   variable to the absolute path to
   `doc/xyz.iinuwa.credentialsd.Credentials.xml`.
2. Open Edge and go to `edge://extensions` (or `chrome://extensions` for Chrome).
3. Enable "Developer mode" (toggle in top right).
4. Click "Load unpacked" and select the `webext/add-on-edge/` directory.
5. Note the extension ID shown on the extensions page (e.g., `abcdefghijklmnop...`).
6. Create the native messaging manifest:
   ```shell
   # For Edge:
   mkdir -p ~/.config/microsoft-edge/NativeMessagingHosts
   # For Chrome:
   # mkdir -p ~/.config/google-chrome/NativeMessagingHosts
   # For Chromium:
   # mkdir -p ~/.config/chromium/NativeMessagingHosts

   cat > ~/.config/microsoft-edge/NativeMessagingHosts/xyz.iinuwa.credentialsd_helper.json << EOF
   {
     "name": "xyz.iinuwa.credentialsd_helper",
     "description": "Helper for integrating browser with credentialsd project",
     "path": "$(readlink -f webext/app/credential_manager_shim.py)",
     "type": "stdio",
     "allowed_origins": [ "chrome-extension://YOUR_EXTENSION_ID/" ]
   }
   EOF
   ```
   Replace `YOUR_EXTENSION_ID` with the extension ID from step 5.
7. Build with `ninja -C ./build` and run the D-Bus services:
   - `GSCHEMA_SCHEMA_DIR=build/credentialsd-ui/data ./build/credentialsd-ui/target/debug/credentialsd-ui`
   - `./build/credentialsd/target/debug/credentialsd`
8. Navigate to [https://webauthn.io]().
9. Run through the registration and creation process.
