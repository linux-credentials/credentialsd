This is a web extension that allows browsers to connect to the D-Bus service
provided by this project. It can be used for testing.

Currently, this is written only for Firefox; there will be some slight API tweaks required to make this work in Chrome.

This requires some setup to make it work:

## Setup Instructions

1. Copy `app/credential_manager_shim.json` to  
   `~/.mozilla/native-messaging-hosts/credential_manager_shim.json`.
2. In the copied file, replace the `path` key with the absolute path to  
   `app/credential_manager_shim.py`.
3. **Important:**  
   If your global Python environment (`#!/usr/bin/env python3`) does **not** have the  
   `dbus_next` package installed, update the shebang at the top of  
   `webext/app/credential_manager_shim.py` to point to a Python binary that does.  
   For example:
   ```python
   #!/path/to/python3_with_dbus_next
   ```
   Replace `/path/to/python3_with_dbus_next` with the absolute path to your Python interpreter  
   where `dbus_next` is installed.
4. Open Firefox and go to `about:debugging`.
5. Click "This Firefox" > "Load Temporary Extension". Select `add-on/manifest.json`.
6. Build and run the `xyz-iinuwa-credential-manager-portal-gtk` binary to start the D-Bus service.
7. Navigate to [https://webauthn.io](https://webauthn.io).
8. Run through the registration and creation process.

---

**Note:**  
If you need to install `dbus_next` in a specific Python environment, you can do so with:
```sh
/path/to/python3_with_dbus_next -m pip install dbus_next
```
