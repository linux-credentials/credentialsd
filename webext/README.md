This is a web extension that allows browsers to connect to the D-Bus service
provided by this project. It can be used for testing.

Currently, this is written only for Firefox; there will be some slight API tweaks required to make this work in Chrome.

This requires some setup to make it work:

1. Copy `app/credential_manager_shim.json` to `~/.mozilla/native-messaging/credential_manager_shim.json`.
2. In the copied file, replace the `path` key with the absolute path to `app/credential_manager_shim.py`
3. Open Firefox and go to `about:debugging`
4. Click "This Firefox" > Load Temporary Extension. Select `add-on/manifest.json`
6. Build and run the `xyz-iinuwa-credential-manager-portal-gtk` binary to start the D-Bus service.
5. Navigate to [https://webauthn.io]().
6. Run through the registration and creation process.