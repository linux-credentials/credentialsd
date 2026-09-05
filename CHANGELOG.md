# [unreleased]

# 0.3.1 [2026-09-05]

## Improvements

- daemon: Fix failure to activate UI service automatically.
- daemon: Decrease USB logging level.
- ui: Remove process ID from credential prompt.

# 0.3.0 [2026-08-27]

This release is a big milestone toward our goal of providing a Credential
portal. To that end, we have changed the structure of credentialsd to fit the
patterns from credentialsd portal. We also now have a dependency on
xdg-desktop-portal to use credentialsd.
[linux-credentials/xdg-desktop-portal][xdp-fork] contains the patches needed to
run xdg-desktop-portal while we work on upstreaming the changes.

[xdp-fork]: https://github.com/linux-credentials/xdg-desktop-portal

## Breaking Changes

- daemon: Removed FlowControl service in favor of portal handler.
- daemon: Added a dependency on a patched xdg-desktop-portal to run credentialsd.
- daemon: Send CTAP2 hybrid QR code data to UI over a file descriptor.
- daemon: Require `origin` parameter to be set on `CreateCredential` and `GetCredential`.
- daemon: Flatten request inputs to remove `request_json` field, making construction more straightforward.
- ui: Reordered parameters in `RequestingApplication`, and made app name optional.
- ui: Send client PIN to daemon over a file descriptor.
- ui: Move discovery from UI service to daemon.
- ui: Lookup app display name from UI instead of daemon.

## Improvements

- ci: Move build directory to take better advantage of caching. (Thank you, @norepro!)
- daemon: Added a handler service to handle Credential portal requests on behalf of xdg-desktop-portal.
- daemon: Accept top_origin as an optional parameter to CreateCredential and GetCredential.
- daemon: Expand list of trusted callers to paths where distros commonly place xdg-desktop-portal.
- daemon: Remove busy loop on USB polling taking up a bunch of CPU.
- daemon: Validate related origins requests.
- daemon: Add support for CTAP2 hybrid over BLE behind a feature flag.
- daemon: Deduplicate USB state events emitted over D-Bus.
- daemon: Don't use hybrid when not available
- daemon: Cancel other transports, if one succeeded/failed
- daemon: Return InvalidStateError to caller when credential is excluded.
- ui: Add Georgian translations. (Thank you, @EkaterinePopova!)
- ui: Add a portal backend API to credentialsd-ui.
- ui: Allow setting client PIN during the flow when required.
- ui: Send initial list of devices on UI initialization.
- ui: Reorganize credential selection screen to promote hybrid QR code.
- ui: Convert UI templates to Blueprint.
- webext: Ignore conditional mediation requests.
- webext: Fix request routing issues when multiple tabs are active.
- webext: Only start extension during WebAuthn calls for performance.
- webext: Propagate gateway errors to JavaScript correctly.
- webext: Load Firefox extension on all sites

# [0.2.0] - 2025-02-18

## Breaking Changes

### Gateway API

- Added window handle parameter.

### UI Controller API

- Renamed `InitiateEventStream()` to `Subscribe()`.
- Serialized `BackgroundEvent`, `HybridState`, `UsbState` as tag-value structs.
- Added window handle parameter.

## Improvements

- Added NFC support.
- Added PRF support.
- Added translation support, with English and German translations.
- Added client information the initial UI prompt.
- Fixed user handle deserialization.
- Added a GUI for demo client.
- Notify user when a UV method is not set when required.

# [0.1.0] - 2025-08-14

## Breaking Changes

None.

## Improvements

- Initial release! 🎉 Includes support for USB and hybrid QR code credentials.
