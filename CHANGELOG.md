# [unreleased]

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
