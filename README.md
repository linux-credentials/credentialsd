# credentialsd

A Linux Credential Manager API.

(Previously called `linux-webauthn-platform-api`.)

## Goals

The primary goal of this project is to provide a spec and reference
implementation of an API to mediate access to web credentials, initially local
and remote FIDO2 authenticators. See [GOALS.md](/GOALS.md) for more information.

## How to install

### From packages

We have [precompiled RPM packages for Fedora and openSUSE][obs-packages] hosted
by the Open Build Service (OBS). We also copy these for released versions to the
[release page][release-page].

There are several sub-packages:

- `credentialsd`: The core credential service
- `credentialsd-ui`: The reference implementation of the UI component for
  credentialsd.
- `credentialsd-webextension`: Binaries and manifest files required for the
  Firefox add-on to function

[obs-packages]: https://build.opensuse.org/package/show/home:MSirringhaus:webauthn_devel/credentialsd
[release-page]: https://github.com/linux-credentials/credentialsd/releases

### From source

Alternatively, you can build the project yourself using the instructions in
[BUILDING.md](/BUILDING.md).

## How to use

Right now, there are two ways to use this service.

### Experimental Firefox Add-On

There is an add-on that you can install in Firefox 140+ that allows you to test
`credentialsd` without a custom Firefox build. You can get the XPI from the
[releases page][release-page] for the corresponding version of
`credentialsd-webextension` package that you installed.

Currently, this add-on only works for https://webauthn.io and
https://demo.yubico.com, but can be used to test various WebAuthn options and
hardware.

### Experimental Firefox Build

There is also an experimental Firefox build that contains a patch to interact
with `credentialsd` directly without an add-on. You can access a
[Flatpak package for it on OBS][firefox-patch-flatpak] as well.

[firefox-patch-flatpak]: https://download.opensuse.org/repositories/home:/MSirringhaus:/webauthn_devel/openSUSE_Factory_flatpak/

## Clients

There is a demo client in the `demo_client`. It mimics an RP, saving the created public keys to a local file and verifying assertions against it.

```shell
cd demo_client/
./main.py create
./main.py get
```

There is also a demo web extension that can be used to test the service in Firefox. Instructions are in [/webext/README.md]().

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

See the [LICENSE.md](/LICENSE.md) file for license rights and limitations (LGPL-3.0-only).
