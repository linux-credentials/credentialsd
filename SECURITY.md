# credentialsd Security Policy

This policy outlines our intentions for addressing security issues and practices
for security researchers investigating this project.

## Submitting Vulnerability Reports

Since this project handles very sensitive data, we take security seriously. If
you have discovered a security vulnerability in this project, please report it
to us privately via the process below.

We use GitHub for private vulnerability disclosure. To report a vulnerability:

1. Go to [Security > Advisories > New draft security advisory][new-advisory].
2. Fill out the report and submit the draft.
3. The maintainers will be privately notified about the advisory and get back to
   you.

[new-advisory]: https://github.com/linux-credentials/credentialsd/security/advisories/new

## Expected Response

We will acknowledge the receipt of the report immediately and will work with
you. We seek to investigate issues within 30 days.

If the issue is confirmed upon investigation, we will collaborate with you to
remediate the vulnerability. Depending on the severity or developer
availability, we may request more time to remediate the issue before allowing
public disclosure.

# Supported Releases

We only support the latest published release. We may backport patches when
possible to help users running on distributions that package older versions of
our software.

## Threat Model

We do not currently have a formally defined threat model; we will continue to
document it over time. However, the basic security guarantees we would like to
achieve are defined below.

Please note, that if you believe you have discovered a security problem outside
of this scope, we still want to know about it! We would still like to discuss
the issue privately, but we may not decide to address it within the response
time described above.

### Definitons

- _privileged client_: A client that is allowed to make requests for credentials
  for any origin.
- _unprivileged client_: A client that is allowed to make requests for
  credentials for only a preconfigured set of origins.

### Scope

- Privileged clients may request credentials via this service[^1] for any origin.
- The list of privileged clients cannot change without:
  - `root` privileges, or
  - user consent[^2]
- The list of unprivileged clients cannot change without:
  - `root` privileges, or
  - user consent[^2]

[^1]:
    Various systems may allow users to interact with authenticators directly
    (e.g. allowing unrestricted permission to USB devices or Bluetooth service
    data), so those are out of scope.

[^2]:
    In the future we may offer stricter configuration where privileged clients
    must include permission metadata be signed by a trusted party.
