Welcome! Thanks for looking into contributing to our project!

# Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [Looking for Help?](#looking-for-help)
  - [Documentation](#documentation)
- [Reporting Issues](#reporting-issues)
- [Submitting Code](#submitting-code)
  - [Building](#building)
  - [Coding Style](#coding-style)
  - [Submitting PRs](#submitting-prs)
  - [Where do I start?](#where-do-i-start)
- [Testing](#testing)

# Ways to Contribute

This document below primarily focuses on writing code for this
project, but there are many different ways you can help out:

- **Testing**: We only have access to a limited set of hardware and accounts.
  Installing the project and using it yourself is a great way to get us more
  feedback to improve the project.

- **Writing UI implementations**: The UI included in this document is for reference
  purposes. We need developers who are familiar with (or willing to learn about)
  the specifics of integrating with particular desktop environments, like GNOME,
  KDE, etc.

- **Writing documentation**: Documentation is always hard. If you notice
  something missing or incorrect, then feel free to ask a question about it or
  send a pull request to address it.

- **Sponsorship**: We haven't set up any sort of platform to receive monetary
  donations, but if you are interested, you can reach out by filing an issue,
  and we can see what we can do. Individual sponsorships are not the only way to
  support the project: getting us in touch with companies or foundations
  offering grants for open source or hardware for testing is also helpful.

- **Spread the word**: We believe that this project is important to get in the hands
  of users. Whether you can help or not, telling others about the project and
  asking them to get involved is another way you can help!

And then there is, of course, writing code!

# Looking for Help?

Here is a list of helpful resources you can consult:

## Documentation

To help you get started, we have provided documentation for various parts of the
project. Take a look at these:

- [credentialsd API Specification](/doc/api.md)
- [ARCHITECTURE.md](/ARCHITECTURE.md), our architecture guide.
- [BUILDING.md](/BUILDING.md)

You may also need to consult various specifications while developing.

- [WebAuthn (Level 3) Specification](https://www.w3.org/TR/webauthn-3/)
- [CTAP 2.2 Specification](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)

# Reporting Issues

If you find any bugs, inconsistencies or other problems, feel free to submit
a GitHub [issue](https://github.com/linux-credentials/credentialsd/issues/new).

Also, if you have trouble getting on board, let us know so we can help future
contributors to the project overcome that hurdle too.

## Security Issues

If you are reporting a security issue, please review
[`SECURITY.md`](/SECURITY.md) for the prodedure to follow.

# Submitting Code

Ready to write some code? Great! Here are some guidelines to follow to
help you on your way:

## Building

When you first start making changes, make sure you can build the code and run
the tests.

To build the project, follow the build instructions in [`BUILDING.md`](/BUILDING.md).

To run tests, follow the [test instructions](/BUILDING.md#running-tests) in the
same file.

## Coding Style

In general, try to replicate the coding style that is already present. Specifically:

### Naming

For internal consistency, credentialsd uses `snake_case` for D-Bus field names
and `SCREAMING_SNAKE_CASE` for enum values. This is consistent with D-Bus
conventions, but it is distinct from Web Credential Management/WebAuthn
conventions, which this API is based on. Values specified within JSON string
payloads should stick to the naming conventions as documented in the WebAuthn
spec.

### Code Formatting and Linting

For Rust code, we use [rustfmt][] to ensure consistent formatting code and
[clippy][] to catch common mistakes not caught by the compiler.

```sh
# if you don't have them installed, install or update the stable toolchain
rustup install stable
# … and install prebuilt rustfmt and clippy executables (available for most platforms)
rustup component add rustfmt clippy
```

Before committing your changes, run `cargo fmt` to format the code (if your
editor / IDE isn't set up to run it automatically) and `cargo clippy` to run
lints. You'll need to run this from each Cargo project (`credentialsd/`,
`credentialsd-ui/`, `credentialsd-common/`).

For Python code, we use [ruff][].

[rustfmt]: https://github.com/rust-lang/rustfmt#readme
[clippy]: https://github.com/rust-lang/rust-clippy#readme
[ruff]: https://docs.astral.sh/ruff/installation/

### Import Formatting

Organize your imports into three groups separated by blank lines:

1. `std` imports
1. External imports (from other crates)
1. Local imports (`crate::`, `super::`, `self::` and things like `LocalEnum::*`)

For example,

```rust
use std::collections::HashMap;

use credentialsd_common::model::Operation;

use super::MyType;
```

### Commit Messages

The commit message should start with the _area_ that is affected by the change, which is usually the name of the folder withouth the `credentialsd-` prefix. The exception is `credentialsd/` itself, which should use `daemon`.

Write commit messages using the imperative mood, as if completing the sentence:
"If applied, this commit will \_\_\_." For example, use "Fix some bug" instead
of "Fixed some bug" or "Add a feature" instead of "Added a feature".

Some examples:

- "daemon: Allow clients to cancel their own requests"
- "ui: Allow users to go back to device selection"

(Take a look at this [blog post][commit-messages-guide] for more information on
writing good commit messages.)

[commit-messages-guide]: https://www.freecodecamp.org/news/writing-good-commit-messages-a-practical-guide/

### Tracking Changes

For bug fixes, breaking changes and improvements add an entry about them to the
[changelog](/CHANGELOG.md).

If your changes affect the the public D-Bus API (Gateway, Flow Control or UI
Control APIs), also make sure to document the change in [doc/api.md](/doc/api.md) and
add a note to the [revision history](/doc/api.md#revision-history) in that file.

## Submitting PRs

Once you're ready to submit your code, create a pull request, and one of our
maintainers will review it. Once your PR has passed review, a maintainer will
merge the request and you're done! 🎉

## Where do I start?

If this is your first contribution to the project, we recommend taking a look
at one of the [open issues][] we've marked for new contributors.

[open issues]: https://github.com/linux-credentials/credentialsd/issues?q=is%3Aissue+is%3Aopen+label%3A"help+wanted"

# Testing

Before committing, run `meson test --interactive` from the `build/` directory to
make sure that your changes can build and pass all tests, as well as running the
formatting and linting tools [mentioned above](#code-formatting-and-linting).

You should also follow the install instructions in [`BUILDING.md`](/BUILDING.md)
and execute authentication flows in a browser to ensure that everything
still works as it should.
