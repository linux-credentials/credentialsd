//! WebAuthn types re-exported from libwebauthn, plus origin/navigation types
//! used to validate and route incoming requests.

use std::{fmt::Display, str::FromStr};

pub use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, RelyingPartyId, WebAuthnIDLResponse,
};

/// An application ID conforming to the
/// [XDG desktop entry syntax][xdg-desktop-entry-name].
///
/// [xdg-desktop-entry-name]: https://specifications.freedesktop.org/desktop-entry/latest/file-naming.html
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AppId(String);

impl AsRef<str> for AppId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for AppId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // begins with a letter
        match s.chars().nth(0) {
            Some(c) if c.is_ascii_alphabetic() => {}
            _ => return Err(()),
        };

        // alphanumeric and labels separated by dots
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(());
        }

        // All labels must be non-empty.
        if s.contains("..") {
            return Err(());
        }

        // ends with a valid label
        if s.ends_with('.') {
            return Err(());
        }
        Ok(AppId(s.to_string()))
    }
}

/// The origin of the client for the request.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Origin {
    Https { host: String, port: Option<u16> },
    AppId(AppId),
}

impl Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::Https { host, port } => {
                write!(f, "https://{}", host)?;
                if let Some(port) = port {
                    write!(f, ":{port}")?;
                }
            }
            Origin::AppId(app_id) => write!(f, "app:{}", app_id.0)?,
        }
        Ok(())
    }
}

impl TryFrom<&Origin> for RelyingPartyId {
    type Error = OriginParseError;

    /// Derives the relying party ID (effective domain) from an origin.
    ///
    /// AppId origins have no effective domain and must be mapped to an rpId
    /// out-of-band, so this conversion fails for them.
    fn try_from(origin: &Origin) -> Result<Self, Self::Error> {
        match origin {
            Origin::Https { host, .. } => {
                RelyingPartyId::try_from(host.as_str()).map_err(|_| OriginParseError::InvalidHost)
            }
            Origin::AppId(_) => Err(OriginParseError::InvalidScheme),
        }
    }
}

impl FromStr for Origin {
    type Err = OriginParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("https://") {
            let (host_candidate, port_candidate): (&str, Option<&str>) = rest
                .split_once(':')
                .map(|(h, p)| (h, Some(p)))
                .unwrap_or((rest, None));

            // begins with a letter
            match host_candidate.chars().nth(0) {
                Some(c) if c.is_ascii_alphabetic() => {}
                _ => return Err(OriginParseError::InvalidHost),
            };
            // alphanumeric with hyphens and labels separated by dots
            if !host_candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            {
                return Err(OriginParseError::InvalidHost);
            }
            // ends with a valid label
            if host_candidate.ends_with('.') {
                return Err(OriginParseError::InvalidHost);
            }
            let host = host_candidate.to_ascii_lowercase();

            let Ok(port) = port_candidate.map(|p| p.parse()).transpose() else {
                return Err(OriginParseError::InvalidPort);
            };

            Ok(Origin::Https { host, port })
        } else if let Some(app_id_candidate) = s.strip_prefix("app:") {
            let app_id = app_id_candidate
                .parse()
                .map_err(|_| OriginParseError::InvalidHost)?;
            Ok(Origin::AppId(app_id))
        } else {
            Err(OriginParseError::InvalidScheme)
        }
    }
}

/// The origin of the request, and its top-level origin, if it is cross-origin.
#[derive(Debug)]
pub(crate) enum NavigationContext {
    /// Represents a client context with a single origin is presented to the user.
    SameOrigin(Origin),

    /// Represents a client context where the origin of the request is nested within
    /// another parent context with a different origin.
    CrossOrigin((Origin, Origin)),
}

impl NavigationContext {
    /// Retrieve the origin from the context.
    pub(crate) fn origin(&self) -> &Origin {
        match self {
            NavigationContext::SameOrigin(origin) => origin,
            NavigationContext::CrossOrigin((origin, _)) => origin,
        }
    }
}

#[derive(Debug)]
pub(crate) enum OriginParseError {
    InvalidScheme,
    InvalidHost,
    InvalidPort,
}

impl std::error::Error for OriginParseError {}

impl Display for OriginParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidScheme => f.write_str("Invalid scheme"),
            Self::InvalidHost => f.write_str("Invalid host"),
            Self::InvalidPort => f.write_str("Invalid port"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::webauthn::{Origin, OriginParseError};

    fn check_https_origin(origin: &str, expected_host: &str, expected_port: Option<u16>) {
        let Origin::Https { host, port }: Origin = origin.parse().unwrap() else {
            panic!("Not an https origin");
        };
        assert_eq!(expected_host, host);
        assert_eq!(expected_port, port);
    }

    #[test]
    fn test_origin_parse_when_http_fails() {
        let err = "http://example.com".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::InvalidScheme));
    }

    #[test]
    fn test_origin_parse_https_origin_without_port_succeeds() {
        check_https_origin("https://example.com", "example.com", None);
    }

    #[test]
    fn test_origin_parse_https_with_port_succeeds() {
        check_https_origin("https://example.org:8443", "example.org", Some(8443));
    }

    #[test]
    fn test_origin_parse_with_trailing_slash_fails() {
        let err = "https://example.org/".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::InvalidHost));
    }

    #[test]
    fn test_origin_parse_with_port_and_path_fails() {
        let err = "https://example.org:8443/".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::InvalidPort));
    }

    #[test]
    fn test_origin_parse_with_invalid_characters_fails() {
        let err = "https://😭.edu:1234".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::InvalidHost));
    }

    #[test]
    fn test_origin_parse_app_id_succeeds() {
        let Origin::AppId(app_id) = "app:com.example.ExampleApp".parse::<Origin>().unwrap() else {
            panic!("not an app origin");
        };
        assert_eq!("com.example.ExampleApp", app_id.0);
    }
}
