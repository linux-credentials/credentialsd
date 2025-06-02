use libwebauthn::proto::ctap2::Ctap2COSEAlgorithmIdentifier;
use tracing::debug;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(i64)]
pub(super) enum CoseKeyType {
    Es256P256,
    EddsaEd25519,
    RS256,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CoseKeyAlgorithmIdentifier {
    ES256,
    EdDSA,
    RS256,
}

impl From<CoseKeyAlgorithmIdentifier> for i64 {
    fn from(value: CoseKeyAlgorithmIdentifier) -> Self {
        match value {
            CoseKeyAlgorithmIdentifier::ES256 => -7,
            CoseKeyAlgorithmIdentifier::EdDSA => -8,
            CoseKeyAlgorithmIdentifier::RS256 => -257,
        }
    }
}

impl From<CoseKeyAlgorithmIdentifier> for i128 {
    fn from(value: CoseKeyAlgorithmIdentifier) -> Self {
        match value {
            CoseKeyAlgorithmIdentifier::ES256 => -7,
            CoseKeyAlgorithmIdentifier::EdDSA => -8,
            CoseKeyAlgorithmIdentifier::RS256 => -257,
        }
    }
}

impl TryFrom<Ctap2COSEAlgorithmIdentifier> for CoseKeyAlgorithmIdentifier {
    type Error = Error;

    fn try_from(value: Ctap2COSEAlgorithmIdentifier) -> Result<Self, Self::Error> {
        match value {
            Ctap2COSEAlgorithmIdentifier::EDDSA => Ok(CoseKeyAlgorithmIdentifier::EdDSA),
            Ctap2COSEAlgorithmIdentifier::ES256 => Ok(CoseKeyAlgorithmIdentifier::ES256),
            Ctap2COSEAlgorithmIdentifier::TOPT => {
                debug!("Unknown public key algorithm type: {:?}", value);
                Err(Error::Unsupported)
            }
            Ctap2COSEAlgorithmIdentifier::Unknown => Err(Error::Unsupported),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum CoseEllipticCurveIdentifier {
    /// P-256 Elliptic Curve using uncompressed points.
    P256,
    /// P-384 Elliptic Curve using uncompressed points.
    P384,
    /// P-521 Elliptic Curve using uncompressed points.
    P521,
    /// Ed25519 Elliptic Curve using compressed points.
    Ed25519,
}

impl From<CoseEllipticCurveIdentifier> for i64 {
    fn from(value: CoseEllipticCurveIdentifier) -> Self {
        match value {
            CoseEllipticCurveIdentifier::P256 => 1,
            CoseEllipticCurveIdentifier::P384 => 2,
            CoseEllipticCurveIdentifier::P521 => 3,
            CoseEllipticCurveIdentifier::Ed25519 => 6,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidKey,
    Unsupported,
}
