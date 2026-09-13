//! Typed public-certificate reads and public-key classification.

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_ber::{BerTlv, Sequence};
use refineid_pkcs15::{CertSlot, Pkcs15Error, Pkcs15Ops};
use refineid_x509::{EcCurve, PublicKey, UnvalidatedCertificate};

const RSA_2048_BITS: usize = 2_048;
const RSA_3072_BITS: usize = 3_072;

/// Supported key profile carried by a card certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardKeyProfile {
    Rsa2048,
    Rsa3072,
    EcdsaP256,
    EcdsaP384,
}

/// Canonical DER encoding of an X.509 certificate.
///
/// Refinement invariant: The inner bytes form a non-empty, structurally sound
/// DER-encoded ASN.1 SEQUENCE whose length exactly matches the buffer length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertificateDer(Vec<u8>);

impl CertificateDer {
    /// Construct and validate `CertificateDer` from raw bytes.
    pub(crate) fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, CertificateReadFailure> {
        let tlv = BerTlv::<Sequence>::parse(&bytes)
            .map_err(|_| CertificateReadFailure::InvalidCertificate)?;
        if tlv.size() != bytes.len() {
            return Err(CertificateReadFailure::InvalidCertificate);
        }
        Ok(Self(bytes))
    }

    /// Construct `CertificateDer` from bytes that have already been validated.
    #[must_use]
    pub(crate) const fn from_validated(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the DER-encoded byte slice.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Byte length of the DER encoding.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Consume into the inner raw byte buffer.
    #[must_use]
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for CertificateDer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Validated public certificate and its reconstructed key profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CardCertificate {
    profile: CardKeyProfile,
    der: CertificateDer,
}

impl CardCertificate {
    /// Construct a `CardCertificate` from a key profile and validated DER.
    #[must_use]
    pub(crate) const fn new(profile: CardKeyProfile, der: CertificateDer) -> Self {
        Self { profile, der }
    }

    /// The key profile of the certificate.
    #[must_use]
    pub(crate) const fn profile(&self) -> CardKeyProfile {
        self.profile
    }

    /// Reference to the canonical certificate DER.
    #[must_use]
    pub(crate) fn der(&self) -> &CertificateDer {
        &self.der
    }

    /// Consume the certificate into its canonical DER representation.
    #[must_use]
    pub(crate) fn into_der(self) -> CertificateDer {
        self.der
    }
}

/// An X.509 CA certificate whose DER structure and public key have been validated.
///
/// Refinement invariant: The inner bytes form a structurally valid X.509 certificate
/// carrying a valid RSA or ECDSA public key. Construction rejects malformed DER,
/// invalid TLV encodings, and unsupported key algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedCaCertificate {
    public_key: PublicKey,
    der: CertificateDer,
}

impl ValidatedCaCertificate {
    /// Construct and validate a CA certificate from an unvalidated certificate.
    pub(crate) fn from_unvalidated(
        certificate: UnvalidatedCertificate,
    ) -> Result<Self, CertificateReadFailure> {
        let der = CertificateDer::try_from_bytes(certificate.as_bytes().to_vec())?;
        let public_key = PublicKey::from_certificate(certificate)
            .map_err(|_| CertificateReadFailure::InvalidCertificate)?;
        Ok(Self { public_key, der })
    }

    /// Construct and validate a CA certificate from a `CertificateDer`.
    pub(crate) fn from_der(der: CertificateDer) -> Result<Self, CertificateReadFailure> {
        Self::from_unvalidated(UnvalidatedCertificate::new(der.into_bytes()))
    }

    /// Borrow the validated DER encoding.
    #[must_use]
    pub(crate) fn der(&self) -> &CertificateDer {
        &self.der
    }
}

/// Validated card Root CA certificate extracted from EF.4334.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootCaCertificate(ValidatedCaCertificate);

impl RootCaCertificate {
    /// Validate and construct a Root CA certificate from `CertificateDer`.
    pub(crate) fn from_der(der: CertificateDer) -> Result<Self, CertificateReadFailure> {
        ValidatedCaCertificate::from_der(der).map(Self)
    }

    /// Validate and construct a Root CA certificate from an unvalidated certificate.
    pub(crate) fn from_unvalidated(
        certificate: UnvalidatedCertificate,
    ) -> Result<Self, CertificateReadFailure> {
        ValidatedCaCertificate::from_unvalidated(certificate).map(Self)
    }

    /// Borrow the validated DER encoding.
    #[must_use]
    pub(crate) fn der(&self) -> &CertificateDer {
        self.0.der()
    }
}

/// Validated card Intermediate / Issuing CA certificate extracted from EF.4336.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntermediateCaCertificate(ValidatedCaCertificate);

impl IntermediateCaCertificate {
    /// Validate and construct an Intermediate CA certificate from `CertificateDer`.
    pub(crate) fn from_der(der: CertificateDer) -> Result<Self, CertificateReadFailure> {
        ValidatedCaCertificate::from_der(der).map(Self)
    }

    /// Validate and construct an Intermediate CA certificate from an unvalidated certificate.
    pub(crate) fn from_unvalidated(
        certificate: UnvalidatedCertificate,
    ) -> Result<Self, CertificateReadFailure> {
        ValidatedCaCertificate::from_unvalidated(certificate).map(Self)
    }

    /// Borrow the validated DER encoding.
    #[must_use]
    pub(crate) fn der(&self) -> &CertificateDer {
        self.0.der()
    }
}

/// Safe failure classes crossing the native boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertificateReadFailure {
    CardUnavailable,
    Rejected,
    Transport,
    InvalidCertificate,
    /// The contactless secure channel refused the CAN.
    PaceRejected,
    Bridge,
    /// The card still awaits factory activation.
    #[allow(dead_code)]
    ActivationRequired,
}

/// Read EF.4331 and reconstruct its public key before returning its DER.
pub(crate) fn read_authentication_certificate<T: CardTransport>(
    transport: &mut T,
) -> Result<CardCertificate, CertificateReadFailure> {
    read_card_certificate(transport, CertSlot::Authentication)
}

/// Read EF.4332 and reconstruct its public key before returning its DER.
pub(crate) fn read_qualified_certificate<T: CardTransport>(
    transport: &mut T,
) -> Result<CardCertificate, CertificateReadFailure> {
    read_card_certificate(transport, CertSlot::Signature)
}

fn read_card_certificate<T: CardTransport>(
    transport: &mut T,
    slot: CertSlot,
) -> Result<CardCertificate, CertificateReadFailure> {
    let certificate = transport.read_certificate(slot).map_err(map_pkcs15_error)?;
    let der_bytes = certificate.as_bytes().to_vec();
    let public_key = PublicKey::from_certificate(certificate)
        .map_err(|_| CertificateReadFailure::InvalidCertificate)?;
    let profile = classify_public_key(&public_key)?;
    let der = CertificateDer::from_validated(der_bytes);
    Ok(CardCertificate::new(profile, der))
}

fn classify_public_key(public_key: &PublicKey) -> Result<CardKeyProfile, CertificateReadFailure> {
    match public_key {
        PublicKey::Rsa(rsa) => match rsa.modulus().bit_length() {
            RSA_2048_BITS => Ok(CardKeyProfile::Rsa2048),
            RSA_3072_BITS => Ok(CardKeyProfile::Rsa3072),
            _ => Err(CertificateReadFailure::InvalidCertificate),
        },
        PublicKey::Ecdsa(ec) => match ec.curve() {
            EcCurve::P256 => Ok(CardKeyProfile::EcdsaP256),
            EcCurve::P384 => Ok(CardKeyProfile::EcdsaP384),
        },
    }
}

pub(crate) fn map_pkcs15_error<E>(error: Pkcs15Error<E>) -> CertificateReadFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            CertificateReadFailure::CardUnavailable
        }
        Pkcs15Error::Status(_) => CertificateReadFailure::Rejected,
        Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => CertificateReadFailure::Transport,
        Pkcs15Error::Empty | Pkcs15Error::TooLarge | Pkcs15Error::InvalidData(_) => {
            CertificateReadFailure::InvalidCertificate
        }
        Pkcs15Error::Outcome(TransportOutcome::Response(_))
        | Pkcs15Error::Aid(_)
        | Pkcs15Error::Command(_) => CertificateReadFailure::Bridge,
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::{ResponseApdu, StatusWord, TransportOutcome};
    use refineid_pkcs15::Pkcs15Error;

    use super::{
        CardCertificate, CardKeyProfile, CertificateDer, CertificateReadFailure, map_pkcs15_error,
    };
    use crate::card_transport::AndroidTransportError;

    const SYNTHETIC_DER_SEQUENCE_TAG: u8 = 0x30;
    const SYNTHETIC_DER_EMPTY_LENGTH: u8 = 0x00;
    const SYNTHETIC_DER_OCTET_STRING_TAG: u8 = 0x04;
    const SYNTHETIC_DER_TRAILING_GARBAGE: u8 = 0xFF;

    #[test]
    fn validates_certificate_der_framing() {
        let valid_der = vec![SYNTHETIC_DER_SEQUENCE_TAG, SYNTHETIC_DER_EMPTY_LENGTH];
        let der = CertificateDer::try_from_bytes(valid_der.clone())
            .expect("empty sequence is valid DER TLV");
        assert_eq!(der.as_bytes(), &valid_der);
        assert_eq!(der.len(), 2);
        assert_eq!(der.into_bytes(), valid_der);

        assert_eq!(
            CertificateDer::try_from_bytes(Vec::new()),
            Err(CertificateReadFailure::InvalidCertificate)
        );

        assert_eq!(
            CertificateDer::try_from_bytes(vec![
                SYNTHETIC_DER_OCTET_STRING_TAG,
                SYNTHETIC_DER_EMPTY_LENGTH
            ]),
            Err(CertificateReadFailure::InvalidCertificate)
        );

        assert_eq!(
            CertificateDer::try_from_bytes(vec![SYNTHETIC_DER_SEQUENCE_TAG, 0x05, 0x01]),
            Err(CertificateReadFailure::InvalidCertificate)
        );

        assert_eq!(
            CertificateDer::try_from_bytes(vec![
                SYNTHETIC_DER_SEQUENCE_TAG,
                0x01,
                0x00,
                SYNTHETIC_DER_TRAILING_GARBAGE
            ]),
            Err(CertificateReadFailure::InvalidCertificate)
        );
    }

    #[test]
    fn card_certificate_into_der_preserves_der_type() {
        let der = CertificateDer::from_validated(vec![
            SYNTHETIC_DER_SEQUENCE_TAG,
            SYNTHETIC_DER_EMPTY_LENGTH,
        ]);
        let cert = CardCertificate::new(CardKeyProfile::Rsa2048, der.clone());
        assert_eq!(cert.profile(), CardKeyProfile::Rsa2048);
        assert_eq!(cert.der(), &der);
        let extracted_der: CertificateDer = cert.into_der();
        assert_eq!(extracted_der, der);
    }

    #[test]
    fn maps_card_and_transport_failures_without_details() {
        let [success_sw1, success_sw2] = StatusWord::Success.as_u16().to_be_bytes();
        assert_eq!(
            map_pkcs15_error::<AndroidTransportError>(Pkcs15Error::Outcome(
                TransportOutcome::NoCard
            )),
            CertificateReadFailure::CardUnavailable
        );
        assert_eq!(
            map_pkcs15_error::<AndroidTransportError>(Pkcs15Error::Status(
                StatusWord::FileNotFound
            )),
            CertificateReadFailure::Rejected
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Transport(AndroidTransportError::Backend)),
            CertificateReadFailure::Transport
        );
        assert_eq!(
            map_pkcs15_error::<AndroidTransportError>(Pkcs15Error::InvalidData(
                "synthetic certificate"
            )),
            CertificateReadFailure::InvalidCertificate
        );
        assert_eq!(
            map_pkcs15_error::<AndroidTransportError>(Pkcs15Error::Outcome(
                TransportOutcome::Response(ResponseApdu {
                    body: Vec::new(),
                    sw1: success_sw1,
                    sw2: success_sw2,
                })
            )),
            CertificateReadFailure::Bridge
        );
    }
}
