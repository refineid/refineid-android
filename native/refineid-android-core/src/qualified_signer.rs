// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! One-shot PIN2 verification and qualified-key SHA-384 signing.
//!
//! The counter-safe preflight runs first. The public qualified certificate is
//! then read in the same exclusive operation, which both proves the requested
//! key profile and leaves DF.ESIGN current for organization cards. Only after
//! exact certificate matching is one fresh PIN2 sent through the non-replayable
//! credential path, followed immediately by one MSE/PSO signature chain.

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_auth::{Pin2, PinOps, PinReferenceScheme, UnvalidatedSecret, VerifyOutcome};
use refineid_digest::Sha384;
use refineid_sign::{KeyRef, SignError, SignOps, SignScheme};

use crate::card_certificate::{
    CardCertificate, CardKeyProfile, CertificateReadFailure, read_qualified_certificate,
};
use crate::card_transport::{AndroidCardTransport, SingleBlockExchange};
use crate::pin2_status::{Pin2PreflightFailure, Pin2State, map_auth_error, probe_pin2_preflight};

/// Upper bound for the exact CMS signed-attribute bytes hashed here.
pub(crate) const MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH: usize = 1_024 * 1_024;

/// Qualified-document algorithms supported by the reviewed public core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QualifiedSigningAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-384 and an RSA-3072 qualified key.
    RsaPkcs1Sha384,
    /// ECDSA with SHA-384 and a P-384 qualified key.
    EcdsaP384Sha384,
}

/// Whether this boundary hashes a content message or accepts a caller-asserted digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QualifiedSigningInput<'a> {
    /// Hash these complete message bytes with SHA-384.
    Message(&'a [u8]),
    /// Use these bytes as an already-computed SHA-384 digest after exact-length validation.
    Prehashed(&'a [u8]),
}

impl QualifiedSigningAlgorithm {
    const fn accepts_profile(self, profile: CardKeyProfile) -> bool {
        matches!(
            (self, profile),
            (Self::RsaPkcs1Sha384, CardKeyProfile::Rsa3072)
                | (Self::EcdsaP384Sha384, CardKeyProfile::EcdsaP384)
        )
    }
}

/// Locally shaped qualified signature returned by the card.
pub(crate) struct QualifiedSignature {
    /// Algorithm that produced the bytes.
    pub(crate) algorithm: QualifiedSigningAlgorithm,
    /// RSA modulus-wide bytes or raw ECDSA `r || s`.
    pub(crate) bytes: Vec<u8>,
}

impl core::fmt::Debug for QualifiedSignature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("QualifiedSignature")
            .field("algorithm", &self.algorithm)
            .field("length", &self.bytes.len())
            .finish()
    }
}

impl Drop for QualifiedSignature {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Coarse one-shot failures safe to encode across JNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QualifiedSignFailure {
    /// The submitted PIN2 did not satisfy its local digit predicate.
    InvalidPin,
    /// The live counter state did not permit a qualified-signature try.
    SafetyRefused,
    /// PIN2 is blocked, invalidated, or became exhausted on this attempt.
    PinLocked,
    /// The card rejected the submitted PIN2 without exhausting it.
    WrongPin,
    /// VERIFY returned a status outside the reviewed outcome vocabulary.
    VerificationRejected,
    /// EF.4332 could not be selected or read.
    CertificateRejected,
    /// EF.4332 was not a valid supported public certificate.
    InvalidCertificate,
    /// The card certificate no longer matches the certificate the caller used.
    CertificateMismatch,
    /// The requested algorithm does not match the card certificate profile.
    KeyProfileMismatch,
    /// The card rejected or malformed the signing chain.
    SigningRejected,
    /// Card or reader disappeared from the slot.
    CardUnavailable,
    /// Transport state became unusable or indeterminate.
    Transport,
    /// An impossible local shape reached the bridge.
    Bridge,
}

/// Public-certificate read seam retained inside the exclusive sign operation.
pub(crate) trait QualifiedCertificateSource: CardTransport {
    fn read_qualified_certificate_for_signing(
        &mut self,
    ) -> Result<CardCertificate, CertificateReadFailure>;
}

impl<Exchange> QualifiedCertificateSource for AndroidCardTransport<Exchange>
where
    Exchange: SingleBlockExchange,
{
    fn read_qualified_certificate_for_signing(
        &mut self,
    ) -> Result<CardCertificate, CertificateReadFailure> {
        read_qualified_certificate(self)
    }
}

/// Present one fresh PIN2 exactly once and sign one signed-attribute value.
pub(crate) fn qualified_sign<T>(
    transport: &mut T,
    algorithm: QualifiedSigningAlgorithm,
    pin_bytes: Vec<u8>,
    input: QualifiedSigningInput<'_>,
    expected_certificate: &[u8],
) -> Result<QualifiedSignature, QualifiedSignFailure>
where
    T: QualifiedCertificateSource,
{
    let digest = match input {
        QualifiedSigningInput::Message(content) => {
            if content.len() > MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH {
                return Err(QualifiedSignFailure::Bridge);
            }
            Sha384::of(content)
        }
        QualifiedSigningInput::Prehashed(digest_bytes) => digest_bytes
            .try_into()
            .map(Sha384::from_bytes)
            .map_err(|_| QualifiedSignFailure::Bridge)?,
    };
    let pin_input = UnvalidatedSecret::from_owned_bytes(pin_bytes);
    let pin = Pin2::reconstruct(pin_input).map_err(|_| QualifiedSignFailure::InvalidPin)?;
    let preflight = probe_pin2_preflight(transport).map_err(map_preflight_failure)?;
    if !preflight.qualified_signature_permitted {
        return Err(match preflight.state {
            Pin2State::Locked => QualifiedSignFailure::PinLocked,
            Pin2State::Verified
            | Pin2State::Remaining(_)
            | Pin2State::NoInformation
            | Pin2State::Unrecognised => QualifiedSignFailure::SafetyRefused,
        });
    }

    let certificate = transport
        .read_qualified_certificate_for_signing()
        .map_err(map_certificate_failure)?;
    if certificate.der().as_bytes() != expected_certificate {
        return Err(QualifiedSignFailure::CertificateMismatch);
    }
    if !algorithm.accepts_profile(certificate.profile()) {
        return Err(QualifiedSignFailure::KeyProfileMismatch);
    }

    let outcome = transport
        .verify_pin2_with_scheme(preflight.scheme, pin)
        .map_err(|error| map_preflight_failure(map_auth_error(error)))?;
    match outcome {
        VerifyOutcome::Ok => {}
        VerifyOutcome::WrongPin { retries_left } if retries_left.is_exhausted() => {
            return Err(QualifiedSignFailure::PinLocked);
        }
        VerifyOutcome::WrongPin { .. } => return Err(QualifiedSignFailure::WrongPin),
        VerifyOutcome::Locked => return Err(QualifiedSignFailure::PinLocked),
        VerifyOutcome::Other(_) => return Err(QualifiedSignFailure::VerificationRejected),
    }

    let scheme = sign_scheme(preflight.scheme);
    let bytes = match algorithm {
        QualifiedSigningAlgorithm::RsaPkcs1Sha384 => transport
            .sign_prehashed_sha384_rsa(scheme, KeyRef::Sign, digest.into_bytes())
            .map(|signature| signature.into_bytes()),
        QualifiedSigningAlgorithm::EcdsaP384Sha384 => transport
            .sign_prehashed_sha384_ecdsa(scheme, KeyRef::Sign, digest.into_bytes())
            .map(|signature| signature.into_bytes()),
    }
    .map_err(map_sign_error)?;

    Ok(QualifiedSignature { algorithm, bytes })
}

const fn sign_scheme(scheme: PinReferenceScheme) -> SignScheme {
    match scheme {
        PinReferenceScheme::Citizen => SignScheme::Citizen,
        PinReferenceScheme::Organizational => SignScheme::Organizational,
    }
}

const fn map_preflight_failure(failure: Pin2PreflightFailure) -> QualifiedSignFailure {
    match failure {
        Pin2PreflightFailure::CardUnavailable => QualifiedSignFailure::CardUnavailable,
        Pin2PreflightFailure::Transport => QualifiedSignFailure::Transport,
        Pin2PreflightFailure::Bridge => QualifiedSignFailure::Bridge,
    }
}

const fn map_certificate_failure(failure: CertificateReadFailure) -> QualifiedSignFailure {
    match failure {
        CertificateReadFailure::CardUnavailable => QualifiedSignFailure::CardUnavailable,
        CertificateReadFailure::Rejected => QualifiedSignFailure::CertificateRejected,
        CertificateReadFailure::Transport => QualifiedSignFailure::Transport,
        CertificateReadFailure::InvalidCertificate => QualifiedSignFailure::InvalidCertificate,
        // The qualified path never opens a PACE channel; a channel
        // refusal reaching it is a local impossibility.
        CertificateReadFailure::PaceRejected
        | CertificateReadFailure::Bridge
        | CertificateReadFailure::ActivationRequired => QualifiedSignFailure::Bridge,
    }
}

fn map_sign_error<E>(error: SignError<E>) -> QualifiedSignFailure {
    match error {
        SignError::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            QualifiedSignFailure::CardUnavailable
        }
        SignError::Transport(_)
        | SignError::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => QualifiedSignFailure::Transport,
        SignError::Status(_, _) | SignError::UnexpectedSignatureLength { .. } => {
            QualifiedSignFailure::SigningRejected
        }
        SignError::Outcome(TransportOutcome::Response(_)) | SignError::Command(_) => {
            QualifiedSignFailure::Bridge
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use refineid_apdu::{
        CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
        TransportOutcome,
    };
    use refineid_digest::Sha384;
    use refineid_sign::{ECDSA_P384_SIG_BYTES, RSA_3072_SIG_BYTES};

    use super::{
        MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH, QualifiedCertificateSource, QualifiedSignFailure,
        QualifiedSigningAlgorithm, QualifiedSigningInput, qualified_sign,
    };
    use crate::card_certificate::{
        CardCertificate, CardKeyProfile, CertificateDer, CertificateReadFailure,
    };

    const SAFE_RETRIES: u8 = 3;
    const LOW_RETRIES: u8 = 2;
    const PUBLIC_PREFLIGHT_CALLS: usize = 2;
    const FULL_RSA_PUBLIC_CALLS: usize = 5;
    const PSO_HASH_PUBLIC_COMMAND_INDEX: usize = 3;
    const VERIFY_INSTRUCTION: u8 = 0x20;
    const INSTRUCTION_OFFSET: usize = 1;
    const SYNTHETIC_PIN2: &[u8] = b"135790";
    const SYNTHETIC_CONTENT: &[u8] = b"qualified signed attributes";
    const SYNTHETIC_CERTIFICATE: &[u8] = b"typed synthetic certificate";
    const DIFFERENT_CERTIFICATE: &[u8] = b"different synthetic certificate";
    const SIGNATURE_FILL: u8 = 0xA5;
    const SINGLE_EXCESS_BYTE_COUNT: usize = 1;

    struct ScriptedTransport {
        public_responses: VecDeque<TransportOutcome>,
        public_commands: Vec<Vec<u8>>,
        credential_response: TransportOutcome,
        public_calls: usize,
        credential_calls: usize,
        certificate_reads: usize,
        certificate: Option<Result<CardCertificate, CertificateReadFailure>>,
    }

    impl ScriptedTransport {
        fn new(
            public_responses: Vec<TransportOutcome>,
            credential_status: StatusWord,
            profile: CardKeyProfile,
        ) -> Self {
            Self {
                public_responses: public_responses.into(),
                public_commands: Vec::new(),
                credential_response: response(credential_status, Vec::new()),
                public_calls: 0,
                credential_calls: 0,
                certificate_reads: 0,
                certificate: Some(Ok(CardCertificate::new(
                    profile,
                    CertificateDer::from_validated(SYNTHETIC_CERTIFICATE.to_vec()),
                ))),
            }
        }
    }

    impl CardTransport for ScriptedTransport {
        type Error = &'static str;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.public_calls += 1;
            self.public_commands.push(command.as_bytes().to_vec());
            if self.public_calls <= PUBLIC_PREFLIGHT_CALLS {
                assert_eq!(
                    command.as_bytes().get(INSTRUCTION_OFFSET).copied(),
                    Some(VERIFY_INSTRUCTION)
                );
            }
            self.public_responses
                .pop_front()
                .ok_or("missing public response")
        }

        fn transmit_credential(
            &mut self,
            command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.credential_calls += 1;
            command.expose_wire(|wire| {
                assert_eq!(
                    wire.get(INSTRUCTION_OFFSET).copied(),
                    Some(VERIFY_INSTRUCTION)
                );
            });
            Ok(self.credential_response.clone())
        }
    }

    impl QualifiedCertificateSource for ScriptedTransport {
        fn read_qualified_certificate_for_signing(
            &mut self,
        ) -> Result<CardCertificate, CertificateReadFailure> {
            self.certificate_reads += 1;
            self.certificate
                .take()
                .expect("one scripted certificate read")
        }
    }

    fn retries(value: u8) -> PinRetries {
        PinRetries::from_nibble(value).expect("synthetic retry count fits")
    }

    fn status(retry_count: u8) -> StatusWord {
        StatusWord::PinIncorrect {
            retries: retries(retry_count),
        }
    }

    fn response(status: StatusWord, body: Vec<u8>) -> TransportOutcome {
        let [sw1, sw2] = status.as_u16().to_be_bytes();
        TransportOutcome::Response(ResponseApdu { body, sw1, sw2 })
    }

    fn success_script(profile: CardKeyProfile, signature_length: usize) -> ScriptedTransport {
        let safe = response(status(SAFE_RETRIES), Vec::new());
        ScriptedTransport::new(
            vec![
                safe.clone(),
                safe,
                response(StatusWord::Success, Vec::new()),
                response(StatusWord::Success, Vec::new()),
                response(StatusWord::Success, vec![SIGNATURE_FILL; signature_length]),
            ],
            StatusWord::Success,
            profile,
        )
    }

    #[test]
    fn one_submission_matches_the_certificate_then_signs_once() {
        let mut transport = success_script(CardKeyProfile::Rsa3072, RSA_3072_SIG_BYTES);

        let result = qualified_sign(
            &mut transport,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Message(SYNTHETIC_CONTENT),
            SYNTHETIC_CERTIFICATE,
        )
        .expect("scripted qualified signature succeeds");

        assert_eq!(result.bytes.len(), RSA_3072_SIG_BYTES);
        assert_eq!(transport.certificate_reads, 1);
        assert_eq!(transport.credential_calls, 1);
        assert_eq!(transport.public_calls, FULL_RSA_PUBLIC_CALLS);
        assert!(transport.public_responses.is_empty());
        let digest = Sha384::of(SYNTHETIC_CONTENT).into_bytes();
        assert!(transport.public_commands[PSO_HASH_PUBLIC_COMMAND_INDEX].ends_with(&digest));
    }

    #[test]
    fn prehashed_submission_signs_exact_digest() {
        let mut transport = success_script(CardKeyProfile::EcdsaP384, ECDSA_P384_SIG_BYTES);
        let digest = Sha384::of(SYNTHETIC_CONTENT).into_bytes();

        let result = qualified_sign(
            &mut transport,
            QualifiedSigningAlgorithm::EcdsaP384Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Prehashed(&digest),
            SYNTHETIC_CERTIFICATE,
        )
        .expect("scripted prehashed signature succeeds");

        assert_eq!(result.algorithm, QualifiedSigningAlgorithm::EcdsaP384Sha384);
        assert_eq!(result.bytes.len(), ECDSA_P384_SIG_BYTES);
        assert_eq!(transport.credential_calls, 1);
    }

    #[test]
    fn both_supported_profiles_have_fixed_signature_shapes() {
        for (algorithm, profile, signature_length) in [
            (
                QualifiedSigningAlgorithm::RsaPkcs1Sha384,
                CardKeyProfile::Rsa3072,
                RSA_3072_SIG_BYTES,
            ),
            (
                QualifiedSigningAlgorithm::EcdsaP384Sha384,
                CardKeyProfile::EcdsaP384,
                ECDSA_P384_SIG_BYTES,
            ),
        ] {
            let mut transport = success_script(profile, signature_length);

            let result = qualified_sign(
                &mut transport,
                algorithm,
                SYNTHETIC_PIN2.to_vec(),
                QualifiedSigningInput::Message(SYNTHETIC_CONTENT),
                SYNTHETIC_CERTIFICATE,
            )
            .expect("scripted profile succeeds");

            assert_eq!(result.algorithm, algorithm);
            assert_eq!(result.bytes.len(), signature_length);
            assert_eq!(transport.credential_calls, 1);
        }
    }

    #[test]
    fn the_retry_floor_refuses_before_certificate_or_credential_access() {
        let low = response(status(LOW_RETRIES), Vec::new());
        let mut transport = ScriptedTransport::new(
            vec![low.clone(), low],
            StatusWord::Success,
            CardKeyProfile::Rsa3072,
        );

        let result = qualified_sign(
            &mut transport,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Message(SYNTHETIC_CONTENT),
            SYNTHETIC_CERTIFICATE,
        );

        assert!(matches!(result, Err(QualifiedSignFailure::SafetyRefused)));
        assert_eq!(transport.certificate_reads, 0);
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn a_certificate_mismatch_refuses_before_pin2_is_sent() {
        let mut transport = success_script(CardKeyProfile::Rsa3072, RSA_3072_SIG_BYTES);

        let result = qualified_sign(
            &mut transport,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Message(SYNTHETIC_CONTENT),
            DIFFERENT_CERTIFICATE,
        );

        assert!(matches!(
            result,
            Err(QualifiedSignFailure::CertificateMismatch)
        ));
        assert_eq!(transport.certificate_reads, 1);
        assert_eq!(transport.credential_calls, 0);
        assert_eq!(transport.public_calls, PUBLIC_PREFLIGHT_CALLS);
    }

    #[test]
    fn a_profile_mismatch_refuses_before_pin2_is_sent() {
        let mut transport = success_script(CardKeyProfile::EcdsaP384, ECDSA_P384_SIG_BYTES);

        let result = qualified_sign(
            &mut transport,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Message(SYNTHETIC_CONTENT),
            SYNTHETIC_CERTIFICATE,
        );

        assert!(matches!(
            result,
            Err(QualifiedSignFailure::KeyProfileMismatch)
        ));
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn a_wrong_pin2_stops_before_mse_and_is_never_replayed() {
        let safe = response(status(SAFE_RETRIES), Vec::new());
        let mut transport = ScriptedTransport::new(
            vec![safe.clone(), safe],
            status(LOW_RETRIES),
            CardKeyProfile::Rsa3072,
        );

        let result = qualified_sign(
            &mut transport,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Message(SYNTHETIC_CONTENT),
            SYNTHETIC_CERTIFICATE,
        );

        assert!(matches!(result, Err(QualifiedSignFailure::WrongPin)));
        assert_eq!(transport.credential_calls, 1);
        assert_eq!(transport.public_calls, PUBLIC_PREFLIGHT_CALLS);
    }

    #[test]
    fn invalid_pin_or_overlong_content_never_touches_the_card() {
        let mut invalid_pin = success_script(CardKeyProfile::Rsa3072, RSA_3072_SIG_BYTES);
        let invalid_pin_result = qualified_sign(
            &mut invalid_pin,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            Vec::new(),
            QualifiedSigningInput::Message(SYNTHETIC_CONTENT),
            SYNTHETIC_CERTIFICATE,
        );
        assert!(matches!(
            invalid_pin_result,
            Err(QualifiedSignFailure::InvalidPin)
        ));
        assert_eq!(invalid_pin.public_calls, 0);
        assert_eq!(invalid_pin.credential_calls, 0);

        let mut oversized = success_script(CardKeyProfile::Rsa3072, RSA_3072_SIG_BYTES);
        let content = vec![
            SIGNATURE_FILL;
            MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH + SINGLE_EXCESS_BYTE_COUNT
        ];
        let oversized_result = qualified_sign(
            &mut oversized,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Message(&content),
            SYNTHETIC_CERTIFICATE,
        );
        assert!(matches!(
            oversized_result,
            Err(QualifiedSignFailure::Bridge)
        ));
        assert_eq!(oversized.public_calls, 0);
        assert_eq!(oversized.credential_calls, 0);

        let mut bad_digest = success_script(CardKeyProfile::Rsa3072, RSA_3072_SIG_BYTES);
        let bad_digest_result = qualified_sign(
            &mut bad_digest,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Prehashed(b"short"),
            SYNTHETIC_CERTIFICATE,
        );
        assert!(matches!(
            bad_digest_result,
            Err(QualifiedSignFailure::Bridge)
        ));
        assert_eq!(bad_digest.public_calls, 0);
        assert_eq!(bad_digest.credential_calls, 0);
    }
}
