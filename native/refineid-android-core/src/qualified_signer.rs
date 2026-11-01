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
//! then read in the same exclusive operation, which proves the requested key
//! profile. Only after exact certificate matching is one fresh PIN2 handed to
//! the core's qualified-key unlock, which on an organization card makes
//! DF.ESIGN current before it sends PIN2 through the non-replayable credential
//! path; the key it returns signs once with one MSE/PSO chain.

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_auth::{Pin2, UnvalidatedSecret, VerifyOutcome};
use refineid_digest::Sha384;
use refineid_pkcs15::Pkcs15Error;
use refineid_sign::{QualifiedUnlockError, SignError, SignOps, SignScheme};

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
    WrongPin {
        /// Attempts the card reports remaining, at least one.
        retries_left: u8,
    },
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
    if !preflight.retry_floor_permits {
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

    let key = transport
        .unlock_qualified_key(SignScheme::from(preflight.scheme), pin)
        .map_err(map_unlock_error)?;
    let bytes = match algorithm {
        QualifiedSigningAlgorithm::RsaPkcs1Sha384 => key
            .sign_prehashed_sha384_rsa(digest.into_bytes())
            .map(|signature| signature.into_bytes()),
        QualifiedSigningAlgorithm::EcdsaP384Sha384 => key
            .sign_prehashed_sha384_ecdsa(digest.into_bytes())
            .map(|signature| signature.into_bytes()),
    }
    .map_err(map_sign_error)?;

    Ok(QualifiedSignature { algorithm, bytes })
}

fn map_unlock_error<E>(error: QualifiedUnlockError<E>) -> QualifiedSignFailure {
    match error {
        QualifiedUnlockError::PinRefused(VerifyOutcome::WrongPin { retries_left })
            if retries_left.is_exhausted() =>
        {
            QualifiedSignFailure::PinLocked
        }
        QualifiedUnlockError::PinRefused(VerifyOutcome::WrongPin { retries_left }) => {
            QualifiedSignFailure::WrongPin {
                retries_left: retries_left.get(),
            }
        }
        QualifiedUnlockError::PinRefused(VerifyOutcome::Locked) => QualifiedSignFailure::PinLocked,
        QualifiedUnlockError::PinRefused(VerifyOutcome::Other(_)) => {
            QualifiedSignFailure::VerificationRejected
        }
        // The core never reports an accepted PIN as a refusal.
        QualifiedUnlockError::PinRefused(VerifyOutcome::Ok) => QualifiedSignFailure::Bridge,
        QualifiedUnlockError::Verify(error) => map_preflight_failure(map_auth_error(error)),
        QualifiedUnlockError::Directory(error) => map_directory_error(error),
    }
}

/// DF.ESIGN would not become current, so PIN2 was never sent.
fn map_directory_error<E>(error: Pkcs15Error<E>) -> QualifiedSignFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            QualifiedSignFailure::CardUnavailable
        }
        Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => QualifiedSignFailure::Transport,
        Pkcs15Error::Status(_) => QualifiedSignFailure::SigningRejected,
        Pkcs15Error::Outcome(TransportOutcome::Response(_))
        | Pkcs15Error::Aid(_)
        | Pkcs15Error::Command(_)
        | Pkcs15Error::Empty
        | Pkcs15Error::TooLarge
        | Pkcs15Error::InvalidData(_) => QualifiedSignFailure::Bridge,
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

    use refineid_apdu::iso7816::SelectFile;
    use refineid_apdu::{
        CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
        TransportOutcome,
    };
    use refineid_auth::verify::VERIFY_INS;
    use refineid_auth::{PinReferenceScheme, PinSlot};
    use refineid_digest::Sha384;
    use refineid_sign::commands::{MSE_INS, PSO_INS};
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
    /// Three probes, SELECT MF and SELECT DF.ESIGN precede the PIN2.
    const ORGANIZATION_PIN2_AFTER_PUBLIC_CALLS: usize = 5;
    const VERIFY_INSTRUCTION: u8 = 0x20;
    const INSTRUCTION_OFFSET: usize = 1;
    const REFERENCE_OFFSET: usize = 3;
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
        /// Public commands already sent, and the P2 reference, at each
        /// credential command.
        credentials: Vec<(usize, Option<u8>)>,
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
                credentials: Vec::new(),
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
            let reference = command.expose_wire(|wire| {
                assert_eq!(
                    wire.get(INSTRUCTION_OFFSET).copied(),
                    Some(VERIFY_INSTRUCTION)
                );
                wire.get(REFERENCE_OFFSET).copied()
            });
            self.credentials.push((self.public_calls, reference));
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
    fn an_organization_card_enters_esign_before_pin2_and_signs_inline() {
        let safe = response(status(SAFE_RETRIES), Vec::new());
        let ok = response(StatusWord::Success, Vec::new());
        let mut transport = ScriptedTransport::new(
            vec![
                // The citizen PIN1 reference is absent on an organization
                // card; the organization PIN1 and PIN2 probes answer.
                response(StatusWord::ReferenceDataNotFound, Vec::new()),
                safe.clone(),
                safe,
                ok.clone(),
                ok.clone(),
                ok,
                response(
                    StatusWord::Success,
                    vec![SIGNATURE_FILL; RSA_3072_SIG_BYTES],
                ),
            ],
            StatusWord::Success,
            CardKeyProfile::Rsa3072,
        );

        let result = qualified_sign(
            &mut transport,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Message(SYNTHETIC_CONTENT),
            SYNTHETIC_CERTIFICATE,
        )
        .expect("scripted organization qualified signature succeeds");

        assert_eq!(result.bytes.len(), RSA_3072_SIG_BYTES);
        let instructions: Vec<Option<u8>> = transport
            .public_commands
            .iter()
            .map(|wire| wire.get(INSTRUCTION_OFFSET).copied())
            .collect();
        assert_eq!(
            instructions,
            [
                VERIFY_INS,
                VERIFY_INS,
                VERIFY_INS,
                SelectFile::INS,
                SelectFile::INS,
                MSE_INS,
                PSO_INS
            ]
            .map(Some)
            .to_vec(),
            "probes, SELECT MF, SELECT DF.ESIGN, MSE:Set, one inline PSO:CDS"
        );
        // PIN2 goes out only after both SELECTs, under the organization
        // reference.
        assert_eq!(
            transport.credentials,
            vec![(
                ORGANIZATION_PIN2_AFTER_PUBLIC_CALLS,
                Some(PinReferenceScheme::Organizational.reference(PinSlot::Pin2))
            )]
        );
        let digest = Sha384::of(SYNTHETIC_CONTENT).into_bytes();
        let signing = transport.public_commands.last().expect("a PSO:CDS");
        assert!(
            signing
                .windows(digest.len())
                .any(|window| window == digest.as_slice()),
            "the digest rides inline in PSO:CDS"
        );
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

        assert!(matches!(
            result,
            Err(QualifiedSignFailure::WrongPin {
                retries_left: LOW_RETRIES
            })
        ));
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
