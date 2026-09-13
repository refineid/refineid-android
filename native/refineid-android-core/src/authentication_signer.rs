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

//! One-shot PIN1 verification and authentication-key signing.
//!
//! The input message is hashed in this boundary, then the counter-safe PIN1
//! preflight, the single credential transmission, and the MSE/PSO signing
//! chain run without releasing the card transport. The entered PIN is
//! reconstructed into the public core's non-clonable role type and consumed
//! by exactly one credential command.

use refineid_apdu::{CardTransport, StatusWord, TransportOutcome};
use refineid_auth::{Pin1, PinOps, PinReferenceScheme, UnvalidatedSecret, VerifyOutcome};
use refineid_digest::{Sha256, Sha384, Sha512};
use refineid_sign::{KeyRef, SignError, SignOps, SignScheme};

use crate::pin1_status::{Pin1PreflightFailure, Pin1State, map_auth_error, probe_pin1_preflight};

/// Browser-facing authentication-signature algorithms supported by the
/// reviewed card core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationSigningAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256 and an RSA-3072 authentication key.
    RsaPkcs1Sha256,
    /// RSASSA-PSS with SHA-256 and an RSA-3072 authentication key.
    RsaPssSha256,
    /// ECDSA with SHA-256 and a P-384 authentication key.
    EcdsaP384Sha256,
    /// ECDSA with SHA-384 and a P-384 authentication key.
    EcdsaP384Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-384 and an RSA-3072 authentication key.
    RsaPkcs1Sha384,
    /// RSASSA-PSS with SHA-384 and an RSA-3072 authentication key.
    RsaPssSha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512 and an RSA-3072 authentication key.
    RsaPkcs1Sha512,
    /// RSASSA-PSS with SHA-512 and an RSA-3072 authentication key.
    RsaPssSha512,
}

/// Whether this boundary hashes a message or accepts a caller-asserted digest.
pub(crate) enum AuthenticationSigningInput<'a> {
    /// Hash these complete message bytes with the algorithm's named digest.
    Message(&'a [u8]),
    /// Use these bytes as an already-computed digest after exact-length validation.
    Prehashed(&'a [u8]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparedAuthenticationSigningInput {
    RsaPkcs1Sha256(Sha256),
    RsaPssSha256(Sha256),
    EcdsaP384Sha256(Sha256),
    EcdsaP384Sha384(Sha384),
    RsaPkcs1Sha384(Sha384),
    RsaPssSha384(Sha384),
    RsaPkcs1Sha512(Sha512),
    RsaPssSha512(Sha512),
}

/// Locally shaped signature returned by the card.
pub(crate) struct AuthenticationSignature {
    /// Algorithm that produced the bytes.
    pub(crate) algorithm: AuthenticationSigningAlgorithm,
    /// RSA modulus-wide bytes or raw ECDSA `r || s`.
    pub(crate) bytes: Vec<u8>,
}

impl core::fmt::Debug for AuthenticationSignature {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticationSignature")
            .field("algorithm", &self.algorithm)
            .field("length", &self.bytes.len())
            .finish()
    }
}

impl Drop for AuthenticationSignature {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Coarse one-shot failures safe to encode across JNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationSignFailure {
    /// The submitted PIN1 did not satisfy its local digit predicate.
    InvalidPin,
    /// The live counter state did not permit a consumer authentication try.
    SafetyRefused,
    /// PIN1 is blocked or became exhausted on this attempt.
    PinLocked,
    /// The card rejected the submitted PIN1 without exhausting it.
    WrongPin,
    /// VERIFY returned a status outside the reviewed outcome vocabulary.
    VerificationRejected,
    /// The card rejected or malformed the signing chain.
    SigningRejected,
    /// Card or reader disappeared from the slot.
    CardUnavailable,
    /// Transport state became unusable or indeterminate.
    Transport,
    /// The contactless secure channel refused the CAN.
    PaceRejected,
    /// An impossible local shape reached the bridge.
    Bridge,
}

/// Present one fresh PIN1 exactly once and sign one validated request input.
///
/// FINEID S1 v4.2 sections 3.5, 3.6, 3.7.2.3, and 3.8 govern the sequence:
/// header-only VERIFY preflight, credential VERIFY, MSE:SET DST, PSO:HASH,
/// and PSO:COMPUTE DIGITAL SIGNATURE. No operation may interleave after the
/// hash has been loaded.
pub(crate) fn authenticate_and_sign<T>(
    transport: &mut T,
    algorithm: AuthenticationSigningAlgorithm,
    pin_bytes: Vec<u8>,
    input: AuthenticationSigningInput<'_>,
) -> Result<AuthenticationSignature, AuthenticationSignFailure>
where
    T: CardTransport,
{
    let pin_input = UnvalidatedSecret::from_owned_bytes(pin_bytes);
    let prepared_input = prepare_signing_input(algorithm, input)?;
    let pin = Pin1::reconstruct(pin_input).map_err(|_| AuthenticationSignFailure::InvalidPin)?;
    let preflight = probe_pin1_preflight(transport).map_err(map_preflight_failure)?;
    if !preflight.consumer_authentication_permitted {
        return Err(match preflight.state {
            Pin1State::Locked => AuthenticationSignFailure::PinLocked,
            Pin1State::Verified
            | Pin1State::Remaining(_)
            | Pin1State::NoInformation
            | Pin1State::Unrecognised => AuthenticationSignFailure::SafetyRefused,
        });
    }

    let scheme = sign_scheme(preflight.scheme);

    if preflight.state == Pin1State::Verified {
        match sign_prepared(transport, scheme, prepared_input) {
            Ok(bytes) => return Ok(AuthenticationSignature { algorithm, bytes }),
            Err(SignError::Status(_, StatusWord::SecurityNotSatisfied)) => {
                // The card security context lapsed or requires re-authentication; fall through.
            }
            Err(error) => return Err(map_sign_error(error)),
        }
    }

    let outcome = transport
        .verify_pin1_with_scheme(preflight.scheme, pin)
        .map_err(|error| map_preflight_failure(map_auth_error(error)))?;
    match outcome {
        VerifyOutcome::Ok => {}
        VerifyOutcome::WrongPin { retries_left } if retries_left.is_exhausted() => {
            return Err(AuthenticationSignFailure::PinLocked);
        }
        VerifyOutcome::WrongPin { .. } => return Err(AuthenticationSignFailure::WrongPin),
        VerifyOutcome::Locked => return Err(AuthenticationSignFailure::PinLocked),
        VerifyOutcome::Other(_) => {
            return Err(AuthenticationSignFailure::VerificationRejected);
        }
    }

    let bytes = sign_prepared(transport, scheme, prepared_input).map_err(map_sign_error)?;
    Ok(AuthenticationSignature { algorithm, bytes })
}

fn prepare_signing_input(
    algorithm: AuthenticationSigningAlgorithm,
    input: AuthenticationSigningInput<'_>,
) -> Result<PreparedAuthenticationSigningInput, AuthenticationSignFailure> {
    match algorithm {
        AuthenticationSigningAlgorithm::RsaPkcs1Sha256 => {
            sha256_input(input).map(PreparedAuthenticationSigningInput::RsaPkcs1Sha256)
        }
        AuthenticationSigningAlgorithm::RsaPssSha256 => {
            sha256_input(input).map(PreparedAuthenticationSigningInput::RsaPssSha256)
        }
        AuthenticationSigningAlgorithm::EcdsaP384Sha256 => {
            sha256_input(input).map(PreparedAuthenticationSigningInput::EcdsaP384Sha256)
        }
        AuthenticationSigningAlgorithm::EcdsaP384Sha384 => {
            sha384_input(input).map(PreparedAuthenticationSigningInput::EcdsaP384Sha384)
        }
        AuthenticationSigningAlgorithm::RsaPkcs1Sha384 => {
            sha384_input(input).map(PreparedAuthenticationSigningInput::RsaPkcs1Sha384)
        }
        AuthenticationSigningAlgorithm::RsaPssSha384 => {
            sha384_input(input).map(PreparedAuthenticationSigningInput::RsaPssSha384)
        }
        AuthenticationSigningAlgorithm::RsaPkcs1Sha512 => {
            sha512_input(input).map(PreparedAuthenticationSigningInput::RsaPkcs1Sha512)
        }
        AuthenticationSigningAlgorithm::RsaPssSha512 => {
            sha512_input(input).map(PreparedAuthenticationSigningInput::RsaPssSha512)
        }
    }
}

fn sha256_input(
    input: AuthenticationSigningInput<'_>,
) -> Result<Sha256, AuthenticationSignFailure> {
    match input {
        AuthenticationSigningInput::Message(message) => Ok(Sha256::of(message)),
        AuthenticationSigningInput::Prehashed(digest) => digest
            .try_into()
            .map(Sha256::from_bytes)
            .map_err(|_| AuthenticationSignFailure::Bridge),
    }
}

fn sha384_input(
    input: AuthenticationSigningInput<'_>,
) -> Result<Sha384, AuthenticationSignFailure> {
    match input {
        AuthenticationSigningInput::Message(message) => Ok(Sha384::of(message)),
        AuthenticationSigningInput::Prehashed(digest) => digest
            .try_into()
            .map(Sha384::from_bytes)
            .map_err(|_| AuthenticationSignFailure::Bridge),
    }
}

fn sha512_input(
    input: AuthenticationSigningInput<'_>,
) -> Result<Sha512, AuthenticationSignFailure> {
    match input {
        AuthenticationSigningInput::Message(message) => Ok(Sha512::of(message)),
        AuthenticationSigningInput::Prehashed(digest) => digest
            .try_into()
            .map(Sha512::from_bytes)
            .map_err(|_| AuthenticationSignFailure::Bridge),
    }
}

fn sign_scheme(scheme: PinReferenceScheme) -> SignScheme {
    match scheme {
        PinReferenceScheme::Citizen => SignScheme::Citizen,
        PinReferenceScheme::Organizational => SignScheme::Organizational,
    }
}

fn sign_prepared<T>(
    transport: &mut T,
    scheme: SignScheme,
    input: PreparedAuthenticationSigningInput,
) -> Result<Vec<u8>, SignError<T::Error>>
where
    T: CardTransport,
{
    match input {
        PreparedAuthenticationSigningInput::RsaPkcs1Sha256(digest) => transport
            .sign_prehashed_sha256_rsa(scheme, KeyRef::Auth, digest.into_bytes())
            .map(|signature| signature.into_bytes()),
        PreparedAuthenticationSigningInput::RsaPssSha256(digest) => transport
            .sign_prehashed_sha256_rsa_pss(scheme, KeyRef::Auth, digest.into_bytes())
            .map(|signature| signature.into_bytes()),
        PreparedAuthenticationSigningInput::EcdsaP384Sha256(digest) => transport
            .sign_prehashed_sha256_ecdsa(scheme, KeyRef::Auth, digest.into_bytes())
            .map(|signature| signature.into_bytes()),
        PreparedAuthenticationSigningInput::EcdsaP384Sha384(digest) => transport
            .sign_prehashed_sha384_ecdsa(scheme, KeyRef::Auth, digest.into_bytes())
            .map(|signature| signature.into_bytes()),
        PreparedAuthenticationSigningInput::RsaPkcs1Sha384(digest) => transport
            .sign_prehashed_sha384_rsa(scheme, KeyRef::Auth, digest.into_bytes())
            .map(|signature| signature.into_bytes()),
        PreparedAuthenticationSigningInput::RsaPssSha384(digest) => transport
            .sign_prehashed_sha384_rsa_pss(scheme, KeyRef::Auth, digest.into_bytes())
            .map(|signature| signature.into_bytes()),
        PreparedAuthenticationSigningInput::RsaPkcs1Sha512(digest) => transport
            .sign_prehashed_sha512_rsa(scheme, KeyRef::Auth, digest.into_bytes())
            .map(|signature| signature.into_bytes()),
        PreparedAuthenticationSigningInput::RsaPssSha512(digest) => transport
            .sign_prehashed_sha512_rsa_pss(scheme, KeyRef::Auth, digest.into_bytes())
            .map(|signature| signature.into_bytes()),
    }
}

fn map_preflight_failure(failure: Pin1PreflightFailure) -> AuthenticationSignFailure {
    match failure {
        Pin1PreflightFailure::CardUnavailable => AuthenticationSignFailure::CardUnavailable,
        Pin1PreflightFailure::Transport => AuthenticationSignFailure::Transport,
        Pin1PreflightFailure::Bridge => AuthenticationSignFailure::Bridge,
    }
}

fn map_sign_error<E>(error: SignError<E>) -> AuthenticationSignFailure {
    match error {
        SignError::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            AuthenticationSignFailure::CardUnavailable
        }
        SignError::Transport(_)
        | SignError::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => AuthenticationSignFailure::Transport,
        SignError::Status(_, _) | SignError::UnexpectedSignatureLength { .. } => {
            AuthenticationSignFailure::SigningRejected
        }
        SignError::Outcome(TransportOutcome::Response(_)) | SignError::Command(_) => {
            AuthenticationSignFailure::Bridge
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
    use refineid_digest::SHA256_LEN;
    use refineid_sign::{ECDSA_P384_SIG_BYTES, RSA_3072_SIG_BYTES};

    use super::{
        AuthenticationSignFailure, AuthenticationSigningAlgorithm, AuthenticationSigningInput,
        authenticate_and_sign,
    };

    const SAFE_RETRIES: u8 = 3;
    const LOW_RETRIES: u8 = 2;
    const PUBLIC_VERIFY_CALLS: usize = 1;
    const FULL_RSA_PUBLIC_CALLS: usize = 4;
    const PSO_HASH_PUBLIC_COMMAND_INDEX: usize = 2;
    const VERIFY_INSTRUCTION: u8 = 0x20;
    const INSTRUCTION_OFFSET: usize = 1;
    const SYNTHETIC_PIN: &[u8] = b"1357";
    const SYNTHETIC_MESSAGE: &[u8] = b"authentication request";
    const SYNTHETIC_DIGEST_FILL: u8 = 0x3C;
    const SYNTHETIC_SHA256_DIGEST: [u8; SHA256_LEN] = [SYNTHETIC_DIGEST_FILL; SHA256_LEN];
    const SINGLE_MISSING_BYTE_COUNT: usize = 1;
    const SIGNATURE_FILL: u8 = 0xA5;

    struct ScriptedTransport {
        public_responses: VecDeque<TransportOutcome>,
        public_commands: Vec<Vec<u8>>,
        credential_response: TransportOutcome,
        public_calls: usize,
        credential_calls: usize,
    }

    impl ScriptedTransport {
        fn new(public_responses: Vec<TransportOutcome>, credential_status: StatusWord) -> Self {
            Self {
                public_responses: public_responses.into(),
                public_commands: Vec::new(),
                credential_response: response(credential_status, Vec::new()),
                public_calls: 0,
                credential_calls: 0,
            }
        }
    }

    impl CardTransport for ScriptedTransport {
        type Error = &'static str;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.public_calls += 1;
            self.public_commands.push(command.as_bytes().to_vec());
            if self.public_calls <= PUBLIC_VERIFY_CALLS {
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

    fn rsa_success_script() -> ScriptedTransport {
        let safe = response(status(SAFE_RETRIES), Vec::new());
        ScriptedTransport::new(
            vec![
                safe,
                response(StatusWord::Success, Vec::new()),
                response(StatusWord::Success, Vec::new()),
                response(
                    StatusWord::Success,
                    vec![SIGNATURE_FILL; RSA_3072_SIG_BYTES],
                ),
            ],
            StatusWord::Success,
        )
    }

    #[test]
    fn one_submission_drives_one_verify_then_one_signature_chain() {
        let mut transport = rsa_success_script();

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN.to_vec(),
            AuthenticationSigningInput::Message(SYNTHETIC_MESSAGE),
        )
        .expect("scripted authentication signature succeeds");

        assert_eq!(result.bytes.len(), RSA_3072_SIG_BYTES);
        assert_eq!(transport.credential_calls, 1);
        assert_eq!(transport.public_calls, FULL_RSA_PUBLIC_CALLS);
        assert!(transport.public_responses.is_empty());
    }

    #[test]
    fn an_invalid_submission_never_touches_the_card() {
        let mut transport = rsa_success_script();

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            Vec::new(),
            AuthenticationSigningInput::Message(SYNTHETIC_MESSAGE),
        );

        assert!(matches!(result, Err(AuthenticationSignFailure::InvalidPin)));
        assert_eq!(transport.public_calls, 0);
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn the_retry_floor_refuses_before_the_credential_path() {
        let low = response(status(LOW_RETRIES), Vec::new());
        let mut transport = ScriptedTransport::new(vec![low], StatusWord::Success);

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN.to_vec(),
            AuthenticationSigningInput::Message(SYNTHETIC_MESSAGE),
        );

        assert!(matches!(
            result,
            Err(AuthenticationSignFailure::SafetyRefused)
        ));
        assert_eq!(transport.public_calls, PUBLIC_VERIFY_CALLS);
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn a_wrong_pin_stops_before_mse_and_is_never_replayed() {
        let safe = response(status(SAFE_RETRIES), Vec::new());
        let mut transport = ScriptedTransport::new(vec![safe], status(LOW_RETRIES));

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN.to_vec(),
            AuthenticationSigningInput::Message(SYNTHETIC_MESSAGE),
        );

        assert!(matches!(result, Err(AuthenticationSignFailure::WrongPin)));
        assert_eq!(transport.public_calls, PUBLIC_VERIFY_CALLS);
        assert_eq!(transport.credential_calls, 1);
    }

    #[test]
    fn prehashed_input_reaches_the_card_without_being_hashed_again() {
        let mut transport = rsa_success_script();

        authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN.to_vec(),
            AuthenticationSigningInput::Prehashed(&SYNTHETIC_SHA256_DIGEST),
        )
        .expect("scripted prehashed authentication signature succeeds");

        assert!(
            transport.public_commands[PSO_HASH_PUBLIC_COMMAND_INDEX]
                .ends_with(&SYNTHETIC_SHA256_DIGEST)
        );
    }

    #[test]
    fn malformed_prehashed_input_never_touches_the_card() {
        let mut transport = rsa_success_script();
        let malformed_digest = [SYNTHETIC_DIGEST_FILL; SHA256_LEN - SINGLE_MISSING_BYTE_COUNT];

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN.to_vec(),
            AuthenticationSigningInput::Prehashed(&malformed_digest),
        );

        assert!(matches!(result, Err(AuthenticationSignFailure::Bridge)));
        assert_eq!(transport.public_calls, 0);
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn every_algorithm_has_a_fixed_signature_shape() {
        for (algorithm, signature_length) in [
            (
                AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
                RSA_3072_SIG_BYTES,
            ),
            (
                AuthenticationSigningAlgorithm::RsaPssSha256,
                RSA_3072_SIG_BYTES,
            ),
            (
                AuthenticationSigningAlgorithm::EcdsaP384Sha256,
                ECDSA_P384_SIG_BYTES,
            ),
            (
                AuthenticationSigningAlgorithm::EcdsaP384Sha384,
                ECDSA_P384_SIG_BYTES,
            ),
            (
                AuthenticationSigningAlgorithm::RsaPkcs1Sha384,
                RSA_3072_SIG_BYTES,
            ),
            (
                AuthenticationSigningAlgorithm::RsaPssSha384,
                RSA_3072_SIG_BYTES,
            ),
            (
                AuthenticationSigningAlgorithm::RsaPkcs1Sha512,
                RSA_3072_SIG_BYTES,
            ),
            (
                AuthenticationSigningAlgorithm::RsaPssSha512,
                RSA_3072_SIG_BYTES,
            ),
        ] {
            let safe = response(status(SAFE_RETRIES), Vec::new());
            let mut transport = ScriptedTransport::new(
                vec![
                    safe,
                    response(StatusWord::Success, Vec::new()),
                    response(StatusWord::Success, Vec::new()),
                    response(StatusWord::Success, vec![SIGNATURE_FILL; signature_length]),
                ],
                StatusWord::Success,
            );

            let result = authenticate_and_sign(
                &mut transport,
                algorithm,
                SYNTHETIC_PIN.to_vec(),
                AuthenticationSigningInput::Message(SYNTHETIC_MESSAGE),
            )
            .expect("scripted algorithm succeeds");
            assert_eq!(result.algorithm, algorithm);
            assert_eq!(result.bytes.len(), signature_length);
            assert_eq!(transport.credential_calls, 1);
        }
    }

    #[test]
    fn verified_session_skips_credential_verification_and_signs_directly() {
        let mut transport = ScriptedTransport::new(
            vec![
                response(StatusWord::Success, Vec::new()),
                response(StatusWord::Success, Vec::new()),
                response(StatusWord::Success, Vec::new()),
                response(
                    StatusWord::Success,
                    vec![SIGNATURE_FILL; RSA_3072_SIG_BYTES],
                ),
            ],
            StatusWord::Success,
        );

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN.to_vec(),
            AuthenticationSigningInput::Message(SYNTHETIC_MESSAGE),
        )
        .expect("scripted authentication signature succeeds");

        assert_eq!(result.bytes.len(), RSA_3072_SIG_BYTES);
        assert_eq!(transport.credential_calls, 0);
        assert_eq!(transport.public_calls, FULL_RSA_PUBLIC_CALLS);
        assert!(transport.public_responses.is_empty());
    }

    #[test]
    fn verified_session_falls_back_to_credential_verification_on_security_status_not_satisfied() {
        let mut transport = ScriptedTransport::new(
            vec![
                response(StatusWord::Success, Vec::new()),
                response(StatusWord::SecurityNotSatisfied, Vec::new()),
                response(StatusWord::Success, Vec::new()),
                response(StatusWord::Success, Vec::new()),
                response(
                    StatusWord::Success,
                    vec![SIGNATURE_FILL; RSA_3072_SIG_BYTES],
                ),
            ],
            StatusWord::Success,
        );

        let result = authenticate_and_sign(
            &mut transport,
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN.to_vec(),
            AuthenticationSigningInput::Message(SYNTHETIC_MESSAGE),
        )
        .expect("scripted authentication signature succeeds after fall-through");

        assert_eq!(result.bytes.len(), RSA_3072_SIG_BYTES);
        assert_eq!(transport.credential_calls, 1);
        assert_eq!(transport.public_calls, FULL_RSA_PUBLIC_CALLS + 1);
        assert!(transport.public_responses.is_empty());
    }
}
