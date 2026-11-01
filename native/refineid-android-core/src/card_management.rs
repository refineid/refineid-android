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

//! Card credential management, health probe, and activation (FINEID S4-1 §4.6).

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_auth::{
    ActivationCode, ActivationReport, ActivationScheme, AuthError, CardActivationNeeds,
    CardPinLengths, CredentialHealthReport, CredentialLengths, ManageOutcome, Pin1, Pin2,
    PinManageOps, PinOps, PinReferenceScheme, PinSlot, PinStatus, Puk, UnvalidatedSecret,
    check_retry_floor,
};

use crate::card_certificate::read_authentication_certificate;
use crate::certificate_validity::validity_start_epoch_seconds;

pub(crate) const MANAGEMENT_TAG_BRIDGE_ERROR: u8 = 0;
pub(crate) const MANAGEMENT_TAG_SUCCEEDED: u8 = 1;
pub(crate) const MANAGEMENT_TAG_CARD_UNAVAILABLE: u8 = 2;
pub(crate) const MANAGEMENT_TAG_TRANSPORT_ERROR: u8 = 3;
pub(crate) const MANAGEMENT_TAG_INVALID_CREDENTIAL: u8 = 4;
pub(crate) const MANAGEMENT_TAG_SAFETY_REFUSED: u8 = 5;
pub(crate) const MANAGEMENT_TAG_PACE_REJECTED: u8 = 6;
pub(crate) const MANAGEMENT_TAG_WRONG_CREDENTIAL: u8 = 7;
pub(crate) const MANAGEMENT_TAG_LOCKED: u8 = 8;
pub(crate) const MANAGEMENT_TAG_OTHER: u8 = 9;

pub(crate) const PIN_STATE_VERIFIED: u8 = 1;
pub(crate) const PIN_STATE_REMAINING: u8 = 2;
pub(crate) const PIN_STATE_LOCKED: u8 = 3;
pub(crate) const PIN_STATE_NO_INFO: u8 = 4;
pub(crate) const PIN_STATE_UNRECOGNISED: u8 = 5;

pub(crate) const SCHEME_CITIZEN: u8 = 1;
pub(crate) const SCHEME_ORGANIZATIONAL: u8 = 2;

pub(crate) const ACTIVATION_SCHEME_UNKNOWN: u8 = 0;
pub(crate) const ACTIVATION_SCHEME_PUK: u8 = 1;
pub(crate) const ACTIVATION_SCHEME_PRESET: u8 = 2;

pub(crate) const ACTIVATION_NEEDS_NONE: u8 = 0;
pub(crate) const ACTIVATION_NEEDS_PIN1_ONLY: u8 = 1;
pub(crate) const ACTIVATION_NEEDS_PIN2_ONLY: u8 = 2;
pub(crate) const ACTIVATION_NEEDS_BOTH: u8 = 3;

pub(crate) const NO_RETRY_COUNT: u8 = 0xFF;

/// Octets of a health reply without the PIN and PUK lengths.
#[cfg(test)]
const HEALTH_REPLY_LENGTH: usize = 10;

/// Coarse failures of card management operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardManagementFailure {
    CardUnavailable,
    TransportError,
    BridgeError,
    InvalidCredential,
    SafetyRefused,
    PaceRejected,
}

pub(crate) fn map_auth_error<E>(error: AuthError<E>) -> CardManagementFailure {
    match error {
        AuthError::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            CardManagementFailure::CardUnavailable
        }
        AuthError::Transport(_)
        | AuthError::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => CardManagementFailure::TransportError,
        AuthError::RetryFloor(_) => CardManagementFailure::SafetyRefused,
        AuthError::PinLength(_) => CardManagementFailure::InvalidCredential,
        AuthError::Outcome(TransportOutcome::Response(_)) | AuthError::Command(_) => {
            CardManagementFailure::BridgeError
        }
    }
}

fn encode_pin_status(status: PinStatus) -> (u8, u8) {
    match status {
        PinStatus::Verified => (PIN_STATE_VERIFIED, NO_RETRY_COUNT),
        PinStatus::Remaining(retries) => (PIN_STATE_REMAINING, retries.get()),
        PinStatus::Locked => (PIN_STATE_LOCKED, 0),
        PinStatus::NoInfo => (PIN_STATE_NO_INFO, NO_RETRY_COUNT),
        PinStatus::Other(_) => (PIN_STATE_UNRECOGNISED, NO_RETRY_COUNT),
    }
}

/// The validity start of the authentication certificate on `transport`,
/// or nothing when the certificate or its date cannot be read.
fn authentication_certificate_validity_start<T: CardTransport>(transport: &mut T) -> Option<i64> {
    read_authentication_certificate(transport)
        .ok()
        .and_then(|certificate| validity_start_epoch_seconds(certificate.der().as_bytes()))
}

/// The activation scheme the core decides for the card on `transport`
/// from its resolved credential numbering and `validity_start`, the
/// authentication certificate's notBefore: organization numbering is
/// FINEID S4-1 section 4.6.1 whatever the date, citizen numbering follows
/// the date, and a citizen card without a date has no scheme. A card whose
/// numbering cannot be resolved has no scheme either.
pub(crate) fn decided_activation_scheme<T: CardTransport>(
    transport: &mut T,
    validity_start: Option<i64>,
) -> Option<ActivationScheme> {
    let numbering = transport.resolve_pin_reference_scheme().ok()?;
    ActivationScheme::from_numbering_and_validity_start(numbering, validity_start)
}

/// The wire byte of an activation scheme, or of none.
pub(crate) const fn activation_scheme_byte(scheme: ActivationScheme) -> u8 {
    match scheme {
        ActivationScheme::ActivationCodeIsPuk => ACTIVATION_SCHEME_PUK,
        ActivationScheme::PresetActivationPin => ACTIVATION_SCHEME_PRESET,
    }
}

/// The wire byte of which PINs still await activation.
pub(crate) const fn activation_needs_byte(needs: CardActivationNeeds) -> u8 {
    match (needs.pin1, needs.pin2) {
        (true, true) => ACTIVATION_NEEDS_BOTH,
        (true, false) => ACTIVATION_NEEDS_PIN1_ONLY,
        (false, true) => ACTIVATION_NEEDS_PIN2_ONLY,
        (false, false) => ACTIVATION_NEEDS_NONE,
    }
}

/// The activation scheme a wire byte names, or none.
pub(crate) const fn activation_scheme_from_byte(byte: u8) -> Option<ActivationScheme> {
    match byte {
        ACTIVATION_SCHEME_PUK => Some(ActivationScheme::ActivationCodeIsPuk),
        ACTIVATION_SCHEME_PRESET => Some(ActivationScheme::PresetActivationPin),
        _ => None,
    }
}

/// Whether a health probe also reads the card's PIN and PUK lengths: only
/// the card management screen, where PINs are set, asks for them; a session
/// open that only checks for activation does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinLengthsRead {
    Read,
    Skip,
}

impl PinLengthsRead {
    /// The read a wire flag names: non-zero reads the lengths.
    pub(crate) const fn from_flag(flag: bool) -> Self {
        if flag { Self::Read } else { Self::Skip }
    }
}

/// The health probe's answer: the credential health and, when asked for,
/// the card's PIN and PUK lengths.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CredentialHealthAnswer {
    pub(crate) report: CredentialHealthReport,
    pub(crate) lengths: Option<CardPinLengths>,
}

/// The health probe, with the activation scheme the core decides from the
/// card's numbering and its authentication certificate's validity start,
/// and the card's PIN and PUK lengths when `lengths_read` asks for them.
pub(crate) fn probe_credential_health<T: CardTransport>(
    transport: &mut T,
    lengths_read: PinLengthsRead,
) -> Result<CredentialHealthAnswer, CardManagementFailure> {
    let validity_start = authentication_certificate_validity_start(transport);
    let report = transport
        .probe_credential_health(validity_start)
        .map_err(map_auth_error)?;
    let lengths = match lengths_read {
        PinLengthsRead::Read => Some(read_lengths(transport)?),
        PinLengthsRead::Skip => None,
    };
    Ok(CredentialHealthAnswer { report, lengths })
}

/// The PIN and PUK lengths of the card on `transport`, read where PINs are
/// set.
fn read_lengths<T: CardTransport>(
    transport: &mut T,
) -> Result<CardPinLengths, CardManagementFailure> {
    transport.read_card_pin_lengths().map_err(map_auth_error)
}

/// The wire pair of one credential's accepted lengths: minimum and maximum,
/// or zero and zero when the card accepts no length for it.
fn encode_credential_lengths(lengths: CredentialLengths) -> [u8; 2] {
    lengths.accepted().map_or([0, 0], |range| {
        [
            u8::try_from(range.min()).unwrap_or(0),
            u8::try_from(range.max()).unwrap_or(0),
        ]
    })
}

/// Encode the health probe's answer to native byte array.
pub(crate) fn encode_credential_health_reply(
    result: Result<CredentialHealthAnswer, CardManagementFailure>,
) -> Vec<u8> {
    match result {
        Ok(CredentialHealthAnswer { report, lengths }) => {
            let (p1_state, p1_retries) = encode_pin_status(report.pin1_status);
            let (p2_state, p2_retries) = encode_pin_status(report.pin2_status);
            let (puk_state, puk_retries) = encode_pin_status(report.puk_status);
            let scheme_byte = match report.pin_reference_scheme {
                PinReferenceScheme::Citizen => SCHEME_CITIZEN,
                PinReferenceScheme::Organizational => SCHEME_ORGANIZATIONAL,
            };
            let act_scheme_byte = report
                .activation_scheme
                .map_or(ACTIVATION_SCHEME_UNKNOWN, activation_scheme_byte);
            let act_needs_byte = report
                .activation_needs
                .map_or(ACTIVATION_NEEDS_NONE, activation_needs_byte);
            let mut reply = vec![
                MANAGEMENT_TAG_SUCCEEDED,
                p1_state,
                p1_retries,
                p2_state,
                p2_retries,
                puk_state,
                puk_retries,
                scheme_byte,
                act_scheme_byte,
                act_needs_byte,
            ];
            if let Some(lengths) = lengths {
                reply.extend_from_slice(&encode_credential_lengths(lengths.pin1()));
                reply.extend_from_slice(&encode_credential_lengths(lengths.pin2()));
                reply.extend_from_slice(&encode_credential_lengths(lengths.puk()));
            }
            reply
        }
        Err(CardManagementFailure::CardUnavailable) => vec![MANAGEMENT_TAG_CARD_UNAVAILABLE],
        Err(CardManagementFailure::TransportError) => vec![MANAGEMENT_TAG_TRANSPORT_ERROR],
        Err(CardManagementFailure::BridgeError) => vec![MANAGEMENT_TAG_BRIDGE_ERROR],
        Err(CardManagementFailure::InvalidCredential) => vec![MANAGEMENT_TAG_INVALID_CREDENTIAL],
        Err(CardManagementFailure::SafetyRefused) => vec![MANAGEMENT_TAG_SAFETY_REFUSED],
        Err(CardManagementFailure::PaceRejected) => vec![MANAGEMENT_TAG_PACE_REJECTED],
    }
}

/// Refuse a command that presents the current `slot` PIN unless the core
/// retry floor serves it; the status query spends no attempt.
fn require_retry_floor<T: CardTransport>(
    transport: &mut T,
    slot: PinSlot,
) -> Result<(), CardManagementFailure> {
    let status = transport.pin_status(slot).map_err(map_auth_error)?;
    check_retry_floor(slot.into(), status).map_err(|_| CardManagementFailure::SafetyRefused)
}

/// Execute change PIN1.
pub(crate) fn change_pin1<T: CardTransport>(
    transport: &mut T,
    mut current_bytes: Vec<u8>,
    mut new_bytes: Vec<u8>,
) -> Result<ManageOutcome, CardManagementFailure> {
    let current_sec = UnvalidatedSecret::from_owned_bytes(current_bytes.clone());
    let new_sec = UnvalidatedSecret::from_owned_bytes(new_bytes.clone());
    current_bytes.fill(0);
    new_bytes.fill(0);

    let current_pin =
        Pin1::reconstruct(current_sec).map_err(|_| CardManagementFailure::InvalidCredential)?;
    let new_pin =
        Pin1::reconstruct(new_sec).map_err(|_| CardManagementFailure::InvalidCredential)?;

    let lengths = read_lengths(transport)?;
    require_retry_floor(transport, PinSlot::Pin1)?;
    transport
        .change_pin1(&lengths, current_pin, new_pin)
        .map_err(map_auth_error)
}

/// Execute change PIN2.
pub(crate) fn change_pin2<T: CardTransport>(
    transport: &mut T,
    mut current_bytes: Vec<u8>,
    mut new_bytes: Vec<u8>,
) -> Result<ManageOutcome, CardManagementFailure> {
    let current_sec = UnvalidatedSecret::from_owned_bytes(current_bytes.clone());
    let new_sec = UnvalidatedSecret::from_owned_bytes(new_bytes.clone());
    current_bytes.fill(0);
    new_bytes.fill(0);

    let current_pin =
        Pin2::reconstruct(current_sec).map_err(|_| CardManagementFailure::InvalidCredential)?;
    let new_pin =
        Pin2::reconstruct(new_sec).map_err(|_| CardManagementFailure::InvalidCredential)?;

    let lengths = read_lengths(transport)?;
    require_retry_floor(transport, PinSlot::Pin2)?;
    transport
        .change_pin2(&lengths, current_pin, new_pin)
        .map_err(map_auth_error)
}

/// Execute unblock / reset PIN1.
pub(crate) fn unblock_pin1<T: CardTransport>(
    transport: &mut T,
    mut puk_bytes: Vec<u8>,
    mut new_bytes: Vec<u8>,
) -> Result<ManageOutcome, CardManagementFailure> {
    let puk_sec = UnvalidatedSecret::from_owned_bytes(puk_bytes.clone());
    let new_sec = UnvalidatedSecret::from_owned_bytes(new_bytes.clone());
    puk_bytes.fill(0);
    new_bytes.fill(0);

    let puk = Puk::reconstruct(puk_sec).map_err(|_| CardManagementFailure::InvalidCredential)?;
    let new_pin =
        Pin1::reconstruct(new_sec).map_err(|_| CardManagementFailure::InvalidCredential)?;

    let lengths = read_lengths(transport)?;
    transport
        .unblock_pin1(&lengths, puk, new_pin)
        .map_err(map_auth_error)
}

/// Execute unblock / reset PIN2.
pub(crate) fn unblock_pin2<T: CardTransport>(
    transport: &mut T,
    mut puk_bytes: Vec<u8>,
    mut new_bytes: Vec<u8>,
) -> Result<ManageOutcome, CardManagementFailure> {
    let puk_sec = UnvalidatedSecret::from_owned_bytes(puk_bytes.clone());
    let new_sec = UnvalidatedSecret::from_owned_bytes(new_bytes.clone());
    puk_bytes.fill(0);
    new_bytes.fill(0);

    let puk = Puk::reconstruct(puk_sec).map_err(|_| CardManagementFailure::InvalidCredential)?;
    let new_pin =
        Pin2::reconstruct(new_sec).map_err(|_| CardManagementFailure::InvalidCredential)?;

    let lengths = read_lengths(transport)?;
    transport
        .unblock_pin2(&lengths, puk, new_pin)
        .map_err(map_auth_error)
}

/// Encode `ManageOutcome` to native byte array.
pub(crate) fn encode_manage_outcome_reply(
    result: Result<ManageOutcome, CardManagementFailure>,
) -> Vec<u8> {
    match result {
        Ok(ManageOutcome::Ok) => vec![MANAGEMENT_TAG_SUCCEEDED, 0, 0, 0],
        Ok(ManageOutcome::WrongCredential { retries_left }) => {
            vec![MANAGEMENT_TAG_WRONG_CREDENTIAL, retries_left.get(), 0, 0]
        }
        Ok(ManageOutcome::Locked) => vec![MANAGEMENT_TAG_LOCKED, 0, 0, 0],
        Ok(ManageOutcome::Other(sw)) => {
            let raw = sw.as_u16();
            let sw1 = (raw >> 8) as u8;
            let sw2 = (raw & 0xFF) as u8;
            vec![MANAGEMENT_TAG_OTHER, 0, sw1, sw2]
        }
        Err(CardManagementFailure::CardUnavailable) => vec![MANAGEMENT_TAG_CARD_UNAVAILABLE],
        Err(CardManagementFailure::TransportError) => vec![MANAGEMENT_TAG_TRANSPORT_ERROR],
        Err(CardManagementFailure::BridgeError) => vec![MANAGEMENT_TAG_BRIDGE_ERROR],
        Err(CardManagementFailure::InvalidCredential) => vec![MANAGEMENT_TAG_INVALID_CREDENTIAL],
        Err(CardManagementFailure::SafetyRefused) => vec![MANAGEMENT_TAG_SAFETY_REFUSED],
        Err(CardManagementFailure::PaceRejected) => vec![MANAGEMENT_TAG_PACE_REJECTED],
    }
}

/// Execute card activation.
pub(crate) fn activate_card<T: CardTransport>(
    transport: &mut T,
    scheme_byte: u8,
    code_bytes: Vec<u8>,
    new_pin1_bytes: Option<Vec<u8>>,
    new_pin2_bytes: Option<Vec<u8>>,
) -> Result<ActivationReport, CardManagementFailure> {
    // Each entry is wrapped at once, so every early return below wipes it.
    let code_sec = UnvalidatedSecret::from_owned_bytes(code_bytes);
    let new_pin1_sec = new_pin1_bytes.map(UnvalidatedSecret::from_owned_bytes);
    let new_pin2_sec = new_pin2_bytes.map(UnvalidatedSecret::from_owned_bytes);

    // The caller names the scheme the health probe or the open decided;
    // without one there is no activation attempt. The code is validated
    // against that scheme and carries it to the core, which sends the
    // scheme's command chain.
    let scheme =
        activation_scheme_from_byte(scheme_byte).ok_or(CardManagementFailure::SafetyRefused)?;
    let code = ActivationCode::reconstruct(code_sec, scheme)
        .map_err(|_| CardManagementFailure::InvalidCredential)?;
    let new_pin1 = new_pin1_sec
        .map(Pin1::reconstruct)
        .transpose()
        .map_err(|_| CardManagementFailure::InvalidCredential)?;
    let new_pin2 = new_pin2_sec
        .map(Pin2::reconstruct)
        .transpose()
        .map_err(|_| CardManagementFailure::InvalidCredential)?;

    let lengths = read_lengths(transport)?;
    transport
        .activate_card(&lengths, code, new_pin1, new_pin2)
        .map_err(map_auth_error)
}

fn outcome_to_pair(outcome: Option<ManageOutcome>) -> (u8, u8) {
    match outcome {
        None => (0, 0),
        Some(ManageOutcome::Ok) => (MANAGEMENT_TAG_SUCCEEDED, 0),
        Some(ManageOutcome::WrongCredential { retries_left }) => {
            (MANAGEMENT_TAG_WRONG_CREDENTIAL, retries_left.get())
        }
        Some(ManageOutcome::Locked) => (MANAGEMENT_TAG_LOCKED, 0),
        Some(ManageOutcome::Other(_)) => (MANAGEMENT_TAG_OTHER, 0),
    }
}

/// Encode `ActivationReport` to native byte array.
pub(crate) fn encode_activation_reply(
    result: Result<ActivationReport, CardManagementFailure>,
) -> Vec<u8> {
    match result {
        Ok(report) => {
            let scheme_byte = match report.scheme {
                ActivationScheme::ActivationCodeIsPuk => ACTIVATION_SCHEME_PUK,
                ActivationScheme::PresetActivationPin => ACTIVATION_SCHEME_PRESET,
            };
            let (p1_tag, p1_retries) = outcome_to_pair(report.pin1);
            let (p2_tag, p2_retries) = outcome_to_pair(report.pin2);
            vec![
                MANAGEMENT_TAG_SUCCEEDED,
                scheme_byte,
                p1_tag,
                p1_retries,
                p2_tag,
                p2_retries,
            ]
        }
        Err(CardManagementFailure::CardUnavailable) => vec![MANAGEMENT_TAG_CARD_UNAVAILABLE],
        Err(CardManagementFailure::TransportError) => vec![MANAGEMENT_TAG_TRANSPORT_ERROR],
        Err(CardManagementFailure::BridgeError) => vec![MANAGEMENT_TAG_BRIDGE_ERROR],
        Err(CardManagementFailure::InvalidCredential) => vec![MANAGEMENT_TAG_INVALID_CREDENTIAL],
        Err(CardManagementFailure::SafetyRefused) => vec![MANAGEMENT_TAG_SAFETY_REFUSED],
        Err(CardManagementFailure::PaceRejected) => vec![MANAGEMENT_TAG_PACE_REJECTED],
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use refineid_apdu::iso7816::SelectFile;
    use refineid_apdu::{CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord};
    use refineid_auth::credentials::{
        FINEID_PIN1_MIN_LENGTH, FINEID_PIN2_MIN_LENGTH, PIN_MAX_LENGTH, PUK_MAX_LENGTH,
        PUK_MIN_LENGTH,
    };
    use refineid_auth::{CardActivationNeeds, FlooredCredential};

    const SYNTHETIC_PIN1: &[u8] = b"1357";
    const SYNTHETIC_NEW_PIN1: &[u8] = b"2468";
    const SYNTHETIC_PIN2: &[u8] = b"135790";
    const SYNTHETIC_NEW_PIN2: &[u8] = b"246802";
    const SYNTHETIC_PUK: &[u8] = b"97531864";
    const SERVED_RETRIES: u8 = 3;
    const BELOW_FLOOR_RETRIES: u8 = 2;
    const LAST_RETRY: u8 = 1;
    const NO_RETRIES: u8 = 0;
    /// Public commands a PIN 2 change sends after the PIN length read and
    /// before it presents the current PIN, each answered here with a served
    /// retry count.
    const PIN2_CHANGE_PUBLIC_COMMANDS: usize = 2;

    /// Offset of the instruction byte in a command's wire bytes.
    const INSTRUCTION_OFFSET: usize = 1;

    /// Answers public commands from a script and records every credential
    /// command without answering it. A SELECT is answered file not found
    /// without taking a scripted answer, so the PIN length read finds no
    /// EF.AOD.
    struct ScriptedTransport {
        responses: VecDeque<StatusWord>,
        credential_calls: usize,
    }

    impl ScriptedTransport {
        fn new(statuses: &[StatusWord]) -> Self {
            Self {
                responses: statuses.iter().copied().collect(),
                credential_calls: 0,
            }
        }
    }

    impl CardTransport for ScriptedTransport {
        type Error = &'static str;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let status = if command.as_bytes().get(INSTRUCTION_OFFSET) == Some(&SelectFile::INS) {
                StatusWord::FileNotFound
            } else {
                self.responses
                    .pop_front()
                    .ok_or("missing scripted response")?
            };
            let [sw1, sw2] = status.as_u16().to_be_bytes();
            Ok(TransportOutcome::Response(ResponseApdu {
                body: Vec::new(),
                sw1,
                sw2,
            }))
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.credential_calls += 1;
            Err("a refused change must not present a credential")
        }
    }

    fn remaining(value: u8) -> StatusWord {
        StatusWord::PinIncorrect {
            retries: PinRetries::from_nibble(value).expect("test retry value fits a nibble"),
        }
    }

    /// The answer a citizen card gives each PIN container read of the PIN
    /// length read: no PIN policy.
    const NO_PIN_POLICY: StatusWord = StatusWord::ReferenceDataNotFound;

    /// PIN container reads of the citizen PIN length read: PIN 1, PIN 2,
    /// the PUK.
    const CITIZEN_PIN_POLICY_READS: usize = 3;

    /// The answers of the PIN length read on a card whose numbering
    /// `resolution` resolves: the numbering, then on a citizen card one PIN
    /// container read per credential, as EF.AOD is not found.
    fn lengths_read(resolution: &[StatusWord]) -> Vec<StatusWord> {
        let mut answers = resolution.to_vec();
        if resolution != organizational_resolution().as_slice() {
            answers.extend([NO_PIN_POLICY; CITIZEN_PIN_POLICY_READS]);
        }
        answers
    }

    /// `transcript` after the PIN length read of a citizen card.
    fn after_citizen_lengths_read(transcript: &[StatusWord]) -> Vec<StatusWord> {
        let mut answers = lengths_read(&[remaining(SERVED_RETRIES)]);
        answers.extend_from_slice(transcript);
        answers
    }

    fn refused_statuses() -> [StatusWord; 5] {
        [
            remaining(BELOW_FLOOR_RETRIES),
            remaining(LAST_RETRY),
            remaining(NO_RETRIES),
            StatusWord::AuthenticationBlocked,
            StatusWord::AuthenticationFailed,
        ]
    }

    #[test]
    fn change_pin1_is_refused_below_the_retry_floor_without_presenting_it() {
        for status in refused_statuses() {
            let mut transport = ScriptedTransport::new(&after_citizen_lengths_read(&[status]));

            let result = change_pin1(
                &mut transport,
                SYNTHETIC_PIN1.to_vec(),
                SYNTHETIC_NEW_PIN1.to_vec(),
            );

            assert_eq!(result, Err(CardManagementFailure::SafetyRefused));
            assert_eq!(transport.credential_calls, 0);
        }
    }

    #[test]
    fn change_pin2_is_refused_below_the_retry_floor_without_presenting_it() {
        for status in refused_statuses() {
            let mut transport = ScriptedTransport::new(&after_citizen_lengths_read(&[
                remaining(SERVED_RETRIES),
                status,
            ]));

            let result = change_pin2(
                &mut transport,
                SYNTHETIC_PIN2.to_vec(),
                SYNTHETIC_NEW_PIN2.to_vec(),
            );

            assert_eq!(result, Err(CardManagementFailure::SafetyRefused));
            assert_eq!(transport.credential_calls, 0);
        }
    }

    #[test]
    fn change_pin1_at_the_floor_reaches_the_card() {
        let mut transport =
            ScriptedTransport::new(&after_citizen_lengths_read(&[remaining(SERVED_RETRIES)]));

        let result = change_pin1(
            &mut transport,
            SYNTHETIC_PIN1.to_vec(),
            SYNTHETIC_NEW_PIN1.to_vec(),
        );

        assert_eq!(result, Err(CardManagementFailure::TransportError));
        assert_eq!(transport.credential_calls, 1);
        assert!(transport.responses.is_empty());
    }

    #[test]
    fn change_pin2_at_the_floor_reaches_the_card() {
        let mut transport = ScriptedTransport::new(&after_citizen_lengths_read(
            &[remaining(SERVED_RETRIES); PIN2_CHANGE_PUBLIC_COMMANDS],
        ));

        let result = change_pin2(
            &mut transport,
            SYNTHETIC_PIN2.to_vec(),
            SYNTHETIC_NEW_PIN2.to_vec(),
        );

        assert_eq!(result, Err(CardManagementFailure::TransportError));
        assert_eq!(transport.credential_calls, 1);
        assert!(transport.responses.is_empty());
    }

    /// The answer the citizen numbering gives the PIN 1 resolution probe
    /// when the target PIN is blocked, as it is before an unblock.
    const CITIZEN_TARGET_BLOCKED: StatusWord = StatusWord::AuthenticationBlocked;

    /// Answers that resolve the citizen numbering, with the target PIN
    /// served or blocked; the target PIN's counter does not gate the PUK.
    fn citizen_resolutions() -> [Vec<StatusWord>; 2] {
        [
            vec![remaining(SERVED_RETRIES)],
            vec![CITIZEN_TARGET_BLOCKED],
        ]
    }

    /// Answers that resolve the organizational numbering: the citizen
    /// reference is not found and the organizational one answers.
    fn organizational_resolution() -> Vec<StatusWord> {
        vec![StatusWord::ReferenceDataNotFound, remaining(SERVED_RETRIES)]
    }

    /// PUK counter answers the floor refuses under either numbering.
    fn refused_puk_counters() -> [StatusWord; 4] {
        [
            remaining(BELOW_FLOOR_RETRIES),
            remaining(LAST_RETRY),
            remaining(NO_RETRIES),
            StatusWord::AuthenticationBlocked,
        ]
    }

    /// Every transcript, up to and including the PUK counter read, that
    /// the floor refuses: low, exhausted and blocked counters under both
    /// numberings and with the target PIN served or blocked; a citizen
    /// probe reporting verified or no counter, whose PIN container read
    /// carries no counter either; an organizational PUK reported verified
    /// or answering without a counter.
    fn refused_puk_transcripts() -> Vec<Vec<StatusWord>> {
        let mut transcripts = Vec::new();
        let resolutions = citizen_resolutions()
            .into_iter()
            .chain([organizational_resolution()]);
        for resolution in resolutions {
            for counter in refused_puk_counters() {
                let mut transcript = lengths_read(&resolution);
                transcript.push(counter);
                transcripts.push(transcript);
            }
        }
        for probe in [StatusWord::Success, StatusWord::AuthenticationFailed] {
            transcripts.push(after_citizen_lengths_read(&[probe, StatusWord::Success]));
        }
        for probe in [StatusWord::Success, StatusWord::AuthenticationFailed] {
            let mut transcript = lengths_read(&organizational_resolution());
            transcript.push(probe);
            transcripts.push(transcript);
        }
        transcripts
    }

    /// Transcripts the floor serves: the PUK at the floor under each
    /// numbering, with the target PIN served or blocked.
    fn served_puk_transcripts() -> Vec<Vec<StatusWord>> {
        citizen_resolutions()
            .into_iter()
            .chain([organizational_resolution()])
            .map(|resolution| {
                let mut transcript = lengths_read(&resolution);
                transcript.push(remaining(SERVED_RETRIES));
                transcript
            })
            .collect()
    }

    type Unblock = fn(
        &mut ScriptedTransport,
        Vec<u8>,
        Vec<u8>,
    ) -> Result<ManageOutcome, CardManagementFailure>;

    /// Both unblock operations with a valid new PIN for the target.
    fn unblocks() -> [(Unblock, &'static [u8]); 2] {
        [
            (unblock_pin1 as Unblock, SYNTHETIC_NEW_PIN1),
            (unblock_pin2 as Unblock, SYNTHETIC_NEW_PIN2),
        ]
    }

    #[test]
    fn unblock_is_refused_below_the_puk_retry_floor_without_presenting_it() {
        for (unblock, new_pin) in unblocks() {
            for transcript in refused_puk_transcripts() {
                let mut transport = ScriptedTransport::new(&transcript);

                let result = unblock(&mut transport, SYNTHETIC_PUK.to_vec(), new_pin.to_vec());

                assert_eq!(
                    result,
                    Err(CardManagementFailure::SafetyRefused),
                    "{transcript:?}"
                );
                assert_eq!(transport.credential_calls, 0);
                assert!(transport.responses.is_empty(), "{transcript:?}");
            }
        }
    }

    #[test]
    fn unblock_at_the_puk_floor_reaches_the_card() {
        for (unblock, new_pin) in unblocks() {
            for transcript in served_puk_transcripts() {
                let mut transport = ScriptedTransport::new(&transcript);

                let result = unblock(&mut transport, SYNTHETIC_PUK.to_vec(), new_pin.to_vec());

                assert_eq!(result, Err(CardManagementFailure::TransportError));
                assert_eq!(transport.credential_calls, 1);
                assert!(transport.responses.is_empty());
            }
        }
    }

    /// Answers a citizen card awaiting activation by PUK gives after the
    /// PIN length read and before the PUK counter read: for PIN 1 and
    /// PIN 2 the PIN container read, which leaves the changed flag
    /// unreadable, and the status probes, every PIN blocked.
    const PUK_ACTIVATION_PREAMBLE: [StatusWord; 5] = [StatusWord::AuthenticationBlocked; 5];

    fn activate_by_puk(
        transport: &mut ScriptedTransport,
    ) -> Result<ActivationReport, CardManagementFailure> {
        activate_card(
            transport,
            ACTIVATION_SCHEME_PUK,
            SYNTHETIC_PUK.to_vec(),
            Some(SYNTHETIC_NEW_PIN1.to_vec()),
            Some(SYNTHETIC_NEW_PIN2.to_vec()),
        )
    }

    #[test]
    fn activation_by_puk_is_refused_below_the_puk_retry_floor_without_presenting_it() {
        for counter in refused_puk_counters() {
            let mut transcript = lengths_read(&[CITIZEN_TARGET_BLOCKED]);
            transcript.extend(PUK_ACTIVATION_PREAMBLE);
            transcript.push(counter);
            let mut transport = ScriptedTransport::new(&transcript);

            let result = activate_by_puk(&mut transport);

            assert_eq!(result, Err(CardManagementFailure::SafetyRefused));
            assert_eq!(transport.credential_calls, 0);
            assert!(transport.responses.is_empty());
        }
    }

    #[test]
    fn activation_by_puk_at_the_puk_floor_reaches_the_card() {
        let mut transcript = lengths_read(&[CITIZEN_TARGET_BLOCKED]);
        transcript.extend(PUK_ACTIVATION_PREAMBLE);
        transcript.push(remaining(SERVED_RETRIES));
        let mut transport = ScriptedTransport::new(&transcript);

        let result = activate_by_puk(&mut transport);

        assert_eq!(result, Err(CardManagementFailure::TransportError));
        assert_eq!(transport.credential_calls, 1);
        assert!(transport.responses.is_empty());
    }

    /// 13 January 2026 00:00:00 UTC, the citizen cutover, and the second
    /// before it.
    const CUTOVER_EPOCH_SECONDS: i64 = 1_768_262_400;
    const BEFORE_CUTOVER_EPOCH_SECONDS: i64 = CUTOVER_EPOCH_SECONDS - 1;

    /// Validity starts on both sides of the cutover, and none read.
    const VALIDITY_STARTS: [Option<i64>; 3] = [
        Some(BEFORE_CUTOVER_EPOCH_SECONDS),
        Some(CUTOVER_EPOCH_SECONDS),
        None,
    ];

    #[test]
    fn organization_numbering_takes_the_activation_code_whatever_the_date() {
        for validity_start in VALIDITY_STARTS {
            let mut transport = ScriptedTransport::new(&organizational_resolution());

            let scheme = decided_activation_scheme(&mut transport, validity_start);

            assert_eq!(
                scheme,
                Some(ActivationScheme::ActivationCodeIsPuk),
                "{validity_start:?}"
            );
            assert!(transport.responses.is_empty());
            assert_eq!(transport.credential_calls, 0);
        }
    }

    #[test]
    fn citizen_numbering_follows_the_validity_start() {
        let expected = [
            Some(ActivationScheme::ActivationCodeIsPuk),
            Some(ActivationScheme::PresetActivationPin),
            None,
        ];
        for (validity_start, expected) in VALIDITY_STARTS.into_iter().zip(expected) {
            let mut transport = ScriptedTransport::new(&[remaining(SERVED_RETRIES)]);

            let scheme = decided_activation_scheme(&mut transport, validity_start);

            assert_eq!(scheme, expected, "{validity_start:?}");
            assert!(transport.responses.is_empty());
        }
    }

    #[test]
    fn unresolved_numbering_decides_no_scheme() {
        let mut transport = ScriptedTransport::new(&[]);

        assert_eq!(
            decided_activation_scheme(&mut transport, Some(CUTOVER_EPOCH_SECONDS)),
            None
        );
    }

    #[test]
    fn activation_without_a_scheme_is_refused_without_reaching_the_card() {
        let mut transport = ScriptedTransport::new(&[]);

        let result = activate_card(
            &mut transport,
            ACTIVATION_SCHEME_UNKNOWN,
            SYNTHETIC_PUK.to_vec(),
            Some(SYNTHETIC_NEW_PIN1.to_vec()),
            Some(SYNTHETIC_NEW_PIN2.to_vec()),
        );

        assert_eq!(result, Err(CardManagementFailure::SafetyRefused));
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn an_activation_code_of_the_other_scheme_length_is_refused_without_reaching_the_card() {
        let mut transport = ScriptedTransport::new(&[]);

        let result = activate_card(
            &mut transport,
            ACTIVATION_SCHEME_PRESET,
            SYNTHETIC_PUK.to_vec(),
            Some(SYNTHETIC_NEW_PIN1.to_vec()),
            Some(SYNTHETIC_NEW_PIN2.to_vec()),
        );

        assert_eq!(result, Err(CardManagementFailure::InvalidCredential));
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn a_retry_floor_refusal_maps_to_the_safety_refusal() {
        let refusal = check_retry_floor(FlooredCredential::Puk, PinStatus::Locked)
            .expect_err("a blocked PUK is refused");
        assert_eq!(
            map_auth_error::<&str>(AuthError::RetryFloor(refusal)),
            CardManagementFailure::SafetyRefused
        );
    }

    #[test]
    fn encodes_credential_health_success() {
        let retries = PinRetries::from_nibble(3).expect("3 fits nibble");
        let report = CredentialHealthReport {
            pin1_status: PinStatus::Remaining(retries),
            pin2_status: PinStatus::Remaining(retries),
            puk_status: PinStatus::Remaining(retries),
            pin_reference_scheme: PinReferenceScheme::Citizen,
            activation_scheme: Some(ActivationScheme::PresetActivationPin),
            activation_needs: Some(CardActivationNeeds {
                pin1: true,
                pin2: true,
            }),
        };
        let encoded = encode_credential_health_reply(Ok(CredentialHealthAnswer {
            report,
            lengths: None,
        }));
        assert_eq!(encoded.len(), HEALTH_REPLY_LENGTH);
        assert_eq!(encoded[0], MANAGEMENT_TAG_SUCCEEDED);
        assert_eq!(encoded[1], PIN_STATE_REMAINING);
        assert_eq!(encoded[2], 3);
        assert_eq!(encoded[7], SCHEME_CITIZEN);
        assert_eq!(encoded[8], ACTIVATION_SCHEME_PRESET);
        assert_eq!(encoded[9], ACTIVATION_NEEDS_BOTH);

        let encoded = encode_credential_health_reply(Ok(CredentialHealthAnswer {
            report,
            lengths: Some(CardPinLengths::not_listed(PinReferenceScheme::Citizen)),
        }));
        assert_eq!(
            encoded[HEALTH_REPLY_LENGTH..],
            [
                FINEID_PIN1_MIN_LENGTH,
                PIN_MAX_LENGTH,
                FINEID_PIN2_MIN_LENGTH,
                PIN_MAX_LENGTH,
                PUK_MIN_LENGTH,
                PUK_MAX_LENGTH,
            ]
            .map(|length| u8::try_from(length).expect("a FINEID bound fits one octet"))
        );
    }

    #[test]
    fn a_length_refusal_maps_to_the_invalid_credential() {
        let refusal = CardPinLengths::not_listed(PinReferenceScheme::Citizen)
            .check_pin2(
                &Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(SYNTHETIC_PIN1.to_vec()))
                    .expect("four digits are a PIN 2 entry"),
            )
            .expect_err("four digits are below the FINEID PIN 2 bound");
        assert_eq!(
            map_auth_error::<&str>(AuthError::PinLength(refusal)),
            CardManagementFailure::InvalidCredential
        );
    }

    #[test]
    fn encodes_manage_outcome_wrong_pin() {
        let retries = PinRetries::from_nibble(2).expect("2 fits nibble");
        let encoded = encode_manage_outcome_reply(Ok(ManageOutcome::WrongCredential {
            retries_left: retries,
        }));
        assert_eq!(encoded[0], MANAGEMENT_TAG_WRONG_CREDENTIAL);
        assert_eq!(encoded[1], 2);
    }

    #[test]
    fn encodes_activation_report() {
        let report = ActivationReport {
            scheme: ActivationScheme::PresetActivationPin,
            pin1: Some(ManageOutcome::Ok),
            pin2: Some(ManageOutcome::Ok),
        };
        let encoded = encode_activation_reply(Ok(report));
        assert_eq!(encoded[0], MANAGEMENT_TAG_SUCCEEDED);
        assert_eq!(encoded[1], ACTIVATION_SCHEME_PRESET);
        assert_eq!(encoded[2], MANAGEMENT_TAG_SUCCEEDED);
        assert_eq!(encoded[4], MANAGEMENT_TAG_SUCCEEDED);
    }
}
