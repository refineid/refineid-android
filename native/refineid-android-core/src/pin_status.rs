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

//! Counter-safe PIN1 and PIN2 status preflight for one selected PKCS#15 session.
//!
//! FINEID S1 v4.2 section 3.5.1.1 defines header-only `VERIFY` as a
//! status query. It carries no credential and does not perform a PIN
//! comparison. The resolved reference scheme is retained beside the status so
//! a later credential or signing operation uses the same card-proven numbering.

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_auth::{
    AuthError, FlooredCredential, PinOps, PinReferenceScheme, PinSlot, PinStatus, check_retry_floor,
};

/// Counter-safe PIN state, with unrecognised status words erased at this
/// boundary rather than exposed as raw card values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinState {
    /// The PIN is already verified in this card session.
    Verified,
    /// The PIN is not verified and has this many attempts remaining.
    Remaining(u8),
    /// The PIN is blocked or invalidated.
    Locked,
    /// The card supplied no retry counter.
    NoInformation,
    /// The card supplied a status outside the reviewed PIN vocabulary.
    Unrecognised,
}

/// One resolved, counter-safe PIN preflight result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinPreflight {
    /// Credential-reference numbering proven by the card.
    pub(crate) scheme: PinReferenceScheme,
    /// Live PIN state from the header-only `VERIFY` query.
    pub(crate) state: PinState,
    /// Whether the core retry floor lets a PIN attempt be sent.
    pub(crate) retry_floor_permits: bool,
}

/// Coarse failures safe to expose across JNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinPreflightFailure {
    /// Card or reader disappeared from the slot.
    CardUnavailable,
    /// Transport state became unusable or indeterminate.
    Transport,
    /// An impossible local shape reached the bridge.
    Bridge,
}

/// Convert a core [`PinStatus`] reading under `scheme` for `slot` into a
/// JNI-ready [`PinPreflight`].
#[must_use]
pub(crate) fn pin_preflight_of(
    scheme: PinReferenceScheme,
    slot: PinSlot,
    status: PinStatus,
) -> PinPreflight {
    let state = match status {
        PinStatus::Verified => PinState::Verified,
        PinStatus::Remaining(retries) => PinState::Remaining(retries.get()),
        PinStatus::Locked => PinState::Locked,
        PinStatus::NoInfo => PinState::NoInformation,
        PinStatus::Other(_) => PinState::Unrecognised,
    };
    let credential = match slot {
        PinSlot::Pin1 => FlooredCredential::Pin1,
        PinSlot::Pin2 => FlooredCredential::Pin2,
    };
    PinPreflight {
        scheme,
        state,
        retry_floor_permits: check_retry_floor(credential, status).is_ok(),
    }
}

/// Resolve the PIN-reference numbering and query `slot` without presenting a
/// credential or consuming a retry.
pub(crate) fn probe_pin_preflight<T>(
    transport: &mut T,
    slot: PinSlot,
) -> Result<PinPreflight, PinPreflightFailure>
where
    T: CardTransport,
{
    let (scheme, resolved_pin1_status) =
        transport.pin1_status_and_scheme().map_err(map_auth_error)?;
    let status = match slot {
        PinSlot::Pin1 => resolved_pin1_status,
        PinSlot::Pin2 => transport
            .pin_status_with_scheme(scheme, PinSlot::Pin2)
            .map_err(map_auth_error)?,
    };
    Ok(pin_preflight_of(scheme, slot, status))
}

/// Map a core [`AuthError`] onto a coarse JNI-safe [`PinPreflightFailure`]
/// without exposing backend or card detail.
pub(crate) fn map_auth_error<E>(error: AuthError<E>) -> PinPreflightFailure {
    match error {
        AuthError::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            PinPreflightFailure::CardUnavailable
        }
        AuthError::Transport(_)
        | AuthError::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => PinPreflightFailure::Transport,
        AuthError::Outcome(TransportOutcome::Response(_))
        | AuthError::Command(_)
        | AuthError::RetryFloor(_)
        | AuthError::PinLength(_) => PinPreflightFailure::Bridge,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use refineid_apdu::{
        CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
        TransportOutcome,
    };
    use refineid_auth::{
        PIN1_REFERENCE, PIN1_REFERENCE_ORGANIZATIONAL, PIN2_REFERENCE,
        PIN2_REFERENCE_ORGANIZATIONAL, PinReferenceScheme, PinSlot,
    };

    use super::{PinPreflightFailure, PinState, map_auth_error, probe_pin_preflight};

    const VERIFY_HEADER_LENGTH: usize = 4;
    const P2_OFFSET: usize = 3;
    const CITIZEN_PIN1_COMMAND_COUNT: usize = 1;
    const ORGANIZATIONAL_PIN1_COMMAND_COUNT: usize = 2;
    const CITIZEN_PIN2_COMMAND_COUNT: usize = 2;
    const ORGANIZATIONAL_PIN2_COMMAND_COUNT: usize = 3;
    const CITIZEN_PROBE_COMMAND_INDEX: usize = 0;
    const ORGANIZATIONAL_PROBE_COMMAND_INDEX: usize = 1;
    const CITIZEN_PIN2_COMMAND_INDEX: usize = 1;
    const ORGANIZATIONAL_PIN2_COMMAND_INDEX: usize = 2;
    const SAFE_RETRIES: u8 = 3;
    const PRISTINE_RETRIES: u8 = 5;
    const ONE_SPENT_RETRIES: u8 = 4;
    const BELOW_FLOOR_RETRIES: u8 = 2;
    const LAST_RETRY: u8 = 1;
    const NO_RETRIES: u8 = 0;
    const SERVED_RETRIES: [u8; 4] = [
        PRISTINE_RETRIES,
        ONE_SPENT_RETRIES,
        SAFE_RETRIES,
        NO_RETRIES,
    ];
    const REFUSED_RETRIES: [u8; 2] = [BELOW_FLOOR_RETRIES, LAST_RETRY];

    struct ScriptedTransport {
        responses: VecDeque<TransportOutcome>,
        public_commands: Vec<Vec<u8>>,
        credential_calls: usize,
    }

    impl ScriptedTransport {
        fn new(statuses: &[StatusWord]) -> Self {
            Self {
                responses: statuses
                    .iter()
                    .copied()
                    .map(response)
                    .collect::<VecDeque<_>>(),
                public_commands: Vec::new(),
                credential_calls: 0,
            }
        }
    }

    impl CardTransport for ScriptedTransport {
        type Error = &'static str;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.public_commands.push(command.as_bytes().to_vec());
            self.responses
                .pop_front()
                .ok_or("missing scripted response")
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.credential_calls += 1;
            Err("status probe must not use the credential path")
        }
    }

    fn retries(value: u8) -> PinRetries {
        PinRetries::from_nibble(value).expect("synthetic retry count fits a nibble")
    }

    fn remaining(value: u8) -> StatusWord {
        StatusWord::PinIncorrect {
            retries: retries(value),
        }
    }

    fn response(status: StatusWord) -> TransportOutcome {
        let [sw1, sw2] = status.as_u16().to_be_bytes();
        TransportOutcome::Response(ResponseApdu {
            body: Vec::new(),
            sw1,
            sw2,
        })
    }

    fn p2(command: &[u8]) -> u8 {
        assert_eq!(command.len(), VERIFY_HEADER_LENGTH);
        command[P2_OFFSET]
    }

    #[test]
    fn citizen_pin1_preflight_uses_one_header_only_public_command() {
        let mut transport = ScriptedTransport::new(&[remaining(SAFE_RETRIES)]);

        let result =
            probe_pin_preflight(&mut transport, PinSlot::Pin1).expect("scripted preflight");

        assert_eq!(result.scheme, PinReferenceScheme::Citizen);
        assert_eq!(result.state, PinState::Remaining(SAFE_RETRIES));
        assert!(result.retry_floor_permits);
        assert_eq!(transport.public_commands.len(), CITIZEN_PIN1_COMMAND_COUNT);
        assert_eq!(
            p2(&transport.public_commands[CITIZEN_PROBE_COMMAND_INDEX]),
            PIN1_REFERENCE
        );
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn organizational_pin1_preflight_resolves_once_on_public_commands() {
        let mut transport =
            ScriptedTransport::new(&[StatusWord::ReferenceDataNotFound, remaining(SAFE_RETRIES)]);

        let result =
            probe_pin_preflight(&mut transport, PinSlot::Pin1).expect("scripted preflight");

        assert_eq!(result.scheme, PinReferenceScheme::Organizational);
        assert_eq!(result.state, PinState::Remaining(SAFE_RETRIES));
        assert_eq!(
            transport.public_commands.len(),
            ORGANIZATIONAL_PIN1_COMMAND_COUNT
        );
        assert_eq!(
            p2(&transport.public_commands[CITIZEN_PROBE_COMMAND_INDEX]),
            PIN1_REFERENCE
        );
        assert_eq!(
            p2(&transport.public_commands[ORGANIZATIONAL_PROBE_COMMAND_INDEX]),
            PIN1_REFERENCE_ORGANIZATIONAL
        );
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn citizen_pin2_preflight_resolves_then_probes_pin2_on_public_commands() {
        let mut transport =
            ScriptedTransport::new(&[remaining(SAFE_RETRIES), remaining(SAFE_RETRIES)]);

        let preflight =
            probe_pin_preflight(&mut transport, PinSlot::Pin2).expect("scripted preflight");

        assert_eq!(preflight.scheme, PinReferenceScheme::Citizen);
        assert_eq!(preflight.state, PinState::Remaining(SAFE_RETRIES));
        assert!(preflight.retry_floor_permits);
        assert_eq!(transport.public_commands.len(), CITIZEN_PIN2_COMMAND_COUNT);
        assert_eq!(
            p2(&transport.public_commands[CITIZEN_PROBE_COMMAND_INDEX]),
            PIN1_REFERENCE
        );
        assert_eq!(
            p2(&transport.public_commands[CITIZEN_PIN2_COMMAND_INDEX]),
            PIN2_REFERENCE
        );
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn organizational_pin2_preflight_reuses_the_resolved_numbering_for_pin2() {
        let mut transport = ScriptedTransport::new(&[
            StatusWord::ReferenceDataNotFound,
            remaining(SAFE_RETRIES),
            remaining(SAFE_RETRIES),
        ]);

        let preflight =
            probe_pin_preflight(&mut transport, PinSlot::Pin2).expect("scripted preflight");

        assert_eq!(preflight.scheme, PinReferenceScheme::Organizational);
        assert_eq!(
            transport.public_commands.len(),
            ORGANIZATIONAL_PIN2_COMMAND_COUNT
        );
        assert_eq!(
            p2(&transport.public_commands[CITIZEN_PROBE_COMMAND_INDEX]),
            PIN1_REFERENCE
        );
        assert_eq!(
            p2(&transport.public_commands[ORGANIZATIONAL_PROBE_COMMAND_INDEX]),
            PIN1_REFERENCE_ORGANIZATIONAL
        );
        assert_eq!(
            p2(&transport.public_commands[ORGANIZATIONAL_PIN2_COMMAND_INDEX]),
            PIN2_REFERENCE_ORGANIZATIONAL
        );
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn retry_floor_serves_five_four_three_zero_blocked_and_verified_for_both_slots() {
        let served = SERVED_RETRIES
            .into_iter()
            .map(|count| (remaining(count), PinState::Remaining(count)))
            .chain([
                (StatusWord::Success, PinState::Verified),
                (StatusWord::AuthenticationBlocked, PinState::Locked),
                (StatusWord::ReferenceDataInvalidated, PinState::Locked),
            ]);
        for (status, expected_state) in served {
            let mut pin1_transport = ScriptedTransport::new(&[status]);
            let pin1 =
                probe_pin_preflight(&mut pin1_transport, PinSlot::Pin1).expect("PIN1 preflight");
            assert_eq!(pin1.state, expected_state);
            assert!(pin1.retry_floor_permits);
            assert_eq!(pin1_transport.credential_calls, 0);

            let mut pin2_transport = ScriptedTransport::new(&[remaining(SAFE_RETRIES), status]);
            let pin2 =
                probe_pin_preflight(&mut pin2_transport, PinSlot::Pin2).expect("PIN2 preflight");
            assert_eq!(pin2.state, expected_state);
            assert!(pin2.retry_floor_permits);
            assert_eq!(pin2_transport.credential_calls, 0);
        }
    }

    #[test]
    fn retry_floor_refuses_two_one_and_unreadable_for_both_slots() {
        let refused = REFUSED_RETRIES
            .into_iter()
            .map(|count| (remaining(count), PinState::Remaining(count)))
            .chain([
                (StatusWord::AuthenticationFailed, PinState::NoInformation),
                (StatusWord::WrongLength, PinState::Unrecognised),
                (StatusWord::FileNotFound, PinState::Unrecognised),
            ]);
        for (status, expected_state) in refused {
            let mut pin1_transport = ScriptedTransport::new(&[status]);
            let pin1 =
                probe_pin_preflight(&mut pin1_transport, PinSlot::Pin1).expect("PIN1 preflight");
            assert_eq!(pin1.state, expected_state);
            assert!(!pin1.retry_floor_permits);
            assert_eq!(pin1_transport.credential_calls, 0);

            let mut pin2_transport = ScriptedTransport::new(&[remaining(SAFE_RETRIES), status]);
            let pin2 =
                probe_pin_preflight(&mut pin2_transport, PinSlot::Pin2).expect("PIN2 preflight");
            assert_eq!(pin2.state, expected_state);
            assert!(!pin2.retry_floor_permits);
            assert_eq!(pin2_transport.credential_calls, 0);
        }
    }

    #[test]
    fn unrecognized_organizational_fallback_keeps_citizen_scheme_for_both_slots() {
        let mut pin1_transport =
            ScriptedTransport::new(&[StatusWord::ReferenceDataNotFound, StatusWord::WrongLength]);
        let pin1 = probe_pin_preflight(&mut pin1_transport, PinSlot::Pin1).expect("PIN1 preflight");
        assert_eq!(pin1.scheme, PinReferenceScheme::Citizen);
        assert_eq!(pin1.state, PinState::Unrecognised);
        assert!(!pin1.retry_floor_permits);
        assert_eq!(
            pin1_transport.public_commands.len(),
            ORGANIZATIONAL_PIN1_COMMAND_COUNT
        );
        assert_eq!(pin1_transport.credential_calls, 0);

        let mut pin2_transport = ScriptedTransport::new(&[
            StatusWord::ReferenceDataNotFound,
            StatusWord::WrongLength,
            StatusWord::WrongLength,
        ]);
        let pin2 = probe_pin_preflight(&mut pin2_transport, PinSlot::Pin2).expect("PIN2 preflight");
        assert_eq!(pin2.scheme, PinReferenceScheme::Citizen);
        assert_eq!(pin2.state, PinState::Unrecognised);
        assert!(!pin2.retry_floor_permits);
        assert_eq!(
            pin2_transport.public_commands.len(),
            ORGANIZATIONAL_PIN2_COMMAND_COUNT
        );
        assert_eq!(
            p2(&pin2_transport.public_commands[ORGANIZATIONAL_PIN2_COMMAND_INDEX]),
            PIN2_REFERENCE
        );
        assert_eq!(pin2_transport.credential_calls, 0);
    }

    #[test]
    fn maps_transport_state_without_exposing_backend_detail() {
        assert_eq!(
            map_auth_error::<&str>(refineid_auth::AuthError::Outcome(TransportOutcome::NoCard)),
            PinPreflightFailure::CardUnavailable
        );
        assert_eq!(
            map_auth_error(refineid_auth::AuthError::Transport("backend")),
            PinPreflightFailure::Transport
        );
        assert_eq!(
            map_auth_error::<&str>(refineid_auth::AuthError::Outcome(
                TransportOutcome::ProtocolDesync
            )),
            PinPreflightFailure::Transport
        );
        assert_eq!(
            map_auth_error::<&str>(refineid_auth::AuthError::Outcome(response(
                StatusWord::Success
            ))),
            PinPreflightFailure::Bridge
        );
        assert_eq!(
            map_auth_error::<&str>(refineid_auth::AuthError::Command(
                refineid_apdu::CredentialBodyError::Empty
            )),
            PinPreflightFailure::Bridge
        );
    }
}
