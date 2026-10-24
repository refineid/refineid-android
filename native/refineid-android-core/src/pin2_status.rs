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

//! Counter-safe PIN2 status preflight for qualified signing.
//!
//! FINEID S1 v4.2 section 3.5.1.1 defines header-only `VERIFY` as a
//! status query. The resolved reference scheme is retained beside the status
//! so the credential and signature chain use one card-proven numbering.

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_auth::{AuthError, PinOps, PinReferenceScheme, PinSlot, PinStatus, check_retry_floor};

/// Counter-safe PIN2 state with unrecognised status words erased.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pin2State {
    /// PIN2 is already verified in this card session.
    Verified,
    /// PIN2 is not verified and has this many attempts remaining.
    Remaining(u8),
    /// PIN2 is blocked or invalidated.
    Locked,
    /// The card supplied no retry counter.
    NoInformation,
    /// The card supplied a status outside the reviewed PIN vocabulary.
    Unrecognised,
}

/// One resolved, counter-safe PIN2 preflight result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pin2Preflight {
    /// Credential-reference numbering proven by the card.
    pub(crate) scheme: PinReferenceScheme,
    /// Live PIN2 state from the header-only `VERIFY` query.
    pub(crate) state: Pin2State,
    /// Whether the core retry floor lets a PIN2 attempt be sent.
    pub(crate) retry_floor_permits: bool,
}

/// Coarse failures safe to expose across JNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pin2PreflightFailure {
    /// Card or reader disappeared from the slot.
    CardUnavailable,
    /// Transport state became unusable or indeterminate.
    Transport,
    /// An impossible local shape reached the bridge.
    Bridge,
}

/// Resolve credential numbering and query PIN2 without presenting a
/// credential or consuming a retry.
pub(crate) fn probe_pin2_preflight<T>(
    transport: &mut T,
) -> Result<Pin2Preflight, Pin2PreflightFailure>
where
    T: CardTransport,
{
    let scheme = transport
        .resolve_pin_reference_scheme()
        .map_err(map_auth_error)?;
    let status = transport
        .pin_status_with_scheme(scheme, PinSlot::Pin2)
        .map_err(map_auth_error)?;
    let state = match status {
        PinStatus::Verified => Pin2State::Verified,
        PinStatus::Remaining(retries) => Pin2State::Remaining(retries.get()),
        PinStatus::Locked => Pin2State::Locked,
        PinStatus::NoInfo => Pin2State::NoInformation,
        PinStatus::Other(_) => Pin2State::Unrecognised,
    };

    Ok(Pin2Preflight {
        scheme,
        state,
        retry_floor_permits: check_retry_floor(PinSlot::Pin2, status).is_ok(),
    })
}

pub(crate) fn map_auth_error<E>(error: AuthError<E>) -> Pin2PreflightFailure {
    match error {
        AuthError::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            Pin2PreflightFailure::CardUnavailable
        }
        AuthError::Transport(_)
        | AuthError::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => Pin2PreflightFailure::Transport,
        AuthError::Outcome(TransportOutcome::Response(_))
        | AuthError::Command(_)
        | AuthError::LengthUnsupported { .. } => Pin2PreflightFailure::Bridge,
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
        PIN2_REFERENCE_ORGANIZATIONAL, PinReferenceScheme,
    };

    use super::{Pin2PreflightFailure, Pin2State, map_auth_error, probe_pin2_preflight};

    const VERIFY_HEADER_LENGTH: usize = 4;
    const P2_OFFSET: usize = 3;
    const SAFE_RETRIES: u8 = 3;
    const PRISTINE_RETRIES: u8 = 5;
    const ONE_SPENT_RETRIES: u8 = 4;
    const BELOW_FLOOR_RETRIES: u8 = 2;
    const LAST_RETRY: u8 = 1;
    const NO_RETRIES: u8 = 0;
    const SERVED_RETRIES: [u8; 3] = [PRISTINE_RETRIES, ONE_SPENT_RETRIES, SAFE_RETRIES];
    const REFUSED_RETRIES: [u8; 3] = [BELOW_FLOOR_RETRIES, LAST_RETRY, NO_RETRIES];
    const CITIZEN_PREFLIGHT_COMMAND_COUNT: usize = 2;
    const ORGANIZATIONAL_PREFLIGHT_COMMAND_COUNT: usize = 3;
    const CITIZEN_REFERENCE_COMMAND_INDEX: usize = 0;
    const ORGANIZATIONAL_REFERENCE_COMMAND_INDEX: usize = 1;
    const CITIZEN_PIN2_COMMAND_INDEX: usize = 1;
    const ORGANIZATIONAL_PIN2_COMMAND_INDEX: usize = 2;

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
        PinRetries::from_nibble(value).expect("synthetic retry count fits")
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
    fn citizen_preflight_resolves_then_probes_pin2_on_public_commands() {
        let mut transport =
            ScriptedTransport::new(&[remaining(SAFE_RETRIES), remaining(SAFE_RETRIES)]);

        let preflight = probe_pin2_preflight(&mut transport).expect("scripted preflight");

        assert_eq!(preflight.scheme, PinReferenceScheme::Citizen);
        assert_eq!(preflight.state, Pin2State::Remaining(SAFE_RETRIES));
        assert!(preflight.retry_floor_permits);
        assert_eq!(
            transport.public_commands.len(),
            CITIZEN_PREFLIGHT_COMMAND_COUNT
        );
        assert_eq!(
            p2(&transport.public_commands[CITIZEN_REFERENCE_COMMAND_INDEX]),
            PIN1_REFERENCE
        );
        assert_eq!(
            p2(&transport.public_commands[CITIZEN_PIN2_COMMAND_INDEX]),
            PIN2_REFERENCE
        );
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn organizational_preflight_reuses_the_resolved_numbering_for_pin2() {
        let mut transport = ScriptedTransport::new(&[
            StatusWord::ReferenceDataNotFound,
            remaining(SAFE_RETRIES),
            remaining(SAFE_RETRIES),
        ]);

        let preflight = probe_pin2_preflight(&mut transport).expect("scripted preflight");

        assert_eq!(preflight.scheme, PinReferenceScheme::Organizational);
        assert_eq!(
            transport.public_commands.len(),
            ORGANIZATIONAL_PREFLIGHT_COMMAND_COUNT
        );
        assert_eq!(
            p2(&transport.public_commands[CITIZEN_REFERENCE_COMMAND_INDEX]),
            PIN1_REFERENCE
        );
        assert_eq!(
            p2(&transport.public_commands[ORGANIZATIONAL_REFERENCE_COMMAND_INDEX]),
            PIN1_REFERENCE_ORGANIZATIONAL
        );
        assert_eq!(
            p2(&transport.public_commands[ORGANIZATIONAL_PIN2_COMMAND_INDEX]),
            PIN2_REFERENCE_ORGANIZATIONAL
        );
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn retry_floor_serves_five_four_three_and_verified() {
        let served = SERVED_RETRIES
            .into_iter()
            .map(remaining)
            .chain([StatusWord::Success]);
        for status in served {
            let mut transport = ScriptedTransport::new(&[remaining(SAFE_RETRIES), status]);

            let preflight = probe_pin2_preflight(&mut transport).expect("scripted preflight");

            assert!(preflight.retry_floor_permits);
            assert_eq!(transport.credential_calls, 0);
        }
    }

    #[test]
    fn retry_floor_refuses_two_one_zero_blocked_and_unreadable() {
        let refused = REFUSED_RETRIES.into_iter().map(remaining).chain([
            StatusWord::AuthenticationFailed,
            StatusWord::AuthenticationBlocked,
            StatusWord::ReferenceDataInvalidated,
            StatusWord::FileNotFound,
        ]);
        for status in refused {
            let mut transport = ScriptedTransport::new(&[remaining(SAFE_RETRIES), status]);

            let preflight = probe_pin2_preflight(&mut transport).expect("scripted preflight");

            assert!(!preflight.retry_floor_permits);
            assert_eq!(transport.credential_calls, 0);
        }
    }

    #[test]
    fn maps_transport_state_without_exposing_backend_detail() {
        assert_eq!(
            map_auth_error::<&str>(refineid_auth::AuthError::Outcome(TransportOutcome::NoCard)),
            Pin2PreflightFailure::CardUnavailable
        );
        assert_eq!(
            map_auth_error(refineid_auth::AuthError::Transport("synthetic backend")),
            Pin2PreflightFailure::Transport
        );
    }
}
