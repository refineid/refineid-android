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

//! Counter-safe PIN1 status preflight for one selected PKCS#15 session.
//!
//! FINEID S1 v4.2 section 3.5.1.1 defines header-only `VERIFY` as a
//! status query. It carries no credential and does not perform a PIN
//! comparison. The resolved reference scheme is retained beside the status so
//! a later credential operation can use the same numbering explicitly.

use refineid_apdu::{CardTransport, StatusWord, TransportOutcome};
use refineid_auth::{
    AuthError, PinOps, PinReferenceScheme, PinSlot, PinStatus, classify_pin_status_sw,
    pin1_status_permits_consumer_authentication,
};

/// Counter-safe PIN1 state, with unrecognised status words erased at this
/// boundary rather than exposed as raw card values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pin1State {
    /// PIN1 is already verified in this card session.
    Verified,
    /// PIN1 is not verified and has this many attempts remaining.
    Remaining(u8),
    /// PIN1 is blocked or invalidated.
    Locked,
    /// The card supplied no retry counter.
    NoInformation,
    /// The card supplied a status outside the reviewed PIN vocabulary.
    Unrecognised,
}

/// One resolved, counter-safe PIN1 preflight result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pin1Preflight {
    /// Credential-reference numbering proven by the card.
    pub(crate) scheme: PinReferenceScheme,
    /// Live PIN1 state from the header-only `VERIFY` query.
    pub(crate) state: Pin1State,
    /// Public core policy verdict for an ordinary authentication operation.
    pub(crate) consumer_authentication_permitted: bool,
}

/// Coarse failures safe to expose across JNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pin1PreflightFailure {
    /// Card or reader disappeared from the slot.
    CardUnavailable,
    /// Transport state became unusable or indeterminate.
    Transport,
    /// An impossible local shape reached the bridge.
    Bridge,
}

/// Resolve the PIN-reference numbering and query PIN1 without presenting a
/// credential or consuming a retry.
pub(crate) fn probe_pin1_preflight<T>(
    transport: &mut T,
) -> Result<Pin1Preflight, Pin1PreflightFailure>
where
    T: CardTransport,
{
    let citizen_sw = transport
        .probe_status_word(PinReferenceScheme::Citizen, PinSlot::Pin1)
        .map_err(map_auth_error)?;
    let (scheme, status) = if citizen_sw != StatusWord::ReferenceDataNotFound {
        (
            PinReferenceScheme::Citizen,
            classify_pin_status_sw(citizen_sw),
        )
    } else {
        let org_sw = transport
            .probe_status_word(PinReferenceScheme::Organizational, PinSlot::Pin1)
            .map_err(map_auth_error)?;
        let org_status = classify_pin_status_sw(org_sw);
        match org_status {
            PinStatus::Other(_) => (PinReferenceScheme::Citizen, PinStatus::Other(citizen_sw)),
            PinStatus::Verified
            | PinStatus::Remaining(_)
            | PinStatus::NoInfo
            | PinStatus::Locked => (PinReferenceScheme::Organizational, org_status),
        }
    };
    let state = match status {
        PinStatus::Verified => Pin1State::Verified,
        PinStatus::Remaining(retries) => Pin1State::Remaining(retries.get()),
        PinStatus::Locked => Pin1State::Locked,
        PinStatus::NoInfo => Pin1State::NoInformation,
        PinStatus::Other(_) => Pin1State::Unrecognised,
    };

    Ok(Pin1Preflight {
        scheme,
        state,
        consumer_authentication_permitted: pin1_status_permits_consumer_authentication(status),
    })
}

pub(crate) fn map_auth_error<E>(error: AuthError<E>) -> Pin1PreflightFailure {
    match error {
        AuthError::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            Pin1PreflightFailure::CardUnavailable
        }
        AuthError::Transport(_)
        | AuthError::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => Pin1PreflightFailure::Transport,
        AuthError::Outcome(TransportOutcome::Response(_))
        | AuthError::Command(_)
        | AuthError::LengthUnsupported { .. } => Pin1PreflightFailure::Bridge,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use refineid_apdu::{
        CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
        TransportOutcome,
    };
    use refineid_auth::{PIN1_REFERENCE, PIN1_REFERENCE_ORGANIZATIONAL, PinReferenceScheme};

    use super::{Pin1PreflightFailure, Pin1State, map_auth_error, probe_pin1_preflight};

    const VERIFY_HEADER_LENGTH: usize = 4;
    const P2_OFFSET: usize = 3;
    const CITIZEN_PROBE_COMMAND_INDEX: usize = 0;
    const ORGANIZATIONAL_PROBE_COMMAND_START_INDEX: usize = 1;
    const SAFE_RETRIES: u8 = 3;
    const LOW_RETRIES: u8 = 2;

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
        match PinRetries::from_nibble(value) {
            Some(retries) => retries,
            None => panic!("test retry value must fit a nibble"),
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

    #[test]
    fn citizen_preflight_uses_only_header_only_public_commands() {
        let status = StatusWord::PinIncorrect {
            retries: retries(SAFE_RETRIES),
        };
        let mut transport = ScriptedTransport::new(&[status]);

        let result = match probe_pin1_preflight(&mut transport) {
            Ok(result) => result,
            Err(failure) => panic!("scripted preflight failed: {failure:?}"),
        };

        assert_eq!(result.scheme, PinReferenceScheme::Citizen);
        assert_eq!(result.state, Pin1State::Remaining(SAFE_RETRIES));
        assert!(result.consumer_authentication_permitted);
        assert_eq!(transport.public_commands.len(), 1);
        assert_eq!(transport.credential_calls, 0);
        for command in transport.public_commands {
            assert_eq!(command.len(), VERIFY_HEADER_LENGTH);
            assert_eq!(command.get(P2_OFFSET).copied(), Some(PIN1_REFERENCE));
        }
    }

    #[test]
    fn organizational_preflight_resolves_once_then_reuses_that_scheme() {
        let organizational_status = StatusWord::PinIncorrect {
            retries: retries(SAFE_RETRIES),
        };
        let mut transport =
            ScriptedTransport::new(&[StatusWord::ReferenceDataNotFound, organizational_status]);

        let result = match probe_pin1_preflight(&mut transport) {
            Ok(result) => result,
            Err(failure) => panic!("scripted preflight failed: {failure:?}"),
        };

        assert_eq!(result.scheme, PinReferenceScheme::Organizational);
        assert_eq!(transport.public_commands.len(), 2);
        assert_eq!(
            transport.public_commands[CITIZEN_PROBE_COMMAND_INDEX]
                .get(P2_OFFSET)
                .copied(),
            Some(PIN1_REFERENCE)
        );
        for command in &transport.public_commands[ORGANIZATIONAL_PROBE_COMMAND_START_INDEX..] {
            assert_eq!(command.len(), VERIFY_HEADER_LENGTH);
            assert_eq!(
                command.get(P2_OFFSET).copied(),
                Some(PIN1_REFERENCE_ORGANIZATIONAL)
            );
        }
        assert_eq!(transport.credential_calls, 0);
    }

    #[test]
    fn low_and_unreadable_states_fail_the_consumer_policy_closed() {
        let low = StatusWord::PinIncorrect {
            retries: retries(LOW_RETRIES),
        };
        for (status, expected_state) in [
            (low, Pin1State::Remaining(LOW_RETRIES)),
            (StatusWord::AuthenticationBlocked, Pin1State::Locked),
            (StatusWord::AuthenticationFailed, Pin1State::NoInformation),
            (StatusWord::WrongLength, Pin1State::Unrecognised),
        ] {
            let mut transport = ScriptedTransport::new(&[status]);
            let result = match probe_pin1_preflight(&mut transport) {
                Ok(result) => result,
                Err(failure) => panic!("scripted preflight failed: {failure:?}"),
            };
            assert_eq!(result.state, expected_state);
            assert!(!result.consumer_authentication_permitted);
            assert_eq!(transport.credential_calls, 0);
        }
    }

    #[test]
    fn maps_transport_state_without_exposing_backend_detail() {
        assert_eq!(
            map_auth_error::<&str>(refineid_auth::AuthError::Outcome(TransportOutcome::NoCard)),
            Pin1PreflightFailure::CardUnavailable
        );
        assert_eq!(
            map_auth_error(refineid_auth::AuthError::Transport("backend")),
            Pin1PreflightFailure::Transport
        );
        assert_eq!(
            map_auth_error::<&str>(refineid_auth::AuthError::Outcome(
                TransportOutcome::ProtocolDesync
            )),
            Pin1PreflightFailure::Transport
        );
    }
}
