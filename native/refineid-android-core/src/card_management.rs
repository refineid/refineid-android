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
    ActivationCode, ActivationReport, ActivationScheme, AuthError, CredentialHealthReport,
    ManageOutcome, Pin1, Pin2, PinManageOps, PinReferenceScheme, PinStatus, Puk, UnvalidatedSecret,
};

use crate::card_certificate::{CardKeyProfile, read_authentication_certificate};

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

/// Coarse failures of card management operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardManagementFailure {
    CardUnavailable,
    TransportError,
    BridgeError,
    InvalidCredential,
    #[allow(dead_code)]
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
        AuthError::LengthUnsupported { .. } => CardManagementFailure::InvalidCredential,
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

fn detect_activation_scheme<T: CardTransport>(transport: &mut T) -> Option<ActivationScheme> {
    if let Ok(cert) = read_authentication_certificate(transport) {
        match cert.profile() {
            CardKeyProfile::Rsa2048 | CardKeyProfile::Rsa3072 => {
                Some(ActivationScheme::ActivationCodeIsPuk)
            }
            CardKeyProfile::EcdsaP256 | CardKeyProfile::EcdsaP384 => {
                Some(ActivationScheme::PresetActivationPin)
            }
        }
    } else {
        None
    }
}

/// Execute credential health probe on `transport`.
pub(crate) fn probe_credential_health<T: CardTransport>(
    transport: &mut T,
) -> Result<CredentialHealthReport, CardManagementFailure> {
    let scheme = detect_activation_scheme(transport);
    transport
        .probe_credential_health(scheme)
        .map_err(map_auth_error)
}

/// Encode `CredentialHealthReport` to native byte array.
pub(crate) fn encode_credential_health_reply(
    result: Result<CredentialHealthReport, CardManagementFailure>,
) -> Vec<u8> {
    match result {
        Ok(report) => {
            let (p1_state, p1_retries) = encode_pin_status(report.pin1_status);
            let (p2_state, p2_retries) = encode_pin_status(report.pin2_status);
            let (puk_state, puk_retries) = encode_pin_status(report.puk_status);
            let scheme_byte = match report.pin_reference_scheme {
                PinReferenceScheme::Citizen => SCHEME_CITIZEN,
                PinReferenceScheme::Organizational => SCHEME_ORGANIZATIONAL,
            };
            let act_scheme_byte = match report.activation_scheme {
                Some(ActivationScheme::ActivationCodeIsPuk) => ACTIVATION_SCHEME_PUK,
                Some(ActivationScheme::PresetActivationPin) => ACTIVATION_SCHEME_PRESET,
                None => ACTIVATION_SCHEME_UNKNOWN,
            };
            let act_needs_byte = match report.activation_needs {
                Some(needs) => match (needs.pin1, needs.pin2) {
                    (true, true) => ACTIVATION_NEEDS_BOTH,
                    (true, false) => ACTIVATION_NEEDS_PIN1_ONLY,
                    (false, true) => ACTIVATION_NEEDS_PIN2_ONLY,
                    (false, false) => ACTIVATION_NEEDS_NONE,
                },
                None => ACTIVATION_NEEDS_NONE,
            };
            vec![
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

    transport
        .change_pin1(current_pin, new_pin)
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

    transport
        .change_pin2(current_pin, new_pin)
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

    transport.unblock_pin1(puk, new_pin).map_err(map_auth_error)
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

    transport.unblock_pin2(puk, new_pin).map_err(map_auth_error)
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
    mut code_bytes: Vec<u8>,
    mut new_pin1_bytes: Option<Vec<u8>>,
    mut new_pin2_bytes: Option<Vec<u8>>,
) -> Result<ActivationReport, CardManagementFailure> {
    let scheme = match scheme_byte {
        ACTIVATION_SCHEME_PUK => ActivationScheme::ActivationCodeIsPuk,
        ACTIVATION_SCHEME_PRESET => ActivationScheme::PresetActivationPin,
        _ => {
            // Auto-detect if unspecified
            detect_activation_scheme(transport).unwrap_or(ActivationScheme::PresetActivationPin)
        }
    };

    let code_sec = UnvalidatedSecret::from_owned_bytes(code_bytes.clone());
    code_bytes.fill(0);
    let code = ActivationCode::reconstruct(code_sec, scheme)
        .map_err(|_| CardManagementFailure::InvalidCredential)?;

    let new_pin1 = if let Some(mut bytes) = new_pin1_bytes.take() {
        let sec = UnvalidatedSecret::from_owned_bytes(bytes.clone());
        bytes.fill(0);
        Some(Pin1::reconstruct(sec).map_err(|_| CardManagementFailure::InvalidCredential)?)
    } else {
        None
    };

    let new_pin2 = if let Some(mut bytes) = new_pin2_bytes.take() {
        let sec = UnvalidatedSecret::from_owned_bytes(bytes.clone());
        bytes.fill(0);
        Some(Pin2::reconstruct(sec).map_err(|_| CardManagementFailure::InvalidCredential)?)
    } else {
        None
    };

    transport
        .activate_card(scheme, code, new_pin1, new_pin2)
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
    use super::*;
    use refineid_apdu::PinRetries;
    use refineid_auth::CardActivationNeeds;

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
        let encoded = encode_credential_health_reply(Ok(report));
        assert_eq!(encoded[0], MANAGEMENT_TAG_SUCCEEDED);
        assert_eq!(encoded[1], PIN_STATE_REMAINING);
        assert_eq!(encoded[2], 3);
        assert_eq!(encoded[7], SCHEME_CITIZEN);
        assert_eq!(encoded[8], ACTIVATION_SCHEME_PRESET);
        assert_eq!(encoded[9], ACTIVATION_NEEDS_BOTH);
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
