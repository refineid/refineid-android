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

//! `EF.CardAccess` recognition for the contactless border.
//!
//! `EF.CardAccess` sits directly under the MF and is readable without PACE
//! or secure messaging -- that is its purpose: a terminal cannot run PACE
//! until the card has advertised which protocol variants and domain
//! parameters it supports (ICAO 9303-11 section 9.2, BSI TR-03110-3 appendix
//! A.1.1.4). Every FINEID card answers it before PACE, the organization card
//! included, which answers nothing else.
//!
//! This module reads that public file through core's parser, so Android can
//! report which kind of card is in the field and so which credential opens
//! it. It establishes no secure channel and sends no credential.

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_pace::{CardAccess, PaceError, read_card_access};
use refineid_pkcs15::Pkcs15Error;

use crate::organization_card::{ContactlessCardKind, contactless_card_kind};

/// Coarse typed outcome of one contactless `EF.CardAccess` probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CardAccessSummary {
    /// What opens the card; `None` for a card listing neither family.
    pub(crate) kind: Option<ContactlessCardKind>,
    /// Number of recognized `PACEInfo` entries, saturated at 255.
    pub(crate) pace_entry_count: u8,
}

/// Failure vocabulary for the contactless card-access probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CardAccessProbeFailure {
    /// Card left the field or was never present.
    CardUnavailable,
    /// The card rejected a select or read with a status word.
    Rejected,
    /// The exchange failed or left the card state uncertain.
    Transport,
    /// The file was empty, oversized, or malformed.
    Invalid,
    /// Android-side bridge failure.
    Bridge,
}

/// Read `EF.CardAccess` in plain the way core's `read_card_access` does: one
/// SELECT of the file by its identifier, then its one DER object. No SELECT of
/// the MF goes first: the organization card refuses it before PACE (`6985`,
/// observed on the phone), and a card fresh in the field is at the MF already.
///
/// ISO 7816-4 ends a secure-messaging session when a plain command arrives,
/// and a card may refuse that ending command (observed on the citizen card),
/// so a select the card refuses is asked once more.
pub(crate) fn read_card_access_in_plain<T: CardTransport>(
    transport: &mut T,
) -> Result<CardAccess, PaceError<T::Error>> {
    match read_card_access(transport) {
        Err(PaceError::CardAccessRead(Pkcs15Error::Status(_))) => read_card_access(transport),
        other => other,
    }
}

/// Read and parse `EF.CardAccess` over a plain (pre-PACE) transport.
pub(crate) fn probe_card_access<T: CardTransport>(
    transport: &mut T,
) -> Result<CardAccessSummary, CardAccessProbeFailure> {
    let card_access = read_card_access_in_plain(transport).map_err(map_pace_error)?;
    Ok(CardAccessSummary {
        kind: contactless_card_kind(&card_access),
        pace_entry_count: u8::try_from(card_access.pace_infos().len()).unwrap_or(u8::MAX),
    })
}

fn map_pace_error<E>(error: PaceError<E>) -> CardAccessProbeFailure {
    match error {
        PaceError::CardAccessRead(read) => map_pkcs15_error(read),
        PaceError::CardAccess(_) => CardAccessProbeFailure::Invalid,
        _ => CardAccessProbeFailure::Bridge,
    }
}

fn map_pkcs15_error<E>(error: Pkcs15Error<E>) -> CardAccessProbeFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            CardAccessProbeFailure::CardUnavailable
        }
        Pkcs15Error::Status(_) => CardAccessProbeFailure::Rejected,
        Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        ) => CardAccessProbeFailure::Transport,
        Pkcs15Error::Empty | Pkcs15Error::TooLarge | Pkcs15Error::InvalidData(_) => {
            CardAccessProbeFailure::Invalid
        }
        Pkcs15Error::Outcome(TransportOutcome::Response(_))
        | Pkcs15Error::Aid(_)
        | Pkcs15Error::Command(_) => CardAccessProbeFailure::Bridge,
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::{StatusWord, TransportOutcome};
    use refineid_pkcs15::Pkcs15Error;

    use std::collections::VecDeque;

    use refineid_apdu::{CardTransport, CommandApdu, CredentialCommand, ResponseApdu};
    use refineid_ber::{BerEncoder, tlv};
    use refineid_pace::PaceDomain;

    use super::{CardAccessProbeFailure, map_pkcs15_error, probe_card_access};
    use crate::organization_card::ContactlessCardKind;

    const INS_SELECT: u8 = 0xA4;
    const INS_READ_BINARY: u8 = 0xB0;
    const INS_INDEX: usize = 1;
    const P1_INDEX: usize = 2;
    const P2_INDEX: usize = 3;
    const DATA_INDEX: usize = 5;
    const LE_MAX_READ: usize = 256;
    /// The MF's file identifier, `3F00` (ISO/IEC 7816-4 section 7.1.1).
    const MF_IDENTIFIER: [u8; 2] = [0x3F, 0x00];
    /// SELECT by DF name, as the second MF variant sends it.
    const P1_SELECT_BY_NAME: u8 = 0x04;
    /// `id-PACE-ECDH-GM-AES-CBC-CMAC-256` (BSI TR-03110-3 section A.1.1.1).
    const ID_PACE_GM_256: [u8; 10] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04];
    const PACE_VERSION: u8 = 2;
    const TAG_OID: u8 = 0x06;
    const TAG_INTEGER: u8 = 0x02;
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_SET: u8 = 0x31;

    /// A card before PACE: it refuses any SELECT of the MF as the
    /// organization card does on the phone (`6985`, then `6A87` by name),
    /// optionally refuses `refusals` more selects first, and serves
    /// EF.CardAccess.
    struct PrePaceCard {
        file: Vec<u8>,
        refusals: VecDeque<StatusWord>,
        commands: Vec<Vec<u8>>,
    }

    impl PrePaceCard {
        fn new(domain: PaceDomain) -> Self {
            let mut fields = BerEncoder::default();
            fields
                .push_tlv(TAG_OID, ID_PACE_GM_256)
                .expect("the OID encodes");
            fields
                .push_tlv(TAG_INTEGER, [PACE_VERSION])
                .expect("the version encodes");
            fields
                .push_tlv(TAG_INTEGER, [domain.parameter_id()])
                .expect("the parameter encodes");
            let info = tlv(TAG_SEQUENCE, fields.finish()).expect("PACEInfo encodes");
            Self {
                file: tlv(TAG_SET, info).expect("the SET encodes"),
                refusals: VecDeque::new(),
                commands: Vec::new(),
            }
        }

        fn selects_the_mf(command: &[u8]) -> bool {
            command.get(DATA_INDEX..DATA_INDEX + MF_IDENTIFIER.len()) == Some(&MF_IDENTIFIER)
                || command.get(P1_INDEX) == Some(&P1_SELECT_BY_NAME)
        }
    }

    fn status(sw: StatusWord) -> ResponseApdu {
        let [sw1, sw2] = sw.as_u16().to_be_bytes();
        ResponseApdu {
            body: Vec::new(),
            sw1,
            sw2,
        }
    }

    impl CardTransport for PrePaceCard {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let bytes = command.as_bytes().to_vec();
            self.commands.push(bytes.clone());
            let answer = match bytes[INS_INDEX] {
                INS_SELECT if Self::selects_the_mf(&bytes) => {
                    if bytes[P1_INDEX] == P1_SELECT_BY_NAME {
                        status(StatusWord::Other(SW_WRONG_DATA_LENGTH))
                    } else {
                        status(StatusWord::Other(SW_CONDITIONS_NOT_SATISFIED))
                    }
                }
                INS_SELECT => match self.refusals.pop_front() {
                    Some(refusal) => status(refusal),
                    None => status(StatusWord::Success),
                },
                INS_READ_BINARY => {
                    let offset =
                        (usize::from(bytes[P1_INDEX]) << u8::BITS) | usize::from(bytes[P2_INDEX]);
                    let end = (offset + LE_MAX_READ).min(self.file.len());
                    ResponseApdu {
                        body: self.file.get(offset..end).unwrap_or_default().to_vec(),
                        ..status(StatusWord::Success)
                    }
                }
                _ => return Err("not expected before PACE".to_owned()),
            };
            Ok(TransportOutcome::Response(answer))
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("no credential before PACE".to_owned())
        }
    }

    /// `6985`, conditions of use not satisfied (ISO/IEC 7816-4 table 6).
    const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
    /// `6A87`, as the phone saw it for SELECT of the MF by name.
    const SW_WRONG_DATA_LENGTH: u16 = 0x6A87;

    #[test]
    fn a_card_refusing_select_mf_is_read_and_named() {
        let mut card = PrePaceCard::new(PaceDomain::NistP384);
        let summary = probe_card_access(&mut card).expect("EF.CardAccess reads");
        assert_eq!(summary.kind, Some(ContactlessCardKind::Organization));
        assert!(
            card.commands
                .iter()
                .all(|command| !PrePaceCard::selects_the_mf(command)),
            "no SELECT of the MF is sent"
        );
    }

    #[test]
    fn a_citizen_card_is_read_and_named_the_same_way() {
        let mut card = PrePaceCard::new(PaceDomain::BrainpoolP384r1);
        let summary = probe_card_access(&mut card).expect("EF.CardAccess reads");
        assert_eq!(summary.kind, Some(ContactlessCardKind::Personal));
    }

    #[test]
    fn a_refused_select_ending_secure_messaging_is_asked_once_more() {
        let mut card = PrePaceCard::new(PaceDomain::NistP384);
        // Both variants of the first SELECT EF are refused.
        card.refusals = [
            StatusWord::Other(SW_CONDITIONS_NOT_SATISFIED),
            StatusWord::Other(SW_CONDITIONS_NOT_SATISFIED),
        ]
        .into();
        let summary = probe_card_access(&mut card).expect("the second read succeeds");
        assert_eq!(summary.kind, Some(ContactlessCardKind::Organization));
    }

    #[test]
    fn a_card_refusing_ef_card_access_twice_is_rejected() {
        let mut card = PrePaceCard::new(PaceDomain::NistP384);
        card.refusals = [StatusWord::Other(SW_CONDITIONS_NOT_SATISFIED); 4].into();
        assert_eq!(
            probe_card_access(&mut card),
            Err(CardAccessProbeFailure::Rejected)
        );
    }

    #[test]
    fn maps_read_failures_onto_the_probe_vocabulary() {
        assert_eq!(
            map_pkcs15_error::<&str>(Pkcs15Error::Outcome(TransportOutcome::NoCard)),
            CardAccessProbeFailure::CardUnavailable
        );
        assert_eq!(
            map_pkcs15_error::<&str>(Pkcs15Error::Status(StatusWord::FileNotFound)),
            CardAccessProbeFailure::Rejected
        );
        assert_eq!(
            map_pkcs15_error::<&str>(Pkcs15Error::Empty),
            CardAccessProbeFailure::Invalid
        );
        assert_eq!(
            map_pkcs15_error(Pkcs15Error::Transport("backend")),
            CardAccessProbeFailure::Transport
        );
    }
}
