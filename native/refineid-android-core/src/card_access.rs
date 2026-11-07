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
use refineid_pace::{PaceError, read_card_access};
use refineid_pkcs15::{Pkcs15Error, Pkcs15Ops as _};

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

/// Read and parse `EF.CardAccess` over a plain (pre-PACE) transport.
pub(crate) fn probe_card_access<T: CardTransport>(
    transport: &mut T,
) -> Result<CardAccessSummary, CardAccessProbeFailure> {
    transport.select_mf().map_err(map_pkcs15_error)?;
    let card_access = read_card_access(transport).map_err(map_pace_error)?;
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

    use super::{CardAccessProbeFailure, map_pkcs15_error};

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
