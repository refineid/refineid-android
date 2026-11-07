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

//! The organization card on the contactless interface.
//!
//! The card has no Card Access Number: PACE takes PIN 1, PIN 2 or the PUK
//! as its password (FINEID S1 v4.0, organizational cards, section 2.1;
//! FINEID S4-2 v4.0 section 6), and before PACE the card answers nothing
//! but EF.CardAccess. Every operation here reads EF.CardAccess, refuses a
//! card that does not list the organization card's suites, and runs its
//! own PACE with the credential it spends; no channel outlives the call.
//!
//! The retry floor is `MSE:Set AT`'s answer, read before the first `GENERAL
//! AUTHENTICATE`: `run_pace` applies core's rule to it, and a channel keeps
//! that answer as its record. Nothing here sends the header-only VERIFY,
//! which this card does not answer with a counter over secure messaging.

use refineid_apdu::{CardTransport, PinRetries, StatusWord, TransportOutcome};
use refineid_auth::{
    AuthError, CardPinLengths, ChannelProof, CredentialHealthReport, FlooredCredential,
    ManageOutcome, Pin1, Pin1PaceChannel as _, Pin1PaceChannelOps as _, Pin2, PinManageOps as _,
    PinReferenceScheme, PinSlot, PinStatus, Puk, PukPaceChannelOps as _, UnvalidatedSecret,
    check_retry_floor,
};
use refineid_ber::BerEncoder;
use refineid_pace::commands::MseSetAt;
use refineid_pace::{
    CardAccess, PaceDomain, PaceError, PacePassword, PaceSession, SmTransport, read_card_access,
    run_pace,
};
use refineid_pkcs15::{Pkcs15Error, Pkcs15Ops as _};
use refineid_sign::{Pin2ChannelError, Pin2ChannelSignOps, SignScheme};

use crate::authentication_signer::{
    AuthenticationSignFailure, AuthenticationSignature, AuthenticationSigningAlgorithm,
    AuthenticationSigningInput, prepare_signing_input, sign_prepared_or_failure,
};
use crate::card_certificate::{
    CardCertificate, CertificateReadFailure, read_authentication_certificate,
    read_organization_qualified_certificate,
};
use crate::card_management::{CardManagementFailure, CredentialHealthAnswer};
use crate::contactless::{ManagedPin, abort_stale_secure_messaging, read_on_card_ca_certificates};
use crate::pin1_status::{Pin1Preflight, Pin1State};
use crate::pin2_status::{Pin2Preflight, Pin2State};
use crate::qualified_signer::{
    QualifiedSignFailure, QualifiedSignature, QualifiedSigningAlgorithm, QualifiedSigningInput,
    map_certificate_failure, map_directory_error, prepared_qualified_digest,
    sign_with_qualified_key,
};

/// `id-PACE-ECDH-GM-AES-CBC-CMAC-256`, the object-identifier body `MSE:Set
/// AT` names for the suite `run_pace` runs (BSI TR-03110-3 section A.1.1.1).
const ID_PACE_ECDH_GM_AES_CBC_CMAC_256: [u8; 10] =
    [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04];

/// Mechanism-reference object of `MSE:Set AT` (BSI TR-03110-3 section B.14.1).
const TAG_MSE_MECHANISM: u8 = 0x80;
/// Password-reference object of `MSE:Set AT` (BSI TR-03110-3 section B.14.1).
const TAG_MSE_PASSWORD: u8 = 0x83;
/// Domain-reference object of `MSE:Set AT` (BSI TR-03110-3 section B.14.1).
const TAG_MSE_DOMAIN: u8 = 0x84;

/// The tries each PIN and the PUK of the organization card start with
/// (FINEID S4-2 v4.0 section 4.3), which `MSE:Set AT` answers as success
/// (BSI TR-03110-3 section B.14.1).
const INITIAL_TRIES: u8 = 5;

/// What opens a card on the contactless interface, as its EF.CardAccess
/// tells before any password is sent.
///
/// The citizen cards list brainpoolP384r1 alone (FINEID S4-1 v4.2 section
/// 3.2); the organization card lists NIST P-256 and P-384 alone (FINEID
/// S4-2 v4.0 section 6; doc/reference/pace.md in refineid-core).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContactlessCardKind {
    /// Opens with the Card Access Number printed on the card.
    Personal,
    /// Opens with PIN 1, PIN 2 or the PUK.
    Organization,
}

/// The kind `card_access` names; `None` for a file that lists no suite this
/// software runs or mixes the two families, to which no password is sent.
pub(crate) fn contactless_card_kind(card_access: &CardAccess) -> Option<ContactlessCardKind> {
    card_access.generic_mapping_suite()?;
    let mut lists_brainpool = false;
    let mut lists_nist = false;
    for info in card_access.pace_infos() {
        match info.domain() {
            PaceDomain::BrainpoolP384r1 => lists_brainpool = true,
            PaceDomain::NistP256 | PaceDomain::NistP384 => lists_nist = true,
        }
    }
    match (lists_brainpool, lists_nist) {
        (true, false) => Some(ContactlessCardKind::Personal),
        (false, true) => Some(ContactlessCardKind::Organization),
        (true, true) | (false, false) => None,
    }
}

/// Why an operation's channel did not open. No variant carries a value
/// entered by the holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelRefusal {
    /// The entry is not a shape the credential's type accepts; nothing went
    /// to the card.
    InvalidEntry,
    /// The retry floor refused: two or one tries left, an unreadable counter
    /// or a deactivated credential. Nothing followed `MSE:Set AT`.
    BelowFloor,
    /// The card answered that the credential is blocked.
    Blocked,
    /// The card refused the credential and reports these tries left.
    Wrong { retries_left: u8 },
    /// The card refused the handshake and no count could be read after it.
    Rejected,
    /// The card in the field does not list the organization card's suites;
    /// no password was named to it.
    NotOrganizationCard,
    /// The card left the field.
    CardUnavailable,
    /// The exchange failed or left the card's state unknown.
    Transport,
    /// A local fault that never reached the card.
    Bridge,
}

impl ChannelRefusal {
    const fn into_authentication(self) -> AuthenticationSignFailure {
        match self {
            Self::InvalidEntry => AuthenticationSignFailure::InvalidPin,
            Self::BelowFloor => AuthenticationSignFailure::SafetyRefused,
            Self::Blocked => AuthenticationSignFailure::PinLocked,
            Self::Wrong { retries_left } => AuthenticationSignFailure::WrongPin { retries_left },
            Self::Rejected => AuthenticationSignFailure::VerificationRejected,
            Self::NotOrganizationCard => AuthenticationSignFailure::PaceRejected,
            Self::CardUnavailable => AuthenticationSignFailure::CardUnavailable,
            Self::Transport => AuthenticationSignFailure::Transport,
            Self::Bridge => AuthenticationSignFailure::Bridge,
        }
    }

    const fn into_qualified(self) -> QualifiedSignFailure {
        match self {
            Self::InvalidEntry => QualifiedSignFailure::InvalidPin,
            Self::BelowFloor => QualifiedSignFailure::SafetyRefused,
            Self::Blocked => QualifiedSignFailure::PinLocked,
            Self::Wrong { retries_left } => QualifiedSignFailure::WrongPin { retries_left },
            Self::Rejected => QualifiedSignFailure::VerificationRejected,
            Self::NotOrganizationCard | Self::Transport => QualifiedSignFailure::Transport,
            Self::CardUnavailable => QualifiedSignFailure::CardUnavailable,
            Self::Bridge => QualifiedSignFailure::Bridge,
        }
    }

    /// The answer to a management operation: a refused credential is the
    /// card's own outcome, every other refusal a failure.
    fn into_management(self) -> Result<ManageOutcome, CardManagementFailure> {
        match self {
            Self::InvalidEntry => Err(CardManagementFailure::InvalidCredential),
            Self::BelowFloor => Err(CardManagementFailure::SafetyRefused),
            Self::Blocked => Ok(ManageOutcome::Locked),
            Self::Wrong { retries_left } => PinRetries::from_nibble(retries_left)
                .map(|retries_left| ManageOutcome::WrongCredential { retries_left })
                .ok_or(CardManagementFailure::BridgeError),
            Self::Rejected | Self::Transport => Err(CardManagementFailure::TransportError),
            Self::NotOrganizationCard => Err(CardManagementFailure::PaceRejected),
            Self::CardUnavailable => Err(CardManagementFailure::CardUnavailable),
            Self::Bridge => Err(CardManagementFailure::BridgeError),
        }
    }
}

/// The credential whose counter a password reference names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OrganizationCredential {
    Pin1,
    Pin2,
    Puk,
}

impl OrganizationCredential {
    /// The card's security-data-object identifier, which `MSE:Set AT` names
    /// (FINEID S4-2 v4.0 sections 4.2, 4.3 and 6).
    const fn reference(self) -> u8 {
        match self {
            Self::Pin1 => PinReferenceScheme::Organizational.reference(PinSlot::Pin1),
            Self::Pin2 => PinReferenceScheme::Organizational.reference(PinSlot::Pin2),
            Self::Puk => PinReferenceScheme::Organizational.puk_reference(),
        }
    }
}

fn outcome_refusal(outcome: &TransportOutcome) -> ChannelRefusal {
    match outcome {
        TransportOutcome::NoCard | TransportOutcome::ReaderRemoved => {
            ChannelRefusal::CardUnavailable
        }
        TransportOutcome::TimeoutUnknownState
        | TransportOutcome::CardReset
        | TransportOutcome::ProtocolDesync
        | TransportOutcome::Response(_) => ChannelRefusal::Transport,
    }
}

fn pkcs15_refusal<E>(error: &Pkcs15Error<E>) -> ChannelRefusal {
    match error {
        Pkcs15Error::Outcome(outcome) => outcome_refusal(outcome),
        Pkcs15Error::Status(_)
        | Pkcs15Error::Transport(_)
        | Pkcs15Error::Empty
        | Pkcs15Error::TooLarge
        | Pkcs15Error::InvalidData(_) => ChannelRefusal::Transport,
        Pkcs15Error::Aid(_) | Pkcs15Error::Command(_) => ChannelRefusal::Bridge,
    }
}

/// The master file made current and EF.CardAccess read, in plain. A card
/// that is not an organization card stops here, with nothing but these
/// reads sent to it.
fn organization_card_access<T: CardTransport>(
    transport: &mut T,
) -> Result<CardAccess, ChannelRefusal> {
    abort_stale_secure_messaging(transport).map_err(|failure| failure.into_refusal())?;
    let card_access = read_card_access(transport).map_err(|error| match error {
        PaceError::CardAccessRead(read) => pkcs15_refusal(&read),
        PaceError::Outcome(outcome) => outcome_refusal(&outcome),
        _ => ChannelRefusal::NotOrganizationCard,
    })?;
    match contactless_card_kind(&card_access) {
        Some(ContactlessCardKind::Organization) => Ok(card_access),
        Some(ContactlessCardKind::Personal) | None => Err(ChannelRefusal::NotOrganizationCard),
    }
}

/// `credential`'s state as `MSE:Set AT` reports it, which spends no try (BSI
/// TR-03110-3 section B.14.1): the answer the handshake's floor reads, asked
/// without a handshake following it.
fn counter_from_mse<T: CardTransport>(
    transport: &mut T,
    card_access: &CardAccess,
    credential: OrganizationCredential,
) -> Result<PinStatus, ChannelRefusal> {
    let suite = card_access
        .generic_mapping_suite()
        .ok_or(ChannelRefusal::NotOrganizationCard)?;
    let mut encoder = BerEncoder::with_capacity(ID_PACE_ECDH_GM_AES_CBC_CMAC_256.len());
    encoder
        .push_tlv(TAG_MSE_MECHANISM, ID_PACE_ECDH_GM_AES_CBC_CMAC_256)
        .and_then(|()| encoder.push_tlv(TAG_MSE_PASSWORD, [credential.reference()]))
        .and_then(|()| encoder.push_tlv(TAG_MSE_DOMAIN, [suite.domain().parameter_id()]))
        .map_err(|_encoding| ChannelRefusal::Bridge)?;
    let command = MseSetAt {
        data: encoder.finish(),
    }
    .into_apdu()
    .map_err(|_encoding| ChannelRefusal::Bridge)?;
    let response = transport
        .transmit(&command)
        .map_err(|_transport| ChannelRefusal::Transport)?
        .into_response()
        .map_err(|outcome| outcome_refusal(&outcome))?;
    Ok(status_from_mse(response.status_word()))
}

/// The state an `MSE:Set AT` status word reports (BSI TR-03110-3 section
/// B.14.1; doc/reference/pace.md in refineid-core).
fn status_from_mse(status: StatusWord) -> PinStatus {
    match status {
        StatusWord::Success => {
            PinRetries::from_nibble(INITIAL_TRIES).map_or(PinStatus::NoInfo, PinStatus::Remaining)
        }
        StatusWord::PinIncorrect { retries } if retries.is_exhausted() => PinStatus::Locked,
        StatusWord::PinIncorrect { retries } => PinStatus::Remaining(retries),
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            PinStatus::Locked
        }
        other => PinStatus::Other(other),
    }
}

/// `credential`'s counter read in plain, with no secret and no try spent. A
/// card that is not an organization card is refused after its EF.CardAccess.
pub(crate) fn read_organization_counter<T: CardTransport>(
    transport: &mut T,
    credential: OrganizationCredential,
) -> Result<PinStatus, ChannelRefusal> {
    let card_access = organization_card_access(transport)?;
    counter_from_mse(transport, &card_access, credential)
}

/// What a failed handshake comes to. A refusal that carries no count has the
/// counter read back, so a try the card took is never spent silently.
fn handshake_refusal<T: CardTransport>(
    transport: &mut T,
    card_access: &CardAccess,
    credential: OrganizationCredential,
    error: PaceError<T::Error>,
) -> ChannelRefusal {
    match error {
        PaceError::RetryFloor(_) | PaceError::PasswordDeactivated => ChannelRefusal::BelowFloor,
        PaceError::WrongPin { retries_left } | PaceError::WrongPuk { retries_left } => {
            if retries_left.is_exhausted() {
                ChannelRefusal::Blocked
            } else {
                ChannelRefusal::Wrong {
                    retries_left: retries_left.get(),
                }
            }
        }
        PaceError::Status(_, StatusWord::AuthenticationBlocked) => ChannelRefusal::Blocked,
        PaceError::Status(_, _) | PaceError::AuthMismatch => {
            if abort_stale_secure_messaging(transport).is_err() {
                return ChannelRefusal::Rejected;
            }
            match counter_from_mse(transport, card_access, credential) {
                Ok(PinStatus::Remaining(retries)) => ChannelRefusal::Wrong {
                    retries_left: retries.get(),
                },
                Ok(PinStatus::Locked) => ChannelRefusal::Blocked,
                Ok(PinStatus::Verified | PinStatus::NoInfo | PinStatus::Other(_)) | Err(_) => {
                    ChannelRefusal::Rejected
                }
            }
        }
        PaceError::Outcome(outcome) => outcome_refusal(&outcome),
        PaceError::CardAccessRead(read) => pkcs15_refusal(&read),
        PaceError::Transport(_)
        | PaceError::Ber(_)
        | PaceError::UnexpectedResponse(_)
        | PaceError::InvalidPoint
        | PaceError::ReflectedKey
        | PaceError::CardAccess(_)
        | PaceError::NoSupportedSuite => ChannelRefusal::Transport,
        PaceError::Encoding | PaceError::Random(_) => ChannelRefusal::Bridge,
    }
}

/// One PACE with `password` on an organization card. The password goes
/// nowhere else: a card whose EF.CardAccess does not name it an organization
/// card gets no `MSE:Set AT`.
fn open_channel<T: CardTransport, P: PacePassword>(
    mut transport: T,
    password: &P,
    credential: OrganizationCredential,
) -> Result<SmTransport<T, P::OpenedBy>, (ChannelRefusal, T)> {
    let card_access = match organization_card_access(&mut transport) {
        Ok(card_access) => card_access,
        Err(refusal) => return Err((refusal, transport)),
    };
    let handshake: Result<PaceSession<P::OpenedBy>, _> =
        run_pace(&mut transport, &card_access, password);
    match handshake {
        Ok(session) => Ok(SmTransport::new(transport, session)),
        Err(error) => {
            let refusal = handshake_refusal(&mut transport, &card_access, credential, error);
            Err((refusal, transport))
        }
    }
}

fn pin1_entry(bytes: Vec<u8>) -> Result<Pin1, ChannelRefusal> {
    Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(bytes))
        .map_err(|_shape| ChannelRefusal::InvalidEntry)
}

fn puk_entry(bytes: Vec<u8>) -> Result<Puk, ChannelRefusal> {
    Puk::reconstruct(UnvalidatedSecret::from_owned_bytes(bytes))
        .map_err(|_shape| ChannelRefusal::InvalidEntry)
}

/// The counter-safe PIN 1 reading the session keeps, from `MSE:Set AT`'s
/// answer or the channel's record of it.
pub(crate) fn pin1_preflight_of(status: PinStatus) -> Pin1Preflight {
    let state = match status {
        PinStatus::Verified => Pin1State::Verified,
        PinStatus::Remaining(retries) => Pin1State::Remaining(retries.get()),
        PinStatus::Locked => Pin1State::Locked,
        PinStatus::NoInfo => Pin1State::NoInformation,
        PinStatus::Other(_) => Pin1State::Unrecognised,
    };
    Pin1Preflight {
        scheme: PinReferenceScheme::Organizational,
        state,
        retry_floor_permits: check_retry_floor(FlooredCredential::Pin1, status).is_ok(),
    }
}

/// The counter-safe PIN 2 reading from `MSE:Set AT`'s answer.
pub(crate) fn pin2_preflight_of(status: PinStatus) -> Pin2Preflight {
    let state = match status {
        PinStatus::Verified => Pin2State::Verified,
        PinStatus::Remaining(retries) => Pin2State::Remaining(retries.get()),
        PinStatus::Locked => Pin2State::Locked,
        PinStatus::NoInfo => Pin2State::NoInformation,
        PinStatus::Other(_) => Pin2State::Unrecognised,
    };
    Pin2Preflight {
        scheme: PinReferenceScheme::Organizational,
        state,
        retry_floor_permits: check_retry_floor(FlooredCredential::Pin2, status).is_ok(),
    }
}

/// What opening an organization card with PIN 1 came to.
pub(crate) enum OrganizationOpenOutcome {
    /// PIN 1 opened the channel: the certificates read through it, and the
    /// PIN 1 reading the floor served.
    Ready {
        certificate: CardCertificate,
        preflight: Pin1Preflight,
        qualified: Result<CardCertificate, CertificateReadFailure>,
    },
    /// The channel did not open, or the card did not answer through it.
    Refused(AuthenticationSignFailure),
    /// The channel opened and the authentication certificate did not read.
    Unreadable(CertificateReadFailure),
}

/// PACE with PIN 1, then the certificates through the channel. PIN 1 is spent
/// on this one handshake.
pub(crate) fn organization_open<T: CardTransport>(
    transport: T,
    pin_bytes: Vec<u8>,
) -> (OrganizationOpenOutcome, T) {
    let pin = match pin1_entry(pin_bytes) {
        Ok(pin) => pin,
        Err(refusal) => {
            return (
                OrganizationOpenOutcome::Refused(refusal.into_authentication()),
                transport,
            );
        }
    };
    let mut secure = match open_channel(transport, &pin, OrganizationCredential::Pin1) {
        Ok(secure) => secure,
        Err((refusal, transport)) => {
            return (
                OrganizationOpenOutcome::Refused(refusal.into_authentication()),
                transport,
            );
        }
    };
    let preflight = pin1_preflight_of(secure.pin1_counter());
    if let Err(error) = secure.select_pkcs15_application() {
        return (
            OrganizationOpenOutcome::Refused(pkcs15_refusal(&error).into_authentication()),
            secure.into_inner(),
        );
    }
    let outcome = match read_authentication_certificate(&mut secure) {
        Ok(certificate) => {
            read_on_card_ca_certificates(&mut secure);
            // Optional, so read last: a refused select of an absent file can
            // leave another file current.
            let qualified = read_organization_qualified_certificate(&mut secure);
            OrganizationOpenOutcome::Ready {
                certificate,
                preflight,
                qualified,
            }
        }
        Err(failure) => OrganizationOpenOutcome::Unreadable(failure),
    };
    (outcome, secure.into_inner())
}

/// PACE with PIN 1 and nothing after it: a completed handshake is the card's
/// proof of the digits (FINEID S4-2 v4.0 section 6).
pub(crate) fn organization_verify_pin1<T: CardTransport>(
    transport: T,
    pin_bytes: Vec<u8>,
) -> (Result<(), AuthenticationSignFailure>, T) {
    let pin = match pin1_entry(pin_bytes) {
        Ok(pin) => pin,
        Err(refusal) => return (Err(refusal.into_authentication()), transport),
    };
    match open_channel(transport, &pin, OrganizationCredential::Pin1) {
        Ok(secure) => (Ok(()), secure.into_inner()),
        Err((refusal, transport)) => (Err(refusal.into_authentication()), transport),
    }
}

/// One authentication signature: PACE with PIN 1 is the presentation, so the
/// application is selected and the key signs with no VERIFY.
pub(crate) fn organization_authenticate_and_sign<T: CardTransport>(
    transport: T,
    algorithm: AuthenticationSigningAlgorithm,
    pin_bytes: Vec<u8>,
    input: AuthenticationSigningInput<'_>,
) -> (
    Result<AuthenticationSignature, AuthenticationSignFailure>,
    T,
) {
    let pin_input = UnvalidatedSecret::from_owned_bytes(pin_bytes);
    let prepared = match prepare_signing_input(algorithm, input) {
        Ok(prepared) => prepared,
        Err(failure) => return (Err(failure), transport),
    };
    let pin = match Pin1::reconstruct(pin_input) {
        Ok(pin) => pin,
        Err(_shape) => return (Err(AuthenticationSignFailure::InvalidPin), transport),
    };
    let mut secure = match open_channel(transport, &pin, OrganizationCredential::Pin1) {
        Ok(secure) => secure,
        Err((refusal, transport)) => return (Err(refusal.into_authentication()), transport),
    };
    let result = match secure.select_pkcs15_application() {
        Ok(()) => sign_prepared_or_failure(&mut secure, SignScheme::Organizational, prepared)
            .map(|bytes| AuthenticationSignature { algorithm, bytes }),
        Err(error) => Err(pkcs15_refusal(&error).into_authentication()),
    };
    (result, secure.into_inner())
}

/// One qualified signature: PACE with PIN 2 is the one presentation of that
/// signature (FINEID S4-1 v4.2 sections 4.1 and 8.1.7), which core's
/// `qualified_key_after_pin2_pace` spends, so no VERIFY goes out. The card's
/// certificate is compared with the one the signed content names first.
pub(crate) fn organization_qualified_sign<T: CardTransport>(
    transport: T,
    algorithm: QualifiedSigningAlgorithm,
    pin_bytes: Vec<u8>,
    input: QualifiedSigningInput<'_>,
    expected_certificate: &[u8],
) -> (Result<QualifiedSignature, QualifiedSignFailure>, T) {
    let pin_input = UnvalidatedSecret::from_owned_bytes(pin_bytes);
    let digest = match prepared_qualified_digest(input) {
        Ok(digest) => digest,
        Err(failure) => return (Err(failure), transport),
    };
    let pin = match Pin2::reconstruct(pin_input) {
        Ok(pin) => pin,
        Err(_shape) => return (Err(QualifiedSignFailure::InvalidPin), transport),
    };
    let mut secure = match open_channel(transport, &pin, OrganizationCredential::Pin2) {
        Ok(secure) => secure,
        Err((refusal, transport)) => return (Err(refusal.into_qualified()), transport),
    };
    let result = sign_on_pin2_channel(&mut secure, algorithm, digest, expected_certificate);
    (result, secure.into_inner())
}

fn sign_on_pin2_channel<S: Pin2ChannelSignOps>(
    secure: &mut S,
    algorithm: QualifiedSigningAlgorithm,
    digest: refineid_digest::Sha384,
    expected_certificate: &[u8],
) -> Result<QualifiedSignature, QualifiedSignFailure> {
    let certificate =
        read_organization_qualified_certificate(secure).map_err(map_certificate_failure)?;
    if certificate.der().as_bytes() != expected_certificate {
        return Err(QualifiedSignFailure::CertificateMismatch);
    }
    if !algorithm.accepts_profile(certificate.profile()) {
        return Err(QualifiedSignFailure::KeyProfileMismatch);
    }
    sign_on_handshake_presentation(secure, algorithm, digest)
}

/// The qualified key on the handshake's presentation of PIN 2: DF.ESIGN made
/// current, one signature, no VERIFY.
fn sign_on_handshake_presentation<S: Pin2ChannelSignOps>(
    secure: &mut S,
    algorithm: QualifiedSigningAlgorithm,
    digest: refineid_digest::Sha384,
) -> Result<QualifiedSignature, QualifiedSignFailure> {
    let key = secure
        .qualified_key_after_pin2_pace()
        .map_err(|error| match error {
            Pin2ChannelError::PresentationSpent(_) => QualifiedSignFailure::Bridge,
            Pin2ChannelError::Directory(directory) => map_directory_error(directory),
        })?;
    sign_with_qualified_key(key, algorithm, digest)
}

/// The health the plain `MSE:Set AT` answers report: each credential's
/// counter, with no secret. Nothing before PACE names the card's lengths or
/// its activation record, so a blocked PIN reads as blocked, whichever way it
/// came to be, and the PUK sets it the same way.
pub(crate) fn organization_credential_health<T: CardTransport>(
    transport: &mut T,
) -> Result<CredentialHealthAnswer, CardManagementFailure> {
    let answer = |refusal: ChannelRefusal| match refusal.into_management() {
        Ok(_) => CardManagementFailure::TransportError,
        Err(failure) => failure,
    };
    let card_access = organization_card_access(transport).map_err(answer)?;
    let pin1_status =
        counter_from_mse(transport, &card_access, OrganizationCredential::Pin1).map_err(answer)?;
    let pin2_status =
        counter_from_mse(transport, &card_access, OrganizationCredential::Pin2).map_err(answer)?;
    let puk_status =
        counter_from_mse(transport, &card_access, OrganizationCredential::Puk).map_err(answer)?;
    Ok(CredentialHealthAnswer {
        report: CredentialHealthReport {
            pin1_status,
            pin2_status,
            puk_status,
            pin_reference_scheme: PinReferenceScheme::Organizational,
            activation_scheme: None,
            activation_needs: None,
        },
        lengths: Some(CardPinLengths::not_listed(
            PinReferenceScheme::Organizational,
        )),
    })
}

fn management_auth_failure<E>(error: AuthError<E>) -> CardManagementFailure {
    crate::card_management::map_auth_error(error)
}

/// The card's PIN and PUK lengths inside a channel, under the numbering the
/// channel's type fixes, so no header-only probe resolves it.
fn lengths_on_channel<S: CardTransport>(
    secure: &mut S,
) -> Result<CardPinLengths, CardManagementFailure> {
    secure
        .read_card_pin_lengths_with_scheme(PinReferenceScheme::Organizational)
        .map_err(management_auth_failure)
}

/// PIN 1 changed: PACE with the current PIN, then core's change on that
/// channel, floored on the channel's record. The card takes the change with
/// the current PIN presented again (doc/reference/pace.md in refineid-core).
pub(crate) fn organization_change_pin1<T: CardTransport>(
    transport: T,
    current_bytes: Vec<u8>,
    new_bytes: Vec<u8>,
) -> (Result<ManageOutcome, CardManagementFailure>, T) {
    let opening_bytes = current_bytes.clone();
    let entries = pin1_entry(opening_bytes).and_then(|opening| {
        let current = pin1_entry(current_bytes)?;
        let new = pin1_entry(new_bytes)?;
        Ok((opening, current, new))
    });
    let (opening, current, new) = match entries {
        Ok(entries) => entries,
        Err(refusal) => return (refusal.into_management(), transport),
    };
    let mut secure = match open_channel(transport, &opening, OrganizationCredential::Pin1) {
        Ok(secure) => secure,
        Err((refusal, transport)) => return (refusal.into_management(), transport),
    };
    let result = match secure.select_pkcs15_application() {
        Ok(()) => lengths_on_channel(&mut secure).and_then(|lengths| {
            secure
                .change_pin1_after_pin1_pace(&lengths, new, ChannelProof::PresentAgain(current))
                .map_err(management_auth_failure)
        }),
        Err(error) => pkcs15_refusal(&error).into_management(),
    };
    (result, secure.into_inner())
}

/// A blocked PIN set: PACE with the PUK, then core's reset on that channel,
/// which carries only the new PIN and spends no PUK try (doc/reference/pace.md
/// in refineid-core). PIN 2 is local to DF.ESIGN, so that directory is made
/// current for its reset.
pub(crate) fn organization_reset_pin<T: CardTransport>(
    transport: T,
    pin: ManagedPin,
    puk_bytes: Vec<u8>,
    new_bytes: Vec<u8>,
) -> (Result<ManageOutcome, CardManagementFailure>, T) {
    let puk = match puk_entry(puk_bytes) {
        Ok(puk) => puk,
        Err(refusal) => return (refusal.into_management(), transport),
    };
    let new_entry = UnvalidatedSecret::from_owned_bytes(new_bytes);
    let mut secure = match open_channel(transport, &puk, OrganizationCredential::Puk) {
        Ok(secure) => secure,
        Err((refusal, transport)) => return (refusal.into_management(), transport),
    };
    let result = match secure.select_pkcs15_application() {
        Ok(()) => lengths_on_channel(&mut secure).and_then(|lengths| match pin {
            ManagedPin::Pin1 => {
                let new = Pin1::reconstruct(new_entry)
                    .map_err(|_shape| CardManagementFailure::InvalidCredential)?;
                secure
                    .reset_pin1_after_puk_pace(&lengths, new, ChannelProof::PaceHandshake)
                    .map_err(management_auth_failure)
            }
            ManagedPin::Pin2 => {
                let new = Pin2::reconstruct(new_entry)
                    .map_err(|_shape| CardManagementFailure::InvalidCredential)?;
                secure
                    .select_esign_directory()
                    .map_err(|_directory| CardManagementFailure::TransportError)?;
                secure
                    .reset_pin2_after_puk_pace(&lengths, new, ChannelProof::PaceHandshake)
                    .map_err(management_auth_failure)
            }
        }),
        Err(error) => pkcs15_refusal(&error).into_management(),
    };
    (result, secure.into_inner())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use refineid_apdu::{
        ApduClass, CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu,
        StatusWord, TransportOutcome,
    };
    use refineid_auth::{ManageOutcome, Pin1, PinReferenceScheme, PinSlot, PinStatus};
    use refineid_ber::{BerEncoder, tlv};
    use refineid_digest::Sha384;
    use refineid_pace::testkit::OrganizationalCard;
    use refineid_pace::{CardAccess, PaceDomain, UnvalidatedCardAccess};
    use refineid_sign::RSA_3072_SIG_BYTES;

    use super::{
        ChannelRefusal, ContactlessCardKind, ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
        OrganizationCredential, contactless_card_kind, open_channel,
        organization_authenticate_and_sign, organization_change_pin1,
        organization_credential_health, organization_open, organization_qualified_sign,
        organization_reset_pin, organization_verify_pin1, read_organization_counter,
        sign_on_handshake_presentation,
    };
    use crate::authentication_signer::{
        AuthenticationSignFailure, AuthenticationSigningAlgorithm, AuthenticationSigningInput,
    };
    use crate::card_management::CardManagementFailure;
    use crate::contactless::ManagedPin;
    use crate::qualified_signer::{
        QualifiedSignFailure, QualifiedSigningAlgorithm, QualifiedSigningInput,
    };

    /// Synthetic credentials, ASCII digits within the organizational bounds.
    const SYNTHETIC_PIN1: &[u8] = b"1357";
    const SYNTHETIC_NEW_PIN1: &[u8] = b"2468";
    const SYNTHETIC_PIN2: &[u8] = b"135790";
    const SYNTHETIC_NEW_PIN2: &[u8] = b"246801";
    const SYNTHETIC_PUK: &[u8] = b"97531864";
    const SYNTHETIC_MESSAGE: &[u8] = b"synthetic message";
    const SYNTHETIC_CERTIFICATE: &[u8] = b"synthetic certificate";

    /// `id-PACE-ECDH-IM-AES-CBC-CMAC-256`, which the organization card also
    /// lists (BSI TR-03110-3 section A.1.1.1).
    const ID_PACE_ECDH_IM_AES_CBC_CMAC_256: [u8; 10] =
        [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x04];
    const PACE_VERSION: u8 = 2;
    const TAG_OID: u8 = 0x06;
    const TAG_INTEGER: u8 = 0x02;
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_SET: u8 = 0x31;

    const INS_SELECT: u8 = 0xA4;
    const INS_READ_BINARY: u8 = 0xB0;
    const INS_MSE: u8 = 0x22;
    const INS_GENERAL_AUTHENTICATE: u8 = 0x86;
    const INS_VERIFY: u8 = 0x20;
    const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;
    const INS_RESET_RETRY_COUNTER: u8 = 0x2C;
    const INS_INDEX: usize = 1;
    const P1_INDEX: usize = 2;
    const P2_INDEX: usize = 3;
    const LE_MAX_READ: usize = 256;
    const SW_DEACTIVATED: StatusWord = StatusWord::Other(0x6283);
    const SW_NOT_SATISFIED_NO_COUNT: StatusWord = StatusWord::Other(0x6300);
    const SW_REFERENCE_NOT_FOUND: StatusWord = StatusWord::ReferenceDataNotFound;
    /// Password-reference object of `MSE:Set AT`, tag and length.
    const MSE_PASSWORD_HEADER: [u8; 2] = [0x83, 0x01];
    /// More scripted successes than any one operation consumes.
    const ENOUGH_ANSWERS: usize = 8;
    /// An ordinary digest filler for the signature fixtures.
    const SIGNATURE_FILL: u8 = 0xC3;
    const DIGEST_FILL: u8 = 0x5A;
    const SHA256_DIGEST_LENGTH: usize = 32;
    const SHA384_DIGEST_LENGTH: usize = 48;

    fn retries(count: u8) -> StatusWord {
        StatusWord::PinIncorrect {
            retries: PinRetries::from_nibble(count).expect("counter value"),
        }
    }

    fn pace_info(oid: [u8; 10], domain: PaceDomain) -> Vec<u8> {
        let mut fields = BerEncoder::default();
        fields.push_tlv(TAG_OID, oid).expect("the OID encodes");
        fields
            .push_tlv(TAG_INTEGER, [PACE_VERSION])
            .expect("the version encodes");
        fields
            .push_tlv(TAG_INTEGER, [domain.parameter_id()])
            .expect("the parameter encodes");
        tlv(TAG_SEQUENCE, fields.finish()).expect("PACEInfo encodes")
    }

    fn card_access_file(infos: &[Vec<u8>]) -> Vec<u8> {
        tlv(TAG_SET, infos.concat()).expect("the SET encodes")
    }

    /// The four entries the Idemia Cosmo X organization card lists
    /// (doc/reference/pace.md in refineid-core).
    fn organization_file() -> Vec<u8> {
        card_access_file(&[
            pace_info(ID_PACE_ECDH_GM_AES_CBC_CMAC_256, PaceDomain::NistP256),
            pace_info(ID_PACE_ECDH_IM_AES_CBC_CMAC_256, PaceDomain::NistP256),
            pace_info(ID_PACE_ECDH_GM_AES_CBC_CMAC_256, PaceDomain::NistP384),
            pace_info(ID_PACE_ECDH_IM_AES_CBC_CMAC_256, PaceDomain::NistP384),
        ])
    }

    /// The generic-mapping suite of the synthetic card, the one it runs.
    fn testkit_file() -> Vec<u8> {
        card_access_file(&[pace_info(
            ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
            PaceDomain::NistP384,
        )])
    }

    fn citizen_file() -> Vec<u8> {
        card_access_file(&[pace_info(
            ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
            PaceDomain::BrainpoolP384r1,
        )])
    }

    fn parsed(file: Vec<u8>) -> CardAccess {
        CardAccess::parse(UnvalidatedCardAccess::from_card_bytes(file)).expect("the fixture parses")
    }

    fn status(sw: StatusWord) -> ResponseApdu {
        let [sw1, sw2] = sw.as_u16().to_be_bytes();
        ResponseApdu {
            body: Vec::new(),
            sw1,
            sw2,
        }
    }

    fn answer(body: Vec<u8>) -> ResponseApdu {
        ResponseApdu {
            body,
            ..status(StatusWord::Success)
        }
    }

    fn successes() -> Vec<ResponseApdu> {
        vec![status(StatusWord::Success); ENOUGH_ANSWERS]
    }

    /// Serves SELECT and READ BINARY of `file` in the clear, as the card does
    /// before PACE, and hands every other command to `inner`. Records the
    /// plain commands it was sent.
    struct PlainFront<C> {
        file: Vec<u8>,
        plain: Vec<Vec<u8>>,
        inner: C,
    }

    impl<C> PlainFront<C> {
        fn new(file: Vec<u8>, inner: C) -> Self {
            Self {
                file,
                plain: Vec::new(),
                inner,
            }
        }

        fn sent(&self, instruction: u8) -> usize {
            self.plain
                .iter()
                .filter(|command| command.get(INS_INDEX) == Some(&instruction))
                .count()
        }
    }

    impl<C: CardTransport<Error = String>> CardTransport for PlainFront<C> {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let bytes = command.as_bytes().to_vec();
            let plain = bytes.first() == Some(&ApduClass::Plain.as_byte());
            let instruction = bytes[INS_INDEX];
            if plain && instruction == INS_SELECT {
                self.plain.push(bytes);
                return Ok(TransportOutcome::Response(status(StatusWord::Success)));
            }
            if plain && instruction == INS_READ_BINARY {
                let offset =
                    (usize::from(bytes[P1_INDEX]) << u8::BITS) | usize::from(bytes[P2_INDEX]);
                let end = (offset + LE_MAX_READ).min(self.file.len());
                let body = self.file.get(offset..end).unwrap_or_default().to_vec();
                self.plain.push(bytes);
                return Ok(TransportOutcome::Response(answer(body)));
            }
            if bytes.first() != Some(&ApduClass::SecureMessaging.as_byte()) {
                self.plain.push(bytes);
            }
            self.inner.transmit(command)
        }

        fn transmit_credential(
            &mut self,
            command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.inner.transmit_credential(command)
        }
    }

    /// Answers `MSE:Set AT` and `GENERAL AUTHENTICATE` from scripts; the
    /// handshake never completes against it.
    #[derive(Default)]
    struct Script {
        mse: VecDeque<StatusWord>,
        general_authenticate: VecDeque<StatusWord>,
    }

    impl Script {
        fn mse(words: &[StatusWord]) -> Self {
            Self {
                mse: words.iter().copied().collect(),
                general_authenticate: VecDeque::new(),
            }
        }

        fn then_general_authenticate(mut self, words: &[StatusWord]) -> Self {
            self.general_authenticate = words.iter().copied().collect();
            self
        }
    }

    impl CardTransport for Script {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let word = match command.as_bytes().get(INS_INDEX) {
                Some(&INS_MSE) => self.mse.pop_front(),
                Some(&INS_GENERAL_AUTHENTICATE) => self.general_authenticate.pop_front(),
                _ => None,
            }
            .ok_or_else(|| "no scripted answer".to_owned())?;
            Ok(TransportOutcome::Response(status(word)))
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("no credential command is expected".to_owned())
        }
    }

    fn scripted(script: Script) -> PlainFront<Script> {
        PlainFront::new(organization_file(), script)
    }

    fn pin1_card(answers: Vec<ResponseApdu>) -> PlainFront<OrganizationalCard> {
        PlainFront::new(
            testkit_file(),
            OrganizationalCard::new(
                PinReferenceScheme::Organizational.reference(PinSlot::Pin1),
                SYNTHETIC_PIN1,
                answers,
            ),
        )
    }

    fn pin2_card(answers: Vec<ResponseApdu>) -> PlainFront<OrganizationalCard> {
        PlainFront::new(
            testkit_file(),
            OrganizationalCard::new(
                PinReferenceScheme::Organizational.reference(PinSlot::Pin2),
                SYNTHETIC_PIN2,
                answers,
            ),
        )
    }

    fn puk_card(answers: Vec<ResponseApdu>) -> PlainFront<OrganizationalCard> {
        PlainFront::new(
            testkit_file(),
            OrganizationalCard::new(
                PinReferenceScheme::Organizational.puk_reference(),
                SYNTHETIC_PUK,
                answers,
            ),
        )
    }

    /// No VERIFY of any shape reached the card over secure messaging.
    fn no_verify(card: &OrganizationalCard) -> bool {
        card.protected_commands()
            .iter()
            .all(|command| command.get(INS_INDEX) != Some(&INS_VERIFY))
    }

    fn verify_with(script: Script) -> (Result<(), AuthenticationSignFailure>, PlainFront<Script>) {
        organization_verify_pin1(scripted(script), SYNTHETIC_PIN1.to_vec())
    }

    #[test]
    fn the_card_access_file_names_the_kind() {
        assert_eq!(
            contactless_card_kind(&parsed(organization_file())),
            Some(ContactlessCardKind::Organization)
        );
        assert_eq!(
            contactless_card_kind(&parsed(citizen_file())),
            Some(ContactlessCardKind::Personal)
        );
    }

    #[test]
    fn a_file_mixing_the_families_or_lacking_generic_mapping_names_no_kind() {
        let mixed = card_access_file(&[
            pace_info(ID_PACE_ECDH_GM_AES_CBC_CMAC_256, PaceDomain::NistP384),
            pace_info(
                ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
                PaceDomain::BrainpoolP384r1,
            ),
        ]);
        assert_eq!(contactless_card_kind(&parsed(mixed)), None);
        let integrated_only = card_access_file(&[pace_info(
            ID_PACE_ECDH_IM_AES_CBC_CMAC_256,
            PaceDomain::NistP384,
        )]);
        assert_eq!(contactless_card_kind(&parsed(integrated_only)), None);
    }

    #[test]
    fn a_pin_is_never_named_to_a_citizen_card() {
        let (outcome, card) = organization_verify_pin1(
            PlainFront::new(citizen_file(), Script::default()),
            SYNTHETIC_PIN1.to_vec(),
        );
        assert_eq!(outcome, Err(AuthenticationSignFailure::PaceRejected));
        assert_eq!(card.sent(INS_MSE), 0, "no MSE:Set AT names a password");
        assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 0);
    }

    #[test]
    fn no_credential_is_named_to_a_citizen_card_on_any_path() {
        let (_, card) = organization_open(
            PlainFront::new(citizen_file(), Script::default()),
            SYNTHETIC_PIN1.to_vec(),
        );
        assert_eq!(card.sent(INS_MSE), 0);

        let (outcome, card) = organization_qualified_sign(
            PlainFront::new(citizen_file(), Script::default()),
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Message(SYNTHETIC_MESSAGE),
            SYNTHETIC_CERTIFICATE,
        );
        assert!(matches!(outcome, Err(QualifiedSignFailure::Transport)));
        assert_eq!(card.sent(INS_MSE), 0);

        let (outcome, card) = organization_reset_pin(
            PlainFront::new(citizen_file(), Script::default()),
            ManagedPin::Pin1,
            SYNTHETIC_PUK.to_vec(),
            SYNTHETIC_NEW_PIN1.to_vec(),
        );
        assert_eq!(outcome, Err(CardManagementFailure::PaceRejected));
        assert_eq!(card.sent(INS_MSE), 0);

        let mut card = PlainFront::new(citizen_file(), Script::default());
        assert_eq!(
            read_organization_counter(&mut card, OrganizationCredential::Pin1),
            Err(ChannelRefusal::NotOrganizationCard)
        );
        assert_eq!(card.sent(INS_MSE), 0);
    }

    #[test]
    fn each_credential_is_named_by_its_own_reference() {
        for (credential, reference) in [
            (
                OrganizationCredential::Pin1,
                PinReferenceScheme::Organizational.reference(PinSlot::Pin1),
            ),
            (
                OrganizationCredential::Pin2,
                PinReferenceScheme::Organizational.reference(PinSlot::Pin2),
            ),
            (
                OrganizationCredential::Puk,
                PinReferenceScheme::Organizational.puk_reference(),
            ),
        ] {
            let mut card = scripted(Script::mse(&[StatusWord::Success]));
            read_organization_counter(&mut card, credential).expect("the counter reads");
            let mse = card
                .plain
                .iter()
                .find(|command| command.get(INS_INDEX) == Some(&INS_MSE))
                .expect("one MSE:Set AT");
            let named: Vec<u8> = [MSE_PASSWORD_HEADER.as_slice(), &[reference]].concat();
            assert!(
                mse.windows(named.len()).any(|window| window == named),
                "MSE:Set AT names the credential's reference"
            );
        }
    }

    #[test]
    fn a_counter_read_is_mse_alone_and_spends_nothing() {
        let mut card = scripted(Script::mse(&[retries(3)]));
        assert_eq!(
            read_organization_counter(&mut card, OrganizationCredential::Pin1),
            Ok(PinStatus::Remaining(
                PinRetries::from_nibble(3).expect("counter value")
            ))
        );
        assert_eq!(card.sent(INS_MSE), 1);
        assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 0);
        assert_eq!(card.sent(INS_VERIFY), 0);
    }

    #[test]
    fn the_counter_reads_the_mse_answers() {
        let five = PinRetries::from_nibble(5).expect("counter value");
        for (word, expected) in [
            (StatusWord::Success, PinStatus::Remaining(five)),
            (retries(0), PinStatus::Locked),
            (StatusWord::AuthenticationBlocked, PinStatus::Locked),
            (SW_DEACTIVATED, PinStatus::Other(SW_DEACTIVATED)),
        ] {
            let mut card = scripted(Script::mse(&[word]));
            assert_eq!(
                read_organization_counter(&mut card, OrganizationCredential::Pin2),
                Ok(expected)
            );
        }
    }

    #[test]
    fn health_reads_all_three_counters_with_no_secret() {
        let mut card = scripted(Script::mse(&[StatusWord::Success, retries(0), retries(4)]));
        let answer = organization_credential_health(&mut card).expect("the card answers");
        assert_eq!(answer.report.pin2_status, PinStatus::Locked);
        assert_eq!(
            answer.report.puk_status,
            PinStatus::Remaining(PinRetries::from_nibble(4).expect("counter value"))
        );
        assert!(answer.lengths.is_some());
        assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 0);
    }

    #[test]
    fn the_floor_refuses_at_two_and_one_tries_left_with_nothing_after_mse() {
        for tries in [2, 1] {
            let (outcome, card) = verify_with(Script::mse(&[retries(tries)]));
            assert_eq!(outcome, Err(AuthenticationSignFailure::SafetyRefused));
            assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 0);
        }
    }

    #[test]
    fn the_floor_refuses_a_deactivated_password_with_nothing_after_mse() {
        let (outcome, card) = verify_with(Script::mse(&[SW_DEACTIVATED]));
        assert_eq!(outcome, Err(AuthenticationSignFailure::SafetyRefused));
        assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 0);
    }

    #[test]
    fn an_unreadable_counter_sends_nothing_after_mse() {
        let (outcome, card) = verify_with(Script::mse(&[
            SW_REFERENCE_NOT_FOUND,
            SW_REFERENCE_NOT_FOUND,
        ]));
        assert_eq!(
            outcome,
            Err(AuthenticationSignFailure::VerificationRejected)
        );
        assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 0);
    }

    #[test]
    fn the_handshake_goes_out_at_five_four_and_three_tries_left() {
        for word in [StatusWord::Success, retries(4), retries(3)] {
            let (outcome, card) =
                verify_with(Script::mse(&[word]).then_general_authenticate(&[retries(2)]));
            assert_eq!(
                outcome,
                Err(AuthenticationSignFailure::WrongPin { retries_left: 2 })
            );
            assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 1);
        }
    }

    #[test]
    fn at_no_tries_left_the_card_answers_for_itself() {
        let (outcome, card) = verify_with(
            Script::mse(&[retries(0)])
                .then_general_authenticate(&[StatusWord::AuthenticationBlocked]),
        );
        assert_eq!(outcome, Err(AuthenticationSignFailure::PinLocked));
        assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 1);
    }

    #[test]
    fn a_refusal_without_a_count_reads_the_count_back() {
        let (outcome, card) = verify_with(
            Script::mse(&[StatusWord::Success, retries(4)])
                .then_general_authenticate(&[SW_NOT_SATISFIED_NO_COUNT]),
        );
        assert_eq!(
            outcome,
            Err(AuthenticationSignFailure::WrongPin { retries_left: 4 })
        );
        assert_eq!(card.sent(INS_MSE), 2);
        assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 1);
    }

    #[test]
    fn a_wrong_puk_reports_the_pucks_own_count() {
        let (outcome, _) = organization_reset_pin(
            scripted(Script::mse(&[StatusWord::Success]).then_general_authenticate(&[retries(4)])),
            ManagedPin::Pin1,
            SYNTHETIC_PUK.to_vec(),
            SYNTHETIC_NEW_PIN1.to_vec(),
        );
        assert_eq!(
            outcome,
            Ok(ManageOutcome::WrongCredential {
                retries_left: PinRetries::from_nibble(4).expect("counter value")
            })
        );
    }

    #[test]
    fn the_puk_floor_refuses_at_two_tries_left() {
        let (outcome, card) = organization_reset_pin(
            scripted(Script::mse(&[retries(2)])),
            ManagedPin::Pin1,
            SYNTHETIC_PUK.to_vec(),
            SYNTHETIC_NEW_PIN1.to_vec(),
        );
        assert_eq!(outcome, Err(CardManagementFailure::SafetyRefused));
        assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 0);
    }

    #[test]
    fn a_malformed_entry_reaches_no_card() {
        let (outcome, card) = organization_verify_pin1(scripted(Script::default()), b"12".to_vec());
        assert_eq!(outcome, Err(AuthenticationSignFailure::InvalidPin));
        assert!(card.plain.is_empty());
    }

    #[test]
    fn pin1_opens_the_channel_with_no_verify_on_the_wire() {
        let (outcome, card) =
            organization_verify_pin1(pin1_card(Vec::new()), SYNTHETIC_PIN1.to_vec());
        assert_eq!(outcome, Ok(()));
        assert!(card.inner.protected_commands().is_empty());
    }

    #[test]
    fn the_channel_keeps_the_mse_answer_as_its_record() {
        use refineid_auth::Pin1PaceChannel as _;
        let card = PlainFront::new(
            testkit_file(),
            OrganizationalCard::new(
                PinReferenceScheme::Organizational.reference(PinSlot::Pin1),
                SYNTHETIC_PIN1,
                Vec::new(),
            )
            .answering_mse_with(retries(3)),
        );
        let pin = Pin1::reconstruct(refineid_auth::UnvalidatedSecret::from_owned_bytes(
            SYNTHETIC_PIN1.to_vec(),
        ))
        .expect("valid PIN 1 fixture");
        let channel = open_channel(card, &pin, OrganizationCredential::Pin1)
            .map_err(|(refusal, _)| refusal)
            .expect("the channel opens");
        assert_eq!(
            channel.pin1_counter(),
            PinStatus::Remaining(PinRetries::from_nibble(3).expect("counter value"))
        );
    }

    #[test]
    fn the_authentication_key_signs_on_the_handshake_with_no_verify() {
        let signature = vec![SIGNATURE_FILL; RSA_3072_SIG_BYTES];
        let digest = [DIGEST_FILL; SHA256_DIGEST_LENGTH];
        let (outcome, card) = organization_authenticate_and_sign(
            pin1_card(vec![
                status(StatusWord::Success),
                status(StatusWord::Success),
                answer(signature.clone()),
            ]),
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            SYNTHETIC_PIN1.to_vec(),
            AuthenticationSigningInput::Prehashed(&digest),
        );
        let signed = outcome.expect("the synthetic card signs");
        assert_eq!(signed.bytes, signature);
        assert!(no_verify(&card.inner));
        assert_eq!(card.inner.credential_commands(), 0);
    }

    #[test]
    fn the_qualified_key_signs_on_the_handshake_with_no_verify() {
        let signature = vec![SIGNATURE_FILL; RSA_3072_SIG_BYTES];
        let digest = Sha384::from_bytes([DIGEST_FILL; SHA384_DIGEST_LENGTH]);
        let card = pin2_card(vec![
            status(StatusWord::Success),
            status(StatusWord::Success),
            status(StatusWord::Success),
            answer(signature.clone()),
        ]);
        let pin = refineid_auth::Pin2::reconstruct(
            refineid_auth::UnvalidatedSecret::from_owned_bytes(SYNTHETIC_PIN2.to_vec()),
        )
        .expect("valid PIN 2 fixture");
        let mut channel = open_channel(card, &pin, OrganizationCredential::Pin2)
            .map_err(|(refusal, _)| refusal)
            .expect("the channel opens");
        let signed = sign_on_handshake_presentation(
            &mut channel,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            digest,
        )
        .expect("the synthetic card signs");
        assert_eq!(signed.bytes, signature);

        // One presentation, one signature: a second key takes a VERIFY.
        let second = sign_on_handshake_presentation(
            &mut channel,
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            digest,
        );
        assert!(matches!(second, Err(QualifiedSignFailure::Bridge)));
        let card = channel.into_inner();
        assert!(no_verify(&card.inner));
        assert_eq!(card.inner.credential_commands(), 0);
    }

    #[test]
    fn an_unreadable_qualified_certificate_signs_nothing() {
        let (outcome, card) = organization_qualified_sign(
            pin2_card(successes()),
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Message(SYNTHETIC_MESSAGE),
            SYNTHETIC_CERTIFICATE,
        );
        assert!(outcome.is_err());
        assert!(no_verify(&card.inner));
        assert_eq!(card.inner.credential_commands(), 0);
    }

    #[test]
    fn pin1_is_changed_on_its_own_channel_presented_once_more() {
        let (outcome, card) = organization_change_pin1(
            pin1_card(successes()),
            SYNTHETIC_PIN1.to_vec(),
            SYNTHETIC_NEW_PIN1.to_vec(),
        );
        assert_eq!(outcome, Ok(ManageOutcome::Ok));
        assert_eq!(card.inner.credential_commands(), 1);
        assert!(no_verify(&card.inner));
        assert!(
            card.inner
                .protected_commands()
                .iter()
                .any(|command| command.get(INS_INDEX) == Some(&INS_CHANGE_REFERENCE_DATA))
        );
    }

    #[test]
    fn a_change_below_the_floor_never_opens_the_channel() {
        let (outcome, card) = organization_change_pin1(
            scripted(Script::mse(&[retries(2)])),
            SYNTHETIC_PIN1.to_vec(),
            SYNTHETIC_NEW_PIN1.to_vec(),
        );
        assert_eq!(outcome, Err(CardManagementFailure::SafetyRefused));
        assert_eq!(card.sent(INS_GENERAL_AUTHENTICATE), 0);
    }

    #[test]
    fn a_blocked_pin_is_set_on_the_puk_channel_with_only_the_new_pin() {
        for (pin, new_pin) in [
            (ManagedPin::Pin1, SYNTHETIC_NEW_PIN1),
            (ManagedPin::Pin2, SYNTHETIC_NEW_PIN2),
        ] {
            let (outcome, card) = organization_reset_pin(
                puk_card(successes()),
                pin,
                SYNTHETIC_PUK.to_vec(),
                new_pin.to_vec(),
            );
            assert_eq!(outcome, Ok(ManageOutcome::Ok));
            assert!(no_verify(&card.inner), "the PUK is not presented again");
            let reset = card
                .inner
                .protected_commands()
                .iter()
                .find(|command| command.get(INS_INDEX) == Some(&INS_RESET_RETRY_COUNTER))
                .expect("one RESET RETRY COUNTER");
            assert!(
                reset.windows(new_pin.len()).any(|window| window == new_pin),
                "the reset carries the new PIN"
            );
            assert!(
                !reset
                    .windows(SYNTHETIC_PUK.len())
                    .any(|window| window == SYNTHETIC_PUK),
                "the reset does not carry the PUK"
            );
        }
    }

    #[test]
    fn pin2_is_reset_inside_df_esign() {
        let (_, card) = organization_reset_pin(
            puk_card(successes()),
            ManagedPin::Pin2,
            SYNTHETIC_PUK.to_vec(),
            SYNTHETIC_NEW_PIN2.to_vec(),
        );
        let commands = card.inner.protected_commands();
        let reset = commands
            .iter()
            .position(|command| command.get(INS_INDEX) == Some(&INS_RESET_RETRY_COUNTER))
            .expect("one RESET RETRY COUNTER");
        assert_eq!(
            commands
                .get(reset - 1)
                .and_then(|command| command.get(INS_INDEX)),
            Some(&INS_SELECT),
            "DF.ESIGN is selected right before the reset"
        );
    }
}
