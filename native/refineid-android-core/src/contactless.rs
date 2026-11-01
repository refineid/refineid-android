//! One-shot contactless card operations behind the PACE secure channel.
//!
//! Each operation owns one raw ISO-DEP transport for its whole lifetime:
//! it runs the PACE handshake with the holder's card access number,
//! wraps the transport in secure messaging, selects the PKCS#15
//! application, and performs exactly one logical operation before
//! returning the exchange to the JNI border. No channel state survives
//! the call; the next operation runs PACE again. The secure-messaging
//! layer is itself a card transport, so the reviewed public operations
//! run unchanged above it (FINEID S4-2; BSI TR-03110).

use std::sync::Mutex;

use refineid_apdu::{CardTransport, TransportOutcome};
use refineid_pace::{
    Can, PaceError, PacePassword, PaceSession, SmTransport, UnvalidatedCan, read_card_access,
    run_pace,
};
use refineid_pkcs15::{CertSlot, Pkcs15Error, Pkcs15Ops};

use crate::authentication_signer::{
    AuthenticationSignFailure, AuthenticationSignature, AuthenticationSigningAlgorithm,
    AuthenticationSigningInput, authenticate_and_sign, verify_authentication_pin,
};
use crate::card_certificate::{
    CardCertificate, CertificateReadFailure, IntermediateCaCertificate, RootCaCertificate,
    map_pkcs15_error, read_authentication_certificate, read_qualified_certificate,
};
use crate::card_management::{
    CardManagementFailure, CredentialHealthAnswer, PinLengthsRead, activate_card, change_pin1,
    change_pin2, decided_activation_scheme, probe_credential_health, unblock_pin1, unblock_pin2,
};
use crate::card_transport::CardExchangeLevel;
use crate::card_transport::{AndroidCardTransport, SingleBlockExchange};
use crate::certificate_validity::validity_start_epoch_seconds;
use crate::pin1_status::{Pin1Preflight, Pin1PreflightFailure, probe_pin1_preflight};
use crate::pin2_status::{Pin2Preflight, Pin2PreflightFailure, probe_pin2_preflight};
use crate::qualified_signer::{
    QualifiedCertificateSource, QualifiedSignFailure, QualifiedSignature,
    QualifiedSigningAlgorithm, QualifiedSigningInput, qualified_sign,
};
use refineid_auth::{
    ActivationReport, ActivationScheme, CardActivationNeeds, ManageOutcome, PinManageOps,
};

/// Coarse failures of the secure-channel front door, before any
/// operation-specific vocabulary applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecureChannelFailure {
    /// Card left the field during the handshake.
    CardUnavailable,
    /// The card refused the handshake; almost always a wrong CAN.
    PaceRejected,
    /// The exchange failed, desynchronized, or left state uncertain.
    Transport,
    /// A local shape or facility failure that never touched the card.
    Bridge,
}

/// The host half of one live contactless secure-messaging session: the
/// PACE keys and the send-sequence counter, held between JNI calls for as
/// long as the reader keeps the RF field up. The card keeps its matching
/// half alive across that same field; rebuilding [`SmTransport`] from this
/// stored session on each call keeps host and card in step, so every
/// operation after the connect skips the PACE handshake and pays only a
/// cheap PKCS#15 re-select. Dropping the field (close, card removed) clears
/// the slot and the keys with it. One slot: the reader drives one card at a
/// time, and a fresh connect supersedes whatever it held.
static HELD_SESSION: Mutex<Option<PaceSession>> = Mutex::new(None);

/// Adopt the live session for reuse by the next operation under the same
/// field. A poisoned lock silently drops the session: the next operation
/// finds no session and the holder reconnects, which is the safe outcome.
fn store_held_session(session: PaceSession) {
    if let Ok(mut slot) = HELD_SESSION.lock() {
        *slot = Some(session);
    }
}

/// Take the live session, leaving the slot empty. The caller either rebuilds
/// the channel and stores the advanced session back, or lets it drop and the
/// keys with it.
fn take_held_session() -> Option<PaceSession> {
    HELD_SESSION.lock().ok().and_then(|mut slot| slot.take())
}

/// Drop any held session and the keys with it. Idempotent: closing an
/// already-closed session is a no-op.
pub(crate) fn contactless_close() {
    if let Ok(mut slot) = HELD_SESSION.lock() {
        *slot = None;
    }
}

/// The latest on-card root CA certificate extracted from EF.4334.
static LAST_READ_ROOT_CA: Mutex<Option<RootCaCertificate>> = Mutex::new(None);

/// The latest on-card intermediate CA certificate extracted from EF.4336.
static LAST_READ_INTERMEDIATE_CA: Mutex<Option<IntermediateCaCertificate>> = Mutex::new(None);

pub(crate) fn get_last_read_root_ca() -> Option<RootCaCertificate> {
    LAST_READ_ROOT_CA
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

pub(crate) fn set_last_read_root_ca(cert: Option<RootCaCertificate>) {
    if let Ok(mut guard) = LAST_READ_ROOT_CA.lock() {
        *guard = cert;
    }
}

pub(crate) fn get_last_read_intermediate_ca() -> Option<IntermediateCaCertificate> {
    LAST_READ_INTERMEDIATE_CA
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

pub(crate) fn set_last_read_intermediate_ca(cert: Option<IntermediateCaCertificate>) {
    if let Ok(mut guard) = LAST_READ_INTERMEDIATE_CA.lock() {
        *guard = cert;
    }
}

fn read_on_card_ca_certificates_if_needed<T: CardTransport + Pkcs15Ops>(secure: &mut T) {
    if get_last_read_root_ca().is_some() && get_last_read_intermediate_ca().is_some() {
        return;
    }
    let mut read_any = false;
    if get_last_read_root_ca().is_none()
        && let Ok(cert) = secure.read_certificate(CertSlot::RootCa)
        && let Ok(root_ca) = RootCaCertificate::from_unvalidated(cert)
    {
        set_last_read_root_ca(Some(root_ca));
        read_any = true;
    }
    if get_last_read_intermediate_ca().is_none()
        && let Ok(cert) = secure.read_certificate(CertSlot::IssuingCaEcc)
        && let Ok(inter_ca) = IntermediateCaCertificate::from_unvalidated(cert)
    {
        set_last_read_intermediate_ca(Some(inter_ca));
        read_any = true;
    }
    if read_any {
        let _ = secure.select_pkcs15_application();
    }
}

pub(crate) enum ContactlessOpenOutcome {
    Ready(CardCertificate, Pin1Preflight),
    /// The card still awaits activation: its scheme, and which PINs. Its
    /// certificate is read for the scheme alone and is not returned.
    ActivationRequired(ActivationScheme, CardActivationNeeds),
    Failure(CertificateReadFailure),
}

/// The first-tap classification, inside the secure channel (FINEID S4-1
/// section 4.6): the core decides the scheme from the card's resolved
/// credential numbering and the validity start of the authentication
/// certificate already read, and the needs come from the card by
/// counter-safe probes alone. An organization card takes section 4.6.1
/// whatever the date. A citizen card whose validity start cannot be read
/// gets no activation decision and is opened as an activated card; a card
/// the probes cannot answer for is treated the same, so a transient fault
/// never routes an activated card to activation.
fn activation_needs<T: CardTransport>(
    transport: &mut T,
    certificate: &CardCertificate,
) -> Option<(ActivationScheme, CardActivationNeeds)> {
    let validity_start = validity_start_epoch_seconds(certificate.der().as_bytes());
    let scheme = decided_activation_scheme(transport, validity_start)?;
    let needs = transport.activation_needs(scheme).ok()?;
    needs.any().then_some((scheme, needs))
}

/// The open sequence after the PKCS#15 selection: the authentication
/// certificate, then the activation classification from it, then, for a
/// card that awaits no activation, the on-card CA certificates and the
/// counter-safe PIN1 preflight. A card awaiting activation returns no
/// identity.
fn open_selected<T>(secure: &mut T) -> ContactlessOpenOutcome
where
    T: CardTransport + Pkcs15Ops,
{
    let certificate = match read_authentication_certificate(secure) {
        Ok(certificate) => certificate,
        Err(failure) => return ContactlessOpenOutcome::Failure(failure),
    };
    if let Some((scheme, needs)) = activation_needs(secure, &certificate) {
        return ContactlessOpenOutcome::ActivationRequired(scheme, needs);
    }
    read_on_card_ca_certificates_if_needed(secure);
    match probe_pin1_preflight(secure) {
        Ok(preflight) => ContactlessOpenOutcome::Ready(certificate, preflight),
        Err(failure) => ContactlessOpenOutcome::Failure(open_preflight_failure(failure)),
    }
}

/// One PACE handshake, then the PKCS#15 selection, authentication
/// certificate read, and counter-safe PIN1 preflight inside the same
/// secure-messaging session. This is the contactless session opener:
/// everything the browser path caches arrives under one handshake.
pub(crate) fn contactless_open<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
) -> (ContactlessOpenOutcome, Exchange) {
    let (outcome, transport) = match open_secure_channel(transport, can_bytes) {
        Ok(mut secure) => {
            let outcome = match secure.select_pkcs15_application().map_err(map_pkcs15_error) {
                Err(failure) => ContactlessOpenOutcome::Failure(failure),
                Ok(()) => open_selected(&mut secure),
            };
            (outcome, secure.into_inner())
        }
        Err((exchange, failure)) => (
            ContactlessOpenOutcome::Failure(certificate_channel_failure(failure)),
            AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu),
        ),
    };
    (outcome, transport.into_exchange())
}

/// PACE, then secure messaging, then the one-shot preflight, VERIFY,
/// and signing sequence. The PIN is zeroized on every path that stops
/// before the reviewed signer consumes it.
pub(crate) fn contactless_authenticate_and_sign<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
    algorithm: AuthenticationSigningAlgorithm,
    mut pin_bytes: Vec<u8>,
    input: AuthenticationSigningInput<'_>,
) -> (
    Result<AuthenticationSignature, AuthenticationSignFailure>,
    Exchange,
) {
    let mut secure = match open_secure_channel(transport, can_bytes) {
        Ok(secure) => secure,
        Err((exchange, failure)) => {
            pin_bytes.fill(0);
            return (Err(sign_channel_failure(failure)), exchange);
        }
    };
    if let Err(error) = secure.select_pkcs15_application() {
        pin_bytes.fill(0);
        return (
            Err(sign_selection_failure(error)),
            secure.into_inner().into_exchange(),
        );
    }
    let result = authenticate_and_sign(&mut secure, algorithm, pin_bytes, input);
    (result, secure.into_inner().into_exchange())
}

/// The persistent-session opener. One PACE handshake, then the PKCS#15
/// selection, authentication-certificate read, and counter-safe PIN1
/// preflight -- byte for byte the one-shot [`contactless_open`] sequence.
/// The one difference is the ending: on full success the live
/// secure-messaging session (keys and send-sequence counter) is retained,
/// so the sign that follows reuses this channel instead of running PACE a
/// second time. A failed open retains nothing and the holder reconnects.
pub(crate) fn contactless_connect<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
) -> (ContactlessOpenOutcome, Exchange) {
    // A fresh connect supersedes any session a prior card left behind.
    contactless_close();
    let (outcome, transport, session) = match open_secure_channel(transport, can_bytes) {
        Ok(mut secure) => {
            let outcome = match secure.select_pkcs15_application().map_err(map_pkcs15_error) {
                Err(failure) => ContactlessOpenOutcome::Failure(failure),
                Ok(()) => open_selected(&mut secure),
            };
            let (transport, session) = secure.into_parts();
            (outcome, transport, Some(session))
        }
        Err((exchange, failure)) => (
            ContactlessOpenOutcome::Failure(certificate_channel_failure(failure)),
            AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu),
            None,
        ),
    };

    if matches!(
        outcome,
        ContactlessOpenOutcome::Ready(_, _) | ContactlessOpenOutcome::ActivationRequired(..)
    ) && let Some(session) = session
    {
        store_held_session(session);
    }
    (outcome, transport.into_exchange())
}

/// The authentication signature on an already-open session: no PACE, only
/// a cheap PKCS#15 re-select before VERIFY and signing on the retained
/// channel. The PIN is zeroized on every path that stops before the
/// reviewed signer consumes it. On completion the advanced session is
/// retained for any further operation under the same field. A missing
/// session -- never connected, or the field dropped between calls -- is a
/// bridge fault: the holder connects again to prove a fresh CAN.
pub(crate) fn contactless_authenticate_and_sign_on_session<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    algorithm: AuthenticationSigningAlgorithm,
    mut pin_bytes: Vec<u8>,
    input: AuthenticationSigningInput<'_>,
) -> (
    Result<AuthenticationSignature, AuthenticationSignFailure>,
    Exchange,
) {
    let Some(session) = take_held_session() else {
        pin_bytes.fill(0);
        return (
            Err(AuthenticationSignFailure::CardUnavailable),
            transport.into_exchange(),
        );
    };
    let mut secure = SmTransport::new(transport, session);
    if let Err(error) = secure.select_pkcs15_application() {
        pin_bytes.fill(0);
        // The channel is troubled; drop the session and require a reconnect.
        return (
            Err(sign_selection_failure(error)),
            secure.into_inner().into_exchange(),
        );
    }
    let result = authenticate_and_sign(&mut secure, algorithm, pin_bytes, input);
    // Keep the advanced session alive for any further operation this field.
    let (transport, session) = secure.into_parts();
    store_held_session(session);
    (result, transport.into_exchange())
}

/// Verify PIN1 on the retained secure channel and preserve its advanced state.
pub(crate) fn contactless_verify_pin1_on_session<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    mut pin_bytes: Vec<u8>,
) -> (Result<(), AuthenticationSignFailure>, Exchange) {
    let Some(session) = take_held_session() else {
        pin_bytes.fill(0);
        return (
            Err(AuthenticationSignFailure::CardUnavailable),
            transport.into_exchange(),
        );
    };
    let mut secure = SmTransport::new(transport, session);
    if let Err(error) = secure.select_pkcs15_application() {
        pin_bytes.fill(0);
        return (
            Err(sign_selection_failure(error)),
            secure.into_inner().into_exchange(),
        );
    }
    let result = verify_authentication_pin(&mut secure, pin_bytes);
    let (transport, session) = secure.into_parts();
    store_held_session(session);
    (result, transport.into_exchange())
}

/// Serve the qualified-certificate read across the PACE secure channel.
/// Secure messaging is itself a card transport, so the reviewed
/// EF.4332 read runs unchanged above it, exactly as on the wired path.
impl<T: CardTransport> QualifiedCertificateSource for SmTransport<T> {
    fn read_qualified_certificate_for_signing(
        &mut self,
    ) -> Result<CardCertificate, CertificateReadFailure> {
        read_qualified_certificate(self)
    }
}

/// The qualified-certificate read inside `channel`. The read leaves
/// EF.4332 selected; the next operation re-selects the PKCS#15
/// application, so no authentication context has to be restored here.
pub(crate) fn contactless_read_qualified_certificate<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    channel: ContactlessChannel,
) -> (Result<CardCertificate, CertificateReadFailure>, Exchange) {
    match open_contactless_channel(transport, channel) {
        Ok(mut open) => {
            let result = read_qualified_certificate(&mut open.secure);
            (result, close_contactless_channel(open))
        }
        Err((failure, exchange)) => {
            let failure = match failure {
                ChannelOpenFailure::Handshake(failure) => certificate_channel_failure(failure),
                ChannelOpenFailure::NoHeldSession => CertificateReadFailure::CardUnavailable,
                ChannelOpenFailure::Selection(error) => map_pkcs15_error(error),
            };
            (Err(failure), exchange)
        }
    }
}

/// The counter-safe PIN2 preflight inside `channel`. The session CAN was
/// proven at connect, so a channel refusal here folds to a transport
/// anomaly, not a CAN fault.
pub(crate) fn contactless_probe_pin2<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    channel: ContactlessChannel,
) -> (Result<Pin2Preflight, Pin2PreflightFailure>, Exchange) {
    match open_contactless_channel(transport, channel) {
        Ok(mut open) => {
            let result = probe_pin2_preflight(&mut open.secure);
            (result, close_contactless_channel(open))
        }
        Err((failure, exchange)) => {
            let failure = match failure {
                ChannelOpenFailure::Handshake(failure) => pin2_channel_failure(failure),
                ChannelOpenFailure::NoHeldSession => Pin2PreflightFailure::CardUnavailable,
                ChannelOpenFailure::Selection(error) => pin2_selection_failure(error),
            };
            (Err(failure), exchange)
        }
    }
}

/// One qualified signature inside `channel`. The PIN2 is zeroized on
/// every path that stops before the reviewed signer consumes it.
pub(crate) fn contactless_qualified_sign<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    channel: ContactlessChannel,
    algorithm: QualifiedSigningAlgorithm,
    mut pin_bytes: Vec<u8>,
    input: QualifiedSigningInput<'_>,
    expected_certificate: &[u8],
) -> (Result<QualifiedSignature, QualifiedSignFailure>, Exchange) {
    match open_contactless_channel(transport, channel) {
        Ok(mut open) => {
            let result = qualified_sign(
                &mut open.secure,
                algorithm,
                pin_bytes,
                input,
                expected_certificate,
            );
            (result, close_contactless_channel(open))
        }
        Err((failure, exchange)) => {
            pin_bytes.fill(0);
            let failure = match failure {
                ChannelOpenFailure::Handshake(failure) => qualified_channel_failure(failure),
                ChannelOpenFailure::NoHeldSession => QualifiedSignFailure::CardUnavailable,
                ChannelOpenFailure::Selection(error) => qualified_selection_failure(error),
            };
            (Err(failure), exchange)
        }
    }
}

/// The secure channel one contactless operation runs in.
pub(crate) enum ContactlessChannel {
    /// A fresh PACE handshake with this card access number, dropped after
    /// the operation.
    Pace(Vec<u8>),
    /// The session a prior `contactless_connect` left open, kept for the
    /// next operation under the same field.
    HeldSession,
}

/// A card access number not consumed by a handshake is wiped with the
/// channel.
impl Drop for ContactlessChannel {
    fn drop(&mut self) {
        if let Self::Pace(can_bytes) = self {
            can_bytes.fill(0);
        }
    }
}

/// Which PIN a change or unblock sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedPin {
    Pin1,
    Pin2,
}

/// An open contactless channel, selected on the PKCS#15 application, and
/// whether its session is kept after the operation.
struct OpenContactlessChannel<Exchange: SingleBlockExchange> {
    secure: SmTransport<AndroidCardTransport<Exchange>>,
    keeps_session: bool,
}

/// The error of the secure-messaging transport over the Android exchange.
type SecureTransportError<Exchange> =
    <SmTransport<AndroidCardTransport<Exchange>> as CardTransport>::Error;

/// Why a contactless channel did not open; each operation maps it onto
/// its own failure vocabulary.
enum ChannelOpenFailure<E> {
    /// The PACE handshake failed.
    Handshake(SecureChannelFailure),
    /// No session is held: never connected, or the field dropped.
    NoHeldSession,
    /// The PKCS#15 re-select inside the channel failed.
    Selection(Pkcs15Error<E>),
}

/// Open `channel` and select the PKCS#15 application inside it. Every
/// command of the operation then runs inside secure messaging: a card
/// opened under PACE refuses a plain command and ends its channel. A
/// failed re-select drops a held session so the holder reconnects. On
/// failure the exchange is handed back so the JNI border can inspect it.
fn open_contactless_channel<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    channel: ContactlessChannel,
) -> Result<
    OpenContactlessChannel<Exchange>,
    (ChannelOpenFailure<SecureTransportError<Exchange>>, Exchange),
> {
    let mut channel = channel;
    let (mut secure, keeps_session) = match &mut channel {
        ContactlessChannel::Pace(can_bytes) => {
            match open_secure_channel(transport, core::mem::take(can_bytes)) {
                Ok(secure) => (secure, false),
                Err((exchange, failure)) => {
                    return Err((ChannelOpenFailure::Handshake(failure), exchange));
                }
            }
        }
        ContactlessChannel::HeldSession => {
            let Some(session) = take_held_session() else {
                return Err((ChannelOpenFailure::NoHeldSession, transport.into_exchange()));
            };
            (SmTransport::new(transport, session), true)
        }
    };
    match secure.select_pkcs15_application() {
        Ok(()) => Ok(OpenContactlessChannel {
            secure,
            keeps_session,
        }),
        Err(error) => Err((
            ChannelOpenFailure::Selection(error),
            secure.into_inner().into_exchange(),
        )),
    }
}

/// End the operation: keep a held session for the next operation under
/// the same field, drop a one-shot one, and hand the exchange back.
fn close_contactless_channel<Exchange: SingleBlockExchange>(
    channel: OpenContactlessChannel<Exchange>,
) -> Exchange {
    let (transport, session) = channel.secure.into_parts();
    if channel.keeps_session {
        store_held_session(session);
    }
    transport.into_exchange()
}

/// A channel that did not open, in the management vocabulary.
fn management_open_failure<E>(failure: ChannelOpenFailure<E>) -> CardManagementFailure {
    match failure {
        ChannelOpenFailure::Handshake(failure) => management_channel_failure(failure),
        ChannelOpenFailure::NoHeldSession => CardManagementFailure::CardUnavailable,
        ChannelOpenFailure::Selection(error) => management_selection_failure(error),
    }
}

/// The credential health probe inside `channel`, with the card's PIN and
/// PUK lengths when `lengths_read` asks for them.
pub(crate) fn contactless_probe_credential_health<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    channel: ContactlessChannel,
    lengths_read: PinLengthsRead,
) -> (
    Result<CredentialHealthAnswer, CardManagementFailure>,
    Exchange,
) {
    match open_contactless_channel(transport, channel) {
        Ok(mut open) => {
            let result = probe_credential_health(&mut open.secure, lengths_read);
            (result, close_contactless_channel(open))
        }
        Err((failure, exchange)) => (Err(management_open_failure(failure)), exchange),
    }
}

/// Change `pin` inside `channel`, presenting the current value.
pub(crate) fn contactless_change_pin<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    channel: ContactlessChannel,
    pin: ManagedPin,
    mut current_bytes: Vec<u8>,
    mut new_bytes: Vec<u8>,
) -> (Result<ManageOutcome, CardManagementFailure>, Exchange) {
    match open_contactless_channel(transport, channel) {
        Ok(mut open) => {
            let result = match pin {
                ManagedPin::Pin1 => change_pin1(&mut open.secure, current_bytes, new_bytes),
                ManagedPin::Pin2 => change_pin2(&mut open.secure, current_bytes, new_bytes),
            };
            (result, close_contactless_channel(open))
        }
        Err((failure, exchange)) => {
            current_bytes.fill(0);
            new_bytes.fill(0);
            (Err(management_open_failure(failure)), exchange)
        }
    }
}

/// Unblock `pin` with the PUK inside `channel`, setting a new value.
pub(crate) fn contactless_unblock_pin<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    channel: ContactlessChannel,
    pin: ManagedPin,
    mut puk_bytes: Vec<u8>,
    mut new_bytes: Vec<u8>,
) -> (Result<ManageOutcome, CardManagementFailure>, Exchange) {
    match open_contactless_channel(transport, channel) {
        Ok(mut open) => {
            let result = match pin {
                ManagedPin::Pin1 => unblock_pin1(&mut open.secure, puk_bytes, new_bytes),
                ManagedPin::Pin2 => unblock_pin2(&mut open.secure, puk_bytes, new_bytes),
            };
            (result, close_contactless_channel(open))
        }
        Err((failure, exchange)) => {
            puk_bytes.fill(0);
            new_bytes.fill(0);
            (Err(management_open_failure(failure)), exchange)
        }
    }
}

/// Card activation inside `channel`, under the scheme `scheme_byte` names.
pub(crate) fn contactless_activate_card<Exchange: SingleBlockExchange>(
    transport: AndroidCardTransport<Exchange>,
    channel: ContactlessChannel,
    scheme_byte: u8,
    mut code_bytes: Vec<u8>,
    mut new_pin1_bytes: Option<Vec<u8>>,
    mut new_pin2_bytes: Option<Vec<u8>>,
) -> (Result<ActivationReport, CardManagementFailure>, Exchange) {
    match open_contactless_channel(transport, channel) {
        Ok(mut open) => {
            let result = activate_card(
                &mut open.secure,
                scheme_byte,
                code_bytes,
                new_pin1_bytes,
                new_pin2_bytes,
            );
            (result, close_contactless_channel(open))
        }
        Err((failure, exchange)) => {
            code_bytes.fill(0);
            for bytes in [new_pin1_bytes.as_mut(), new_pin2_bytes.as_mut()]
                .into_iter()
                .flatten()
            {
                bytes.fill(0);
            }
            (Err(management_open_failure(failure)), exchange)
        }
    }
}

/// Reconstruct the typed CAN and run the PACE handshake. On failure the
/// exchange is handed back so the JNI border can inspect it.
fn open_secure_channel<Exchange: SingleBlockExchange>(
    mut transport: AndroidCardTransport<Exchange>,
    can_bytes: Vec<u8>,
) -> Result<SmTransport<AndroidCardTransport<Exchange>>, (Exchange, SecureChannelFailure)> {
    let Some(can) = reconstruct_can(can_bytes) else {
        return Err((transport.into_exchange(), SecureChannelFailure::Bridge));
    };
    if let Err(failure) = abort_stale_secure_messaging(&mut transport) {
        return Err((transport.into_exchange(), failure));
    }
    // The PACE suite and its domain parameter come from EF.CardAccess in
    // the master file, read in plain before the handshake. An
    // organization card authenticating PACE with a PIN would pass
    // `PacePassword::Pin1` or `PacePassword::Pin2` here instead of the CAN.
    let handshake = read_card_access(&mut transport)
        .and_then(|card_access| run_pace(&mut transport, &card_access, PacePassword::Can(&can)));
    match handshake {
        Ok(session) => Ok(SmTransport::new(transport, session)),
        Err(error) => {
            let failure = map_pace_error(&error);
            Err((transport.into_exchange(), failure))
        }
    }
}

/// Return a connection possibly left inside an earlier secure-messaging
/// session to plain state before the handshake.
///
/// ISO 7816-4 terminates a secure-messaging session when a plain APDU
/// arrives, and the card may reject that terminating command with a
/// status word (observed on the production FINEID card: the first plain
/// command after a completed session is refused, the next is processed
/// in plain). One replay-safe, credential-free SELECT MF absorbs that
/// termination deterministically; its status word is deliberately not
/// interpreted, and only transport-level faults stop the open.
fn abort_stale_secure_messaging<T: CardTransport>(
    transport: &mut T,
) -> Result<(), SecureChannelFailure> {
    match transport.select_mf() {
        Ok(()) | Err(Pkcs15Error::Status(_)) => Ok(()),
        Err(Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved)) => {
            Err(SecureChannelFailure::CardUnavailable)
        }
        Err(
            Pkcs15Error::Transport(_)
            | Pkcs15Error::Outcome(
                TransportOutcome::TimeoutUnknownState
                | TransportOutcome::CardReset
                | TransportOutcome::ProtocolDesync
                | TransportOutcome::Response(_),
            ),
        ) => Err(SecureChannelFailure::Transport),
        Err(
            Pkcs15Error::Aid(_)
            | Pkcs15Error::Command(_)
            | Pkcs15Error::Empty
            | Pkcs15Error::TooLarge
            | Pkcs15Error::InvalidData(_),
        ) => Err(SecureChannelFailure::Bridge),
    }
}

/// Rebuild the typed CAN from its owned digit bytes; the Kotlin entry
/// gate makes a local shape failure a bridge fault, not a card outcome.
fn reconstruct_can(can_bytes: Vec<u8>) -> Option<Can> {
    let text = match String::from_utf8(can_bytes) {
        Ok(text) => text,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.fill(0);
            return None;
        }
    };
    Can::reconstruct(UnvalidatedCan::from_owned_text(text)).ok()
}

fn map_pace_error<E>(error: &PaceError<E>) -> SecureChannelFailure {
    match error {
        PaceError::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            SecureChannelFailure::CardUnavailable
        }
        PaceError::Status(_, _) | PaceError::AuthMismatch => SecureChannelFailure::PaceRejected,
        PaceError::Transport(_)
        | PaceError::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync
            | TransportOutcome::Response(_),
        )
        | PaceError::Ber(_)
        | PaceError::UnexpectedResponse(_)
        | PaceError::InvalidPoint
        | PaceError::ReflectedKey => SecureChannelFailure::Transport,
        PaceError::CardAccessRead(error) => card_access_read_failure(error),
        PaceError::CardAccess(_) | PaceError::NoSupportedSuite => SecureChannelFailure::Transport,
        // The PIN outcomes answer a PIN password, which this CAN channel
        // never sends.
        PaceError::RetryFloor(_)
        | PaceError::PasswordDeactivated
        | PaceError::WrongPin { .. }
        | PaceError::Encoding
        | PaceError::Random(_) => SecureChannelFailure::Bridge,
    }
}

fn card_access_read_failure<E>(error: &Pkcs15Error<E>) -> SecureChannelFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            SecureChannelFailure::CardUnavailable
        }
        Pkcs15Error::Transport(_)
        | Pkcs15Error::Status(_)
        | Pkcs15Error::Empty
        | Pkcs15Error::TooLarge
        | Pkcs15Error::InvalidData(_)
        | Pkcs15Error::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync
            | TransportOutcome::Response(_),
        ) => SecureChannelFailure::Transport,
        Pkcs15Error::Aid(_) | Pkcs15Error::Command(_) => SecureChannelFailure::Bridge,
    }
}

fn certificate_channel_failure(failure: SecureChannelFailure) -> CertificateReadFailure {
    match failure {
        SecureChannelFailure::CardUnavailable => CertificateReadFailure::CardUnavailable,
        SecureChannelFailure::PaceRejected => CertificateReadFailure::PaceRejected,
        SecureChannelFailure::Transport => CertificateReadFailure::Transport,
        SecureChannelFailure::Bridge => CertificateReadFailure::Bridge,
    }
}

/// Preflight failures inside the opened channel fold onto the open
/// reply's shared failure vocabulary.
fn open_preflight_failure(failure: Pin1PreflightFailure) -> CertificateReadFailure {
    match failure {
        Pin1PreflightFailure::CardUnavailable => CertificateReadFailure::CardUnavailable,
        Pin1PreflightFailure::Transport => CertificateReadFailure::Transport,
        Pin1PreflightFailure::Bridge => CertificateReadFailure::Bridge,
    }
}

fn sign_channel_failure(failure: SecureChannelFailure) -> AuthenticationSignFailure {
    match failure {
        SecureChannelFailure::CardUnavailable => AuthenticationSignFailure::CardUnavailable,
        SecureChannelFailure::PaceRejected => AuthenticationSignFailure::PaceRejected,
        SecureChannelFailure::Transport => AuthenticationSignFailure::Transport,
        SecureChannelFailure::Bridge => AuthenticationSignFailure::Bridge,
    }
}

pub(crate) fn sign_selection_failure<E>(error: Pkcs15Error<E>) -> AuthenticationSignFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            AuthenticationSignFailure::CardUnavailable
        }
        Pkcs15Error::Aid(_) | Pkcs15Error::Command(_) => AuthenticationSignFailure::Bridge,
        Pkcs15Error::Status(_)
        | Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(_)
        | Pkcs15Error::Empty
        | Pkcs15Error::TooLarge
        | Pkcs15Error::InvalidData(_) => AuthenticationSignFailure::Transport,
    }
}

/// The session CAN was proven at connect, so a PACE refusal on this
/// later probe is a transport anomaly rather than a holder-facing fault.
fn pin2_channel_failure(failure: SecureChannelFailure) -> Pin2PreflightFailure {
    match failure {
        SecureChannelFailure::CardUnavailable => Pin2PreflightFailure::CardUnavailable,
        SecureChannelFailure::PaceRejected | SecureChannelFailure::Transport => {
            Pin2PreflightFailure::Transport
        }
        SecureChannelFailure::Bridge => Pin2PreflightFailure::Bridge,
    }
}

fn pin2_selection_failure<E>(error: Pkcs15Error<E>) -> Pin2PreflightFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            Pin2PreflightFailure::CardUnavailable
        }
        Pkcs15Error::Aid(_) | Pkcs15Error::Command(_) => Pin2PreflightFailure::Bridge,
        Pkcs15Error::Status(_)
        | Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(_)
        | Pkcs15Error::Empty
        | Pkcs15Error::TooLarge
        | Pkcs15Error::InvalidData(_) => Pin2PreflightFailure::Transport,
    }
}

fn management_channel_failure(failure: SecureChannelFailure) -> CardManagementFailure {
    match failure {
        SecureChannelFailure::CardUnavailable => CardManagementFailure::CardUnavailable,
        SecureChannelFailure::PaceRejected => CardManagementFailure::PaceRejected,
        SecureChannelFailure::Transport => CardManagementFailure::TransportError,
        SecureChannelFailure::Bridge => CardManagementFailure::BridgeError,
    }
}

fn management_selection_failure<E>(error: Pkcs15Error<E>) -> CardManagementFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            CardManagementFailure::CardUnavailable
        }
        Pkcs15Error::Aid(_) | Pkcs15Error::Command(_) => CardManagementFailure::BridgeError,
        Pkcs15Error::Status(_)
        | Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(_)
        | Pkcs15Error::Empty
        | Pkcs15Error::TooLarge
        | Pkcs15Error::InvalidData(_) => CardManagementFailure::TransportError,
    }
}

/// A channel refusal folds to a transport anomaly: qualified signing
/// carries no CAN-facing outcome, and the session CAN was already proven.
fn qualified_channel_failure(failure: SecureChannelFailure) -> QualifiedSignFailure {
    match failure {
        SecureChannelFailure::CardUnavailable => QualifiedSignFailure::CardUnavailable,
        SecureChannelFailure::PaceRejected | SecureChannelFailure::Transport => {
            QualifiedSignFailure::Transport
        }
        SecureChannelFailure::Bridge => QualifiedSignFailure::Bridge,
    }
}

fn qualified_selection_failure<E>(error: Pkcs15Error<E>) -> QualifiedSignFailure {
    match error {
        Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved) => {
            QualifiedSignFailure::CardUnavailable
        }
        Pkcs15Error::Aid(_) | Pkcs15Error::Command(_) => QualifiedSignFailure::Bridge,
        Pkcs15Error::Status(_)
        | Pkcs15Error::Transport(_)
        | Pkcs15Error::Outcome(_)
        | Pkcs15Error::Empty
        | Pkcs15Error::TooLarge
        | Pkcs15Error::InvalidData(_) => QualifiedSignFailure::Transport,
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::{StatusWord, TransportOutcome};
    use refineid_pace::PaceError;
    use refineid_pkcs15::Pkcs15Error;

    use super::{
        ContactlessChannel, ManagedPin, SecureChannelFailure, contactless_activate_card,
        contactless_change_pin, contactless_close, contactless_probe_credential_health,
        contactless_probe_pin2, contactless_qualified_sign, contactless_read_qualified_certificate,
        contactless_unblock_pin, map_pace_error, open_preflight_failure, pin2_channel_failure,
        qualified_channel_failure, reconstruct_can,
    };
    use crate::card_certificate::CertificateReadFailure;
    use crate::card_management::{ACTIVATION_SCHEME_PUK, CardManagementFailure, PinLengthsRead};
    use crate::card_transport::{
        AndroidCardTransport, CardExchangeLevel, SingleBlockExchange, SingleExchangeOutcome,
    };
    use crate::pin1_status::Pin1PreflightFailure;
    use crate::pin2_status::Pin2PreflightFailure;
    use crate::qualified_signer::{
        QualifiedSignFailure, QualifiedSigningAlgorithm, QualifiedSigningInput,
    };

    // A syntactically valid but meaningless CAN for shape tests only;
    // never a real card value.
    const SYNTHETIC_CAN_DIGITS: &[u8] = b"000000";
    const NON_DIGIT_CAN: &[u8] = b"00000A";
    const SHORT_CAN: &[u8] = b"00000";

    const SYNTHETIC_PIN1: &[u8] = b"1357";
    const SYNTHETIC_NEW_PIN1: &[u8] = b"2468";
    const SYNTHETIC_PUK: &[u8] = b"97531864";

    /// Counts every block it is asked to move and answers none.
    #[derive(Default)]
    struct CountingExchange {
        blocks: usize,
    }

    impl SingleBlockExchange for CountingExchange {
        fn exchange_public(&mut self, _block: &[u8]) -> SingleExchangeOutcome {
            self.blocks += 1;
            SingleExchangeOutcome::NoCard
        }

        fn exchange_credential(&mut self, _block: &[u8]) -> SingleExchangeOutcome {
            self.blocks += 1;
            SingleExchangeOutcome::NoCard
        }
    }

    fn transport() -> AndroidCardTransport<CountingExchange> {
        AndroidCardTransport::new(CountingExchange::default(), CardExchangeLevel::Apdu)
    }

    #[test]
    fn management_without_a_held_session_sends_nothing() {
        contactless_close();
        let unavailable = Err(CardManagementFailure::CardUnavailable);

        let (health, exchange) = contactless_probe_credential_health(
            transport(),
            ContactlessChannel::HeldSession,
            PinLengthsRead::Read,
        );
        assert!(matches!(
            health,
            Err(CardManagementFailure::CardUnavailable)
        ));
        assert_eq!(exchange.blocks, 0);

        let (change, exchange) = contactless_change_pin(
            transport(),
            ContactlessChannel::HeldSession,
            ManagedPin::Pin1,
            SYNTHETIC_PIN1.to_vec(),
            SYNTHETIC_NEW_PIN1.to_vec(),
        );
        assert_eq!(change, unavailable);
        assert_eq!(exchange.blocks, 0);

        let (unblock, exchange) = contactless_unblock_pin(
            transport(),
            ContactlessChannel::HeldSession,
            ManagedPin::Pin1,
            SYNTHETIC_PUK.to_vec(),
            SYNTHETIC_NEW_PIN1.to_vec(),
        );
        assert_eq!(unblock, unavailable);
        assert_eq!(exchange.blocks, 0);

        let (activation, exchange) = contactless_activate_card(
            transport(),
            ContactlessChannel::HeldSession,
            ACTIVATION_SCHEME_PUK,
            SYNTHETIC_PUK.to_vec(),
            Some(SYNTHETIC_NEW_PIN1.to_vec()),
            None,
        );
        assert_eq!(activation, Err(CardManagementFailure::CardUnavailable));
        assert_eq!(exchange.blocks, 0);
    }

    /// Synthetic ASCII stand-ins for the qualified-signature inputs.
    const SYNTHETIC_PIN2: &[u8] = b"135790";
    const SYNTHETIC_MESSAGE: &[u8] = b"synthetic message";
    const SYNTHETIC_CERTIFICATE: &[u8] = b"synthetic certificate";

    #[test]
    fn qualified_operations_without_a_held_session_send_nothing() {
        contactless_close();

        let (certificate, exchange) =
            contactless_read_qualified_certificate(transport(), ContactlessChannel::HeldSession);
        assert!(matches!(
            certificate,
            Err(CertificateReadFailure::CardUnavailable)
        ));
        assert_eq!(exchange.blocks, 0);

        let (pin2, exchange) = contactless_probe_pin2(transport(), ContactlessChannel::HeldSession);
        assert!(matches!(pin2, Err(Pin2PreflightFailure::CardUnavailable)));
        assert_eq!(exchange.blocks, 0);

        let (signature, exchange) = contactless_qualified_sign(
            transport(),
            ContactlessChannel::HeldSession,
            QualifiedSigningAlgorithm::EcdsaP384Sha384,
            SYNTHETIC_PIN2.to_vec(),
            QualifiedSigningInput::Message(SYNTHETIC_MESSAGE),
            SYNTHETIC_CERTIFICATE,
        );
        assert!(matches!(
            signature,
            Err(QualifiedSignFailure::CardUnavailable)
        ));
        assert_eq!(exchange.blocks, 0);
    }

    #[test]
    fn accepts_only_six_digit_can_shapes() {
        assert!(reconstruct_can(SYNTHETIC_CAN_DIGITS.to_vec()).is_some());
        assert!(reconstruct_can(NON_DIGIT_CAN.to_vec()).is_none());
        assert!(reconstruct_can(SHORT_CAN.to_vec()).is_none());
        assert!(reconstruct_can(Vec::new()).is_none());
    }

    #[test]
    fn maps_pace_errors_onto_channel_failures() {
        assert_eq!(
            map_pace_error::<&str>(&PaceError::Outcome(TransportOutcome::NoCard)),
            SecureChannelFailure::CardUnavailable
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::AuthMismatch),
            SecureChannelFailure::PaceRejected
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::Status(
                "mutual-auth",
                StatusWord::AuthenticationFailed,
            )),
            SecureChannelFailure::PaceRejected
        );
        assert_eq!(
            map_pace_error(&PaceError::Transport("backend")),
            SecureChannelFailure::Transport
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::Outcome(TransportOutcome::ProtocolDesync)),
            SecureChannelFailure::Transport
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::ReflectedKey),
            SecureChannelFailure::Transport
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::Encoding),
            SecureChannelFailure::Bridge
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::NoSupportedSuite),
            SecureChannelFailure::Transport
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::PasswordDeactivated),
            SecureChannelFailure::Bridge
        );
    }

    #[test]
    fn maps_card_access_read_errors_onto_channel_failures() {
        assert_eq!(
            map_pace_error::<&str>(&PaceError::CardAccessRead(Pkcs15Error::Outcome(
                TransportOutcome::ReaderRemoved
            ))),
            SecureChannelFailure::CardUnavailable
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::CardAccessRead(Pkcs15Error::Status(
                StatusWord::FileNotFound
            ))),
            SecureChannelFailure::Transport
        );
        assert_eq!(
            map_pace_error(&PaceError::CardAccessRead(Pkcs15Error::Transport(
                "backend"
            ))),
            SecureChannelFailure::Transport
        );
        assert_eq!(
            map_pace_error::<&str>(&PaceError::CardAccessRead(Pkcs15Error::Empty)),
            SecureChannelFailure::Transport
        );
    }

    #[test]
    fn folds_preflight_failures_onto_the_open_vocabulary() {
        assert_eq!(
            open_preflight_failure(Pin1PreflightFailure::CardUnavailable),
            CertificateReadFailure::CardUnavailable
        );
        assert_eq!(
            open_preflight_failure(Pin1PreflightFailure::Transport),
            CertificateReadFailure::Transport
        );
        assert_eq!(
            open_preflight_failure(Pin1PreflightFailure::Bridge),
            CertificateReadFailure::Bridge
        );
    }

    // The session CAN was proven at connect, so a later PACE refusal on
    // the qualified path is a transport anomaly, never a CAN outcome: the
    // PIN2 and qualified-sign vocabularies carry no PACE-rejected code.
    #[test]
    fn folds_channel_failures_onto_the_pin2_vocabulary() {
        assert_eq!(
            pin2_channel_failure(SecureChannelFailure::CardUnavailable),
            Pin2PreflightFailure::CardUnavailable
        );
        assert_eq!(
            pin2_channel_failure(SecureChannelFailure::PaceRejected),
            Pin2PreflightFailure::Transport
        );
        assert_eq!(
            pin2_channel_failure(SecureChannelFailure::Transport),
            Pin2PreflightFailure::Transport
        );
        assert_eq!(
            pin2_channel_failure(SecureChannelFailure::Bridge),
            Pin2PreflightFailure::Bridge
        );
    }

    #[test]
    fn folds_channel_failures_onto_the_qualified_vocabulary() {
        assert_eq!(
            qualified_channel_failure(SecureChannelFailure::CardUnavailable),
            QualifiedSignFailure::CardUnavailable
        );
        assert_eq!(
            qualified_channel_failure(SecureChannelFailure::PaceRejected),
            QualifiedSignFailure::Transport
        );
        assert_eq!(
            qualified_channel_failure(SecureChannelFailure::Transport),
            QualifiedSignFailure::Transport
        );
        assert_eq!(
            qualified_channel_failure(SecureChannelFailure::Bridge),
            QualifiedSignFailure::Bridge
        );
    }
}
