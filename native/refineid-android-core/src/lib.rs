//! Narrow JNI border between Android and the reviewed RefineID core.
//!
//! ATR bytes return only a small typed status. Public authentication and
//! qualified-signature certificates cross back only after the core has bounded
//! each DER read and reconstructed its public key; credential bytes never cross
//! this border.

#![allow(deprecated)]

mod authentication_signer;
mod card_access;
mod card_certificate;
mod card_management;
mod card_transport;
mod certificate_validity;
mod contactless;
mod jni_card_exchange;
mod organization_card;
mod organization_jni;
mod pin_status;
mod qualified_signer;
mod timestamp_trust;

use authentication_signer::{
    AuthenticationSignFailure, AuthenticationSignature, AuthenticationSigningAlgorithm,
    AuthenticationSigningInput, authenticate_and_sign, verify_authentication_pin,
};
use card_access::{CardAccessProbeFailure, CardAccessSummary, probe_card_access};
use card_certificate::{
    CardCertificate, CardKeyProfile, CertificateDer, CertificateReadFailure,
    IntermediateCaCertificate, RootCaCertificate, read_authentication_certificate,
    read_qualified_certificate,
};
use card_transport::{AndroidCardTransport, CardExchangeLevel};
use contactless::{
    ContactlessChannel, ContactlessOpenOutcome, contactless_authenticate_and_sign,
    contactless_close, contactless_connect, contactless_probe_pin2, contactless_qualified_sign,
    contactless_read_qualified_certificate, contactless_verify_pin1_on_session,
    sign_selection_failure,
};
use jni::objects::{JByteArray, JClass, JObject};
use jni::sys::{jboolean, jint};
use jni::{Env, NativeMethod};
use jni_card_exchange::JniBlockExchange;
use organization_card::ContactlessCardKind;
use pin_status::{PinPreflight, PinPreflightFailure, PinState, probe_pin_preflight};
use qualified_signer::{
    MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH, QualifiedSignFailure, QualifiedSignature,
    QualifiedSigningAlgorithm, QualifiedSigningInput, qualified_sign,
};
use refineid_apdu::TransportOutcome;
use refineid_atr::{Atr, Convention};
use refineid_auth::{PinReferenceScheme, PinSlot};
use refineid_pkcs15::{Pkcs15Error, Pkcs15Ops};

const ATR_INVALID: jint = 0;
const ATR_VALID_T0_DIRECT: jint = 1;
const ATR_VALID_T0_INVERSE: jint = 2;
const ATR_VALID_NON_T0_DIRECT: jint = 3;
const ATR_VALID_NON_T0_INVERSE: jint = 4;

const EXCHANGE_LEVEL_APDU: jint = 0;
const EXCHANGE_LEVEL_T0_TPDU: jint = 1;

const _: () = {
    assert!(card_management::CHANNEL_MODE_WIRED_APDU == EXCHANGE_LEVEL_APDU);
    assert!(card_management::CHANNEL_MODE_WIRED_T0_TPDU == EXCHANGE_LEVEL_T0_TPDU);
};

const CARD_OPERATION_BRIDGE_ERROR: jint = 0;
const CARD_OPERATION_SUCCEEDED: jint = 1;
const CARD_OPERATION_CARD_UNAVAILABLE: jint = 2;
const CARD_OPERATION_REJECTED: jint = 3;
const CARD_OPERATION_TRANSPORT_ERROR: jint = 4;

/// The held contactless session was dropped. Closing is best-effort and
/// touches no card, so the only outcome is success.
const CONTACTLESS_SESSION_CLOSED: jint = 0;

const CERTIFICATE_BRIDGE_ERROR: u8 = 0;
const CERTIFICATE_SUCCEEDED: u8 = 1;
const CERTIFICATE_CARD_UNAVAILABLE: u8 = 2;
const CERTIFICATE_REJECTED: u8 = 3;
const CERTIFICATE_TRANSPORT_ERROR: u8 = 4;
const CERTIFICATE_INVALID: u8 = 5;
const CERTIFICATE_PACE_REJECTED: u8 = 6;
const CERTIFICATE_ACTIVATION_REQUIRED: u8 = 7;
const CERTIFICATE_ORGANIZATION_CARD: u8 = 8;

const CARD_ACCESS_BRIDGE_ERROR: u8 = 0;
const CARD_ACCESS_SUCCEEDED: u8 = 1;
const CARD_ACCESS_CARD_UNAVAILABLE: u8 = 2;
const CARD_ACCESS_REJECTED: u8 = 3;
const CARD_ACCESS_TRANSPORT_ERROR: u8 = 4;
const CARD_ACCESS_INVALID: u8 = 5;

const CARD_KIND_UNKNOWN: u8 = 0;
const CARD_KIND_PERSONAL: u8 = 1;
const CARD_KIND_ORGANIZATION: u8 = 2;

const PIN_PREFLIGHT_BRIDGE_ERROR: u8 = 0;
const PIN_PREFLIGHT_SUCCEEDED: u8 = 1;
const PIN_PREFLIGHT_CARD_UNAVAILABLE: u8 = 2;
const PIN_PREFLIGHT_TRANSPORT_ERROR: u8 = 3;

const AUTHENTICATION_SIGNATURE_BRIDGE_ERROR: u8 = 0;
const AUTHENTICATION_SIGNATURE_SUCCEEDED: u8 = 1;
const AUTHENTICATION_SIGNATURE_CARD_UNAVAILABLE: u8 = 2;
const AUTHENTICATION_SIGNATURE_TRANSPORT_ERROR: u8 = 3;
const AUTHENTICATION_SIGNATURE_INVALID_PIN: u8 = 4;
const AUTHENTICATION_SIGNATURE_SAFETY_REFUSED: u8 = 5;
const AUTHENTICATION_SIGNATURE_PIN_LOCKED: u8 = 6;
const AUTHENTICATION_SIGNATURE_WRONG_PIN: u8 = 7;
const AUTHENTICATION_SIGNATURE_VERIFICATION_REJECTED: u8 = 8;
const AUTHENTICATION_SIGNATURE_SIGNING_REJECTED: u8 = 9;
const AUTHENTICATION_SIGNATURE_PACE_REJECTED: u8 = 10;

const AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256: u8 = 0;
const AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256: u8 = 1;
const AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256: u8 = 2;
const AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384: u8 = 3;
const AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA256: u8 = 4;
const AUTHENTICATION_PREHASHED_RSA_PSS_SHA256: u8 = 5;
const AUTHENTICATION_PREHASHED_ECDSA_P384_SHA256: u8 = 6;
const AUTHENTICATION_PREHASHED_ECDSA_P384_SHA384: u8 = 7;
const AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384: u8 = 8;
const AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384: u8 = 9;
const AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512: u8 = 10;
const AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512: u8 = 11;
const AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA384: u8 = 12;
const AUTHENTICATION_PREHASHED_RSA_PSS_SHA384: u8 = 13;
const AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA512: u8 = 14;
const AUTHENTICATION_PREHASHED_RSA_PSS_SHA512: u8 = 15;

const QUALIFIED_SIGNATURE_BRIDGE_ERROR: u8 = 0;
const QUALIFIED_SIGNATURE_SUCCEEDED: u8 = 1;
const QUALIFIED_SIGNATURE_CARD_UNAVAILABLE: u8 = 2;
const QUALIFIED_SIGNATURE_TRANSPORT_ERROR: u8 = 3;
const QUALIFIED_SIGNATURE_INVALID_PIN: u8 = 4;
const QUALIFIED_SIGNATURE_SAFETY_REFUSED: u8 = 5;
const QUALIFIED_SIGNATURE_PIN_LOCKED: u8 = 6;
const QUALIFIED_SIGNATURE_WRONG_PIN: u8 = 7;
const QUALIFIED_SIGNATURE_VERIFICATION_REJECTED: u8 = 8;
const QUALIFIED_SIGNATURE_CERTIFICATE_REJECTED: u8 = 9;
const QUALIFIED_SIGNATURE_INVALID_CERTIFICATE: u8 = 10;
const QUALIFIED_SIGNATURE_CERTIFICATE_MISMATCH: u8 = 11;
const QUALIFIED_SIGNATURE_KEY_PROFILE_MISMATCH: u8 = 12;
const QUALIFIED_SIGNATURE_SIGNING_REJECTED: u8 = 13;

const QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384: u8 = 0;
const QUALIFIED_ALGORITHM_ECDSA_P384_SHA384: u8 = 1;
const QUALIFIED_PREHASHED_RSA_PKCS1_SHA384: u8 = 2;
const QUALIFIED_PREHASHED_ECDSA_P384_SHA384: u8 = 3;
const SHA384_DIGEST_LENGTH: usize = 48;

const PIN_REFERENCE_CITIZEN: u8 = 0;
const PIN_REFERENCE_ORGANIZATIONAL: u8 = 1;

const PIN_STATE_VERIFIED: u8 = 0;
const PIN_STATE_REMAINING: u8 = 1;
const PIN_STATE_LOCKED: u8 = 2;
const PIN_STATE_NO_INFORMATION: u8 = 3;
const PIN_STATE_UNRECOGNISED: u8 = 4;

const POLICY_REFUSED: u8 = 0;
const POLICY_PERMITTED: u8 = 1;
const NO_RETRY_COUNT: u8 = u8::MAX;

const KEY_PROFILE_RSA_2048: u8 = 0;
const KEY_PROFILE_RSA_3072: u8 = 1;
const KEY_PROFILE_ECDSA_P256: u8 = 2;
const KEY_PROFILE_ECDSA_P384: u8 = 3;

const CERTIFICATE_REPLY_HEADER_LENGTH: usize = 2;
const CARD_ACCESS_REPLY_LENGTH: usize = 3;
const CONTACTLESS_OPEN_HEADER_LENGTH: usize = 2;
const PIN_PREFLIGHT_REPLY_LENGTH: usize = 5;
const PIN_PREFLIGHT_REPLY_LENGTH_BYTE: u8 = PIN_PREFLIGHT_REPLY_LENGTH as u8;
const AUTHENTICATION_SIGNATURE_REPLY_HEADER_LENGTH: usize = 2;
const QUALIFIED_SIGNATURE_REPLY_HEADER_LENGTH: usize = 2;
const MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH: usize = 1_024 * 1_024;
const MAXIMUM_EXPECTED_CERTIFICATE_LENGTH: usize = 16 * 1_024;
const JAVA_ARRAY_CLEAR_CHUNK_LENGTH: usize = 64;

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn validate_atr_native(atr: [jbyte]) -> jint,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeQualifiedCore",
    static extern fn read_qualified_certificate_native(
        exchange_level: jint,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativePin1Verification",
    static extern fn verify_pin1_native(
        exchange_level: jint,
        held_session: jboolean,
        pin: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn authenticate_and_sign_native(
        exchange_level: jint,
        request: jint,
        pin: [jbyte],
        message: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeQualifiedCore",
    static extern fn qualified_sign_native(
        exchange_level: jint,
        algorithm: jint,
        pin: [jbyte],
        content: [jbyte],
        expected_certificate: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn probe_pin1_status_native(
        exchange_level: jint,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeQualifiedCore",
    static extern fn probe_pin2_status_native(
        exchange_level: jint,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn read_authentication_certificate_native(
        exchange_level: jint,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCore",
    static extern fn select_pkcs15_application_native(
        exchange_level: jint,
        callback: JObject,
    ) -> jint,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCardCa",
    static extern fn read_card_root_ca_certificate_native() -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCardCa",
    static extern fn read_card_intermediate_ca_certificate_native() -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCardCa",
    static extern fn last_ca_read_answer_native(slot: jint) -> jint,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCardCa",
    static extern fn set_cached_ca_certificates_native(
        root_ca: [jbyte],
        intermediate_ca: [jbyte],
    ) -> jint,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn probe_card_access_native(
        exchange_level: jint,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn contactless_authenticate_and_sign_native(
        can: [jbyte],
        request: jint,
        pin: [jbyte],
        message: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn contactless_read_qualified_certificate_native(
        can: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn contactless_probe_pin2_native(
        can: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessCore",
    static extern fn contactless_qualified_sign_native(
        can: [jbyte],
        algorithm: jint,
        pin: [jbyte],
        content: [jbyte],
        expected_certificate: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessSession",
    static extern fn contactless_connect_native(
        can: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessSession",
    static extern fn contactless_authenticate_and_sign_on_session_native(
        request: jint,
        pin: [jbyte],
        message: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessSession",
    static extern fn contactless_read_qualified_certificate_on_session_native(
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessSession",
    static extern fn contactless_probe_pin2_on_session_native(
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessSession",
    static extern fn contactless_qualified_sign_on_session_native(
        algorithm: jint,
        pin: [jbyte],
        content: [jbyte],
        expected_certificate: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeContactlessSession",
    static extern fn contactless_close_native() -> jint,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCardManagement",
    static extern fn probe_credential_health_native(
        channel_mode: jint,
        can: [jbyte],
        read_pin_lengths: jboolean,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCardManagement",
    static extern fn manage_pin_native(
        channel_mode: jint,
        op: jint,
        can: [jbyte],
        first_secret: [jbyte],
        second_secret: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeCardManagement",
    static extern fn activate_card_native(
        channel_mode: jint,
        scheme: jint,
        can: [jbyte],
        code: [jbyte],
        new_pin1: [jbyte],
        new_pin2: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

fn validate_atr_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    atr: JByteArray<'local>,
) -> Result<jint, jni::errors::Error> {
    let mut bytes = env.convert_byte_array(&atr)?;
    let status = validate_atr_bytes(&bytes);
    bytes.fill(0);
    Ok(status)
}

fn validate_atr_bytes(bytes: &[u8]) -> jint {
    match Atr::new(bytes) {
        Ok(atr) => match (atr.supports_non_t0_protocol(), atr.convention()) {
            (false, Convention::Direct) => ATR_VALID_T0_DIRECT,
            (false, Convention::Inverse) => ATR_VALID_T0_INVERSE,
            (true, Convention::Direct) => ATR_VALID_NON_T0_DIRECT,
            (true, Convention::Inverse) => ATR_VALID_NON_T0_INVERSE,
        },
        Err(_) => ATR_INVALID,
    }
}

fn select_pkcs15_application_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<jint, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        return Ok(CARD_OPERATION_BRIDGE_ERROR);
    };

    let exchange = JniBlockExchange::new(env, callback);
    let mut transport = AndroidCardTransport::new(exchange, level);
    let result = transport.select_pkcs15_application();
    let exchange = transport.into_exchange();
    if exchange.bridge_failed() {
        return Ok(CARD_OPERATION_BRIDGE_ERROR);
    }

    Ok(map_pkcs15_selection_result(result))
}

fn read_authentication_certificate_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        return env.byte_array_from_slice(&[CERTIFICATE_BRIDGE_ERROR]);
    };

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let result = read_authentication_certificate(&mut transport);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CERTIFICATE_BRIDGE_ERROR]
    } else {
        encode_certificate_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn read_qualified_certificate_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        return env.byte_array_from_slice(&[CERTIFICATE_BRIDGE_ERROR]);
    };

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let result = read_qualified_certificate(&mut transport);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CERTIFICATE_BRIDGE_ERROR]
    } else {
        encode_certificate_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn probe_card_access_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        return env.byte_array_from_slice(&[CARD_ACCESS_BRIDGE_ERROR]);
    };

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let result = probe_card_access(&mut transport);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CARD_ACCESS_BRIDGE_ERROR]
    } else {
        encode_card_access_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

/// The persistent-session opener: runs `contactless_connect`, which retains
/// the live secure-messaging session on full success so the operation that
/// follows can skip PACE.
fn contactless_connect_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let can_bytes = take_secret_bytes(env, &can)?;

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
        let (result, exchange) = contactless_connect(transport, can_bytes);
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CERTIFICATE_BRIDGE_ERROR]
    } else {
        encode_contactless_open_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

/// The authentication signature on the session a prior `contactless_connect`
/// left open. It carries no CAN: the channel is rebuilt from the held
/// session and PACE is skipped. Otherwise it mirrors
/// `contactless_authenticate_and_sign_native` byte for byte.
fn contactless_authenticate_and_sign_on_session_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    request: jint,
    pin: JByteArray<'local>,
    message: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    contactless_authentication_sign_reply(
        env,
        ContactlessChannel::HeldSession,
        request,
        &pin,
        &message,
        callback,
    )
}

/// Drop the held contactless session and its keys. No card interaction: the
/// card's half dies with the field, so closing is a local clear that always
/// reports success.
fn contactless_close_native<'local>(
    _env: &mut Env<'local>,
    _class: JClass<'local>,
) -> Result<jint, jni::errors::Error> {
    contactless_close();
    Ok(CONTACTLESS_SESSION_CLOSED)
}

fn read_card_root_ca_certificate_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let cert = contactless::get_last_read_root_ca();
    match cert {
        Some(cert) => env.byte_array_from_slice(cert.der().as_bytes()),
        None => env.new_byte_array(0),
    }
}

fn read_card_intermediate_ca_certificate_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let cert = contactless::get_last_read_intermediate_ca();
    match cert {
        Some(cert) => env.byte_array_from_slice(cert.der().as_bytes()),
        None => env.new_byte_array(0),
    }
}

/// The answer to the last unconditional read of one on-card CA certificate
/// (`slot` 0 for EF.4334, 1 for EF.4336): `step * CA_READ_STEP_FACTOR +
/// status word`, with no status word as 0 and an unknown slot or an
/// unasked read as `CA_READ_NOT_ASKED`.
fn last_ca_read_answer_native<'local>(
    _env: &mut Env<'local>,
    _class: JClass<'local>,
    slot: jint,
) -> Result<jint, jni::errors::Error> {
    let answers = contactless::last_ca_read_answers();
    let answer = usize::try_from(slot)
        .ok()
        .and_then(|index| answers.get(index).copied())
        .unwrap_or(contactless::CaReadAnswer::NotAsked);
    Ok(encode_ca_read_answer(answer))
}

const CA_READ_NOT_ASKED: jint = 0;
const CA_READ_STEP_FACTOR: jint = 0x1_0000;
const CA_READ_NO_STATUS: jint = 0;
const CA_READ_STEP_SELECT_MF: jint = 1;
const CA_READ_STEP_SELECT_FILE: jint = 2;
const CA_READ_STEP_READ_BINARY: jint = 3;
const CA_READ_STEP_CERTIFICATE: jint = 4;
const CA_READ_STEP_READ: jint = 5;
/// SW1-SW2 `90 00`, the answer of a read that completed.
const CA_READ_SUCCESS_STATUS: jint = 0x9000;

fn encode_ca_read_answer(answer: contactless::CaReadAnswer) -> jint {
    use contactless::{CaReadAnswer, CaReadStep};
    let step_code = |step: CaReadStep| match step {
        CaReadStep::SelectMf => CA_READ_STEP_SELECT_MF,
        CaReadStep::SelectFile => CA_READ_STEP_SELECT_FILE,
        CaReadStep::ReadBinary => CA_READ_STEP_READ_BINARY,
        CaReadStep::Certificate => CA_READ_STEP_CERTIFICATE,
    };
    match answer {
        CaReadAnswer::NotAsked => CA_READ_NOT_ASKED,
        CaReadAnswer::Read => CA_READ_STEP_READ * CA_READ_STEP_FACTOR + CA_READ_SUCCESS_STATUS,
        CaReadAnswer::Refused { step, status } => {
            step_code(step) * CA_READ_STEP_FACTOR + jint::from(status)
        }
        CaReadAnswer::Failed { step } => step_code(step) * CA_READ_STEP_FACTOR + CA_READ_NO_STATUS,
    }
}

fn set_cached_ca_certificates_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    root_ca: JByteArray<'local>,
    intermediate_ca: JByteArray<'local>,
) -> Result<jint, jni::errors::Error> {
    let root = env.convert_byte_array(&root_ca)?;
    if !root.is_empty()
        && let Ok(der) = CertificateDer::try_from_bytes(root)
        && let Ok(cert) = RootCaCertificate::from_der(der)
    {
        contactless::set_last_read_root_ca(Some(cert));
    } else {
        contactless::set_last_read_root_ca(None);
    }
    let intermediate = env.convert_byte_array(&intermediate_ca)?;
    if !intermediate.is_empty()
        && let Ok(der) = CertificateDer::try_from_bytes(intermediate)
        && let Ok(cert) = IntermediateCaCertificate::from_der(der)
    {
        contactless::set_last_read_intermediate_ca(Some(cert));
    } else {
        contactless::set_last_read_intermediate_ca(None);
    }
    Ok(CARD_OPERATION_SUCCEEDED)
}

fn contactless_authenticate_and_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    request: jint,
    pin: JByteArray<'local>,
    message: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let can_bytes = match take_secret_bytes(env, &can) {
        Ok(bytes) => bytes,
        Err(error) => {
            best_effort_clear_java_arrays(env, &[&pin]);
            return Err(error);
        }
    };
    contactless_authentication_sign_reply(
        env,
        ContactlessChannel::Pace(can_bytes),
        request,
        &pin,
        &message,
        callback,
    )
}

fn contactless_authentication_sign_reply<'local>(
    env: &mut Env<'local>,
    channel: ContactlessChannel,
    request: jint,
    pin: &JByteArray<'local>,
    message: &JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    jni_authentication_sign_reply(
        env,
        request,
        pin,
        message,
        callback,
        |exchange, algorithm, pin_bytes, input| {
            let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
            contactless_authenticate_and_sign(transport, channel, algorithm, pin_bytes, input)
        },
    )
}

fn contactless_read_qualified_certificate_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let channel = ContactlessChannel::Pace(take_secret_bytes(env, &can)?);
    contactless_qualified_certificate_reply(env, channel, callback)
}

fn contactless_read_qualified_certificate_on_session_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    contactless_qualified_certificate_reply(env, ContactlessChannel::HeldSession, callback)
}

fn contactless_qualified_certificate_reply<'local>(
    env: &mut Env<'local>,
    channel: ContactlessChannel,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
        let (result, exchange) = contactless_read_qualified_certificate(transport, channel);
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![CERTIFICATE_BRIDGE_ERROR]
    } else {
        encode_certificate_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn contactless_probe_pin2_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let channel = ContactlessChannel::Pace(take_secret_bytes(env, &can)?);
    contactless_pin2_reply(env, channel, callback)
}

fn contactless_probe_pin2_on_session_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    contactless_pin2_reply(env, ContactlessChannel::HeldSession, callback)
}

fn contactless_pin2_reply<'local>(
    env: &mut Env<'local>,
    channel: ContactlessChannel,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
        let (result, exchange) = contactless_probe_pin2(transport, channel);
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![PIN_PREFLIGHT_BRIDGE_ERROR]
    } else {
        encode_pin_preflight_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

/// The Java arrays and request code of one qualified signature.
pub(crate) struct QualifiedSignRequest<'a, 'local> {
    pub(crate) algorithm: jint,
    pub(crate) pin: &'a JByteArray<'local>,
    pub(crate) content: &'a JByteArray<'local>,
    pub(crate) expected_certificate: &'a JByteArray<'local>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the static JNI ABI carries the CAN and five explicit request fields plus its environment, class, and callback"
)]
fn contactless_qualified_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    can: JByteArray<'local>,
    algorithm: jint,
    pin: JByteArray<'local>,
    content: JByteArray<'local>,
    expected_certificate: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let can_bytes = match take_secret_bytes(env, &can) {
        Ok(bytes) => bytes,
        Err(error) => {
            best_effort_clear_java_arrays(env, &[&pin]);
            return Err(error);
        }
    };
    let request = QualifiedSignRequest {
        algorithm,
        pin: &pin,
        content: &content,
        expected_certificate: &expected_certificate,
    };
    contactless_qualified_sign_reply(env, ContactlessChannel::Pace(can_bytes), request, callback)
}

fn contactless_qualified_sign_on_session_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    algorithm: jint,
    pin: JByteArray<'local>,
    content: JByteArray<'local>,
    expected_certificate: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let request = QualifiedSignRequest {
        algorithm,
        pin: &pin,
        content: &content,
        expected_certificate: &expected_certificate,
    };
    contactless_qualified_sign_reply(env, ContactlessChannel::HeldSession, request, callback)
}

/// Validate one qualified-signature request and sign inside `channel`.
/// The channel's CAN and the PIN are wiped on every path that stops before
/// the reviewed signer consumes them.
fn contactless_qualified_sign_reply<'local>(
    env: &mut Env<'local>,
    channel: ContactlessChannel,
    request: QualifiedSignRequest<'_, 'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    jni_qualified_sign_reply(
        env,
        request,
        callback,
        |exchange, algorithm, pin_bytes, input, expected| {
            let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
            contactless_qualified_sign(transport, channel, algorithm, pin_bytes, input, expected)
        },
    )
}

fn probe_pin1_status_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    probe_pin_status_reply(env, exchange_level, callback, PinSlot::Pin1)
}

fn probe_pin2_status_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    probe_pin_status_reply(env, exchange_level, callback, PinSlot::Pin2)
}

fn probe_pin_status_reply<'local>(
    env: &mut Env<'local>,
    exchange_level: jint,
    callback: JObject<'local>,
    slot: PinSlot,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        return env.byte_array_from_slice(&[PIN_PREFLIGHT_BRIDGE_ERROR]);
    };

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let result = probe_pin_preflight(&mut transport, slot);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };

    let mut reply = if bridge_failed {
        vec![PIN_PREFLIGHT_BRIDGE_ERROR]
    } else {
        encode_pin_preflight_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

/// Secret bytes owned at the JNI border and wiped when dropped without being
/// handed into a domain operation.
struct OwnedSecret(Vec<u8>);

impl OwnedSecret {
    fn into_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

impl Drop for OwnedSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Which card channel a management JNI entry point runs over.
enum ManagementChannel {
    Wired(CardExchangeLevel),
    Contactless(ContactlessChannel),
}

/// Decode `channel_mode` together with its optional `can` array. Modes that do
/// not run PACE require `can` to be absent; `CHANNEL_MODE_CONTACTLESS_PACE`
/// requires `can` to be present. Any rejected combination drops `can`, wiping
/// its bytes.
fn management_channel_from_wire(
    channel_mode: jint,
    can: Option<OwnedSecret>,
) -> Option<ManagementChannel> {
    match (channel_mode, can) {
        (card_management::CHANNEL_MODE_WIRED_APDU, None) => {
            Some(ManagementChannel::Wired(CardExchangeLevel::Apdu))
        }
        (card_management::CHANNEL_MODE_WIRED_T0_TPDU, None) => {
            Some(ManagementChannel::Wired(CardExchangeLevel::T0Tpdu))
        }
        (card_management::CHANNEL_MODE_CONTACTLESS_PACE, Some(can)) => Some(
            ManagementChannel::Contactless(ContactlessChannel::Pace(can.into_vec())),
        ),
        (card_management::CHANNEL_MODE_CONTACTLESS_HELD_SESSION, None) => Some(
            ManagementChannel::Contactless(ContactlessChannel::HeldSession),
        ),
        _ => None,
    }
}

fn management_reply<'local>(
    env: &mut Env<'local>,
    bridge_failed: bool,
    encoded: Vec<u8>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let mut reply = if bridge_failed {
        vec![card_management::MANAGEMENT_TAG_BRIDGE_ERROR]
    } else {
        encoded
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

fn probe_credential_health_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    channel_mode: jint,
    can: JByteArray<'local>,
    read_pin_lengths: jboolean,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let can = take_nullable_secret_bytes(env, &can)?;
    if callback.is_null() {
        return one_byte_reply(env, card_management::MANAGEMENT_TAG_BRIDGE_ERROR);
    }
    let Some(channel) = management_channel_from_wire(channel_mode, can) else {
        return one_byte_reply(env, card_management::MANAGEMENT_TAG_BRIDGE_ERROR);
    };
    let lengths_read = card_management::PinLengthsRead::from_flag(read_pin_lengths);

    let (result, bridge_failed) = match channel {
        ManagementChannel::Wired(level) => {
            let exchange = JniBlockExchange::new(env, callback);
            let mut transport = AndroidCardTransport::new(exchange, level);
            let result = card_management::probe_credential_health(&mut transport, lengths_read);
            let exchange = transport.into_exchange();
            (result, exchange.bridge_failed())
        }
        ManagementChannel::Contactless(contactless_channel) => {
            let exchange = JniBlockExchange::new(env, callback);
            let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
            let (result, exchange) = contactless::contactless_probe_credential_health(
                transport,
                contactless_channel,
                lengths_read,
            );
            (result, exchange.bridge_failed())
        }
    };

    management_reply(
        env,
        bridge_failed,
        card_management::encode_credential_health_reply(result),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the static JNI ABI carries channel mode, operation, optional CAN, two secrets, and callback"
)]
fn manage_pin_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    channel_mode: jint,
    op: jint,
    can: JByteArray<'local>,
    first_secret: JByteArray<'local>,
    second_secret: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let can = match take_nullable_secret_bytes(env, &can) {
        Ok(bytes) => bytes,
        Err(error) => {
            best_effort_clear_java_arrays(env, &[&first_secret, &second_secret]);
            return Err(error);
        }
    };
    let first_secret = match take_nullable_secret_bytes(env, &first_secret) {
        Ok(bytes) => bytes,
        Err(error) => {
            best_effort_clear_java_arrays(env, &[&second_secret]);
            return Err(error);
        }
    };
    let second_secret = take_nullable_secret_bytes(env, &second_secret)?;

    let (Some(first_secret), Some(second_secret)) = (first_secret, second_secret) else {
        return one_byte_reply(env, card_management::MANAGEMENT_TAG_BRIDGE_ERROR);
    };
    if callback.is_null() {
        return one_byte_reply(env, card_management::MANAGEMENT_TAG_BRIDGE_ERROR);
    }
    let Some(op) = card_management::PinManageOp::from_wire(op) else {
        return one_byte_reply(env, card_management::MANAGEMENT_TAG_BRIDGE_ERROR);
    };
    let Some(channel) = management_channel_from_wire(channel_mode, can) else {
        return one_byte_reply(env, card_management::MANAGEMENT_TAG_BRIDGE_ERROR);
    };

    let (result, bridge_failed) = match channel {
        ManagementChannel::Wired(level) => {
            let exchange = JniBlockExchange::new(env, callback);
            let mut transport = AndroidCardTransport::new(exchange, level);
            let result = card_management::manage_pin(
                &mut transport,
                op,
                first_secret.into_vec(),
                second_secret.into_vec(),
            );
            let exchange = transport.into_exchange();
            (result, exchange.bridge_failed())
        }
        ManagementChannel::Contactless(contactless_channel) => {
            let exchange = JniBlockExchange::new(env, callback);
            let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
            let (result, exchange) = contactless::contactless_manage_pin(
                transport,
                contactless_channel,
                op,
                first_secret.into_vec(),
                second_secret.into_vec(),
            );
            (result, exchange.bridge_failed())
        }
    };

    management_reply(
        env,
        bridge_failed,
        card_management::encode_manage_outcome_reply(result),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the static JNI ABI carries channel mode, scheme, optional CAN, code, two optional PINs, and callback"
)]
fn activate_card_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    channel_mode: jint,
    scheme: jint,
    can: JByteArray<'local>,
    code: JByteArray<'local>,
    new_pin1: JByteArray<'local>,
    new_pin2: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let can = match take_nullable_secret_bytes(env, &can) {
        Ok(bytes) => bytes,
        Err(error) => {
            best_effort_clear_java_arrays(env, &[&code, &new_pin1, &new_pin2]);
            return Err(error);
        }
    };
    let code = match take_nullable_secret_bytes(env, &code) {
        Ok(bytes) => bytes,
        Err(error) => {
            best_effort_clear_java_arrays(env, &[&new_pin1, &new_pin2]);
            return Err(error);
        }
    };
    let new_pin1 = match take_optional_secret_bytes(env, &new_pin1) {
        Ok(bytes) => bytes,
        Err(error) => {
            best_effort_clear_java_arrays(env, &[&new_pin2]);
            return Err(error);
        }
    };
    let new_pin2 = take_optional_secret_bytes(env, &new_pin2)?;

    let Some(code) = code else {
        return one_byte_reply(env, card_management::MANAGEMENT_TAG_BRIDGE_ERROR);
    };
    if callback.is_null() {
        return one_byte_reply(env, card_management::MANAGEMENT_TAG_BRIDGE_ERROR);
    }
    let Some(scheme_byte) = card_management::validate_activation_scheme_wire(scheme) else {
        return one_byte_reply(env, card_management::MANAGEMENT_TAG_BRIDGE_ERROR);
    };
    let Some(channel) = management_channel_from_wire(channel_mode, can) else {
        return one_byte_reply(env, card_management::MANAGEMENT_TAG_BRIDGE_ERROR);
    };

    let new_pin1_bytes = new_pin1.map(OwnedSecret::into_vec);
    let new_pin2_bytes = new_pin2.map(OwnedSecret::into_vec);

    let (result, bridge_failed) = match channel {
        ManagementChannel::Wired(level) => {
            let exchange = JniBlockExchange::new(env, callback);
            let mut transport = AndroidCardTransport::new(exchange, level);
            let result = card_management::activate_card(
                &mut transport,
                scheme_byte,
                code.into_vec(),
                new_pin1_bytes,
                new_pin2_bytes,
            );
            let exchange = transport.into_exchange();
            (result, exchange.bridge_failed())
        }
        ManagementChannel::Contactless(contactless_channel) => {
            let exchange = JniBlockExchange::new(env, callback);
            let transport = AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu);
            let (result, exchange) = contactless::contactless_activate_card(
                transport,
                contactless_channel,
                scheme_byte,
                code.into_vec(),
                new_pin1_bytes,
                new_pin2_bytes,
            );
            (result, exchange.bridge_failed())
        }
    };

    management_reply(
        env,
        bridge_failed,
        card_management::encode_activation_reply(result),
    )
}

/// Take two secret arrays, wiping the first when the second fails.
fn take_secret_pair(
    env: &mut Env<'_>,
    first: &JByteArray<'_>,
    second: &JByteArray<'_>,
) -> Result<(Vec<u8>, Vec<u8>), jni::errors::Error> {
    let mut first_bytes = take_secret_bytes(env, first)?;
    match take_secret_bytes(env, second) {
        Ok(second_bytes) => Ok((first_bytes, second_bytes)),
        Err(error) => {
            first_bytes.fill(0);
            Err(error)
        }
    }
}

/// Copy a nullable secret array, clearing the Java copy immediately; a null
/// reference means no array was supplied.
fn take_nullable_secret_bytes(
    env: &mut Env<'_>,
    array: &JByteArray<'_>,
) -> Result<Option<OwnedSecret>, jni::errors::Error> {
    if array.is_null() {
        Ok(None)
    } else {
        take_secret_bytes(env, array).map(|bytes| Some(OwnedSecret(bytes)))
    }
}

/// Copy an optional new-PIN array, clearing the Java copy immediately; a null
/// or empty array means that PIN is omitted.
fn take_optional_secret_bytes(
    env: &mut Env<'_>,
    array: &JByteArray<'_>,
) -> Result<Option<OwnedSecret>, jni::errors::Error> {
    if array.is_null() {
        return Ok(None);
    }
    let bytes = take_secret_bytes(env, array)?;
    if bytes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(OwnedSecret(bytes)))
    }
}

fn best_effort_clear_java_arrays(env: &Env<'_>, arrays: &[&JByteArray<'_>]) {
    for array in arrays {
        if !array.is_null() {
            let _ = clear_java_byte_array(env, array);
        }
    }
}

fn verify_pin1_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    held_session: jboolean,
    pin: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let mut pin_bytes = take_secret_bytes(env, &pin)?;
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        pin_bytes.fill(0);
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    };
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = AndroidCardTransport::new(exchange, level);
        let (result, exchange) = if held_session {
            contactless_verify_pin1_on_session(transport, pin_bytes)
        } else {
            let result = match transport.select_pkcs15_application() {
                Ok(()) => verify_authentication_pin(&mut transport, pin_bytes),
                Err(error) => {
                    pin_bytes.fill(0);
                    Err(sign_selection_failure(error))
                }
            };
            (result, transport.into_exchange())
        };
        (result, exchange.bridge_failed())
    };
    let reply = if bridge_failed {
        vec![AUTHENTICATION_SIGNATURE_BRIDGE_ERROR]
    } else {
        match result {
            Ok(()) => vec![AUTHENTICATION_SIGNATURE_SUCCEEDED],
            Err(error) => encode_authentication_signature_reply(Err(error)),
        }
    };
    env.byte_array_from_slice(&reply)
}

fn authenticate_and_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    request: jint,
    pin: JByteArray<'local>,
    message: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        let _pin = OwnedSecret(take_secret_bytes(env, &pin)?);
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    };
    jni_authentication_sign_reply(
        env,
        request,
        &pin,
        &message,
        callback,
        |exchange, algorithm, pin_bytes, input| {
            let mut transport = AndroidCardTransport::new(exchange, level);
            let result = authenticate_and_sign(&mut transport, algorithm, pin_bytes, input);
            (result, transport.into_exchange())
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the static JNI ABI carries five explicit request fields plus its environment, class, and callback"
)]
fn qualified_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    exchange_level: jint,
    algorithm: jint,
    pin: JByteArray<'local>,
    content: JByteArray<'local>,
    expected_certificate: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let Some(level) = exchange_level_from_jint(exchange_level) else {
        let _pin = OwnedSecret(take_secret_bytes(env, &pin)?);
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    };
    let request = QualifiedSignRequest {
        algorithm,
        pin: &pin,
        content: &content,
        expected_certificate: &expected_certificate,
    };
    jni_qualified_sign_reply(
        env,
        request,
        callback,
        |exchange, algorithm, pin_bytes, input, expected| {
            let mut transport = AndroidCardTransport::new(exchange, level);
            let result = qualified_sign(&mut transport, algorithm, pin_bytes, input, expected);
            (result, transport.into_exchange())
        },
    )
}

/// Validate one authentication-signature JNI request, clear the Java PIN copy
/// immediately, bound the input length before copying, run `sign` over the JNI
/// exchange, and encode the bounded reply. Any secondary secret owned by `sign`
/// (such as a `ContactlessChannel::Pace` CAN) drops and wipes automatically on
/// early exit or JNI error.
pub(crate) fn jni_authentication_sign_reply<'local>(
    env: &mut Env<'local>,
    request: jint,
    pin: &JByteArray<'local>,
    message: &JByteArray<'local>,
    callback: JObject<'local>,
    sign: impl for<'env, 'input> FnOnce(
        JniBlockExchange<'env, 'local>,
        AuthenticationSigningAlgorithm,
        Vec<u8>,
        AuthenticationSigningInput<'input>,
    ) -> (
        Result<AuthenticationSignature, AuthenticationSignFailure>,
        JniBlockExchange<'env, 'local>,
    ),
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let pin = OwnedSecret(take_secret_bytes(env, pin)?);
    if callback.is_null() || message.is_null() {
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    }
    let Some((algorithm, input_mode)) = authentication_request_from_jint(request) else {
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    };
    let message_length = message.len(env)?;
    if message_length > MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH {
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    }
    let message_bytes = OwnedSecret(env.convert_byte_array(message)?);

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let input = match input_mode {
            AuthenticationSigningInputMode::Message => {
                AuthenticationSigningInput::Message(&message_bytes.0)
            }
            AuthenticationSigningInputMode::Prehashed => {
                AuthenticationSigningInput::Prehashed(&message_bytes.0)
            }
        };
        let (result, exchange) = sign(exchange, algorithm, pin.into_vec(), input);
        (result, exchange.bridge_failed())
    };
    drop(message_bytes);

    let mut reply = if bridge_failed {
        vec![AUTHENTICATION_SIGNATURE_BRIDGE_ERROR]
    } else {
        encode_authentication_signature_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

/// Validate one qualified-signature JNI request, clear the Java PIN copy
/// immediately, bound the content and certificate lengths before copying, run
/// `sign` over the JNI exchange, and encode the bounded reply. Any secondary
/// secret owned by `sign` drops and wipes automatically on early exit or error.
pub(crate) fn jni_qualified_sign_reply<'local>(
    env: &mut Env<'local>,
    request: QualifiedSignRequest<'_, 'local>,
    callback: JObject<'local>,
    sign: impl for<'env, 'input> FnOnce(
        JniBlockExchange<'env, 'local>,
        QualifiedSigningAlgorithm,
        Vec<u8>,
        QualifiedSigningInput<'input>,
        &'input [u8],
    ) -> (
        Result<QualifiedSignature, QualifiedSignFailure>,
        JniBlockExchange<'env, 'local>,
    ),
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let pin = OwnedSecret(take_secret_bytes(env, request.pin)?);
    if callback.is_null() || request.content.is_null() || request.expected_certificate.is_null() {
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    }
    let Some((algorithm, input_mode)) = qualified_request_from_jint(request.algorithm) else {
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    };
    let content_length = request.content.len(env)?;
    let content_length_accepted = match input_mode {
        QualifiedSigningInputMode::Message => {
            content_length <= MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH
        }
        QualifiedSigningInputMode::Prehashed => content_length == SHA384_DIGEST_LENGTH,
    };
    if !content_length_accepted {
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    }
    let certificate_length = request.expected_certificate.len(env)?;
    if certificate_length == 0 || certificate_length > MAXIMUM_EXPECTED_CERTIFICATE_LENGTH {
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    }

    let content_bytes = OwnedSecret(env.convert_byte_array(request.content)?);
    let certificate_bytes = OwnedSecret(env.convert_byte_array(request.expected_certificate)?);

    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let input = match input_mode {
            QualifiedSigningInputMode::Message => QualifiedSigningInput::Message(&content_bytes.0),
            QualifiedSigningInputMode::Prehashed => {
                QualifiedSigningInput::Prehashed(&content_bytes.0)
            }
        };
        let (result, exchange) = sign(
            exchange,
            algorithm,
            pin.into_vec(),
            input,
            &certificate_bytes.0,
        );
        (result, exchange.bridge_failed())
    };
    drop(content_bytes);
    drop(certificate_bytes);

    let mut reply = if bridge_failed {
        vec![QUALIFIED_SIGNATURE_BRIDGE_ERROR]
    } else {
        encode_qualified_signature_reply(result)
    };
    let java_reply = env.byte_array_from_slice(&reply);
    reply.fill(0);
    java_reply
}

/// Copy a caller-owned secret array, clearing the Java copy immediately.
/// The returned bytes are the only remaining copy and must be zeroized
/// by the caller on every path.
fn take_secret_bytes(
    env: &mut Env<'_>,
    array: &JByteArray<'_>,
) -> Result<Vec<u8>, jni::errors::Error> {
    let mut bytes = match env.convert_byte_array(array) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = clear_java_byte_array(env, array);
            return Err(error);
        }
    };
    if let Err(error) = clear_java_byte_array(env, array) {
        bytes.fill(0);
        return Err(error);
    }
    Ok(bytes)
}

fn clear_java_byte_array(env: &Env<'_>, array: &JByteArray<'_>) -> Result<(), jni::errors::Error> {
    const ZEROES: [i8; JAVA_ARRAY_CLEAR_CHUNK_LENGTH] = [0; JAVA_ARRAY_CLEAR_CHUNK_LENGTH];
    let length = array.len(env)?;
    let mut offset = 0usize;
    while offset < length {
        let chunk_length = (length - offset).min(JAVA_ARRAY_CLEAR_CHUNK_LENGTH);
        array.set_region(env, offset as jni::sys::jsize, &ZEROES[..chunk_length])?;
        offset += chunk_length;
    }
    Ok(())
}

fn one_byte_reply<'local>(
    env: &mut Env<'local>,
    tag: u8,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    env.byte_array_from_slice(&[tag])
}

fn exchange_level_from_jint(value: jint) -> Option<CardExchangeLevel> {
    match value {
        EXCHANGE_LEVEL_APDU => Some(CardExchangeLevel::Apdu),
        EXCHANGE_LEVEL_T0_TPDU => Some(CardExchangeLevel::T0Tpdu),
        _ => None,
    }
}

fn authentication_algorithm_from_jint(value: jint) -> Option<AuthenticationSigningAlgorithm> {
    match value {
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256) => {
            Some(AuthenticationSigningAlgorithm::RsaPkcs1Sha256)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256) => {
            Some(AuthenticationSigningAlgorithm::RsaPssSha256)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256) => {
            Some(AuthenticationSigningAlgorithm::EcdsaP384Sha256)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384) => {
            Some(AuthenticationSigningAlgorithm::EcdsaP384Sha384)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384) => {
            Some(AuthenticationSigningAlgorithm::RsaPkcs1Sha384)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384) => {
            Some(AuthenticationSigningAlgorithm::RsaPssSha384)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512) => {
            Some(AuthenticationSigningAlgorithm::RsaPkcs1Sha512)
        }
        value if value == jint::from(AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512) => {
            Some(AuthenticationSigningAlgorithm::RsaPssSha512)
        }
        _ => None,
    }
}

fn qualified_algorithm_from_jint(value: jint) -> Option<QualifiedSigningAlgorithm> {
    match value {
        value if value == jint::from(QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384) => {
            Some(QualifiedSigningAlgorithm::RsaPkcs1Sha384)
        }
        value if value == jint::from(QUALIFIED_ALGORITHM_ECDSA_P384_SHA384) => {
            Some(QualifiedSigningAlgorithm::EcdsaP384Sha384)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QualifiedSigningInputMode {
    Message,
    Prehashed,
}

fn qualified_request_from_jint(
    value: jint,
) -> Option<(QualifiedSigningAlgorithm, QualifiedSigningInputMode)> {
    if let Some(algorithm) = qualified_algorithm_from_jint(value) {
        return Some((algorithm, QualifiedSigningInputMode::Message));
    }
    match value {
        value if value == jint::from(QUALIFIED_PREHASHED_RSA_PKCS1_SHA384) => Some((
            QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            QualifiedSigningInputMode::Prehashed,
        )),
        value if value == jint::from(QUALIFIED_PREHASHED_ECDSA_P384_SHA384) => Some((
            QualifiedSigningAlgorithm::EcdsaP384Sha384,
            QualifiedSigningInputMode::Prehashed,
        )),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticationSigningInputMode {
    Message,
    Prehashed,
}

fn authentication_request_from_jint(
    value: jint,
) -> Option<(
    AuthenticationSigningAlgorithm,
    AuthenticationSigningInputMode,
)> {
    if let Some(algorithm) = authentication_algorithm_from_jint(value) {
        return Some((algorithm, AuthenticationSigningInputMode::Message));
    }
    match value {
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA256) => Some((
            AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PSS_SHA256) => Some((
            AuthenticationSigningAlgorithm::RsaPssSha256,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_ECDSA_P384_SHA256) => Some((
            AuthenticationSigningAlgorithm::EcdsaP384Sha256,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_ECDSA_P384_SHA384) => Some((
            AuthenticationSigningAlgorithm::EcdsaP384Sha384,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA384) => Some((
            AuthenticationSigningAlgorithm::RsaPkcs1Sha384,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PSS_SHA384) => Some((
            AuthenticationSigningAlgorithm::RsaPssSha384,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA512) => Some((
            AuthenticationSigningAlgorithm::RsaPkcs1Sha512,
            AuthenticationSigningInputMode::Prehashed,
        )),
        value if value == jint::from(AUTHENTICATION_PREHASHED_RSA_PSS_SHA512) => Some((
            AuthenticationSigningAlgorithm::RsaPssSha512,
            AuthenticationSigningInputMode::Prehashed,
        )),
        _ => None,
    }
}

fn map_pkcs15_selection_result(
    result: Result<(), Pkcs15Error<card_transport::AndroidTransportError>>,
) -> jint {
    match result {
        Ok(()) => CARD_OPERATION_SUCCEEDED,
        Err(Pkcs15Error::Outcome(TransportOutcome::NoCard | TransportOutcome::ReaderRemoved)) => {
            CARD_OPERATION_CARD_UNAVAILABLE
        }
        Err(Pkcs15Error::Status(_)) => CARD_OPERATION_REJECTED,
        Err(Pkcs15Error::Transport(_))
        | Err(Pkcs15Error::Outcome(
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync,
        )) => CARD_OPERATION_TRANSPORT_ERROR,
        Err(Pkcs15Error::Outcome(TransportOutcome::Response(_)))
        | Err(Pkcs15Error::Aid(_))
        | Err(Pkcs15Error::Command(_))
        | Err(Pkcs15Error::Empty)
        | Err(Pkcs15Error::TooLarge)
        | Err(Pkcs15Error::InvalidData(_)) => CARD_OPERATION_BRIDGE_ERROR,
    }
}

fn encode_certificate_reply(result: Result<CardCertificate, CertificateReadFailure>) -> Vec<u8> {
    match result {
        Ok(certificate) => {
            let profile = certificate.profile();
            let der = certificate.into_der();
            let der_bytes = der.as_bytes();
            let mut reply = Vec::with_capacity(CERTIFICATE_REPLY_HEADER_LENGTH + der.len());
            reply.push(CERTIFICATE_SUCCEEDED);
            reply.push(match profile {
                CardKeyProfile::Rsa2048 => KEY_PROFILE_RSA_2048,
                CardKeyProfile::Rsa3072 => KEY_PROFILE_RSA_3072,
                CardKeyProfile::EcdsaP256 => KEY_PROFILE_ECDSA_P256,
                CardKeyProfile::EcdsaP384 => KEY_PROFILE_ECDSA_P384,
            });
            reply.extend_from_slice(der_bytes);
            reply
        }
        Err(failure) => vec![match failure {
            CertificateReadFailure::CardUnavailable => CERTIFICATE_CARD_UNAVAILABLE,
            CertificateReadFailure::Rejected => CERTIFICATE_REJECTED,
            CertificateReadFailure::Transport => CERTIFICATE_TRANSPORT_ERROR,
            CertificateReadFailure::InvalidCertificate => CERTIFICATE_INVALID,
            CertificateReadFailure::PaceRejected => CERTIFICATE_PACE_REJECTED,
            CertificateReadFailure::Bridge => CERTIFICATE_BRIDGE_ERROR,
            CertificateReadFailure::ActivationRequired => CERTIFICATE_ACTIVATION_REQUIRED,
            CertificateReadFailure::OrganizationCard => CERTIFICATE_ORGANIZATION_CARD,
        }],
    }
}

/// The contactless open reply nests the two established vocabularies:
/// `[CERTIFICATE_SUCCEEDED, preflight-reply length, preflight reply,
/// certificate reply]` on success, `[CERTIFICATE_ACTIVATION_REQUIRED,
/// activation scheme, activation needs]` for a card awaiting activation,
/// whose identity is not read, or one certificate-vocabulary failure
/// byte. Kotlin splits the wrapper and reuses both strict sub-decoders.
fn encode_contactless_open_reply(outcome: ContactlessOpenOutcome) -> Vec<u8> {
    match outcome {
        ContactlessOpenOutcome::Ready(certificate, preflight) => {
            let mut preflight_reply = encode_pin_preflight_reply(Ok(preflight));
            let mut certificate_reply = encode_certificate_reply(Ok(certificate));
            let mut reply = Vec::with_capacity(
                CONTACTLESS_OPEN_HEADER_LENGTH + preflight_reply.len() + certificate_reply.len(),
            );
            reply.push(CERTIFICATE_SUCCEEDED);
            reply.push(PIN_PREFLIGHT_REPLY_LENGTH_BYTE);
            reply.append(&mut preflight_reply);
            reply.append(&mut certificate_reply);
            reply
        }
        ContactlessOpenOutcome::ActivationRequired(scheme, needs) => vec![
            CERTIFICATE_ACTIVATION_REQUIRED,
            card_management::activation_scheme_byte(scheme),
            card_management::activation_needs_byte(needs),
        ],
        ContactlessOpenOutcome::Failure(failure) => encode_certificate_reply(Err(failure)),
    }
}

fn encode_card_access_reply(result: Result<CardAccessSummary, CardAccessProbeFailure>) -> Vec<u8> {
    match result {
        Ok(summary) => {
            let reply: [u8; CARD_ACCESS_REPLY_LENGTH] = [
                CARD_ACCESS_SUCCEEDED,
                match summary.kind {
                    None => CARD_KIND_UNKNOWN,
                    Some(ContactlessCardKind::Personal) => CARD_KIND_PERSONAL,
                    Some(ContactlessCardKind::Organization) => CARD_KIND_ORGANIZATION,
                },
                summary.pace_entry_count,
            ];
            reply.to_vec()
        }
        Err(failure) => vec![match failure {
            CardAccessProbeFailure::CardUnavailable => CARD_ACCESS_CARD_UNAVAILABLE,
            CardAccessProbeFailure::Rejected => CARD_ACCESS_REJECTED,
            CardAccessProbeFailure::Transport => CARD_ACCESS_TRANSPORT_ERROR,
            CardAccessProbeFailure::Invalid => CARD_ACCESS_INVALID,
            CardAccessProbeFailure::Bridge => CARD_ACCESS_BRIDGE_ERROR,
        }],
    }
}

fn encode_pin_preflight_reply(result: Result<PinPreflight, PinPreflightFailure>) -> Vec<u8> {
    match result {
        Ok(preflight) => {
            let (state, retries) = match preflight.state {
                PinState::Verified => (PIN_STATE_VERIFIED, NO_RETRY_COUNT),
                PinState::Remaining(retries) => (PIN_STATE_REMAINING, retries),
                PinState::Locked => (PIN_STATE_LOCKED, NO_RETRY_COUNT),
                PinState::NoInformation => (PIN_STATE_NO_INFORMATION, NO_RETRY_COUNT),
                PinState::Unrecognised => (PIN_STATE_UNRECOGNISED, NO_RETRY_COUNT),
            };
            let scheme_byte = match preflight.scheme {
                PinReferenceScheme::Citizen => PIN_REFERENCE_CITIZEN,
                PinReferenceScheme::Organizational => PIN_REFERENCE_ORGANIZATIONAL,
                PinReferenceScheme::Estonian => return vec![PIN_PREFLIGHT_BRIDGE_ERROR],
            };
            let reply: [u8; PIN_PREFLIGHT_REPLY_LENGTH] = [
                PIN_PREFLIGHT_SUCCEEDED,
                scheme_byte,
                state,
                retries,
                if preflight.retry_floor_permits {
                    POLICY_PERMITTED
                } else {
                    POLICY_REFUSED
                },
            ];
            reply.to_vec()
        }
        Err(failure) => vec![match failure {
            PinPreflightFailure::CardUnavailable => PIN_PREFLIGHT_CARD_UNAVAILABLE,
            PinPreflightFailure::Transport => PIN_PREFLIGHT_TRANSPORT_ERROR,
            PinPreflightFailure::Bridge => PIN_PREFLIGHT_BRIDGE_ERROR,
        }],
    }
}

fn encode_authentication_signature_reply(
    result: Result<AuthenticationSignature, AuthenticationSignFailure>,
) -> Vec<u8> {
    match result {
        Ok(mut signature) => {
            let mut reply = Vec::with_capacity(
                AUTHENTICATION_SIGNATURE_REPLY_HEADER_LENGTH + signature.bytes.len(),
            );
            reply.push(AUTHENTICATION_SIGNATURE_SUCCEEDED);
            reply.push(match signature.algorithm {
                AuthenticationSigningAlgorithm::RsaPkcs1Sha256 => {
                    AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256
                }
                AuthenticationSigningAlgorithm::RsaPssSha256 => {
                    AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256
                }
                AuthenticationSigningAlgorithm::EcdsaP384Sha256 => {
                    AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256
                }
                AuthenticationSigningAlgorithm::EcdsaP384Sha384 => {
                    AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384
                }
                AuthenticationSigningAlgorithm::RsaPkcs1Sha384 => {
                    AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384
                }
                AuthenticationSigningAlgorithm::RsaPssSha384 => {
                    AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384
                }
                AuthenticationSigningAlgorithm::RsaPkcs1Sha512 => {
                    AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512
                }
                AuthenticationSigningAlgorithm::RsaPssSha512 => {
                    AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512
                }
            });
            reply.append(&mut signature.bytes);
            reply
        }
        Err(AuthenticationSignFailure::WrongPin { retries_left }) => {
            vec![AUTHENTICATION_SIGNATURE_WRONG_PIN, retries_left]
        }
        Err(failure) => vec![match failure {
            AuthenticationSignFailure::InvalidPin => AUTHENTICATION_SIGNATURE_INVALID_PIN,
            AuthenticationSignFailure::SafetyRefused => AUTHENTICATION_SIGNATURE_SAFETY_REFUSED,
            AuthenticationSignFailure::PinLocked => AUTHENTICATION_SIGNATURE_PIN_LOCKED,
            AuthenticationSignFailure::WrongPin { .. } => AUTHENTICATION_SIGNATURE_WRONG_PIN,
            AuthenticationSignFailure::VerificationRejected => {
                AUTHENTICATION_SIGNATURE_VERIFICATION_REJECTED
            }
            AuthenticationSignFailure::SigningRejected => AUTHENTICATION_SIGNATURE_SIGNING_REJECTED,
            AuthenticationSignFailure::CardUnavailable => AUTHENTICATION_SIGNATURE_CARD_UNAVAILABLE,
            AuthenticationSignFailure::Transport => AUTHENTICATION_SIGNATURE_TRANSPORT_ERROR,
            AuthenticationSignFailure::PaceRejected => AUTHENTICATION_SIGNATURE_PACE_REJECTED,
            AuthenticationSignFailure::Bridge => AUTHENTICATION_SIGNATURE_BRIDGE_ERROR,
        }],
    }
}

fn encode_qualified_signature_reply(
    result: Result<QualifiedSignature, QualifiedSignFailure>,
) -> Vec<u8> {
    match result {
        Ok(mut signature) => {
            let mut reply =
                Vec::with_capacity(QUALIFIED_SIGNATURE_REPLY_HEADER_LENGTH + signature.bytes.len());
            reply.push(QUALIFIED_SIGNATURE_SUCCEEDED);
            reply.push(match signature.algorithm {
                QualifiedSigningAlgorithm::RsaPkcs1Sha384 => QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384,
                QualifiedSigningAlgorithm::EcdsaP384Sha384 => QUALIFIED_ALGORITHM_ECDSA_P384_SHA384,
            });
            reply.append(&mut signature.bytes);
            reply
        }
        Err(QualifiedSignFailure::WrongPin { retries_left }) => {
            vec![QUALIFIED_SIGNATURE_WRONG_PIN, retries_left]
        }
        Err(failure) => vec![match failure {
            QualifiedSignFailure::InvalidPin => QUALIFIED_SIGNATURE_INVALID_PIN,
            QualifiedSignFailure::SafetyRefused => QUALIFIED_SIGNATURE_SAFETY_REFUSED,
            QualifiedSignFailure::PinLocked => QUALIFIED_SIGNATURE_PIN_LOCKED,
            QualifiedSignFailure::WrongPin { .. } => QUALIFIED_SIGNATURE_WRONG_PIN,
            QualifiedSignFailure::VerificationRejected => QUALIFIED_SIGNATURE_VERIFICATION_REJECTED,
            QualifiedSignFailure::CertificateRejected => QUALIFIED_SIGNATURE_CERTIFICATE_REJECTED,
            QualifiedSignFailure::InvalidCertificate => QUALIFIED_SIGNATURE_INVALID_CERTIFICATE,
            QualifiedSignFailure::CertificateMismatch => QUALIFIED_SIGNATURE_CERTIFICATE_MISMATCH,
            QualifiedSignFailure::KeyProfileMismatch => QUALIFIED_SIGNATURE_KEY_PROFILE_MISMATCH,
            QualifiedSignFailure::SigningRejected => QUALIFIED_SIGNATURE_SIGNING_REJECTED,
            QualifiedSignFailure::CardUnavailable => QUALIFIED_SIGNATURE_CARD_UNAVAILABLE,
            QualifiedSignFailure::Transport => QUALIFIED_SIGNATURE_TRANSPORT_ERROR,
            QualifiedSignFailure::Bridge => QUALIFIED_SIGNATURE_BRIDGE_ERROR,
        }],
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::TransportOutcome;
    use refineid_atr::{Convention, MINIMAL_DIRECT_ATR};
    use refineid_auth::PinReferenceScheme;
    use refineid_pkcs15::Pkcs15Error;

    use crate::card_management;
    use refineid_sign::{ECDSA_P384_SIG_BYTES, RSA_3072_SIG_BYTES};

    use crate::organization_card::ContactlessCardKind;

    #[test]
    fn a_ca_read_answer_names_its_step_and_the_card_s_word() {
        use super::{
            CA_READ_NOT_ASKED, CA_READ_STEP_CERTIFICATE, CA_READ_STEP_FACTOR, CA_READ_STEP_READ,
            CA_READ_STEP_SELECT_FILE, CA_READ_SUCCESS_STATUS, encode_ca_read_answer,
        };
        use crate::contactless::{CaReadAnswer, CaReadStep};
        const FILE_NOT_FOUND: u16 = 0x6A82;
        assert_eq!(
            encode_ca_read_answer(CaReadAnswer::NotAsked),
            CA_READ_NOT_ASKED
        );
        assert_eq!(
            encode_ca_read_answer(CaReadAnswer::Read),
            CA_READ_STEP_READ * CA_READ_STEP_FACTOR + CA_READ_SUCCESS_STATUS
        );
        assert_eq!(
            encode_ca_read_answer(CaReadAnswer::Refused {
                step: CaReadStep::SelectFile,
                status: FILE_NOT_FOUND,
            }),
            CA_READ_STEP_SELECT_FILE * CA_READ_STEP_FACTOR + i32::from(FILE_NOT_FOUND)
        );
        assert_eq!(
            encode_ca_read_answer(CaReadAnswer::Failed {
                step: CaReadStep::Certificate,
            }),
            CA_READ_STEP_CERTIFICATE * CA_READ_STEP_FACTOR
        );
    }

    use super::{
        ATR_INVALID, ATR_VALID_NON_T0_DIRECT, ATR_VALID_T0_DIRECT, ATR_VALID_T0_INVERSE,
        AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256, AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384,
        AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256, AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384,
        AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512, AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256,
        AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384, AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512,
        AUTHENTICATION_PREHASHED_ECDSA_P384_SHA256, AUTHENTICATION_PREHASHED_ECDSA_P384_SHA384,
        AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA256, AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA384,
        AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA512, AUTHENTICATION_PREHASHED_RSA_PSS_SHA256,
        AUTHENTICATION_PREHASHED_RSA_PSS_SHA384, AUTHENTICATION_PREHASHED_RSA_PSS_SHA512,
        AUTHENTICATION_SIGNATURE_CARD_UNAVAILABLE, AUTHENTICATION_SIGNATURE_PACE_REJECTED,
        AUTHENTICATION_SIGNATURE_REPLY_HEADER_LENGTH, AUTHENTICATION_SIGNATURE_SUCCEEDED,
        AUTHENTICATION_SIGNATURE_WRONG_PIN, CARD_ACCESS_BRIDGE_ERROR, CARD_ACCESS_CARD_UNAVAILABLE,
        CARD_ACCESS_INVALID, CARD_ACCESS_REJECTED, CARD_ACCESS_REPLY_LENGTH, CARD_ACCESS_SUCCEEDED,
        CARD_ACCESS_TRANSPORT_ERROR, CARD_KIND_PERSONAL, CARD_KIND_UNKNOWN,
        CARD_OPERATION_CARD_UNAVAILABLE, CARD_OPERATION_REJECTED, CARD_OPERATION_SUCCEEDED,
        CARD_OPERATION_TRANSPORT_ERROR, CERTIFICATE_ACTIVATION_REQUIRED,
        CERTIFICATE_CARD_UNAVAILABLE, CERTIFICATE_INVALID, CERTIFICATE_PACE_REJECTED,
        CERTIFICATE_REPLY_HEADER_LENGTH, CERTIFICATE_SUCCEEDED, ContactlessOpenOutcome,
        EXCHANGE_LEVEL_APDU, EXCHANGE_LEVEL_T0_TPDU, KEY_PROFILE_RSA_2048, NO_RETRY_COUNT,
        PIN_PREFLIGHT_BRIDGE_ERROR, PIN_PREFLIGHT_CARD_UNAVAILABLE, PIN_PREFLIGHT_REPLY_LENGTH,
        PIN_PREFLIGHT_REPLY_LENGTH_BYTE, PIN_PREFLIGHT_SUCCEEDED, PIN_PREFLIGHT_TRANSPORT_ERROR,
        PIN_REFERENCE_CITIZEN, PIN_REFERENCE_ORGANIZATIONAL, PIN_STATE_REMAINING, POLICY_PERMITTED,
        QUALIFIED_ALGORITHM_ECDSA_P384_SHA384, QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384,
        QUALIFIED_PREHASHED_ECDSA_P384_SHA384, QUALIFIED_PREHASHED_RSA_PKCS1_SHA384,
        QUALIFIED_SIGNATURE_CARD_UNAVAILABLE, QUALIFIED_SIGNATURE_REPLY_HEADER_LENGTH,
        QUALIFIED_SIGNATURE_SUCCEEDED, QUALIFIED_SIGNATURE_WRONG_PIN,
        authentication_algorithm_from_jint, authentication_request_from_jint,
        encode_authentication_signature_reply, encode_card_access_reply, encode_certificate_reply,
        encode_contactless_open_reply, encode_pin_preflight_reply,
        encode_qualified_signature_reply, exchange_level_from_jint, map_pkcs15_selection_result,
        qualified_algorithm_from_jint, qualified_request_from_jint, validate_atr_bytes,
    };
    use crate::authentication_signer::{
        AuthenticationSignFailure, AuthenticationSignature, AuthenticationSigningAlgorithm,
    };
    use crate::card_access::{CardAccessProbeFailure, CardAccessSummary};
    use crate::card_certificate::{
        CardCertificate, CardKeyProfile, CertificateDer, CertificateReadFailure,
    };
    use crate::card_transport::{AndroidTransportError, CardExchangeLevel};
    use crate::pin_status::{PinPreflight, PinPreflightFailure, PinState};
    use crate::qualified_signer::{
        QualifiedSignFailure, QualifiedSignature, QualifiedSigningAlgorithm,
    };

    const AUTHENTICATION_SIGNATURE_TAG_OFFSET: usize = 0;
    const AUTHENTICATION_SIGNATURE_ALGORITHM_OFFSET: usize = 1;
    const QUALIFIED_SIGNATURE_TAG_OFFSET: usize = 0;
    const QUALIFIED_SIGNATURE_ALGORITHM_OFFSET: usize = 1;
    const ATR_CONVENTION_OFFSET: usize = 0;
    const UNSUPPORTED_EXCHANGE_LEVEL: i32 = 2;
    const AUTHENTICATION_ALGORITHM_BELOW_RANGE: i32 = -1;
    const AUTHENTICATION_ALGORITHM_NON_MESSAGE_CODE: i32 =
        AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA256 as i32;
    const AUTHENTICATION_REQUEST_BELOW_RANGE: i32 = -1;
    const AUTHENTICATION_REQUEST_ABOVE_RANGE: i32 =
        AUTHENTICATION_PREHASHED_RSA_PSS_SHA512 as i32 + 1;
    const QUALIFIED_ALGORITHM_BELOW_RANGE: i32 = -1;
    const QUALIFIED_ALGORITHM_ABOVE_RANGE: i32 = 2;
    const QUALIFIED_REQUEST_ABOVE_RANGE: i32 = QUALIFIED_PREHASHED_ECDSA_P384_SHA384 as i32 + 1;
    const SYNTHETIC_REJECTED_STATUS_WORD: u16 = 0x6a82;
    const SYNTHETIC_DER_SEQUENCE_TAG: u8 = 0x30;
    const SYNTHETIC_DER_EMPTY_LENGTH: u8 = 0x00;
    const SYNTHETIC_PIN_RETRY_COUNT: u8 = 3;
    const PIN_PREFLIGHT_RETRY_COUNT_OFFSET: usize = 3;

    #[test]
    fn accepts_minimal_direct_atr() {
        assert_eq!(validate_atr_bytes(&MINIMAL_DIRECT_ATR), ATR_VALID_T0_DIRECT);
    }

    #[test]
    fn accepts_minimal_inverse_atr() {
        let mut atr = MINIMAL_DIRECT_ATR;
        atr[ATR_CONVENTION_OFFSET] = Convention::Inverse.as_ts();

        assert_eq!(validate_atr_bytes(&atr), ATR_VALID_T0_INVERSE);
    }

    #[test]
    fn classifies_a_non_t0_protocol() {
        const T0_WITH_TD1: u8 = 1 << 7;
        const TD1_T1: u8 = 1;
        let tck = T0_WITH_TD1 ^ TD1_T1;
        let atr = [Convention::Direct.as_ts(), T0_WITH_TD1, TD1_T1, tck];

        assert_eq!(validate_atr_bytes(&atr), ATR_VALID_NON_T0_DIRECT);
    }

    #[test]
    fn rejects_truncated_atr() {
        assert_eq!(validate_atr_bytes(&[]), ATR_INVALID);
    }

    #[test]
    fn accepts_only_stable_exchange_level_codes() {
        assert_eq!(
            exchange_level_from_jint(EXCHANGE_LEVEL_APDU),
            Some(CardExchangeLevel::Apdu)
        );
        assert_eq!(
            exchange_level_from_jint(EXCHANGE_LEVEL_T0_TPDU),
            Some(CardExchangeLevel::T0Tpdu)
        );
        assert_eq!(exchange_level_from_jint(UNSUPPORTED_EXCHANGE_LEVEL), None);
    }

    #[test]
    fn accepts_only_stable_authentication_algorithm_codes() {
        for (wire_value, algorithm) in [
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256,
                AuthenticationSigningAlgorithm::RsaPssSha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256,
                AuthenticationSigningAlgorithm::EcdsaP384Sha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384,
                AuthenticationSigningAlgorithm::EcdsaP384Sha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384,
                AuthenticationSigningAlgorithm::RsaPssSha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha512,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512,
                AuthenticationSigningAlgorithm::RsaPssSha512,
            ),
        ] {
            assert_eq!(
                authentication_algorithm_from_jint(i32::from(wire_value)),
                Some(algorithm)
            );
        }
        assert_eq!(
            authentication_algorithm_from_jint(AUTHENTICATION_ALGORITHM_BELOW_RANGE),
            None
        );
        assert_eq!(
            authentication_algorithm_from_jint(AUTHENTICATION_ALGORITHM_NON_MESSAGE_CODE),
            None
        );
    }

    #[test]
    fn accepts_only_stable_qualified_algorithm_codes() {
        assert_eq!(
            qualified_algorithm_from_jint(i32::from(QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384)),
            Some(QualifiedSigningAlgorithm::RsaPkcs1Sha384)
        );
        assert_eq!(
            qualified_algorithm_from_jint(QUALIFIED_ALGORITHM_BELOW_RANGE),
            None
        );
        assert_eq!(
            qualified_algorithm_from_jint(QUALIFIED_ALGORITHM_ABOVE_RANGE),
            None
        );
    }

    #[test]
    fn accepts_only_stable_qualified_request_codes() {
        assert_eq!(
            qualified_request_from_jint(i32::from(QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384)),
            Some((
                QualifiedSigningAlgorithm::RsaPkcs1Sha384,
                super::QualifiedSigningInputMode::Message
            ))
        );
        assert_eq!(
            qualified_request_from_jint(i32::from(QUALIFIED_ALGORITHM_ECDSA_P384_SHA384)),
            Some((
                QualifiedSigningAlgorithm::EcdsaP384Sha384,
                super::QualifiedSigningInputMode::Message
            ))
        );
        assert_eq!(
            qualified_request_from_jint(i32::from(QUALIFIED_PREHASHED_RSA_PKCS1_SHA384)),
            Some((
                QualifiedSigningAlgorithm::RsaPkcs1Sha384,
                super::QualifiedSigningInputMode::Prehashed
            ))
        );
        assert_eq!(
            qualified_request_from_jint(i32::from(QUALIFIED_PREHASHED_ECDSA_P384_SHA384)),
            Some((
                QualifiedSigningAlgorithm::EcdsaP384Sha384,
                super::QualifiedSigningInputMode::Prehashed
            ))
        );
        assert_eq!(
            qualified_request_from_jint(QUALIFIED_ALGORITHM_BELOW_RANGE),
            None
        );
        assert_eq!(
            qualified_request_from_jint(QUALIFIED_REQUEST_ABOVE_RANGE),
            None
        );
    }

    #[test]
    fn accepts_only_stable_authentication_request_codes() {
        for (wire_value, algorithm) in [
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA256,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA256,
                AuthenticationSigningAlgorithm::RsaPssSha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA256,
                AuthenticationSigningAlgorithm::EcdsaP384Sha256,
            ),
            (
                AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384,
                AuthenticationSigningAlgorithm::EcdsaP384Sha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA384,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA384,
                AuthenticationSigningAlgorithm::RsaPssSha384,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PKCS1_SHA512,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha512,
            ),
            (
                AUTHENTICATION_ALGORITHM_RSA_PSS_SHA512,
                AuthenticationSigningAlgorithm::RsaPssSha512,
            ),
        ] {
            assert_eq!(
                authentication_request_from_jint(i32::from(wire_value)),
                Some((algorithm, super::AuthenticationSigningInputMode::Message))
            );
        }
        for (wire_value, algorithm) in [
            (
                AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA256,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha256,
            ),
            (
                AUTHENTICATION_PREHASHED_RSA_PSS_SHA256,
                AuthenticationSigningAlgorithm::RsaPssSha256,
            ),
            (
                AUTHENTICATION_PREHASHED_ECDSA_P384_SHA256,
                AuthenticationSigningAlgorithm::EcdsaP384Sha256,
            ),
            (
                AUTHENTICATION_PREHASHED_ECDSA_P384_SHA384,
                AuthenticationSigningAlgorithm::EcdsaP384Sha384,
            ),
            (
                AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA384,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha384,
            ),
            (
                AUTHENTICATION_PREHASHED_RSA_PSS_SHA384,
                AuthenticationSigningAlgorithm::RsaPssSha384,
            ),
            (
                AUTHENTICATION_PREHASHED_RSA_PKCS1_SHA512,
                AuthenticationSigningAlgorithm::RsaPkcs1Sha512,
            ),
            (
                AUTHENTICATION_PREHASHED_RSA_PSS_SHA512,
                AuthenticationSigningAlgorithm::RsaPssSha512,
            ),
        ] {
            assert_eq!(
                authentication_request_from_jint(i32::from(wire_value)),
                Some((algorithm, super::AuthenticationSigningInputMode::Prehashed))
            );
        }
        assert_eq!(
            authentication_request_from_jint(AUTHENTICATION_REQUEST_BELOW_RANGE),
            None
        );
        assert_eq!(
            authentication_request_from_jint(AUTHENTICATION_REQUEST_ABOVE_RANGE),
            None
        );
    }

    #[test]
    fn maps_pkcs15_selection_outcomes_without_exposing_details() {
        assert_eq!(
            map_pkcs15_selection_result(Ok(())),
            CARD_OPERATION_SUCCEEDED
        );
        assert_eq!(
            map_pkcs15_selection_result(Err(Pkcs15Error::Outcome(TransportOutcome::NoCard))),
            CARD_OPERATION_CARD_UNAVAILABLE
        );
        assert_eq!(
            map_pkcs15_selection_result(Err(Pkcs15Error::Outcome(
                TransportOutcome::ProtocolDesync
            ))),
            CARD_OPERATION_TRANSPORT_ERROR
        );
        assert_eq!(
            map_pkcs15_selection_result(Err(Pkcs15Error::Transport(
                AndroidTransportError::Backend
            ))),
            CARD_OPERATION_TRANSPORT_ERROR
        );
        assert_eq!(
            map_pkcs15_selection_result(Err(Pkcs15Error::Status(
                refineid_apdu::StatusWord::Other(SYNTHETIC_REJECTED_STATUS_WORD)
            ))),
            CARD_OPERATION_REJECTED
        );
    }

    #[test]
    fn encodes_certificate_success_and_typed_failures() {
        const SYNTHETIC_DER: &[u8] = &[SYNTHETIC_DER_SEQUENCE_TAG, SYNTHETIC_DER_EMPTY_LENGTH];
        let success = encode_certificate_reply(Ok(CardCertificate::new(
            CardKeyProfile::Rsa2048,
            CertificateDer::from_validated(SYNTHETIC_DER.to_vec()),
        )));
        assert_eq!(
            success,
            [
                &[CERTIFICATE_SUCCEEDED, KEY_PROFILE_RSA_2048],
                SYNTHETIC_DER,
            ]
            .concat()
        );
        assert_eq!(
            success.len(),
            CERTIFICATE_REPLY_HEADER_LENGTH + SYNTHETIC_DER.len()
        );
        assert_eq!(
            encode_certificate_reply(Err(CertificateReadFailure::CardUnavailable)),
            vec![CERTIFICATE_CARD_UNAVAILABLE]
        );
        assert_eq!(
            encode_certificate_reply(Err(CertificateReadFailure::InvalidCertificate)),
            vec![CERTIFICATE_INVALID]
        );
    }

    #[test]
    fn encodes_card_access_summary_and_typed_failures() {
        const SYNTHETIC_PACE_ENTRY_COUNT: u8 = 2;
        let published = encode_card_access_reply(Ok(CardAccessSummary {
            kind: Some(ContactlessCardKind::Personal),
            pace_entry_count: SYNTHETIC_PACE_ENTRY_COUNT,
        }));
        assert_eq!(
            published,
            vec![
                CARD_ACCESS_SUCCEEDED,
                CARD_KIND_PERSONAL,
                SYNTHETIC_PACE_ENTRY_COUNT,
            ]
        );
        assert_eq!(published.len(), CARD_ACCESS_REPLY_LENGTH);
        assert_eq!(
            encode_card_access_reply(Ok(CardAccessSummary {
                kind: None,
                pace_entry_count: 1,
            })),
            vec![CARD_ACCESS_SUCCEEDED, CARD_KIND_UNKNOWN, 1]
        );
        assert_eq!(
            encode_card_access_reply(Err(CardAccessProbeFailure::CardUnavailable)),
            vec![CARD_ACCESS_CARD_UNAVAILABLE]
        );
        assert_eq!(
            encode_card_access_reply(Err(CardAccessProbeFailure::Rejected)),
            vec![CARD_ACCESS_REJECTED]
        );
        assert_eq!(
            encode_card_access_reply(Err(CardAccessProbeFailure::Transport)),
            vec![CARD_ACCESS_TRANSPORT_ERROR]
        );
        assert_eq!(
            encode_card_access_reply(Err(CardAccessProbeFailure::Invalid)),
            vec![CARD_ACCESS_INVALID]
        );
        assert_eq!(
            encode_card_access_reply(Err(CardAccessProbeFailure::Bridge)),
            vec![CARD_ACCESS_BRIDGE_ERROR]
        );
    }

    #[test]
    fn encodes_contactless_open_as_nested_established_replies() {
        const SYNTHETIC_DER: &[u8] = &[SYNTHETIC_DER_SEQUENCE_TAG, SYNTHETIC_DER_EMPTY_LENGTH];
        let success = encode_contactless_open_reply(ContactlessOpenOutcome::Ready(
            CardCertificate::new(
                CardKeyProfile::Rsa2048,
                CertificateDer::from_validated(SYNTHETIC_DER.to_vec()),
            ),
            PinPreflight {
                scheme: PinReferenceScheme::Citizen,
                state: PinState::Remaining(SYNTHETIC_PIN_RETRY_COUNT),
                retry_floor_permits: true,
            },
        ));
        assert_eq!(
            success,
            [
                &[
                    CERTIFICATE_SUCCEEDED,
                    PIN_PREFLIGHT_REPLY_LENGTH_BYTE,
                    PIN_PREFLIGHT_SUCCEEDED,
                    PIN_REFERENCE_CITIZEN,
                    PIN_STATE_REMAINING,
                    SYNTHETIC_PIN_RETRY_COUNT,
                    POLICY_PERMITTED,
                    CERTIFICATE_SUCCEEDED,
                    KEY_PROFILE_RSA_2048,
                ],
                SYNTHETIC_DER,
            ]
            .concat()
        );
        let activation_required =
            encode_contactless_open_reply(ContactlessOpenOutcome::ActivationRequired(
                refineid_auth::ActivationScheme::PresetActivationPin,
                refineid_auth::CardActivationNeeds {
                    pin1: false,
                    pin2: true,
                },
            ));
        assert_eq!(
            activation_required,
            [
                CERTIFICATE_ACTIVATION_REQUIRED,
                card_management::ACTIVATION_SCHEME_PRESET,
                card_management::ACTIVATION_NEEDS_PIN2_ONLY,
            ]
        );
        assert_eq!(
            encode_contactless_open_reply(ContactlessOpenOutcome::Failure(
                CertificateReadFailure::PaceRejected
            )),
            vec![CERTIFICATE_PACE_REJECTED]
        );
        assert_eq!(
            encode_contactless_open_reply(ContactlessOpenOutcome::Failure(
                CertificateReadFailure::CardUnavailable
            )),
            vec![CERTIFICATE_CARD_UNAVAILABLE]
        );
    }

    #[test]
    fn encodes_pin_preflight_without_raw_card_values() {
        let success = encode_pin_preflight_reply(Ok(PinPreflight {
            scheme: PinReferenceScheme::Citizen,
            state: PinState::Remaining(SYNTHETIC_PIN_RETRY_COUNT),
            retry_floor_permits: true,
        }));
        assert_eq!(
            success,
            vec![
                PIN_PREFLIGHT_SUCCEEDED,
                PIN_REFERENCE_CITIZEN,
                PIN_STATE_REMAINING,
                SYNTHETIC_PIN_RETRY_COUNT,
                POLICY_PERMITTED,
            ]
        );
        assert_eq!(success.len(), PIN_PREFLIGHT_REPLY_LENGTH);
        assert_ne!(success[PIN_PREFLIGHT_RETRY_COUNT_OFFSET], NO_RETRY_COUNT);
        let organizational = encode_pin_preflight_reply(Ok(PinPreflight {
            scheme: PinReferenceScheme::Organizational,
            state: PinState::Remaining(SYNTHETIC_PIN_RETRY_COUNT),
            retry_floor_permits: true,
        }));
        assert_eq!(
            organizational,
            vec![
                PIN_PREFLIGHT_SUCCEEDED,
                PIN_REFERENCE_ORGANIZATIONAL,
                PIN_STATE_REMAINING,
                SYNTHETIC_PIN_RETRY_COUNT,
                POLICY_PERMITTED,
            ]
        );
        let estonian = encode_pin_preflight_reply(Ok(PinPreflight {
            scheme: PinReferenceScheme::Estonian,
            state: PinState::Remaining(SYNTHETIC_PIN_RETRY_COUNT),
            retry_floor_permits: true,
        }));
        assert_eq!(estonian, vec![PIN_PREFLIGHT_BRIDGE_ERROR]);
        assert_eq!(
            encode_pin_preflight_reply(Err(PinPreflightFailure::CardUnavailable)),
            vec![PIN_PREFLIGHT_CARD_UNAVAILABLE]
        );
        assert_eq!(
            encode_pin_preflight_reply(Err(PinPreflightFailure::Transport)),
            vec![PIN_PREFLIGHT_TRANSPORT_ERROR]
        );
        assert_eq!(
            encode_pin_preflight_reply(Err(PinPreflightFailure::Bridge)),
            vec![PIN_PREFLIGHT_BRIDGE_ERROR]
        );
    }

    #[test]
    fn encodes_signature_success_and_coarse_failure() {
        const SYNTHETIC_SIGNATURE_FILL: u8 = 0xA5;
        const SYNTHETIC_SIGNATURE: [u8; ECDSA_P384_SIG_BYTES] =
            [SYNTHETIC_SIGNATURE_FILL; ECDSA_P384_SIG_BYTES];
        let success = encode_authentication_signature_reply(Ok(AuthenticationSignature {
            algorithm: AuthenticationSigningAlgorithm::EcdsaP384Sha384,
            bytes: SYNTHETIC_SIGNATURE.to_vec(),
        }));
        assert_eq!(
            success[AUTHENTICATION_SIGNATURE_TAG_OFFSET],
            AUTHENTICATION_SIGNATURE_SUCCEEDED
        );
        assert_eq!(
            success[AUTHENTICATION_SIGNATURE_ALGORITHM_OFFSET],
            AUTHENTICATION_ALGORITHM_ECDSA_P384_SHA384
        );
        assert_eq!(
            &success[AUTHENTICATION_SIGNATURE_REPLY_HEADER_LENGTH..],
            &SYNTHETIC_SIGNATURE
        );
        assert_eq!(
            encode_authentication_signature_reply(Err(AuthenticationSignFailure::CardUnavailable,)),
            vec![AUTHENTICATION_SIGNATURE_CARD_UNAVAILABLE]
        );
        assert_eq!(
            encode_authentication_signature_reply(Err(AuthenticationSignFailure::PaceRejected)),
            vec![AUTHENTICATION_SIGNATURE_PACE_REJECTED]
        );
    }

    #[test]
    fn encodes_qualified_signature_success_and_coarse_failure() {
        const SYNTHETIC_QUALIFIED_SIGNATURE_FILL: u8 = 0xC3;
        const SYNTHETIC_QUALIFIED_SIGNATURE: [u8; RSA_3072_SIG_BYTES] =
            [SYNTHETIC_QUALIFIED_SIGNATURE_FILL; RSA_3072_SIG_BYTES];
        let success = encode_qualified_signature_reply(Ok(QualifiedSignature {
            algorithm: QualifiedSigningAlgorithm::RsaPkcs1Sha384,
            bytes: SYNTHETIC_QUALIFIED_SIGNATURE.to_vec(),
        }));
        assert_eq!(
            success[QUALIFIED_SIGNATURE_TAG_OFFSET],
            QUALIFIED_SIGNATURE_SUCCEEDED
        );
        assert_eq!(
            success[QUALIFIED_SIGNATURE_ALGORITHM_OFFSET],
            QUALIFIED_ALGORITHM_RSA_PKCS1_SHA384
        );
        assert_eq!(
            &success[QUALIFIED_SIGNATURE_REPLY_HEADER_LENGTH..],
            &SYNTHETIC_QUALIFIED_SIGNATURE
        );
        assert_eq!(
            encode_qualified_signature_reply(Err(QualifiedSignFailure::CardUnavailable)),
            vec![QUALIFIED_SIGNATURE_CARD_UNAVAILABLE]
        );
    }

    #[test]
    fn a_wrong_pin_reply_carries_the_remaining_attempts() {
        const SYNTHETIC_RETRIES_LEFT: u8 = 2;
        assert_eq!(
            encode_authentication_signature_reply(Err(AuthenticationSignFailure::WrongPin {
                retries_left: SYNTHETIC_RETRIES_LEFT,
            })),
            vec![AUTHENTICATION_SIGNATURE_WRONG_PIN, SYNTHETIC_RETRIES_LEFT]
        );
        assert_eq!(
            encode_qualified_signature_reply(Err(QualifiedSignFailure::WrongPin {
                retries_left: SYNTHETIC_RETRIES_LEFT,
            })),
            vec![QUALIFIED_SIGNATURE_WRONG_PIN, SYNTHETIC_RETRIES_LEFT]
        );
    }

    #[test]
    fn decodes_only_valid_management_channel_wire_combinations() {
        use super::{
            CardExchangeLevel, ContactlessChannel, ManagementChannel, OwnedSecret,
            management_channel_from_wire,
        };
        const SYNTHETIC_CAN: &[u8] = b"aaaaaa";
        const NEGATIVE_CHANNEL_MODE: i32 = -1;
        const UNASSIGNED_CHANNEL_MODE: i32 =
            card_management::CHANNEL_MODE_CONTACTLESS_HELD_SESSION + 1;

        assert!(matches!(
            management_channel_from_wire(card_management::CHANNEL_MODE_WIRED_APDU, None),
            Some(ManagementChannel::Wired(CardExchangeLevel::Apdu))
        ));
        assert!(matches!(
            management_channel_from_wire(card_management::CHANNEL_MODE_WIRED_T0_TPDU, None),
            Some(ManagementChannel::Wired(CardExchangeLevel::T0Tpdu))
        ));
        assert!(matches!(
            management_channel_from_wire(
                card_management::CHANNEL_MODE_CONTACTLESS_PACE,
                Some(OwnedSecret(SYNTHETIC_CAN.to_vec())),
            ),
            Some(ManagementChannel::Contactless(ContactlessChannel::Pace(ref bytes)))
                if bytes.as_slice() == SYNTHETIC_CAN
        ));
        assert!(matches!(
            management_channel_from_wire(
                card_management::CHANNEL_MODE_CONTACTLESS_HELD_SESSION,
                None,
            ),
            Some(ManagementChannel::Contactless(
                ContactlessChannel::HeldSession
            ))
        ));

        // Missing CAN for PACE, unexpected CAN for non-PACE modes, and unknown wire modes fail.
        assert!(
            management_channel_from_wire(card_management::CHANNEL_MODE_CONTACTLESS_PACE, None)
                .is_none()
        );
        for non_pace_mode in [
            card_management::CHANNEL_MODE_WIRED_APDU,
            card_management::CHANNEL_MODE_WIRED_T0_TPDU,
            card_management::CHANNEL_MODE_CONTACTLESS_HELD_SESSION,
        ] {
            assert!(
                management_channel_from_wire(
                    non_pace_mode,
                    Some(OwnedSecret(SYNTHETIC_CAN.to_vec())),
                )
                .is_none()
            );
        }
        for invalid_mode in [
            NEGATIVE_CHANNEL_MODE,
            UNASSIGNED_CHANNEL_MODE,
            i32::MIN,
            i32::MAX,
        ] {
            assert!(management_channel_from_wire(invalid_mode, None).is_none());
            assert!(
                management_channel_from_wire(
                    invalid_mode,
                    Some(OwnedSecret(SYNTHETIC_CAN.to_vec())),
                )
                .is_none()
            );
        }
    }
}
