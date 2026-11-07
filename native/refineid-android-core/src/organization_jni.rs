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

//! The JNI border of the organization card's contactless operations. Every
//! secret is cleared from its Java array here and owned by the operation; the
//! replies reuse the established vocabularies.

use jni::objects::{JByteArray, JClass, JObject};
use jni::sys::{jboolean, jint};
use jni::{Env, NativeMethod};
use refineid_auth::PinStatus;

use crate::authentication_signer::{AuthenticationSignFailure, AuthenticationSigningInput};
use crate::card_certificate::CertificateReadFailure;
use crate::card_management::{
    MANAGEMENT_TAG_BRIDGE_ERROR, encode_credential_health_reply, encode_manage_outcome_reply,
};
use crate::card_transport::{AndroidCardTransport, CardExchangeLevel, SingleBlockExchange};
use crate::contactless::{ContactlessOpenOutcome, ManagedPin};
use crate::jni_card_exchange::JniBlockExchange;
use crate::organization_card::{
    ChannelRefusal, OrganizationCredential, OrganizationOpenOutcome,
    organization_authenticate_and_sign, organization_change_pin1, organization_change_pin2,
    organization_credential_health, organization_open, organization_qualified_sign,
    organization_reset_pin, organization_verify_pin1, pin1_preflight_of, pin2_preflight_of,
    read_organization_counter,
};
use crate::pin1_status::Pin1PreflightFailure;
use crate::pin2_status::Pin2PreflightFailure;
use crate::qualified_signer::{MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH, QualifiedSigningInput};
use crate::{
    AUTHENTICATION_SIGNATURE_BRIDGE_ERROR, AUTHENTICATION_SIGNATURE_SUCCEEDED,
    AuthenticationSigningInputMode, CERTIFICATE_BRIDGE_ERROR,
    MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH, MAXIMUM_EXPECTED_CERTIFICATE_LENGTH,
    PIN1_PREFLIGHT_BRIDGE_ERROR, PIN2_PREFLIGHT_BRIDGE_ERROR, QUALIFIED_SIGNATURE_BRIDGE_ERROR,
    QualifiedSigningInputMode, SHA384_DIGEST_LENGTH, authentication_request_from_jint,
    encode_authentication_signature_reply, encode_certificate_reply, encode_contactless_open_reply,
    encode_pin1_preflight_reply, encode_pin2_preflight_reply, encode_qualified_signature_reply,
    one_byte_reply, qualified_request_from_jint, take_secret_bytes, take_secret_pair,
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_pin1_counter_native(callback: JObject) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_pin2_counter_native(callback: JObject) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_health_native(callback: JObject) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_open_native(pin: [jbyte], callback: JObject) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_verify_pin1_native(pin: [jbyte], callback: JObject) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_authenticate_and_sign_native(
        request: jint,
        pin: [jbyte],
        message: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_qualified_sign_native(
        algorithm: jint,
        pin: [jbyte],
        content: [jbyte],
        expected_certificate: [jbyte],
        read_ca_certificates: jboolean,
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_change_pin1_native(
        current_pin: [jbyte],
        new_pin: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_change_pin2_native(
        current_pin: [jbyte],
        new_pin: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_reset_pin1_native(
        puk: [jbyte],
        new_pin: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.core.NativeOrganizationCard",
    static extern fn organization_reset_pin2_native(
        puk: [jbyte],
        new_pin: [jbyte],
        callback: JObject,
    ) -> [jbyte],
};

/// A card transport over the Java callback, always at the APDU level: the
/// contactless interface carries whole commands.
fn apdu_transport<Exchange: SingleBlockExchange>(
    exchange: Exchange,
) -> AndroidCardTransport<Exchange> {
    AndroidCardTransport::new(exchange, CardExchangeLevel::Apdu)
}

fn reply<'local>(
    env: &mut Env<'local>,
    mut bytes: Vec<u8>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let java_reply = env.byte_array_from_slice(&bytes);
    bytes.fill(0);
    java_reply
}

fn organization_pin1_counter_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = apdu_transport(exchange);
        let result = read_organization_counter(&mut transport, OrganizationCredential::Pin1);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };
    let bytes = if bridge_failed {
        vec![PIN1_PREFLIGHT_BRIDGE_ERROR]
    } else {
        encode_pin1_preflight_reply(result.map(pin1_preflight_of).map_err(pin1_counter_failure))
    };
    reply(env, bytes)
}

fn organization_pin2_counter_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let (result, bridge_failed): (Result<PinStatus, ChannelRefusal>, bool) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = apdu_transport(exchange);
        let result = read_organization_counter(&mut transport, OrganizationCredential::Pin2);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };
    let bytes = if bridge_failed {
        vec![PIN2_PREFLIGHT_BRIDGE_ERROR]
    } else {
        encode_pin2_preflight_reply(result.map(pin2_preflight_of).map_err(pin2_counter_failure))
    };
    reply(env, bytes)
}

const fn pin1_counter_failure(refusal: ChannelRefusal) -> Pin1PreflightFailure {
    match refusal {
        ChannelRefusal::CardUnavailable => Pin1PreflightFailure::CardUnavailable,
        ChannelRefusal::Bridge | ChannelRefusal::InvalidEntry => Pin1PreflightFailure::Bridge,
        ChannelRefusal::BelowFloor
        | ChannelRefusal::Blocked
        | ChannelRefusal::Wrong { .. }
        | ChannelRefusal::Rejected
        | ChannelRefusal::NotOrganizationCard
        | ChannelRefusal::Transport => Pin1PreflightFailure::Transport,
    }
}

const fn pin2_counter_failure(refusal: ChannelRefusal) -> Pin2PreflightFailure {
    match refusal {
        ChannelRefusal::CardUnavailable => Pin2PreflightFailure::CardUnavailable,
        ChannelRefusal::Bridge | ChannelRefusal::InvalidEntry => Pin2PreflightFailure::Bridge,
        ChannelRefusal::BelowFloor
        | ChannelRefusal::Blocked
        | ChannelRefusal::Wrong { .. }
        | ChannelRefusal::Rejected
        | ChannelRefusal::NotOrganizationCard
        | ChannelRefusal::Transport => Pin2PreflightFailure::Transport,
    }
}

fn organization_health_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let mut transport = apdu_transport(exchange);
        let result = organization_credential_health(&mut transport);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };
    let bytes = if bridge_failed {
        vec![MANAGEMENT_TAG_BRIDGE_ERROR]
    } else {
        encode_credential_health_reply(result)
    };
    reply(env, bytes)
}

/// The open reply: `[OPEN_ANSWERED, identity length as four big-endian bytes,
/// contactless open reply, qualified-certificate reply]`, or `[OPEN_REFUSED,
/// the authentication-failure reply]`.
pub(crate) fn encode_organization_open_reply(outcome: OrganizationOpenOutcome) -> Vec<u8> {
    let (open, qualified) = match outcome {
        OrganizationOpenOutcome::Ready {
            certificate,
            preflight,
            qualified,
        } => (
            encode_contactless_open_reply(ContactlessOpenOutcome::Ready(certificate, preflight)),
            encode_certificate_reply(qualified),
        ),
        OrganizationOpenOutcome::Unreadable(failure) => (
            encode_certificate_reply(Err(failure)),
            encode_certificate_reply(Err(CertificateReadFailure::Rejected)),
        ),
        OrganizationOpenOutcome::Refused(failure) => {
            let mut bytes = vec![OPEN_REFUSED];
            bytes.extend_from_slice(&encode_authentication_signature_reply(Err(failure)));
            return bytes;
        }
    };
    let open_length = u32::try_from(open.len()).unwrap_or(u32::MAX).to_be_bytes();
    let mut bytes = Vec::with_capacity(OPEN_REPLY_HEADER_LENGTH + open.len() + qualified.len());
    bytes.push(OPEN_ANSWERED);
    bytes.extend_from_slice(&open_length);
    bytes.extend_from_slice(&open);
    bytes.extend_from_slice(&qualified);
    bytes
}

/// The open was answered: the identity and the qualified certificate follow.
const OPEN_ANSWERED: u8 = 0;
/// The channel did not open: an authentication-failure reply follows.
const OPEN_REFUSED: u8 = 1;
/// The tag and the identity's four-byte length.
const OPEN_REPLY_HEADER_LENGTH: usize = 5;

fn organization_open_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    pin: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let pin_bytes = take_secret_bytes(env, &pin)?;
    let (outcome, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let (outcome, transport) = organization_open(apdu_transport(exchange), pin_bytes);
        let exchange = transport.into_exchange();
        (outcome, exchange.bridge_failed())
    };
    let bytes = if bridge_failed {
        vec![OPEN_REFUSED, CERTIFICATE_BRIDGE_ERROR]
    } else {
        encode_organization_open_reply(outcome)
    };
    reply(env, bytes)
}

fn organization_verify_pin1_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    pin: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let pin_bytes = take_secret_bytes(env, &pin)?;
    let (result, bridge_failed): (Result<(), AuthenticationSignFailure>, bool) = {
        let exchange = JniBlockExchange::new(env, callback);
        let (result, transport) = organization_verify_pin1(apdu_transport(exchange), pin_bytes);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };
    let bytes = if bridge_failed {
        vec![AUTHENTICATION_SIGNATURE_BRIDGE_ERROR]
    } else {
        match result {
            Ok(()) => vec![AUTHENTICATION_SIGNATURE_SUCCEEDED],
            Err(failure) => encode_authentication_signature_reply(Err(failure)),
        }
    };
    reply(env, bytes)
}

fn organization_authenticate_and_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    request: jint,
    pin: JByteArray<'local>,
    message: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let mut pin_bytes = take_secret_bytes(env, &pin)?;
    let Some((algorithm, input_mode)) = authentication_request_from_jint(request) else {
        pin_bytes.fill(0);
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    };
    let message_length = match message.len(env) {
        Ok(length) => length,
        Err(error) => {
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    if message_length > MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH {
        pin_bytes.fill(0);
        return one_byte_reply(env, AUTHENTICATION_SIGNATURE_BRIDGE_ERROR);
    }
    let mut message_bytes = match env.convert_byte_array(&message) {
        Ok(bytes) => bytes,
        Err(error) => {
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let input = match input_mode {
            AuthenticationSigningInputMode::Message => {
                AuthenticationSigningInput::Message(&message_bytes)
            }
            AuthenticationSigningInputMode::Prehashed => {
                AuthenticationSigningInput::Prehashed(&message_bytes)
            }
        };
        let (result, transport) = organization_authenticate_and_sign(
            apdu_transport(exchange),
            algorithm,
            pin_bytes,
            input,
        );
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };
    message_bytes.fill(0);
    let bytes = if bridge_failed {
        vec![AUTHENTICATION_SIGNATURE_BRIDGE_ERROR]
    } else {
        encode_authentication_signature_reply(result)
    };
    reply(env, bytes)
}

#[allow(clippy::too_many_arguments)]
fn organization_qualified_sign_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    algorithm: jint,
    pin: JByteArray<'local>,
    content: JByteArray<'local>,
    expected_certificate: JByteArray<'local>,
    read_ca_certificates: jboolean,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let mut pin_bytes = take_secret_bytes(env, &pin)?;
    let Some((algorithm, input_mode)) = qualified_request_from_jint(algorithm) else {
        pin_bytes.fill(0);
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    };
    let lengths = content.len(env).and_then(|content_length| {
        expected_certificate
            .len(env)
            .map(|certificate_length| (content_length, certificate_length))
    });
    let (content_length, certificate_length) = match lengths {
        Ok(lengths) => lengths,
        Err(error) => {
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    let content_length_accepted = match input_mode {
        QualifiedSigningInputMode::Message => {
            content_length <= MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH
        }
        QualifiedSigningInputMode::Prehashed => content_length == SHA384_DIGEST_LENGTH,
    };
    if !content_length_accepted || certificate_length > MAXIMUM_EXPECTED_CERTIFICATE_LENGTH {
        pin_bytes.fill(0);
        return one_byte_reply(env, QUALIFIED_SIGNATURE_BRIDGE_ERROR);
    }
    let arrays = env.convert_byte_array(&content).and_then(|content_bytes| {
        env.convert_byte_array(&expected_certificate)
            .map(|expected| (content_bytes, expected))
    });
    let (mut content_bytes, expected) = match arrays {
        Ok(arrays) => arrays,
        Err(error) => {
            pin_bytes.fill(0);
            return Err(error);
        }
    };
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let input = match input_mode {
            QualifiedSigningInputMode::Message => QualifiedSigningInput::Message(&content_bytes),
            QualifiedSigningInputMode::Prehashed => {
                QualifiedSigningInput::Prehashed(&content_bytes)
            }
        };
        let (result, transport) = organization_qualified_sign(
            apdu_transport(exchange),
            algorithm,
            pin_bytes,
            input,
            &expected,
            read_ca_certificates,
        );
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };
    content_bytes.fill(0);
    let bytes = if bridge_failed {
        vec![QUALIFIED_SIGNATURE_BRIDGE_ERROR]
    } else {
        encode_qualified_signature_reply(result)
    };
    reply(env, bytes)
}

/// The change of `pin` on the channel its current value opens.
fn change_reply<'local>(
    env: &mut Env<'local>,
    pin: ManagedPin,
    current_pin: JByteArray<'local>,
    new_pin: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let (current, new) = take_secret_pair(env, &current_pin, &new_pin)?;
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let (result, transport) = match pin {
            ManagedPin::Pin1 => organization_change_pin1(apdu_transport(exchange), current, new),
            ManagedPin::Pin2 => organization_change_pin2(apdu_transport(exchange), current, new),
        };
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };
    let bytes = if bridge_failed {
        vec![MANAGEMENT_TAG_BRIDGE_ERROR]
    } else {
        encode_manage_outcome_reply(result)
    };
    reply(env, bytes)
}

fn organization_change_pin1_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    current_pin: JByteArray<'local>,
    new_pin: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    change_reply(env, ManagedPin::Pin1, current_pin, new_pin, callback)
}

fn organization_change_pin2_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    current_pin: JByteArray<'local>,
    new_pin: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    change_reply(env, ManagedPin::Pin2, current_pin, new_pin, callback)
}

fn reset_reply<'local>(
    env: &mut Env<'local>,
    pin: ManagedPin,
    puk: JByteArray<'local>,
    new_pin: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let (puk_bytes, new) = take_secret_pair(env, &puk, &new_pin)?;
    let (result, bridge_failed) = {
        let exchange = JniBlockExchange::new(env, callback);
        let (result, transport) =
            organization_reset_pin(apdu_transport(exchange), pin, puk_bytes, new);
        let exchange = transport.into_exchange();
        (result, exchange.bridge_failed())
    };
    let bytes = if bridge_failed {
        vec![MANAGEMENT_TAG_BRIDGE_ERROR]
    } else {
        encode_manage_outcome_reply(result)
    };
    reply(env, bytes)
}

fn organization_reset_pin1_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    puk: JByteArray<'local>,
    new_pin: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    reset_reply(env, ManagedPin::Pin1, puk, new_pin, callback)
}

fn organization_reset_pin2_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    puk: JByteArray<'local>,
    new_pin: JByteArray<'local>,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    reset_reply(env, ManagedPin::Pin2, puk, new_pin, callback)
}
