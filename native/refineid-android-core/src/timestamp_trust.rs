// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
// https://www.apache.org/licenses/LICENSE-2.0
//! Android shell for ETSI TS 119 612 time-stamping anchors from signed EU lists.
//! Missing or stale national lists yield no anchors. The LOTL must be fresh and
//! verified under the core's Commission list-signing identities. Service status
//! history is interpreted by the core; timestamp responses provide no trust.

use jni::objects::{JByteArray, JClass, JObject, JValue};
use jni::sys::{jint, jlong};
use jni::{Env, NativeMethod, jni_sig, jni_str};
use refineid_cms::x509::DateTime;
use refineid_doc_sign::verification::trust::{AnchorRole, TrustAnchor, TrustAnchors};
use refineid_doc_sign::verification::trusted_list::{
    LOTL_LOCATION, MAX_LIST_BYTES, ServiceType, TrustedLists, lotl_signers,
};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAXIMUM_CACHE_AGE_SECONDS: u64 = 3_600;
const MAXIMUM_ANCHORS: usize = 1_024;
const MAXIMUM_CERTIFICATE_BYTES: usize = 65_536;
const MAXIMUM_ANCHOR_REPLY_BYTES: usize = 16_777_216;
const WORD_BYTES: usize = size_of::<u32>();
const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;

static CACHE: Mutex<Option<CachedAnchors>> = Mutex::new(None);

const _: NativeMethod = jni::native_method! {
    java_type = "fi.refineid.android.network.NativeTimestampTrust",
    static extern fn timestamp_anchors_native(
        generated_at: jlong,
        nanoseconds: jint,
        callback: JObject,
    ) -> [jbyte],
};

#[derive(Clone)]
struct CachedAnchors {
    anchors: TrustAnchors,
    fetched_at: DateTime,
    valid_until: DateTime,
}

impl CachedAnchors {
    fn fresh_at(&self, now: DateTime) -> bool {
        self.fetched_at <= now && now < self.valid_until
    }
}

fn timestamp_anchors_native<'local>(
    env: &mut Env<'local>,
    _class: JClass<'local>,
    generated_at: jlong,
    nanoseconds: jint,
    callback: JObject<'local>,
) -> Result<JByteArray<'local>, jni::errors::Error> {
    let reply = timestamp_anchors(env, &callback, generated_at, nanoseconds).unwrap_or_default();
    env.byte_array_from_slice(&reply)
}

fn timestamp_anchors(
    env: &mut Env<'_>,
    callback: &JObject<'_>,
    generated_at: i64,
    nanoseconds: i32,
) -> Option<Vec<u8>> {
    let seconds = u64::try_from(generated_at).ok()?;
    epoch_time(seconds)?;
    let nanoseconds = u32::try_from(nanoseconds).ok()?;
    if nanoseconds >= NANOSECONDS_PER_SECOND {
        return None;
    }
    let generated_at = Duration::new(seconds, nanoseconds);
    let now =
        DateTime::from_unix_duration(SystemTime::now().duration_since(UNIX_EPOCH).ok()?).ok()?;
    let existing = {
        let cached = CACHE.lock().ok()?;
        if cached.as_ref().is_some_and(|cache| now < cache.fetched_at) {
            return None;
        }
        cached.as_ref().filter(|cache| cache.fresh_at(now)).cloned()
    };
    let cache = match existing {
        Some(cache) => cache,
        None => {
            let lotl = fetch(env, callback, LOTL_LOCATION)?;
            let cache = load_anchors(lotl, now, |address| fetch(env, callback, address))?;
            *CACHE.lock().ok()? = Some(cache.clone());
            cache
        }
    };
    let completed_at =
        DateTime::from_unix_duration(SystemTime::now().duration_since(UNIX_EPOCH).ok()?).ok()?;
    if !cache.fresh_at(completed_at) {
        return None;
    }
    encode_anchors(&cache.anchors, generated_at)
}

fn load_anchors(
    lotl: Vec<u8>,
    now: DateTime,
    mut fetch: impl FnMut(&str) -> Option<Vec<u8>>,
) -> Option<CachedAnchors> {
    let (lists, _) =
        TrustedLists::read(lotl, &lotl_signers(), |uri| fetch(&uri.to_string()), now).ok()?;
    if lists.list_of_the_lists().is_stale(now) || lists.list_of_the_lists().issued_at() > now {
        return None;
    }
    let horizon = now
        .unix_duration()
        .as_secs()
        .checked_add(MAXIMUM_CACHE_AGE_SECONDS)?;
    let mut valid_until = epoch_time(horizon)?;
    if let Some(next) = lists.list_of_the_lists().next_update() {
        valid_until = valid_until.min(next);
    }
    let mut anchors = Vec::new();
    for national in lists.national() {
        let Ok(list) = national.outcome() else {
            continue;
        };
        if list.is_stale(now) || list.issued_at() > now {
            continue;
        }
        let mut included = false;
        for service in list.services() {
            if service.service_type() != &ServiceType::QualifiedTimeStamps {
                continue;
            }
            let periods = service.granted_periods();
            for certificate in service.certificates() {
                if let Ok(anchor) = TrustAnchor::new(
                    certificate.clone(),
                    AnchorRole::TimeStamping,
                    periods.clone(),
                ) {
                    anchors.push(anchor);
                    included = true;
                }
            }
        }
        if included && let Some(next) = list.next_update() {
            valid_until = valid_until.min(next);
        }
    }
    if anchors.is_empty() || valid_until <= now {
        return None;
    }
    Some(CachedAnchors {
        anchors: TrustAnchors::new(anchors),
        fetched_at: now,
        valid_until,
    })
}

fn epoch_time(seconds: u64) -> Option<DateTime> {
    DateTime::from_unix_duration(Duration::from_secs(seconds)).ok()
}

fn encode_anchors(anchors: &TrustAnchors, at: Duration) -> Option<Vec<u8>> {
    let mut certificates = Vec::new();
    for anchor in anchors.anchors() {
        let cert = anchor.certificate();
        if anchor.role() == AnchorRole::TimeStamping
            && anchor.granted().iter().any(|period| {
                period.from().unix_duration() <= at
                    && period.to().is_none_or(|until| at <= until.unix_duration())
            })
        {
            let encoded = cert.as_der();
            if encoded.is_empty() || encoded.len() > MAXIMUM_CERTIFICATE_BYTES {
                return None;
            }
            if !certificates.contains(&encoded) {
                certificates.push(encoded);
                if certificates.len() > MAXIMUM_ANCHORS {
                    return None;
                }
            }
        }
    }
    let mut reply = u32::try_from(certificates.len())
        .ok()?
        .to_be_bytes()
        .to_vec();
    for certificate in certificates {
        if reply
            .len()
            .checked_add(WORD_BYTES)?
            .checked_add(certificate.len())?
            > MAXIMUM_ANCHOR_REPLY_BYTES
        {
            return None;
        }
        reply.extend_from_slice(&u32::try_from(certificate.len()).ok()?.to_be_bytes());
        reply.extend_from_slice(certificate);
    }
    Some(reply)
}

fn fetch(env: &mut Env<'_>, callback: &JObject<'_>, address: &str) -> Option<Vec<u8>> {
    let input = env.new_string(address).ok()?;
    let result = env.call_method(
        callback,
        jni_str!("get"),
        jni_sig!((JString) -> [jbyte]),
        &[JValue::Object(input.as_ref())],
    );
    env.delete_local_ref(input);
    let object = result.ok()?.l().ok()?;
    if object.is_null() {
        return None;
    }
    let array = JByteArray::cast_local(env, object).ok()?;
    let length = array.len(env).ok()?;
    let result = if length > MAX_LIST_BYTES {
        None
    } else {
        env.convert_byte_array(&array).ok()
    };
    env.delete_local_ref(array);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use refineid_cms::testkit::{CertificateSpec, TestKey, certificate};
    use refineid_cms::x509::OwnedCert;
    use refineid_doc_sign::verification::trust::GrantedPeriod;

    const GRANTED_AT: u64 = 1_767_225_600;
    const WITHDRAWN_AT: u64 = GRANTED_AT + MAXIMUM_CACHE_AGE_SECONDS;
    const BEFORE_GRANT: u64 = GRANTED_AT - ONE_SECOND;
    const AFTER_WITHDRAWAL: u64 = WITHDRAWN_AT + ONE_SECOND;
    const ONE_SECOND: u64 = 1;
    const SYNTHETIC_SERIAL: u8 = 1;
    const EXPECTED_CERTIFICATE_COUNT: u32 = 1;
    const NO_CERTIFICATES: u32 = 0;
    const SYNTHETIC_NAME: &str = "Synthetic timestamp authority";

    fn time(seconds: u64) -> DateTime {
        epoch_time(seconds).expect("synthetic time is representable")
    }

    fn synthetic_certificate() -> OwnedCert {
        let key = TestKey::rsa_2048();
        let spec = CertificateSpec {
            serial: SYNTHETIC_SERIAL,
            subject: SYNTHETIC_NAME,
            issuer: SYNTHETIC_NAME,
            not_before: time(BEFORE_GRANT),
            not_after: time(AFTER_WITHDRAWAL),
            extensions: Vec::new(),
        };
        OwnedCert::from_der(&certificate(&spec, &key, &key)).expect("synthetic certificate")
    }

    fn anchor(certificate: OwnedCert, role: AnchorRole) -> TrustAnchor {
        TrustAnchor::new(
            certificate,
            role,
            vec![
                GrantedPeriod::new(time(GRANTED_AT), Some(time(WITHDRAWN_AT)))
                    .expect("ordered period"),
            ],
        )
        .expect("nonempty period")
    }

    fn encoded_count(anchors: &TrustAnchors, seconds: u64) -> u32 {
        let encoded =
            encode_anchors(anchors, Duration::from_secs(seconds)).expect("bounded synthetic reply");
        let word: [u8; WORD_BYTES] = encoded[..WORD_BYTES].try_into().expect("count word");
        u32::from_be_bytes(word)
    }

    #[test]
    fn only_time_stamping_roles_granted_at_the_token_time_are_exported() {
        let certificate = synthetic_certificate();
        let issuer = TrustAnchors::new(vec![anchor(
            certificate.clone(),
            AnchorRole::CertificateIssuing,
        )]);
        assert_eq!(encoded_count(&issuer, GRANTED_AT), NO_CERTIFICATES);
        let timestamp = TrustAnchors::new(vec![anchor(certificate, AnchorRole::TimeStamping)]);
        assert_eq!(encoded_count(&timestamp, BEFORE_GRANT), NO_CERTIFICATES);
        assert_eq!(
            encoded_count(&timestamp, GRANTED_AT),
            EXPECTED_CERTIFICATE_COUNT
        );
        assert_eq!(
            encoded_count(&timestamp, WITHDRAWN_AT),
            EXPECTED_CERTIFICATE_COUNT
        );
        assert_eq!(encoded_count(&timestamp, AFTER_WITHDRAWAL), NO_CERTIFICATES);
    }

    #[test]
    fn fractional_generation_time_does_not_cross_granted_period_boundaries() {
        const ONE_NANOSECOND: u64 = 1;
        let anchors = TrustAnchors::new(vec![anchor(
            synthetic_certificate(),
            AnchorRole::TimeStamping,
        )]);
        let fraction = Duration::from_nanos(ONE_NANOSECOND);
        for outside in [
            Duration::from_secs(GRANTED_AT) - fraction,
            Duration::from_secs(WITHDRAWN_AT) + fraction,
        ] {
            let encoded = encode_anchors(&anchors, outside).expect("bounded reply");
            assert_eq!(encoded, NO_CERTIFICATES.to_be_bytes());
        }
        let inside = encode_anchors(&anchors, Duration::from_secs(GRANTED_AT) + fraction)
            .expect("bounded reply");
        assert!(inside.len() > WORD_BYTES);
    }

    #[test]
    fn duplicate_services_export_one_owned_certificate() {
        let certificate = synthetic_certificate();
        let anchors = TrustAnchors::new(vec![
            anchor(certificate.clone(), AnchorRole::TimeStamping),
            anchor(certificate.clone(), AnchorRole::TimeStamping),
        ]);
        let encoded = encode_anchors(&anchors, Duration::from_secs(GRANTED_AT))
            .expect("bounded synthetic reply");
        assert_eq!(
            encoded_count(&anchors, GRANTED_AT),
            EXPECTED_CERTIFICATE_COUNT
        );
        assert_eq!(&encoded[WORD_BYTES + WORD_BYTES..], certificate.as_der());
    }

    #[test]
    fn cache_is_never_used_after_expiry_or_before_its_fetch_time() {
        let cache = CachedAnchors {
            anchors: TrustAnchors::default(),
            fetched_at: time(GRANTED_AT),
            valid_until: time(WITHDRAWN_AT),
        };
        assert!(!cache.fresh_at(time(BEFORE_GRANT)));
        assert!(cache.fresh_at(time(GRANTED_AT)));
        assert!(!cache.fresh_at(time(WITHDRAWN_AT)));
        assert!(!cache.fresh_at(time(AFTER_WITHDRAWAL)));
    }

    #[test]
    fn malformed_list_fails_before_any_national_request() {
        let cache = load_anchors(
            b"not a signed EU trusted list".to_vec(),
            time(GRANTED_AT),
            |_| panic!("unverified LOTL must never control a request"),
        );
        assert!(cache.is_none());
    }
}
