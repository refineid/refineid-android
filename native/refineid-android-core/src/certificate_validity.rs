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

//! The validity start of the card's authentication certificate (RFC 5280
//! section 4.1.2.5), the date input of the core's activation scheme
//! decision (`ActivationScheme::from_numbering_and_validity_start`,
//! FINEID S4-1 section 4.6). The core parses the X.509 certificate under
//! strict DER and decides the scheme; this module reads `notBefore` as UTC
//! epoch seconds. A certificate whose validity start cannot be read answers
//! nothing.

use refineid_cms::x509::Certificate;

/// The notBefore of `certificate_der` in UTC epoch seconds, or nothing
/// when the certificate or its validity cannot be read.
///
/// [`Certificate::from_der`] decodes `Validity` into `der::DateTime`, which is
/// anchored at the Unix epoch (`1970-01-01T00:00:00Z`); pre-epoch dates are
/// rejected at decode time as `None` (X.509 postdates 1970).
#[must_use]
pub(crate) fn validity_start_epoch_seconds(certificate_der: &[u8]) -> Option<i64> {
    let certificate = Certificate::from_der(certificate_der).ok()?;
    i64::try_from(certificate.not_before.unix_duration().as_secs()).ok()
}

#[cfg(test)]
mod tests {
    use refineid_cms::testkit::{
        CONTEXT_0, GENERALIZED_TIME, INTEGER, SEQUENCE, TestKey, UTC_TIME, X509_VERSION_3, name,
        signed, tlv,
    };

    use super::validity_start_epoch_seconds;

    /// A synthetic positive serial number.
    const SERIAL_NUMBER: u8 = 1;
    /// BER long-form length prefix encoding one length octet (X.690 section 8.1.3.5):
    /// non-minimal when the length fits short form (`< 128`).
    const BER_NON_MINIMAL_ONE_OCTET_LENGTH_PREFIX: u8 = 0x81;
    /// 13 January 2026 00:00:00 UTC.
    const CUTOVER_EPOCH_SECONDS: i64 = 1_768_262_400;
    /// 1 January 2050 00:00:00 UTC (RFC 5280 section 4.1.2.5.2 GeneralizedTime era).
    const YEAR_2050_EPOCH_SECONDS: i64 = 2_524_608_000;
    const ONE_SECOND: i64 = 1;

    /// A synthetic distinguished name, not DVV's.
    const DISTINGUISHED_NAME: &str = "Test Certificates - G0";

    /// UTCTime and GeneralizedTime values around the cutover and RFC 5280 era boundaries.
    const BEFORE_CUTOVER: &[u8] = b"260112235959Z";
    const AT_CUTOVER: &[u8] = b"260113000000Z";
    const YEAR_2050_GENERALIZED: &[u8] = b"20500101000000Z";
    const NOT_AFTER_GENERALIZED: &[u8] = b"20600101000000Z";
    const PRE_EPOCH_UTC: &[u8] = b"550101000000Z";
    const PRE_EPOCH_GENERALIZED: &[u8] = b"19691231235959Z";
    const INVALID_CALENDAR_DAY: &[u8] = b"260231000000Z";
    const NON_LEAP_FEBRUARY_29: &[u8] = b"260229000000Z";
    const MALFORMED_TIME: &[u8] = b"2601AB000000Z";
    const MISSING_ZULU: &[u8] = b"260113000000";

    fn certificate_with_not_before_tlv(not_before_tlv: &[u8]) -> Vec<u8> {
        let key = TestKey::rsa_2048();
        let version = tlv(CONTEXT_0, tlv(INTEGER, [X509_VERSION_3]));
        let serial = tlv(INTEGER, [SERIAL_NUMBER]);
        let algorithm = key.algorithm_identifier();
        let issuer = name(DISTINGUISHED_NAME);
        let mut validity_body = not_before_tlv.to_vec();
        validity_body.extend_from_slice(&tlv(GENERALIZED_TIME, NOT_AFTER_GENERALIZED));
        let validity = tlv(SEQUENCE, validity_body);
        let subject = name(DISTINGUISHED_NAME);
        let spki = key.spki();
        let tbs = tlv(
            SEQUENCE,
            [version, serial, algorithm, issuer, validity, subject, spki].concat(),
        );
        signed(&tbs, &key)
    }

    fn certificate(not_before_tag: u8, not_before: &[u8]) -> Vec<u8> {
        certificate_with_not_before_tlv(&tlv(not_before_tag, not_before))
    }

    #[test]
    fn the_validity_start_is_read_from_either_time_form() {
        assert_eq!(
            validity_start_epoch_seconds(&certificate(UTC_TIME, AT_CUTOVER)),
            Some(CUTOVER_EPOCH_SECONDS)
        );
        assert_eq!(
            validity_start_epoch_seconds(&certificate(UTC_TIME, BEFORE_CUTOVER)),
            Some(CUTOVER_EPOCH_SECONDS - ONE_SECOND)
        );
        assert_eq!(
            validity_start_epoch_seconds(&certificate(GENERALIZED_TIME, YEAR_2050_GENERALIZED)),
            Some(YEAR_2050_EPOCH_SECONDS)
        );
    }

    #[test]
    fn pre_epoch_validity_starts_answer_nothing_without_panicking() {
        assert_eq!(
            validity_start_epoch_seconds(&certificate(UTC_TIME, PRE_EPOCH_UTC)),
            None
        );
        assert_eq!(
            validity_start_epoch_seconds(&certificate(GENERALIZED_TIME, PRE_EPOCH_GENERALIZED)),
            None
        );
    }

    #[test]
    fn impossible_calendar_dates_and_non_minimal_lengths_answer_nothing() {
        for invalid_date in [INVALID_CALENDAR_DAY, NON_LEAP_FEBRUARY_29] {
            assert_eq!(
                validity_start_epoch_seconds(&certificate(UTC_TIME, invalid_date)),
                None
            );
        }
        let non_minimal_len = u8::try_from(AT_CUTOVER.len()).expect("UTCTime length fits u8");
        let mut non_minimal_not_before = vec![
            UTC_TIME,
            BER_NON_MINIMAL_ONE_OCTET_LENGTH_PREFIX,
            non_minimal_len,
        ];
        non_minimal_not_before.extend_from_slice(AT_CUTOVER);
        assert_eq!(
            validity_start_epoch_seconds(&certificate_with_not_before_tlv(&non_minimal_not_before)),
            None
        );
    }

    #[test]
    fn an_unreadable_validity_start_answers_nothing() {
        for time in [MALFORMED_TIME, MISSING_ZULU] {
            assert_eq!(
                validity_start_epoch_seconds(&certificate(UTC_TIME, time)),
                None
            );
        }
        assert_eq!(
            validity_start_epoch_seconds(&certificate(SEQUENCE, AT_CUTOVER)),
            None
        );
    }

    #[test]
    fn malformed_and_truncated_certificates_answer_nothing() {
        let whole = certificate(UTC_TIME, AT_CUTOVER);
        assert_eq!(validity_start_epoch_seconds(&[]), None);
        assert_eq!(
            validity_start_epoch_seconds(&whole[..whole.len() / 2]),
            None
        );
        assert_eq!(validity_start_epoch_seconds(&whole[1..]), None);
    }
}
