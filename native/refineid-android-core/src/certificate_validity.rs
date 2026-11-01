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
//! FINEID S4-1 section 4.6). The core decides the scheme; this module only
//! reads the date. A certificate whose validity start cannot be read
//! answers nothing.

use refineid_ber::{BerTlvAny, BerTlvIter};

/// ASN.1 SEQUENCE (ITU-T X.690 section 8.9).
const TAG_SEQUENCE: u16 = 0x30;
/// ASN.1 UTCTime (X.690 section 11.8): `YYMMDDHHMMSSZ`.
const TAG_UTC_TIME: u16 = 0x17;
/// ASN.1 GeneralizedTime (X.690 section 11.7): `YYYYMMDDHHMMSSZ`.
const TAG_GENERALIZED_TIME: u16 = 0x18;
/// The explicit `[0]` wrapping the optional TBSCertificate version
/// (RFC 5280 section 4.1).
const TAG_VERSION_EXPLICIT: u16 = 0xA0;

/// Digits of a UTCTime up to and including the seconds.
const UTC_TIME_DIGITS: usize = 12;
/// Digits of a GeneralizedTime up to and including the seconds.
const GENERALIZED_TIME_DIGITS: usize = 14;
/// The trailing `Z` of a time in DER.
const TIME_ZULU: u8 = b'Z';
/// Two-digit years below this belong to the twenty-first century
/// (X.690 section 11.8 via RFC 5280 section 4.1.2.5.1).
const UTC_TIME_CENTURY_PIVOT: i64 = 50;
const NINETEENTH_HUNDREDS: i64 = 1900;
const TWENTIETH_HUNDREDS: i64 = 2000;
const DECIMAL_RADIX: i64 = 10;

const MONTHS_PER_YEAR: i64 = 12;
const HOURS_PER_DAY: i64 = 24;
const MINUTES_PER_HOUR: i64 = 60;
const SECONDS_PER_MINUTE: i64 = 60;
const SECONDS_PER_DAY: i64 = HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE;
/// Days from 0000-03-01 to 1970-01-01 in the proleptic Gregorian
/// calendar, the offset of the civil-day algorithm below.
const DAYS_TO_UNIX_EPOCH: i64 = 719_468;
const DAYS_PER_400_YEARS: i64 = 146_097;
const YEARS_PER_ERA: i64 = 400;
const MONTHS_BEFORE_MARCH: i64 = 2;
const MONTHS_FROM_MARCH_TO_YEAR_END: i64 = 9;
/// The multiplier and offsets of the day-of-year from the month, counting
/// from March (`(153 * m + 2) / 5`).
const DAY_OF_YEAR_MONTH_FACTOR: i64 = 153;
const DAY_OF_YEAR_MONTH_OFFSET: i64 = 2;
const DAY_OF_YEAR_MONTH_DIVISOR: i64 = 5;
const DAYS_PER_YEAR: i64 = 365;
const LEAP_CYCLE_YEARS: i64 = 4;
const CENTURY_YEARS: i64 = 100;
const MIN_MONTH: i64 = 1;
const MIN_DAY: i64 = 1;
const MAX_DAY: i64 = 31;
const MAX_HOUR: i64 = 23;
const MAX_MINUTE: i64 = 59;
const MAX_SECOND: i64 = 59;

/// The notBefore of `certificate_der` in UTC epoch seconds, or nothing
/// when the certificate or its validity cannot be read.
#[must_use]
pub(crate) fn validity_start_epoch_seconds(certificate_der: &[u8]) -> Option<i64> {
    let certificate = sequence(certificate_der)?;
    let tbs = sequence(certificate.value())?;
    let mut fields = BerTlvIter::new(tbs.value());
    let mut field = next_field(&mut fields)?;
    if field.tag() == TAG_VERSION_EXPLICIT {
        field = next_field(&mut fields)?; // serialNumber
    }
    let _serial_number = field;
    let _signature_algorithm = next_field(&mut fields)?;
    let issuer = next_field(&mut fields)?;
    if issuer.tag() != TAG_SEQUENCE {
        return None;
    }
    let validity = next_field(&mut fields)?;
    if validity.tag() != TAG_SEQUENCE {
        return None;
    }
    let not_before = BerTlvIter::new(validity.value()).next()?.ok()?;
    time_epoch_seconds(&not_before)
}

fn sequence(bytes: &[u8]) -> Option<BerTlvAny<'_>> {
    let tlv = BerTlvAny::parse(bytes).ok()?;
    (tlv.tag() == TAG_SEQUENCE).then_some(tlv)
}

fn next_field<'a>(fields: &mut BerTlvIter<'a>) -> Option<BerTlvAny<'a>> {
    fields.next()?.ok()
}

/// The UTC epoch seconds of a DER UTCTime or GeneralizedTime, or nothing
/// for any other shape.
fn time_epoch_seconds(time: &BerTlvAny<'_>) -> Option<i64> {
    let text = time.value();
    let (digits, year): (&[u8], i64) = match time.tag() {
        TAG_UTC_TIME => {
            let digits = time_digits(text, UTC_TIME_DIGITS)?;
            let two_digit_year = decimal(&digits[..2])?;
            let century = if two_digit_year < UTC_TIME_CENTURY_PIVOT {
                TWENTIETH_HUNDREDS
            } else {
                NINETEENTH_HUNDREDS
            };
            (&digits[2..], century + two_digit_year)
        }
        TAG_GENERALIZED_TIME => {
            let digits = time_digits(text, GENERALIZED_TIME_DIGITS)?;
            (&digits[4..], decimal(&digits[..4])?)
        }
        _ => return None,
    };
    let month = decimal(&digits[..2])?;
    let day = decimal(&digits[2..4])?;
    let hour = decimal(&digits[4..6])?;
    let minute = decimal(&digits[6..8])?;
    let second = decimal(&digits[8..10])?;
    if !(MIN_MONTH..=MONTHS_PER_YEAR).contains(&month)
        || !(MIN_DAY..=MAX_DAY).contains(&day)
        || hour > MAX_HOUR
        || minute > MAX_MINUTE
        || second > MAX_SECOND
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(
        days * SECONDS_PER_DAY
            + hour * MINUTES_PER_HOUR * SECONDS_PER_MINUTE
            + minute * SECONDS_PER_MINUTE
            + second,
    )
}

/// The digits of a DER time of `digit_count` digits followed by `Z`.
fn time_digits(text: &[u8], digit_count: usize) -> Option<&[u8]> {
    let (digits, zulu) = text.split_at_checked(digit_count)?;
    if zulu != [TIME_ZULU] || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(digits)
}

fn decimal(digits: &[u8]) -> Option<i64> {
    digits.iter().try_fold(0_i64, |value, digit| {
        let digit = i64::from(digit.checked_sub(b'0')?);
        value.checked_mul(DECIMAL_RADIX)?.checked_add(digit)
    })
}

/// Days since 1970-01-01 of a proleptic Gregorian civil date, after
/// Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= MONTHS_BEFORE_MARCH {
        year - 1
    } else {
        year
    };
    let era = year.div_euclid(YEARS_PER_ERA);
    let year_of_era = year - era * YEARS_PER_ERA;
    let month_from_march = if month > MONTHS_BEFORE_MARCH {
        month - MONTHS_BEFORE_MARCH - 1
    } else {
        month + MONTHS_FROM_MARCH_TO_YEAR_END
    };
    let day_of_year = (DAY_OF_YEAR_MONTH_FACTOR * month_from_march + DAY_OF_YEAR_MONTH_OFFSET)
        / DAY_OF_YEAR_MONTH_DIVISOR
        + day
        - 1;
    let day_of_era = year_of_era * DAYS_PER_YEAR + year_of_era / LEAP_CYCLE_YEARS
        - year_of_era / CENTURY_YEARS
        + day_of_year;
    era * DAYS_PER_400_YEARS + day_of_era - DAYS_TO_UNIX_EPOCH
}

#[cfg(test)]
mod tests {
    use refineid_ber::{BerEncoder, tlv};

    use super::{
        SECONDS_PER_DAY, TAG_GENERALIZED_TIME, TAG_SEQUENCE, TAG_UTC_TIME, TAG_VERSION_EXPLICIT,
        days_from_civil, validity_start_epoch_seconds,
    };

    /// ASN.1 tags used only to build fixtures (X.690).
    const TAG_INTEGER: u8 = 0x02;
    const TAG_NULL: u8 = 0x05;
    const TAG_OID: u8 = 0x06;
    const TAG_PRINTABLE_STRING: u8 = 0x13;
    const TAG_SET: u8 = 0x31;
    /// `id-at-commonName`, OID 2.5.4.3 (RFC 5280 appendix A).
    const OID_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];
    /// TBSCertificate version v3, encoded as 2 (RFC 5280 section 4.1.2.1).
    const VERSION_V3: u8 = 2;
    /// A synthetic serial number.
    const SERIAL_NUMBER: u8 = 1;
    /// Room for one RDN attribute and for a validity pair.
    const FIXTURE_CAPACITY: usize = 64;
    /// Days from 1970-01-01 to 2000-01-01: thirty years, seven of them leap.
    const DAYS_1970_TO_2000: i64 = 30 * 365 + 7;
    /// 13 January 2026 00:00:00 UTC.
    const CUTOVER_EPOCH_SECONDS: i64 = 1_768_262_400;
    const ONE_SECOND: i64 = 1;

    /// A synthetic issuer name, not DVV's.
    const ISSUER: &str = "Test Certificates - G0";

    /// UTCTime and GeneralizedTime values around 13 January 2026 00:00:00 UTC.
    const BEFORE_CUTOVER: &[u8] = b"260112235959Z";
    const AT_CUTOVER: &[u8] = b"260113000000Z";
    const AT_CUTOVER_GENERALIZED: &[u8] = b"20260113000000Z";
    const MALFORMED_TIME: &[u8] = b"2601AB000000Z";
    const MISSING_ZULU: &[u8] = b"260113000000";

    fn tag8(tag: u16) -> u8 {
        u8::try_from(tag).expect("single-byte tag")
    }

    fn certificate(not_before_tag: u8, not_before: &[u8]) -> Vec<u8> {
        let version = tlv(
            tag8(TAG_VERSION_EXPLICIT),
            tlv(TAG_INTEGER, [VERSION_V3]).expect("integer"),
        )
        .expect("version");
        let serial = tlv(TAG_INTEGER, [SERIAL_NUMBER]).expect("serial");
        let algorithm = tlv(tag8(TAG_SEQUENCE), tlv(TAG_NULL, []).expect("null")).expect("alg");
        let attribute = {
            let mut encoder = BerEncoder::with_capacity(FIXTURE_CAPACITY);
            encoder.push_tlv(TAG_OID, OID_COMMON_NAME).expect("oid");
            encoder
                .push_tlv(TAG_PRINTABLE_STRING, ISSUER.as_bytes())
                .expect("cn");
            tlv(tag8(TAG_SEQUENCE), encoder.finish()).expect("attribute")
        };
        let rdn = tlv(TAG_SET, attribute).expect("rdn");
        let issuer = tlv(tag8(TAG_SEQUENCE), rdn).expect("issuer");
        let validity = {
            let mut encoder = BerEncoder::with_capacity(FIXTURE_CAPACITY);
            encoder
                .push_tlv(not_before_tag, not_before)
                .expect("notBefore");
            encoder
                .push_tlv(not_before_tag, not_before)
                .expect("notAfter");
            tlv(tag8(TAG_SEQUENCE), encoder.finish()).expect("validity")
        };
        let tbs = [version, serial, algorithm, issuer, validity].concat();
        let tbs = tlv(tag8(TAG_SEQUENCE), tbs).expect("tbs");
        tlv(tag8(TAG_SEQUENCE), tbs).expect("certificate")
    }

    #[test]
    fn the_validity_start_is_read_from_either_time_form() {
        assert_eq!(
            validity_start_epoch_seconds(&certificate(tag8(TAG_UTC_TIME), AT_CUTOVER)),
            Some(CUTOVER_EPOCH_SECONDS)
        );
        assert_eq!(
            validity_start_epoch_seconds(&certificate(tag8(TAG_UTC_TIME), BEFORE_CUTOVER)),
            Some(CUTOVER_EPOCH_SECONDS - ONE_SECOND)
        );
        assert_eq!(
            validity_start_epoch_seconds(&certificate(
                tag8(TAG_GENERALIZED_TIME),
                AT_CUTOVER_GENERALIZED
            )),
            Some(CUTOVER_EPOCH_SECONDS)
        );
    }

    #[test]
    fn an_unreadable_validity_start_answers_nothing() {
        for time in [MALFORMED_TIME, MISSING_ZULU] {
            assert_eq!(
                validity_start_epoch_seconds(&certificate(tag8(TAG_UTC_TIME), time)),
                None
            );
        }
        assert_eq!(
            validity_start_epoch_seconds(&certificate(tag8(TAG_SEQUENCE), AT_CUTOVER)),
            None
        );
    }

    #[test]
    fn malformed_and_truncated_certificates_answer_nothing() {
        let whole = certificate(tag8(TAG_UTC_TIME), AT_CUTOVER);
        assert_eq!(validity_start_epoch_seconds(&[]), None);
        assert_eq!(
            validity_start_epoch_seconds(&whole[..whole.len() / 2]),
            None
        );
        assert_eq!(validity_start_epoch_seconds(&whole[1..]), None);
    }

    #[test]
    fn the_civil_day_count_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), DAYS_1970_TO_2000);
        assert_eq!(
            days_from_civil(2026, 1, 13) * SECONDS_PER_DAY,
            CUTOVER_EPOCH_SECONDS
        );
    }
}
