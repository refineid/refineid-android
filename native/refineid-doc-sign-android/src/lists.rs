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

//! The EU trusted lists behind a small disk cache, for verification anchors.
//!
//! The core ships no certificate-issuing or time-stamping anchors: what a
//! signature may chain to comes from the list of the lists and the Finnish
//! national list it points at, fetched over the app's HTTP transport and
//! cached under a directory the app names. LOTL plus Finland only: a phone
//! verifies FINEID documents, and the retired pins these lists replace
//! were DVV-only too. [`anchors`] returns the lists' anchors, fetching
//! when the cache is missing or due and falling back to it when the
//! network fails, so verification also judges offline. Every signature
//! is verified again on every use; the cache stores bytes, never trust.

use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::Duration;

use refineid_doc_sign::uri::Uri;
use refineid_doc_sign::verification::TrustAnchors;
use refineid_doc_sign::verification::trusted_list::{
    CachedList, LOTL_LOCATION, TrustedList, TrustedLists, fetch_over_http, lotl_signers,
};
use refineid_doc_sign::x509::DateTime;

/// Why verification has no anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListsFailure {
    /// Neither fetched nor cached lists read.
    Unavailable,
}

/// The `SchemeTerritory` of Finland's national list: the ISO 3166-1
/// alpha-2 code `ETSI TS 119 612` clause 5.3.10 names a member state's
/// list by. FINEID cards chain to the services it lists.
const FINNISH_TERRITORY: &str = "FI";
/// Refresh lists older than this even when their next update lies ahead.
const REFRESH_AFTER: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// The cached list of the lists.
const LOTL_FILE: &str = "lotl.list";
/// The cached Finnish national list.
const FINNISH_FILE: &str = "fi.list";
/// The record key of the list's location.
const KEY_LOCATION: &str = "location";
/// The record key of the fetch time.
const KEY_FETCHED_AT: &str = "fetched-at";
/// The record key of the list's next update.
const KEY_NEXT_UPDATE: &str = "next-update";
/// The separator of a record key and its value.
const KEY_SEPARATOR: &str = ": ";
/// The value of `next-update` for a closed list.
const NO_NEXT_UPDATE: &str = "-";
/// What ends the record header and starts the list's bytes.
const RECORD_END: &[u8] = b"\n\n";
/// The extension of a record being written.
const TEMPORARY_EXTENSION: &str = "tmp";
/// Owner-only file permissions.
const FILE_MODE: u32 = 0o600;

/// The lists' anchors at `now`: the cached records when fresh, else
/// fetched over the app's transport and stored. A fetch that fails
/// falls back to the cache, stale or not; verification with
/// yesterday's anchors beats no verification offline. Stored records
/// are best-effort: a cache that cannot be written is skipped, and
/// the fetched lists still anchor this run.
///
/// # Errors
/// [`ListsFailure::Unavailable`] when neither fetching nor the cache
/// yields the list of the lists and Finland's list.
pub fn anchors(cache_directory: &Path, now: DateTime) -> Result<TrustAnchors, ListsFailure> {
    let cached_lotl = read_record(&cache_directory.join(LOTL_FILE));
    let cached_finnish = read_record(&cache_directory.join(FINNISH_FILE));
    let (lotl_bytes, lotl_fetched) = lotl_bytes(cached_lotl.as_ref(), now)?;
    let finnish_url = finnish_location(&lotl_bytes).ok_or(ListsFailure::Unavailable)?;
    let (finnish_bytes, finnish_fetched) =
        finnish_bytes(cached_finnish.as_ref(), &finnish_url, now)?;
    let (lists, records) = TrustedLists::read(
        lotl_bytes,
        &lotl_signers(),
        |url| (url == &finnish_url).then(|| finnish_bytes.clone()),
        now,
    )
    .map_err(|_error| ListsFailure::Unavailable)?;
    if !finnish_outcome_ok(&lists) {
        return Err(ListsFailure::Unavailable);
    }
    for record in &records {
        let fetched = (lotl_fetched && record.location().to_string() == LOTL_LOCATION)
            || (finnish_fetched && record.location() == &finnish_url);
        if fetched {
            let name = if record.location().to_string() == LOTL_LOCATION {
                LOTL_FILE
            } else {
                FINNISH_FILE
            };
            let _stored = store(cache_directory, name, record);
        }
    }
    Ok(TrustAnchors::from_trusted_lists(&lists))
}

/// The list of the lists' bytes and whether they were fetched: the
/// cache when fresh, else the network, else the stale cache.
fn lotl_bytes(cached: Option<&CachedList>, now: DateTime) -> Result<(Vec<u8>, bool), ListsFailure> {
    if let Some(record) = cached.filter(|record| is_fresh(record, now)) {
        return Ok((record.bytes().to_vec(), false));
    }
    if let Some(fetched) = fetch_lotl() {
        return Ok((fetched, true));
    }
    cached
        .map(|record| (record.bytes().to_vec(), false))
        .ok_or(ListsFailure::Unavailable)
}

/// Finland's list's bytes at `url` and whether they were fetched: the
/// cache when fresh and still published there, else the network, else
/// the stale cache published there.
fn finnish_bytes(
    cached: Option<&CachedList>,
    url: &Uri,
    now: DateTime,
) -> Result<(Vec<u8>, bool), ListsFailure> {
    if let Some(record) = cached.filter(|record| record.location() == url && is_fresh(record, now))
    {
        return Ok((record.bytes().to_vec(), false));
    }
    if let Some(fetched) = fetch_over_http(url) {
        return Ok((fetched, true));
    }
    cached
        .filter(|record| record.location() == url)
        .map(|record| (record.bytes().to_vec(), false))
        .ok_or(ListsFailure::Unavailable)
}

/// The list of the lists over the app's transport, if it arrives.
fn fetch_lotl() -> Option<Vec<u8>> {
    let url = Uri::parse(LOTL_LOCATION.to_owned()).ok()?;
    fetch_over_http(&url)
}

/// The URL of Finland's national list in the list of the lists.
fn finnish_location(lotl: &[u8]) -> Option<Uri> {
    let parsed = TrustedList::read(lotl.to_vec(), &lotl_signers()).ok()?;
    parsed
        .pointers()
        .iter()
        .filter(|pointer| pointer.territory() == FINNISH_TERRITORY && pointer.names_national_list())
        .find_map(|pointer| pointer.location().cloned())
}

/// Whether Finland's list read in `lists`.
fn finnish_outcome_ok(lists: &TrustedLists) -> bool {
    lists
        .national()
        .iter()
        .any(|list| list.territory() == FINNISH_TERRITORY && list.outcome().is_ok())
}

/// Whether `record` is young enough and ahead of its next update. A
/// record from the future is not fresh: the clock moved, not the list.
fn is_fresh(record: &CachedList, now: DateTime) -> bool {
    let age = now
        .unix_duration()
        .saturating_sub(record.fetched_at().unix_duration());
    if record.fetched_at().unix_duration() > now.unix_duration() || age >= REFRESH_AFTER {
        return false;
    }
    record
        .next_update()
        .is_none_or(|due| now.unix_duration() < due.unix_duration())
}

/// The stored form of `record`: `key: value` lines, one blank line,
/// then the list's bytes as fetched.
fn encode(record: &CachedList) -> Vec<u8> {
    let next_update = record
        .next_update()
        .map_or_else(|| NO_NEXT_UPDATE.to_owned(), |due| due.to_string());
    let mut out = String::new();
    for (key, value) in [
        (KEY_LOCATION, record.location().to_string()),
        (KEY_FETCHED_AT, record.fetched_at().to_string()),
        (KEY_NEXT_UPDATE, next_update),
    ] {
        out.push_str(key);
        out.push_str(KEY_SEPARATOR);
        out.push_str(&value);
        out.push('\n');
    }
    out.push('\n');
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(record.bytes());
    bytes
}

/// The record `bytes` store, if they read.
fn decode(bytes: &[u8]) -> Option<CachedList> {
    let end = bytes
        .windows(RECORD_END.len())
        .position(|window| window == RECORD_END)?;
    let (head, rest) = bytes.split_at(end);
    let list = rest.get(RECORD_END.len()..)?.to_vec();
    let head = core::str::from_utf8(head).ok()?;
    let mut lines = head.lines().map(|line| line.split_once(KEY_SEPARATOR));
    let mut value = |key: &str| match lines.next() {
        Some(Some((found, value))) if found == key => Some(value),
        _ => None,
    };
    let location = Uri::parse(value(KEY_LOCATION)?.to_owned()).ok()?;
    let fetched_at = value(KEY_FETCHED_AT)?.parse().ok()?;
    let next_update = match value(KEY_NEXT_UPDATE)? {
        NO_NEXT_UPDATE => None,
        due => Some(due.parse().ok()?),
    };
    if lines.next().is_some() {
        return None;
    }
    Some(CachedList::new(location, fetched_at, next_update, list))
}

fn read_record(path: &Path) -> Option<CachedList> {
    decode(&std::fs::read(path).ok()?)
}

/// Store `record` under `name` in `directory`: owner-only, atomic.
fn store(directory: &Path, name: &str, record: &CachedList) -> std::io::Result<()> {
    std::fs::create_dir_all(directory)?;
    let path = directory.join(name);
    let temporary = path.with_extension(format!("{TEMPORARY_EXTENSION}.{}", std::process::id()));
    let written = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(FILE_MODE).create(true).truncate(true);
        let mut file: File = options.open(&temporary)?;
        use std::io::Write as _;
        file.write_all(&encode(record))?;
        file.flush()?;
        Ok::<(), std::io::Error>(())
    })();
    match written {
        Ok(()) => match std::fs::rename(&temporary, &path) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _removed = std::fs::remove_file(&temporary);
                Err(error)
            }
        },
        Err(error) => {
            let _removed = std::fs::remove_file(&temporary);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LOTL_LOCATION, decode, encode, is_fresh};
    use refineid_doc_sign::uri::Uri;
    use refineid_doc_sign::verification::trusted_list::CachedList;
    use refineid_doc_sign::x509::DateTime;

    /// A record round-trips through its stored form.
    #[test]
    fn a_record_survives_its_stored_form() {
        let now = refineid_doc_sign::now_date_time();
        let record = CachedList::new(
            Uri::parse(LOTL_LOCATION.to_owned()).expect("a URL"),
            now,
            None,
            b"<TrustServiceStatusList/>".to_vec(),
        );
        let back = decode(&encode(&record)).expect("a record");
        assert_eq!(back.location(), record.location());
        assert_eq!(back.fetched_at(), record.fetched_at());
        assert_eq!(back.next_update(), record.next_update());
        assert_eq!(back.bytes(), record.bytes());
    }

    /// Garbage, truncated headers and short headers read as nothing.
    #[test]
    fn malformed_records_read_as_nothing() {
        assert!(decode(b"not a record").is_none());
        assert!(decode(b"location: https://example.invalid/list.xml\n\n").is_none());
        let now = refineid_doc_sign::now_date_time();
        let record = CachedList::new(
            Uri::parse(LOTL_LOCATION.to_owned()).expect("a URL"),
            now,
            Some(now),
            Vec::new(),
        );
        let mut stored = encode(&record);
        stored.truncate(stored.len() / 2);
        assert!(decode(&stored).is_none());
    }

    /// Fresh means young and ahead of its next update.
    #[test]
    fn freshness_follows_age_and_next_update() {
        let now = refineid_doc_sign::now_date_time();
        let location = Uri::parse(LOTL_LOCATION.to_owned()).expect("a URL");
        let fresh = CachedList::new(location.clone(), now, None, Vec::new());
        assert!(is_fresh(&fresh, now));
        let past_due = CachedList::new(location.clone(), now, Some(now), Vec::new());
        assert!(!is_fresh(&past_due, now));
        let old = CachedList::new(
            location,
            DateTime::from_unix_duration(now.unix_duration().saturating_sub(super::REFRESH_AFTER))
                .expect("a time"),
            None,
            Vec::new(),
        );
        assert!(!is_fresh(&old, now));
    }
}
