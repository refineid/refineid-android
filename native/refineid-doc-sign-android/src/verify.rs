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

//! Verifying a signed document.
//!
//! [`verify_document`] judges every signature of a file under the EU
//! trusted lists' anchors at this clock ([`crate::lists`]), and asks
//! the responders about a signer whose file says nothing about its
//! status. The report is the core's, field for field, in the app's
//! vocabulary.

use core::fmt;

use refineid_doc_sign::verification::live::live_revocation;
use refineid_doc_sign::verification::{
    DocumentFailure, DocumentFile, DocumentReport, Revision, Revocation, SignatureOutcome,
    SignatureReport, SignatureRow, TrustAnchors, verify,
};
use refineid_doc_sign::x509::DateTime;

use crate::lists::ListsFailure;

/// Why a file yielded no report. A negative verdict is a report.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum VerifyFailure {
    /// The file could not be read.
    FileRead,
    /// Neither a PDF, a ZIP archive nor a DER structure.
    NotASignedDocument,
    /// A file of a known kind whose structure does not parse.
    Unreadable {
        /// The core's account.
        detail: String,
    },
    /// The file parses and carries no signature.
    NoSignatures,
    /// The file uses a profile the core does not implement.
    Unsupported {
        /// The core's account.
        detail: String,
    },
    /// The trusted lists could neither be fetched nor read from the
    /// cache, so nothing anchors a chain.
    AnchorsUnavailable,
}

impl fmt::Display for VerifyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for VerifyFailure {}

impl From<DocumentFailure> for VerifyFailure {
    fn from(failure: DocumentFailure) -> Self {
        match failure {
            DocumentFailure::NotASignedDocument => Self::NotASignedDocument,
            DocumentFailure::Unreadable(_) => Self::Unreadable {
                detail: failure.to_string(),
            },
            DocumentFailure::NoSignatures => Self::NoSignatures,
            DocumentFailure::UnsupportedProfile(_) => Self::Unsupported {
                detail: failure.to_string(),
            },
        }
    }
}

/// The revocation status of the signer's path.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RevocationStatus {
    /// A verified answer says good; `at` is the evidence time.
    Good {
        /// The evidence time.
        at: String,
    },
    /// A verified answer says revoked at `at`, for `reason` when the
    /// evidence gives one.
    Revoked {
        /// The revocation time.
        at: String,
        /// The `CRLReason`.
        reason: Option<String>,
    },
    /// No verified answer speaks for the validation time.
    Unavailable,
}

impl From<Revocation> for RevocationStatus {
    fn from(revocation: Revocation) -> Self {
        match revocation {
            Revocation::Good { at } => Self::Good { at: at.to_string() },
            Revocation::Revoked { at, reason } => Self::Revoked {
                at: at.to_string(),
                reason: reason.map(|reason| reason.to_string()),
            },
            Revocation::Unavailable => Self::Unavailable,
        }
    }
}

/// What the revisions after the signed one do to a PDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RevisionStatus {
    /// No byte follows the signed revision.
    WholeDocument,
    /// Later revisions only add signatures, timestamps and validation
    /// material.
    LaterRevisionsHarmless,
    /// A later revision changes what the signer saw.
    ChangedAfterSigning,
}

impl From<Revision> for RevisionStatus {
    fn from(revision: Revision) -> Self {
        match revision {
            Revision::WholeDocument => Self::WholeDocument,
            Revision::LaterRevisionsHarmless => Self::LaterRevisionsHarmless,
            Revision::ChangedAfterSigning(_) => Self::ChangedAfterSigning,
        }
    }
}

/// One judged signature's facts.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JudgedSignature {
    /// The holder the signer certificate names: its `commonName`
    /// verbatim, else its whole subject.
    pub signer: String,
    /// The holder's Finnish electronic user identifier, when the
    /// certificate carries one.
    pub identifier: Option<String>,
    /// Every covered byte digests to the stated value and no later
    /// revision changes what was signed.
    pub document_intact: bool,
    /// The signature verifies under the signer's key.
    pub signature_valid: bool,
    /// The signer chains to a certificate-issuing anchor at the
    /// validation time.
    pub chain_verified: bool,
    /// The revocation status of the path.
    pub revocation: RevocationStatus,
    /// The earliest time an anchored timestamp proves.
    pub proof_of_existence: Option<String>,
    /// The signing time the signature claims, proving nothing.
    pub claimed_signing_time: Option<String>,
    /// The signature's own timestamps.
    pub timestamps: u32,
    /// The archive timestamps.
    pub archive_timestamps: u32,
    /// What the later revisions do to the document.
    pub revision: RevisionStatus,
    /// Whether the signature is valid: intact, valid, chained, and not
    /// revoked before the proof of existence.
    pub valid: bool,
}

impl From<&SignatureReport> for JudgedSignature {
    fn from(report: &SignatureReport) -> Self {
        Self {
            signer: report.signer().name().to_owned(),
            identifier: report
                .signer()
                .identifier()
                .map(|identifier| identifier.to_string()),
            document_intact: report.document_intact(),
            signature_valid: report.signature_valid(),
            chain_verified: report.chain_verified(),
            revocation: report.revocation().into(),
            proof_of_existence: report.proof_of_existence().map(|time| time.to_string()),
            claimed_signing_time: report.claimed_signing_time().map(|time| time.to_string()),
            timestamps: count(report.timestamps().len()),
            archive_timestamps: count(report.archive_timestamps().len()),
            revision: report.revision().into(),
            valid: report.is_valid(),
        }
    }
}

/// What became of one signature found in the document.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SignatureVerdict {
    /// The signature was judged.
    Judged {
        /// The facts.
        signature: JudgedSignature,
    },
    /// The signature was found and not judged.
    Unsupported {
        /// Why, in the core's words.
        reason: String,
        /// The holder the signer certificate names, unverified.
        signer: Option<String>,
    },
}

/// One signature found in the document.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignatureEntry {
    /// Whether it was judged, and the facts or the reason.
    pub verdict: SignatureVerdict,
    /// The index in [`DocumentVerdict::signatures`] of the signature
    /// this one counter-signs; `None` for a signature over the document.
    pub counter_signs: Option<u32>,
}

impl From<&SignatureRow> for SignatureEntry {
    fn from(row: &SignatureRow) -> Self {
        Self {
            verdict: match row.outcome() {
                SignatureOutcome::Judged(report) => SignatureVerdict::Judged {
                    signature: JudgedSignature::from(report.as_ref()),
                },
                SignatureOutcome::Unsupported { reason, signer } => SignatureVerdict::Unsupported {
                    reason: format!("{reason:?}"),
                    signer: signer.as_ref().map(|signer| signer.name().to_owned()),
                },
            },
            counter_signs: row.counter_signs().map(count),
        }
    }
}

/// The verification of one document.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DocumentVerdict {
    /// Whether the document is valid: at least one signature over the
    /// document, every one judged and valid.
    pub valid: bool,
    /// Every signature found, in document order.
    pub signatures: Vec<SignatureEntry>,
    /// PDF document timestamps found.
    pub document_timestamps: u32,
}

impl From<&DocumentReport> for DocumentVerdict {
    fn from(report: &DocumentReport) -> Self {
        Self {
            valid: report.is_valid(),
            signatures: report.rows().iter().map(SignatureEntry::from).collect(),
            document_timestamps: count(report.document_timestamps().len()),
        }
    }
}

/// A count as the app takes it.
fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Verify every signature of the file at `path` under the EU trusted
/// lists' anchors at this clock, asking the responders about each
/// judged signer the file leaves unavailable on a verified chain.
/// `cache_directory` holds the lists' cache ([`crate::lists`]).
///
/// # Errors
/// [`VerifyFailure`] when there is nothing to judge, or no anchors to
/// judge it under.
#[uniffi::export]
pub fn verify_document(
    path: String,
    cache_directory: String,
) -> Result<DocumentVerdict, VerifyFailure> {
    let bytes = std::fs::read(path).map_err(|_error| VerifyFailure::FileRead)?;
    let now = refineid_doc_sign::now_date_time();
    let file = DocumentFile::from_file(bytes)?;
    let anchors =
        crate::lists::anchors(std::path::Path::new(&cache_directory), now).map_err(|error| {
            match error {
                ListsFailure::Unavailable => VerifyFailure::AnchorsUnavailable,
            }
        })?;
    Ok(judge(&file, &anchors, now)?)
}

/// [`verify_document`] on `bytes` under `anchors` at `now`.
fn verify_bytes(
    bytes: Vec<u8>,
    anchors: &TrustAnchors,
    now: DateTime,
) -> Result<DocumentVerdict, DocumentFailure> {
    let file = DocumentFile::from_file(bytes)?;
    judge(&file, anchors, now)
}

/// Judge the signatures of the parsed `file` under `anchors` at `now`.
fn judge(
    file: &DocumentFile,
    anchors: &TrustAnchors,
    now: DateTime,
) -> Result<DocumentVerdict, DocumentFailure> {
    let report = verify(file, anchors, now)?
        .with_live_revocation(|signature| live_revocation(signature, anchors, now));
    Ok(DocumentVerdict::from(&report))
}

#[cfg(test)]
mod tests {
    use super::{RevocationStatus, SignatureVerdict, VerifyFailure, verify_bytes, verify_document};
    use crate::sign::DocumentFormat;
    use crate::sign::DocumentOutcome;
    use crate::sign::tests::{ScriptedCard, WorkDir, sign_offline};
    use refineid_doc_sign::testkit::minimal_pdf;
    use refineid_doc_sign::verification::TrustAnchors;

    /// [`verify_bytes`] under no anchors: unit tests stay offline, and
    /// the lists' fetching is [`crate::lists`]' to test.
    fn verify_offline(
        path: impl AsRef<std::path::Path>,
    ) -> Result<super::DocumentVerdict, VerifyFailure> {
        let bytes = std::fs::read(path).map_err(|_error| VerifyFailure::FileRead)?;
        let anchors = TrustAnchors::new(Vec::new());
        Ok(verify_bytes(
            bytes,
            &anchors,
            refineid_doc_sign::now_date_time(),
        )?)
    }

    #[test]
    fn a_document_the_card_signed_is_judged_intact_and_valid_but_unanchored() {
        let dir = WorkDir::new("verify");
        let inputs = vec![dir.write("letter.pdf", &minimal_pdf())];
        let out = dir.outputs();
        let outcomes = sign_offline(ScriptedCard::signing(), inputs, &out, DocumentFormat::Pades)
            .expect("signed");
        let DocumentOutcome::Signed { document } = &outcomes[0] else {
            panic!("not signed");
        };
        let verdict = verify_offline(&document.path).expect("a report");
        assert_eq!(verdict.signatures.len(), 1);
        assert_eq!(verdict.document_timestamps, 0);
        let SignatureVerdict::Judged { signature } = &verdict.signatures[0].verdict else {
            panic!("not judged");
        };
        assert_eq!(signature.signer, "Test Holder");
        assert!(signature.document_intact);
        assert!(signature.signature_valid);
        assert!(!signature.chain_verified, "a test CA is no pinned anchor");
        assert_eq!(signature.revocation, RevocationStatus::Unavailable);
        assert!(!signature.valid);
        assert!(!verdict.valid);
        assert_eq!(verdict.signatures[0].counter_signs, None);
    }

    #[test]
    fn a_file_that_is_no_document_and_an_unsigned_pdf_yield_no_report() {
        let dir = WorkDir::new("verify-none");
        let text = dir.write("note.txt", b"plain text");
        assert_eq!(
            verify_offline(&text),
            Err(VerifyFailure::NotASignedDocument)
        );
        let unsigned = dir.write("blank.pdf", &minimal_pdf());
        assert_eq!(verify_offline(&unsigned), Err(VerifyFailure::NoSignatures));
        assert_eq!(
            verify_offline(dir.path().join("missing.pdf")),
            Err(VerifyFailure::FileRead)
        );
    }

    #[test]
    fn verify_without_lists_or_cache_reports_no_anchors() {
        let dir = WorkDir::new("verify-no-lists");
        let unsigned = dir.write("blank.pdf", &minimal_pdf());
        // No transport is registered in a unit test and the cache is
        // empty, so the lists cannot load. A file that parses but
        // carries no signature would report first; sign one offline so
        // the anchors are what is missing.
        let out = dir.outputs();
        let card = ScriptedCard::signing();
        let outcomes =
            sign_offline(card, vec![unsigned], &out, DocumentFormat::Pades).expect("signed");
        let DocumentOutcome::Signed { document } = &outcomes[0] else {
            panic!("not signed");
        };
        assert_eq!(
            verify_document(
                document.path.clone(),
                dir.path()
                    .join("trusted-lists")
                    .to_string_lossy()
                    .into_owned()
            ),
            Err(VerifyFailure::AnchorsUnavailable)
        );
    }
}
