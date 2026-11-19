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

//! Signing documents with the card in this phone.
//!
//! [`sign_documents`] signs the files the app staged: each PDF as its
//! own `PAdES` document, or every file as one `ASiC-E` container, both
//! at LTA like the first-party clients, timestamped by the authorities
//! the holder configured, or the default authority when none is
//! configured. A PDF carries the verification seal in the language of
//! the app's locale. Each signed document lands in the app's output
//! directory under the core's signed-document name.

use core::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use refineid_doc_sign::cades::SigningTime;
use refineid_doc_sign::document::Format;
use refineid_doc_sign::material::MaterialError;
use refineid_doc_sign::pades::{SignatureMetadata, StampLanguage, VisibleSignature};
use refineid_doc_sign::remote::{PhoneSignOptions, sign_on_phone};
use refineid_doc_sign::service::{
    DEFAULT_TIMESTAMP_AUTHORITY, DocumentRequest, SignErrorKind, SignOutput, SignReport,
    SigningBuild, TimestampCredentials,
};
use refineid_doc_sign::signed_name::PendingSignedName;

use crate::signer::{CardSignRefusal, CardSigner, LocalCardSigner};

/// What the signature produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DocumentFormat {
    /// Each input, a PDF, signed inside itself.
    Pades,
    /// Every input in one `ASiC-E` container with an `XAdES` signature.
    AsicE,
}

impl DocumentFormat {
    /// The core's format.
    const fn core(self) -> Format {
        match self {
            Self::Pades => Format::Pades,
            Self::AsicE => Format::AsicEXades,
        }
    }
}

/// One timestamp authority the holder configured.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct TimestampAuthority {
    /// The authority's URL.
    pub url: String,
    /// The HTTP Basic login the authority asks for, if any.
    pub login: Option<TimestampLogin>,
}

/// An HTTP Basic login for one timestamp authority. Its `Debug` shows
/// neither field.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct TimestampLogin {
    /// The user name.
    pub username: String,
    /// The password, UTF-8.
    pub password: Vec<u8>,
}

impl fmt::Debug for TimestampAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimestampAuthority")
            .field("login", &self.login.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for TimestampLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TimestampLogin([redacted])")
    }
}

/// The authorities of one signing in the core's terms: their URLs, the
/// default one when the holder configured none, and the login of the
/// one that has a login. The core accepts a login only for a sole HTTPS
/// authority and refuses the signing otherwise.
#[derive(Clone)]
struct Timestamping {
    urls: Vec<String>,
    credentials: Option<TimestampCredentials>,
}

impl Timestamping {
    fn of(authorities: Vec<TimestampAuthority>) -> Result<Self, SignFailure> {
        if authorities.is_empty() {
            return Ok(Self {
                urls: vec![DEFAULT_TIMESTAMP_AUTHORITY.to_owned()],
                credentials: None,
            });
        }
        let mut urls = Vec::with_capacity(authorities.len());
        let mut credentials = None;
        for authority in authorities {
            urls.push(authority.url);
            if let Some(login) = authority.login {
                if credentials.is_some() {
                    return Err(timestamp_refusal(
                        "timestamp credentials require exactly one authority",
                    ));
                }
                let password = String::from_utf8(login.password)
                    .map_err(|_error| timestamp_refusal("timestamp password is not UTF-8"))?;
                credentials = Some(
                    TimestampCredentials::new(login.username, password)
                        .map_err(timestamp_refusal)?,
                );
            }
        }
        Ok(Self { urls, credentials })
    }
}

fn timestamp_refusal(detail: &str) -> SignFailure {
    SignFailure::Timestamp {
        detail: detail.to_owned(),
    }
}

/// One finished document.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignedDocument {
    /// Where the signed document was written.
    pub path: String,
    /// The size of the written file.
    pub output_len: u64,
    /// Timestamp tokens the document carries.
    pub timestamps: u32,
    /// The `commonName` of the signing certificate's subject.
    pub signer: Option<String>,
}

impl From<SignReport> for SignedDocument {
    fn from(report: SignReport) -> Self {
        Self {
            path: report.signature_path.to_string_lossy().into_owned(),
            output_len: u64::try_from(report.output_len).unwrap_or(u64::MAX),
            timestamps: u32::try_from(report.timestamps).unwrap_or(u32::MAX),
            signer: report.cert_subject_cn.map(|name| name.to_string()),
        }
    }
}

/// Why a document was not signed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum SignFailure {
    /// The request or the document's format could not be built.
    Document {
        /// The core's account.
        detail: String,
    },
    /// The chain or revocation answers could not be collected.
    Material {
        /// The core's account.
        detail: String,
    },
    /// A verified revocation answer says a certificate on the signer's
    /// path, or on a timestamp authority's path, is revoked; nothing was
    /// written.
    Revoked {
        /// The revocation time the answer states.
        revoked_at: String,
        /// The `CRLReason` the answer states, when it states one.
        reason: Option<String>,
    },
    /// The timestamp authority could not be reached or refused.
    Timestamp {
        /// The core's account.
        detail: String,
    },
    /// An input file could not be read.
    InputRead,
    /// The signed document could not be written.
    OutputWrite,
    /// The card gave no certificate or no signatures.
    Card {
        /// Why.
        refusal: CardSignRefusal,
    },
    /// The card's certificate is not a qualified-signature certificate
    /// a document can be signed with.
    Certificate {
        /// The core's account.
        detail: String,
    },
    /// The card's signatures do not match the documents; nothing was
    /// written.
    SignatureInvalid,
}

impl fmt::Display for SignFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for SignFailure {}

impl From<SignErrorKind> for SignFailure {
    fn from(error: SignErrorKind) -> Self {
        match error {
            SignErrorKind::Document(_)
            | SignErrorKind::VisibleSignatureFormat
            | SignErrorKind::UnsupportedDocumentKey(_)
            | SignErrorKind::DocumentNameLength
            | SignErrorKind::PackageInBatch
            | SignErrorKind::BelowArchivalLevel { .. }
            | SignErrorKind::NoDocuments => Self::Document {
                detail: error.to_string(),
            },
            SignErrorKind::Material {
                error:
                    MaterialError::Revoked {
                        revoked_at, reason, ..
                    },
                ..
            } => Self::Revoked {
                revoked_at: revoked_at.to_string(),
                reason: reason.map(|reason| reason.to_string()),
            },
            SignErrorKind::Material { .. } => Self::Material {
                detail: error.to_string(),
            },
            SignErrorKind::Timestamp(detail) => Self::Timestamp { detail },
            SignErrorKind::InputRead { .. } => Self::InputRead,
            SignErrorKind::SignatureWrite { .. } => Self::OutputWrite,
            SignErrorKind::Phone(refusal) => Self::Card {
                refusal: refusal_of(refusal),
            },
            SignErrorKind::PhoneCertificate(error) => Self::Certificate {
                detail: error.to_string(),
            },
            SignErrorKind::PhoneSignatureCount { .. }
            | SignErrorKind::PhoneSignatureInvalid { .. } => Self::SignatureInvalid,
        }
    }
}

/// The core's refusal as the card's; the core's two names for a phone
/// that is not there are the card not answering.
const fn refusal_of(refusal: refineid_doc_sign::remote::PhoneRefusal) -> CardSignRefusal {
    use refineid_doc_sign::remote::PhoneRefusal;
    match refusal {
        PhoneRefusal::Declined => CardSignRefusal::Declined,
        PhoneRefusal::Expired => CardSignRefusal::Expired,
        PhoneRefusal::CardUnavailable | PhoneRefusal::Unreachable => {
            CardSignRefusal::CardUnavailable
        }
        PhoneRefusal::RetryFloor => CardSignRefusal::RetryFloor,
        PhoneRefusal::NotGranted | PhoneRefusal::Unsupported => CardSignRefusal::Unsupported,
        PhoneRefusal::PhoneFailed => CardSignRefusal::CardFailed,
    }
}

/// What became of one document once every signature verified.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DocumentOutcome {
    /// The document was finished and written.
    Signed {
        /// The document.
        document: SignedDocument,
    },
    /// The document's finish failed; the others stand on their own.
    Failed {
        /// Why.
        failure: SignFailure,
    },
}

/// Sign `inputs` with the card in this phone through `signer`, writing
/// each signed document into `output_directory` under the core's
/// signed-document name. `language` is the app's locale name; a PDF's
/// verification seal is in its language. `timestamp_authorities` are
/// the holder's; none means the default authority. `signer_anchors`
/// are the DER certificates the signer's long-term material may end
/// at: the card's issuing CA and root, which the app read from the
/// card. A release build without one is refused before the card signs.
///
/// # Errors
/// [`SignFailure`] when nothing was written: no input, a refused
/// timestamp configuration, a refused
/// request, the card's refusal, a refused certificate, or signatures
/// that do not verify. Once every signature has verified, each document
/// finishes on its own, and its outcome is at its input's position.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn sign_documents(
    signer: Arc<dyn LocalCardSigner>,
    inputs: Vec<String>,
    output_directory: String,
    format: DocumentFormat,
    language: String,
    timestamp_authorities: Vec<TimestampAuthority>,
    signer_anchors: Vec<Vec<u8>>,
) -> Result<Vec<DocumentOutcome>, SignFailure> {
    let timestamping = Timestamping::of(timestamp_authorities)?;
    let inputs: Vec<PathBuf> = inputs.into_iter().map(PathBuf::from).collect();
    let output_directory = PathBuf::from(output_directory);
    let signing_time = SigningTime::now();
    let clock = refineid_doc_sign::now_date_time();
    let documents = match format {
        DocumentFormat::Pades => inputs
            .iter()
            .map(|input| {
                options(
                    input,
                    Vec::new(),
                    &output_directory,
                    format,
                    signing_time,
                    clock,
                    Some(&language),
                    timestamping.clone(),
                    signer_anchors.clone(),
                )
            })
            .collect(),
        DocumentFormat::AsicE => match inputs.split_first() {
            Some((first, rest)) => vec![options(
                first,
                rest.to_vec(),
                &output_directory,
                format,
                signing_time,
                clock,
                None,
                timestamping,
                signer_anchors,
            )],
            None => Vec::new(),
        },
    };
    let mut card = CardSigner::new(signer);
    Ok(sign_on_phone(&mut card, documents)?
        .into_iter()
        .map(|outcome| match outcome {
            Ok(report) => DocumentOutcome::Signed {
                document: SignedDocument::from(report),
            },
            Err(error) => DocumentOutcome::Failed {
                failure: SignFailure::from(error),
            },
        })
        .collect())
}

/// One document to sign: `input` with `additional` in a container,
/// written into `output_directory` under the name the core gives the
/// inputs' names there, with the seal in `language` when given,
/// timestamped as `timestamping` says.
#[allow(clippy::too_many_arguments)]
fn options(
    input: &Path,
    additional: Vec<PathBuf>,
    output_directory: &Path,
    format: DocumentFormat,
    signing_time: SigningTime,
    clock: refineid_doc_sign::x509::DateTime,
    language: Option<&str>,
    timestamping: Timestamping,
    signer_anchors: Vec<Vec<u8>>,
) -> PhoneSignOptions {
    let named = core::iter::once(input)
        .chain(additional.iter().map(PathBuf::as_path))
        .map(|path| output_directory.join(path.file_name().unwrap_or_default()))
        .collect();
    PhoneSignOptions {
        input: input.to_path_buf(),
        output: SignOutput::SignedName(PendingSignedName::new(named, format.core(), clock)),
        document: DocumentRequest {
            format: format.core(),
            additional_inputs: additional,
            signing_time,
            metadata: SignatureMetadata {
                visible_signature: language
                    .map(|name| VisibleSignature::verification(StampLanguage::for_locale(name))),
                ..SignatureMetadata::default()
            },
            archive: true,
            long_term: true,
            signer_anchors,
            timestamp_authorities: timestamping.urls,
            timestamp_credentials: timestamping.credentials,
            build: SigningBuild::THIS,
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        DocumentFormat, DocumentOutcome, SignFailure, TimestampAuthority, TimestampLogin,
        Timestamping, options, sign_documents,
    };
    use crate::signer::{CardSignRefusal, DigestBatch, LocalCardSigner};
    use refineid_doc_sign::crl::CrlReason;
    use refineid_doc_sign::document::Format;
    use refineid_doc_sign::material::MaterialError;
    use refineid_doc_sign::remote::PhoneRefusal;
    use refineid_doc_sign::service::{MaterialPath, SignErrorKind};
    use refineid_doc_sign::testkit::{
        CertificateSpec, KEY_USAGE_NON_REPUDIATION, KEY_USAGE_NON_REPUDIATION_UNUSED, TestCurve,
        TestKey, certificate, day, key_usage, minimal_pdf,
    };
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    /// First day of the fixture certificate's validity.
    const NOT_BEFORE: u8 = 1;
    /// Last day of the fixture certificate's validity.
    const NOT_AFTER: u8 = 28;
    /// Serial of the fixture certificate.
    const SIGNER_SERIAL: u8 = 7;
    /// The locale the tests sign under.
    const LOCALE: &str = "fi_FI";
    /// A locale the seal does not carry.
    const OTHER_LOCALE: &str = "de_DE";
    /// Documents in the PDF batch.
    const BATCH_SIZE: usize = 2;

    /// A directory under the system temporary directory, removed on
    /// drop.
    pub(crate) struct WorkDir(PathBuf);

    impl WorkDir {
        pub(crate) fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "refineid-doc-sign-android-{label}-{}-{}",
                std::process::id(),
                refineid_doc_sign::now_date_time()
                    .to_string()
                    .replace(':', "-")
            ));
            std::fs::create_dir_all(&path).expect("a work directory");
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }

        pub(crate) fn write(&self, name: &str, content: &[u8]) -> String {
            let path = self.0.join(name);
            std::fs::write(&path, content).expect("a fixture file");
            path.to_string_lossy().into_owned()
        }

        pub(crate) fn outputs(&self) -> PathBuf {
            let path = self.0.join("out");
            std::fs::create_dir_all(&path).expect("an output directory");
            path
        }
    }

    impl Drop for WorkDir {
        fn drop(&mut self) {
            let _removed = std::fs::remove_dir_all(&self.0);
        }
    }

    /// What the scripted card does when asked to sign.
    #[derive(Clone, Copy)]
    enum Answer {
        /// Signs every digest in order.
        Sign,
        /// Refuses with this.
        Refuse(CardSignRefusal),
    }

    /// A card holding a P-384 qualified-signature key, as the app's
    /// signer presents it.
    pub(crate) struct ScriptedCard {
        key: TestKey,
        certificate: Vec<u8>,
        answer: Answer,
        pub(crate) batches: Mutex<Vec<DigestBatch>>,
    }

    impl ScriptedCard {
        fn with(answer: Answer) -> Arc<Self> {
            let key = TestKey::derive(TestCurve::P384, b"card-signature");
            let issuer = TestKey::derive(TestCurve::P384, b"card-signature-issuer");
            let spec = CertificateSpec {
                serial: SIGNER_SERIAL,
                subject: "Test Holder",
                issuer: "Test Signature CA",
                not_before: day(NOT_BEFORE),
                not_after: day(NOT_AFTER),
                extensions: vec![key_usage(
                    KEY_USAGE_NON_REPUDIATION_UNUSED,
                    KEY_USAGE_NON_REPUDIATION,
                )],
            };
            let certificate = certificate(&spec, &key, &issuer);
            Arc::new(Self {
                key,
                certificate,
                answer,
                batches: Mutex::new(Vec::new()),
            })
        }

        pub(crate) fn signing() -> Arc<Self> {
            Self::with(Answer::Sign)
        }
    }

    impl LocalCardSigner for ScriptedCard {
        fn signature_certificate(&self) -> Result<Vec<u8>, CardSignRefusal> {
            Ok(self.certificate.clone())
        }

        fn sign(&self, batch: DigestBatch) -> Result<Vec<Vec<u8>>, CardSignRefusal> {
            let signatures = batch
                .documents
                .iter()
                .map(|document| self.key.sign_digest_raw(&document.digest))
                .collect();
            self.batches.lock().expect("batches").push(batch);
            match self.answer {
                Answer::Sign => Ok(signatures),
                Answer::Refuse(refusal) => Err(refusal),
            }
        }
    }

    /// Level B: no network in a unit test. The levels the app asks for
    /// are tested on `options`.
    pub(crate) fn sign_offline(
        card: Arc<ScriptedCard>,
        inputs: Vec<String>,
        out: &Path,
        format: DocumentFormat,
    ) -> Result<Vec<DocumentOutcome>, SignFailure> {
        let documents: Vec<_> = match format {
            DocumentFormat::Pades => inputs
                .iter()
                .map(|input| offline(Path::new(input), Vec::new(), out, format))
                .collect(),
            DocumentFormat::AsicE => {
                let (first, rest) = inputs.split_first().expect("an input");
                vec![offline(
                    Path::new(first),
                    rest.iter().map(PathBuf::from).collect(),
                    out,
                    format,
                )]
            }
        };
        let mut signer = crate::signer::CardSigner::new(card);
        Ok(
            refineid_doc_sign::remote::sign_on_phone(&mut signer, documents)?
                .into_iter()
                .map(|outcome| match outcome {
                    Ok(report) => DocumentOutcome::Signed {
                        document: report.into(),
                    },
                    Err(error) => DocumentOutcome::Failed {
                        failure: error.into(),
                    },
                })
                .collect(),
        )
    }

    fn offline(
        input: &Path,
        additional: Vec<PathBuf>,
        out: &Path,
        format: DocumentFormat,
    ) -> refineid_doc_sign::remote::PhoneSignOptions {
        let mut options = options(
            input,
            additional,
            out,
            format,
            refineid_doc_sign::cades::SigningTime::now(),
            refineid_doc_sign::now_date_time(),
            (format == DocumentFormat::Pades).then_some(LOCALE),
            default_timestamping(),
            Vec::new(),
        );
        options.document.archive = false;
        options.document.long_term = false;
        options.document.timestamp_authorities.clear();
        options
    }

    fn signed_path(outcome: &DocumentOutcome) -> PathBuf {
        match outcome {
            DocumentOutcome::Signed { document } => PathBuf::from(&document.path),
            DocumentOutcome::Failed { failure } => panic!("not signed: {failure}"),
        }
    }

    #[test]
    fn each_pdf_is_signed_on_its_own_into_the_output_directory() {
        let dir = WorkDir::new("pades");
        let inputs: Vec<String> = (0..BATCH_SIZE)
            .map(|index| dir.write(&format!("letter-{index}.pdf"), &minimal_pdf()))
            .collect();
        let out = dir.outputs();
        let card = ScriptedCard::signing();
        let outcomes =
            sign_offline(Arc::clone(&card), inputs, &out, DocumentFormat::Pades).expect("signed");
        assert_eq!(outcomes.len(), BATCH_SIZE);
        for (index, outcome) in outcomes.iter().enumerate() {
            let path = signed_path(outcome);
            assert_eq!(path.parent(), Some(out.as_path()));
            let name = path.file_name().expect("a name").to_string_lossy();
            assert!(name.starts_with(&format!("letter-{index}-signed-")));
            assert!(name.ends_with(".pdf"));
            assert!(path.is_file());
        }
        let batches = card.batches.lock().expect("batches");
        assert_eq!(batches.len(), 1, "one PIN 2 entry for the batch");
        assert_eq!(batches[0].key_profile, crate::signer::KeyProfile::EcdsaP384);
        assert_eq!(
            batches[0].algorithm,
            crate::signer::SignatureAlgorithm::EcdsaSha384
        );
        let names: Vec<&str> = batches[0]
            .documents
            .iter()
            .map(|document| document.name.as_str())
            .collect();
        assert_eq!(names, vec!["letter-0.pdf", "letter-1.pdf"]);
    }

    #[test]
    fn several_files_become_one_container_named_portfolio() {
        let dir = WorkDir::new("asice");
        let inputs = vec![
            dir.write("letter.txt", b"letter"),
            dir.write("annex.txt", b"annex"),
        ];
        let out = dir.outputs();
        let card = ScriptedCard::signing();
        let outcomes =
            sign_offline(Arc::clone(&card), inputs, &out, DocumentFormat::AsicE).expect("signed");
        assert_eq!(outcomes.len(), 1);
        let path = signed_path(&outcomes[0]);
        let name = path.file_name().expect("a name").to_string_lossy();
        assert!(name.starts_with("portfolio-signed-"));
        assert!(name.ends_with(".asice"));
        let batches = card.batches.lock().expect("batches");
        assert_eq!(batches[0].documents.len(), 1);
        assert_eq!(batches[0].documents[0].name, "portfolio-signed.asice");
    }

    #[test]
    fn a_declined_card_writes_nothing() {
        let dir = WorkDir::new("declined");
        let inputs = vec![dir.write("letter.pdf", &minimal_pdf())];
        let out = dir.outputs();
        let card = ScriptedCard::with(Answer::Refuse(CardSignRefusal::Declined));
        let failure =
            sign_offline(card, inputs, &out, DocumentFormat::Pades).expect_err("declined");
        assert_eq!(
            failure,
            SignFailure::Card {
                refusal: CardSignRefusal::Declined
            }
        );
        assert_eq!(std::fs::read_dir(&out).expect("readable").count(), 0);
    }

    #[test]
    fn no_input_is_refused_before_the_card_is_asked() {
        let card = ScriptedCard::signing();
        let failure = sign_documents(
            Arc::clone(&card) as Arc<dyn LocalCardSigner>,
            Vec::new(),
            String::new(),
            DocumentFormat::AsicE,
            LOCALE.to_owned(),
            Vec::new(),
            Vec::new(),
        )
        .expect_err("nothing to sign");
        assert!(matches!(failure, SignFailure::Document { .. }));
        assert!(card.batches.lock().expect("batches").is_empty());
    }

    /// The authorities when the holder configured none.
    fn default_timestamping() -> Timestamping {
        Timestamping::of(Vec::new()).expect("the default authority")
    }

    /// A configured authority's URL.
    const CONFIGURED_AUTHORITY: &str = "https://tsa.example/stamp";
    /// A second configured authority's URL.
    const OTHER_AUTHORITY: &str = "https://other-tsa.example/stamp";
    /// A synthetic login.
    const LOGIN_NAME: &str = "holder";
    /// A synthetic password.
    const LOGIN_PASSWORD: &str = "synthetic-password";

    fn authority(url: &str, login: bool) -> TimestampAuthority {
        TimestampAuthority {
            url: url.to_owned(),
            login: login.then(|| TimestampLogin {
                username: LOGIN_NAME.to_owned(),
                password: LOGIN_PASSWORD.as_bytes().to_vec(),
            }),
        }
    }

    #[test]
    fn no_configured_authority_means_the_default_one() {
        let timestamping = default_timestamping();
        assert_eq!(
            timestamping.urls,
            vec![refineid_doc_sign::service::DEFAULT_TIMESTAMP_AUTHORITY.to_owned()]
        );
        assert!(timestamping.credentials.is_none());
    }

    #[test]
    fn configured_authorities_replace_the_default_in_order() {
        let timestamping = Timestamping::of(vec![
            authority(CONFIGURED_AUTHORITY, false),
            authority(OTHER_AUTHORITY, false),
        ])
        .expect("accepted");
        assert_eq!(
            timestamping.urls,
            vec![CONFIGURED_AUTHORITY, OTHER_AUTHORITY]
        );
        assert!(timestamping.credentials.is_none());
    }

    #[test]
    fn a_sole_authority_carries_its_login() {
        let timestamping =
            Timestamping::of(vec![authority(CONFIGURED_AUTHORITY, true)]).expect("accepted");
        assert!(timestamping.credentials.is_some());
        let pades = options(
            Path::new("in/letter.pdf"),
            Vec::new(),
            Path::new("out"),
            DocumentFormat::Pades,
            refineid_doc_sign::cades::SigningTime::now(),
            refineid_doc_sign::now_date_time(),
            None,
            timestamping,
            Vec::new(),
        );
        assert_eq!(
            pades.document.timestamp_authorities,
            vec![CONFIGURED_AUTHORITY]
        );
        assert!(pades.document.timestamp_credentials.is_some());
    }

    #[test]
    fn two_logins_or_a_bad_login_are_refused() {
        let two = Timestamping::of(vec![
            authority(CONFIGURED_AUTHORITY, true),
            authority(OTHER_AUTHORITY, true),
        ]);
        assert!(matches!(two, Err(SignFailure::Timestamp { .. })));
        let mut empty_name = authority(CONFIGURED_AUTHORITY, true);
        if let Some(login) = empty_name.login.as_mut() {
            login.username.clear();
        }
        assert!(matches!(
            Timestamping::of(vec![empty_name]),
            Err(SignFailure::Timestamp { .. })
        ));
    }

    #[test]
    fn a_login_never_shows_in_debug_output() {
        let shown = format!("{:?}", authority(CONFIGURED_AUTHORITY, true));
        assert!(!shown.contains(LOGIN_NAME));
        assert!(!shown.contains(LOGIN_PASSWORD));
        assert!(!shown.contains(CONFIGURED_AUTHORITY));
    }

    #[test]
    fn the_levels_are_the_first_party_clients() {
        let anchors = vec![vec![1, 2, 3]];
        let pades = options(
            Path::new("in/letter.pdf"),
            Vec::new(),
            Path::new("out"),
            DocumentFormat::Pades,
            refineid_doc_sign::cades::SigningTime::now(),
            refineid_doc_sign::now_date_time(),
            Some(OTHER_LOCALE),
            default_timestamping(),
            anchors.clone(),
        );
        assert_eq!(pades.document.format, Format::Pades);
        assert!(pades.document.archive && pades.document.long_term);
        assert_eq!(pades.document.signer_anchors, anchors);
        assert_eq!(
            pades.document.build,
            refineid_doc_sign::service::SigningBuild::THIS
        );
        assert_eq!(
            pades.document.timestamp_authorities,
            vec![refineid_doc_sign::service::DEFAULT_TIMESTAMP_AUTHORITY.to_owned()]
        );
        assert!(pades.document.metadata.visible_signature.is_some());
        assert_eq!(pades.output.path(None).parent(), Some(Path::new("out")));

        let container = options(
            Path::new("in/letter.txt"),
            vec![PathBuf::from("in/annex.txt")],
            Path::new("out"),
            DocumentFormat::AsicE,
            refineid_doc_sign::cades::SigningTime::now(),
            refineid_doc_sign::now_date_time(),
            None,
            default_timestamping(),
            Vec::new(),
        );
        assert_eq!(container.document.format, Format::AsicEXades);
        assert!(container.document.archive && container.document.long_term);
        assert!(container.document.metadata.visible_signature.is_none());
        assert_eq!(
            container.document.additional_inputs,
            vec![PathBuf::from("in/annex.txt")]
        );
    }

    #[test]
    fn every_core_failure_has_a_name_without_a_path_or_a_document() {
        assert_eq!(
            SignFailure::from(SignErrorKind::Phone(PhoneRefusal::Unreachable)),
            SignFailure::Card {
                refusal: CardSignRefusal::CardUnavailable
            }
        );
        assert_eq!(
            SignFailure::from(SignErrorKind::InputRead {
                path: PathBuf::from("private/name.pdf"),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            }),
            SignFailure::InputRead
        );
        assert_eq!(
            SignFailure::from(SignErrorKind::PhoneSignatureCount {
                expected: BATCH_SIZE,
                got: 0
            }),
            SignFailure::SignatureInvalid
        );
        assert!(matches!(
            SignFailure::from(SignErrorKind::NoDocuments),
            SignFailure::Document { .. }
        ));
        assert!(matches!(
            SignFailure::from(SignErrorKind::PackageInBatch),
            SignFailure::Document { .. }
        ));
        assert!(matches!(
            SignFailure::from(SignErrorKind::BelowArchivalLevel {
                format: Format::Pades,
                requested: refineid_doc_sign::service::BaselineLevel::Lt,
            }),
            SignFailure::Document { .. }
        ));
    }

    /// A revocation answer's account; synthetic.
    const REVOCATION_DETAIL: &str = "responder says revoked";
    /// A timestamp authority's address; synthetic.
    const AUTHORITY: &str = "http://tsa.example/stamp";

    fn revoked(reason: Option<CrlReason>) -> MaterialError {
        MaterialError::Revoked {
            revoked_at: refineid_doc_sign::now_date_time(),
            reason,
            detail: REVOCATION_DETAIL.to_owned(),
        }
    }

    #[test]
    fn a_revoked_path_is_its_own_failure_on_every_path() {
        let at = refineid_doc_sign::now_date_time().to_string();
        for path in [
            MaterialPath::Signer,
            MaterialPath::SignatureTimestamp {
                authority: AUTHORITY.to_owned(),
            },
            MaterialPath::ArchiveTimestamp {
                authority: AUTHORITY.to_owned(),
            },
        ] {
            let failure = SignFailure::from(SignErrorKind::Material {
                path,
                error: revoked(Some(CrlReason::KeyCompromise)),
            });
            let SignFailure::Revoked { revoked_at, reason } = failure else {
                panic!("not revoked: {failure:?}");
            };
            assert_eq!(revoked_at, at);
            assert_eq!(reason, Some(CrlReason::KeyCompromise.to_string()));
        }
        assert_eq!(
            SignFailure::from(SignErrorKind::Material {
                path: MaterialPath::Signer,
                error: revoked(None),
            }),
            SignFailure::Revoked {
                revoked_at: at,
                reason: None
            }
        );
    }

    #[test]
    fn another_material_failure_keeps_the_cores_text() {
        let kind = SignErrorKind::Material {
            path: MaterialPath::Signer,
            error: MaterialError::Revocation(REVOCATION_DETAIL.to_owned()),
        };
        let text = kind.to_string();
        assert_eq!(
            SignFailure::from(kind),
            SignFailure::Material { detail: text }
        );
    }
}
