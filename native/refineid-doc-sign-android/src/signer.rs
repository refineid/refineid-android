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

//! The card in this phone as the core's signer.
//!
//! `refineid_doc_sign::remote` signs a batch of documents through a
//! signer that yields the card's signature certificate and signs each
//! document's digest; the core plans the documents around the
//! certificate, verifies every returned signature against it and
//! finishes the documents. The app implements [`LocalCardSigner`] over
//! its own card session: it reads the certificate off the card, asks
//! the holder for PIN 2 on this screen, and has the card sign each
//! digest. No PIN reaches this crate.

use core::fmt;
use std::sync::Arc;

use refineid_doc_sign::remote::{
    PhoneRefusal, PhoneSigningBatch, RemoteSigner, UnvalidatedPhoneCertificate,
    UnvalidatedPhoneSignature,
};
use refineid_remote::{RemoteKeyProfile, RemoteSignatureAlgorithm};

/// The profile of the card key the certificate names, as the core read
/// it off the certificate (RAPP v26.10.29 section 9.2 names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyProfile {
    /// RSA with a 2048-bit modulus.
    Rsa2048,
    /// RSA with a 3072-bit modulus.
    Rsa3072,
    /// ECDSA on P-384.
    EcdsaP384,
}

/// The signature the card computes over each digest: the digest's
/// algorithm and the scheme the card applies to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 over a SHA-256 digest.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 over a SHA-384 digest.
    RsaPkcs1Sha384,
    /// ECDSA over a SHA-256 digest, the signature as fixed-width `r || s`.
    EcdsaSha256,
    /// ECDSA over a SHA-384 digest, the signature as fixed-width `r || s`.
    EcdsaSha384,
}

/// One document the card signs: the name the core gives it and the
/// digest of exactly what the document's format signs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DocumentDigest {
    /// The file's name, or the container's signed name.
    pub name: String,
    /// The digest, of [`DigestBatch::algorithm`]'s length.
    pub digest: Vec<u8>,
}

/// Every document of one signing, in order, under one key profile and
/// one algorithm; the card signs each with one PIN 2 entry by the holder.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DigestBatch {
    /// The profile of the key the certificate names.
    pub key_profile: KeyProfile,
    /// What the card computes over each digest.
    pub algorithm: SignatureAlgorithm,
    /// The documents, in signing order; one or more.
    pub documents: Vec<DocumentDigest>,
}

/// Why the card in this phone produced no certificate or no signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Error)]
pub enum CardSignRefusal {
    /// The holder declined the PIN 2 entry.
    Declined,
    /// The card did not answer within the app's wait.
    Expired,
    /// No card was held, or the card left before it answered.
    CardUnavailable,
    /// The card allows fewer PIN 2 tries than the floor serves at, or
    /// PIN 2 is blocked; no PIN was sent.
    RetryFloor,
    /// The card session cannot sign with this key profile or algorithm.
    Unsupported,
    /// The card or the session failed for a reason of its own.
    CardFailed,
}

impl fmt::Display for CardSignRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for CardSignRefusal {}

impl From<CardSignRefusal> for PhoneRefusal {
    fn from(refusal: CardSignRefusal) -> Self {
        match refusal {
            CardSignRefusal::Declined => Self::Declined,
            CardSignRefusal::Expired => Self::Expired,
            CardSignRefusal::CardUnavailable => Self::CardUnavailable,
            CardSignRefusal::RetryFloor => Self::RetryFloor,
            CardSignRefusal::Unsupported => Self::Unsupported,
            CardSignRefusal::CardFailed => Self::PhoneFailed,
        }
    }
}

/// The card in this phone, as the app drives it: the one signer of a
/// signing. [`Self::signature_certificate`] is called once, then
/// [`Self::sign`] once, on the thread that runs the signing.
#[uniffi::export(with_foreign)]
pub trait LocalCardSigner: Send + Sync {
    /// The DER of the card's qualified-signature certificate.
    ///
    /// # Errors
    /// Why the card gave none.
    fn signature_certificate(&self) -> Result<Vec<u8>, CardSignRefusal>;

    /// The card's signature over every document of `batch`, in the same
    /// order: for RSA the PKCS#1 v1.5 signature over the DigestInfo of
    /// the digest, for ECDSA the fixed-width `r || s`.
    ///
    /// # Errors
    /// Why the card signed nothing; no signature of a refused batch is
    /// used.
    fn sign(&self, batch: DigestBatch) -> Result<Vec<Vec<u8>>, CardSignRefusal>;
}

/// The app's signer as the core's.
pub(crate) struct CardSigner {
    /// The app's signer.
    card: Arc<dyn LocalCardSigner>,
}

impl CardSigner {
    /// The core's signer over `card`.
    pub(crate) const fn new(card: Arc<dyn LocalCardSigner>) -> Self {
        Self { card }
    }
}

impl RemoteSigner for CardSigner {
    fn signature_certificate(&mut self) -> Result<UnvalidatedPhoneCertificate, PhoneRefusal> {
        self.card
            .signature_certificate()
            .map(UnvalidatedPhoneCertificate::from_der)
            .map_err(PhoneRefusal::from)
    }

    fn sign(
        &mut self,
        batch: &PhoneSigningBatch,
    ) -> Result<Vec<UnvalidatedPhoneSignature>, PhoneRefusal> {
        let batch = DigestBatch {
            key_profile: key_profile(batch.key_profile())?,
            algorithm: algorithm(batch.algorithm())?,
            documents: batch
                .documents()
                .iter()
                .map(|document| DocumentDigest {
                    name: document.name().as_str().to_owned(),
                    digest: document.digest().to_vec(),
                })
                .collect(),
        };
        Ok(self
            .card
            .sign(batch)
            .map_err(PhoneRefusal::from)?
            .into_iter()
            .map(UnvalidatedPhoneSignature::from_bytes)
            .collect())
    }
}

/// The batch's key profile in the app's vocabulary; the document signing
/// flow names only these three.
fn key_profile(profile: RemoteKeyProfile) -> Result<KeyProfile, PhoneRefusal> {
    match profile {
        RemoteKeyProfile::Rsa2048 => Ok(KeyProfile::Rsa2048),
        RemoteKeyProfile::Rsa3072 => Ok(KeyProfile::Rsa3072),
        RemoteKeyProfile::EcdsaP384 => Ok(KeyProfile::EcdsaP384),
        RemoteKeyProfile::EcdsaP256 => Err(PhoneRefusal::Unsupported),
    }
}

/// The batch's algorithm in the app's vocabulary; a document format
/// names only these four.
fn algorithm(algorithm: RemoteSignatureAlgorithm) -> Result<SignatureAlgorithm, PhoneRefusal> {
    match algorithm {
        RemoteSignatureAlgorithm::RsaPkcs1Sha256 => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
        RemoteSignatureAlgorithm::RsaPkcs1Sha384 => Ok(SignatureAlgorithm::RsaPkcs1Sha384),
        RemoteSignatureAlgorithm::EcdsaSha256 => Ok(SignatureAlgorithm::EcdsaSha256),
        RemoteSignatureAlgorithm::EcdsaSha384 => Ok(SignatureAlgorithm::EcdsaSha384),
        RemoteSignatureAlgorithm::EcdsaSha224
        | RemoteSignatureAlgorithm::EcdsaSha512
        | RemoteSignatureAlgorithm::RsaPkcs1Sha512
        | RemoteSignatureAlgorithm::RsaPssSha256 => Err(PhoneRefusal::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CardSignRefusal, KeyProfile, PhoneRefusal, SignatureAlgorithm, algorithm, key_profile,
    };
    use refineid_remote::{RemoteKeyProfile, RemoteSignatureAlgorithm};

    #[test]
    fn every_refusal_has_a_core_name() {
        let cases = [
            (CardSignRefusal::Declined, PhoneRefusal::Declined),
            (CardSignRefusal::Expired, PhoneRefusal::Expired),
            (
                CardSignRefusal::CardUnavailable,
                PhoneRefusal::CardUnavailable,
            ),
            (CardSignRefusal::RetryFloor, PhoneRefusal::RetryFloor),
            (CardSignRefusal::Unsupported, PhoneRefusal::Unsupported),
            (CardSignRefusal::CardFailed, PhoneRefusal::PhoneFailed),
        ];
        for (refusal, expected) in cases {
            assert_eq!(PhoneRefusal::from(refusal), expected);
        }
    }

    #[test]
    fn the_document_profiles_and_algorithms_map_and_the_rest_are_refused() {
        assert_eq!(
            key_profile(RemoteKeyProfile::EcdsaP384),
            Ok(KeyProfile::EcdsaP384)
        );
        assert_eq!(
            key_profile(RemoteKeyProfile::Rsa2048),
            Ok(KeyProfile::Rsa2048)
        );
        assert_eq!(
            key_profile(RemoteKeyProfile::Rsa3072),
            Ok(KeyProfile::Rsa3072)
        );
        assert_eq!(
            key_profile(RemoteKeyProfile::EcdsaP256),
            Err(PhoneRefusal::Unsupported)
        );
        assert_eq!(
            algorithm(RemoteSignatureAlgorithm::EcdsaSha384),
            Ok(SignatureAlgorithm::EcdsaSha384)
        );
        assert_eq!(
            algorithm(RemoteSignatureAlgorithm::RsaPkcs1Sha256),
            Ok(SignatureAlgorithm::RsaPkcs1Sha256)
        );
        assert_eq!(
            algorithm(RemoteSignatureAlgorithm::RsaPssSha256),
            Err(PhoneRefusal::Unsupported)
        );
    }
}
