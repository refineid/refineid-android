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

//! Document signing and verification for Android over `refineid_doc_sign`.
//!
//! The core builds, checks and finishes every document and judges every
//! signature; this crate is the UniFFI surface the app drives it through.
//! The app brings two things the core has no platform for: the card in
//! this phone, as a [`signer::LocalCardSigner`] that signs the digests the
//! core hands it, and the network, as a [`network::HttpClient`] the core's
//! timestamp, revocation and verification fetches go through. The two
//! calls the app makes are [`sign::sign_documents`] and
//! [`verify::verify_document`].
//!
//! Every call blocks the thread it is made on and calls the app's signer
//! and client back on that thread, so the app makes them off its main
//! thread.

#![forbid(unsafe_code)]

pub mod lists;
pub mod network;
pub mod sign;
pub mod signer;
pub mod verify;

uniffi::setup_scaffolding!();
