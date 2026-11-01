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

//! The app's HTTP client as the core's transport.
//!
//! The core fetches timestamps, chain and revocation answers while
//! signing, and revocation answers while verifying, through one
//! registered transport. The app registers its client with
//! [`set_http_client`]. The core resolves every certificate-published
//! host through [`HttpClient::resolve`], refuses any answer that is not
//! a public unicast address, and hands the vetted addresses to
//! [`HttpClient::get`] and [`HttpClient::post`]; the client connects to
//! one of them and follows a redirect only to a target
//! [`vet_destination`] accepts. A configured timestamp authority goes
//! through [`HttpClient::post_authority`] unvetted, and its redirect is
//! allowed only when [`authority_redirect_ok`] says so.

use core::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use refineid_doc_sign::http::{self, HttpError, HttpTransport};
use refineid_doc_sign::uri::Uri;

/// Why one request got no body.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum HttpFailure {
    /// The URL does not parse as HTTP or HTTPS.
    BadUrl,
    /// The name resolved to nothing, the connection failed, or the
    /// exchange broke off; `retryable` when a fresh attempt may succeed
    /// without changing anything.
    Transport {
        /// Whether the same request may be repeated.
        retryable: bool,
    },
    /// The server answered with a status outside 2xx.
    Status {
        /// The status code.
        code: u16,
    },
    /// The body exceeded the caller's bound.
    BodyTooLarge,
    /// A redirect target resolved to a non-public address.
    UnsafeDestination,
    /// A redirect crossed a policy boundary or exceeded its hop budget.
    UnsafeRedirect,
}

impl fmt::Display for HttpFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for HttpFailure {}

/// The `io::ErrorKind` a retryable transport failure is reported as.
const RETRYABLE_IO_KIND: io::ErrorKind = io::ErrorKind::ConnectionReset;
/// The `io::ErrorKind` a transport failure not worth repeating is
/// reported as.
const FINAL_IO_KIND: io::ErrorKind = io::ErrorKind::Other;
/// The reason phrase of a status the client reports; the client keeps
/// the server's own.
const STATUS_REASON: &str = "";
/// The body bound the core states when the client reports an oversized
/// body; the client has not read the body, so its length is unknown.
const UNKNOWN_BODY_LENGTH: usize = 0;

impl From<HttpFailure> for HttpError {
    fn from(failure: HttpFailure) -> Self {
        match failure {
            HttpFailure::BadUrl => Self::BadUrl("the client refused the URL"),
            HttpFailure::Transport { retryable: true } => {
                Self::Io(io::Error::from(RETRYABLE_IO_KIND))
            }
            HttpFailure::Transport { retryable: false } => Self::Io(io::Error::from(FINAL_IO_KIND)),
            HttpFailure::Status { code } => Self::HttpStatus {
                code,
                reason: STATUS_REASON.to_owned(),
                location: None,
            },
            HttpFailure::BodyTooLarge => Self::BodyTooLarge {
                content_length: UNKNOWN_BODY_LENGTH,
                limit: UNKNOWN_BODY_LENGTH,
            },
            HttpFailure::UnsafeDestination => {
                Self::UnsafeDestination("the client refused the destination".to_owned())
            }
            HttpFailure::UnsafeRedirect => {
                Self::UnsafeRedirect("the client refused the redirect".to_owned())
            }
        }
    }
}

/// The core's failure in the client's vocabulary, for [`vet_destination`].
impl From<HttpError> for HttpFailure {
    fn from(error: HttpError) -> Self {
        match error {
            HttpError::BadUrl(_) | HttpError::UnsupportedScheme(_) => Self::BadUrl,
            HttpError::Io(_) => Self::Transport { retryable: true },
            HttpError::HttpStatus { code, .. } => Self::Status { code },
            HttpError::BodyTooLarge { .. } => Self::BodyTooLarge,
            HttpError::UnsafeDestination(_) => Self::UnsafeDestination,
            HttpError::UnsafeRedirect(_) => Self::UnsafeRedirect,
            HttpError::Https { retryable, .. } => Self::Transport { retryable },
            HttpError::BadStatusLine(_)
            | HttpError::UnknownBodyLength
            | HttpError::BadChunkSize(_)
            | HttpError::InsecureCredentials => Self::Transport { retryable: false },
        }
    }
}

/// The app's HTTP client. It resolves names with the resolver the
/// platform trusts, names itself in every request it sends, and reads
/// at most `max_bytes` of a body.
#[uniffi::export(with_foreign)]
pub trait HttpClient: Send + Sync {
    /// The IP addresses `host` (a name or an address literal) resolves
    /// to, each as text.
    ///
    /// # Errors
    /// The resolver's failure.
    fn resolve(&self, host: String) -> Result<Vec<String>, HttpFailure>;

    /// GET `url`, connecting to one of `addresses`, the vetted answers
    /// of [`Self::resolve`] for its host; a redirect connects only to
    /// what [`vet_destination`] returns for its target.
    ///
    /// # Errors
    /// Why there is no body.
    fn get(
        &self,
        url: String,
        addresses: Vec<String>,
        max_bytes: u64,
    ) -> Result<Vec<u8>, HttpFailure>;

    /// POST `body` as `content_type` to `url`, connecting as
    /// [`Self::get`] does.
    ///
    /// # Errors
    /// Why there is no body.
    fn post(
        &self,
        url: String,
        addresses: Vec<String>,
        content_type: String,
        body: Vec<u8>,
        max_bytes: u64,
    ) -> Result<Vec<u8>, HttpFailure>;

    /// POST `body` to a configured timestamp authority, resolving the
    /// host itself, with `authorization` as the `Authorization` header
    /// when given; a redirect is followed only when
    /// [`authority_redirect_ok`] allows it.
    ///
    /// # Errors
    /// Why there is no body.
    fn post_authority(
        &self,
        url: String,
        content_type: String,
        body: Vec<u8>,
        max_bytes: u64,
        authorization: Option<String>,
    ) -> Result<Vec<u8>, HttpFailure>;
}

/// The registered client, kept here as well as in the core's transport
/// slot: the core has no entry point that vets a destination through
/// its registered transport, so [`vet_destination`] vets through this.
static CLIENT: RwLock<Option<Arc<dyn HttpClient>>> = RwLock::new(None);

/// Register `client` as the transport of every signing and verification
/// in this process; the latest registration serves.
#[uniffi::export]
pub fn set_http_client(client: Arc<dyn HttpClient>) {
    if let Ok(mut slot) = CLIENT.write() {
        *slot = Some(Arc::clone(&client));
    }
    http::set_http_transport(Box::new(ClientTransport { client }));
}

/// The addresses the core accepts for `url`'s host, resolved through
/// the registered client: every answer is a public unicast address. The
/// client calls this for each redirect target of a certificate-published
/// URL and connects to one of the answers.
///
/// # Errors
/// [`HttpFailure::UnsafeDestination`] when the host resolves to nothing
/// or to any non-public address; the resolver's failure;
/// [`HttpFailure::BadUrl`]; or a transport failure when no client is
/// registered.
#[uniffi::export]
pub fn vet_destination(url: String) -> Result<Vec<String>, HttpFailure> {
    let url = Uri::parse(url).map_err(|_error| HttpFailure::BadUrl)?;
    let client = CLIENT
        .read()
        .ok()
        .and_then(|slot| slot.clone())
        .ok_or(HttpFailure::Transport { retryable: false })?;
    let addresses = http::guard_destination(&ClientTransport { client }, &url)?;
    Ok(address_texts(&addresses))
}

/// Whether a timestamp authority at `from` may redirect to `to`: the
/// same origin, or the same host upgraded from HTTP to HTTPS.
#[uniffi::export]
pub fn authority_redirect_ok(from: String, to: String) -> bool {
    match (Uri::parse(from), Uri::parse(to)) {
        (Ok(from), Ok(to)) => http::authority_redirect_ok(&from, &to),
        (Err(_), _) | (_, Err(_)) => false,
    }
}

/// The app's client as the core's transport.
pub(crate) struct ClientTransport {
    /// The app's client.
    client: Arc<dyn HttpClient>,
}

impl ClientTransport {
    /// The core's transport over `client`.
    #[cfg(test)]
    pub(crate) const fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

/// `addresses` as the client takes them: the address text of each.
fn address_texts(addresses: &[SocketAddr]) -> Vec<String> {
    addresses
        .iter()
        .map(|address| address.ip().to_string())
        .collect()
}

/// `max_bytes` as the client takes it.
fn bound(max_bytes: usize) -> u64 {
    u64::try_from(max_bytes).unwrap_or(u64::MAX)
}

impl HttpTransport for ClientTransport {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, HttpError> {
        self.client
            .resolve(host.to_owned())?
            .iter()
            .map(|text| {
                text.parse::<IpAddr>()
                    .map(|ip| SocketAddr::new(ip, port))
                    .map_err(|_error| {
                        HttpError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "the client's resolver answered with something other than an address",
                        ))
                    })
            })
            .collect()
    }

    fn get(
        &self,
        url: &Uri,
        addresses: &[SocketAddr],
        max_bytes: usize,
    ) -> Result<Vec<u8>, HttpError> {
        Ok(self
            .client
            .get(url.to_string(), address_texts(addresses), bound(max_bytes))?)
    }

    fn post(
        &self,
        url: &Uri,
        addresses: &[SocketAddr],
        content_type: &str,
        body: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>, HttpError> {
        Ok(self.client.post(
            url.to_string(),
            address_texts(addresses),
            content_type.to_owned(),
            body.to_vec(),
            bound(max_bytes),
        )?)
    }

    fn post_authority(
        &self,
        url: &Uri,
        content_type: &str,
        body: &[u8],
        max_bytes: usize,
        auth_header: Option<&str>,
    ) -> Result<Vec<u8>, HttpError> {
        Ok(self.client.post_authority(
            url.to_string(),
            content_type.to_owned(),
            body.to_vec(),
            bound(max_bytes),
            auth_header.map(str::to_owned),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientTransport, HttpClient, HttpError, HttpFailure, HttpTransport, authority_redirect_ok,
    };
    use refineid_doc_sign::uri::Uri;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    /// A public unicast address (Quad9 resolver).
    const PUBLIC_V4: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
    /// The port the tests resolve for.
    const PORT: u16 = 80;
    /// The body bound the tests pass.
    const MAX_BYTES: usize = 16;
    /// What the scripted client answers every request with.
    const BODY: &[u8] = b"answer";
    /// The content type the tests post.
    const CONTENT_TYPE: &str = "application/octet-stream";
    /// A status the scripted client refuses with.
    const REFUSED_STATUS: u16 = 503;

    /// What the scripted client saw of the last request.
    #[derive(Default)]
    struct Seen {
        url: String,
        addresses: Vec<String>,
        max_bytes: u64,
        authorization: Option<String>,
    }

    /// A client that answers resolves with `answers`, records requests
    /// and serves [`BODY`], or refuses with `refusal`.
    struct ScriptedClient {
        answers: Vec<String>,
        refusal: Option<HttpFailure>,
        seen: Mutex<Seen>,
    }

    impl ScriptedClient {
        fn serving(answers: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                answers: answers.iter().map(|text| (*text).to_owned()).collect(),
                refusal: None,
                seen: Mutex::new(Seen::default()),
            })
        }

        fn refusing(refusal: HttpFailure) -> Arc<Self> {
            Arc::new(Self {
                answers: Vec::new(),
                refusal: Some(refusal),
                seen: Mutex::new(Seen::default()),
            })
        }

        fn record(&self, seen: Seen) -> Result<Vec<u8>, HttpFailure> {
            if let Ok(mut slot) = self.seen.lock() {
                *slot = seen;
            }
            self.refusal.clone().map_or(Ok(BODY.to_vec()), Err)
        }
    }

    impl HttpClient for ScriptedClient {
        fn resolve(&self, _host: String) -> Result<Vec<String>, HttpFailure> {
            self.refusal.clone().map_or(Ok(self.answers.clone()), Err)
        }

        fn get(
            &self,
            url: String,
            addresses: Vec<String>,
            max_bytes: u64,
        ) -> Result<Vec<u8>, HttpFailure> {
            self.record(Seen {
                url,
                addresses,
                max_bytes,
                authorization: None,
            })
        }

        fn post(
            &self,
            url: String,
            addresses: Vec<String>,
            _content_type: String,
            _body: Vec<u8>,
            max_bytes: u64,
        ) -> Result<Vec<u8>, HttpFailure> {
            self.record(Seen {
                url,
                addresses,
                max_bytes,
                authorization: None,
            })
        }

        fn post_authority(
            &self,
            url: String,
            _content_type: String,
            _body: Vec<u8>,
            max_bytes: u64,
            authorization: Option<String>,
        ) -> Result<Vec<u8>, HttpFailure> {
            self.record(Seen {
                url,
                addresses: Vec::new(),
                max_bytes,
                authorization,
            })
        }
    }

    fn uri(text: &str) -> Uri {
        Uri::parse(text.to_owned()).expect("test URL parses")
    }

    #[test]
    fn resolved_texts_become_socket_addresses_with_the_port() {
        let client = ScriptedClient::serving(&["9.9.9.9", "2620:fe::fe"]);
        let transport = ClientTransport::new(client);
        let resolved = transport
            .resolve("public.example", PORT)
            .expect("two addresses");
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0], SocketAddr::new(IpAddr::V4(PUBLIC_V4), PORT));
        assert!(resolved.iter().all(|address| address.port() == PORT));
    }

    #[test]
    fn a_resolver_answer_that_is_no_address_is_a_transport_failure() {
        let client = ScriptedClient::serving(&["not an address"]);
        let transport = ClientTransport::new(client);
        assert!(matches!(
            transport.resolve("public.example", PORT),
            Err(HttpError::Io(_))
        ));
    }

    #[test]
    fn the_vetted_addresses_and_the_bound_reach_the_client() {
        let client = ScriptedClient::serving(&[]);
        let transport = ClientTransport::new(Arc::clone(&client) as Arc<dyn HttpClient>);
        let vetted = [SocketAddr::new(IpAddr::V4(PUBLIC_V4), PORT)];
        let body = transport
            .get(&uri("http://public.example/crl"), &vetted, MAX_BYTES)
            .expect("the body");
        assert_eq!(body, BODY);
        let seen = client.seen.lock().expect("recorded");
        assert_eq!(seen.url, "http://public.example/crl");
        assert_eq!(seen.addresses, vec![PUBLIC_V4.to_string()]);
        assert_eq!(seen.max_bytes, u64::try_from(MAX_BYTES).expect("fits"));
    }

    #[test]
    fn an_authority_post_carries_the_authorization_and_no_addresses() {
        let client = ScriptedClient::serving(&[]);
        let transport = ClientTransport::new(Arc::clone(&client) as Arc<dyn HttpClient>);
        transport
            .post_authority(
                &uri("https://tsa.example/"),
                CONTENT_TYPE,
                b"request",
                MAX_BYTES,
                Some("Basic abc"),
            )
            .expect("the body");
        let seen = client.seen.lock().expect("recorded");
        assert!(seen.addresses.is_empty());
        assert_eq!(seen.authorization.as_deref(), Some("Basic abc"));
    }

    #[test]
    fn a_client_refusal_is_the_core_failure_of_the_same_name() {
        let client = ScriptedClient::refusing(HttpFailure::Status {
            code: REFUSED_STATUS,
        });
        let transport = ClientTransport::new(client);
        let vetted = [SocketAddr::new(IpAddr::V4(PUBLIC_V4), PORT)];
        let error = transport
            .post(
                &uri("http://public.example/ocsp"),
                &vetted,
                CONTENT_TYPE,
                b"request",
                MAX_BYTES,
            )
            .expect_err("refused");
        assert!(matches!(
            error,
            HttpError::HttpStatus {
                code: REFUSED_STATUS,
                ..
            }
        ));
        assert!(error.is_retryable_authority_failure());
        assert!(
            HttpError::from(HttpFailure::Transport { retryable: true })
                .is_retryable_authority_failure()
        );
        assert!(
            !HttpError::from(HttpFailure::Transport { retryable: false })
                .is_retryable_authority_failure()
        );
        assert!(matches!(
            HttpError::from(HttpFailure::UnsafeRedirect),
            HttpError::UnsafeRedirect(_)
        ));
    }

    #[test]
    fn every_core_failure_has_a_client_name() {
        assert_eq!(
            HttpFailure::from(HttpError::UnsafeDestination(String::new())),
            HttpFailure::UnsafeDestination
        );
        assert_eq!(
            HttpFailure::from(HttpError::BadUrl("")),
            HttpFailure::BadUrl
        );
        assert_eq!(
            HttpFailure::from(HttpError::UnknownBodyLength),
            HttpFailure::Transport { retryable: false }
        );
    }

    #[test]
    fn an_authority_redirect_stays_on_its_origin() {
        assert!(authority_redirect_ok(
            "https://tsa.example/".to_owned(),
            "https://tsa.example/qualified".to_owned()
        ));
        assert!(!authority_redirect_ok(
            "https://tsa.example/".to_owned(),
            "https://other.example/".to_owned()
        ));
        assert!(!authority_redirect_ok(
            "not a url".to_owned(),
            "https://tsa.example/".to_owned()
        ));
    }
}
