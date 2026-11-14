//! The network probes of the site check. Each returns an outcome;
//! `evaluate` turns outcomes into checks. None of them needs a privilege.
use std::{
    io,
    net::{IpAddr, SocketAddr, TcpStream},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, Utc};
use rand::RngCore;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use tokio::{net::UdpSocket, time::timeout};

pub(super) const TIMEOUT: Duration = Duration::from_secs(6);
const NTP_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_HTTP_BODY: usize = 4096;
/// The time servers of the NixOS default configuration
/// (`networking.timeServers`), after those the school's DHCP hands out.
const DEFAULT_NTP_SERVERS: [&str; 2] = ["0.nixos.pool.ntp.org", "1.nixos.pool.ntp.org"];
const MAX_NTP_SERVERS: usize = 3;
const NETWORKD_LEASES: &str = "/run/systemd/netif/leases";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    Resolved(Vec<IpAddr>),
    NotResolved,
}

pub(crate) async fn resolve(host: &str, port: u16) -> Resolution {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Resolution::Resolved(vec![address]);
    }
    match timeout(TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(addresses)) => {
            let mut found: Vec<IpAddr> = addresses.map(|address| address.ip()).collect();
            // IPv4 first: schools rarely route IPv6 to the internet.
            found.sort_by_key(|address| address.is_ipv6());
            found.dedup();
            if found.is_empty() {
                Resolution::NotResolved
            } else {
                Resolution::Resolved(found)
            }
        }
        _ => Resolution::NotResolved,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateProblem {
    UnknownIssuer,
    WrongName,
    Expired,
    NotYetValid,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TlsOutcome {
    Trusted,
    NotResolved,
    Unreachable,
    Refused,
    Untrusted {
        problem: CertificateProblem,
        issuer: Option<String>,
    },
    HandshakeFailed,
}

/// A TLS handshake with `host:port`, verified against the public roots and
/// `extra_ca` (PEM). On failure the certificate the server presented is
/// kept, so an intercepting proxy can be named by its issuer.
pub(crate) async fn tls(host: String, port: u16, extra_ca: Option<String>) -> TlsOutcome {
    let addresses = match resolve(&host, port).await {
        Resolution::Resolved(addresses) => addresses,
        Resolution::NotResolved => return TlsOutcome::NotResolved,
    };
    tokio::task::spawn_blocking(move || handshake(&host, port, &addresses, extra_ca.as_deref()))
        .await
        .unwrap_or(TlsOutcome::HandshakeFailed)
}

fn handshake(host: &str, port: u16, addresses: &[IpAddr], extra_ca: Option<&str>) -> TlsOutcome {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let Ok(inner) =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots(extra_ca)), provider.clone())
            .build()
    else {
        return TlsOutcome::HandshakeFailed;
    };
    let presented = Arc::new(Mutex::new(Vec::new()));
    let verifier = Arc::new(Recording {
        inner,
        presented: presented.clone(),
    });
    let Ok(builder) =
        ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()
    else {
        return TlsOutcome::HandshakeFailed;
    };
    let config = Arc::new(
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    );
    let Ok(name) = ServerName::try_from(host.to_string()) else {
        return TlsOutcome::HandshakeFailed;
    };
    let mut outcome = TlsOutcome::Unreachable;
    for address in addresses.iter().take(3) {
        let mut stream = match TcpStream::connect_timeout(&SocketAddr::new(*address, port), TIMEOUT)
        {
            Ok(stream) => stream,
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                outcome = TlsOutcome::Refused;
                continue;
            }
            Err(_) => continue,
        };
        let _ = stream.set_read_timeout(Some(TIMEOUT));
        let _ = stream.set_write_timeout(Some(TIMEOUT));
        let Ok(mut connection) = ClientConnection::new(config.clone(), name.clone()) else {
            return TlsOutcome::HandshakeFailed;
        };
        while connection.is_handshaking() {
            if let Err(error) = connection.complete_io(&mut stream) {
                return tls_failure(&error, &presented);
            }
        }
        return TlsOutcome::Trusted;
    }
    outcome
}

fn tls_failure(error: &io::Error, presented: &Mutex<Vec<CertificateDer<'static>>>) -> TlsOutcome {
    use rustls::CertificateError as Certificate;
    let Some(rustls::Error::InvalidCertificate(problem)) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TlsOutcome::Unreachable,
            _ => TlsOutcome::HandshakeFailed,
        };
    };
    let problem = match problem {
        Certificate::UnknownIssuer | Certificate::BadSignature => CertificateProblem::UnknownIssuer,
        Certificate::NotValidForName | Certificate::NotValidForNameContext { .. } => {
            CertificateProblem::WrongName
        }
        Certificate::Expired | Certificate::ExpiredContext { .. } => CertificateProblem::Expired,
        Certificate::NotValidYet | Certificate::NotValidYetContext { .. } => {
            CertificateProblem::NotYetValid
        }
        _ => CertificateProblem::Other,
    };
    let issuer = presented
        .lock()
        .ok()
        .and_then(|chain| chain.first().and_then(|leaf| issuer_name(leaf)));
    TlsOutcome::Untrusted { problem, issuer }
}

fn roots(extra_ca: Option<&str>) -> RootCertStore {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Some(pem) = extra_ca {
        for certificate in CertificateDer::pem_slice_iter(pem.as_bytes()).flatten() {
            let _ = roots.add(certificate);
        }
    }
    roots
}

/// Verifies like rustls's WebPKI verifier and keeps what the server presented.
#[derive(Debug)]
struct Recording {
    inner: Arc<WebPkiServerVerifier>,
    presented: Arc<Mutex<Vec<CertificateDer<'static>>>>,
}

impl ServerCertVerifier for Recording {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut presented) = self.presented.lock() {
            *presented = std::iter::once(end_entity)
                .chain(intermediates)
                .take(8)
                .map(|certificate| certificate.clone().into_owned())
                .collect();
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The issuer's common name (or organization) of a DER certificate.
pub(super) fn issuer_name(certificate: &[u8]) -> Option<String> {
    let (body, _) = der(certificate, 0x30)?;
    let (tbs, _) = der(body, 0x30)?;
    let mut rest = tbs;
    if rest.first() == Some(&0xa0) {
        rest = der_any(rest)?.2;
    }
    rest = der_any(rest)?.2; // serial number
    rest = der_any(rest)?.2; // signature algorithm
    let (mut names, _) = der(rest, 0x30)?;
    let (mut common, mut organization) = (None, None);
    while !names.is_empty() {
        let (mut set, next) = der(names, 0x31)?;
        names = next;
        while !set.is_empty() {
            let (attribute, next) = der(set, 0x30)?;
            set = next;
            let (oid, value) = der(attribute, 0x06)?;
            let (tag, value, _) = der_any(value)?;
            if !matches!(tag, 0x0c | 0x13 | 0x14 | 0x16) {
                continue;
            }
            let text = String::from_utf8_lossy(value).into_owned();
            match oid {
                [0x55, 0x04, 0x03] => common = Some(text),
                [0x55, 0x04, 0x0a] => organization = Some(text),
                _ => {}
            }
        }
    }
    let name: String = common
        .or(organization)?
        .chars()
        .filter(|character| !character.is_control())
        .take(80)
        .collect();
    (!name.trim().is_empty()).then(|| name.trim().to_string())
}

fn der(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (found, content, rest) = der_any(input)?;
    (found == tag).then_some((content, rest))
}

fn der_any(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)? as usize;
    let (length, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for byte in input.get(2..2 + count)? {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    Some((tag, input.get(header..end)?, input.get(end..)?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Clock {
    Synchronized,
    NotSynchronized,
    Unknown,
}

/// The kernel's synchronization state (read-only `adjtimex`).
pub(crate) fn clock() -> Clock {
    // SAFETY: `timex` is plain data; modes 0 only reads the kernel state.
    let mut value: libc::timex = unsafe { std::mem::zeroed() };
    value.modes = 0;
    let state = unsafe { libc::adjtimex(&mut value) };
    if state < 0 {
        Clock::Unknown
    } else if state == libc::TIME_ERROR || value.status & libc::STA_UNSYNC != 0 {
        Clock::NotSynchronized
    } else {
        Clock::Synchronized
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NtpOutcome {
    Answered,
    NoAnswer,
    NotResolved,
}

/// Time servers the Nest uses: those of its DHCP leases, then the defaults.
pub(crate) fn ntp_servers(leases: &Path) -> Vec<String> {
    let mut servers = Vec::new();
    if let Ok(entries) = std::fs::read_dir(leases) {
        for entry in entries.flatten().take(16) {
            let mut text = String::new();
            let Ok(file) = std::fs::File::open(entry.path()) else {
                continue;
            };
            if io::Read::read_to_string(&mut io::Read::take(file, 64 * 1024), &mut text).is_err() {
                continue;
            }
            for line in text.lines() {
                if let Some(value) = line.strip_prefix("NTP=") {
                    servers.extend(value.split_whitespace().map(str::to_string));
                }
            }
        }
    }
    servers.extend(DEFAULT_NTP_SERVERS.iter().map(|server| server.to_string()));
    let mut unique = Vec::new();
    for server in servers {
        if super::valid_host(&server) && !unique.contains(&server) {
            unique.push(server);
        }
    }
    unique.truncate(MAX_NTP_SERVERS);
    unique
}

pub(crate) fn default_leases_dir() -> &'static Path {
    Path::new(NETWORKD_LEASES)
}

/// One NTP client request to `server`; an answer is a valid server reply
/// echoing this request.
pub(crate) async fn ntp(server: &str) -> NtpOutcome {
    let addresses = match resolve(server, 123).await {
        Resolution::Resolved(addresses) => addresses,
        Resolution::NotResolved => return NtpOutcome::NotResolved,
    };
    for address in addresses.into_iter().take(2) {
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let Ok(socket) = UdpSocket::bind(bind).await else {
            continue;
        };
        let mut request = [0u8; 48];
        request[0] = 0x23; // version 4, client
        rand::rngs::OsRng.fill_bytes(&mut request[40..48]);
        if socket
            .send_to(&request, SocketAddr::new(address, 123))
            .await
            .is_err()
        {
            continue;
        }
        let mut answer = [0u8; 512];
        if let Ok(Ok((length, _))) = timeout(NTP_TIMEOUT, socket.recv_from(&mut answer)).await {
            if valid_ntp_answer(&request, &answer[..length]) {
                return NtpOutcome::Answered;
            }
        }
    }
    NtpOutcome::NoAnswer
}

pub(super) fn valid_ntp_answer(request: &[u8; 48], answer: &[u8]) -> bool {
    answer.len() >= 48
        && answer[0] & 0x07 == 4
        && answer[0] >> 6 != 3
        && (1..=15).contains(&answer[1])
        && answer[24..32] == request[40..48]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpAnswer {
    pub(crate) status: u16,
    pub(crate) date: Option<DateTime<Utc>>,
    pub(crate) body_matches: bool,
}

/// GET `url` without redirects; `None` when no HTTP answer arrived.
pub(crate) async fn http_get(url: &str, expect: &str) -> Option<HttpAnswer> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let mut response = client.get(url).send().await.ok()?;
    let status = response.status().as_u16();
    let date = response
        .headers()
        .get(reqwest::header::DATE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| DateTime::parse_from_rfc2822(value).ok())
        .map(|value| value.with_timezone(&Utc));
    let mut body = Vec::new();
    while body.len() < MAX_HTTP_BODY {
        match timeout(TIMEOUT, response.chunk()).await {
            Ok(Ok(Some(chunk))) => body.extend_from_slice(&chunk),
            _ => break,
        }
    }
    body.truncate(MAX_HTTP_BODY);
    Some(HttpAnswer {
        status,
        date,
        body_matches: String::from_utf8_lossy(&body).contains(expect),
    })
}
