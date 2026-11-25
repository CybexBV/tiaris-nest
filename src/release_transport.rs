//! Bounded, proxy-independent transport for signed public release artifacts.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use reqwest::{
    Client, Response, StatusCode, Url,
    dns::{Addrs, Name, Resolve, Resolving},
    header,
};
use tokio::net::lookup_host;

const MAX_REDIRECTS: usize = 5;
const REDIRECT_CACHE_TTL: Duration = Duration::from_secs(120);
const REDIRECT_CACHE_MAX_ENTRIES: usize = 16;

/// Custom DNS resolver enforcing the public-network (or explicit development
/// private-network) IP policy on every connection establishment inside a
/// pooled `reqwest::Client`. Rejects disallowed addresses before TCP connect
/// while letting keep-alive HTTP/1.1 and HTTP/2 connections stay pooled across
/// Range requests.
struct PolicyDnsResolver {
    allow_private_urls: bool,
}

impl Resolve for PolicyDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let allow_private_urls = self.allow_private_urls;
        Box::pin(async move {
            let addresses = lookup_host((host.as_str(), 0))
                .await
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?
                .collect::<BTreeSet<SocketAddr>>();
            if addresses.is_empty()
                || addresses
                    .iter()
                    .any(|address| !address_allowed(address.ip(), allow_private_urls))
            {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "signed release artifact host resolved to a disallowed address",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            let iter: Addrs = Box::new(addresses.into_iter());
            Ok(iter)
        })
    }
}

fn pooled_client(allow_private_urls: bool) -> Result<Client> {
    let build = || -> Result<Client> {
        let mut builder = Client::builder()
            .read_timeout(Duration::from_secs(90))
            .connect_timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(PolicyDnsResolver { allow_private_urls }));
        if !allow_private_urls {
            builder = builder
                .https_only(true)
                .min_tls_version(reqwest::tls::Version::TLS_1_2);
        }
        builder.build().context("build pooled release HTTP client")
    };
    if allow_private_urls {
        static PRIVATE: OnceLock<Client> = OnceLock::new();
        if let Some(client) = PRIVATE.get() {
            return Ok(client.clone());
        }
        let client = build()?;
        let _ = PRIVATE.set(client.clone());
        Ok(client)
    } else {
        static PUBLIC: OnceLock<Client> = OnceLock::new();
        if let Some(client) = PUBLIC.get() {
            return Ok(client.clone());
        }
        let client = build()?;
        let _ = PUBLIC.set(client.clone());
        Ok(client)
    }
}

#[derive(Clone)]
struct CachedRedirect {
    target: Url,
    expires_at: Instant,
}

fn redirect_cache() -> &'static Mutex<BTreeMap<(bool, String), CachedRedirect>> {
    static CACHE: OnceLock<Mutex<BTreeMap<(bool, String), CachedRedirect>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn cached_redirect_target(allow_private_urls: bool, origin: &str) -> Option<Url> {
    let mut guard = redirect_cache().lock().ok()?;
    let key = (allow_private_urls, origin.to_string());
    let now = Instant::now();
    if let Some(entry) = guard.get(&key) {
        if entry.expires_at > now {
            return Some(entry.target.clone());
        }
        guard.remove(&key);
    }
    None
}

fn store_redirect_target(allow_private_urls: bool, origin: &str, target: Url) {
    if let Ok(mut guard) = redirect_cache().lock() {
        let now = Instant::now();
        guard.retain(|_, entry| entry.expires_at > now);
        if guard.len() >= REDIRECT_CACHE_MAX_ENTRIES {
            guard.clear();
        }
        guard.insert(
            (allow_private_urls, origin.to_string()),
            CachedRedirect {
                target,
                expires_at: now + REDIRECT_CACHE_TTL,
            },
        );
    }
}

fn invalidate_redirect_target(allow_private_urls: bool, origin: &str) {
    if let Ok(mut guard) = redirect_cache().lock() {
        guard.remove(&(allow_private_urls, origin.to_string()));
    }
}

/// Fetch a signed release artifact while re-applying the public-network policy
/// to every redirect hop. DNS resolution is validated on every connect inside
/// a pooled client, so connections stay alive across Range requests while
/// private addresses remain blocked.
pub(crate) async fn get(
    value: &str,
    allow_private_urls: bool,
    follow_redirects: bool,
    timeout: Duration,
    range_offset: Option<u64>,
) -> Result<Response> {
    let range = range_offset
        .filter(|offset| *offset > 0)
        .map(|offset| format!("bytes={offset}-"));
    request(value, allow_private_urls, follow_redirects, timeout, range).await
}

/// [`get`] of the bytes `first..=last` only.
pub(crate) async fn get_range(
    value: &str,
    allow_private_urls: bool,
    follow_redirects: bool,
    timeout: Duration,
    first: u64,
    last: u64,
) -> Result<Response> {
    let range = Some(format!("bytes={first}-{last}"));
    request(value, allow_private_urls, follow_redirects, timeout, range).await
}

async fn request(
    value: &str,
    allow_private_urls: bool,
    follow_redirects: bool,
    timeout: Duration,
    range: Option<String>,
) -> Result<Response> {
    let origin_url = Url::parse(value).context("parse signed release artifact URL")?;
    validate_url(&origin_url, allow_private_urls)?;
    if follow_redirects {
        if let Some(cached_target) = cached_redirect_target(allow_private_urls, value) {
            if validate_url(&cached_target, allow_private_urls).is_ok() {
                if let Ok(response) = send_once(
                    &cached_target,
                    allow_private_urls,
                    timeout,
                    range.as_deref(),
                )
                .await
                {
                    let status = response.status();
                    if !status.is_redirection()
                        && !status.is_server_error()
                        && !matches!(
                            status,
                            StatusCode::UNAUTHORIZED
                                | StatusCode::FORBIDDEN
                                | StatusCode::NOT_FOUND
                                | StatusCode::GONE
                        )
                    {
                        return Ok(response);
                    }
                }
                invalidate_redirect_target(allow_private_urls, value);
            }
        }
    }

    let mut url = origin_url;
    let mut redirected = false;
    for redirects in 0..=MAX_REDIRECTS {
        validate_url(&url, allow_private_urls)?;
        let response = send_once(&url, allow_private_urls, timeout, range.as_deref()).await?;
        if !response.status().is_redirection() || !follow_redirects {
            if redirected && (response.status().is_success()) {
                store_redirect_target(allow_private_urls, value, url);
            }
            return Ok(response);
        }
        if redirects == MAX_REDIRECTS {
            bail!("signed release artifact redirected too many times");
        }
        let location = response
            .headers()
            .get(header::LOCATION)
            .ok_or_else(|| anyhow!("signed release artifact redirect omitted Location"))?
            .to_str()
            .context("signed release artifact redirect Location is invalid")?;
        url = url
            .join(location)
            .context("resolve signed release artifact redirect Location")?;
        redirected = true;
    }
    unreachable!("bounded release redirect loop always returns")
}

async fn send_once(
    url: &Url,
    allow_private_urls: bool,
    timeout: Duration,
    range: Option<&str>,
) -> Result<Response> {
    validate_url(url, allow_private_urls)?;
    let client = pooled_client(allow_private_urls)?;
    let mut request = client
        .get(url.clone())
        .timeout(timeout)
        .header(header::ACCEPT_ENCODING, "identity");
    if let Some(range) = range {
        request = request.header(header::RANGE, range);
    }
    request
        .send()
        .await
        .context("download signed release artifact")
}

fn validate_url(url: &Url, allow_private_urls: bool) -> Result<()> {
    if (!allow_private_urls && url.scheme() != "https")
        || (allow_private_urls && !matches!(url.scheme(), "http" | "https"))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("signed release artifact redirect URL is unsafe");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("signed release artifact URL has no host"))?;
    let _port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("signed release artifact URL has no usable port"))?;
    // Literal IP hosts bypass DNS resolution in hyper/reqwest, so validate them
    // explicitly here before sending the request.
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        if !address_allowed(ip, allow_private_urls) {
            bail!("signed release artifact host resolved to a disallowed address");
        }
    }
    Ok(())
}

#[cfg(test)]
async fn client_for_url(
    url: Url,
    allow_private_urls: bool,
    _timeout: Duration,
) -> Result<(Client, Url)> {
    validate_url(&url, allow_private_urls)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("signed release artifact URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("signed release artifact URL has no usable port"))?;
    let addresses = lookup_host((host, port))
        .await
        .context("resolve signed release artifact host")?
        .collect::<BTreeSet<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !address_allowed(address.ip(), allow_private_urls))
    {
        bail!("signed release artifact host resolved to a disallowed address");
    }
    Ok((pooled_client(allow_private_urls)?, url))
}

pub(crate) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)))
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(ipv4));
            }
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || segments[0] & 0xe000 != 0x2000
                || segments[0] == 0x2002
                || (segments[0] == 0x2001 && segments[1] == 0x0000)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x2001 && segments[1] == 0x0002)
                || (segments[0] == 0x2001 && (0x0010..=0x002f).contains(&segments[1])))
        }
    }
}

fn address_allowed(ip: IpAddr, allow_private_urls: bool) -> bool {
    public_ip(ip) || (allow_private_urls && development_private_ip(ip))
}

fn development_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || ip.is_unique_local() || ip.is_loopback(),
            |ipv4| development_private_ip(IpAddr::V4(ipv4)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn one_response(listener: TcpListener, response: Vec<u8>) -> String {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let read = stream.read(&mut request).await.unwrap();
        stream.write_all(&response).await.unwrap();
        String::from_utf8_lossy(&request[..read]).into_owned()
    }

    #[tokio::test]
    async fn redirects_fetch_the_target_without_forwarding_credentials() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!("http://{}/artifact", target.local_addr().unwrap());
        let target_task = tokio::spawn(one_response(
            target,
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsigned".to_vec(),
        ));
        let redirect = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let start_url = format!("http://{}/signed", redirect.local_addr().unwrap());
        let redirect_task = tokio::spawn(one_response(redirect, format!(
            "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ).into_bytes()));
        let response = get(&start_url, true, true, Duration::from_secs(5), None)
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"signed");
        for request in [redirect_task.await.unwrap(), target_task.await.unwrap()] {
            let lower = request.to_ascii_lowercase();
            assert!(!lower.contains("authorization:"));
            assert!(!lower.contains("cookie:"));
            assert!(!lower.contains("proxy-authorization:"));
        }
    }

    #[tokio::test]
    async fn public_policy_rejects_http_downgrade_and_private_redirect_hops() {
        for value in [
            "http://8.8.8.8/artifact",
            "https://127.0.0.1/artifact",
            "https://[::1]/artifact",
            "https://169.254.169.254/artifact",
        ] {
            assert!(
                client_for_url(Url::parse(value).unwrap(), false, Duration::from_secs(5))
                    .await
                    .is_err(),
                "unsafe public redirect hop accepted: {value}"
            );
        }
    }

    #[tokio::test]
    async fn redirect_chain_stops_at_the_five_hop_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/loop", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for _ in 0..=MAX_REDIRECTS {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; b"GET /loop HTTP/1.1".len()];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"GET /loop HTTP/1.1");
                stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            }
        });
        let error = get(&url, true, true, Duration::from_secs(5), None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("redirected too many times"));
        server.await.unwrap();
    }

    #[test]
    fn development_override_allows_only_public_private_or_loopback_addresses() {
        for value in [
            "8.8.8.8",
            "2606:4700:4700::1111",
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                address_allowed(value.parse().unwrap(), true),
                "development address should be allowed: {value}"
            );
        }
        for value in [
            "0.0.0.0",
            "100.64.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "::",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2002:0a00:0001::",
            "::ffff:169.254.169.254",
        ] {
            assert!(
                !address_allowed(value.parse().unwrap(), true),
                "special development address must be rejected: {value}"
            );
        }
        assert!(!address_allowed("10.0.0.1".parse().unwrap(), false));
        assert!(address_allowed("8.8.8.8".parse().unwrap(), false));
    }

    #[tokio::test]
    async fn redirect_cache_reuses_target_and_invalidates_on_forbidden() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let target_hits = Arc::new(AtomicUsize::new(0));
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!(
            "http://{}/artifact-v1",
            target_listener.local_addr().unwrap()
        );
        let hits = target_hits.clone();
        let target_server = tokio::spawn(async move {
            for attempt in 0..3 {
                let (mut stream, _) = target_listener.accept().await.unwrap();
                let mut req = [0_u8; 4096];
                let _ = stream.read(&mut req).await.unwrap();
                hits.fetch_add(1, Ordering::SeqCst);
                let body = if attempt == 2 {
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .as_slice()
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                        .as_slice()
                };
                stream.write_all(body).await.unwrap();
            }
        });

        let fresh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fresh_url = format!(
            "http://{}/artifact-v2",
            fresh_listener.local_addr().unwrap()
        );
        let fresh_server = tokio::spawn(one_response(
            fresh_listener,
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnew".to_vec(),
        ));

        let redirect_hits = Arc::new(AtomicUsize::new(0));
        let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let start_url = format!("http://{}/signed", redirect_listener.local_addr().unwrap());
        let rhits = redirect_hits.clone();
        let redirect_server = tokio::spawn(async move {
            for location in [&target_url, &fresh_url] {
                let (mut stream, _) = redirect_listener.accept().await.unwrap();
                let mut req = [0_u8; 4096];
                let _ = stream.read(&mut req).await.unwrap();
                rhits.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        // 1st request: resolves redirect and caches target.
        let r1 = get(&start_url, true, true, Duration::from_secs(5), None)
            .await
            .unwrap();
        assert_eq!(r1.bytes().await.unwrap().as_ref(), b"ok");
        assert_eq!(redirect_hits.load(Ordering::SeqCst), 1);

        // 2nd request: hits cached target directly, skipping redirect server.
        let r2 = get(&start_url, true, true, Duration::from_secs(5), None)
            .await
            .unwrap();
        assert_eq!(r2.bytes().await.unwrap().as_ref(), b"ok");
        assert_eq!(redirect_hits.load(Ordering::SeqCst), 1);
        assert_eq!(target_hits.load(Ordering::SeqCst), 2);

        // 3rd request: cached target returns 403 -> invalidates cache and re-resolves redirect.
        let r3 = get(&start_url, true, true, Duration::from_secs(5), None)
            .await
            .unwrap();
        assert_eq!(r3.bytes().await.unwrap().as_ref(), b"new");
        assert_eq!(redirect_hits.load(Ordering::SeqCst), 2);

        target_server.await.unwrap();
        fresh_server.await.unwrap();
        redirect_server.await.unwrap();
    }
}
