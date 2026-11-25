//! Whether computers depend on this Nest right now.
//!
//! A Nest installs a prepared update once it served no computer and ran no
//! build for a quiet period (and in the night at the latest). Every boot,
//! netboot, install and cache request passes the daemon, so it alone can
//! tell. A cache or runtime file it hands to nginx (`assets::hand_file`)
//! counts until the client's connection to nginx closes, as nginx sends the
//! file after the daemon answered. Requests the Nest makes to itself, such as
//! its readiness check, serve no computer and do not count. It publishes
//! `/run/tiaris-nest/activity.json`; the root updater
//! (`tiaris-nest-appliance-update-window`) reads it and decides.
use std::{
    collections::{BTreeSet, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Result;
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::Response,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use tracing::warn;

use crate::AppState;

pub const ACTIVITY_PATH: &str = "/run/tiaris-nest/activity.json";
const SCHEMA: &str = "tiaris.nest.activity.v1";
const REFRESH: Duration = Duration::from_secs(20);
const MAX_BYTES: usize = 4 * 1024;

/// nginx's port (`nixos-appliance/nginx.nix`).
const NGINX_PORT: u16 = 80;

/// What the HTTP routes are serving right now.
pub struct Counter {
    in_flight: AtomicUsize,
    /// Unix seconds of the last moment a computer request was being served.
    last_served: AtomicI64,
    /// Client connections nginx is sending a handed-over file on, while the
    /// activity report follows them (only then are they ever let go).
    handed: Mutex<BTreeSet<SocketAddr>>,
    following: AtomicBool,
}

impl Counter {
    const fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            last_served: AtomicI64::new(0),
            handed: Mutex::new(BTreeSet::new()),
            following: AtomicBool::new(false),
        }
    }

    fn touch(&self) {
        self.last_served
            .fetch_max(Utc::now().timestamp(), Ordering::SeqCst);
    }

    fn handed(&self) -> std::sync::MutexGuard<'_, BTreeSet<SocketAddr>> {
        self.handed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn hand(&self, client: SocketAddr) {
        if self.following.load(Ordering::SeqCst) {
            self.handed().insert(client);
        }
    }

    /// Whether nginx may still be sending a handed-over file: its client's
    /// connection is open. A closed one ends its download now, never earlier
    /// than it did; one kept alive counts until nginx closes it (75 s idle at
    /// most). Without the list of open connections all of them still count.
    /// `open` lists them while the hand-overs are locked: a download handed
    /// over on a connection opened after a list was read is never let go by
    /// that list.
    fn sending(&self, open: impl FnOnce() -> std::io::Result<HashSet<SocketAddr>>) -> bool {
        let mut handed = self.handed();
        if handed.is_empty() {
            return false;
        }
        match open() {
            Ok(open) => {
                let before = handed.len();
                handed.retain(|client| open.contains(client));
                if handed.len() < before {
                    self.touch();
                }
            }
            Err(error) => {
                warn!(error = %error, "could not list nginx's connections; handed-over downloads still count");
            }
        }
        !handed.is_empty()
    }
}

static SERVED: Counter = Counter::new();
/// Unix seconds since when nothing kept the Nest busy, as last published;
/// 0 while something does or before the first report.
static IDLE_SINCE: AtomicI64 = AtomicI64::new(0);

/// How long nothing has kept the Nest busy, as of its last activity report
/// (at most `REFRESH` old). `None` while busy, and always on a Nest that does
/// not track its activity (not the NixOS appliance).
pub fn quiet_for(now: DateTime<Utc>) -> Option<chrono::Duration> {
    match IDLE_SINCE.load(Ordering::SeqCst) {
        0 => None,
        since => Some(chrono::Duration::seconds((now.timestamp() - since).max(0))),
    }
}

/// Whether the Nest has served no computer requests for at least
/// `min_quiet_seconds` and has no active requests in flight. Non-NixOS hosts
/// (unit tests and standalone setups) do not spawn the activity tracker and
/// return `true`.
pub fn is_idle_for_maintenance(min_quiet_seconds: i64) -> bool {
    if !crate::appliance::nixos::is_nixos() {
        return true;
    }
    if SERVED.in_flight.load(Ordering::SeqCst) > 0 {
        return false;
    }
    quiet_for(Utc::now()).is_some_and(|quiet| quiet.num_seconds() >= min_quiet_seconds)
}

/// Counts one request from its first byte until its body is finished or
/// dropped, so a long SquashFS or cache download keeps the Nest busy.
struct Served(&'static Counter);

impl Served {
    fn start(counter: &'static Counter) -> Self {
        counter.in_flight.fetch_add(1, Ordering::SeqCst);
        counter.touch();
        Self(counter)
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.0.touch();
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Tracked {
    inner: Body,
    _served: Served,
}

impl http_body::Body for Tracked {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<http_body::Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Health probes serve nobody; every other route serves a computer (boot
/// scripts, netboot, installer, USB stick, cache) unless the Nest itself asks.
fn counts(path: &str) -> bool {
    !path.starts_with("/healthz")
}

fn serves_a_computer(request: &Request) -> bool {
    let connect = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0);
    counts(request.uri().path()) && !crate::routes::is_own_request(request.headers(), connect)
}

pub async fn track(request: Request, next: Next) -> Response {
    track_with(&SERVED, request, next).await
}

async fn track_with(counter: &'static Counter, request: Request, next: Next) -> Response {
    if !serves_a_computer(&request) {
        return next.run(request).await;
    }
    let client = crate::routes::forwarded_connection(
        request.headers(),
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|value| value.0),
    );
    let served = Served::start(counter);
    let response = next.run(request).await;
    if let Some(client) = client.filter(|_| {
        response
            .headers()
            .contains_key(crate::assets::X_ACCEL_REDIRECT)
    }) {
        counter.hand(client);
    }
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(Tracked {
            inner: body,
            _served: served,
        }),
    )
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Report {
    schema: &'static str,
    written_at: String,
    /// Since when nothing kept the Nest busy, or `None` while something does.
    idle_since: Option<String>,
    busy: Vec<&'static str>,
}

/// Idle from the first quiet observation, but never before the last served
/// request: one that started and ended between two samples still counts.
fn next_idle_since(previous: Option<i64>, busy: bool, now: i64, last_served: i64) -> Option<i64> {
    if busy {
        None
    } else {
        Some(previous.unwrap_or(now).max(last_served))
    }
}

fn timestamp(seconds: i64) -> String {
    DateTime::<Utc>::from_timestamp(seconds, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// The client ends of established TCP connections to nginx, from
/// `/proc/net/tcp` and `/proc/net/tcp6`.
fn nginx_clients() -> std::io::Result<HashSet<SocketAddr>> {
    let mut clients = HashSet::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        match std::fs::read_to_string(table) {
            Ok(text) => clients.extend(established_clients(&text, NGINX_PORT)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(clients)
}

/// Remote ends of the established connections to `local_port` in one
/// `/proc/net/tcp*` table (addresses in hex, each 32-bit word in host order).
fn established_clients(table: &str, local_port: u16) -> impl Iterator<Item = SocketAddr> + '_ {
    const ESTABLISHED: &str = "01";
    table.lines().skip(1).filter_map(move |line| {
        let mut fields = line.split_whitespace().skip(1);
        let local = proc_endpoint(fields.next()?)?;
        let remote = proc_endpoint(fields.next()?)?;
        (fields.next()? == ESTABLISHED && local.port() == local_port).then_some(remote)
    })
}

fn proc_endpoint(value: &str) -> Option<SocketAddr> {
    let (address, port) = value.split_once(':')?;
    let word = |hex: &str| u32::from_str_radix(hex, 16).ok().map(u32::to_ne_bytes);
    let ip = match address.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(address)?)),
        32 => {
            let mut bytes = [0_u8; 16];
            for (chunk, hex) in bytes.chunks_mut(4).zip(address.as_bytes().chunks(4 * 2)) {
                chunk.copy_from_slice(&word(std::str::from_utf8(hex).ok()?)?);
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(
        ip.to_canonical(),
        u16::from_str_radix(port, 16).ok()?,
    ))
}

async fn busy_reasons(state: &AppState, now: DateTime<Utc>) -> Vec<&'static str> {
    let mut busy = Vec::new();
    if SERVED.in_flight.load(Ordering::SeqCst) > 0 || SERVED.sending(nginx_clients) {
        busy.push("serving_computers");
    }
    // Boot grants live ten minutes from a computer's start or install.
    match crate::console_status::count_active_installs(&state.db, now).await {
        Ok(0) => {}
        Ok(_) => busy.push("computers_starting"),
        Err(_) => busy.push("activity_unknown"),
    }
    match crate::db::active_build_job_count(&state.db).await {
        Ok(0) => {}
        Ok(_) => busy.push("building_apps"),
        Err(_) => busy.push("activity_unknown"),
    }
    busy.dedup();
    busy
}

fn write(report: &Report) -> Result<()> {
    let body = serde_json::to_vec(report)?;
    crate::public_status::write_public_json(std::path::Path::new(ACTIVITY_PATH), &body, MAX_BYTES)
}

/// Only the NixOS appliance gates updates on this report.
pub fn spawn(state: AppState) {
    if !crate::appliance::nixos::is_nixos() {
        return;
    }
    // nginx went on sending what the daemon handed over before it stopped:
    // every computer connected to nginx now counts until it disconnects.
    SERVED.following.store(true, Ordering::SeqCst);
    if let Ok(open) = nginx_clients() {
        SERVED
            .handed()
            .extend(open.into_iter().filter(|client| !client.ip().is_loopback()));
    }
    tokio::spawn(async move {
        // A daemon that just started has not seen the computers that were
        // mid-boot when it stopped; its quiet period starts now.
        SERVED.touch();
        let mut idle_since = None;
        loop {
            let now = Utc::now();
            let busy = busy_reasons(&state, now).await;
            idle_since = next_idle_since(
                idle_since,
                !busy.is_empty(),
                now.timestamp(),
                SERVED.last_served.load(Ordering::SeqCst),
            );
            IDLE_SINCE.store(idle_since.unwrap_or(0), Ordering::SeqCst);
            let report = Report {
                schema: SCHEMA,
                written_at: timestamp(now.timestamp()),
                idle_since: idle_since.map(timestamp),
                busy,
            };
            if let Err(error) = write(&report) {
                warn!(error = %error, "could not publish Nest activity; when-idle updates wait");
            }
            tokio::time::sleep(REFRESH).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use tower::ServiceExt;

    #[test]
    fn idle_starts_at_the_first_quiet_sample_or_the_last_request() {
        assert_eq!(next_idle_since(None, true, 100, 0), None);
        assert_eq!(next_idle_since(None, false, 100, 40), Some(100));
        assert_eq!(next_idle_since(Some(100), false, 160, 40), Some(100));
        // A request between two samples restarts the quiet period.
        assert_eq!(next_idle_since(Some(100), false, 160, 150), Some(150));
        assert_eq!(next_idle_since(Some(100), true, 180, 150), None);
    }

    #[test]
    fn only_health_probes_are_not_computer_traffic() {
        for path in ["/healthz", "/healthz/pxe"] {
            assert!(!counts(path));
        }
        for path in [
            "/boot.ipxe",
            "/boot/aa:bb",
            "/netboot/abc/nix-store.squashfs",
            "/cache/nar/x.nar.zst",
            "/files/x",
            "/usb-installer/v1/boot",
            "/boot-session/x/context.cpio",
        ] {
            assert!(counts(path), "{path}");
        }
    }

    #[tokio::test]
    async fn a_download_counts_until_its_body_is_gone() {
        static COUNTER: Counter = Counter::new();
        let app = Router::new()
            .route("/cache/x", get(|| async { "body" }))
            .route("/healthz", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(|request, next| {
                track_with(&COUNTER, request, next)
            }));
        let probe = app
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(COUNTER.in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(COUNTER.last_served.load(Ordering::SeqCst), 0);
        drop(probe);
        let response = app
            .oneshot(Request::get("/cache/x").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(COUNTER.in_flight.load(Ordering::SeqCst), 1);
        drop(response);
        assert!(COUNTER.last_served.load(Ordering::SeqCst) > 0);
        assert_eq!(COUNTER.in_flight.load(Ordering::SeqCst), 0);
    }

    /// nginx sends a handed-over file after the daemon answered: it counts
    /// until the client's connection to nginx closes. The Nest's own requests
    /// are never followed.
    #[tokio::test]
    async fn a_handed_over_download_counts_until_its_connection_closes() {
        static COUNTER: Counter = Counter::new();
        COUNTER.following.store(true, Ordering::SeqCst);
        let app = Router::new()
            .route(
                "/cache/x",
                get(|| async { ([("x-accel-redirect", "/_tiaris/cache/x")], "") }),
            )
            .layer(axum::middleware::from_fn(|request, next| {
                track_with(&COUNTER, request, next)
            }));
        let request = |client: &str| {
            let mut request = Request::get("/cache/x")
                .header("x-forwarded-for", client)
                .header("x-tiaris-client-port", "51000")
                .body(Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50200))));
            request
        };
        drop(app.clone().oneshot(request("127.0.0.1")).await.unwrap());
        drop(app.oneshot(request("192.0.2.55")).await.unwrap());
        assert_eq!(COUNTER.in_flight.load(Ordering::SeqCst), 0);
        let client: SocketAddr = "192.0.2.55:51000".parse().unwrap();
        assert_eq!(*COUNTER.handed(), BTreeSet::from([client]));

        assert!(COUNTER.sending(|| Ok(HashSet::from([client]))));
        assert!(
            COUNTER.sending(|| Err(std::io::Error::other("unreadable"))),
            "unknown connections still count"
        );
        COUNTER.last_served.store(0, Ordering::SeqCst);
        assert!(!COUNTER.sending(|| Ok(HashSet::new())));
        assert!(COUNTER.last_served.load(Ordering::SeqCst) > 0);
    }

    /// A download handed over on a connection that opened after nginx's
    /// connections were listed still counts: that list never lets it go.
    /// (The pause lets the hand-over run while the list is read; without the
    /// lock it was pruned and the Nest could restart during the download.)
    #[test]
    fn a_download_handed_over_while_connections_are_listed_still_counts() {
        static COUNTER: Counter = Counter::new();
        COUNTER.following.store(true, Ordering::SeqCst);
        let (waiting, other) = (
            "192.0.2.54:51000".parse().unwrap(),
            "192.0.2.55:51000".parse().unwrap(),
        );
        COUNTER.hand(waiting);
        let (listing, listed) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                listed.recv().unwrap();
                COUNTER.hand(other);
            });
            COUNTER.sending(|| {
                listing.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(50));
                Ok(HashSet::new())
            });
        });
        assert!(COUNTER.sending(|| Ok(HashSet::from([other]))));
    }

    /// A listener, two clients of nginx (one of them on an IPv6 socket), a
    /// closing connection and a connection to another port, as the x86 kernel
    /// prints them.
    #[test]
    fn nginx_clients_are_the_established_remote_ends_on_its_port() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue
   0: 00000000:0050 00000000:0000 0A 00000000:00000000
   1: 2A0200C0:0050 370200C0:C738 01 00000000:00000000
   2: 2A0200C0:0050 390200C0:C73A 08 00000000:00000000
   3: 0100007F:1F90 0100007F:C73B 01 00000000:00000000
";
        let tcp6 =
            "  sl  local_address                         remote_address                        st
   0: 0000000000000000FFFF00002A0200C0:0050 0000000000000000FFFF0000380200C0:C739 01
";
        let clients: HashSet<SocketAddr> = established_clients(tcp, NGINX_PORT)
            .chain(established_clients(tcp6, NGINX_PORT))
            .collect();
        assert_eq!(
            clients,
            HashSet::from([
                "192.0.2.55:51000".parse().unwrap(),
                "192.0.2.56:51001".parse().unwrap(),
            ])
        );
    }

    /// The readiness check asks for `/boot.ipxe?tiaris_check=1` through nginx
    /// about every seven seconds. An hour of it leaves the Nest idle for the
    /// updater; one computer's request, even with the same marker, does not.
    #[tokio::test]
    async fn an_hour_of_readiness_checks_ends_idle_and_a_computer_does_not() {
        // The updater's QUIET_SECONDS (tiaris-nest-appliance-update-window).
        const QUIET_SECONDS: i64 = 10 * 60;
        static COUNTER: Counter = Counter::new();
        let app = Router::new()
            .route("/boot.ipxe", get(|| async { "#!ipxe\n" }))
            .layer(axum::middleware::from_fn(|request, next| {
                track_with(&COUNTER, request, next)
            }));
        let request = |client: &'static str| {
            let mut request = Request::get("/boot.ipxe?tiaris_check=1")
                .header("x-forwarded-for", client)
                .body(Body::empty())
                .unwrap();
            // nginx reaches the daemon on loopback.
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50200))));
            request
        };
        let sample = |idle_since, now| {
            next_idle_since(
                idle_since,
                COUNTER.in_flight.load(Ordering::SeqCst) > 0,
                now,
                COUNTER.last_served.load(Ordering::SeqCst),
            )
        };
        // The hour ends now, as served requests are stamped with the clock.
        let end = Utc::now().timestamp();
        let mut idle_since = None;
        for second in 0..3600 {
            if second % 7 == 0 {
                drop(app.clone().oneshot(request("127.0.0.1")).await.unwrap());
            }
            if second % 20 == 0 {
                idle_since = sample(idle_since, end - 3600 + second);
            }
        }
        idle_since = sample(idle_since, end);
        assert!(idle_since.is_some_and(|since| end - since >= QUIET_SECONDS));

        drop(app.oneshot(request("192.0.2.55")).await.unwrap());
        let now = Utc::now().timestamp();
        idle_since = sample(idle_since, now);
        assert!(idle_since.is_some_and(|since| now - since < QUIET_SECONDS));
    }

    #[test]
    fn the_report_names_its_schema_and_utc_times() {
        let report = Report {
            schema: SCHEMA,
            written_at: timestamp(1_800_000_000),
            idle_since: None,
            busy: vec!["building_apps"],
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["schema"], "tiaris.nest.activity.v1");
        assert_eq!(value["written_at"], "2027-01-15T08:00:00Z");
        assert!(value["idle_since"].is_null());
    }
}
