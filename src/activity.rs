//! Whether computers depend on this Nest right now.
//!
//! A Nest installs a prepared update once it served no computer and ran no
//! build for a quiet period (and in the night at the latest). The daemon
//! serves every boot, netboot, install and cache request, so it alone can
//! tell. Requests the Nest makes to itself, such as its readiness check, serve
//! no computer and do not count. It publishes `/run/tiaris-nest/activity.json`;
//! the root updater (`tiaris-nest-appliance-update-window`) reads it and decides.
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicI64, AtomicUsize, Ordering},
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

/// What the HTTP routes are serving right now.
pub struct Counter {
    in_flight: AtomicUsize,
    /// Unix seconds of the last moment a computer request was being served.
    last_served: AtomicI64,
}

impl Counter {
    const fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            last_served: AtomicI64::new(0),
        }
    }

    fn touch(&self) {
        self.last_served
            .fetch_max(Utc::now().timestamp(), Ordering::SeqCst);
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
    let served = Served::start(counter);
    let response = next.run(request).await;
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

async fn busy_reasons(state: &AppState, now: DateTime<Utc>) -> Vec<&'static str> {
    let mut busy = Vec::new();
    if SERVED.in_flight.load(Ordering::SeqCst) > 0 {
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
