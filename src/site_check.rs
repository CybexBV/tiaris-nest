//! Site check: before a school installs a classroom, the Nest tests the
//! school network from where the computers are and names the exact blocker,
//! instead of computers failing later.
//!
//! Six checks, each `pass`, `fail`, `not_applicable` or `could_not_check`
//! with a machine-readable reason, a short detail and a plain-English remedy:
//!
//! - `network_boot`: the Nest's boot answer is served on its network, the
//!   school's DHCP server answers, no other server hands out boot
//!   information, and computers do not keep asking without receiving the
//!   answer (a switch DHCP guard). The privileged PXE supervisor gathers this
//!   (`nixos-appliance/runtime/site_probe.py`); this service only reads it.
//! - `dns`: Manage, the software cache (where it is on) and the directory
//!   hosts resolve.
//! - `time`: the clock is synchronized; when not, whether NTP is blocked.
//! - `manage`, `software_cache`: HTTPS with a trusted certificate. A
//!   certificate from an unknown authority is named by its issuer: that is
//!   HTTPS interception. The software cache is checked only where Manage
//!   names one (`site_check.software_cache_url`): where it is off, computers
//!   never use that host and the check is `not_applicable`.
//! - `directory`: LDAPS with a certificate computers trust, when the
//!   organization signs in with a directory.
//!
//! It runs a minute after start, every six hours (every 15 minutes while a
//! check does not pass), and when Manage asks ("Check again",
//! `site_check.requested_at`), at most once a minute. The latest result is a
//! state file (`site-check/site-check.json`), never SQLite
//! (`docs/sqlite-schema-evolution.md`), and travels in the Nest report's
//! `site_check` lane to a Manage that says it accepts `site_check_v1`.
use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    sync::Notify,
    time::{Instant, sleep},
};
use tracing::{info, warn};

use crate::AppState;

mod evaluate;
mod probes;
#[cfg(test)]
mod tests;

use evaluate::{BootProbe, PxeStatus};

pub const CAPABILITY: &str = "site_check_v1";
pub const REPORT_SCHEMA: &str = "tiaris.nest.site-check.v1";
const STATE_FILE: &str = "site-check.json";
const STATE_SCHEMA: &str = "tiaris.nest.site-check-state.v1";
const MAX_STATE_BYTES: u64 = 256 * 1024;
/// Asks the PXE supervisor for a fresh boot probe; next to its inventory.
const REQUEST_FILE: &str = "site-check-request.json";
const REQUEST_SCHEMA: &str = "tiaris.nest.site-check-request.v1";
const BOOT_PROBE_PATH: &str = "/run/tiaris-nest-pxe/boot-probe.json";
const PXE_STATUS_PATH: &str = "/run/tiaris-nest-pxe/status.json";
const START_DELAY: Duration = Duration::from_secs(60);
const PERIOD: Duration = Duration::from_secs(6 * 3600);
const RETRY_WHILE_NOT_PASSING: Duration = Duration::from_secs(15 * 60);
const MIN_INTERVAL: Duration = Duration::from_secs(60);
const BOOT_PROBE_WAIT: Duration = Duration::from_secs(15);
const MAX_DIRECTORIES: usize = 4;
const MAX_CA_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    NetworkBoot,
    Dns,
    Time,
    Manage,
    SoftwareCache,
    Directory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    NotApplicable,
    CouldNotCheck,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub id: CheckId,
    pub status: Status,
    /// Machine-readable, `[a-z0-9_]`.
    pub reason: String,
    /// What was found, such as the names that did not resolve.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// What the school can do about it; empty when nothing is needed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remedy: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    Start,
    Periodic,
    Requested,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema: String,
    pub checked_at: String,
    pub trigger: Trigger,
    /// The Manage request ("Check again") this run answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<String>,
    pub checks: Vec<Check>,
}

/// What Manage sends in the Nest configuration (`site_check`). Unknown
/// fields are ignored so a newer Manage can add targets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Targets {
    #[serde(default)]
    pub(crate) requested_at: Option<String>,
    #[serde(default)]
    pub(crate) directories: Vec<DirectoryTarget>,
    #[serde(default)]
    pub(crate) software_cache_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DirectoryTarget {
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The private CA computers trust for this directory (PEM).
    #[serde(default)]
    pub(crate) ca_certificate: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    targets: Targets,
    #[serde(default)]
    handled_request: Option<String>,
    #[serde(default)]
    last: Option<Report>,
}

fn state_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("site-check")
}

fn load(data_dir: &Path) -> State {
    crate::state_files::read::<State>(
        &state_dir(data_dir),
        STATE_FILE,
        STATE_SCHEMA,
        MAX_STATE_BYTES,
    )
    .unwrap_or_default()
}

async fn update(data_dir: &Path, change: impl FnOnce(&mut State)) -> Result<()> {
    let dir = state_dir(data_dir);
    let _guard = crate::state_files::lock(&dir).await;
    let mut state = load(data_dir);
    change(&mut state);
    crate::state_files::write(&dir, STATE_FILE, STATE_SCHEMA, MAX_STATE_BYTES, &state)
}

fn check_now() -> &'static Notify {
    static CHECK_NOW: OnceLock<Notify> = OnceLock::new();
    CHECK_NOW.get_or_init(Notify::new)
}

fn timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

/// A DNS name or IP literal, as Manage or a DHCP lease names a host.
pub(crate) fn valid_host(host: &str) -> bool {
    (1..=253).contains(&host.len())
        && (host.parse::<std::net::IpAddr>().is_ok()
            || host.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            }))
}

pub(crate) fn validate_targets(value: &Value) -> Result<Targets> {
    let targets: Targets = serde_json::from_value(value.clone())
        .map_err(|error| anyhow!("site_check is not a site check configuration: {error}"))?;
    if let Some(requested) = &targets.requested_at {
        if timestamp(requested).is_none() {
            bail!("site_check.requested_at is not RFC 3339");
        }
    }
    if targets.directories.len() > MAX_DIRECTORIES {
        bail!("site_check lists more than {MAX_DIRECTORIES} directories");
    }
    for directory in &targets.directories {
        if !valid_host(&directory.host) || directory.port == 0 {
            bail!("site_check names an invalid directory host");
        }
        if directory
            .ca_certificate
            .as_ref()
            .is_some_and(|pem| pem.len() > MAX_CA_BYTES)
        {
            bail!("site_check directory CA exceeds {MAX_CA_BYTES} bytes");
        }
    }
    if let Some(url) = &targets.software_cache_url {
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| anyhow!("site_check.software_cache_url is not a URL"))?;
        if parsed.scheme() != "https" || parsed.host_str().is_none_or(|host| !valid_host(host)) {
            bail!("site_check.software_cache_url must be an https URL");
        }
    }
    Ok(targets)
}

/// The site check lane of the Nest configuration. `None` from a Manage that
/// predates it: the check still runs on its own schedule with default
/// targets.
pub(crate) async fn apply_managed(data_dir: &Path, value: Option<&Value>) -> Result<()> {
    let targets = match value {
        None | Some(Value::Null) => Targets::default(),
        Some(value) => validate_targets(value)?,
    };
    let current = load(data_dir);
    if current.targets == targets {
        return Ok(());
    }
    let newer_request = newer(
        targets.requested_at.as_deref(),
        current.handled_request.as_deref(),
    ) && newer(
        targets.requested_at.as_deref(),
        current.targets.requested_at.as_deref(),
    );
    update(data_dir, |state| state.targets = targets).await?;
    if newer_request {
        check_now().notify_one();
    }
    Ok(())
}

fn newer(candidate: Option<&str>, than: Option<&str>) -> bool {
    match (candidate.and_then(timestamp), than.and_then(timestamp)) {
        (Some(candidate), Some(than)) => candidate > than,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn pending_request(state: &State) -> Option<String> {
    let requested = state.targets.requested_at.clone()?;
    newer(Some(&requested), state.handled_request.as_deref()).then_some(requested)
}

/// The latest result, for the Nest report.
pub(crate) fn report(data_dir: &Path) -> Option<Report> {
    load(data_dir).last
}

/// Starts the schedule on a Nest that reports to Manage.
pub fn spawn(state: AppState) {
    if !state.config.manage.enabled {
        return;
    }
    tokio::spawn(run(state));
}

async fn run(state: AppState) {
    let data_dir = state.config.paths.data_dir.clone();
    tokio::select! {
        _ = sleep(START_DELAY) => {}
        _ = check_now().notified() => {}
    }
    let mut trigger = Trigger::Start;
    let mut last_run: Option<Instant> = None;
    loop {
        if let Some(elapsed) = last_run.map(|at| at.elapsed()) {
            if elapsed < MIN_INTERVAL {
                sleep(MIN_INTERVAL - elapsed).await;
            }
        }
        let request = pending_request(&load(&data_dir));
        let trigger_now = if request.is_some() {
            Trigger::Requested
        } else {
            trigger
        };
        let report = check(&state, trigger_now, request.clone()).await;
        last_run = Some(Instant::now());
        let settled = report
            .checks
            .iter()
            .all(|check| matches!(check.status, Status::Pass | Status::NotApplicable));
        for check in report
            .checks
            .iter()
            .filter(|check| check.status != Status::Pass)
        {
            info!(
                check = ?check.id,
                status = ?check.status,
                reason = %check.reason,
                detail = %check.detail,
                "site check"
            );
        }
        if let Err(error) = update(&data_dir, |stored| {
            if request.is_some() {
                stored.handled_request = request;
            }
            stored.last = Some(report);
        })
        .await
        {
            warn!(error = %format!("{error:#}"), "could not store the site check result");
        }
        let wait = if settled {
            PERIOD
        } else {
            RETRY_WHILE_NOT_PASSING
        };
        trigger = tokio::select! {
            _ = sleep(wait) => Trigger::Periodic,
            _ = check_now().notified() => Trigger::Requested,
        };
    }
}

/// `https://host[:port]/...` as host and port.
fn endpoint(url: &str) -> Option<(String, u16)> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?.trim_matches(['[', ']']).to_string();
    Some((host, parsed.port_or_known_default()?))
}

/// The software cache to check, as its URL and endpoint: only where Manage
/// names one. Where the cache is off Manage sends no address, computers never
/// use the host, and a school that filters it must not get a failed check.
fn software_cache_target(targets: &Targets) -> Option<(String, (String, u16))> {
    let url = targets
        .software_cache_url
        .as_deref()?
        .trim_end_matches('/')
        .to_string();
    let target = endpoint(&url)?;
    Some((url, target))
}

/// Runs every check once.
pub(crate) async fn check(
    state: &AppState,
    trigger: Trigger,
    requested_at: Option<String>,
) -> Report {
    let targets = load(&state.config.paths.data_dir).targets;
    let api_url = state
        .config
        .manage
        .api_url
        .trim()
        .trim_end_matches('/')
        .to_string();
    let manage = endpoint(&api_url);
    let cache = software_cache_target(&targets);

    let mut hosts: Vec<(String, u16)> = Vec::new();
    for (host, port) in manage
        .iter()
        .chain(cache.iter().map(|(_, target)| target))
        .cloned()
        .chain(
            targets
                .directories
                .iter()
                .map(|directory| (directory.host.clone(), directory.port)),
        )
    {
        if !hosts.iter().any(|(known, _)| *known == host) {
            hosts.push((host, port));
        }
    }

    let clock = probes::clock();
    let boot = network_boot(state);
    let dns = join_all(
        hosts
            .iter()
            .cloned()
            .map(|(host, port)| async move {
                let resolution = probes::resolve(&host, port).await;
                (host, resolution)
            })
            .collect(),
    );
    let manage_probe = async {
        match &manage {
            Some((host, port)) => Some((
                probes::tls(host.clone(), *port, None).await,
                probes::http_get(&format!("{api_url}/v1/health"), "").await,
            )),
            None => None,
        }
    };
    let cache_probe = async {
        match &cache {
            Some((cache_url, (host, port))) => Some((
                probes::tls(host.clone(), *port, None).await,
                probes::http_get(&format!("{cache_url}/nix-cache-info"), "StoreDir:").await,
            )),
            None => None,
        }
    };
    let directories = join_all(
        targets
            .directories
            .iter()
            .cloned()
            .map(|directory| async move {
                let outcome = probes::tls(
                    directory.host.clone(),
                    directory.port,
                    directory.ca_certificate,
                )
                .await;
                (directory.host, directory.port, outcome)
            })
            .collect(),
    );
    let ntp = ntp_outcomes(clock, probes::ntp_servers(probes::default_leases_dir()));
    let (boot, dns, manage_probe, cache_probe, directories, ntp) =
        tokio::join!(boot, dns, manage_probe, cache_probe, directories, ntp);

    let skew = manage_probe
        .as_ref()
        .and_then(|(_, http)| http.as_ref())
        .and_then(|http| http.date)
        .map(|date| (Utc::now() - date).num_seconds());
    let manage_check = match (&manage, &manage_probe) {
        (Some((host, _)), Some((tls, http))) => evaluate::manage(host, tls, http.as_ref(), clock),
        _ => Check {
            id: CheckId::Manage,
            status: Status::CouldNotCheck,
            reason: "manage_not_configured".into(),
            detail: String::new(),
            remedy: String::new(),
        },
    };
    let cache_check = match (&cache, &cache_probe) {
        (Some((_, (host, _))), Some((tls, http))) => {
            evaluate::software_cache(host, tls, http.as_ref(), clock)
        }
        _ => Check {
            id: CheckId::SoftwareCache,
            status: Status::NotApplicable,
            reason: "software_cache_off".into(),
            detail: String::new(),
            remedy: String::new(),
        },
    };
    Report {
        schema: REPORT_SCHEMA.into(),
        checked_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        trigger,
        requested_at,
        checks: vec![
            boot,
            evaluate::dns(&dns),
            evaluate::time(clock, &ntp, skew),
            manage_check,
            cache_check,
            evaluate::directory(&directories, clock),
        ],
    }
}

/// Runs `tasks` concurrently; the outputs keep the tasks' order.
async fn join_all<T, F>(tasks: Vec<F>) -> Vec<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    let mut set = tokio::task::JoinSet::new();
    for (index, task) in tasks.into_iter().enumerate() {
        set.spawn(async move { (index, task.await) });
    }
    let mut outputs = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(output) = joined {
            outputs.push(output);
        }
    }
    outputs.sort_by_key(|(index, _)| *index);
    outputs.into_iter().map(|(_, output)| output).collect()
}

/// NTP answers, asked only when the clock is not synchronized.
async fn ntp_outcomes(clock: probes::Clock, servers: Vec<String>) -> Vec<probes::NtpOutcome> {
    if clock == probes::Clock::Synchronized {
        return Vec::new();
    }
    join_all(
        servers
            .into_iter()
            .map(|server| async move { probes::ntp(&server).await })
            .collect(),
    )
    .await
}

/// The time check against `servers` (qualification,
/// `examples/site-check-probe.rs`); `unsynchronized` stands in for a Nest
/// whose clock has not been set yet.
pub async fn time_check(servers: Vec<String>, unsynchronized: bool) -> Check {
    let clock = if unsynchronized {
        probes::Clock::NotSynchronized
    } else {
        probes::clock()
    };
    evaluate::time(clock, &ntp_outcomes(clock, servers).await, None)
}

/// The network boot check from the PXE supervisor's files (qualification).
pub fn network_boot_from_files(status: &Path, probe: &Path, now: i64) -> Check {
    evaluate::network_boot(
        true,
        read_json::<PxeStatus>(status).as_ref(),
        read_json::<BootProbe>(probe).as_ref(),
        now,
    )
}

/// Asks the PXE supervisor for a fresh probe, then reads its evidence.
async fn network_boot(state: &AppState) -> Check {
    let now = || Utc::now().timestamp();
    if !crate::appliance::is_managed_appliance() {
        return evaluate::network_boot(false, None, None, now());
    }
    let requested = now();
    if let Some(dir) = state.config.manage.state_path.parent() {
        let body = serde_json::json!({"schema": REQUEST_SCHEMA, "requested_at": requested});
        if let Err(error) =
            crate::state_files::write_bytes(dir, REQUEST_FILE, body.to_string().as_bytes(), 1024)
        {
            warn!(error = %format!("{error:#}"), "could not ask for a boot probe");
        }
    }
    let deadline = Instant::now() + BOOT_PROBE_WAIT;
    let mut probe = read_json::<BootProbe>(Path::new(BOOT_PROBE_PATH));
    while probe
        .as_ref()
        .is_none_or(|probe| probe.checked_at < requested)
        && Instant::now() < deadline
    {
        sleep(Duration::from_secs(1)).await;
        probe = read_json::<BootProbe>(Path::new(BOOT_PROBE_PATH));
    }
    if let Some(probe) = probe.as_mut() {
        let mut booted = std::collections::HashMap::new();
        for client in &probe.dropped {
            if let Some(at) = latest_boot(&state.db, &client.mac).await {
                booted.insert(client.mac.clone(), at);
            }
        }
        probe.dropped_clients = evaluate::still_dropped(probe, |mac| booted.get(mac).copied());
    }
    let pxe = read_json::<PxeStatus>(Path::new(PXE_STATUS_PATH));
    evaluate::network_boot(true, pxe.as_ref(), probe.as_ref(), now())
}

/// When the computer with `mac` last fetched its boot script from the Nest.
async fn latest_boot(pool: &sqlx::SqlitePool, mac: &str) -> Option<i64> {
    let created: Option<String> = sqlx::query_scalar(
        "SELECT created_at FROM boot_events WHERE lower(mac) = lower(?) ORDER BY id DESC LIMIT 1",
    )
    .bind(mac)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    created
        .and_then(|at| timestamp(&at))
        .map(|at| at.timestamp())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let dir = path.parent()?;
    let name = path.file_name()?.to_str()?;
    let bytes = crate::state_files::read_bytes(dir, name, 64 * 1024).ok()??;
    serde_json::from_slice(&bytes).ok()
}
