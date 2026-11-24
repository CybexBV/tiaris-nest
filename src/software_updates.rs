//! Nest-driven software updates: the NixOS channel check.
//!
//! Every six hours, at a random minute that falls between 01:00 and 05:00 in
//! the Nest's update-schedule time zone, and when Manage asks
//! (`software_update_check_requested_at`), Nest reads the newest commit of its
//! NixOS channel. A commit it has not handled is evaluated, never built. The
//! evaluation is heavy: a commit found by day waits until the Nest is idle or
//! the night comes (`may_prepare`), so school hours are not slowed.
//!
//! 1. The commit must be on the channel's branch of NixOS/nixpkgs after the
//!    release pin (GitHub compare). `nix flake metadata` records its
//!    `lastModified` and `narHash`; every later fetch is pinned to it.
//! 2. The references are configurations of the shipped Tiaris source only,
//!    never an organization's Blueprint: the Tiaris packages (Manage's
//!    `tiaris-workstation-cache-seeds.nix`), the reference Blueprints in
//!    `deploy/nixos/reference-blueprints` and the plain desktop profiles.
//!    Each is dry-run at the release pin and at the commit
//!    (`local_work`): what would this Nest have to build that the public
//!    NixOS cache does not have?
//! 3. The commit is ready when it asks for no new compilation: everything
//!    it would build is a download, a script (`preferLocalBuild` or one
//!    `buildCommand`), or of a kind the release pin builds as well.
//!
//! The result is a detected commit, `ready` or `blocked` with a reason:
//! `source_build_required` (the names of what would compile),
//! `evaluation_failed`, `provenance_unverified` or `insufficient_disk`.
//! Ready commits are admitted by `build_target` and reported to Manage, which
//! offers them to the organization as a software update.
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Days, NaiveTime, TimeZone, Timelike, Utc};
use rand::{Rng, RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::SqlitePool;
use tokio::{sync::Notify, time::sleep};
use tracing::{info, warn};

use crate::{
    AppState,
    build::{self, BUILTIN_LAST_MODIFIED, BUILTIN_NIXOS_RELEASE},
    config::AppConfig,
    manage_source,
    subprocess::run_bounded_command,
};

pub(crate) mod findings;
mod local_work;

pub const DEFAULT_CHANNEL: &str = "nixos-26.05";
/// Report limit (Manage design §5).
pub(crate) const MAX_REPORTED_DETECTED_COMMITS: i64 = 32;
const MAX_REASON_DETAILS: usize = 50;
const CHANNEL_ORIGIN: &str = "https://channels.nixos.org";
const MAX_CHANNEL_RESPONSE_BYTES: usize = 128;
/// Desktop profiles of the shipped `tiaris-blueprints.nix`, used as plain
/// references next to the shipped reference Blueprints.
const BUILTIN_BLUEPRINT_PROFILES: [&str; 2] = ["taskbar", "dock"];
/// The reference that lists the Tiaris packages no public cache has
/// (Manage's `tiaris-workstation-cache-seeds.nix` and the agent).
const TIARIS_PACKAGES: &str = "tiaris-packages";
/// Directory of the shipped Tiaris source holding the built-in Blueprints'
/// compiler exports, one `<name>/{blueprint.nix,desktop.nix}` each.
const REFERENCE_BLUEPRINTS_DIR: &str = "deploy/nixos/reference-blueprints";
const MAX_REFERENCE_BLUEPRINTS: usize = 16;
/// Wall-clock bound on evaluating one commit.
const CHECK_TIME_LIMIT: Duration = Duration::from_secs(60 * 60);
/// A commit whose evaluation or provenance failed is retried at most daily,
/// whoever asks; a request only repeats the channel lookup.
const RETRY_INTERVAL: chrono::Duration = chrono::Duration::hours(24);
const GITHUB_COMPARE: &str = "https://api.github.com/repos/NixOS/nixpkgs/compare";
const MAX_GITHUB_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const SYSTEM_IDENTITY_PATH: &str = "/usr/share/tiaris-nest/system-identity.json";
const MAX_SYSTEM_IDENTITY_BYTES: u64 = 64 * 1024;
/// 01:00 local time, and the length of the night window in minutes.
const NIGHT_WINDOW_START_MINUTE: u32 = 60;
const NIGHT_WINDOW_MINUTES: u32 = 240;
/// The channel is read four times a day, the first in the night window.
const CHECKS_PER_DAY: u32 = 4;
/// A commit found by day is evaluated once nothing kept the Nest busy this
/// long, as its own updates wait (`tiaris-nest-appliance-update-window`).
const QUIET_BEFORE_PREPARING: chrono::Duration = chrono::Duration::minutes(10);
/// How often a commit found by day looks whether the Nest became idle.
const WAITING_POLL: Duration = Duration::from_secs(5 * 60);
const ON_DEMAND_MIN_INTERVAL: chrono::Duration = chrono::Duration::minutes(10);
/// The check right after an update of this Nest is tried this often, this
/// far apart, before it is left to the scheduled checks.
const STARTUP_CHECK_ATTEMPTS: u32 = 5;
const STARTUP_CHECK_RETRY: Duration = Duration::from_secs(120);
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);
const EVALUATION_TIMEOUT: Duration = Duration::from_secs(900);
const EVALUATION_STDOUT_MAX_BYTES: usize = 1024 * 1024;
const EVALUATION_STDERR_MAX_BYTES: usize = 1024 * 1024;

/// The commit would make this Nest compile something the release pin does
/// not: a package the public NixOS cache lacks at this commit.
pub(crate) const REASON_SOURCE_BUILD_REQUIRED: &str = "source_build_required";
/// The commit, or a reference at it, does not evaluate.
pub(crate) const REASON_EVALUATION_FAILED: &str = "evaluation_failed";
/// The commit could not be shown to be on the channel's branch of
/// NixOS/nixpkgs after the release pin.
pub(crate) const REASON_PROVENANCE_UNVERIFIED: &str = "provenance_unverified";
/// The build work directory had too little free space for the check.
pub(crate) const REASON_INSUFFICIENT_DISK: &str = "insufficient_disk";

/// Directory of the software-update records under the Nest state directory
/// (`<data_dir>/software-updates`); see `state_files`.
pub(crate) fn state_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("software-updates")
}

/// Where this Nest keeps its detected commits.
fn detected_dir(data_dir: &Path) -> PathBuf {
    state_dir(data_dir).join("detected-commits")
}

/// Where Nest 0.2.173 and older keep theirs, with a build profile in each
/// record. Such a Nest can run again after this one: an update that fails
/// its health check goes back to it, and its generation stays in the boot
/// menu. It cannot read a record without a profile, and it writes its own
/// verdict over the record of the channel's newest commit. So this Nest
/// takes the ready commits from that folder (`adopt_ready_commits_of_older_nests`)
/// and writes nothing there: each of the two finds its records as it left
/// them.
fn older_nests_detected_dir(data_dir: &Path) -> PathBuf {
    state_dir(data_dir).join("detected")
}

const CHECK_STATE_FILE: &str = "check-state.json";
const CHECK_STATE_SCHEMA: &str = "tiaris.nest.software-update-check.v1";
const DETECTED_SCHEMA: &str = "tiaris.nest.detected-commit.v1";
/// Records an older Nest wrote carry a build profile of up to this size;
/// it is ignored.
const MAX_DETECTED_RECORD_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CHECK_STATE_BYTES: u64 = 64 * 1024;
/// Detected commits kept: every ready one a Blueprint job uses, then the
/// newest. The report sends at most `MAX_REPORTED_DETECTED_COMMITS`.
const MAX_DETECTED_RECORDS: usize = 64;
/// A record with another reason is not used: those of an older Nest's strict
/// "Nest only" check.
const DETECTED_REASONS: [&str; 4] = [
    REASON_SOURCE_BUILD_REQUIRED,
    REASON_EVALUATION_FAILED,
    REASON_PROVENANCE_UNVERIFIED,
    REASON_INSUFFICIENT_DISK,
];

fn check_now() -> &'static Notify {
    static CHECK_NOW: OnceLock<Notify> = OnceLock::new();
    CHECK_NOW.get_or_init(Notify::new)
}

/// Nest follows only the channel of its own NixOS release; moving to the
/// next release is a Tiaris release.
fn supported_channel(channel: &str) -> bool {
    channel == format!("nixos-{BUILTIN_NIXOS_RELEASE}")
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The channel and on-demand check request Manage last sent, the outcome of
/// the last check, and when a check last completed
/// (`software_update_checked_at`).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckState {
    channel: Option<String>,
    check_requested_at: Option<String>,
    check_handled_at: Option<String>,
    last_checked_at: Option<String>,
    last_completed_at: Option<String>,
    #[serde(default)]
    last_error: String,
}

/// An absent or corrupt record is the default state: the default channel and
/// no pending request.
async fn check_state(data_dir: &Path) -> Result<CheckState> {
    Ok(crate::state_files::read::<CheckState>(
        &state_dir(data_dir),
        CHECK_STATE_FILE,
        CHECK_STATE_SCHEMA,
        MAX_CHECK_STATE_BYTES,
    )
    .filter(|state| {
        state.channel.as_deref().is_none_or(supported_channel)
            && [
                &state.check_requested_at,
                &state.check_handled_at,
                &state.last_checked_at,
                &state.last_completed_at,
            ]
            .iter()
            .all(|value| value.is_none() || parse_timestamp(value.as_deref()).is_some())
    })
    .unwrap_or_default())
}

async fn update_check_state(data_dir: &Path, change: impl FnOnce(&mut CheckState)) -> Result<()> {
    let dir = state_dir(data_dir);
    let _guard = crate::state_files::lock(&dir).await;
    let mut state = check_state(data_dir).await?;
    change(&mut state);
    state.last_error = state.last_error.chars().take(500).collect();
    crate::state_files::write(
        &dir,
        CHECK_STATE_FILE,
        CHECK_STATE_SCHEMA,
        MAX_CHECK_STATE_BYTES,
        &state,
    )
}

fn parse_timestamp(value: Option<&str>) -> Option<DateTime<Utc>> {
    value
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

/// The software-update lane of the Nest configuration Manage sends. Both
/// fields are optional; an older Manage sends neither and Nest follows the
/// default channel on its schedule.
pub(crate) async fn apply_managed(
    data_dir: &Path,
    channel: Option<&Value>,
    check_requested_at: Option<&Value>,
) -> Result<()> {
    let channel = match channel {
        None | Some(Value::Null) => None,
        Some(Value::String(channel)) if supported_channel(channel) => Some(channel.clone()),
        Some(_) => bail!(
            "software_update_channel must be nixos-{BUILTIN_NIXOS_RELEASE}; this Nest does not cross NixOS releases"
        ),
    };
    let requested = match check_requested_at {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(
            parse_timestamp(Some(value))
                .ok_or_else(|| anyhow!("software_update_check_requested_at is not RFC 3339"))?,
        ),
        Some(_) => bail!("software_update_check_requested_at must be a timestamp"),
    };
    let current = check_state(data_dir).await?;
    let newer_request = requested.filter(|requested| {
        parse_timestamp(current.check_requested_at.as_deref())
            .is_none_or(|previous| *requested > previous)
    });
    update_check_state(data_dir, |state| {
        state.channel = channel;
        if let Some(requested) = newer_request {
            state.check_requested_at = Some(requested.to_rfc3339());
        }
    })
    .await?;
    if newer_request.is_some() {
        check_now().notify_one();
    }
    Ok(())
}

/// One detected commit, one record each (`detected-commits/<commit>.json`).
/// Fields an older Nest wrote and this one does not know are ignored.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct DetectedRow {
    commit_rev: String,
    channel: String,
    last_modified: String,
    nar_hash: String,
    kernel_version: String,
    state: String,
    reason: Option<String>,
    /// JSON list of the names behind `reason`.
    reason_details: String,
    detected_at: String,
    /// The Nest build that evaluated the commit.
    derived_by: String,
}

impl DetectedRow {
    /// The record's own rules: a record that breaks one is not used.
    fn is_valid(&self, commit: &str) -> bool {
        let ready = self.state == "ready";
        self.commit_rev == commit
            && valid_commit(&self.commit_rev)
            && (ready || self.state == "blocked")
            && ready == self.reason.is_none()
            && self
                .reason
                .as_deref()
                .is_none_or(|reason| DETECTED_REASONS.contains(&reason))
            && parse_timestamp(Some(&self.last_modified)).is_some()
            && parse_timestamp(Some(&self.detected_at)).is_some()
            && serde_json::from_str::<Vec<String>>(&self.reason_details).is_ok()
    }
}

/// One detected commit in the Nest report (protocol 5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct DetectedCommitReport {
    pub(crate) commit: String,
    pub(crate) channel: String,
    pub(crate) last_modified: String,
    pub(crate) nar_hash: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) kernel_version: String,
    pub(crate) state: String,
    /// Why a commit is blocked. The names behind it stay in the Nest's
    /// record (`reason_details`); Manage's wire carries the reason only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    pub(crate) detected_at: String,
}

impl From<DetectedRow> for DetectedCommitReport {
    fn from(row: DetectedRow) -> Self {
        Self {
            commit: row.commit_rev,
            channel: row.channel,
            last_modified: row.last_modified,
            nar_hash: row.nar_hash,
            kernel_version: row.kernel_version,
            state: row.state,
            reason: row.reason,
            detected_at: row.detected_at,
        }
    }
}

/// The record of `commit`; a missing, corrupt or invalid record is absent.
async fn detected_row(data_dir: &Path, commit: &str) -> Result<Option<DetectedRow>> {
    if !valid_commit(commit) {
        return Ok(None);
    }
    Ok(crate::state_files::read::<DetectedRow>(
        &detected_dir(data_dir),
        &format!("{commit}.json"),
        DETECTED_SCHEMA,
        MAX_DETECTED_RECORD_BYTES,
    )
    .filter(|row| {
        let valid = row.is_valid(commit);
        if !valid {
            warn!(%commit, "ignoring a detected commit record that breaks its rules");
        }
        valid
    }))
}

/// Every usable record, newest `last_modified` first.
async fn detected_rows(data_dir: &Path) -> Result<Vec<DetectedRow>> {
    let mut rows = Vec::new();
    for name in crate::state_files::list(&detected_dir(data_dir), ".json", 4 * MAX_DETECTED_RECORDS)
    {
        let commit = name.trim_end_matches(".json");
        if let Some(row) = detected_row(data_dir, commit).await? {
            rows.push(row);
        }
    }
    rows.sort_by(|left, right| {
        right
            .last_modified
            .cmp(&left.last_modified)
            .then_with(|| left.commit_rev.cmp(&right.commit_rev))
    });
    Ok(rows)
}

/// Commits the Blueprint jobs this Nest holds build at.
async fn commits_in_use(db: &SqlitePool) -> Result<BTreeSet<String>> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT json_extract(build_spec, '$.nixpkgs_commit') FROM nest_build_jobs
         WHERE json_valid(build_spec)
           AND json_type(build_spec, '$.nixpkgs_commit') = 'text'",
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .collect())
}

/// The Nest's full current list for the report; each report replaces the
/// previous one in Manage. Ready commits a Blueprint job still uses come
/// first, so the 32-entry limit never drops a commit this Nest builds; then
/// the newest.
pub(crate) async fn report(db: &SqlitePool, data_dir: &Path) -> Result<Vec<DetectedCommitReport>> {
    let in_use = commits_in_use(db).await?;
    let mut rows = detected_rows(data_dir).await?;
    // Stable: within each group the newest stay first.
    rows.sort_by_key(|row| !(row.state == "ready" && in_use.contains(&row.commit_rev)));
    Ok(rows
        .into_iter()
        .take(MAX_REPORTED_DETECTED_COMMITS as usize)
        .map(DetectedCommitReport::from)
        .collect())
}

/// A ready detected commit: the jobs it admits build with nixpkgs pinned to
/// its recorded `narHash`.
pub(crate) struct ReadyCommit {
    pub(crate) commit: String,
    pub(crate) nar_hash: String,
}

/// The recorded `narHash` of a ready commit.
async fn current_ready_nar_hash(data_dir: &Path, commit: &str) -> Result<Option<String>> {
    Ok(ready_commit(data_dir, commit)
        .await?
        .map(|ready| ready.nar_hash))
}

pub(crate) async fn ready_commit(data_dir: &Path, commit: &str) -> Result<Option<ReadyCommit>> {
    Ok(detected_row(data_dir, commit)
        .await?
        .filter(|row| row.state == "ready" && build::valid_nar_hash(&row.nar_hash))
        .map(|row| ReadyCommit {
            commit: row.commit_rev,
            nar_hash: row.nar_hash,
        }))
}

/// This Nest build: its version and the release, source and Tiaris source
/// revisions of the installed system. What another build held back is
/// forgotten at startup.
fn nest_build_identity() -> String {
    #[derive(Deserialize)]
    struct Installed {
        #[serde(default)]
        release_id: String,
        #[serde(default)]
        source_revision: String,
        #[serde(default)]
        manage_source_revision: String,
    }
    let installed = std::fs::read(SYSTEM_IDENTITY_PATH)
        .ok()
        .filter(|body| body.len() as u64 <= MAX_SYSTEM_IDENTITY_BYTES)
        .and_then(|body| serde_json::from_slice::<Installed>(&body).ok());
    match installed {
        Some(installed) => format!(
            "{} release={} source={} tiaris={}",
            env!("CARGO_PKG_VERSION"),
            installed.release_id,
            installed.source_revision,
            installed.manage_source_revision
        ),
        None => format!("{} release=unknown", env!("CARGO_PKG_VERSION")),
    }
}

/// The commits this Nest can build: its release pins, the newest ready
/// detected commit, and every ready detected commit a Blueprint job it still
/// holds uses (the jobs of released Blueprints and open updates).
pub(crate) async fn workstation_nixpkgs_commits(state: &AppState) -> Vec<String> {
    let mut commits = crate::config::workstation_nixpkgs_commits(&state.config);
    if commits.is_empty() {
        return commits;
    }
    match ready_commits_in_use(&state.db, &state.config.paths.data_dir).await {
        Ok(ready) => commits.extend(ready),
        Err(error) => warn!(error = %error, "could not read ready detected nixpkgs commits"),
    }
    commits.sort();
    commits.dedup();
    commits
}

async fn ready_commits_in_use(db: &SqlitePool, data_dir: &Path) -> Result<Vec<String>> {
    // The newest ready commit, and every one a Blueprint job this Nest holds
    // uses.
    let ready = detected_rows(data_dir)
        .await?
        .into_iter()
        .filter(|row| row.state == "ready")
        .collect::<Vec<_>>();
    let newest = ready
        .iter()
        .max_by(|left, right| left.last_modified.cmp(&right.last_modified))
        .map(|row| row.commit_rev.clone());
    let in_use = commits_in_use(db).await?;
    Ok(ready
        .into_iter()
        .map(|row| row.commit_rev)
        .filter(|commit| Some(commit) == newest.as_ref() || in_use.contains(commit))
        .collect())
}

/// Start the channel check. Only Nests that build Blueprints and report to
/// Manage check for updates.
pub fn spawn(state: AppState) {
    if !state.config.manage.enabled
        || crate::config::workstation_nixpkgs_commits(&state.config).is_empty()
    {
        return;
    }
    findings::spawn(state.clone());
    tokio::spawn(run(state));
}

async fn run(state: AppState) {
    remove_interrupted_checks(&state.config).await;
    let offset = rand::thread_rng().gen_range(0..NIGHT_WINDOW_MINUTES);
    match check_state(&state.config.paths.data_dir).await {
        Ok(current) if pending_request(&current).is_some() => check_now().notify_one(),
        Ok(_) => {}
        Err(error) => warn!(error = %error, "could not read software update check state"),
    }
    // After an update of this Nest, the ready commits of the previous build
    // stay, what it held back is forgotten, and the channel is looked at
    // again now rather than at the next scheduled check: the update may be what it
    // waited for. (The ready commits of Nest 0.2.173 and older were taken
    // over before this task started: `take_over_commits_of_older_nests`.)
    // A commit to evaluate waits for a quiet Nest or the night as any other:
    // right after its update the Nest builds what waited for it.
    let data_dir = &state.config.paths.data_dir;
    let forgot = forget_verdicts_of_other_builds(data_dir).await;
    // A commit found by day that waits for a quiet Nest or the night.
    let mut waiting = false;
    if forgot || updated_nest_has_not_looked(data_dir).await {
        // The network may come up after the Nest: try for some minutes.
        for attempt in 1..=STARTUP_CHECK_ATTEMPTS {
            match check(&state, Prepare::WhenQuiet(local_timezone())).await {
                Ok(checked) => {
                    waiting = matches!(checked, Checked::Waiting);
                    break;
                }
                Err(error) => {
                    warn!(attempt, error = %error, "software update check after an update of this Nest failed");
                    sleep(STARTUP_CHECK_RETRY).await;
                }
            }
        }
    }
    loop {
        let timezone = local_timezone();
        let now = Utc::now();
        let scheduled = next_check(now, timezone, offset);
        let mut wait = (scheduled - now).to_std().unwrap_or_default();
        if waiting {
            wait = wait.min(WAITING_POLL);
        }
        let on_demand = tokio::select! {
            _ = sleep(wait) => false,
            _ = check_now().notified() => true,
        };
        if !on_demand && Utc::now() < scheduled && !may_prepare(Utc::now(), timezone) {
            // Still busy, and still day: the commit waits.
            continue;
        }
        let current = check_state(&state.config.paths.data_dir)
            .await
            .unwrap_or_default();
        let request = pending_request(&current);
        if on_demand
            && (request.is_none()
                || parse_timestamp(current.last_checked_at.as_deref())
                    .is_some_and(|last| Utc::now() - last < ON_DEMAND_MIN_INTERVAL))
        {
            // Duplicate wake-ups and requests within minutes of a check are
            // answered by the check that just ran.
            if let Some(request) = request {
                let _ = mark_checked(&state.config.paths.data_dir, Some(&request), None).await;
            }
            continue;
        }
        // Manage's request is an admin's: it evaluates at once.
        let prepare = if on_demand {
            Prepare::Now
        } else {
            Prepare::WhenQuiet(timezone)
        };
        let outcome = match check(&state, prepare).await {
            Ok(Checked::Waiting) => {
                waiting = true;
                continue;
            }
            Ok(Checked::Done) => {
                waiting = false;
                Ok(())
            }
            Err(error) => {
                warn!(error = %error, "software update check failed");
                Err(format!("{error:#}").chars().take(500).collect::<String>())
            }
        };
        if let Err(error) = mark_checked(
            &state.config.paths.data_dir,
            request.as_deref(),
            Some(outcome),
        )
        .await
        {
            warn!(error = %error, "could not record software update check");
        }
    }
}

/// The time zone the night and the scheduled checks are in.
fn local_timezone() -> chrono_tz::Tz {
    crate::appliance::nixos::is_nixos()
        .then(crate::appliance::schedule::timezone)
        .flatten()
        .unwrap_or(chrono_tz::UTC)
}

fn pending_request(state: &CheckState) -> Option<String> {
    let requested = parse_timestamp(state.check_requested_at.as_deref())?;
    parse_timestamp(state.check_handled_at.as_deref())
        .is_none_or(|handled| requested > handled)
        .then(|| state.check_requested_at.clone())
        .flatten()
}

/// Record a handled request and, when a check ran (`outcome`), its result.
/// Only a check that completed moves `last_completed_at`.
async fn mark_checked(
    data_dir: &Path,
    handled_request: Option<&str>,
    outcome: Option<std::result::Result<(), String>>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let ran = outcome.is_some();
    let completed = matches!(outcome, Some(Ok(())));
    let error = match outcome {
        Some(Err(error)) => error,
        _ => String::new(),
    };
    update_check_state(data_dir, |state| {
        if let Some(handled) = handled_request {
            state.check_handled_at = Some(handled.to_string());
        }
        if ran {
            state.last_checked_at = Some(now.clone());
            state.last_error = error;
        }
        if completed {
            state.last_completed_at = Some(now);
        }
    })
    .await
}

/// When a channel check last completed, whether or not it found a new
/// commit (`software_update_checked_at`).
pub(crate) async fn checked_at(data_dir: &Path) -> Result<Option<String>> {
    let value = check_state(data_dir).await?.last_completed_at;
    Ok(parse_timestamp(value.as_deref())
        .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)))
}

/// The next scheduled check after `now`: 01:00 plus `offset_minutes` (below
/// 240) in `timezone`, and every six hours after it, today or tomorrow. A
/// time skipped by a DST change runs an hour later.
fn next_check<Tz: TimeZone>(
    now: DateTime<Utc>,
    timezone: Tz,
    offset_minutes: u32,
) -> DateTime<Utc> {
    let first = NIGHT_WINDOW_START_MINUTE + offset_minutes % NIGHT_WINDOW_MINUTES;
    let today = now.with_timezone(&timezone).date_naive();
    let times = [today, today + Days::new(1), today + Days::new(2)]
        .into_iter()
        .flat_map(|date| {
            (0..CHECKS_PER_DAY).map(move |slot| {
                let minute = first + slot * (24 * 60 / CHECKS_PER_DAY);
                let time = NaiveTime::from_hms_opt(minute / 60, minute % 60, 0)
                    .expect("minute within a day");
                date.and_time(time)
            })
        });
    for local in times {
        let candidate = timezone
            .from_local_datetime(&local)
            .earliest()
            .or_else(|| {
                timezone
                    .from_local_datetime(&(local + chrono::Duration::hours(1)))
                    .earliest()
            })
            .map(|value| value.with_timezone(&Utc));
        if let Some(candidate) = candidate.filter(|candidate| *candidate > now) {
            return candidate;
        }
    }
    now + chrono::Duration::hours(6)
}

/// Whether the heavy evaluation of a new commit may start: in the night
/// window, or once nothing kept the Nest busy for `QUIET_BEFORE_PREPARING`.
fn may_prepare<Tz: TimeZone>(now: DateTime<Utc>, timezone: Tz) -> bool {
    let local = now.with_timezone(&timezone);
    prepare_now(
        local.hour() * 60 + local.minute(),
        crate::activity::quiet_for(now),
    )
}

fn prepare_now(local_minute: u32, quiet_for: Option<chrono::Duration>) -> bool {
    (NIGHT_WINDOW_START_MINUTE..NIGHT_WINDOW_START_MINUTE + NIGHT_WINDOW_MINUTES)
        .contains(&local_minute)
        || quiet_for.is_some_and(|quiet| quiet >= QUIET_BEFORE_PREPARING)
}

/// When a new commit is evaluated.
#[derive(Clone, Copy)]
enum Prepare {
    /// Now: an admin asked.
    Now,
    /// Only when `may_prepare`; otherwise the check waits.
    WhenQuiet(chrono_tz::Tz),
}

enum Checked {
    Done,
    /// A new commit waits for a quiet Nest or the night.
    Waiting,
}

/// Read the channel and handle its newest commit. A commit already recorded
/// is evaluated again only when its evaluation, provenance or disk check
/// failed at least a day ago; a request from Manage repeats only the channel
/// lookup. Network failures before evaluation record nothing.
async fn check(state: &AppState, prepare: Prepare) -> Result<Checked> {
    let data_dir = &state.config.paths.data_dir;
    let channel = check_state(data_dir)
        .await?
        .channel
        .unwrap_or_else(|| DEFAULT_CHANNEL.to_string());
    if !supported_channel(&channel) {
        bail!("channel {channel} is not this Nest's NixOS release");
    }
    let commit = channel_revision(&channel).await?;
    if !crate::config::workstation_nixpkgs_commits(&state.config).contains(&commit) {
        let existing = detected_row(data_dir, &commit).await?;
        if needs_evaluation(existing.as_ref(), Utc::now()) {
            if let Prepare::WhenQuiet(timezone) = prepare {
                if !may_prepare(Utc::now(), timezone) {
                    info!(%commit, "found a newer NixOS channel commit; it is checked once the Nest is idle or at night");
                    return Ok(Checked::Waiting);
                }
            }
            evaluate_and_record(state, &channel, &commit, existing.as_ref()).await?;
        }
    }
    Ok(Checked::Done)
}

/// A commit is evaluated when it is new, and when its evaluation, provenance
/// or disk check failed at least a day ago. Any other verdict of this Nest
/// build stands: a ready commit stays ready, and a commit that needs a new
/// compile is not asked again (the next channel commit is).
fn needs_evaluation(existing: Option<&DetectedRow>, now: DateTime<Utc>) -> bool {
    existing.is_none_or(|row| {
        check_did_not_finish(row)
            && parse_timestamp(Some(&row.detected_at))
                .is_none_or(|detected| now - detected >= RETRY_INTERVAL)
    })
}

/// The record says the check could not be done (evaluation, provenance or
/// disk space), not what the commit needs: it is tried again.
fn check_did_not_finish(row: &DetectedRow) -> bool {
    matches!(
        row.reason.as_deref(),
        Some(REASON_EVALUATION_FAILED | REASON_PROVENANCE_UNVERIFIED | REASON_INSUFFICIENT_DISK)
    )
}

/// Proof that the ready commits of older Nests were taken over
/// (`take_over_commits_of_older_nests`). The build worker and the reporter
/// to Manage cannot start without it, so neither looks at the detected
/// commits before the takeover is done: a queued job of a Blueprint released
/// on such a commit would be refused (`target_not_allowed`), and the first
/// report would leave the commit out.
#[derive(Clone, Copy, Debug)]
pub struct OlderNestsCommitsTakenOver(());

/// Take over the ready commits of older Nests, once, when the Nest starts
/// and before anything reads the detected commits. A small local copy.
pub async fn take_over_commits_of_older_nests(config: &AppConfig) -> OlderNestsCommitsTakenOver {
    adopt_ready_commits_of_older_nests(&config.paths.data_dir).await;
    OlderNestsCommitsTakenOver(())
}

/// Take over the ready commits Nest 0.2.173 and older recorded
/// (`older_nests_detected_dir`), so the Blueprints released on them keep
/// building. A verdict of this Nest stands, with one exception: a record of
/// a check that did not finish (`check_did_not_finish`) gives way. The older
/// Nest ran the same checks later and they passed (it can run after this
/// one: see `older_nests_detected_dir`), and once the channel has moved on
/// this Nest never checks the commit again. What the older Nest held back is
/// not taken over, and its records are left as they are.
async fn adopt_ready_commits_of_older_nests(data_dir: &Path) {
    let older = older_nests_detected_dir(data_dir);
    let dir = detected_dir(data_dir);
    let _guard = crate::state_files::lock(&dir).await;
    for name in crate::state_files::list(&older, ".json", 4 * MAX_DETECTED_RECORDS) {
        let commit = name.trim_end_matches(".json");
        if !valid_commit(commit) {
            continue;
        }
        match detected_row(data_dir, commit).await {
            Ok(None) => {}
            Ok(Some(own)) if check_did_not_finish(&own) => {}
            Ok(Some(_)) | Err(_) => continue,
        }
        let ready = crate::state_files::read::<DetectedRow>(
            &older,
            &name,
            DETECTED_SCHEMA,
            MAX_DETECTED_RECORD_BYTES,
        )
        .filter(|row| row.is_valid(commit) && row.state == "ready");
        let Some(row) = ready else { continue };
        if let Err(error) = crate::state_files::write(
            &dir,
            &name,
            DETECTED_SCHEMA,
            MAX_DETECTED_RECORD_BYTES,
            &row,
        ) {
            warn!(%commit, error = %format!("{error:#}"), "could not take over a ready commit of an older Nest");
        }
    }
}

/// Whether this Nest was updated and its new build has not recorded a commit
/// yet: another build left records (in this Nest's folder or an older
/// Nest's) and none is this build's. Such a Nest looks at the channel when
/// it starts. A newly installed Nest has no records and waits for the
/// scheduled check, which evaluates only when the Nest is idle or at night:
/// the evaluation is heavy, and its first hours are the day the school
/// installs its computers.
async fn updated_nest_has_not_looked(data_dir: &Path) -> bool {
    let build = nest_build_identity();
    let rows = detected_rows(data_dir).await.unwrap_or_default();
    if rows.iter().any(|row| row.derived_by == build) {
        return false;
    }
    !rows.is_empty()
        || !crate::state_files::list(&older_nests_detected_dir(data_dir), ".json", 1).is_empty()
}

/// Remove the record of every commit another Nest build held back, whatever
/// its reason (also reasons this build no longer has); whether one was
/// removed. A ready commit is kept: it stays ready.
async fn forget_verdicts_of_other_builds(data_dir: &Path) -> bool {
    let dir = detected_dir(data_dir);
    let _guard = crate::state_files::lock(&dir).await;
    let build = nest_build_identity();
    let mut forgot = false;
    for name in crate::state_files::list(&dir, ".json", 4 * MAX_DETECTED_RECORDS) {
        let other_build = crate::state_files::read::<DetectedRow>(
            &dir,
            &name,
            DETECTED_SCHEMA,
            MAX_DETECTED_RECORD_BYTES,
        )
        .is_some_and(|row| row.state == "blocked" && row.derived_by != build);
        if other_build && crate::state_files::remove(&dir, &name).is_ok() {
            forgot = true;
        }
    }
    forgot
}

async fn evaluate_and_record(
    state: &AppState,
    channel: &str,
    commit: &str,
    existing: Option<&DetectedRow>,
) -> Result<()> {
    let metadata = flake_metadata(
        &state.config,
        commit,
        existing.map(|row| row.nar_hash.as_str()),
    )
    .await?;
    if metadata.last_modified <= BUILTIN_LAST_MODIFIED {
        bail!("channel commit {commit} is not newer than the release pin");
    }
    let newest = detected_rows(&state.config.paths.data_dir)
        .await?
        .iter()
        .filter(|row| row.commit_rev != commit)
        .filter_map(|row| parse_timestamp(Some(&row.last_modified)))
        .map(|value| value.timestamp())
        .max();
    if newest.is_some_and(|newest| metadata.last_modified < newest) {
        bail!("channel commit {commit} is older than a commit this Nest already detected");
    }
    let provenance = verify_provenance(channel, commit).await;
    let disk = enough_disk(&state.config);
    let outcome = match (provenance, disk) {
        (Err(error), _) => {
            warn!(%commit, error = %format!("{error:#}"), "could not verify the commit's provenance");
            DetectedOutcome::blocked(
                String::new(),
                REASON_PROVENANCE_UNVERIFIED,
                vec![format!("{error:#}").chars().take(200).collect()],
            )
        }
        (Ok(()), Err(error)) => {
            warn!(%commit, error = %format!("{error:#}"), "not enough disk space to evaluate the commit");
            DetectedOutcome::blocked(
                String::new(),
                REASON_INSUFFICIENT_DISK,
                vec![format!("{error:#}").chars().take(200).collect()],
            )
        }
        (Ok(()), Ok(())) => {
            info!(%commit, %channel, "evaluating NixOS channel commit");
            match tokio::time::timeout(
                CHECK_TIME_LIMIT,
                evaluate_commit(&state.config, commit, &metadata),
            )
            .await
            {
                Ok(outcome) => outcome?,
                Err(_) => {
                    warn!(%commit, "evaluating the commit exceeded its time limit");
                    DetectedOutcome::blocked(
                        String::new(),
                        REASON_EVALUATION_FAILED,
                        vec!["time limit".to_string()],
                    )
                }
            }
        }
    };
    store_detected(
        &state.db,
        &state.config.paths.data_dir,
        commit,
        channel,
        &metadata,
        &outcome,
    )
    .await?;
    info!(
        %commit,
        state = outcome.state(),
        reason = outcome.reason,
        details = ?outcome.details,
        "recorded detected nixpkgs commit"
    );
    Ok(())
}

/// The commit is on the channel's branch of NixOS/nixpkgs (an ancestor of,
/// or the same as, its tip) and descends from the release pin. A fork-only
/// commit diverges from the branch. Any failure leaves the commit unverified.
async fn verify_provenance(channel: &str, commit: &str) -> Result<()> {
    let on_branch = github_compare(commit, channel).await?;
    if !matches!(on_branch.as_str(), "ahead" | "identical") {
        bail!("{commit} is not on NixOS/nixpkgs {channel} (compare status {on_branch})");
    }
    let after_pin = github_compare(build::BUILTIN_NIXPKGS_COMMIT, commit).await?;
    if after_pin != "ahead" {
        bail!("{commit} does not descend from the release pin (compare status {after_pin})");
    }
    Ok(())
}

/// GitHub's comparison of `base...head` on NixOS/nixpkgs: `ahead` when head
/// descends from base, `identical`, `behind` or `diverged`.
async fn github_compare(base: &str, head: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(CHANNEL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("tiaris-nest/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build GitHub client")?;
    let response = client
        .get(format!("{GITHUB_COMPARE}/{base}...{head}?per_page=1"))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .context("compare commits on GitHub")?;
    if !response.status().is_success() {
        bail!("GitHub compare returned {}", response.status());
    }
    let body = crate::bounded_io::response_bytes(response, MAX_GITHUB_RESPONSE_BYTES).await?;
    compare_status(&body)
}

fn compare_status(body: &[u8]) -> Result<String> {
    let value: Value = serde_json::from_slice(body).context("parse GitHub compare")?;
    match value.get("status").and_then(Value::as_str) {
        Some(status @ ("ahead" | "behind" | "identical" | "diverged")) => Ok(status.to_string()),
        _ => bail!("GitHub compare has no status"),
    }
}

async fn channel_revision(channel: &str) -> Result<String> {
    let url = format!("{CHANNEL_ORIGIN}/{channel}/git-revision");
    let response = crate::release_transport::get(&url, false, true, CHANNEL_TIMEOUT, None)
        .await
        .context("read NixOS channel revision")?;
    if !response.status().is_success() {
        bail!("NixOS channel revision returned {}", response.status());
    }
    let body = crate::bounded_io::response_bytes(response, MAX_CHANNEL_RESPONSE_BYTES)
        .await
        .context("read NixOS channel revision body")?;
    let commit = std::str::from_utf8(&body)
        .context("NixOS channel revision is not UTF-8")?
        .trim()
        .to_string();
    if !valid_commit(&commit) {
        bail!("NixOS channel revision is not a 40-character commit");
    }
    Ok(commit)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FlakeMetadata {
    path: String,
    last_modified: i64,
    nar_hash: String,
}

/// `nix flake metadata` of the commit, pinned to `known_nar_hash` when Nest
/// has fetched it before.
async fn flake_metadata(
    config: &AppConfig,
    commit: &str,
    known_nar_hash: Option<&str>,
) -> Result<FlakeMetadata> {
    let reference = build::nixpkgs_flake_ref(commit, known_nar_hash)?;
    let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
    command
        .args(["flake", "metadata", "--json", "--no-write-lock-file"])
        .args(["--option", "accept-flake-config", "false"])
        .arg(&reference)
        .env("LC_ALL", "C")
        .env("LANG", "C");
    let output = run_bounded_command(
        command,
        EVALUATION_TIMEOUT,
        EVALUATION_STDOUT_MAX_BYTES,
        EVALUATION_STDERR_MAX_BYTES,
        "nix flake metadata",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix flake metadata failed: {}",
            tail(&String::from_utf8_lossy(&output.stderr), 300)
        );
    }
    parse_flake_metadata(&output.stdout, commit, known_nar_hash)
}

fn parse_flake_metadata(
    stdout: &[u8],
    commit: &str,
    known_nar_hash: Option<&str>,
) -> Result<FlakeMetadata> {
    let value: Value = serde_json::from_slice(stdout).context("parse nix flake metadata")?;
    let locked = &value["locked"];
    let path = value["path"].as_str().unwrap_or_default();
    let nar_hash = locked["narHash"].as_str().unwrap_or_default();
    let last_modified = locked["lastModified"]
        .as_i64()
        .ok_or_else(|| anyhow!("nix flake metadata has no lastModified"))?;
    if locked["rev"].as_str() != Some(commit)
        || !build::valid_nar_hash(nar_hash)
        || known_nar_hash.is_some_and(|known| known != nar_hash)
        || build::store_path_item(path).is_none()
        || last_modified <= 0
    {
        bail!("nix flake metadata does not describe commit {commit} with its recorded narHash");
    }
    Ok(FlakeMetadata {
        path: path.to_string(),
        last_modified,
        nar_hash: nar_hash.to_string(),
    })
}

/// Outcome of evaluating one commit.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DetectedOutcome {
    kernel_version: String,
    reason: Option<&'static str>,
    /// The names behind `reason`: what would compile, or what failed.
    details: Vec<String>,
}

impl DetectedOutcome {
    fn state(&self) -> &'static str {
        if self.reason.is_none() {
            "ready"
        } else {
            "blocked"
        }
    }

    fn ready(kernel_version: String) -> Self {
        Self {
            kernel_version,
            reason: None,
            details: Vec::new(),
        }
    }

    fn blocked(kernel_version: String, reason: &'static str, details: Vec<String>) -> Self {
        let mut details = details;
        details.truncate(MAX_REASON_DETAILS);
        Self {
            kernel_version,
            reason: Some(reason),
            details,
        }
    }
}

async fn store_detected(
    db: &SqlitePool,
    data_dir: &Path,
    commit: &str,
    channel: &str,
    metadata: &FlakeMetadata,
    outcome: &DetectedOutcome,
) -> Result<()> {
    let last_modified = DateTime::<Utc>::from_timestamp(metadata.last_modified, 0)
        .ok_or_else(|| anyhow!("lastModified is out of range"))?
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let dir = detected_dir(data_dir);
    let _guard = crate::state_files::lock(&dir).await;
    // A commit keeps the channel and lastModified it was first recorded with.
    let existing = detected_row(data_dir, commit).await?;
    let row = DetectedRow {
        commit_rev: commit.to_string(),
        channel: existing
            .as_ref()
            .map_or_else(|| channel.to_string(), |row| row.channel.clone()),
        last_modified: existing
            .as_ref()
            .map_or(last_modified, |row| row.last_modified.clone()),
        nar_hash: existing
            .as_ref()
            .map_or_else(|| metadata.nar_hash.clone(), |row| row.nar_hash.clone()),
        kernel_version: outcome.kernel_version.clone(),
        state: outcome.state().to_string(),
        reason: outcome.reason.map(str::to_string),
        reason_details: serde_json::to_string(&outcome.details)?,
        detected_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        derived_by: nest_build_identity(),
    };
    if !row.is_valid(commit) {
        bail!("detected commit {commit} would break its record's rules");
    }
    crate::state_files::write(
        &dir,
        &format!("{commit}.json"),
        DETECTED_SCHEMA,
        MAX_DETECTED_RECORD_BYTES,
        &row,
    )?;
    // Keep every ready commit a Blueprint job uses, then the newest.
    let in_use = commits_in_use(db).await?;
    let mut rows = detected_rows(data_dir).await?;
    rows.sort_by_key(|row| !(row.state == "ready" && in_use.contains(&row.commit_rev)));
    for stale in rows.iter().skip(MAX_DETECTED_RECORDS) {
        crate::state_files::remove(&dir, &format!("{}.json", stale.commit_rev))?;
    }
    Ok(())
}

/// What the check reads from the commit's nixpkgs itself.
#[derive(Debug, Deserialize)]
struct EvaluatedRelease {
    release: String,
    kernel_version: String,
}

/// Evaluate the commit in a private work directory that is always removed.
/// Errors that are not about the commit itself (the work directory, the
/// shipped Tiaris source) are returned and record nothing.
async fn evaluate_commit(
    config: &AppConfig,
    commit: &str,
    metadata: &FlakeMetadata,
) -> Result<DetectedOutcome> {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let manage_source_url = shipped_manage_source_url(config)?;
    let work = CheckWorkDir::create(
        config
            .build
            .work_dir
            .join(format!("{CHECK_WORK_DIR_PREFIX}{}", hex::encode(nonce))),
    )?;
    // Every private store of the check lives inside its work directory.
    let mut check_config = config.clone();
    check_config.build.work_dir = work.path.join("stores");
    let result = evaluate_commit_in(
        &check_config,
        commit,
        metadata,
        &manage_source_url,
        &work.path,
    )
    .await;
    work.remove().await;
    result
}

const CHECK_WORK_DIR_PREFIX: &str = "software-update-";

/// A check's private work directory. Removed when the check ends and, if a
/// timeout cancels it, when it is dropped.
struct CheckWorkDir {
    path: PathBuf,
}

impl CheckWorkDir {
    fn create(path: PathBuf) -> Result<Self> {
        create_private_dir(&path)?;
        Ok(Self { path })
    }

    async fn remove(self) {
        let path = self.path.clone();
        let _ = tokio::task::spawn_blocking(move || local_work::remove_private_tree(&path)).await;
        std::mem::forget(self);
    }
}

impl Drop for CheckWorkDir {
    fn drop(&mut self) {
        local_work::remove_private_tree(&self.path);
    }
}

/// Remove check work directories a restart interrupted. Runs before this
/// Nest's first check; build jobs never use these names.
async fn remove_interrupted_checks(config: &AppConfig) {
    let work_dir = config.build.work_dir.clone();
    let removed = tokio::task::spawn_blocking(move || {
        let Ok(entries) = std::fs::read_dir(&work_dir) else {
            return 0;
        };
        entries
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.strip_prefix(CHECK_WORK_DIR_PREFIX))
                    .is_some_and(|nonce| {
                        nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
            })
            .map(|entry| local_work::remove_private_tree(&entry.path()))
            .count()
    })
    .await
    .unwrap_or(0);
    if removed > 0 {
        info!(
            removed,
            "removed interrupted software update check directories"
        );
    }
}

/// Free space the check needs in the build work directory: one private
/// store with a nixpkgs source (about 330 MB) and the evaluation.
const MIN_CHECK_FREE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn enough_disk(config: &AppConfig) -> Result<()> {
    let stats = crate::disk::stats(&config.build.work_dir).context("read build disk space")?;
    if stats.available_bytes < MIN_CHECK_FREE_BYTES {
        bail!(
            "{} MiB free below {}, {} MiB needed",
            stats.available_bytes / (1024 * 1024),
            config.build.work_dir.display(),
            MIN_CHECK_FREE_BYTES / (1024 * 1024)
        );
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::create_dir_all(path.parent().unwrap_or(Path::new("/")))?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("create {}", path.display()))
}

fn write_private_file(path: PathBuf, contents: &str) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write {}", path.display()))
}

async fn evaluate_commit_in(
    config: &AppConfig,
    commit: &str,
    metadata: &FlakeMetadata,
    manage_source_url: &str,
    work: &Path,
) -> Result<DetectedOutcome> {
    let evaluated = match evaluate_release(config, &metadata.path).await {
        Ok(evaluated) => evaluated,
        Err(error) => {
            warn!(%commit, error = %error, "could not evaluate the commit's nixpkgs");
            return Ok(DetectedOutcome::blocked(
                String::new(),
                REASON_EVALUATION_FAILED,
                vec!["nixpkgs".to_string()],
            ));
        }
    };
    if evaluated.release != BUILTIN_NIXOS_RELEASE {
        bail!(
            "commit {commit} is NixOS {}, not {BUILTIN_NIXOS_RELEASE}; Nest does not cross releases",
            evaluated.release
        );
    }
    let kernel = evaluated
        .kernel_version
        .chars()
        .take(64)
        .collect::<String>();
    let blocked = |reason: &'static str, details: Vec<String>| {
        DetectedOutcome::blocked(kernel.clone(), reason, details)
    };

    // Everything below is evaluated from the shipped Tiaris source and
    // nixpkgs (the commit, narHash-pinned, or the pin): never from an
    // organization's Blueprint.
    let commit_flake = work.join("flake");
    let pin_flake = work.join("pin-flake");
    create_private_dir(&commit_flake)?;
    create_private_dir(&pin_flake)?;
    write_reference_flake(
        &commit_flake,
        &build::nixpkgs_flake_ref(commit, Some(&metadata.nar_hash))?,
        manage_source_url,
    )?;
    write_reference_flake(
        &pin_flake,
        &build::nixpkgs_flake_ref(build::BUILTIN_NIXPKGS_COMMIT, None)?,
        manage_source_url,
    )?;
    let installable =
        |flake: &Path, name: &str| format!("{}#packages.x86_64-linux.{name}", flake.display());

    // The references: the Tiaris packages, the shipped reference Blueprints
    // and the plain desktop profiles of the shipped module.
    let names = match reference_blueprint_names(config, &commit_flake).await {
        Ok(names) => names,
        Err(error) => {
            warn!(%commit, error = %format!("{error:#}"), "could not list the reference Blueprints");
            return Ok(blocked(
                REASON_EVALUATION_FAILED,
                vec!["reference blueprints".to_string()],
            ));
        }
    };
    let references = std::iter::once(TIARIS_PACKAGES.to_string())
        .chain(names.iter().map(|name| format!("reference-{name}")))
        .chain(
            BUILTIN_BLUEPRINT_PROFILES
                .iter()
                .map(|profile| profile.to_string()),
        )
        .collect::<Vec<_>>();

    // Each reference at the pin and at the commit, one private store at a
    // time. What the pin builds on a Nest is what a Tiaris release was made
    // and tested with: the Tiaris packages, the initrd, generated
    // configuration. Only work beyond that holds the commit back.
    let mut known_roles = BTreeSet::new();
    let mut possible_compiles = Vec::new();
    for reference in &references {
        let both = async {
            anyhow::Ok((
                local_work::dry_run(config, &installable(&pin_flake, reference)).await?,
                local_work::dry_run(config, &installable(&commit_flake, reference)).await?,
            ))
        };
        match both.await {
            Ok((pin, new)) => {
                let compiles = new.possible_compiles();
                // What is neither a download nor a script, at the commit:
                // the Tiaris packages and whatever the public cache lacks.
                info!(
                    %commit,
                    reference,
                    local_at_pin = pin.len(),
                    local_at_commit = new.len(),
                    compiles = ?compiles.iter().map(|(_, name)| name).collect::<Vec<_>>(),
                    "checked a reference"
                );
                known_roles.extend(pin.roles());
                possible_compiles.extend(compiles);
            }
            Err(error) => {
                warn!(%commit, reference, error = %format!("{error:#}"), "could not evaluate a reference");
                return Ok(blocked(REASON_EVALUATION_FAILED, vec![reference.clone()]));
            }
        }
    }
    let mut compiles = Vec::new();
    for (role, name) in possible_compiles {
        if !known_roles.contains(&role) && !compiles.contains(&name) {
            compiles.push(name);
        }
    }
    Ok(if compiles.is_empty() {
        DetectedOutcome::ready(kernel)
    } else {
        blocked(REASON_SOURCE_BUILD_REQUIRED, compiles)
    })
}

/// The shipped reference Blueprints (`deploy/nixos/reference-blueprints/<name>`).
async fn reference_blueprint_names(config: &AppConfig, flake: &Path) -> Result<Vec<String>> {
    let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
    command
        .args(["eval", "--json", "--no-write-lock-file"])
        .args(["--option", "allow-import-from-derivation", "false"])
        .args(["--option", "accept-flake-config", "false"])
        .arg(format!("{}#referenceBlueprints", flake.display()))
        .env("LC_ALL", "C")
        .env("LANG", "C");
    let output = run_bounded_command(
        command,
        EVALUATION_TIMEOUT,
        EVALUATION_STDOUT_MAX_BYTES,
        EVALUATION_STDERR_MAX_BYTES,
        "list reference Blueprints",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix eval failed: {}",
            tail(&String::from_utf8_lossy(&output.stderr), 300)
        );
    }
    let names: Vec<String> =
        serde_json::from_slice(&output.stdout).context("parse reference Blueprint names")?;
    if names.len() > MAX_REFERENCE_BLUEPRINTS
        || !names.iter().all(|name| valid_reference_name(name))
    {
        bail!("the shipped reference Blueprints are not a bounded list of safe names");
    }
    Ok(names)
}

fn valid_reference_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The NixOS release and kernel version of the nixpkgs source at
/// `nixpkgs_path`. Evaluation only.
async fn evaluate_release(config: &AppConfig, nixpkgs_path: &str) -> Result<EvaluatedRelease> {
    let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
    command
        .args(["eval", "--json", "--impure"])
        .args(["--option", "allow-import-from-derivation", "false"])
        .args(["--option", "accept-flake-config", "false"])
        .arg("--expr")
        .arg(format!(
            "let pkgs = import {nixpkgs_path} {{ system = \"x86_64-linux\"; config = {{ }}; overlays = [ ]; }}; in {{ release = pkgs.lib.trivial.release; kernel_version = pkgs.linuxPackages.kernel.version; }}"
        ))
        .env("LC_ALL", "C")
        .env("LANG", "C");
    let output = run_bounded_command(
        command,
        EVALUATION_TIMEOUT,
        EVALUATION_STDOUT_MAX_BYTES,
        EVALUATION_STDERR_MAX_BYTES,
        "evaluate the nixpkgs release",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix eval failed: {}",
            tail(&String::from_utf8_lossy(&output.stderr), 300)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse the evaluated nixpkgs release")
}

#[derive(Deserialize)]
struct SystemIdentity {
    manage_source_revision: String,
}

/// The Tiaris source shipped with this Nest: the revision named by the
/// installed system identity, verified like installer-target builds.
fn shipped_manage_source_url(config: &AppConfig) -> Result<String> {
    use std::io::Read;
    let mut body = Vec::new();
    std::fs::File::open(SYSTEM_IDENTITY_PATH)
        .context("open installed system identity")?
        .take(MAX_SYSTEM_IDENTITY_BYTES)
        .read_to_end(&mut body)?;
    let identity: SystemIdentity =
        serde_json::from_slice(&body).context("parse installed system identity")?;
    if !valid_commit(&identity.manage_source_revision) {
        bail!("installed system identity has no Tiaris source revision");
    }
    Ok(manage_source::verify_revision(
        &config.build.manage_source_url_template,
        &identity.manage_source_revision,
        config.workstation_netboot.allow_private_release_urls,
    )
    .context("verify shipped Tiaris source")?
    .url)
}

/// The flake the check dry-runs: the Tiaris packages, each shipped
/// reference Blueprint and the plain desktop profiles, configured by the same
/// Nest templates as Blueprint jobs. Every input is the shipped Tiaris source
/// or nixpkgs.
fn write_reference_flake(work: &Path, nixpkgs_ref: &str, manage_url: &str) -> Result<()> {
    for (name, contents) in build::blueprint_job_template_files()? {
        write_private_file(work.join(name), &contents)?;
    }
    write_private_file(work.join("blueprint.nix"), "{ ... }:\n\n{ }\n")?;
    write_private_file(
        work.join("tiaris-blueprints.nix"),
        "{ manageSource, ... }:\n\n{\n  imports = [ (manageSource + \"/deploy/nixos/tiaris-blueprints.nix\") ];\n}\n",
    )?;
    write_private_file(
        work.join("flake.nix"),
        &reference_flake(nixpkgs_ref, manage_url),
    )
}

fn reference_flake(nixpkgs_ref: &str, manage_url: &str) -> String {
    let nixpkgs = serde_json::to_string(nixpkgs_ref).expect("string serializes");
    let manage = serde_json::to_string(manage_url).expect("string serializes");
    let profiles = BUILTIN_BLUEPRINT_PROFILES
        .iter()
        .fold(String::new(), |mut lines, profile| {
            use std::fmt::Write;
            let _ = writeln!(lines, "        {profile} = blueprint \"{profile}\";");
            lines
        });
    format!(
        r#"{{
  description = "Tiaris Nest software update check";

  inputs.nixpkgs.url = {nixpkgs};
  inputs.manage = {{
    url = {manage};
    flake = false;
  }};

  outputs = {{ self, nixpkgs, manage }}:
    let
      system = "x86_64-linux";
      lib = nixpkgs.lib;
      pkgs = import nixpkgs {{ inherit system; }};
      workstationAgent = import (manage + "/deploy/nixos/tiaris-agent-package.nix") {{
        inherit pkgs;
        repoRoot = manage;
      }};
      seeds = import (manage + "/deploy/nixos/tiaris-workstation-cache-seeds.nix") {{
        inherit pkgs system workstationAgent;
        nixpkgs = nixpkgs.outPath;
        manageRepo = manage;
      }};
      blueprint = profile:
        (lib.nixosSystem {{
          inherit system;
          specialArgs.manageSource = manage;
          modules = [
            ./configuration.nix
            {{ tiaris.desktop.profile = profile; }}
          ];
        }}).config.system.build.toplevel;
      references = manage + "/{REFERENCE_BLUEPRINTS_DIR}";
      referenceNames =
        if builtins.pathExists references
        then builtins.attrNames (lib.filterAttrs (_: type: type == "directory") (builtins.readDir references))
        else [ ];
      # The job configuration with the reference's compiler exports in the
      # places of a job's desktop module and generated Blueprint.
      reference = name:
        (lib.nixosSystem {{
          inherit system;
          modules = [
            (import ./reference-configuration.nix {{
              desktop = references + "/${{name}}/desktop.nix";
              blueprint = references + "/${{name}}/blueprint.nix";
            }})
          ];
        }}).config.system.build.toplevel;
    in {{
      referenceBlueprints = referenceNames;
      packages.${{system}} = {{
        {TIARIS_PACKAGES} = pkgs.writeText "{TIARIS_PACKAGES}"
          (builtins.concatStringsSep "\n" (map (package: package.outPath) ([ workstationAgent ] ++ seeds.packages)));
{profiles}      }} // lib.listToAttrs (map (name: {{
        name = "reference-${{name}}";
        value = reference name;
      }}) referenceNames);
    }};
}}
"#
    )
}

fn tail(text: &str, max_chars: usize) -> String {
    let skip = text.chars().count().saturating_sub(max_chars);
    text.chars().skip(skip).collect()
}

#[cfg(test)]
mod tests;
