use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(test)]
use tokio::process::Command;
use tokio::{
    io::AsyncRead,
    sync::Mutex,
    time::{sleep, timeout},
};
use tracing::{info, warn};

use crate::{
    AppState, cache,
    config::{AppConfig, BuildTargetConfig, pinned_nixpkgs_revision},
    db, manage_source,
    models::BuildJob,
    nix_log::InternalJsonParser,
    protected_material,
    redact::{contains_sensitive_key_value, redact_sensitive_key_values},
    subprocess::{PIPE_DRAIN_TIMEOUT, ProcessGroup, run_bounded_command},
};

mod failure;
mod scan_rebuild;

pub(crate) use scan_rebuild::{RebuiltClosure, rebuild_for_scan};

/// The nixpkgs commit of this Nest release: the pin its Blueprint targets
/// build at, and what the software-update check compares a channel commit
/// with.
pub(crate) const BUILTIN_NIXPKGS_COMMIT: &str = "74cc63f702f7d60a557e152a57b40fb1fd0f72ac";
/// The NixOS release of the built-in commit. Detected commits never cross it.
pub(crate) const BUILTIN_NIXOS_RELEASE: &str = "26.05";
/// `lastModified` of the built-in commit (2026-07-08). A detected commit must
/// be newer.
pub(crate) const BUILTIN_LAST_MODIFIED: i64 = 1_783_549_019;

const BLUEPRINT_BUILD_INPUT_KIND: &str = "blueprint_nixos_module";
const LEGACY_DESKTOP_EXPERIENCE_BUILD_INPUT_KIND: &str = "desktop_experience_nixos_module";
const INSTALLER_TARGET_BUILD_INPUT_KIND: &str = "installer_target_nixos_module";
const INSTALLER_TARGET_BUILD_SCHEMA_V1: &str = "tiaris.installer-target.build.v1";
const INSTALLER_TARGET_BUILD_SCHEMA: &str = "tiaris.installer-target.build.v2";
/// Device-agnostic cohort identity: the closure is a function of the Blueprint
/// revision artifact, the hardware module, the target module, the Tiaris source
/// revision, and the nixpkgs pin only. Tiaris reuses the verified closure for
/// every approval with the same inputs, so the identity must not name a
/// device, preparation, disk, or boot session.
const INSTALLER_TARGET_BUILD_SCHEMA_V3: &str = "tiaris.installer-target.build.v3";
const MAX_GENERATED_NIX_BYTES: usize = 1024 * 1024;
const MAX_DESKTOP_MODULE_NIX_BYTES: usize = 1024 * 1024;
const MAX_HARDWARE_MODULE_NIX_BYTES: usize = 1024 * 1024;
const MAX_TARGET_MODULE_NIX_BYTES: usize = 1024 * 1024;
const MAX_PENDING_LOG_LINE_BYTES: usize = 64 * 1024;
const CAPACITY_ACCOUNTING_TOLERANCE_BYTES: u64 = 1024 * 1024;
/// Progress range reserved for the nix build itself; the phases before
/// (preparing, 12) and after (inspecting, 80) bound it.
const BUILDING_PROGRESS_START: i32 = 25;
const BUILDING_PROGRESS_END: i32 = 79;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSpec {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub artifact_type: String,
    pub target: String,
    pub system: String,
    pub input_revision: String,
    pub input_config_hash: String,
    #[serde(default)]
    #[serde(alias = "desktop_experience_id")]
    pub blueprint_id: Option<String>,
    #[serde(default)]
    #[serde(alias = "desktop_experience_revision_id")]
    pub blueprint_revision_id: Option<String>,
    #[serde(default)]
    #[serde(alias = "desktop_experience_revision_config_hash")]
    pub blueprint_revision_config_hash: Option<String>,
    #[serde(default)]
    pub nixpkgs_commit: Option<String>,
    #[serde(default)]
    pub source_lock_sha256: Option<String>,
    #[serde(default)]
    pub software_package_refs: Vec<String>,
    #[serde(default)]
    pub build_input: Option<BlueprintBuildInput>,
    /// Ignored: every build may compile ("Nest only" delivery was removed on
    /// 20 November 2026). Manage still sends it for Nests released before.
    #[serde(default, rename = "allow_source_builds")]
    pub ignored_allow_source_builds: Option<bool>,
    /// Copy the verified closure from an approved sibling Nest instead of
    /// building it. Lives outside `build_input`, so the cohort identity
    /// (`input_config_hash`) and the installer-target identity are unchanged;
    /// Tiaris compares the resulting manifest with the origin's.
    #[serde(default)]
    pub closure_source: Option<ClosureSource>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureSource {
    pub kind: String,
    pub server_device_id: String,
    pub cache_base_url: String,
    pub public_key: String,
    pub toplevel_store_path: String,
    pub closure_store_paths_sha256: String,
    pub closure_member_count: u64,
    #[serde(default)]
    pub evaluated_derivation: Option<String>,
}

#[derive(Clone, Debug)]
struct ValidatedClosureSource {
    server_device_id: String,
    cache_base_url: String,
    public_key: String,
    toplevel_store_path: String,
    closure_store_paths_sha256: String,
    closure_member_count: u64,
    evaluated_derivation: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlueprintBuildInput {
    pub kind: String,
    pub generated_nix: String,
    #[serde(default)]
    pub desktop_module_nix: Option<String>,
    #[serde(default)]
    pub expected_state: Option<Value>,
    #[serde(default)]
    #[serde(alias = "desktop_experience_name")]
    pub blueprint_name: Option<String>,
    #[serde(default)]
    #[serde(alias = "desktop_experience_revision")]
    pub blueprint_revision: Option<i64>,
    #[serde(default)]
    pub hardware_module_nix: Option<String>,
    #[serde(default)]
    pub target_module_nix: Option<String>,
    #[serde(default)]
    pub manage_source_revision: Option<String>,
    #[serde(default)]
    pub installer_target: Option<Value>,
    #[serde(default)]
    pub wallpaper_asset: Option<BlueprintWallpaperAsset>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlueprintWallpaperAsset {
    pub schema: String,
    pub id: String,
    pub blueprint_revision_id: String,
    pub name: String,
    pub mime_type: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug)]
struct ValidatedBuildSpec {
    artifact_type: String,
    target: String,
    system: String,
    input_revision: String,
    input_config_hash: String,
    blueprint_id: Option<String>,
    blueprint_revision_id: Option<String>,
    blueprint_revision_config_hash: Option<String>,
    nixpkgs_commit: Option<String>,
    source_lock_sha256: Option<String>,
    software_package_refs: Vec<String>,
    build_input: Option<ValidatedBlueprintBuildInput>,
    closure_source: Option<ValidatedClosureSource>,
}

#[derive(Clone, Debug)]
struct ValidatedBlueprintBuildInput {
    kind: String,
    generated_nix: String,
    desktop_module_nix: Option<String>,
    expected_state: Option<Value>,
    blueprint_name: Option<String>,
    blueprint_revision: Option<i64>,
    hardware_module_nix: Option<String>,
    target_module_nix: Option<String>,
    manage_source_revision: Option<String>,
    installer_target: Option<Value>,
    wallpaper_asset: Option<BlueprintWallpaperAsset>,
}

#[derive(Clone, Debug)]
pub(crate) struct NixBuildCommand {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    out_link: PathBuf,
}

#[derive(Clone, Debug)]
struct NixOutputInfo {
    output_path: String,
    output_sha256: String,
    output_size_bytes: i64,
    closure_size_bytes: i64,
    evaluated_derivation: Option<String>,
}

#[derive(Clone)]
struct SharedLog {
    inner: Arc<Mutex<SharedLogState>>,
    max_bytes: usize,
}

#[derive(Debug, Default)]
struct SharedLogState {
    text: String,
    pending: String,
    redact_following: usize,
}

enum ProcessOutcome {
    Succeeded(i32),
    Failed(i32),
    Cancelled,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BuildCapacity {
    memory_bytes: u64,
    swap_bytes: u64,
}

pub fn spawn(state: AppState) {
    if !state.config.build.enabled {
        return;
    }
    tokio::spawn(async move {
        match db::recover_running_build_jobs(
            &state.db,
            "Nest restarted while this build was running; mark failed for explicit retry.",
        )
        .await
        {
            Ok(count) if count > 0 => {
                warn!(count, "recovered stale running Nest build jobs");
            }
            Ok(_) => {}
            Err(err) => warn!(error = %err, "failed to recover running Nest build jobs"),
        }
        sweep_stale_job_dirs(&state.config).await;

        for worker_index in 0..state.config.build.max_concurrent_builds {
            let worker_state = state.clone();
            tokio::spawn(async move { worker_loop(worker_state, worker_index).await });
        }
    });
}

async fn worker_loop(state: AppState, worker_index: usize) {
    let mut claim_failures: u32 = 0;
    loop {
        let _maintenance_lease = match crate::maintenance::acquire_build_lease().await {
            Ok(lease) => lease,
            Err(error) => {
                warn!(%error, "build admission barrier unavailable");
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let Some(_memory_lease) = state.build_admission.try_acquire(&state.config.build) else {
            drop(_maintenance_lease);
            sleep(Duration::from_secs(2)).await;
            continue;
        };
        match db::claim_next_build_job(&state.db).await {
            Ok(Some(job)) => {
                claim_failures = 0;
                let job_id = job.id;
                info!(job_id, worker_index, "claimed Nest build job");
                let cancellation = tokio_util::sync::CancellationToken::new();
                let _cancel_on_drop = cancellation.clone().drop_guard();
                let watched = cancellation.clone();
                let pool = state.db.clone();
                let _watcher = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                    loop {
                        if matches!(
                            db::build_job_cancel_requested(&pool, job_id).await,
                            Ok(true)
                        ) {
                            watched.cancel();
                            break;
                        }
                        sleep(Duration::from_millis(500)).await;
                    }
                }));
                if let Err(err) = crate::subprocess::BUILD_CANCELLATION
                    .scope(cancellation, execute_claimed_job(&state, job))
                    .await
                {
                    warn!(error = %safe_error(&err), job_id, worker_index, "Nest build job execution failed");
                    recover_failed_job_execution(&state, job_id, worker_index).await;
                }
                cleanup_job_dirs(&state.config, job_id).await;
            }
            Ok(None) => {
                drop(_maintenance_lease);
                drop(_memory_lease);
                claim_failures = 0;
                sleep(Duration::from_secs(2)).await;
            }
            Err(err) => {
                drop(_maintenance_lease);
                drop(_memory_lease);
                claim_failures = claim_failures.saturating_add(1);
                let delay = (5u64 << claim_failures.saturating_sub(1).min(5)).min(120);
                warn!(error = %err, worker_index, retry_in_seconds = delay, "failed to claim Nest build job");
                sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

async fn recover_failed_job_execution(state: &AppState, job_id: i64, worker_index: usize) {
    const RECOVERY_REASON: &str =
        "Nest stopped the build safely after an internal worker error; retry the build.";
    let mut failures: u32 = 0;
    loop {
        match db::fail_running_build_job_after_worker_error(&state.db, job_id, RECOVERY_REASON)
            .await
        {
            Ok(true) => {
                warn!(job_id, worker_index, "recovered failed Nest build worker");
                return;
            }
            Ok(false) => return,
            Err(err) => {
                let err = anyhow::Error::new(err);
                failures = failures.saturating_add(1);
                let delay = (2u64 << failures.saturating_sub(1).min(5)).min(60);
                warn!(
                    error = %safe_error(&err),
                    job_id,
                    worker_index,
                    retry_in_seconds = delay,
                    "failed to persist Nest build worker recovery"
                );
                sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

/// Remove a finished job's output dir (whose `result` out-link is an indirect
/// Nix gcroot pinning the build closure) and its generated flake input dir.
/// The out-link is only needed between build completion and cache export, so
/// once the job reaches a terminal state these must go or `/nix/store` grows
/// without bound.
async fn cleanup_job_dirs(config: &AppConfig, job_id: i64) {
    let job_dir = config.build.output_dir.join(format!("job-{job_id}"));
    let input_dir = config.build.work_dir.join(format!("job-{job_id}-input"));
    for dir in [job_dir, input_dir] {
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                warn!(error = %err, path = %dir.display(), "failed to remove Nest build job directory");
            }
        }
    }
}

/// Remove job dirs left behind by earlier Nest runs. Runs once at startup,
/// after stale running jobs have been marked failed and before workers start,
/// so nothing under these names can be live.
async fn sweep_stale_job_dirs(config: &AppConfig) {
    let mut removed = 0usize;
    for (root, prefix, suffix) in [
        (&config.build.output_dir, "job-", ""),
        (&config.build.work_dir, "job-", "-input"),
    ] {
        let mut entries = match tokio::fs::read_dir(root).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                warn!(error = %err, path = %root.display(), "failed to scan Nest build directory");
                continue;
            }
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(middle) = name
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
            else {
                continue;
            };
            if middle.is_empty() || !middle.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            match tokio::fs::remove_dir_all(entry.path()).await {
                Ok(()) => removed += 1,
                Err(err) => {
                    warn!(error = %err, path = %entry.path().display(), "failed to remove stale Nest build job directory");
                }
            }
        }
    }
    if removed > 0 {
        info!(removed, "removed stale Nest build job directories");
    }
}

async fn execute_claimed_job(state: &AppState, job: BuildJob) -> Result<()> {
    let spec = match validate_build_spec(&state.config, &job) {
        Ok(spec) => spec,
        Err(err) => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                "",
                &format!("invalid build spec: {}", safe_error(&err)),
                "",
                "",
                0,
                None,
                Some(build_result_metadata(
                    &state.config,
                    &job,
                    None,
                    Some("invalid_build_spec"),
                )),
            )
            .await?;
            return Ok(());
        }
    };
    db::update_build_job_progress(
        &state.db,
        job.id,
        Some(8),
        "validating",
        "Build spec validated",
    )
    .await?;
    // A Blueprint at a ready detected commit builds with narHash-pinned
    // nixpkgs. Storage errors fail closed:
    // without a valid record only the release pin is admitted.
    let detected = match (spec.build_input.as_ref(), spec.nixpkgs_commit.as_deref()) {
        (Some(_), Some(commit)) => crate::software_updates::ready_commit(
            &state.config.paths.data_dir,
            commit,
        )
        .await
        .unwrap_or_else(|error| {
            warn!(job_id = job.id, error = %error, "could not read detected nixpkgs commits");
            None
        }),
        _ => None,
    };
    let (target, admitted_commit) = match admit_build_target(
        &state.config,
        &spec,
        detected.as_ref().map(|ready| ready.commit.as_str()),
    ) {
        Ok(admitted) => (admitted.target.clone(), admitted.nixpkgs_commit),
        Err(err) => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                "",
                &format!("build target is not allowed: {}", safe_error(&err)),
                "",
                "",
                0,
                None,
                Some(build_result_metadata(
                    &state.config,
                    &job,
                    None,
                    Some("target_not_allowed"),
                )),
            )
            .await?;
            return Ok(());
        }
    };

    db::update_build_job_progress(
        &state.db,
        job.id,
        Some(12),
        "preparing",
        "Checking builder capacity and preparing inputs",
    )
    .await?;
    if let Err(err) = crate::disk::ensure_headroom(
        Path::new("/nix/store"),
        state.config.build.max_artifact_size_bytes,
        "Nest build",
    ) {
        db::finish_build_job(
            &state.db,
            job.id,
            "failed",
            "",
            &safe_error(&err),
            "",
            "",
            0,
            None,
            Some(admitted_result_metadata(
                &state.config,
                &job,
                &target,
                admitted_commit.as_deref(),
                detected.as_ref().map(|ready| ready.nar_hash.as_str()),
                Some("insufficient_disk_space"),
            )),
        )
        .await?;
        return Ok(());
    }
    let capacity = match build_capacity() {
        Ok(capacity) => capacity,
        Err(err) => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                "",
                &format!(
                    "could not inspect Nest memory capacity: {}",
                    safe_error(&err)
                ),
                "",
                "",
                0,
                None,
                Some(admitted_result_metadata(
                    &state.config,
                    &job,
                    &target,
                    admitted_commit.as_deref(),
                    detected.as_ref().map(|ready| ready.nar_hash.as_str()),
                    Some("capacity_check_failed"),
                )),
            )
            .await?;
            return Ok(());
        }
    };
    let capacity_error = if !capacity_meets_minimum(
        capacity.memory_bytes,
        state.config.build.minimum_memory_bytes,
    ) {
        Some((
            "insufficient_memory",
            format!(
                "Nest requires at least {} bytes of memory for Build/Cache; detected {} bytes",
                state.config.build.minimum_memory_bytes, capacity.memory_bytes
            ),
        ))
    } else if !capacity_meets_minimum(capacity.swap_bytes, state.config.build.minimum_swap_bytes) {
        Some((
            "insufficient_swap",
            format!(
                "Nest requires at least {} bytes of emergency swap for Build/Cache; detected {} bytes",
                state.config.build.minimum_swap_bytes, capacity.swap_bytes
            ),
        ))
    } else {
        None
    };
    if let Some((error_kind, error)) = capacity_error {
        db::finish_build_job(
            &state.db,
            job.id,
            "failed",
            "",
            &error,
            "",
            "",
            0,
            None,
            Some(admitted_result_metadata(
                &state.config,
                &job,
                &target,
                admitted_commit.as_deref(),
                detected.as_ref().map(|ready| ready.nar_hash.as_str()),
                Some(error_kind),
            )),
        )
        .await?;
        return Ok(());
    }
    if let Err(err) = ensure_nix_daemon_available(&state.config).await {
        db::finish_build_job(
            &state.db,
            job.id,
            "failed",
            "",
            &format!("Nix daemon is unavailable: {}", safe_error(&err)),
            "",
            "",
            0,
            None,
            Some(admitted_result_metadata(
                &state.config,
                &job,
                &target,
                admitted_commit.as_deref(),
                detected.as_ref().map(|ready| ready.nar_hash.as_str()),
                Some("nix_daemon_unavailable"),
            )),
        )
        .await?;
        return Ok(());
    }

    if let Some(source) = spec.closure_source.clone() {
        return execute_replica_copy(
            state,
            &job,
            &spec,
            &target,
            &source,
            admitted_commit.as_deref(),
            detected.as_ref().map(|ready| ready.nar_hash.as_str()),
        )
        .await;
    }
    let command = nix_build_command_with_nixpkgs_nar_hash(
        &state.config,
        &target,
        &spec,
        job.id,
        detected.as_ref().map(|ready| ready.nar_hash.as_str()),
    )?;
    let log = SharedLog::new(state.config.build.max_log_bytes);
    db::update_build_job_progress(
        &state.db,
        job.id,
        Some(25),
        "building",
        "Building NixOS closure",
    )
    .await?;
    let oom_kills_before = cgroup_oom_kill_count();
    let outcome = run_nix_build(&state.db, &job, &command, &log, &state.config).await?;
    let oom_kills_after = cgroup_oom_kill_count();
    let logs = log.snapshot().await;
    match outcome {
        ProcessOutcome::Succeeded(exit_code) => {
            db::update_build_job_progress(
                &state.db,
                job.id,
                Some(80),
                "inspecting",
                "Inspecting build output",
            )
            .await?;
            let output_info = match inspect_build_output(&state.config, &command).await {
                Ok(info) => info,
                Err(err) => {
                    db::finish_build_job(
                        &state.db,
                        job.id,
                        "failed",
                        &logs,
                        &format!("build output validation failed: {}", safe_error(&err)),
                        "",
                        "",
                        0,
                        Some(exit_code.into()),
                        Some(admitted_result_metadata(
                            &state.config,
                            &job,
                            &target,
                            admitted_commit.as_deref(),
                            detected.as_ref().map(|ready| ready.nar_hash.as_str()),
                            Some("output_validation_failed"),
                        )),
                    )
                    .await?;
                    return Ok(());
                }
            };
            if output_info.output_size_bytes as u64 > state.config.build.max_artifact_size_bytes {
                db::finish_build_job(
                    &state.db,
                    job.id,
                    "failed",
                    &logs,
                    "build output exceeded max_artifact_size_bytes",
                    &output_info.output_path,
                    &output_info.output_sha256,
                    output_info.output_size_bytes,
                    Some(exit_code.into()),
                    Some(admitted_result_metadata(
                        &state.config,
                        &job,
                        &target,
                        admitted_commit.as_deref(),
                        detected.as_ref().map(|ready| ready.nar_hash.as_str()),
                        Some("artifact_too_large"),
                    )),
                )
                .await?;
                return Ok(());
            }
            let nixpkgs_nar_hash = detected.as_ref().map(|ready| ready.nar_hash.as_str());
            let software_inventory =
                evaluate_software_inventory(&state.config, &spec, nixpkgs_nar_hash).await;
            db::update_build_job_progress(
                &state.db,
                job.id,
                Some(90),
                "exporting",
                "Exporting closure to Nest cache",
            )
            .await?;
            let mut cached = match cache::export_output(
                &state.db,
                &state.config,
                &job,
                &output_info.output_path,
                &output_info.output_sha256,
                output_info.closure_size_bytes,
                output_info.evaluated_derivation.as_deref(),
            )
            .await
            {
                Ok(artifact) => artifact,
                Err(err) => {
                    db::finish_build_job(
                        &state.db,
                        job.id,
                        "failed",
                        &logs,
                        &format!("cache export failed: {}", safe_error(&err)),
                        &output_info.output_path,
                        &output_info.output_sha256,
                        output_info.output_size_bytes,
                        Some(exit_code.into()),
                        Some(admitted_result_metadata(
                            &state.config,
                            &job,
                            &target,
                            admitted_commit.as_deref(),
                            detected.as_ref().map(|ready| ready.nar_hash.as_str()),
                            Some("cache_export_failed"),
                        )),
                    )
                    .await?;
                    return Ok(());
                }
            };
            merge_build_metadata(
                &mut cached.metadata,
                &success_result_metadata(
                    &state.config,
                    &job,
                    &target,
                    &spec,
                    &software_inventory,
                    nixpkgs_nar_hash,
                ),
            );
            db::update_build_job_progress(
                &state.db,
                job.id,
                Some(96),
                "publishing",
                "Publishing cache artifact metadata",
            )
            .await?;
            cache::record_cached_artifact(
                &state.db,
                &state.config,
                &job,
                &spec.artifact_type,
                cached,
            )
            .await?;
            db::finish_build_job(
                &state.db,
                job.id,
                "succeeded",
                &logs,
                "",
                &output_info.output_path,
                &output_info.output_sha256,
                output_info.output_size_bytes,
                Some(exit_code.into()),
                Some(success_result_metadata(
                    &state.config,
                    &job,
                    &target,
                    &spec,
                    &software_inventory,
                    nixpkgs_nar_hash,
                )),
            )
            .await?;
            crate::software_updates::findings::candidate_built();
        }
        ProcessOutcome::Failed(exit_code) => {
            let oom_killed = oom_kills_after > oom_kills_before;
            let failure = failure::classify_nix_build_failure(&logs, oom_killed);
            let mut metadata = admitted_result_metadata(
                &state.config,
                &job,
                &target,
                admitted_commit.as_deref(),
                detected.as_ref().map(|ready| ready.nar_hash.as_str()),
                Some(failure.kind),
            );
            if let (Some(map), false) =
                (metadata.as_object_mut(), failure.failed_packages.is_empty())
            {
                map.insert(
                    failure::FAILED_PACKAGES_KEY.to_string(),
                    json!(failure.failed_packages),
                );
            }
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                &logs,
                &failure.message,
                "",
                "",
                0,
                Some(exit_code.into()),
                Some(metadata),
            )
            .await?;
        }
        ProcessOutcome::Cancelled => {
            db::finish_build_job(
                &state.db,
                job.id,
                "cancelled",
                &logs,
                "build cancelled by Tiaris",
                "",
                "",
                0,
                None,
                Some(admitted_result_metadata(
                    &state.config,
                    &job,
                    &target,
                    admitted_commit.as_deref(),
                    detected.as_ref().map(|ready| ready.nar_hash.as_str()),
                    Some("cancelled"),
                )),
            )
            .await?;
        }
        ProcessOutcome::TimedOut => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                &logs,
                "build exceeded configured timeout",
                "",
                "",
                0,
                None,
                Some(admitted_result_metadata(
                    &state.config,
                    &job,
                    &target,
                    admitted_commit.as_deref(),
                    detected.as_ref().map(|ready| ready.nar_hash.as_str()),
                    Some("build_timeout"),
                )),
            )
            .await?;
        }
    }
    Ok(())
}

/// A replica copy mirrors a verified closure from an approved sibling Nest
/// instead of building it. The cache module verifies every member against
/// the origin's signature and file hash and re-verifies the mirrored closure
/// under this node's key; the job then publishes exactly like a build.
async fn execute_replica_copy(
    state: &AppState,
    job: &BuildJob,
    spec: &ValidatedBuildSpec,
    target: &BuildTargetConfig,
    source: &ValidatedClosureSource,
    admitted_commit: Option<&str>,
    nixpkgs_nar_hash: Option<&str>,
) -> Result<()> {
    db::update_build_job_progress(
        &state.db,
        job.id,
        Some(25),
        "copying",
        &format!(
            "Mirroring the verified closure from Nest {}",
            source.server_device_id
        ),
    )
    .await?;
    let imported = cache::import_replica_closure(
        &state.db,
        &state.config,
        job,
        cache::ReplicaClosureSource {
            cache_base_url: &source.cache_base_url,
            public_key: &source.public_key,
            toplevel_store_path: &source.toplevel_store_path,
            closure_store_paths_sha256: &source.closure_store_paths_sha256,
            closure_member_count: source.closure_member_count,
            evaluated_derivation: source.evaluated_derivation.as_deref(),
        },
    )
    .await;
    let (mut cached, summary) = match imported {
        Ok(imported) => imported,
        Err(err) => {
            db::finish_build_job(
                &state.db,
                job.id,
                "failed",
                "",
                &format!("replica copy failed: {}", safe_error(&err)),
                "",
                "",
                0,
                None,
                Some(admitted_result_metadata(
                    &state.config,
                    job,
                    target,
                    admitted_commit,
                    nixpkgs_nar_hash,
                    Some("replica_copy_failed"),
                )),
            )
            .await?;
            return Ok(());
        }
    };
    if summary.output_size_bytes as u64 > state.config.build.max_artifact_size_bytes {
        db::finish_build_job(
            &state.db,
            job.id,
            "failed",
            "",
            "mirrored output exceeded max_artifact_size_bytes",
            &source.toplevel_store_path,
            &summary.output_sha256,
            summary.output_size_bytes,
            None,
            Some(admitted_result_metadata(
                &state.config,
                job,
                target,
                admitted_commit,
                nixpkgs_nar_hash,
                Some("artifact_too_large"),
            )),
        )
        .await?;
        return Ok(());
    }
    db::update_build_job_progress(
        &state.db,
        job.id,
        Some(90),
        "exporting",
        "Verified mirrored closure in Nest cache",
    )
    .await?;
    let software_inventory =
        evaluate_software_inventory(&state.config, spec, nixpkgs_nar_hash).await;
    merge_build_metadata(
        &mut cached.metadata,
        &success_result_metadata(
            &state.config,
            job,
            target,
            spec,
            &software_inventory,
            nixpkgs_nar_hash,
        ),
    );
    db::update_build_job_progress(
        &state.db,
        job.id,
        Some(96),
        "publishing",
        "Publishing cache artifact metadata",
    )
    .await?;
    cache::record_cached_artifact(&state.db, &state.config, job, &spec.artifact_type, cached)
        .await?;
    db::finish_build_job(
        &state.db,
        job.id,
        "succeeded",
        &format!(
            "mirrored {} closure members from {}\n",
            summary.members, source.cache_base_url
        ),
        "",
        &source.toplevel_store_path,
        &summary.output_sha256,
        summary.output_size_bytes,
        Some(0),
        Some(success_result_metadata(
            &state.config,
            job,
            target,
            spec,
            &software_inventory,
            nixpkgs_nar_hash,
        )),
    )
    .await?;
    Ok(())
}

fn capacity_meets_minimum(actual: u64, minimum: u64) -> bool {
    actual >= minimum.saturating_sub(CAPACITY_ACCOUNTING_TOLERANCE_BYTES)
}

fn validate_build_spec(config: &AppConfig, job: &BuildJob) -> Result<ValidatedBuildSpec> {
    protected_material::validate_build_spec(&job.build_spec)?;
    let raw_build_input = job.build_spec.get("build_input").cloned();
    let spec: BuildSpec = serde_json::from_value(job.build_spec.clone())
        .context("build_spec does not match schema")?;
    if spec.schema_version != 1 {
        bail!("unsupported build spec schema_version");
    }
    let artifact_type = normalize_artifact_type(&spec.artifact_type)?;
    let target = normalize_target(&spec.target)?;
    let system = normalize_system(&spec.system)?;
    if !config
        .build
        .allowed_systems
        .iter()
        .any(|value| value == &system)
    {
        bail!("system is not allowed on this Nest node");
    }
    let input_revision = normalize_revision(&spec.input_revision)?;
    let input_config_hash = normalize_sha256(&spec.input_config_hash)?;
    if artifact_type != job.requested_artifact_type {
        bail!("build_spec artifact_type does not match job artifact type");
    }
    if target != job.target || system != job.system {
        bail!("build_spec target/system does not match job row");
    }
    if input_revision != job.input_revision || input_config_hash != job.input_config_hash {
        bail!("build_spec input revision/hash does not match job row");
    }
    let blueprint_id = spec
        .blueprint_id
        .map(|value| normalize_optional_uuidish("blueprint_id", &value))
        .transpose()?;
    let blueprint_revision_id = spec
        .blueprint_revision_id
        .map(|value| normalize_optional_uuidish("blueprint_revision_id", &value))
        .transpose()?;
    let blueprint_revision_config_hash = spec
        .blueprint_revision_config_hash
        .map(|value| normalize_sha256(&value))
        .transpose()?;
    let build_input = spec
        .build_input
        .map(validate_blueprint_build_input)
        .transpose()?;
    if build_input.is_some() && artifact_type != "nixos_closure" {
        bail!("blueprint build_input requires artifact_type nixos_closure");
    }
    let nixpkgs_commit = spec
        .nixpkgs_commit
        .map(|value| normalize_nixpkgs_commit(&value))
        .transpose()?;
    let source_lock_sha256 = spec
        .source_lock_sha256
        .map(|value| normalize_sha256(&value))
        .transpose()?;
    if build_input.is_some() && (nixpkgs_commit.is_none() || source_lock_sha256.is_none()) {
        bail!("Blueprint builds require nixpkgs_commit and source_lock_sha256");
    }
    if spec.software_package_refs.len() > 128 {
        bail!("software_package_refs exceeds 128 items");
    }
    let software_package_refs = spec
        .software_package_refs
        .iter()
        .map(|value| normalize_package_ref(value))
        .collect::<Result<Vec<_>>>()?;
    if target == "installer_target" {
        validate_installer_target_build_binding(
            &input_revision,
            &input_config_hash,
            blueprint_id.as_deref(),
            blueprint_revision_id.as_deref(),
            blueprint_revision_config_hash.as_deref(),
            nixpkgs_commit.as_deref(),
            source_lock_sha256.as_deref(),
            build_input.as_ref().ok_or_else(|| {
                anyhow!("installer target requires its exact Blueprint build input")
            })?,
            raw_build_input.as_ref().ok_or_else(|| {
                anyhow!("installer target requires its exact raw Blueprint build input")
            })?,
        )?;
    }
    let closure_source = spec
        .closure_source
        .as_ref()
        .map(|source| validate_closure_source(source, &target))
        .transpose()?;
    Ok(ValidatedBuildSpec {
        artifact_type,
        target,
        system,
        input_revision,
        input_config_hash,
        blueprint_id,
        blueprint_revision_id,
        blueprint_revision_config_hash,
        nixpkgs_commit,
        source_lock_sha256,
        software_package_refs,
        build_input,
        closure_source,
    })
}

const CLOSURE_SOURCE_KIND_NEST_CACHE: &str = "nest_cache";
const MAX_CLOSURE_SOURCE_MEMBERS: u64 = 200_000;
const MAX_CLOSURE_SOURCE_URL_BYTES: usize = 2048;

fn valid_closure_source_store_path(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("/nix/store/") else {
        return false;
    };
    let Some((hash, name)) = rest.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        && !name.is_empty()
        && name.len() <= 211
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
        })
}

/// A replica copy is accepted only for exact installer-target closures, from
/// an http(s) cache base URL without credentials, query, or fragment, with a
/// parseable Nix cache public key and a bounded exact closure identity.
fn validate_closure_source(source: &ClosureSource, target: &str) -> Result<ValidatedClosureSource> {
    if target != "installer_target" {
        bail!("closure_source is only accepted for installer_target builds");
    }
    if source.kind != CLOSURE_SOURCE_KIND_NEST_CACHE {
        bail!("unsupported closure_source kind");
    }
    let server_device_id = source.server_device_id.trim();
    if server_device_id.is_empty()
        || server_device_id.len() > 128
        || server_device_id
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("closure_source server_device_id has an invalid shape");
    }
    let cache_base_url = source.cache_base_url.trim();
    let parsed = reqwest::Url::parse(cache_base_url).context("closure_source cache_base_url")?;
    if cache_base_url.len() > MAX_CLOSURE_SOURCE_URL_BYTES
        || !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || cache_base_url.ends_with('/')
    {
        bail!("closure_source cache_base_url must be a plain http(s) cache base URL");
    }
    let public_key = source.public_key.trim();
    crate::cache::parse_cache_public_key(public_key).context("closure_source public_key")?;
    let toplevel_store_path = source.toplevel_store_path.trim();
    if !valid_closure_source_store_path(toplevel_store_path) {
        bail!("closure_source toplevel_store_path is not a store path");
    }
    let closure_store_paths_sha256 = normalize_sha256(&source.closure_store_paths_sha256)?;
    if !(1..=MAX_CLOSURE_SOURCE_MEMBERS).contains(&source.closure_member_count) {
        bail!("closure_source closure_member_count is out of range");
    }
    let evaluated_derivation = source
        .evaluated_derivation
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            if !valid_closure_source_store_path(value) || !value.ends_with(".drv") {
                bail!("closure_source evaluated_derivation must be a .drv store path");
            }
            Ok(value.to_string())
        })
        .transpose()?;
    Ok(ValidatedClosureSource {
        server_device_id: server_device_id.to_string(),
        cache_base_url: cache_base_url.to_string(),
        public_key: public_key.to_string(),
        toplevel_store_path: toplevel_store_path.to_string(),
        closure_store_paths_sha256,
        closure_member_count: source.closure_member_count,
        evaluated_derivation,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_installer_target_build_binding(
    input_revision: &str,
    input_config_hash: &str,
    blueprint_id: Option<&str>,
    blueprint_revision_id: Option<&str>,
    blueprint_revision_config_hash: Option<&str>,
    nixpkgs_commit: Option<&str>,
    source_lock_sha256: Option<&str>,
    build_input: &ValidatedBlueprintBuildInput,
    raw_build_input: &Value,
) -> Result<()> {
    if canonical_json_sha256(raw_build_input)? != input_config_hash {
        bail!("installer target build input does not match its canonical hash");
    }
    let identity = build_input
        .installer_target
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("installer target identity is required"))?;
    let identity_text = |field: &str| {
        identity
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("installer_target.{field} is required"))
    };
    let expected_state = build_input
        .expected_state
        .as_ref()
        .ok_or_else(|| anyhow!("installer target expected state is required"))?;
    let artifact_config_hash = normalize_sha256(
        expected_state
            .pointer("/deployment/artifact_config_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("installer target artifact config hash is required"))?,
    )?;
    if blueprint_id != Some(identity_text("blueprint_id")?)
        || blueprint_revision_id != Some(identity_text("blueprint_revision_id")?)
        || blueprint_revision_id != Some(input_revision)
        || nixpkgs_commit != Some(identity_text("nixpkgs_revision")?)
        || source_lock_sha256 != Some(identity_text("source_lock_sha256")?)
        || blueprint_revision_config_hash != Some(artifact_config_hash.as_str())
    {
        bail!("installer target provenance fields do not match");
    }
    if identity.get("schema").and_then(Value::as_str) == Some(INSTALLER_TARGET_BUILD_SCHEMA_V3)
        && blueprint_revision_config_hash != Some(identity_text("blueprint_revision_config_hash")?)
    {
        bail!("installer target provenance fields do not match");
    }
    Ok(())
}

fn canonical_json_sha256(value: &Value) -> Result<String> {
    fn write(value: &Value, output: &mut Vec<u8>) -> serde_json::Result<()> {
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                serde_json::to_writer(output, value)
            }
            Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write(value, output)?;
                }
                output.push(b']');
                Ok(())
            }
            Value::Object(object) => {
                output.push(b'{');
                let mut keys = object.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    serde_json::to_writer(&mut *output, key)?;
                    output.push(b':');
                    write(&object[key], output)?;
                }
                output.push(b'}');
                Ok(())
            }
        }
    }
    let mut canonical = Vec::new();
    write(value, &mut canonical).context("serialize canonical installer build input")?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn validate_blueprint_build_input(
    input: BlueprintBuildInput,
) -> Result<ValidatedBlueprintBuildInput> {
    let kind = input.kind.trim();
    if !matches!(
        kind,
        BLUEPRINT_BUILD_INPUT_KIND
            | LEGACY_DESKTOP_EXPERIENCE_BUILD_INPUT_KIND
            | INSTALLER_TARGET_BUILD_INPUT_KIND
    ) {
        bail!("unsupported build_input kind");
    }
    let installer_target_build = kind == INSTALLER_TARGET_BUILD_INPUT_KIND;
    if !installer_target_build {
        protected_material::validate_generated_nix(&input.generated_nix)?;
    }
    if let Some(desktop_module_nix) = input.desktop_module_nix.as_deref() {
        protected_material::validate_desktop_module_nix(desktop_module_nix)?;
    }
    if let Some(expected_state) = input.expected_state.as_ref() {
        if installer_target_build {
            protected_material::validate_installer_target_expected_state(expected_state)?;
            protected_material::validate_installer_target_generated_nix(
                &input.generated_nix,
                expected_state,
            )?;
        } else {
            protected_material::validate_expected_state(expected_state)?;
        }
    }
    if input.generated_nix.trim().is_empty() {
        bail!("build_input.generated_nix is required");
    }
    if input.generated_nix.len() > MAX_GENERATED_NIX_BYTES {
        bail!("build_input.generated_nix is too large");
    }
    if input.generated_nix.bytes().any(|byte| byte == 0) {
        bail!("build_input.generated_nix must not contain NUL bytes");
    }
    if let Some(desktop_module_nix) = input.desktop_module_nix.as_deref() {
        if desktop_module_nix.trim().is_empty() {
            bail!("build_input.desktop_module_nix must not be empty");
        }
        if desktop_module_nix.len() > MAX_DESKTOP_MODULE_NIX_BYTES {
            bail!("build_input.desktop_module_nix is too large");
        }
        if desktop_module_nix.bytes().any(|byte| byte == 0) {
            bail!("build_input.desktop_module_nix must not contain NUL bytes");
        }
        let expected_state = input
            .expected_state
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("build_input.expected_state must be an object when desktop_module_nix is supplied"))?;
        if !matches!(
            expected_state.get("schema").and_then(Value::as_str),
            Some("tiaris.blueprint.expected-state.v1" | "tiaris.blueprint.expected-state.v2")
        ) {
            bail!("build_input.expected_state has an unsupported schema");
        }
    } else if input.expected_state.is_some() && !installer_target_build {
        bail!("build_input.expected_state requires desktop_module_nix");
    }
    if installer_target_build {
        let hardware_module_nix = input
            .hardware_module_nix
            .as_deref()
            .ok_or_else(|| anyhow!("installer target requires hardware_module_nix"))?;
        validate_bounded_nix_input(
            "build_input.hardware_module_nix",
            hardware_module_nix,
            MAX_HARDWARE_MODULE_NIX_BYTES,
        )?;
        protected_material::validate_installer_target_non_blueprint_module(
            "build_spec.build_input.hardware_module_nix",
            hardware_module_nix,
        )?;
        let target_module_nix = input
            .target_module_nix
            .as_deref()
            .ok_or_else(|| anyhow!("installer target requires target_module_nix"))?;
        validate_bounded_nix_input(
            "build_input.target_module_nix",
            target_module_nix,
            MAX_TARGET_MODULE_NIX_BYTES,
        )?;
        protected_material::validate_installer_target_non_blueprint_module(
            "build_spec.build_input.target_module_nix",
            target_module_nix,
        )?;
        let manage_source_revision = input
            .manage_source_revision
            .as_deref()
            .ok_or_else(|| anyhow!("installer target requires manage_source_revision"))?;
        normalize_nixpkgs_commit(manage_source_revision)
            .context("normalize installer target Tiaris revision")?;
        validate_installer_target_identity(
            input
                .installer_target
                .as_ref()
                .ok_or_else(|| anyhow!("installer target identity is required"))?,
            manage_source_revision,
            InstallerTargetModuleDigests {
                generated_nix: &input.generated_nix,
                expected_state: input.expected_state.as_ref(),
                hardware_module_nix,
                target_module_nix,
            },
        )?;
        let expected_revision = input
            .expected_state
            .as_ref()
            .and_then(|value| value.pointer("/deployment/blueprint_revision_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("installer target expected-state revision is required"))?;
        if input
            .installer_target
            .as_ref()
            .and_then(|value| value.get("blueprint_revision_id"))
            .and_then(Value::as_str)
            != Some(expected_revision)
        {
            bail!("installer target Blueprint revision fields do not match");
        }
        if input.desktop_module_nix.is_some() || input.expected_state.is_none() {
            bail!(
                "installer target must use the packaged Tiaris desktop module and requires expected state"
            );
        }
    } else if input.hardware_module_nix.is_some()
        || input.target_module_nix.is_some()
        || input.manage_source_revision.is_some()
        || input.installer_target.is_some()
    {
        bail!("installer target fields require installer_target_nixos_module");
    }
    let wallpaper_asset = input
        .wallpaper_asset
        .map(validate_blueprint_wallpaper_asset)
        .transpose()?;
    Ok(ValidatedBlueprintBuildInput {
        kind: kind.to_string(),
        generated_nix: input.generated_nix,
        desktop_module_nix: input.desktop_module_nix,
        expected_state: input.expected_state,
        blueprint_name: input
            .blueprint_name
            .map(|value| bounded_metadata_text(&value, 200))
            .filter(|value| !value.is_empty()),
        blueprint_revision: input.blueprint_revision.filter(|value| *value > 0),
        hardware_module_nix: input.hardware_module_nix,
        target_module_nix: input.target_module_nix,
        manage_source_revision: input.manage_source_revision,
        installer_target: input.installer_target,
        wallpaper_asset,
    })
}

pub(crate) fn validate_blueprint_wallpaper_asset(
    mut asset: BlueprintWallpaperAsset,
) -> Result<BlueprintWallpaperAsset> {
    if asset.schema != "tiaris.blueprint-wallpaper.v1" {
        bail!("build_input.wallpaper_asset has an unsupported schema");
    }
    asset.id = normalize_optional_uuidish("wallpaper_asset.id", &asset.id)?;
    asset.blueprint_revision_id = normalize_optional_uuidish(
        "wallpaper_asset.blueprint_revision_id",
        &asset.blueprint_revision_id,
    )?;
    asset.sha256 = normalize_sha256(&asset.sha256)?;
    asset.name = bounded_metadata_text(&asset.name, 160);
    if asset.name.is_empty() {
        bail!("build_input.wallpaper_asset.name is required");
    }
    if asset.mime_type != "image/jpeg" {
        bail!("build_input.wallpaper_asset must be image/jpeg");
    }
    if asset.size_bytes == 0 || asset.size_bytes > 4 * 1024 * 1024 {
        bail!("build_input.wallpaper_asset size is invalid");
    }
    if asset.width == 0 || asset.height == 0 || asset.width > 3840 || asset.height > 2160 {
        bail!("build_input.wallpaper_asset dimensions are invalid");
    }
    Ok(asset)
}

pub(crate) fn wallpaper_asset_cache_path(config: &AppConfig, sha256: &str) -> Result<PathBuf> {
    let sha256 = normalize_sha256(sha256)?;
    Ok(config
        .build
        .work_dir
        .join("wallpaper-assets")
        .join(format!("{sha256}.jpg")))
}

fn verify_cached_wallpaper_asset(
    config: &AppConfig,
    asset: &BlueprintWallpaperAsset,
) -> Result<PathBuf> {
    let path = wallpaper_asset_cache_path(config, &asset.sha256)?;
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect Blueprint wallpaper asset {}", path.display()))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != asset.size_bytes
    {
        bail!("cached Blueprint wallpaper asset has an invalid file identity");
    }
    let bytes = fs::read(&path)
        .with_context(|| format!("read Blueprint wallpaper asset {}", path.display()))?;
    if !bytes.starts_with(&[0xff, 0xd8, 0xff])
        || !bytes.ends_with(&[0xff, 0xd9])
        || hex::encode(Sha256::digest(&bytes)) != asset.sha256
    {
        bail!("cached Blueprint wallpaper asset failed its integrity check");
    }
    Ok(path)
}

fn validate_bounded_nix_input(field: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must not be empty");
    }
    if value.len() > max_bytes {
        bail!("{field} is too large");
    }
    if value.bytes().any(|byte| byte == 0) {
        bail!("{field} must not contain NUL bytes");
    }
    // The whole BuildSpec has already passed the protected-material scanner;
    // keep this helper focused on the bounded text contract.
    Ok(())
}

struct InstallerTargetModuleDigests<'a> {
    generated_nix: &'a str,
    expected_state: Option<&'a Value>,
    hardware_module_nix: &'a str,
    target_module_nix: &'a str,
}

fn sha256_hex_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// v3: every digest in the identity must match the module text Nest actually
/// evaluates, so a reported identity is proof of the exact closure inputs.
fn validate_installer_target_cohort_identity(
    object: &serde_json::Map<String, Value>,
    manage_revision: &str,
    digests: InstallerTargetModuleDigests<'_>,
) -> Result<()> {
    let expected = [
        "schema",
        "blueprint_id",
        "blueprint_revision_id",
        "blueprint_revision_config_hash",
        "generated_nix_sha256",
        "expected_state_sha256",
        "hardware_driver_policy",
        "hardware_module_sha256",
        "target_module_sha256",
        "manage_source_revision",
        "nixpkgs_revision",
        "source_lock_sha256",
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    let actual = object.keys().map(String::as_str).collect::<HashSet<_>>();
    if actual != expected {
        bail!("installer_target does not match its schema");
    }
    for field in ["blueprint_id", "blueprint_revision_id"] {
        normalize_canonical_uuid(
            field,
            object
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("installer_target.{field} is required"))?,
        )?;
    }
    let text = |field: &str| -> Result<&str> {
        object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("installer_target.{field} is required"))
    };
    for field in [
        "blueprint_revision_config_hash",
        "generated_nix_sha256",
        "expected_state_sha256",
        "hardware_module_sha256",
        "target_module_sha256",
        "source_lock_sha256",
    ] {
        normalize_sha256(text(field)?)
            .with_context(|| format!("normalize installer_target.{field}"))?;
    }
    if text("generated_nix_sha256")? != sha256_hex_text(digests.generated_nix) {
        bail!("installer_target.generated_nix_sha256 does not match the Blueprint module");
    }
    if text("hardware_module_sha256")? != sha256_hex_text(digests.hardware_module_nix) {
        bail!("installer_target.hardware_module_sha256 does not match the hardware module");
    }
    if text("target_module_sha256")? != sha256_hex_text(digests.target_module_nix) {
        bail!("installer_target.target_module_sha256 does not match the target module");
    }
    let expected_state = digests
        .expected_state
        .ok_or_else(|| anyhow!("installer target expected state is required"))?;
    if text("expected_state_sha256")? != canonical_json_sha256(expected_state)? {
        bail!("installer_target.expected_state_sha256 does not match the expected state");
    }
    if normalize_nixpkgs_commit(text("manage_source_revision")?)? != manage_revision {
        bail!("installer target Tiaris revision fields do not match");
    }
    normalize_nixpkgs_commit(text("nixpkgs_revision")?)?;
    let policy = text("hardware_driver_policy")?;
    if !matches!(
        policy,
        "auto" | "open_graphics" | "nvidia_open" | "nvidia_proprietary" | "disabled"
    ) {
        bail!("installer_target.hardware_driver_policy is invalid");
    }
    Ok(())
}

fn validate_installer_target_identity(
    value: &Value,
    manage_revision: &str,
    digests: InstallerTargetModuleDigests<'_>,
) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("installer_target must be an object"))?;
    let schema = object
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("installer_target.schema is required"))?;
    if schema == INSTALLER_TARGET_BUILD_SCHEMA_V3 {
        return validate_installer_target_cohort_identity(object, manage_revision, digests);
    }
    if !matches!(
        schema,
        INSTALLER_TARGET_BUILD_SCHEMA_V1 | INSTALLER_TARGET_BUILD_SCHEMA
    ) {
        bail!("unsupported installer_target schema");
    }
    let mut expected = [
        "schema",
        "preparation_id",
        "device_id",
        "device_incarnation_id",
        "blueprint_id",
        "blueprint_revision_id",
        "hardware_facts_sha256",
        "hardware_driver_policy",
        "disk_layout_sha256",
        "nest_device_id",
        "bundle_sha256",
        "profile_id",
        "managed_device_id",
        "reinstall_request_id",
        "manage_source_revision",
        "nixpkgs_revision",
        "source_lock_sha256",
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    // v1 shipped before frozen execution configuration was part of the build
    // identity. Accept its original exact shape and the briefly emitted
    // additive shape so retained jobs remain retryable across rolling
    // upgrades. Every newly issued v2 identity must carry the hash.
    if schema == INSTALLER_TARGET_BUILD_SCHEMA
        || (schema == INSTALLER_TARGET_BUILD_SCHEMA_V1
            && object.contains_key("effective_config_sha256"))
    {
        expected.insert("effective_config_sha256");
    }
    let actual = object.keys().map(String::as_str).collect::<HashSet<_>>();
    if actual != expected {
        bail!("installer_target does not match its schema");
    }
    for field in [
        "preparation_id",
        "device_incarnation_id",
        "blueprint_id",
        "blueprint_revision_id",
        "profile_id",
    ] {
        normalize_canonical_uuid(
            field,
            object
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("installer_target.{field} is required"))?,
        )?;
    }
    for field in ["managed_device_id", "reinstall_request_id"] {
        if let Some(value) = object.get(field).and_then(Value::as_str) {
            if field == "reinstall_request_id" {
                normalize_canonical_uuid(field, value)?;
            } else {
                normalize_public_identifier(field, value, 160)?;
            }
        } else if !object.get(field).is_some_and(Value::is_null) {
            bail!("installer_target.{field} must be a string or null");
        }
    }
    if object.get("managed_device_id").is_some_and(Value::is_null)
        != object
            .get("reinstall_request_id")
            .is_some_and(Value::is_null)
    {
        bail!("installer_target reinstall bindings must both be present or both be null");
    }
    for field in ["device_id", "nest_device_id"] {
        normalize_public_identifier(
            field,
            object
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("installer_target.{field} is required"))?,
            160,
        )?;
    }
    for field in [
        "hardware_facts_sha256",
        "disk_layout_sha256",
        "bundle_sha256",
        "source_lock_sha256",
    ] {
        normalize_sha256(
            object
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("installer_target.{field} is required"))?,
        )?;
    }
    if let Some(effective_config_sha256) = object.get("effective_config_sha256") {
        let effective_config_sha256 = effective_config_sha256.as_str().ok_or_else(|| {
            anyhow!("installer_target.effective_config_sha256 must be a SHA-256 string")
        })?;
        normalize_sha256(effective_config_sha256)
            .context("normalize installer_target.effective_config_sha256")?;
    }
    let identity_manage_revision = object
        .get("manage_source_revision")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("installer_target.manage_source_revision is required"))?;
    if normalize_nixpkgs_commit(identity_manage_revision)? != manage_revision {
        bail!("installer target Tiaris revision fields do not match");
    }
    normalize_nixpkgs_commit(
        object
            .get("nixpkgs_revision")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("installer_target.nixpkgs_revision is required"))?,
    )?;
    let policy = object
        .get("hardware_driver_policy")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("installer_target.hardware_driver_policy is required"))?;
    if !matches!(
        policy,
        "auto" | "open_graphics" | "nvidia_open" | "nvidia_proprietary" | "disabled"
    ) {
        bail!("installer_target.hardware_driver_policy is invalid");
    }
    Ok(())
}

fn normalize_canonical_uuid(field: &str, value: &str) -> Result<String> {
    let parsed = uuid::Uuid::parse_str(value).with_context(|| format!("{field} must be a UUID"))?;
    let canonical = parsed.hyphenated().to_string();
    if value != canonical {
        bail!("{field} must be a canonical lowercase UUID");
    }
    Ok(canonical)
}

fn normalize_public_identifier(field: &str, value: &str, max_chars: usize) -> Result<String> {
    if value.is_empty()
        || value != value.trim()
        || value.chars().count() > max_chars
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("{field} is invalid");
    }
    Ok(value.to_string())
}

#[cfg(test)]
fn build_target<'a>(
    config: &'a AppConfig,
    spec: &ValidatedBuildSpec,
) -> Result<&'a BuildTargetConfig> {
    build_target_for_detected_commit(config, spec, None)
}

#[cfg(test)]
fn build_target_for_detected_commit<'a>(
    config: &'a AppConfig,
    spec: &ValidatedBuildSpec,
    detected: Option<&str>,
) -> Result<&'a BuildTargetConfig> {
    admit_build_target(config, spec, detected).map(|admitted| admitted.target)
}

/// The configured target a job builds and the nixpkgs commit it was admitted
/// at.
struct AdmittedTarget<'a> {
    target: &'a BuildTargetConfig,
    nixpkgs_commit: Option<String>,
}

/// A Blueprint job is admitted at the target's release pin or at the ready
/// detected commit `detected` (looked up from the job's own commit). A job
/// without a Blueprint builds the target's own flake: it is admitted at that
/// flake's nixpkgs pin, and a `nixpkgs_commit` it names must be that pin.
fn admit_build_target<'a>(
    config: &'a AppConfig,
    spec: &ValidatedBuildSpec,
    detected: Option<&str>,
) -> Result<AdmittedTarget<'a>> {
    let target = config
        .build
        .targets
        .iter()
        .find(|target| {
            target.artifact_type == spec.artifact_type
                && build_target_names_compatible(&target.target, &spec.target)
                && target.system == spec.system
        })
        .ok_or_else(|| {
            anyhow!("no configured build target matched artifact_type, target, and system")
        })?;
    let target_pin = pinned_nixpkgs_revision(&target.flake).ok();
    let commit = spec.nixpkgs_commit.as_deref();
    let nixpkgs_commit = if spec.build_input.is_some() {
        let configured_revision = pinned_nixpkgs_revision(&target.flake)
            .context("validate configured Blueprint nixpkgs pin")?;
        if commit == Some(configured_revision) || (detected.is_some() && commit == detected) {
            commit.map(str::to_string)
        } else {
            bail!(
                "Blueprint nixpkgs_commit does not match this Nest target's reviewed source pin or a ready detected commit"
            );
        }
    } else {
        if commit.is_some() && commit != target_pin {
            bail!("nixpkgs_commit does not match this Nest target's nixpkgs pin");
        }
        target_pin.map(str::to_string)
    };
    Ok(AdmittedTarget {
        target,
        nixpkgs_commit,
    })
}

fn build_target_names_compatible(configured: &str, requested: &str) -> bool {
    configured == requested
        || matches!(
            (configured, requested),
            ("desktop_experience", "blueprint")
                | ("blueprint", "desktop_experience")
                | ("blueprint", "installer_target")
                | ("desktop_experience", "installer_target")
        )
}

fn build_capacity() -> Result<BuildCapacity> {
    if let Some((memory_bytes, swap_bytes)) = crate::resources::capacity() {
        return Ok(BuildCapacity {
            memory_bytes,
            swap_bytes,
        });
    }
    // Hardened systemd units may hide /proc/meminfo, so retain sysinfo(2) as a
    // fallback when the cgroup controller reports an unbounded root.
    let sysinfo = kernel_sysinfo_capacity();
    let memory_bytes = read_cgroup_limit("/sys/fs/cgroup/memory.max")?
        .or_else(|| read_meminfo_bytes("MemTotal"))
        .or_else(|| sysinfo.map(|capacity| capacity.memory_bytes))
        .ok_or_else(|| anyhow!("memory limit and MemTotal were unavailable"))?;
    let swap_bytes = read_cgroup_limit("/sys/fs/cgroup/memory.swap.max")?
        .or_else(|| read_meminfo_bytes("SwapTotal"))
        .or_else(|| sysinfo.map(|capacity| capacity.swap_bytes))
        .unwrap_or(0);
    Ok(BuildCapacity {
        memory_bytes,
        swap_bytes,
    })
}

fn kernel_sysinfo_capacity() -> Option<BuildCapacity> {
    let mut info = std::mem::MaybeUninit::<libc::sysinfo>::zeroed();
    // SAFETY: sysinfo(2) initializes the provided libc::sysinfo structure on
    // success, and we only assume initialization after checking its return.
    if unsafe { libc::sysinfo(info.as_mut_ptr()) } != 0 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    Some(capacity_from_sysinfo_values(
        info.totalram,
        info.totalswap,
        u64::from(info.mem_unit),
    ))
}

fn capacity_from_sysinfo_values(totalram: u64, totalswap: u64, mem_unit: u64) -> BuildCapacity {
    BuildCapacity {
        memory_bytes: totalram.saturating_mul(mem_unit),
        swap_bytes: totalswap.saturating_mul(mem_unit),
    }
}

fn read_cgroup_limit(path: &str) -> Result<Option<u64>> {
    match fs::read_to_string(path) {
        Ok(raw) => parse_cgroup_limit(&raw).with_context(|| format!("parse cgroup limit {path}")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read cgroup limit {path}")),
    }
}

fn parse_cgroup_limit(raw: &str) -> Result<Option<u64>> {
    let raw = raw.trim();
    if raw == "max" || raw.is_empty() {
        return Ok(None);
    }
    Ok(Some(raw.parse().context("cgroup limit is not an integer")?))
}

fn read_meminfo_bytes(field: &str) -> Option<u64> {
    let raw = fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo_bytes(&raw, field)
}

fn parse_meminfo_bytes(raw: &str, field: &str) -> Option<u64> {
    let value_kib = raw.lines().find_map(|line| {
        let (name, rest) = line.split_once(':')?;
        if name != field {
            return None;
        }
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })?;
    value_kib.checked_mul(1024)
}

fn cgroup_oom_kill_count() -> u64 {
    crate::resources::oom_kills()
}

#[cfg(test)]
fn parse_memory_event(raw: &str, event: &str) -> Option<u64> {
    raw.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == event)
            .then(|| fields.next()?.parse::<u64>().ok())
            .flatten()
    })
}

const SOFTWARE_INVENTORY_PROBE_TIMEOUT_SECS: u64 = 15;
const SOFTWARE_INVENTORY_TOTAL_TIMEOUT_SECS: u64 = 120;
const SOFTWARE_INVENTORY_STDOUT_MAX_BYTES: usize = 16 * 1024;
const SOFTWARE_INVENTORY_STDERR_MAX_BYTES: usize = 64 * 1024;
const REJECT_FLAKE_CONFIG_NIX_OPTION: [&str; 3] = ["--option", "accept-flake-config", "false"];
const REQUIRE_BUILD_SANDBOX_NIX_OPTION: [&str; 3] = ["--option", "sandbox", "true"];

fn append_build_isolation_nix_options(args: &mut Vec<String>) {
    // Nest is a trusted Nix client because it exports and signs closures.
    // Pin the daemon-side sandbox and refuse flake-supplied client settings on
    // every path so a Blueprint cannot use that trust to relax isolation.
    args.extend(
        REJECT_FLAKE_CONFIG_NIX_OPTION
            .iter()
            .map(|value| value.to_string()),
    );
    args.extend(
        REQUIRE_BUILD_SANDBOX_NIX_OPTION
            .iter()
            .map(|value| value.to_string()),
    );
}

#[derive(Clone, Copy)]
struct SoftwareInventoryLimits {
    probe_timeout: Duration,
    total_timeout: Duration,
    stdout_max_bytes: usize,
    stderr_max_bytes: usize,
}

impl Default for SoftwareInventoryLimits {
    fn default() -> Self {
        Self {
            probe_timeout: Duration::from_secs(SOFTWARE_INVENTORY_PROBE_TIMEOUT_SECS),
            total_timeout: Duration::from_secs(SOFTWARE_INVENTORY_TOTAL_TIMEOUT_SECS),
            stdout_max_bytes: SOFTWARE_INVENTORY_STDOUT_MAX_BYTES,
            stderr_max_bytes: SOFTWARE_INVENTORY_STDERR_MAX_BYTES,
        }
    }
}

/// A safe store path's store item (`<hash>-<name>`).
pub(crate) fn store_path_item(path: &str) -> Option<&str> {
    safe_nix_store_path(path)
        .then(|| path.strip_prefix("/nix/store/")?.split('/').next())
        .flatten()
}

fn safe_nix_store_path(value: &str) -> bool {
    let Some(relative) = value.strip_prefix("/nix/store/") else {
        return false;
    };
    let components = relative.split('/').collect::<Vec<_>>();
    if components.is_empty()
        || components.iter().any(|component| component.is_empty())
        || components.iter().skip(1).any(|component| {
            matches!(
                Path::new(component).components().next(),
                Some(std::path::Component::CurDir | std::path::Component::ParentDir)
            ) || Path::new(component).components().count() != 1
        })
    {
        return false;
    }
    let store_item = components[0];
    let Some((hash, name)) = store_item.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        && !name.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'-')
        })
}

fn normalize_store_path(path: &str) -> Option<String> {
    let path = if path.starts_with("/nix/store/") {
        path.to_string()
    } else if !path.contains('/') {
        format!("/nix/store/{path}")
    } else {
        return None;
    };
    safe_nix_store_path(&path).then_some(path)
}

fn normalize_derivation_store_path(path: &str) -> Option<String> {
    let path = normalize_store_path(path)?;
    path.ends_with(".drv").then_some(path)
}

async fn ensure_nix_daemon_available(config: &AppConfig) -> Result<()> {
    let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
    command.args(["store", "ping", "--store", "daemon"]);
    let output = run_bounded_command(
        command,
        Duration::from_secs(30),
        4096,
        65536,
        "nix store ping",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "{}",
            String::from_utf8_lossy(&output.stderr)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    Ok(())
}

fn build_result_metadata(
    config: &AppConfig,
    job: &BuildJob,
    target: Option<&BuildTargetConfig>,
    error_kind: Option<&str>,
) -> Value {
    let mut metadata = job.cache_metadata.as_object().cloned().unwrap_or_default();
    metadata.insert(
        "result_schema".to_string(),
        json!("tiaris.nest.build.result.v1"),
    );
    metadata.insert(
        "resource_phase_peaks".into(),
        json!(crate::resources::job_peaks(job.id)),
    );
    metadata.insert("max_nix_jobs".into(), json!(config.build.max_nix_jobs));
    metadata.insert(
        "memory_per_build_bytes".into(),
        json!(config.build.memory_per_build_bytes),
    );
    metadata.insert(
        "max_build_cores".to_string(),
        json!(config.build.max_build_cores),
    );
    metadata.insert(
        "minimum_memory_bytes".to_string(),
        json!(config.build.minimum_memory_bytes),
    );
    metadata.insert(
        "minimum_swap_bytes".to_string(),
        json!(config.build.minimum_swap_bytes),
    );
    if let Some(target) = target {
        metadata.insert("nixpkgs_flake".to_string(), json!(target.flake));
        if let Ok(revision) = pinned_nixpkgs_revision(&target.flake) {
            metadata.insert("nixpkgs_revision".to_string(), json!(revision));
        }
    }
    // A retry may carry its predecessor's metadata: only this result's
    // failure names what failed.
    metadata.remove(failure::FAILED_PACKAGES_KEY);
    if let Some(error_kind) = error_kind {
        metadata.insert("error_kind".to_string(), json!(error_kind));
    } else {
        metadata.remove("error_kind");
    }
    Value::Object(metadata)
}

/// Result metadata of a job admitted at `admitted_commit`. At a detected
/// commit it names that commit and its narHash-pinned source instead of the
/// target's release pin.
fn admitted_result_metadata(
    config: &AppConfig,
    job: &BuildJob,
    target: &BuildTargetConfig,
    admitted_commit: Option<&str>,
    nixpkgs_nar_hash: Option<&str>,
    error_kind: Option<&str>,
) -> Value {
    let mut metadata = build_result_metadata(config, job, Some(target), error_kind);
    if let (Some(commit), Some(object)) = (admitted_commit, metadata.as_object_mut()) {
        object.insert("nixpkgs_revision".to_string(), json!(commit));
        if let Ok(flake) = nixpkgs_flake_ref(commit, nixpkgs_nar_hash) {
            object.insert("nixpkgs_flake".to_string(), json!(flake));
        }
    }
    metadata
}

fn success_result_metadata(
    config: &AppConfig,
    job: &BuildJob,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    software_inventory: &Value,
    nixpkgs_nar_hash: Option<&str>,
) -> Value {
    let mut metadata = build_result_metadata(config, job, Some(target), None);
    let Some(object) = metadata.as_object_mut() else {
        return metadata;
    };
    object.insert("target".to_string(), json!(spec.target));
    object.insert("system".to_string(), json!(spec.system));
    object.insert("input_revision".to_string(), json!(spec.input_revision));
    object.insert(
        "input_config_hash".to_string(),
        json!(spec.input_config_hash),
    );
    object.insert("blueprint_id".to_string(), json!(spec.blueprint_id));
    object.insert(
        "blueprint_revision_id".to_string(),
        json!(spec.blueprint_revision_id),
    );
    object.insert(
        "blueprint_revision_config_hash".to_string(),
        json!(spec.blueprint_revision_config_hash),
    );
    object.insert(
        "build_input_kind".to_string(),
        json!(spec.build_input.as_ref().map(|input| input.kind.as_str())),
    );
    if let Some(input) = spec.build_input.as_ref() {
        if let Some(revision) = input.manage_source_revision.as_deref() {
            object.insert("manage_source_revision".to_string(), json!(revision));
        }
        if let Some(identity) = input.installer_target.as_ref() {
            object.insert("installer_target".to_string(), identity.clone());
        }
    }
    object.insert("cache".to_string(), json!("exported"));
    if let Some(commit) = spec.nixpkgs_commit.as_deref() {
        object.insert("nixpkgs_revision".to_string(), json!(commit));
        // The fetched source: narHash-pinned at a detected commit.
        object.insert(
            "nixpkgs_flake".to_string(),
            json!(
                nixpkgs_flake_ref(commit, nixpkgs_nar_hash)
                    .unwrap_or_else(|_| format!("github:NixOS/nixpkgs/{commit}"))
            ),
        );
    }
    object.insert(
        "source_lock_sha256".to_string(),
        json!(spec.source_lock_sha256),
    );
    object.insert("software_inventory".to_string(), software_inventory.clone());
    if let Some(source) = spec.closure_source.as_ref() {
        object.insert(
            "closure_source".to_string(),
            json!({
                "kind": CLOSURE_SOURCE_KIND_NEST_CACHE,
                "server_device_id": source.server_device_id,
                "cache_base_url": source.cache_base_url,
            }),
        );
    }
    metadata
}

fn software_inventory_eval_args(installable: &str) -> Vec<String> {
    let mut args = Vec::new();
    // Inventory is metadata, but `nix eval` can still realize an
    // import-from-derivation before returning that metadata. Keep it inside
    // the same isolation boundary as the real build.
    append_build_isolation_nix_options(&mut args);
    args.extend([
        "eval".to_string(),
        "--raw".to_string(),
        "--no-write-lock-file".to_string(),
        installable.to_string(),
    ]);
    args
}

async fn evaluate_software_inventory(
    config: &AppConfig,
    spec: &ValidatedBuildSpec,
    nixpkgs_nar_hash: Option<&str>,
) -> Value {
    evaluate_software_inventory_pinned(
        config,
        spec,
        nixpkgs_nar_hash,
        SoftwareInventoryLimits::default(),
    )
    .await
}

#[cfg(test)]
async fn evaluate_software_inventory_with_limits(
    config: &AppConfig,
    spec: &ValidatedBuildSpec,
    limits: SoftwareInventoryLimits,
) -> Value {
    evaluate_software_inventory_pinned(config, spec, None, limits).await
}

/// Probe package versions at the job's commit, from the narHash-pinned
/// source at a detected commit.
async fn evaluate_software_inventory_pinned(
    config: &AppConfig,
    spec: &ValidatedBuildSpec,
    nixpkgs_nar_hash: Option<&str>,
    limits: SoftwareInventoryLimits,
) -> Value {
    let Some(commit) = spec.nixpkgs_commit.as_deref() else {
        return json!([]);
    };
    let Ok(nixpkgs) = nixpkgs_flake_ref(commit, nixpkgs_nar_hash) else {
        return json!([]);
    };
    let mut refs = vec![(
        "linux-kernel".to_string(),
        "linuxPackages.kernel".to_string(),
    )];
    for package_ref in &spec.software_package_refs {
        if !refs.iter().any(|(_, existing)| existing == package_ref) {
            refs.push((package_ref.clone(), package_ref.clone()));
        }
    }
    let started = Instant::now();
    let mut inventory = Vec::new();
    for (name, package_ref) in refs {
        let remaining = limits.total_timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let installable = format!(
            "{nixpkgs}#legacyPackages.{}.{}.version",
            spec.system, package_ref
        );
        let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
        command.args(software_inventory_eval_args(&installable));
        let output = run_bounded_command(
            command,
            limits.probe_timeout.min(remaining),
            limits.stdout_max_bytes,
            limits.stderr_max_bytes,
            "nix software inventory eval",
        )
        .await;
        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let version = String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if version.is_empty() || version.len() > 160 {
            continue;
        }
        inventory.push(json!({
            "name": name,
            "package_ref": package_ref,
            "version": version,
        }));
    }
    Value::Array(inventory)
}

fn merge_build_metadata(destination: &mut Value, source: &Value) {
    let Some(source) = source.as_object() else {
        return;
    };
    let Some(destination) = destination.as_object_mut() else {
        return;
    };
    for (key, value) in source {
        // Cache export metadata includes cryptographically verified fields
        // such as the closure manifest and its digest. Managed/request
        // metadata may add context, but must never replace an export result.
        destination
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
}

#[cfg(test)]
fn nix_build_command(
    config: &AppConfig,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    job_id: i64,
) -> Result<NixBuildCommand> {
    nix_build_command_with_nixpkgs_nar_hash(config, target, spec, job_id, None)
}

/// `nixpkgs_nar_hash` pins a detected commit's source to the `narHash`
/// recorded when Nest first fetched it; Nix refuses any other content.
fn nix_build_command_with_nixpkgs_nar_hash(
    config: &AppConfig,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    job_id: i64,
    nixpkgs_nar_hash: Option<&str>,
) -> Result<NixBuildCommand> {
    if let Some(build_input) = spec.build_input.as_ref() {
        return blueprint_nix_build_command_with_nixpkgs_nar_hash(
            config,
            target,
            spec,
            build_input,
            job_id,
            nixpkgs_nar_hash,
        );
    }
    let job_dir = config.build.output_dir.join(format!("job-{job_id}"));
    let out_link = job_dir.join("result");
    let installable = format!("{}#{}", target.flake, target.attr);
    let mut args = vec!["build".to_string()];
    append_build_isolation_nix_options(&mut args);
    args.extend([
        installable,
        "--cores".to_string(),
        config.build.max_build_cores.to_string(),
        "--max-jobs".to_string(),
        if config.build.max_nix_jobs == 0 {
            "auto".to_string()
        } else {
            config.build.max_nix_jobs.to_string()
        },
        "--system".to_string(),
        spec.system.clone(),
        "--out-link".to_string(),
        out_link.display().to_string(),
        "--print-build-logs".to_string(),
        "--log-format".to_string(),
        "internal-json".to_string(),
        "--no-write-lock-file".to_string(),
    ]);
    Ok(NixBuildCommand {
        program: config.build.nix_binary.clone(),
        args,
        env: Vec::new(),
        out_link,
    })
}

#[cfg(test)]
fn blueprint_nix_build_command(
    config: &AppConfig,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    build_input: &ValidatedBlueprintBuildInput,
    job_id: i64,
) -> Result<NixBuildCommand> {
    blueprint_nix_build_command_with_nixpkgs_nar_hash(
        config,
        target,
        spec,
        build_input,
        job_id,
        None,
    )
}

fn blueprint_nix_build_command_with_nixpkgs_nar_hash(
    config: &AppConfig,
    target: &BuildTargetConfig,
    spec: &ValidatedBuildSpec,
    build_input: &ValidatedBlueprintBuildInput,
    job_id: i64,
    nixpkgs_nar_hash: Option<&str>,
) -> Result<NixBuildCommand> {
    // ValidatedBuildSpec is private, but keep the write boundary independently
    // guarded so future internal call sites cannot materialize protected data.
    if build_input.kind != INSTALLER_TARGET_BUILD_INPUT_KIND {
        protected_material::validate_generated_nix(&build_input.generated_nix)?;
    }
    if let Some(desktop_module_nix) = build_input.desktop_module_nix.as_deref() {
        protected_material::validate_desktop_module_nix(desktop_module_nix)?;
    }
    if let Some(expected_state) = build_input.expected_state.as_ref() {
        if build_input.kind == INSTALLER_TARGET_BUILD_INPUT_KIND {
            protected_material::validate_installer_target_expected_state(expected_state)?;
            protected_material::validate_installer_target_generated_nix(
                &build_input.generated_nix,
                expected_state,
            )?;
        } else {
            protected_material::validate_expected_state(expected_state)?;
        }
    }
    if build_input.kind == INSTALLER_TARGET_BUILD_INPUT_KIND {
        protected_material::validate_installer_target_non_blueprint_module(
            "build_spec.build_input.hardware_module_nix",
            build_input
                .hardware_module_nix
                .as_deref()
                .expect("validated installer target hardware module"),
        )?;
        protected_material::validate_installer_target_non_blueprint_module(
            "build_spec.build_input.target_module_nix",
            build_input
                .target_module_nix
                .as_deref()
                .expect("validated installer target target module"),
        )?;
    }
    let manage_source_url = if build_input.kind == INSTALLER_TARGET_BUILD_INPUT_KIND {
        let revision = build_input
            .manage_source_revision
            .as_deref()
            .expect("validated installer target Tiaris revision");
        Some(
            manage_source::verify_revision(
                &config.build.manage_source_url_template,
                revision,
                config.workstation_netboot.allow_private_release_urls,
            )
            .context("verify packaged Tiaris source for installer target")?
            .url,
        )
    } else {
        None
    };

    fs::create_dir_all(&config.build.work_dir).with_context(|| {
        format!(
            "create build work directory {}",
            config.build.work_dir.display()
        )
    })?;
    set_private_job_input_dir_permissions(&config.build.work_dir)?;
    let input_dir = config.build.work_dir.join(format!("job-{job_id}-input"));
    fs::create_dir(&input_dir)
        .with_context(|| format!("create build input directory {}", input_dir.display()))?;
    set_private_job_input_dir_permissions(&input_dir)?;
    write_job_input_file(input_dir.join("blueprint.nix"), &build_input.generated_nix)?;
    if build_input.kind != INSTALLER_TARGET_BUILD_INPUT_KIND {
        if let Some(desktop_module_nix) = build_input.desktop_module_nix.as_deref() {
            write_job_input_file(input_dir.join("tiaris-blueprints.nix"), desktop_module_nix)?;
        }
    }
    if let Some(expected_state) = build_input.expected_state.as_ref() {
        let expected_state = serde_json::to_string_pretty(expected_state)
            .context("serialize Blueprint expected state")?;
        write_job_input_file(input_dir.join("expected-state.json"), &expected_state)?;
    }
    if let Some(hardware_module_nix) = build_input.hardware_module_nix.as_deref() {
        write_job_input_file(input_dir.join("hardware.nix"), hardware_module_nix)?;
    }
    if let Some(target_module_nix) = build_input.target_module_nix.as_deref() {
        write_job_input_file(input_dir.join("target.nix"), target_module_nix)?;
    }
    let compatibility_module = if build_input.kind == INSTALLER_TARGET_BUILD_INPUT_KIND {
        installer_target_compat_module()
    } else {
        blueprint_compat_module(build_input.desktop_module_nix.is_some())
    };
    write_job_input_file(
        input_dir.join("tiaris-compat-options.nix"),
        compatibility_module,
    )?;
    write_job_input_file(
        input_dir.join("configuration.nix"),
        &nest_nixos_configuration(build_input),
    )?;
    write_job_input_file(
        input_dir.join("flake.nix"),
        &nest_nixos_flake(
            &nixpkgs_flake_ref(
                spec.nixpkgs_commit
                    .as_deref()
                    .expect("validated Blueprint source pin"),
                nixpkgs_nar_hash,
            )?,
            &spec.system,
            build_input,
            manage_source_url.as_deref(),
        ),
    )?;

    let job_dir = config.build.output_dir.join(format!("job-{job_id}"));
    let out_link = job_dir.join("result");
    let installable = format!("{}#{}", input_dir.display(), target.attr);
    let mut args = vec!["build".to_string()];
    append_build_isolation_nix_options(&mut args);
    args.extend([
        installable,
        "--cores".to_string(),
        config.build.max_build_cores.to_string(),
        "--max-jobs".to_string(),
        if config.build.max_nix_jobs == 0 {
            "auto".to_string()
        } else {
            config.build.max_nix_jobs.to_string()
        },
        "--out-link".to_string(),
        out_link.display().to_string(),
        "--print-build-logs".to_string(),
        "--log-format".to_string(),
        "internal-json".to_string(),
        "--no-write-lock-file".to_string(),
    ]);
    let mut env = Vec::new();
    if let Some(asset) = build_input.wallpaper_asset.as_ref() {
        let wallpaper_path = verify_cached_wallpaper_asset(config, asset)?;
        args.push("--impure".to_string());
        env.push((
            "TIARIS_BLUEPRINT_WALLPAPER_PATH".to_string(),
            wallpaper_path.display().to_string(),
        ));
    }
    Ok(NixBuildCommand {
        program: config.build.nix_binary.clone(),
        args,
        env,
        out_link,
    })
}

/// `github:NixOS/nixpkgs/<commit>`, with the recorded `narHash` when one is
/// known so a later fetch of the same commit must have the same content.
pub(crate) fn nixpkgs_flake_ref(commit: &str, nar_hash: Option<&str>) -> Result<String> {
    let commit = normalize_nixpkgs_commit(commit)?;
    let Some(nar_hash) = nar_hash else {
        return Ok(format!("github:NixOS/nixpkgs/{commit}"));
    };
    if !valid_nar_hash(nar_hash) {
        bail!("nixpkgs narHash must be an SRI sha256 hash");
    }
    Ok(format!(
        "github:NixOS/nixpkgs/{commit}?narHash={}",
        urlencoding::encode(nar_hash)
    ))
}

pub(crate) fn valid_nar_hash(value: &str) -> bool {
    value.strip_prefix("sha256-").is_some_and(|encoded| {
        encoded.len() == 44
            && encoded.ends_with('=')
            && encoded[..43]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
            && base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
                .is_ok_and(|digest| digest.len() == 32)
    })
}

fn write_job_input_file(path: PathBuf, contents: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("create build input {}", path.display()))?;
    set_private_job_input_file_permissions(&path)?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write build input {}", path.display()))
}

#[cfg(unix)]
fn set_private_job_input_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restrict build input directory {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_job_input_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_job_input_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict build input file {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_job_input_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn nest_nixos_flake(
    nixpkgs_flake: &str,
    system: &str,
    build_input: &ValidatedBlueprintBuildInput,
    manage_source_url: Option<&str>,
) -> String {
    let name = build_input.blueprint_name.as_deref().unwrap_or("Blueprint");
    let revision = build_input
        .blueprint_revision
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let description = serde_json::to_string(&format!(
        "Tiaris Nest Blueprint build: {name} rev {revision}"
    ))
    .unwrap_or_else(|_| "\"Tiaris Nest Blueprint build\"".to_string());
    let nixpkgs_flake =
        serde_json::to_string(nixpkgs_flake).unwrap_or_else(|_| "\"nixpkgs\"".to_string());
    if build_input.kind == INSTALLER_TARGET_BUILD_INPUT_KIND {
        let manage_flake = serde_json::to_string(
            manage_source_url.expect("verified installer target Tiaris source"),
        )
        .unwrap_or_else(|_| "\"manage\"".to_string());
        return format!(
            r#"{{
  description = {description};

  inputs.nixpkgs.url = {nixpkgs_flake};
  inputs.manage = {{
    url = {manage_flake};
    flake = false;
  }};

  outputs = {{ self, nixpkgs, manage }}:
    let
      system = "{system}";
      pkgs = import nixpkgs {{ inherit system; }};
      # Keep the shared protocol files and source layout required by this
      # signed runtime's agent, using the same recipe as its netboot bundle.
      tiarisAgent = import (manage + "/deploy/nixos/tiaris-agent-package.nix") {{
        inherit pkgs;
        repoRoot = manage;
      }};
    in {{
      packages.${{system}}.desktop-experience =
        (nixpkgs.lib.nixosSystem {{
          inherit system;
          specialArgs = {{
            manageSource = manage;
            inherit tiarisAgent;
          }};
          modules = [ ./configuration.nix ];
        }}).config.system.build.toplevel;
    }};
}}
"#
        );
    }
    format!(
        r#"{{
  description = {description};

  inputs.nixpkgs.url = {nixpkgs_flake};

  outputs = {{ self, nixpkgs }}:
    let
      system = "{system}";
    in {{
      packages.${{system}}.desktop-experience =
        (nixpkgs.lib.nixosSystem {{
          inherit system;
          modules = [
            ./configuration.nix
          ];
        }}).config.system.build.toplevel;
    }};
}}
"#
    )
}

/// The Nest configuration and option shim of a Blueprint job with a desktop
/// module (`./tiaris-blueprints.nix` and `./blueprint.nix` are the caller's),
/// and the same configuration as a function of a reference's desktop module
/// and generated Blueprint (`reference-configuration.nix`), for the
/// detected-commit check's dry runs.
pub(crate) fn blueprint_job_template_files() -> Result<[(&'static str, String); 3]> {
    let input = ValidatedBlueprintBuildInput {
        kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
        generated_nix: String::new(),
        desktop_module_nix: Some(String::new()),
        expected_state: None,
        blueprint_name: None,
        blueprint_revision: None,
        hardware_module_nix: None,
        target_module_nix: None,
        manage_source_revision: None,
        installer_target: None,
        wallpaper_asset: None,
    };
    let configuration = nest_nixos_configuration(&input);
    let imports = "    ./tiaris-blueprints.nix\n    ./blueprint.nix\n";
    if configuration.matches(imports).count() != 1 {
        bail!("the Blueprint job configuration no longer imports its desktop module and Blueprint");
    }
    let reference = format!(
        "{{ desktop, blueprint }}:\n\n{}",
        configuration.replace(imports, "    desktop\n    blueprint\n")
    );
    Ok([
        ("configuration.nix", configuration),
        ("reference-configuration.nix", reference),
        (
            "tiaris-compat-options.nix",
            blueprint_compat_module(true).to_string(),
        ),
    ])
}

fn nest_nixos_configuration(build_input: &ValidatedBlueprintBuildInput) -> String {
    let include_desktop_module = build_input.desktop_module_nix.is_some();
    if build_input.kind == INSTALLER_TARGET_BUILD_INPUT_KIND {
        return r#"{ manageSource, ... }:

{
  imports = [
    ./tiaris-compat-options.nix
    (manageSource + "/deploy/nixos/tiaris-blueprints.nix")
    (manageSource + "/deploy/nixos/tiaris-agent-module.nix")
    (manageSource + "/deploy/nixos/tiaris-workstation-runtime.nix")
    ./blueprint.nix
    ./hardware.nix
    ./target.nix
  ];
}
"#
        .to_string();
    }
    let desktop_module_import = if include_desktop_module {
        "    ./tiaris-blueprints.nix\n"
    } else {
        ""
    };
    r#"{ lib, modulesPath, ... }:

{
  imports = [
    ./tiaris-compat-options.nix
@DESKTOP_MODULE_IMPORT@
    ./blueprint.nix
  ];

  system.stateVersion = lib.mkDefault lib.trivial.release;
  networking.hostName = lib.mkDefault "tiaris-nest-build";
  networking.useDHCP = lib.mkDefault true;

  fileSystems."/" = {
    device = "none";
    fsType = "tmpfs";
  };

  boot.loader.grub.enable = lib.mkDefault false;
  boot.loader.systemd-boot.enable = lib.mkDefault false;
  boot.initrd.enable = lib.mkForce false;
  boot.initrd.systemd.enable = lib.mkDefault false;
  boot.initrd.includeDefaultModules = false;
  boot.initrd.availableKernelModules = lib.mkForce [];
  boot.initrd.kernelModules = lib.mkForce [];
  boot.kernelModules = lib.mkForce [];
  boot.extraModulePackages = lib.mkForce [];
  security.lockKernelModules = lib.mkForce false;
  systemd.services.systemd-udevd.restartTriggers = lib.mkForce [];
}
"#
    .replace("@DESKTOP_MODULE_IMPORT@\n", desktop_module_import)
}

fn blueprint_compat_module(include_desktop_module: bool) -> &'static str {
    if !include_desktop_module {
        return r#"{ lib, ... }:

{
  options.tiaris = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    default = {};
    description = "Tiaris Blueprint metadata accepted while Nest prebuilds a generic NixOS closure.";
  };

  options.services.tiaris-agent = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    default = {};
    description = "Tiaris Agent policy accepted while Nest prebuilds a generic NixOS closure.";
  };
}
"#;
    }
    // The reviewed desktop module owns the Tiaris option declarations. Keep
    // this shim limited to the legacy catalog alias and the generic Agent
    // policy sink; redeclaring an option in two imported NixOS modules makes
    // the entire evaluation fail before cache/source policy can be checked.
    r#"{ lib, ... }:

{
  imports = [
    (lib.mkAliasOptionModule
      [ "tiaris" "catalog" "applications" ]
      [ "tiaris" "blueprint" "applications" ])
  ];

  options.services.tiaris-agent = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    default = {};
    description = "Tiaris Agent policy accepted while Nest prebuilds a generic NixOS closure.";
  };
}
"#
}

fn installer_target_compat_module() -> &'static str {
    // Installer targets always import the reviewed desktop module and the
    // real tiaris-agent module, so both option trees already have one owner.
    r#"{ lib, ... }:

{
  imports = [
    (lib.mkAliasOptionModule
      [ "tiaris" "catalog" "applications" ]
      [ "tiaris" "blueprint" "applications" ])
  ];
}
"#
}

async fn run_nix_build(
    pool: &sqlx::SqlitePool,
    job: &BuildJob,
    command: &NixBuildCommand,
    log: &SharedLog,
    config: &AppConfig,
) -> Result<ProcessOutcome> {
    if let Some(parent) = command.out_link.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create build output directory {}", parent.display()))?;
    }
    tokio::fs::create_dir_all(&config.build.work_dir)
        .await
        .with_context(|| {
            format!(
                "create build work directory {}",
                config.build.work_dir.display()
            )
        })?;
    let mut child = crate::nix_command::tokio_command(&command.program)
        .args(&command.args)
        .envs(command.env.iter().map(|(key, value)| (key, value)))
        .current_dir(&config.build.work_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0)
        .spawn()
        .with_context(|| format!("spawn {}", command.program))?;
    let process_group = ProcessGroup::new(child.id());
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("nix build stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("nix build stderr was not captured"))?;
    let stdout_log = log.clone();
    let stderr_log = log.clone();
    let progress = Arc::new(Mutex::new(InternalJsonParser::new()));
    let stderr_progress = progress.clone();
    let mut stdout_task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        read_log_stream(stdout, stdout_log).await
    }));
    let mut stderr_task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        read_internal_json_log_stream(stderr, stderr_log, stderr_progress).await
    }));
    let started = Instant::now();
    let mut last_log_update = Instant::now();
    let mut last_progress_sent: Option<(i32, String)> = None;
    let outcome = loop {
        match db::build_job_cancel_requested(pool, job.id).await {
            Ok(true) => {
                process_group.signal(libc::SIGTERM);
                let _ = timeout(
                    Duration::from_secs(config.build.cancel_grace_seconds),
                    child.wait(),
                )
                .await;
                process_group.signal(libc::SIGKILL);
                let _ = timeout(PIPE_DRAIN_TIMEOUT, child.wait()).await;
                break ProcessOutcome::Cancelled;
            }
            Ok(false) => {}
            Err(err) => {
                warn!(
                    error = %safe_error(&err.into()),
                    job_id = job.id,
                    "could not check Nest build cancellation; build supervision will retry"
                );
            }
        }
        if started.elapsed() >= Duration::from_secs(config.build.timeout_seconds) {
            process_group.signal(libc::SIGTERM);
            let _ = timeout(
                Duration::from_secs(config.build.cancel_grace_seconds),
                child.wait(),
            )
            .await;
            process_group.signal(libc::SIGKILL);
            let _ = timeout(PIPE_DRAIN_TIMEOUT, child.wait()).await;
            break ProcessOutcome::TimedOut;
        }
        if let Some(status) = child.try_wait().context("poll nix build child")? {
            let code = status.code().unwrap_or(-1);
            break if status.success() {
                ProcessOutcome::Succeeded(code)
            } else {
                ProcessOutcome::Failed(code)
            };
        }
        if last_log_update.elapsed() >= Duration::from_secs(5) {
            if let Err(err) = db::update_build_job_logs(pool, job.id, &log.snapshot().await).await {
                warn!(
                    error = %safe_error(&err.into()),
                    job_id = job.id,
                    "could not persist Nest build logs; build supervision will retry"
                );
            }
            let update = progress
                .lock()
                .await
                .snapshot()
                .progress_update(BUILDING_PROGRESS_START, BUILDING_PROGRESS_END);
            if let Some((mut percent, message)) = update {
                // Keep the reported percentage monotonic even if nix raises
                // its expected-derivation count mid-build.
                if let Some((last_percent, _)) = last_progress_sent.as_ref() {
                    percent = percent.max(*last_percent);
                }
                if last_progress_sent.as_ref() != Some(&(percent, message.clone())) {
                    match db::update_build_job_progress(
                        pool,
                        job.id,
                        Some(percent),
                        "building",
                        &message,
                    )
                    .await
                    {
                        Ok(()) => last_progress_sent = Some((percent, message)),
                        Err(err) => warn!(
                            error = %safe_error(&err.into()),
                            job_id = job.id,
                            "could not persist Nest build progress; build supervision will retry"
                        ),
                    }
                }
            }
            last_log_update = Instant::now();
        }
        sleep(Duration::from_millis(500)).await;
    };
    // A helper may retain the pipes after its parent exits. Drain finite output,
    // then kill our group and abort readers on every return/cancellation path.
    let drained = timeout(PIPE_DRAIN_TIMEOUT, async {
        let (out, err) = tokio::join!(&mut stdout_task, &mut stderr_task);
        out.context("join build stdout reader")??;
        err.context("join build stderr reader")??;
        Ok::<_, anyhow::Error>(())
    })
    .await;
    process_group.signal(libc::SIGKILL);
    match drained {
        Ok(result) => result?,
        Err(_) => bail!("nix build output pipes remained open after child exit"),
    }
    db::update_build_job_logs(pool, job.id, &log.snapshot().await).await?;
    Ok(outcome)
}

async fn inspect_build_output(
    config: &AppConfig,
    command: &NixBuildCommand,
) -> Result<NixOutputInfo> {
    let output_path = tokio::fs::read_link(&command.out_link)
        .await
        .with_context(|| format!("read build out-link {}", command.out_link.display()))?;
    let output_path = output_path
        .to_str()
        .ok_or_else(|| anyhow!("build output path is not UTF-8"))?
        .to_string();
    if !output_path.starts_with("/nix/store/") {
        bail!("build output path was not in /nix/store");
    }
    let output_sha256 = run_nix_hash(config, &output_path).await?;
    let (output_size_bytes, closure_size_bytes, evaluated_derivation) =
        run_nix_path_info(config, &output_path).await?;
    Ok(NixOutputInfo {
        output_path,
        output_sha256,
        output_size_bytes,
        closure_size_bytes,
        evaluated_derivation,
    })
}

async fn run_nix_hash(config: &AppConfig, path: &str) -> Result<String> {
    let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
    command
        .arg("hash")
        .arg("path")
        .arg("--type")
        .arg("sha256")
        .arg("--base16")
        .arg(path);
    let output = run_bounded_command(
        command,
        Duration::from_secs(config.build.timeout_seconds),
        4096,
        65536,
        "nix hash path",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix hash path failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("nix hash path did not return a SHA-256 hex digest");
    }
    Ok(hash.to_ascii_lowercase())
}

async fn run_nix_path_info(config: &AppConfig, path: &str) -> Result<(i64, i64, Option<String>)> {
    let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
    command
        .arg("path-info")
        .arg("--json")
        .arg("--closure-size")
        .arg("--size")
        .arg(path);
    let output = run_bounded_command(
        command,
        Duration::from_secs(config.build.timeout_seconds),
        1048576,
        65536,
        "nix path-info",
    )
    .await?;
    if !output.status.success() {
        bail!(
            "nix path-info failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: Value =
        serde_json::from_slice(&output.stdout).context("parse nix path-info JSON")?;
    let first = nix_path_info_row(&value, path)?;
    let (output_size_bytes, closure_size_bytes) = nix_path_info_sizes(first);
    let evaluated_derivation = nix_path_info_deriver(first);
    Ok((output_size_bytes, closure_size_bytes, evaluated_derivation))
}

fn nix_path_info_row<'a>(value: &'a Value, path: &str) -> Result<&'a Value> {
    if let Some(array) = value.as_array() {
        if array.len() != 1 {
            bail!("nix path-info returned an unexpected number of rows");
        }
        let first = &array[0];
        if let Some(returned_path) = first.get("path").and_then(Value::as_str) {
            if returned_path != path {
                bail!("nix path-info returned a row for an unexpected store path");
            }
        }
        return Ok(first);
    }
    if let Some(object) = value.as_object() {
        if let Some(row) = object.get(path) {
            return Ok(row);
        }
        bail!("nix path-info omitted the requested store path");
    }
    Err(anyhow!("nix path-info returned no rows"))
}

fn nix_path_info_sizes(first: &Value) -> (i64, i64) {
    let closure_size = first
        .get("closureSize")
        .or_else(|| first.get("closure_size"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let nar_size = first
        .get("narSize")
        .or_else(|| first.get("size"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    (closure_size.max(nar_size).max(0), closure_size.max(0))
}

fn nix_path_info_deriver(first: &Value) -> Option<String> {
    first
        .get("deriver")
        .and_then(Value::as_str)
        .and_then(normalize_derivation_store_path)
}

async fn read_internal_json_log_stream<R>(
    reader: R,
    log: SharedLog,
    progress: Arc<Mutex<InternalJsonParser>>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut lines = crate::bounded_io::Lines::new(reader, MAX_PENDING_LOG_LINE_BYTES);
    while let Some(frame) = lines.next().await? {
        match frame {
            crate::bounded_io::Frame::Line(line) => {
                let rendered = progress.lock().await.feed_line(&line);
                if let Some(text) = rendered {
                    log.append(&format!("{text}\n")).await;
                }
            }
            crate::bounded_io::Frame::Oversized | crate::bounded_io::Frame::InvalidEncoding => {
                log.append("[... oversized or invalid build log frame redacted ...]\n")
                    .await;
            }
        }
    }
    Ok(())
}

async fn read_log_stream<R>(reader: R, log: SharedLog) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut lines = crate::bounded_io::Lines::new(reader, MAX_PENDING_LOG_LINE_BYTES);
    while let Some(frame) = lines.next().await? {
        match frame {
            crate::bounded_io::Frame::Line(line) => log.append(&format!("{line}\n")).await,
            crate::bounded_io::Frame::Oversized | crate::bounded_io::Frame::InvalidEncoding => {
                log.append("[... oversized or invalid build log frame redacted ...]\n")
                    .await;
            }
        }
    }
    Ok(())
}

impl SharedLog {
    fn new(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedLogState::default())),
            max_bytes,
        }
    }

    async fn append(&self, text: &str) {
        let mut inner = self.inner.lock().await;
        inner.pending.push_str(text);
        if let Some(last_newline) = inner.pending.rfind('\n') {
            let complete = inner.pending[..=last_newline].to_string();
            inner.pending.drain(..=last_newline);
            let mut redact_following = inner.redact_following;
            let redacted = redact_log_text(&complete, &mut redact_following);
            inner.redact_following = redact_following;
            inner.text.push_str(&redacted);
            bound_captured_log(&mut inner.text, self.max_bytes);
        }
        if inner.pending.len() > MAX_PENDING_LOG_LINE_BYTES {
            inner
                .text
                .push_str("[... oversized unbroken build log line redacted ...]\n");
            inner.pending.clear();
            inner.redact_following = 0;
            bound_captured_log(&mut inner.text, self.max_bytes);
        }
    }

    async fn snapshot(&self) -> String {
        let inner = self.inner.lock().await;
        let mut snapshot = inner.text.clone();
        let mut redact_following = inner.redact_following;
        snapshot.push_str(&redact_log_text(&inner.pending, &mut redact_following));
        bound_captured_log(&mut snapshot, self.max_bytes);
        snapshot
    }
}

fn bound_captured_log(text: &mut String, max_bytes: usize) {
    if text.len() <= max_bytes {
        return;
    }
    let marker = "[... earlier build log truncated ...]\n";
    let keep = max_bytes.saturating_sub(marker.len());
    let start = utf8_tail_start(text, keep);
    let tail = text[start..].to_string();
    *text = format!("{marker}{tail}");
}

fn redact_log_text(text: &str, redact_following: &mut usize) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut first = true;
    for line in text.split('\n') {
        if !first {
            redacted.push('\n');
        }
        first = false;
        redacted.push_str(&redact_log_line(line, redact_following));
    }
    redacted
}

fn redact_log_line(line: &str, redact_following: &mut usize) -> String {
    let line = redact_sensitive_key_values(line);
    line.split_whitespace()
        .map(|token| {
            if *redact_following > 0 {
                *redact_following -= 1;
                return "[REDACTED]".to_string();
            }
            let lower = token.to_ascii_lowercase();
            if lower.contains("authorization:") || lower.contains("private-key") {
                *redact_following = 2;
                "[REDACTED]".to_string()
            } else if contains_sensitive_key_value(token) {
                redact_sensitive_key_values(token)
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn utf8_tail_start(value: &str, keep_bytes: usize) -> usize {
    if value.len() <= keep_bytes {
        return 0;
    }
    let mut start = value.len() - keep_bytes;
    while start < value.len() && !value.is_char_boundary(start) {
        start += 1;
    }
    start
}

fn normalize_artifact_type(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    match value.as_str() {
        "nixos_closure" | "netboot_artifact" | "desktop_image" | "system_generation" => Ok(value),
        _ => bail!("unsupported artifact_type"),
    }
}

fn normalize_target(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 64
        || value.starts_with(['-', '.', '_'])
        || value.ends_with(['-', '.', '_'])
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        bail!("invalid target");
    }
    Ok(value)
}

fn normalize_system(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("invalid system");
    }
    Ok(value.to_string())
}

fn normalize_revision(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        bail!("invalid input_revision");
    }
    Ok(value.to_string())
}

fn normalize_sha256(value: &str) -> Result<String> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("input_config_hash must be a SHA-256 hex digest");
    }
    Ok(value.to_ascii_lowercase())
}

fn normalize_nixpkgs_commit(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("nixpkgs_commit must be a lowercase 40-character commit");
    }
    Ok(value)
}

fn normalize_package_ref(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 192
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|part| part.is_empty())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+' | b'.'))
    {
        bail!("invalid software package reference");
    }
    Ok(value.to_string())
}

fn normalize_optional_uuidish(field: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{field} is invalid");
    }
    Ok(value.to_string())
}

fn bounded_metadata_text(value: &str, max_chars: usize) -> String {
    value
        .replace(['\n', '\r', '\t'], " ")
        .chars()
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

fn default_schema_version() -> u32 {
    1
}

fn safe_error(err: &anyhow::Error) -> String {
    redact_sensitive_key_values(&err.to_string())
        .chars()
        .take(1000)
        .collect()
}
#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{AppConfig, BuildTargetConfig};

    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn nix_daemon_probe_enables_required_features() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-nix-daemon-feature-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let fake_nix = root.join("nix");
        std::fs::write(
            &fake_nix,
            r#"#!/bin/sh
set -eu
case "${NIX_CONFIG:-}" in
  *"extra-experimental-features = nix-command flakes"*) ;;
  *) printf '%s\n' 'required Nix features are missing' >&2; exit 64 ;;
esac
[ "$#" -eq 4 ]
[ "$1" = store ]
[ "$2" = ping ]
[ "$3" = --store ]
[ "$4" = daemon ]
"#,
        )
        .unwrap();
        std::fs::set_permissions(&fake_nix, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut config = AppConfig::default();
        config.build.nix_binary = fake_nix.display().to_string();
        let result = ensure_nix_daemon_available(&config).await;
        std::fs::remove_dir_all(root).unwrap();
        result.unwrap();
    }

    fn valid_installer_target_identity() -> Value {
        json!({
            "schema": INSTALLER_TARGET_BUILD_SCHEMA,
            "preparation_id": "00000000-0000-4000-8000-000000000001",
            "device_id": "device_1",
            "device_incarnation_id": "00000000-0000-4000-8000-000000000002",
            "blueprint_id": "00000000-0000-4000-8000-000000000003",
            "blueprint_revision_id": "00000000-0000-4000-8000-000000000004",
            "hardware_facts_sha256": "11".repeat(32),
            "hardware_driver_policy": "auto",
            "disk_layout_sha256": "22".repeat(32),
            "nest_device_id": "nest_1",
            "bundle_sha256": "33".repeat(32),
            "profile_id": "00000000-0000-4000-8000-000000000005",
            "managed_device_id": null,
            "reinstall_request_id": null,
            "manage_source_revision": "4".repeat(40),
            "nixpkgs_revision": "5".repeat(40),
            "source_lock_sha256": "66".repeat(32),
            "effective_config_sha256": "77".repeat(32)
        })
    }

    fn valid_installer_target_build_job() -> BuildJob {
        let revision = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000004").unwrap();
        let profile_generation = "b".repeat(64);
        let secret_ref =
            protected_material::local_account_secret_ref(revision, &profile_generation, "student");
        let build_input = json!({
            "kind": INSTALLER_TARGET_BUILD_INPUT_KIND,
            "generated_nix": protected_material::installer_target_test_generated_nix(&[(
                "student",
                "Shared Student",
                false,
                &["audio", "networkmanager", "video"],
                &secret_ref,
            )]),
            "expected_state": {
                "schema": "tiaris.blueprint.expected-state.v2",
                "compiler_version": 2,
                "deployment": {
                    "blueprint_revision_id": revision,
                    "artifact_config_hash": "7".repeat(64),
                    "local_account_profile_generation_sha256": profile_generation,
                },
                "checks": [{
                    "id": "identity.local-account.inventory",
                    "kind": "local-account-inventory",
                    "expected": {
                        "accounts": [{
                            "username": "student",
                            "display_name": "Shared Student",
                            "admin": false,
                            "groups": ["audio", "networkmanager", "video"],
                        }],
                    },
                }, {
                    "id": "identity.local-account.student.password",
                    "kind": "local-account-password-hash",
                    "expected": {
                        "username": "student",
                        "password_secret_ref": secret_ref,
                    },
                }],
            },
            "blueprint_name": "Device-specific installer target",
            "blueprint_revision": 1,
            "hardware_module_nix": "{ ... }: {}",
            "target_module_nix": "{ ... }: { tiaris.agent.organizationSlug = \"users\"; }",
            "manage_source_revision": "4".repeat(40),
            "installer_target": valid_installer_target_identity(),
        });
        let input_config_hash = canonical_json_sha256(&build_input).unwrap();
        let build_spec = json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "installer_target",
            "system": "x86_64-linux",
            "input_revision": revision,
            "input_config_hash": input_config_hash,
            "blueprint_id": "00000000-0000-4000-8000-000000000003",
            "blueprint_revision_id": revision,
            "blueprint_revision_config_hash": "7".repeat(64),
            "nixpkgs_commit": "5".repeat(40),
            "source_lock_sha256": "66".repeat(32),
            "software_package_refs": [],
            "build_input": build_input,
            "allow_source_builds": true,
        });
        BuildJob {
            id: 1,
            managed_job_id: Some("00000000-0000-4000-8000-000000000009".to_string()),
            requested_artifact_type: "nixos_closure".to_string(),
            build_spec,
            target: "installer_target".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: revision.to_string(),
            input_config_hash,
            status: "queued".to_string(),
            progress_percent: None,
            progress_stage: None,
            progress_message: None,
            logs: String::new(),
            error: String::new(),
            rejection_code: String::new(),
            output_path: String::new(),
            output_sha256: String::new(),
            output_size_bytes: 0,
            exit_code: None,
            cache_metadata: json!({}),
            started_at: None,
            completed_at: None,
            cancel_requested_at: None,
            created_at: "2026-08-12T00:00:00Z".to_string(),
            updated_at: "2026-08-12T00:00:00Z".to_string(),
        }
    }

    fn refresh_installer_target_input_hash(job: &mut BuildJob) {
        let hash = canonical_json_sha256(&job.build_spec["build_input"]).unwrap();
        job.input_config_hash.clone_from(&hash);
        job.build_spec["input_config_hash"] = json!(hash);
    }

    #[test]
    fn installer_target_build_spec_binds_every_provenance_field_and_canonical_input() {
        let config = AppConfig::default();
        validate_build_spec(&config, &valid_installer_target_build_job()).unwrap();

        for pointer in [
            "/build_input/installer_target/blueprint_id",
            "/build_input/installer_target/nixpkgs_revision",
            "/build_input/installer_target/source_lock_sha256",
        ] {
            let mut changed = valid_installer_target_build_job();
            *changed.build_spec.pointer_mut(pointer).unwrap() = match pointer {
                "/build_input/installer_target/blueprint_id" => {
                    json!("00000000-0000-4000-8000-000000000008")
                }
                "/build_input/installer_target/nixpkgs_revision" => json!("8".repeat(40)),
                _ => json!("88".repeat(32)),
            };
            refresh_installer_target_input_hash(&mut changed);
            assert!(validate_build_spec(&config, &changed).is_err(), "{pointer}");
        }

        let mut wrong_input_revision = valid_installer_target_build_job();
        wrong_input_revision.input_revision = "00000000-0000-4000-8000-000000000008".to_string();
        wrong_input_revision.build_spec["input_revision"] =
            json!(wrong_input_revision.input_revision.clone());
        assert!(validate_build_spec(&config, &wrong_input_revision).is_err());

        let mut wrong_artifact_hash = valid_installer_target_build_job();
        wrong_artifact_hash.build_spec["blueprint_revision_config_hash"] = json!("8".repeat(64));
        assert!(validate_build_spec(&config, &wrong_artifact_hash).is_err());

        let mut wrong_build_input_hash = valid_installer_target_build_job();
        wrong_build_input_hash.build_spec["input_config_hash"] = json!("8".repeat(64));
        wrong_build_input_hash.input_config_hash = "8".repeat(64);
        assert!(validate_build_spec(&config, &wrong_build_input_hash).is_err());
    }

    fn legacy_identity_digests() -> InstallerTargetModuleDigests<'static> {
        InstallerTargetModuleDigests {
            generated_nix: "",
            expected_state: None,
            hardware_module_nix: "",
            target_module_nix: "",
        }
    }

    fn valid_cohort_identity(
        generated_nix: &str,
        expected_state: &Value,
        hardware_module_nix: &str,
        target_module_nix: &str,
    ) -> Value {
        json!({
            "schema": INSTALLER_TARGET_BUILD_SCHEMA_V3,
            "blueprint_id": "00000000-0000-4000-8000-000000000003",
            "blueprint_revision_id": "00000000-0000-4000-8000-000000000004",
            "blueprint_revision_config_hash": "7".repeat(64),
            "generated_nix_sha256": sha256_hex_text(generated_nix),
            "expected_state_sha256": canonical_json_sha256(expected_state).unwrap(),
            "hardware_driver_policy": "auto",
            "hardware_module_sha256": sha256_hex_text(hardware_module_nix),
            "target_module_sha256": sha256_hex_text(target_module_nix),
            "manage_source_revision": "4".repeat(40),
            "nixpkgs_revision": "5".repeat(40),
            "source_lock_sha256": "6".repeat(64),
        })
    }

    fn valid_closure_source() -> Value {
        json!({
            "kind": "nest_cache",
            "server_device_id": "dev_origin",
            "cache_base_url": "http://10.0.0.5/cache",
            "public_key": "tiaris-nest-cache:rRtA+N3tj2cIPfWQONIGcJBzdFSCPxJN2xRHg1hNhKU=",
            "toplevel_store_path": "/nix/store/w3xanx4s88yziz926n9aykfjkzckdyr8-nixos-system-tiaris-workstation-26.05",
            "closure_store_paths_sha256": "a".repeat(64),
            "closure_member_count": 2059,
            "evaluated_derivation": "/nix/store/w3xanx4s88yziz926n9aykfjkzckdyr8-nixos-system-tiaris-workstation-26.05.drv",
        })
    }

    #[test]
    fn replica_copy_source_is_validated_and_only_for_installer_targets() {
        let config = AppConfig::default();
        let mut job = valid_installer_target_build_job();
        let build_input = job.build_spec["build_input"].clone();
        let identity = valid_cohort_identity(
            build_input["generated_nix"].as_str().unwrap(),
            &build_input["expected_state"],
            build_input["hardware_module_nix"].as_str().unwrap(),
            build_input["target_module_nix"].as_str().unwrap(),
        );
        job.build_spec["build_input"]["installer_target"] = identity;
        refresh_installer_target_input_hash(&mut job);
        job.build_spec["closure_source"] = valid_closure_source();
        let spec = validate_build_spec(&config, &job).expect("replica copy spec is valid");
        let source = spec.closure_source.expect("closure source is retained");
        assert_eq!(source.server_device_id, "dev_origin");
        assert_eq!(source.closure_member_count, 2059);
        // The copy hint lives outside build_input: the cohort identity is untouched.
        assert_eq!(spec.input_config_hash, job.input_config_hash);

        for (field, value) in [
            ("kind", json!("rsync")),
            ("cache_base_url", json!("ftp://10.0.0.5/cache")),
            ("cache_base_url", json!("http://user:pw@10.0.0.5/cache")),
            ("cache_base_url", json!("http://10.0.0.5/cache?priority=10")),
            ("cache_base_url", json!("http://10.0.0.5/cache/")),
            ("public_key", json!("not-a-key")),
            ("toplevel_store_path", json!("/etc/passwd")),
            ("closure_store_paths_sha256", json!("zz")),
            ("closure_member_count", json!(0)),
            ("closure_member_count", json!(200_001)),
            ("server_device_id", json!("")),
            (
                "evaluated_derivation",
                json!("/nix/store/w3xanx4s88yziz926n9aykfjkzckdyr8-not-a-derivation"),
            ),
        ] {
            let mut changed = job.clone();
            changed.build_spec["closure_source"][field] = value;
            assert!(validate_build_spec(&config, &changed).is_err(), "{field}");
        }
        let mut extra = job.clone();
        extra.build_spec["closure_source"]["device_id"] = json!("x");
        assert!(validate_build_spec(&config, &extra).is_err());

        let source: ClosureSource = serde_json::from_value(valid_closure_source()).unwrap();
        assert!(
            validate_closure_source(&source, "blueprint")
                .unwrap_err()
                .to_string()
                .contains("only accepted for installer_target")
        );
    }

    #[test]
    fn installer_target_cohort_identity_binds_every_module_digest() {
        let config = AppConfig::default();
        let mut job = valid_installer_target_build_job();
        let build_input = job.build_spec["build_input"].clone();
        let identity = valid_cohort_identity(
            build_input["generated_nix"].as_str().unwrap(),
            &build_input["expected_state"],
            build_input["hardware_module_nix"].as_str().unwrap(),
            build_input["target_module_nix"].as_str().unwrap(),
        );
        job.build_spec["build_input"]["installer_target"] = identity.clone();
        refresh_installer_target_input_hash(&mut job);
        validate_build_spec(&config, &job).unwrap();

        for field in [
            "generated_nix_sha256",
            "expected_state_sha256",
            "hardware_module_sha256",
            "target_module_sha256",
            "blueprint_revision_config_hash",
        ] {
            let mut changed = job.clone();
            changed.build_spec["build_input"]["installer_target"][field] = json!("9".repeat(64));
            refresh_installer_target_input_hash(&mut changed);
            assert!(validate_build_spec(&config, &changed).is_err(), "{field}");
        }
        for forbidden in ["device_id", "preparation_id", "device_incarnation_id"] {
            let mut changed = job.clone();
            changed.build_spec["build_input"]["installer_target"][forbidden] = json!("x");
            refresh_installer_target_input_hash(&mut changed);
            assert!(
                validate_build_spec(&config, &changed).is_err(),
                "{forbidden}"
            );
        }
        let mut wrong_manage = job.clone();
        wrong_manage.build_spec["build_input"]["installer_target"]["manage_source_revision"] =
            json!("8".repeat(40));
        refresh_installer_target_input_hash(&mut wrong_manage);
        assert!(validate_build_spec(&config, &wrong_manage).is_err());
    }

    #[test]
    fn installer_target_identity_is_exact_and_bound_to_manage_source() {
        let valid = valid_installer_target_identity();
        validate_installer_target_identity(&valid, &"4".repeat(40), legacy_identity_digests())
            .unwrap();

        let mut legacy = valid.clone();
        legacy["schema"] = json!(INSTALLER_TARGET_BUILD_SCHEMA_V1);
        legacy
            .as_object_mut()
            .unwrap()
            .remove("effective_config_sha256");
        validate_installer_target_identity(&legacy, &"4".repeat(40), legacy_identity_digests())
            .unwrap();

        let mut transitional = valid.clone();
        transitional["schema"] = json!(INSTALLER_TARGET_BUILD_SCHEMA_V1);
        validate_installer_target_identity(
            &transitional,
            &"4".repeat(40),
            legacy_identity_digests(),
        )
        .unwrap();

        let mut incomplete_v2 = valid.clone();
        incomplete_v2
            .as_object_mut()
            .unwrap()
            .remove("effective_config_sha256");
        assert!(
            validate_installer_target_identity(
                &incomplete_v2,
                &"4".repeat(40),
                legacy_identity_digests()
            )
            .is_err()
        );

        let mut invalid_effective_config = valid.clone();
        invalid_effective_config["effective_config_sha256"] = json!("not-a-sha256");
        assert!(
            validate_installer_target_identity(
                &invalid_effective_config,
                &"4".repeat(40),
                legacy_identity_digests()
            )
            .is_err()
        );

        let mut non_string_effective_config = valid.clone();
        non_string_effective_config["effective_config_sha256"] = Value::Null;
        assert!(
            validate_installer_target_identity(
                &non_string_effective_config,
                &"4".repeat(40),
                legacy_identity_digests()
            )
            .is_err()
        );

        let mut wrong_manage = valid.clone();
        wrong_manage["manage_source_revision"] = json!("7".repeat(40));
        assert!(
            validate_installer_target_identity(
                &wrong_manage,
                &"4".repeat(40),
                legacy_identity_digests()
            )
            .unwrap_err()
            .to_string()
            .contains("Tiaris revision fields do not match")
        );

        let mut one_sided_reinstall = valid.clone();
        one_sided_reinstall["managed_device_id"] = json!("device_1");
        assert!(
            validate_installer_target_identity(
                &one_sided_reinstall,
                &"4".repeat(40),
                legacy_identity_digests()
            )
            .unwrap_err()
            .to_string()
            .contains("reinstall bindings")
        );

        let mut unknown = valid;
        unknown["unexpected"] = json!(true);
        assert!(
            validate_installer_target_identity(
                &unknown,
                &"4".repeat(40),
                legacy_identity_digests()
            )
            .unwrap_err()
            .to_string()
            .contains("does not match its schema")
        );

        let mut noncanonical_uuid = valid_installer_target_identity();
        noncanonical_uuid["preparation_id"] = json!("00000000000040008000000000000001");
        assert!(
            validate_installer_target_identity(
                &noncanonical_uuid,
                &"4".repeat(40),
                legacy_identity_digests()
            )
            .is_err()
        );
    }

    #[test]
    fn installer_target_build_accepts_retained_v1_jobs_but_requires_v2_execution_hash() {
        let config = AppConfig::default();

        let mut legacy = valid_installer_target_build_job();
        legacy.build_spec["build_input"]["installer_target"]["schema"] =
            json!(INSTALLER_TARGET_BUILD_SCHEMA_V1);
        legacy.build_spec["build_input"]["installer_target"]
            .as_object_mut()
            .unwrap()
            .remove("effective_config_sha256");
        refresh_installer_target_input_hash(&mut legacy);
        validate_build_spec(&config, &legacy).unwrap();

        let mut transitional = valid_installer_target_build_job();
        transitional.build_spec["build_input"]["installer_target"]["schema"] =
            json!(INSTALLER_TARGET_BUILD_SCHEMA_V1);
        refresh_installer_target_input_hash(&mut transitional);
        validate_build_spec(&config, &transitional).unwrap();

        let mut incomplete_v2 = valid_installer_target_build_job();
        incomplete_v2.build_spec["build_input"]["installer_target"]
            .as_object_mut()
            .unwrap()
            .remove("effective_config_sha256");
        refresh_installer_target_input_hash(&mut incomplete_v2);
        assert!(validate_build_spec(&config, &incomplete_v2).is_err());
    }

    fn flake_config_is_rejected(args: &[String]) -> bool {
        args.windows(REJECT_FLAKE_CONFIG_NIX_OPTION.len())
            .any(|window| {
                window
                    .iter()
                    .map(String::as_str)
                    .eq(REJECT_FLAKE_CONFIG_NIX_OPTION)
            })
    }

    fn build_sandbox_is_required(args: &[String]) -> bool {
        args.windows(REQUIRE_BUILD_SANDBOX_NIX_OPTION.len())
            .any(|window| {
                window
                    .iter()
                    .map(String::as_str)
                    .eq(REQUIRE_BUILD_SANDBOX_NIX_OPTION)
            })
    }

    fn software_inventory_test_spec(software_package_refs: Vec<String>) -> ValidatedBuildSpec {
        ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: Some("c".repeat(40)),
            source_lock_sha256: Some("d".repeat(64)),
            software_package_refs,
            build_input: None,
            closure_source: None,
        }
    }

    #[test]
    fn software_inventory_eval_keeps_the_build_isolation() {
        let installable =
            "github:NixOS/nixpkgs/reviewed#legacyPackages.x86_64-linux.firefox.version";
        let args = software_inventory_eval_args(installable);
        assert!(flake_config_is_rejected(&args));
        assert!(build_sandbox_is_required(&args));
        assert_eq!(args.last().map(String::as_str), Some(installable));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn software_inventory_uses_bounded_isolated_eval() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-software-inventory-policy-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let fake_nix = root.join("fake-nix");
        std::fs::write(
            &fake_nix,
            r#"#!/bin/sh
set -eu
case " $* " in
  *" --option accept-flake-config false "*) ;;
  *) exit 91 ;;
esac
printf '123.4\n'
"#,
        )
        .unwrap();
        std::fs::set_permissions(&fake_nix, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = AppConfig::default();
        config.build.nix_binary = fake_nix.display().to_string();
        let spec = software_inventory_test_spec(vec!["firefox".to_string()]);

        let inventory = evaluate_software_inventory_with_limits(
            &config,
            &spec,
            SoftwareInventoryLimits {
                probe_timeout: Duration::from_secs(1),
                total_timeout: Duration::from_secs(2),
                stdout_max_bytes: 1024,
                stderr_max_bytes: 1024,
            },
        )
        .await;

        let inventory = inventory.as_array().unwrap();
        assert_eq!(inventory.len(), 2);
        assert!(
            inventory
                .iter()
                .all(|item| item.get("version") == Some(&json!("123.4")))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn software_inventory_timeout_kills_the_probe_process_group() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-software-inventory-timeout-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let marker = root.join("orphan-survived");
        let fake_nix = root.join("fake-nix");
        std::fs::write(
            &fake_nix,
            format!(
                r#"#!/bin/sh
set -eu
case " $* " in
  *" --option accept-flake-config false "*) ;;
  *) exit 91 ;;
esac
case " $* " in
  *" --option allow-import-from-derivation false "*) ;;
  *) exit 92 ;;
esac
( sleep 0.25; printf survived > '{}' ) &
sleep 5
"#,
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_nix, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = AppConfig::default();
        config.build.nix_binary = fake_nix.display().to_string();
        let spec = software_inventory_test_spec(vec!["firefox".to_string()]);
        let started = Instant::now();

        let inventory = evaluate_software_inventory_with_limits(
            &config,
            &spec,
            SoftwareInventoryLimits {
                probe_timeout: Duration::from_millis(50),
                total_timeout: Duration::from_millis(80),
                stdout_max_bytes: 1024,
                stderr_max_bytes: 1024,
            },
        )
        .await;

        assert_eq!(inventory, json!([]));
        assert!(started.elapsed() < Duration::from_secs(1));
        sleep(Duration::from_millis(350)).await;
        assert!(
            !marker.exists(),
            "a timed-out inventory probe left a descendant process running"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn cleanup_and_sweep_remove_job_dirs() {
        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-build-cleanup-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = AppConfig::default();
        config.build.output_dir = root.join("out");
        config.build.work_dir = root.join("work");
        let finished_out = config.build.output_dir.join("job-7");
        let finished_input = config.build.work_dir.join("job-7-input");
        let stale_out = config.build.output_dir.join("job-3");
        let stale_input = config.build.work_dir.join("job-3-input");
        let unrelated_out = config.build.output_dir.join("job-notanumber");
        let unrelated_work = config.build.work_dir.join("keepme");
        for dir in [
            &finished_out,
            &finished_input,
            &stale_out,
            &stale_input,
            &unrelated_out,
            &unrelated_work,
        ] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("result"), b"x").unwrap();
        }

        cleanup_job_dirs(&config, 7).await;
        assert!(!finished_out.exists());
        assert!(!finished_input.exists());
        assert!(stale_out.exists());

        sweep_stale_job_dirs(&config).await;
        assert!(!stale_out.exists());
        assert!(!stale_input.exists());
        assert!(unrelated_out.exists());
        assert!(unrelated_work.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_spec_rejects_unknown_fields() {
        let value = json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "desktop_experience",
            "system": "x86_64-linux",
            "input_revision": "rev",
            "input_config_hash": "a".repeat(64),
            "raw_nix": "builtins.currentSystem"
        });
        let parsed = serde_json::from_value::<BuildSpec>(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn sysinfo_capacity_scales_kernel_units_without_overflow() {
        assert_eq!(
            capacity_from_sysinfo_values(32 * 1024 * 1024, 8 * 1024 * 1024, 1024),
            BuildCapacity {
                memory_bytes: 32 * 1024 * 1024 * 1024,
                swap_bytes: 8 * 1024 * 1024 * 1024,
            }
        );
        assert_eq!(
            capacity_from_sysinfo_values(u64::MAX, 1, 4096).memory_bytes,
            u64::MAX
        );
    }

    #[test]
    fn capacity_minimum_allows_only_small_kernel_accounting_rounding() {
        let eight_gib = 8 * 1024 * 1024 * 1024;
        assert!(capacity_meets_minimum(eight_gib, eight_gib));
        assert!(capacity_meets_minimum(eight_gib - 4096, eight_gib));
        assert!(!capacity_meets_minimum(
            eight_gib - CAPACITY_ACCOUNTING_TOLERANCE_BYTES - 1,
            eight_gib
        ));
    }

    #[test]
    fn build_spec_accepts_blueprint_build_input() {
        let value = json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "blueprint",
            "system": "x86_64-linux",
            "input_revision": "rev",
            "input_config_hash": "a".repeat(64),
            "build_input": {
                "kind": "blueprint_nixos_module",
                "generated_nix": "{ lib, ... }: { networking.hostName = lib.mkDefault \"test\"; }",
                "desktop_module_nix": "{ lib, ... }: { options.tiaris.desktop.profile = lib.mkOption { type = lib.types.str; default = \"auto\"; }; }",
                "expected_state": {
                    "schema": "tiaris.blueprint.expected-state.v2",
                    "compiler_version": 2,
                    "desktop": {"profile": "gnome"},
                    "checks": []
                },
                "blueprint_name": "Standard Workstation",
                "blueprint_revision": 8
            }
        });
        let parsed = serde_json::from_value::<BuildSpec>(value).unwrap();
        let validated = validate_blueprint_build_input(parsed.build_input.unwrap()).unwrap();
        assert!(validated.desktop_module_nix.is_some());
        assert!(validated.expected_state.is_some());
    }

    #[test]
    fn blueprint_wallpaper_descriptor_is_exact_bounded_jpeg_metadata() {
        let asset = BlueprintWallpaperAsset {
            schema: "tiaris.blueprint-wallpaper.v1".to_string(),
            id: "c1ba1e3e-5cb6-4ad3-bf92-47534e9e79e8".to_string(),
            blueprint_revision_id: "b1c5c356-9c4a-48d9-96a7-8a05c468c027".to_string(),
            name: "Office wall".to_string(),
            mime_type: "image/jpeg".to_string(),
            sha256: "a".repeat(64),
            size_bytes: 4096,
            width: 1920,
            height: 1080,
        };
        let validated = validate_blueprint_wallpaper_asset(asset.clone()).unwrap();
        assert_eq!(validated.mime_type, "image/jpeg");

        let mut png = asset.clone();
        png.mime_type = "image/png".to_string();
        assert!(validate_blueprint_wallpaper_asset(png).is_err());

        let mut oversized = asset.clone();
        oversized.size_bytes = 4 * 1024 * 1024 + 1;
        assert!(validate_blueprint_wallpaper_asset(oversized).is_err());

        let mut mismatched_dimensions = asset;
        mismatched_dimensions.width = 3841;
        assert!(validate_blueprint_wallpaper_asset(mismatched_dimensions).is_err());
    }

    #[test]
    fn installer_target_build_input_accepts_exact_local_account_reference_contract() {
        let revision = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000004").unwrap();
        let profile_generation = "b".repeat(64);
        let secret_ref =
            protected_material::local_account_secret_ref(revision, &profile_generation, "student");
        let validated = validate_blueprint_build_input(BlueprintBuildInput {
            kind: INSTALLER_TARGET_BUILD_INPUT_KIND.to_string(),
            generated_nix: protected_material::installer_target_test_generated_nix(&[(
                "student",
                "Shared Student",
                false,
                &["audio", "networkmanager", "video"],
                &secret_ref,
            )]),
            desktop_module_nix: None,
            expected_state: Some(json!({
                "schema": "tiaris.blueprint.expected-state.v2",
                "compiler_version": 2,
                "deployment": {
                    "blueprint_revision_id": revision,
                    "local_account_profile_generation_sha256": profile_generation,
                },
                "checks": [{
                    "id": "identity.local-account.inventory",
                    "kind": "local-account-inventory",
                    "expected": {
                        "accounts": [{
                            "username": "student",
                            "display_name": "Shared Student",
                            "admin": false,
                            "groups": ["audio", "networkmanager", "video"],
                        }],
                    },
                }, {
                    "id": "identity.local-account.student.password",
                    "kind": "local-account-password-hash",
                    "expected": {
                        "username": "student",
                        "password_secret_ref": secret_ref,
                    },
                }],
            })),
            blueprint_name: Some("Device-specific installer target".to_string()),
            blueprint_revision: Some(1),
            hardware_module_nix: Some("{ ... }: {}".to_string()),
            target_module_nix: Some("{ ... }: {}".to_string()),
            manage_source_revision: Some("4".repeat(40)),
            installer_target: Some(valid_installer_target_identity()),
            wallpaper_asset: None,
        })
        .unwrap();

        assert_eq!(validated.kind, INSTALLER_TARGET_BUILD_INPUT_KIND);
        assert!(validated.expected_state.is_some());
    }

    #[test]
    fn blueprint_build_input_requires_expected_state_with_real_desktop_module() {
        let input = BlueprintBuildInput {
            kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
            generated_nix: "{ ... }: {}".to_string(),
            desktop_module_nix: Some("{ ... }: {}".to_string()),
            expected_state: None,
            blueprint_name: None,
            blueprint_revision: None,
            hardware_module_nix: None,
            target_module_nix: None,
            manage_source_revision: None,
            installer_target: None,
            wallpaper_asset: None,
        };

        let err = validate_blueprint_build_input(input).unwrap_err();
        assert!(err.to_string().contains("expected_state must be an object"));
    }

    #[test]
    fn build_spec_accepts_legacy_desktop_experience_aliases() {
        let value = json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "desktop_experience",
            "system": "x86_64-linux",
            "input_revision": "rev",
            "input_config_hash": "a".repeat(64),
            "desktop_experience_id": "legacy-blueprint",
            "build_input": {
                "kind": "desktop_experience_nixos_module",
                "generated_nix": "{ lib, ... }: { networking.hostName = lib.mkDefault \"test\"; }",
                "desktop_experience_name": "Legacy Workstation",
                "desktop_experience_revision": 7
            }
        });
        let parsed = serde_json::from_value::<BuildSpec>(value).unwrap();
        assert_eq!(parsed.blueprint_id.as_deref(), Some("legacy-blueprint"));
        assert_eq!(
            parsed.build_input.unwrap().blueprint_name.as_deref(),
            Some("Legacy Workstation")
        );
        assert!(build_target_names_compatible(
            "desktop_experience",
            "blueprint"
        ));
    }

    #[test]
    fn nix_build_command_uses_allowlisted_attr() {
        let mut config = AppConfig::default();
        config.build.output_dir = PathBuf::from("/tmp/tiaris-nest-test-builds");
        config.build.nix_binary = "nix".to_string();
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "/srv/tiaris-nest/build-inputs/tiaris".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: None,
            source_lock_sha256: None,
            software_package_refs: Vec::new(),
            build_input: None,
            closure_source: None,
        };

        let command = nix_build_command(&config, &target, &spec, 42).unwrap();

        assert_eq!(command.program, "nix");
        assert_eq!(command.args[0], "build");
        assert!(
            command.args.contains(
                &"/srv/tiaris-nest/build-inputs/tiaris#packages.x86_64-linux.desktop-experience"
                    .to_string()
            )
        );
        assert!(command.args.contains(&"--out-link".to_string()));
        assert!(command.args.windows(2).any(|args| args == ["--cores", "4"]));
        assert!(flake_config_is_rejected(&command.args));
        assert!(build_sandbox_is_required(&command.args));
    }

    #[test]
    fn blueprint_build_target_requires_the_reviewed_configured_nixpkgs_pin() {
        let reviewed = "74cc63f702f7d60a557e152a57b40fb1fd0f72ac";
        let mut config = AppConfig::default();
        config.build.targets = vec![BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: format!("github:NixOS/nixpkgs/{reviewed}"),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        }];
        let mut spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: Some(reviewed.to_string()),
            source_lock_sha256: Some("b".repeat(64)),
            software_package_refs: Vec::new(),
            build_input: Some(ValidatedBlueprintBuildInput {
                kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
                generated_nix: "{ ... }: {}".to_string(),
                desktop_module_nix: None,
                expected_state: None,
                blueprint_name: None,
                blueprint_revision: None,
                hardware_module_nix: None,
                target_module_nix: None,
                manage_source_revision: None,
                installer_target: None,
                wallpaper_asset: None,
            }),
            closure_source: None,
        };
        assert!(build_target(&config, &spec).is_ok());

        spec.nixpkgs_commit = Some("293d6abedf0478e681a4dfcfcb35b30fc796a32f".to_string());
        let error = build_target(&config, &spec).unwrap_err().to_string();
        assert!(error.contains("does not match"));
    }

    #[test]
    fn nix_store_paths_reject_traversal_and_noncanonical_components() {
        let item = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package-1.0";
        for valid in [
            item.to_string(),
            format!("{item}/bin/tool"),
            format!("{item}/share/.hidden/file+name_1"),
        ] {
            assert!(safe_nix_store_path(&valid), "expected valid path: {valid}");
        }
        for invalid in [
            format!("{item}/./bin/tool"),
            format!("{item}/../other/bin/tool"),
            format!("{item}//bin/tool"),
            format!("{item}/bin/"),
            "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-package/bin/tool".to_string(),
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-/bin/tool".to_string(),
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package/bin/tool".to_string(),
            "nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package/bin/tool".to_string(),
            format!("{item}/bin/tool:other"),
        ] {
            assert!(
                !safe_nix_store_path(&invalid),
                "expected invalid path: {invalid}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bounded_command_retries_a_transient_busy_executable() {
        use rand::{RngCore, rngs::OsRng};
        use std::os::unix::fs::PermissionsExt;

        let mut nonce = [0_u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-bounded-spawn-test-{}-{}",
            std::process::id(),
            hex::encode(nonce)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("busy-command");
        std::fs::write(&executable, "#!/bin/sh\nprintf ready\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&executable)
            .unwrap();
        let release_writer = tokio::spawn(async move {
            sleep(Duration::from_millis(20)).await;
            drop(writer);
        });

        let output = run_bounded_command(
            Command::new(&executable),
            Duration::from_secs(1),
            1024,
            1024,
            "transient busy executable test",
        )
        .await
        .unwrap();
        release_writer.await.unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, b"ready");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resource_parsers_and_failure_classifier_are_specific() {
        assert_eq!(
            parse_cgroup_limit("8589934592\n").unwrap(),
            Some(8_589_934_592)
        );
        assert_eq!(parse_cgroup_limit("max\n").unwrap(), None);
        assert_eq!(
            parse_meminfo_bytes("MemTotal: 16384 kB\nSwapTotal: 8192 kB\n", "SwapTotal"),
            Some(8 * 1024 * 1024)
        );
        assert_eq!(
            parse_memory_event("oom 3\noom_kill 2\n", "oom_kill"),
            Some(2)
        );
        assert_eq!(
            failure::classify_nix_build_failure("compiler killed", true).kind,
            "out_of_memory"
        );
        assert_eq!(
            failure::classify_nix_build_failure(
                "error: builder for '/nix/store/example.drv' failed",
                false
            )
            .kind,
            "package_build_failed"
        );
        assert_eq!(
            failure::classify_nix_build_failure("No space left on device", false).kind,
            "insufficient_disk_space"
        );
        assert_eq!(
            failure::classify_nix_build_failure("cannot connect to socket at daemon-socket", false)
                .kind,
            "nix_daemon_unavailable"
        );
    }

    #[test]
    fn nix_build_command_writes_blueprint_flake_input() {
        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-build-input-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = AppConfig::default();
        config.build.work_dir = root.join("work");
        config.build.output_dir = root.join("out");
        config.build.nix_binary = "nix".to_string();
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "/srv/tiaris-nest/build-inputs/tiaris".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: Some("c".repeat(40)),
            source_lock_sha256: Some("d".repeat(64)),
            software_package_refs: vec!["firefox".to_string()],
            build_input: Some(ValidatedBlueprintBuildInput {
                kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
                generated_nix: "{ lib, ... }: { networking.hostName = lib.mkDefault \"test\"; }"
                    .to_string(),
                desktop_module_nix: Some(
                    "{ lib, ... }: { options.tiaris.desktop.profile = lib.mkOption { type = lib.types.str; default = \"auto\"; }; }"
                        .to_string(),
                ),
                expected_state: Some(json!({
                    "schema": "tiaris.blueprint.expected-state.v1",
                    "desktop": {"profile": "gnome"}
                })),
                blueprint_name: Some("Standard Workstation".to_string()),
                blueprint_revision: Some(8),
                hardware_module_nix: None,
                target_module_nix: None,
            manage_source_revision: None,
            installer_target: None,
            wallpaper_asset: None,
            }),
            closure_source: None,
        };

        let command = nix_build_command(&config, &target, &spec, 42).unwrap();

        assert_eq!(command.program, "nix");
        assert_eq!(command.args[0], "build");
        assert!(
            command
                .args
                .iter()
                .any(|arg| arg.ends_with("#packages.x86_64-linux.desktop-experience"))
        );
        assert!(flake_config_is_rejected(&command.args));
        assert!(build_sandbox_is_required(&command.args));
        assert!(root.join("work/job-42-input/flake.nix").is_file());
        assert!(root.join("work/job-42-input/blueprint.nix").is_file());
        assert!(
            root.join("work/job-42-input/tiaris-blueprints.nix")
                .is_file()
        );
        assert!(root.join("work/job-42-input/expected-state.json").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let input_dir = root.join("work/job-42-input");
            assert_eq!(
                std::fs::metadata(&input_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for entry in std::fs::read_dir(&input_dir).unwrap() {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                assert!(metadata.is_file());
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            }
        }
        let configuration =
            std::fs::read_to_string(root.join("work/job-42-input/configuration.nix")).unwrap();
        assert!(configuration.contains("./tiaris-blueprints.nix"));
        assert!(
            configuration
                .contains("systemd.services.systemd-udevd.restartTriggers = lib.mkForce [];")
        );
        assert!(configuration.contains("boot.initrd.enable = lib.mkForce false;"));
        assert!(configuration.contains("boot.initrd.includeDefaultModules = false;"));
        assert!(configuration.contains("boot.initrd.availableKernelModules = lib.mkForce [];"));
        assert!(configuration.contains("boot.kernelModules = lib.mkForce [];"));
        assert!(configuration.contains("security.lockKernelModules = lib.mkForce false;"));
        let compatibility =
            std::fs::read_to_string(root.join("work/job-42-input/tiaris-compat-options.nix"))
                .unwrap();
        assert!(compatibility.contains("lib.mkAliasOptionModule"));
        assert!(compatibility.contains("options.services.tiaris-agent"));
        assert!(!compatibility.contains("options.tiaris.desktop.environment"));
        assert!(!compatibility.contains("options.tiaris.blueprint.applications"));
        assert!(!compatibility.contains("options.tiaris.security.luks.enable"));
        let flake = std::fs::read_to_string(root.join("work/job-42-input/flake.nix")).unwrap();
        assert!(flake.contains(&format!(
            r#"inputs.nixpkgs.url = "github:NixOS/nixpkgs/{}";"#,
            "c".repeat(40)
        )));
        assert!(!flake.contains("/srv/tiaris-nest/build-inputs/tiaris"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn installer_target_compatibility_does_not_redeclare_owned_options() {
        let compatibility = installer_target_compat_module();

        assert!(compatibility.contains("lib.mkAliasOptionModule"));
        assert!(!compatibility.contains("options.services.tiaris-agent"));
        assert!(!compatibility.contains("options.tiaris.desktop.environment"));
        assert!(!compatibility.contains("options.tiaris.blueprint.applications"));
        assert!(!compatibility.contains("options.tiaris.security.luks.enable"));
    }

    #[cfg(unix)]
    #[test]
    fn installer_target_build_uses_only_verified_packaged_manage_source() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-installer-source-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let revision = "4".repeat(40);
        let source_dir = root.join("manage-source");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::set_permissions(&source_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let archive_body = b"deterministic installer Tiaris source";
        let archive_path = source_dir.join(format!("{revision}.tar"));
        std::fs::write(&archive_path, archive_body).unwrap();
        std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let metadata_path = source_dir.join(format!("{revision}.json"));
        std::fs::write(
            &metadata_path,
            format!(
                "{{\"filename\":\"{revision}.tar\",\"revision\":\"{revision}\",\"schema\":\"tiaris.nest.manage-source.v1\",\"sha256\":\"{}\",\"size_bytes\":{}}}\n",
                hex::encode(Sha256::digest(archive_body)),
                archive_body.len()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&metadata_path, std::fs::Permissions::from_mode(0o444)).unwrap();

        let mut config = AppConfig::default();
        config.build.work_dir = root.join("work");
        config.build.output_dir = root.join("out");
        config.workstation_netboot.allow_private_release_urls = true;
        config.build.manage_source_url_template =
            format!("tarball+file://{}/{{revision}}.tar", source_dir.display());
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "github:NixOS/nixpkgs/fixture".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "fixture".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: Some("5".repeat(40)),
            source_lock_sha256: Some("6".repeat(64)),
            software_package_refs: Vec::new(),
            build_input: None,
            closure_source: None,
        };
        let build_input = ValidatedBlueprintBuildInput {
            kind: INSTALLER_TARGET_BUILD_INPUT_KIND.to_string(),
            generated_nix: "{ ... }: {}".to_string(),
            desktop_module_nix: None,
            expected_state: None,
            blueprint_name: Some("Installer fixture".to_string()),
            blueprint_revision: Some(1),
            hardware_module_nix: Some("{ ... }: {}".to_string()),
            target_module_nix: Some("{ ... }: {}".to_string()),
            manage_source_revision: Some(revision.clone()),
            installer_target: Some(valid_installer_target_identity()),
            wallpaper_asset: None,
        };

        blueprint_nix_build_command(&config, &target, &spec, &build_input, 44).unwrap();
        let flake = std::fs::read_to_string(root.join("work/job-44-input/flake.nix")).unwrap();
        assert!(flake.contains(&format!(
            "tarball+file://{}/{revision}.tar",
            source_dir.display()
        )));
        assert!(!flake.contains("github:CybexHQ/manage"));
        assert!(flake.contains("import (manage + \"/deploy/nixos/tiaris-agent-package.nix\")"));
        assert!(flake.contains("repoRoot = manage;"));
        assert!(!flake.contains("src = manage + \"/agent/tiaris-agent\""));
        let configuration =
            std::fs::read_to_string(root.join("work/job-44-input/configuration.nix")).unwrap();
        assert!(configuration.contains("(manageSource + \"/deploy/nixos/tiaris-blueprints.nix\")"));
        assert!(
            configuration.contains("(manageSource + \"/deploy/nixos/tiaris-agent-module.nix\")")
        );
        assert!(
            !root
                .join("work/job-44-input/tiaris-blueprints.nix")
                .exists()
        );

        std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&archive_path, b"tampered source").unwrap();
        std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let error =
            blueprint_nix_build_command(&config, &target, &spec, &build_input, 45).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("size does not match"));
        assert!(!root.join("work/job-45-input").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nix_build_command_rejects_protected_material_before_writing_inputs() {
        let sentinel = "TIARIS_NEST_PROTECTED_SENTINEL_7f922a";
        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-protected-build-input-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = AppConfig::default();
        config.build.work_dir = root.join("work");
        config.build.output_dir = root.join("out");
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "/srv/tiaris-nest/build-inputs/tiaris".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let spec = ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: Some("c".repeat(40)),
            source_lock_sha256: Some("d".repeat(64)),
            software_package_refs: Vec::new(),
            build_input: Some(ValidatedBlueprintBuildInput {
                kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
                generated_nix: format!(
                    "{{ ... }}: {{ users.users.alice.hashedPassword = \"{sentinel}\"; }}"
                ),
                desktop_module_nix: None,
                expected_state: None,
                blueprint_name: None,
                blueprint_revision: None,
                hardware_module_nix: None,
                target_module_nix: None,
                manage_source_revision: None,
                installer_target: None,
                wallpaper_asset: None,
            }),
            closure_source: None,
        };

        let error = nix_build_command(&config, &target, &spec, 99)
            .unwrap_err()
            .to_string();

        assert!(!error.contains(sentinel));
        assert!(!root.join("work/job-99-input").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn log_capture_bounds_and_redacts() {
        let log = SharedLog::new(64);
        log.append("token=secret normal password=hunter2 secret-key=/tmp/key\n")
            .await;
        let snapshot = log.snapshot().await;

        assert!(snapshot.contains("[REDACTED]"));
        assert!(!snapshot.contains("hunter2"));
        assert!(snapshot.len() <= 64);
    }

    #[tokio::test]
    async fn log_capture_redacts_authorization_header_value() {
        let log = SharedLog::new(1024);
        log.append("normal Authorization: Bearer top-secret-token done\n")
            .await;
        let snapshot = log.snapshot().await;

        assert!(snapshot.contains("normal"));
        assert!(snapshot.contains("done"));
        assert!(!snapshot.contains("Bearer"));
        assert!(!snapshot.contains("top-secret-token"));
    }

    #[tokio::test]
    async fn log_capture_redacts_authorization_header_value_split_across_appends() {
        let log = SharedLog::new(1024);
        log.append("normal Authorization:").await;
        log.append(" Bearer split-secret done\n").await;
        let snapshot = log.snapshot().await;

        assert!(snapshot.contains("normal"));
        assert!(snapshot.contains("done"));
        assert!(!snapshot.contains("Bearer"));
        assert!(!snapshot.contains("split-secret"));
    }

    #[tokio::test]
    async fn log_capture_redacts_spaced_nix_assignments_and_modular_hashes() {
        let sentinel = "TIARIS_NEST_PROTECTED_SENTINEL_7f922a";
        let password_hash = "$6$rounds=5000$abcdefghijklmnop$uHL2DmwkR2iK6s.wDbxLW3GxvjJT7qW2rEHemZz3oMlKlfj8JwHc99.FNZrTO4drUslZ0MRyYkBDumQxKdL8q/";
        let log = SharedLog::new(4096);
        log.append(&format!(
            "users.users.alice.hashedPassword = \"{sentinel}\"; bare {password_hash}\n"
        ))
        .await;
        let snapshot = log.snapshot().await;

        assert!(snapshot.contains("[REDACTED]"));
        assert!(!snapshot.contains(sentinel));
        assert!(!snapshot.contains(password_hash));
    }

    #[tokio::test]
    async fn log_capture_redacts_assignments_split_across_stream_chunks() {
        let sentinel = "TIARIS_NEST_PROTECTED_SENTINEL_7f922a";
        let log = SharedLog::new(4096);
        log.append("users.users.alice.hashedPassword = \"TIARIS_NEST_")
            .await;
        assert!(!log.snapshot().await.contains("TIARIS_NEST_"));

        log.append("PROTECTED_SENTINEL_7f922a\"; done\n").await;
        let snapshot = log.snapshot().await;

        assert!(snapshot.contains("done"));
        assert!(!snapshot.contains(sentinel));
    }

    #[test]
    fn safe_error_redacts_entire_secret_key_value() {
        let err =
            anyhow!("copy failed for file:///cache?secret-key=/tmp/cache.key&compression=zstd");
        let message = safe_error(&err);

        assert!(message.contains("secret-key=[REDACTED]&compression=zstd"));
        assert!(!message.contains("/tmp/cache.key"));
    }

    #[test]
    fn nix_path_info_parser_accepts_object_or_array_shapes() {
        let object = json!({
            "/nix/store/example": {
                "closureSize": 128,
                "narSize": 64,
                "deriver": format!("/nix/store/{}-example.drv", "a".repeat(32))
            }
        });
        let row = nix_path_info_row(&object, "/nix/store/example").unwrap();
        assert_eq!(nix_path_info_sizes(row), (128, 128));
        assert_eq!(
            nix_path_info_deriver(row).as_deref(),
            Some(format!("/nix/store/{}-example.drv", "a".repeat(32)).as_str())
        );

        let array = json!([
            {
                "closureSize": 200,
                "narSize": 300
            }
        ]);
        let row = nix_path_info_row(&array, "/nix/store/other").unwrap();
        assert_eq!(nix_path_info_sizes(row), (300, 200));
        assert_eq!(nix_path_info_deriver(row), None);

        let unrelated_object = json!({
            "/nix/store/unrelated": {
                "deriver": format!("/nix/store/{}-unrelated.drv", "b".repeat(32))
            }
        });
        assert!(
            nix_path_info_row(&unrelated_object, "/nix/store/requested")
                .unwrap_err()
                .to_string()
                .contains("omitted the requested store path")
        );

        let unrelated_array = json!([{
            "path": "/nix/store/unrelated",
            "deriver": format!("/nix/store/{}-unrelated.drv", "b".repeat(32))
        }]);
        assert!(
            nix_path_info_row(&unrelated_array, "/nix/store/requested")
                .unwrap_err()
                .to_string()
                .contains("unexpected store path")
        );
    }

    #[test]
    fn managed_metadata_cannot_replace_verified_cache_export_fields() {
        let mut destination = json!({
            "cache_schema": "tiaris.nest.cache.v1",
            "closure_manifest": {"verified": true},
            "closure_manifest_sha256": "a".repeat(64)
        });
        let source = json!({
            "cache_schema": "untrusted",
            "closure_manifest": {"forged": true},
            "closure_manifest_sha256": "b".repeat(64),
            "target": "blueprint"
        });

        merge_build_metadata(&mut destination, &source);

        assert_eq!(destination["cache_schema"], "tiaris.nest.cache.v1");
        assert_eq!(destination["closure_manifest"], json!({"verified": true}));
        assert_eq!(destination["closure_manifest_sha256"], "a".repeat(64));
        assert_eq!(destination["target"], "blueprint");
    }

    #[test]
    fn blueprint_jobs_build_only_at_the_pin_or_the_ready_detected_commit() {
        let reviewed = "74cc63f702f7d60a557e152a57b40fb1fd0f72ac";
        let detected = "6f06d204d8f2d8761d9da78778745974a3216381";
        let mut config = AppConfig::default();
        config.build.targets = vec![BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: format!("github:NixOS/nixpkgs/{reviewed}"),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        }];
        let mut spec = blueprint_spec_for_commit(detected);
        assert!(build_target_for_detected_commit(&config, &spec, Some(detected)).is_ok());
        let error = build_target_for_detected_commit(&config, &spec, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("ready detected commit"));
        assert!(
            build_target_for_detected_commit(
                &config,
                &spec,
                Some("1111111111111111111111111111111111111111")
            )
            .is_err()
        );
        spec.nixpkgs_commit = Some(reviewed.to_string());
        assert!(build_target_for_detected_commit(&config, &spec, Some(detected)).is_ok());
    }

    fn blueprint_spec_for_commit(commit: &str) -> ValidatedBuildSpec {
        ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: Some(commit.to_string()),
            source_lock_sha256: Some("b".repeat(64)),
            software_package_refs: Vec::new(),
            build_input: Some(ValidatedBlueprintBuildInput {
                kind: BLUEPRINT_BUILD_INPUT_KIND.to_string(),
                generated_nix: "{ ... }: {}".to_string(),
                desktop_module_nix: None,
                expected_state: None,
                blueprint_name: None,
                blueprint_revision: None,
                hardware_module_nix: None,
                target_module_nix: None,
                manage_source_revision: None,
                installer_target: None,
                wallpaper_asset: None,
            }),
            closure_source: None,
        }
    }

    #[test]
    fn detected_commit_jobs_pin_nixpkgs_to_the_recorded_nar_hash() {
        let commit = "6f06d204d8f2d8761d9da78778745974a3216381";
        let nar_hash = "sha256-loLMnbbS4KhmG2ln9EY6f0YMNCA273Yx02oWYQ9IMeE=";
        assert_eq!(
            nixpkgs_flake_ref(commit, None).unwrap(),
            format!("github:NixOS/nixpkgs/{commit}")
        );
        assert_eq!(
            nixpkgs_flake_ref(commit, Some(nar_hash)).unwrap(),
            format!(
                "github:NixOS/nixpkgs/{commit}?narHash=sha256-loLMnbbS4KhmG2ln9EY6f0YMNCA273Yx02oWYQ9IMeE%3D"
            )
        );
        for invalid in [
            "",
            "sha256-",
            "sha512-loLMnbbS4KhmG2ln9EY6f0YMNCA273Yx02oWYQ9IMeE=",
            "sha256-loLMnbbS4KhmG2ln9EY6f0YMNCA273Yx02oWYQ9IMe=",
            "sha256-loLMnbbS4KhmG2ln9EY6f0YMNCA273Yx02oWYQ9IMe&=",
        ] {
            assert!(
                nixpkgs_flake_ref(commit, Some(invalid)).is_err(),
                "{invalid}"
            );
        }
        let root =
            std::env::temp_dir().join(format!("tiaris-nest-detected-flake-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = AppConfig::default();
        config.build.work_dir = root.join("work");
        config.build.output_dir = root.join("out");
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "github:NixOS/nixpkgs/74cc63f702f7d60a557e152a57b40fb1fd0f72ac".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let spec = blueprint_spec_for_commit(commit);
        nix_build_command_with_nixpkgs_nar_hash(&config, &target, &spec, 7, Some(nar_hash))
            .unwrap();
        let flake =
            std::fs::read_to_string(config.build.work_dir.join("job-7-input/flake.nix")).unwrap();
        assert!(flake.contains(&format!(
            "inputs.nixpkgs.url = \"github:NixOS/nixpkgs/{commit}?narHash="
        )));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_job_is_admitted_at_the_pin_or_a_ready_commit_only() {
        let pin = "74cc63f702f7d60a557e152a57b40fb1fd0f72ac";
        let detected_commit = "6f06d204d8f2d8761d9da78778745974a3216381";
        let other = "1111111111111111111111111111111111111111";

        let mut config = AppConfig::default();
        config.build.targets = vec![BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: format!("github:NixOS/nixpkgs/{pin}"),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        }];
        // A Blueprint job is admitted at the commit it names, if allowed.
        let spec = blueprint_spec_for_commit(detected_commit);
        let admitted = admit_build_target(&config, &spec, Some(detected_commit)).unwrap();
        assert_eq!(admitted.nixpkgs_commit.as_deref(), Some(detected_commit));
        // A job without a Blueprint builds the target's flake: it is admitted
        // at that flake's pin, whatever its spec text says.
        let mut plain = blueprint_spec_for_commit(pin);
        plain.build_input = None;
        assert_eq!(
            admit_build_target(&config, &plain, None)
                .unwrap()
                .nixpkgs_commit
                .as_deref(),
            Some(pin)
        );
        plain.nixpkgs_commit = None;
        assert_eq!(
            admit_build_target(&config, &plain, None)
                .unwrap()
                .nixpkgs_commit
                .as_deref(),
            Some(pin)
        );
        for claimed in [detected_commit, other] {
            plain.nixpkgs_commit = Some(claimed.to_string());
            assert!(admit_build_target(&config, &plain, Some(detected_commit)).is_err());
        }
        // A target flake that is not a pinned nixpkgs gives no commit.
        config.build.targets[0].target = "custom".to_string();
        config.build.targets[0].flake = "path:/srv/custom".to_string();
        plain.target = "custom".to_string();
        plain.nixpkgs_commit = None;
        let admitted = admit_build_target(&config, &plain, None).unwrap();
        assert_eq!(admitted.nixpkgs_commit, None);
    }

    #[test]
    fn a_job_at_a_detected_commit_names_that_commit_in_its_result_metadata() {
        let commit = "6f06d204d8f2d8761d9da78778745974a3216381";
        let nar_hash = "sha256-loLMnbbS4KhmG2ln9EY6f0YMNCA273Yx02oWYQ9IMeE=";
        let config = AppConfig::default();
        let target = BuildTargetConfig {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            flake: "github:NixOS/nixpkgs/74cc63f702f7d60a557e152a57b40fb1fd0f72ac".to_string(),
            attr: "packages.x86_64-linux.desktop-experience".to_string(),
        };
        let job = BuildJob {
            id: 7,
            ..serde_json::from_value(json!({
                "id": 7, "managed_job_id": null, "requested_artifact_type": "nixos_closure",
                "build_spec": {}, "target": "blueprint", "system": "x86_64-linux",
                "input_revision": "rev", "input_config_hash": "a".repeat(64), "status": "running",
                "progress_percent": null, "progress_stage": null, "progress_message": null,
                "logs": "", "error": "", "rejection_code": "", "output_path": "", "output_sha256": "",
                "output_size_bytes": 0, "exit_code": null, "cache_metadata": {},
                "started_at": null, "completed_at": null, "cancel_requested_at": null,
                "created_at": "2026-10-31T00:00:00Z", "updated_at": "2026-10-31T00:00:00Z"
            }))
            .unwrap()
        };
        let detected = admitted_result_metadata(
            &config,
            &job,
            &target,
            Some(commit),
            Some(nar_hash),
            Some("package_build_failed"),
        );
        assert_eq!(detected["nixpkgs_revision"], commit);
        assert_eq!(
            detected["nixpkgs_flake"],
            nixpkgs_flake_ref(commit, Some(nar_hash)).unwrap()
        );
        assert_eq!(detected["error_kind"], "package_build_failed");
        let pin = admitted_result_metadata(
            &config,
            &job,
            &target,
            Some("74cc63f702f7d60a557e152a57b40fb1fd0f72ac"),
            None,
            None,
        );
        assert_eq!(pin["nixpkgs_flake"], target.flake);
    }
}
