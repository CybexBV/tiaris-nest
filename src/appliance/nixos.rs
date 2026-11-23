//! NixOS daemon download and independent privileged update admission.
use super::{
    closure, members,
    release_v3::{self, NixosRelease, ReleaseDescriptor},
};
use anyhow::{Result, anyhow, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub const CAPABILITY: &str = "appliance_update_v3";
/// The Nest takes a newer release in place of a staged update that has not
/// started (`store`); Manage replaces a waiting attempt only for such a Nest.
pub const REPLACE_CAPABILITY: &str = "appliance_update_replace_v1";
pub const IDENTITY_PATH: &str = "/usr/share/tiaris-nest/system-identity.json";
pub const MIGRATIONS_PATH: &str = "/usr/share/tiaris-nest/sqlite-migrations.json";
// STATE is deliberately only 16 GiB. Bulk bytes belong to the root-backed
// cache; only requests and durable privileged transaction receipts use STATE.
const UPDATE_CACHE_ROOT: &str = "/var/cache/tiaris-nest/appliance-updates";
const UPDATE_BUNDLE_ROOT: &str = "/var/cache/tiaris-nest/appliance-updates/inbox";
/// Beside the updater request, for root (`generation_update.make_download_room`).
const UPDATE_ROOM_REQUEST_PATH: &str =
    "/var/lib/tiaris-nest/state/inbox/appliance-update-room.json";
const UPDATE_PRIVATE_ROOT: &str = "/var/cache/tiaris-nest/appliance-updates/private";
const DATABASE_BACKUP_RESERVE: u64 = 1024 * 1024 * 1024;
static QUEUE: Mutex<(bool, Option<super::ManagedApplianceUpdate<NixosRelease>>)> =
    Mutex::new((false, None));

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredUpdate {
    schema: String,
    attempt_id: Uuid,
    requested_at: DateTime<Utc>,
    release: NixosRelease,
    bundle_path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledState {
    pub schema: String,
    pub release: NixosRelease,
    pub system_generation: String,
    pub system_toplevel: String,
    pub system_closure_sha256: String,
    pub base_os: String,
    pub base_os_version: String,
    pub at_rest_protection: String,
}
pub fn is_nixos() -> bool {
    Path::new(IDENTITY_PATH).is_file()
}
pub fn queue(update: super::ManagedApplianceUpdate<ReleaseDescriptor>) -> bool {
    let ReleaseDescriptor::Nixos(release) = update.release;
    let Ok(mut state) = QUEUE.lock() else {
        return false;
    };
    state.1 = Some(super::ManagedApplianceUpdate {
        release,
        attempt_id: update.attempt_id,
        requested_at: update.requested_at,
        qualification_package_transport_url: update.qualification_package_transport_url,
    });
    if state.0 {
        return false;
    }
    state.0 = true;
    drop(state);
    tokio::spawn(async {
        loop {
            let update = {
                let Ok(mut s) = QUEUE.lock() else { return };
                match s.1.take() {
                    Some(v) => v,
                    None => {
                        s.0 = false;
                        return;
                    }
                }
            };
            if let Err(error) = store(update).await {
                tracing::warn!(error=%error,"NixOS appliance update staging failed");
            }
        }
    });
    true
}
fn read_installed() -> Result<InstalledState> {
    let bytes = crate::provisioning::read_bounded_nofollow(
        Path::new(super::INSTALLED_STATE_PATH),
        256 * 1024,
        "installed NixOS receipt",
    )?;
    let state: InstalledState = serde_json::from_value(release_v3::strict_json(&bytes)?)?;
    state
        .release
        .verify_file(Path::new(super::RELEASE_PUBLIC_KEY_PATH))?;
    ensure!(
        state.schema == "tiaris.nest.installed-appliance.v3"
            && state.base_os == "nixos"
            && state.base_os_version == state.release.base_os_version
            && state.at_rest_protection == "none"
            && state.system_toplevel == state.release.system_toplevel
            && state.system_closure_sha256 == state.release.system_closure.sha256,
        "installed NixOS receipt mismatch"
    );
    generation(&state.system_generation)?;
    Ok(state)
}
pub fn generation(v: &str) -> Result<u64> {
    let n: u64 = v.parse()?;
    ensure!(n > 0 && n.to_string() == v, "noncanonical NixOS generation");
    Ok(n)
}
fn newer(release: &NixosRelease, current: &NixosRelease) -> Result<()> {
    ensure!(
        semver::Version::parse(&release.release_id)?
            .cmp_precedence(&semver::Version::parse(&current.release_id)?)
            .is_gt(),
        "appliance update must be strictly newer"
    );
    Ok(())
}
async fn store(update: super::ManagedApplianceUpdate<NixosRelease>) -> Result<()> {
    ensure!(
        is_nixos() && !update.attempt_id.is_nil(),
        "NixOS update requires installed NixOS"
    );
    let key = update
        .release
        .verify_file(Path::new(super::RELEASE_PUBLIC_KEY_PATH))?;
    if let Some(status) =
        super::read_optional_bounded_json::<Value>(Path::new(super::UPDATE_STATUS_PATH), 128 * 1024)
    {
        if status["attempt_id"] == update.attempt_id.to_string()
            && status["target_release"] == update.release.release_id
            && status["system_closure_sha256"] == update.release.system_closure.sha256
            && matches!(
                status["status"].as_str(),
                Some("succeeded" | "failed" | "rolled_back")
            )
        {
            return Ok(());
        }
    }
    let current = read_installed()?;
    newer(&update.release, &current.release)?;
    let prior = super::read_optional_bounded_json::<StoredUpdate>(
        Path::new(super::UPDATE_REQUEST_PATH),
        256 * 1024,
    );
    if let Some(prior) = &prior {
        if prior.attempt_id == update.attempt_id && prior.release == update.release {
            return Ok(());
        }
        // Manage replaces a waiting update only with a newer release.
        newer(&update.release, &prior.release)
            .map_err(|_| anyhow!("another appliance update is already staged"))?;
        // Look first, so a request that cannot be swapped now (root is
        // preparing or installing it) is not downloaded for nothing.
        drop(replaceable(prior)?);
    }
    validate_directory(Path::new(UPDATE_CACHE_ROOT), 0, 0o755)?;
    validate_directory(Path::new(UPDATE_BUNDLE_ROOT), 985, 0o700)?;
    let transport = update
        .qualification_package_transport_url
        .as_deref()
        .unwrap_or(&update.release.system_closure.url);
    if transport != update.release.system_closure.url {
        let artifact = super::ApplianceRepositorySnapshot {
            url: update.release.system_closure.url.clone(),
            sha256: update.release.system_closure.sha256.clone(),
            size_bytes: update.release.system_closure.size_bytes,
        };
        super::validate_qualification_package_transport_url(transport, &artifact)?;
    }
    let allow_private = transport != update.release.system_closure.url;
    let path = match by_store_path(&update, &key, transport, allow_private, prior.is_none()).await?
    {
        Some(path) => path,
        None => {
            let path = archive_bundle(update.attempt_id);
            let download_bytes = update
                .release
                .system_closure
                .size_bytes
                .saturating_sub(partial_bytes(&path, &update.release));
            download_room(&update, download_bytes, prior.is_none())?;
            download(&update.release, transport, &path, allow_private).await?;
            path
        }
    };
    // So the Nest serves this release's workstation runtime right after the
    // restart (`netboot::prepare`).
    crate::netboot::prepare::wait(&update.release.release_id).await;
    let stored = StoredUpdate {
        schema: "tiaris.nest.appliance-update-request.v3".into(),
        attempt_id: update.attempt_id,
        requested_at: update.requested_at,
        release: update.release,
        bundle_path: path.to_str().ok_or_else(|| anyhow!("archive path"))?.into(),
    };
    let Some(prior) = prior else {
        return super::write_atomic_json(Path::new(super::UPDATE_REQUEST_PATH), &stored, 0o600);
    };
    let replaced = replace_waiting(&prior, &stored);
    if replaced.is_err() {
        // The older update goes ahead; Manage hands this one again later.
        let _ = fs::remove_file(&path);
    }
    replaced
}

/// The inbox names of an attempt's download: the archive, or the members
/// the running system lacks (`members`).
fn archive_bundle(attempt_id: Uuid) -> PathBuf {
    Path::new(UPDATE_BUNDLE_ROOT).join(format!("{attempt_id}.tar.zst"))
}
fn members_bundle(attempt_id: Uuid) -> PathBuf {
    Path::new(UPDATE_BUNDLE_ROOT).join(format!("{attempt_id}.members.tar"))
}

/// The download only has to fit, and only what it still misses: an earlier
/// try may have left part of it. Whether the update itself fits is root's
/// decision (`verify_update`): root can free space first, and its refusal
/// reaches Tiaris with a reason. Retention restores the floor meanwhile.
fn download_room(
    update: &super::ManagedApplianceUpdate<NixosRelease>,
    download_bytes: u64,
    ask: bool,
) -> Result<()> {
    let Err(error) = crate::disk::ensure_headroom(
        Path::new(UPDATE_BUNDLE_ROOT),
        download_bytes,
        "Nest update download",
    ) else {
        return Ok(());
    };
    // Root never sees an update whose download did not land, so it is asked
    // for room: it frees space as it does for an update that does not fit.
    // Tiaris hands the update again; then the download fits, or root has
    // ended the attempt with `insufficient_store_space`. A staged older
    // update goes first and makes its own room.
    if ask {
        super::write_atomic_json(
            Path::new(UPDATE_ROOM_REQUEST_PATH),
            &room_request(update, download_bytes),
            0o600,
        )?;
    }
    Err(error)
}

/// The update by store path (`members`): only the members the running
/// system lacks. `None` takes the full archive: an archive packed another
/// way, most of it new, or a server or bytes that do not allow it. A
/// download that keeps dropping is an error: the next try continues it.
async fn by_store_path(
    update: &super::ManagedApplianceUpdate<NixosRelease>,
    key: &ed25519_dalek::VerifyingKey,
    transport: &str,
    allow_private: bool,
    ask_room: bool,
) -> Result<Option<PathBuf>> {
    let inbox = Path::new(UPDATE_BUNDLE_ROOT);
    let fallback = |error: anyhow::Error| {
        if error.is::<members::KeepTrying>() {
            return Err(error);
        }
        tracing::warn!(error = %format!("{error:#}"), "Nest update takes the whole archive");
        Ok(None)
    };
    let planned = match members::running_system_async().await {
        Ok(present) => {
            members::plan(
                &update.release,
                key,
                transport,
                allow_private,
                inbox,
                &present,
            )
            .await
        }
        Err(error) => Err(error),
    };
    let plan = match planned {
        Ok(Some(plan)) => plan,
        Ok(None) => return Ok(None),
        Err(error) => return fallback(error),
    };
    discard_other_partials(&members::partial_path(inbox, &update.release))?;
    download_room(update, plan.remaining_bytes(), ask_room)?;
    tracing::info!(
        members = plan.members(),
        bytes = plan.bytes,
        "Nest update fetches only the store paths it lacks"
    );
    let target = members_bundle(update.attempt_id);
    match members::stage(&plan, &target).await {
        Ok(()) => Ok(Some(target)),
        Err(error) => fallback(error),
    }
}

/// What root needs to make room for a download and to report the attempt:
/// its identity and how much must be free.
fn room_request(
    update: &super::ManagedApplianceUpdate<NixosRelease>,
    download_bytes: u64,
) -> Value {
    json!({
        "schema": "tiaris.nest.appliance-update-room.v1",
        "attempt_id": update.attempt_id,
        "release": update.release,
        "required_available_bytes": download_bytes.saturating_add(crate::disk::DISK_HEADROOM_BYTES),
    })
}

/// Puts a newer release in place of a staged update the root updater has
/// not started installing. What root prepared ahead for it does not count:
/// root drops it for a request that changed (`generation_update.drop_prepared`).
fn replace_waiting(prior: &StoredUpdate, stored: &StoredUpdate) -> Result<()> {
    let _lease = replaceable(prior)?;
    super::write_atomic_json(Path::new(super::UPDATE_REQUEST_PATH), stored, 0o600)?;
    remove_bundles(prior.attempt_id)
}

/// Remove an attempt's download, whichever it is. Only the canonical
/// basenames, never a caller path; unlink does not follow a symlink there.
fn remove_bundles(attempt_id: Uuid) -> Result<()> {
    let mut removed = false;
    for bundle in [archive_bundle(attempt_id), members_bundle(attempt_id)] {
        match fs::remove_file(&bundle) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    if removed {
        super::sync_directory(Path::new(UPDATE_BUNDLE_ROOT))?;
    }
    Ok(())
}

/// The maintenance lock, held while the staged request is still `prior` and
/// root has not started installing it.
fn replaceable(prior: &StoredUpdate) -> Result<crate::maintenance::BuildLease> {
    let Some(lease) = crate::maintenance::try_exclusive()? else {
        bail!("the staged appliance update is being prepared or installed")
    };
    let staged = super::read_optional_bounded_json::<StoredUpdate>(
        Path::new(super::UPDATE_REQUEST_PATH),
        256 * 1024,
    );
    ensure!(
        staged.is_some_and(|staged| staged.attempt_id == prior.attempt_id),
        "the staged appliance update changed"
    );
    let status = super::read_optional_bounded_json::<Value>(
        Path::new(super::UPDATE_STATUS_PATH),
        128 * 1024,
    );
    ensure!(
        !started(status.as_ref(), prior.attempt_id),
        "the staged appliance update has started"
    );
    Ok(lease)
}

/// Whether the root updater reported more than waiting for this attempt.
fn started(status: Option<&Value>, attempt_id: Uuid) -> bool {
    status.is_some_and(|status| {
        status["attempt_id"] == attempt_id.to_string() && status["status"] != "waiting_window"
    })
}

/// Drops one download call resumes after; the next call continues the
/// partial file. Each drop in a row without new bytes waits 5 s longer.
const RESUMES: u32 = 8;
const RESUME_PAUSE: Duration = Duration::from_secs(5);

/// Where the signed archive's bytes collect beside `path` until they are
/// complete. Named for the archive, so only this exact archive's bytes are
/// ever continued, also by a later attempt of the same release.
pub fn partial_path(path: &Path, release: &NixosRelease) -> Result<PathBuf> {
    Ok(path
        .parent()
        .ok_or_else(|| anyhow!("closure archive path has no directory"))?
        .join(format!("{}.part", release.system_closure.sha256)))
}

/// The bytes of the signed archive already downloaded beside `path`.
pub fn partial_bytes(path: &Path, release: &NixosRelease) -> u64 {
    partial_path(path, release)
        .ok()
        .and_then(|partial| fs::symlink_metadata(partial).ok())
        .filter(|metadata| metadata.is_file())
        .map_or(0, |metadata| {
            metadata.len().min(release.system_closure.size_bytes)
        })
}

pub async fn download(
    release: &NixosRelease,
    transport: &str,
    path: &Path,
    allow_private: bool,
) -> Result<closure::AuthenticatedArchive> {
    download_with_progress(release, transport, path, allow_private, &mut |_, _| {}).await
}

/// Download the signed closure to `path` and return it open and
/// authenticated: this is the archive's one SHA-256 pass. Reports
/// `(received, signed_total)` bytes after each chunk; the callback observes
/// progress only and cannot affect the signed size and hash checks.
///
/// A dropped transfer resumes with HTTP Range. The bytes collect in a
/// private partial file beside `path` ([`partial_path`]), continued after a
/// drop in this call and by a later call: a restart, Tiaris handing the
/// update again, a retried setup. The hash reads the bytes already there
/// once, then takes each new chunk. Only bytes of the signed size and hash
/// become `path`; a partial file that ends otherwise is removed.
pub async fn download_with_progress(
    release: &NixosRelease,
    transport: &str,
    path: &Path,
    allow_private: bool,
    progress: &mut (dyn FnMut(u64, u64) + Send),
) -> Result<closure::AuthenticatedArchive> {
    download_resuming(
        release,
        transport,
        path,
        allow_private,
        progress,
        RESUME_PAUSE,
    )
    .await
}

async fn download_resuming(
    release: &NixosRelease,
    transport: &str,
    path: &Path,
    allow_private: bool,
    progress: &mut (dyn FnMut(u64, u64) + Send),
    pause: Duration,
) -> Result<closure::AuthenticatedArchive> {
    let total = release.system_closure.size_bytes;
    let partial = partial_path(path, release)?;
    discard_other_partials(&partial)?;
    let (file, mut received, mut hash) = {
        let partial = partial.clone();
        tokio::task::spawn_blocking(move || open_partial(&partial, total)).await??
    };
    let mut file = tokio::fs::File::from_std(file);
    progress(received, total);
    let (mut resumes, mut idle) = (0u32, 0u32);
    while received < total {
        let before = received;
        let error = match fetch(
            release,
            transport,
            allow_private,
            &mut file,
            &mut received,
            &mut hash,
            progress,
        )
        .await
        {
            Ok(()) if received == total => break,
            Ok(()) => anyhow!("closure download ended early"),
            Err(Transfer::Dropped(error)) => error,
            Err(Transfer::Refused(error)) => return Err(error),
        };
        idle = if received > before { 1 } else { idle + 1 };
        resumes += 1;
        if resumes > RESUMES {
            return Err(error.context("closure download kept dropping; the next try continues it"));
        }
        tracing::warn!(error = %error, received, total, "closure download dropped; resuming");
        tokio::time::sleep(pause * idle).await;
    }
    file.sync_all().await?;
    let file = file.into_std().await;
    let archive = match closure::AuthenticatedArchive::hashed(file, hash, received, release) {
        Ok(archive) => archive,
        Err(error) => {
            let _ = fs::remove_file(&partial);
            return Err(error);
        }
    };
    fs::rename(&partial, path)?;
    super::sync_directory(path.parent().ok_or_else(|| anyhow!("archive path"))?)?;
    Ok(archive)
}

/// The partial file, its bytes and their hash. Bytes beyond the signed size
/// cannot be the archive: the download starts again.
fn open_partial(partial: &Path, total: u64) -> Result<(fs::File, u64, Sha256)> {
    let open = || {
        OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(partial)
    };
    let mut file = open()?;
    let metadata = file.metadata()?;
    if !(metadata.is_file()
        && metadata.nlink() == 1
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o777 == 0o600)
    {
        fs::remove_file(partial)?;
        file = open()?;
    }
    let mut hash = Sha256::new();
    let mut length = file.metadata()?.len();
    if length > total {
        file.set_len(0)?;
        length = 0;
    }
    file.rewind()?;
    ensure!(
        std::io::copy(&mut (&file).take(length), &mut hash)? == length,
        "closure partial download changed while it was read"
    );
    Ok((file, length, hash))
}

/// Partial downloads of other archives in the same private directory, and
/// of members (`members::partial_path`), and the temporary files of the
/// downloader before partial files (`<name>.tar.<uuid>.tmp`), which a
/// stopped download left behind.
fn discard_other_partials(partial: &Path) -> Result<()> {
    let directory = partial
        .parent()
        .ok_or_else(|| anyhow!("closure partial download has no directory"))?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.path() == partial {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let other_partial = name
            .strip_suffix(".part")
            .map(|stem| stem.strip_suffix(".members").unwrap_or(stem))
            .is_some_and(|hash| {
                hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            });
        let old_temporary = name
            .strip_suffix(".tmp")
            .and_then(|stem| stem.rsplit_once('.'))
            .is_some_and(|(stem, id)| stem.ends_with(".tar") && Uuid::parse_str(id).is_ok());
        if (other_partial || old_temporary) && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

enum Transfer {
    /// The connection or the server failed: the bytes so far stand.
    Dropped(anyhow::Error),
    /// The answer is not the archive: give up.
    Refused(anyhow::Error),
}

/// One request for the archive's bytes from `received` on, appended to
/// `file` and `hash` as they come.
async fn fetch(
    release: &NixosRelease,
    transport: &str,
    allow_private: bool,
    file: &mut tokio::fs::File,
    received: &mut u64,
    hash: &mut Sha256,
    progress: &mut (dyn FnMut(u64, u64) + Send),
) -> std::result::Result<(), Transfer> {
    use reqwest::{StatusCode, header};
    let refused =
        |message: &str| Transfer::Refused(anyhow!("invalid closure HTTP response: {message}"));
    let total = release.system_closure.size_bytes;
    let offset = *received;
    let mut response = crate::release_transport::get(
        transport,
        allow_private,
        !allow_private,
        Duration::from_secs(4 * 60 * 60),
        Some(offset),
    )
    .await
    .map_err(Transfer::Dropped)?;
    let status = response.status();
    let length = response.content_length();
    if response
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|value| value != "identity")
    {
        return Err(refused("encoded body"));
    }
    match status {
        StatusCode::OK if length.is_none_or(|n| n == total) => {
            if offset > 0 {
                // The server sent the whole archive instead of the rest.
                start_over(file, hash, received, progress, total).await?;
            }
        }
        StatusCode::PARTIAL_CONTENT if offset > 0 => {
            let range = format!("bytes {offset}-{}/{total}", total - 1);
            if response
                .headers()
                .get(header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                != Some(range.as_str())
                || length.is_some_and(|n| n != total - offset)
            {
                return Err(refused("range"));
            }
        }
        StatusCode::RANGE_NOT_SATISFIABLE if offset > 0 => {
            // The server does not know these bytes as the archive's start.
            start_over(file, hash, received, progress, total).await?;
            return Err(Transfer::Dropped(anyhow!("closure download range refused")));
        }
        status
            if status.is_server_error()
                || status == StatusCode::REQUEST_TIMEOUT
                || status == StatusCode::TOO_MANY_REQUESTS =>
        {
            return Err(Transfer::Dropped(anyhow!(
                "closure download answered {status}"
            )));
        }
        _ => return Err(refused("status or length")),
    }
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| Transfer::Dropped(error.into()))?
    {
        let next = received
            .checked_add(chunk.len() as u64)
            .filter(|next| *next <= total)
            .ok_or_else(|| Transfer::Refused(anyhow!("closure exceeds signed size")))?;
        file.write_all(&chunk)
            .await
            .map_err(|error| Transfer::Refused(error.into()))?;
        hash.update(&chunk);
        *received = next;
        progress(next, total);
    }
    Ok(())
}

async fn start_over(
    file: &mut tokio::fs::File,
    hash: &mut Sha256,
    received: &mut u64,
    progress: &mut (dyn FnMut(u64, u64) + Send),
    total: u64,
) -> std::result::Result<(), Transfer> {
    file.set_len(0)
        .await
        .map_err(|error| Transfer::Refused(error.into()))?;
    *hash = Sha256::new();
    *received = 0;
    progress(0, total);
    Ok(())
}

/// The update needs more free disk space than there is. `verify_update`
/// changes nothing for it the first time: the root updater frees space
/// (`generation_update.make_room`) and asks again.
#[derive(Debug, thiserror::Error)]
#[error("insufficient_store_space: the update needs {required_available_bytes} bytes free")]
pub struct InsufficientSpace {
    /// What must be free before the verifier starts again from nothing.
    pub required_available_bytes: u64,
}

/// Installation: the extracted cache and the closure fit and leave the
/// Nest's free-space floor.
/// The installer has no configuration to load: it writes the Nest's own
/// (`provisioning::storage::nest_config`) without a build size, so the
/// default is the floor the installed Nest keeps.
pub fn ensure_space(path: &Path, temporary_and_missing: u64) -> Result<()> {
    let floor = crate::disk::free_space_floor(&crate::config::BuildConfig::default());
    let required = temporary_and_missing
        .checked_add(floor)
        .ok_or_else(|| anyhow!("space admission overflow"))?;
    ensure!(
        crate::disk::stats(path)?.available_bytes >= required,
        "insufficient space for the closure and the Nest's free-space floor"
    );
    Ok(())
}

/// The NAR bytes of the store paths the store does not hold yet.
/// Conservative accounting never counts protected/shared paths as
/// reclaimable; a path already there, such as the running predecessor's, is
/// not charged twice.
fn missing_nar_bytes(manifest: &closure::ClosureManifest) -> Result<u64> {
    manifest
        .store_paths
        .iter()
        .filter(|path| !Path::new(&path.path).exists())
        .try_fold(0u64, |total, path| {
            total
                .checked_add(path.nar_size)
                .ok_or_else(|| anyhow!("missing path size overflow"))
        })
}

fn validate_directory(path: &Path, owner: u32, mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o777 == mode,
        "unsafe appliance update staging directory"
    );
    Ok(())
}

/// Whether an update fits: its staging files, the store paths it still
/// misses, and after them the Nest's free-space floor. Too little room for
/// the store is [`InsufficientSpace`], with what must be free there.
fn admit_update_space(
    same_filesystem: bool,
    staging_free: u64,
    store_free: u64,
    temporary: u64,
    missing: u64,
    floor: u64,
) -> Result<()> {
    let mut store_required = missing
        .checked_add(floor)
        .ok_or_else(|| anyhow!("store space overflow"))?;
    if same_filesystem {
        store_required = temporary
            .checked_add(store_required)
            .ok_or_else(|| anyhow!("staging space overflow"))?;
    } else {
        let staging_required = temporary
            .checked_add(2 * 1024 * 1024 * 1024)
            .ok_or_else(|| anyhow!("staging space overflow"))?;
        ensure!(
            staging_free >= staging_required,
            "insufficient appliance cache staging space"
        );
    }
    if store_free < store_required {
        return Err(InsufficientSpace {
            required_available_bytes: store_required,
        }
        .into());
    }
    Ok(())
}

fn ensure_update_space(
    staging: &Path,
    store: &Path,
    temporary: u64,
    missing: u64,
    floor: u64,
) -> Result<()> {
    admit_update_space(
        fs::metadata(staging)?.dev() == fs::metadata(store)?.dev(),
        crate::disk::stats(staging)?.available_bytes,
        crate::disk::stats(store)?.available_bytes,
        temporary,
        missing,
        floor,
    )
}

/// Root's admission of the staged update. `floor` is the Nest's free-space
/// floor (`crate::disk::free_space_floor`), which the update must leave.
/// Short of disk space this changes nothing and returns [`InsufficientSpace`]
/// so the caller can free space and ask again; once `space_freed` says it
/// did, too little space ends the attempt with `insufficient_store_space`.
pub fn verify_update(floor: u64, space_freed: bool) -> Result<PathBuf> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "root verification required"
    );
    let body = crate::provisioning::read_bounded_nofollow(
        Path::new(super::UPDATE_REQUEST_PATH),
        256 * 1024,
        "NixOS update inbox",
    )?;
    let request: StoredUpdate = serde_json::from_value(release_v3::strict_json(&body)?)?;
    ensure!(
        request.schema == "tiaris.nest.appliance-update-request.v3" && !request.attempt_id.is_nil(),
        "update inbox schema/attempt"
    );
    let key = request
        .release
        .verify_file(Path::new(super::RELEASE_PUBLIC_KEY_PATH))?;
    let verified_result = (|| -> Result<PathBuf> {
        let current = read_installed()?;
        newer(&request.release, &current.release)?;
        ensure!(
            fs::canonicalize("/run/current-system")?.to_str()
                == Some(current.system_toplevel.as_str()),
            "running system differs from source receipt"
        );
        validate_migrations(&current.release, &request.release)?;
        validate_directory(Path::new(UPDATE_CACHE_ROOT), 0, 0o755)?;
        validate_directory(Path::new(UPDATE_BUNDLE_ROOT), 985, 0o700)?;
        validate_directory(Path::new(UPDATE_PRIVATE_ROOT), 0, 0o700)?;
        let canonical = archive_bundle(request.attempt_id);
        let staged = members_bundle(request.attempt_id);
        let by_store_path = Path::new(&request.bundle_path) == staged;
        ensure!(
            by_store_path || Path::new(&request.bundle_path) == canonical,
            "noncanonical update archive path"
        );
        fs::create_dir_all(super::UPDATE_ROOT)?;
        let parent = fs::symlink_metadata(super::UPDATE_ROOT)?;
        ensure!(
            parent.is_dir() && parent.uid() == 0 && parent.mode() & 0o022 == 0,
            "unsafe private updater root"
        );
        for receipt in [
            "pending-system-generation.json",
            "system-prepare-intent.json",
            "system-commit-intent.json",
            "system-rollback-intent.json",
        ] {
            ensure!(
                !Path::new("/var/lib/tiaris-nest/control")
                    .join(receipt)
                    .exists(),
                "pending update transaction blocks verifier"
            );
        }
        let private = Path::new(UPDATE_PRIVATE_ROOT).join(request.attempt_id.to_string());
        let receipt_directory = Path::new(super::UPDATE_ROOT).join(request.attempt_id.to_string());
        for directory in [&private, &receipt_directory] {
            if fs::symlink_metadata(directory).is_ok() {
                validate_directory(directory, 0, 0o700)?;
                fs::remove_dir_all(directory)?;
            }
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let result = (|| {
            let cache = private.join("cache");
            let (total_nar_bytes, missing) = if by_store_path {
                verify_staged_update(&request.release, &key, &staged, &private, &cache, floor)?
            } else {
                verify_archive_update(&request.release, &key, &canonical, &private, &cache, floor)?
            };
            let database_backup = snapshot_database(&private)?;
            super::write_atomic_json(
                &receipt_directory.join("verified-update.json"),
                &json!({
                    "schema":"tiaris.nest.verified-appliance-update.v3","attempt_id":request.attempt_id,"request_sha256":hex::encode(Sha256::digest(&body)),
                    "descriptor_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&super::canonical_json(serde_json::to_value(&request.release)?))?)),
                    "target_release":request.release.release_id,"source_revision":request.release.source_revision,"system_closure_sha256":request.release.system_closure.sha256,
                    "system_closure_size_bytes":request.release.system_closure.size_bytes,"system_toplevel":request.release.system_toplevel,"sqlite_migrations_sha256":request.release.sqlite_migrations_sha256,
                    "total_nar_bytes":total_nar_bytes,"missing_nar_bytes":missing,"cache_path":cache,"database_backup":database_backup,"release":request.release,"source_system_generation":current.system_generation,"source_system_toplevel":current.system_toplevel,
                }),
                0o600,
            )?;
            Ok(cache)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&private);
            let _ = fs::remove_dir_all(&receipt_directory);
        }
        result
    })();
    if let Err(error) = &verified_result {
        let short_of_space = error.downcast_ref::<InsufficientSpace>().is_some();
        if short_of_space && !space_freed {
            // Not the end of the attempt: the request and its archive stay.
            return verified_result;
        }
        let pending = [
            "pending-system-generation.json",
            "system-prepare-intent.json",
            "system-commit-intent.json",
            "system-rollback-intent.json",
        ]
        .iter()
        .any(|name| {
            Path::new("/var/lib/tiaris-nest/control")
                .join(name)
                .exists()
        });
        if !pending {
            let reason = if short_of_space {
                "insufficient_store_space"
            } else if error.to_string().contains("rollback_database_incompatible") {
                "rollback_database_incompatible"
            } else {
                "appliance_update_verification_failed"
            };
            let mut status = json!({"attempt_id":request.attempt_id,"target_release":request.release.release_id,"source_revision":request.release.source_revision,"system_closure_sha256":request.release.system_closure.sha256,"system_toplevel":request.release.system_toplevel,"status":"failed","stage":"verification_failed","rollback_reason":reason,"progress_percent":0,"reported_at":Utc::now()});
            if let Ok(source) = read_installed() {
                status["resulting_system_generation"] = source.system_generation.into();
            }
            match super::write_atomic_json(Path::new(super::UPDATE_STATUS_PATH), &status, 0o640) {
                Err(write_error) => {
                    tracing::error!(%write_error,"could not persist authenticated update verification failure")
                }
                Ok(()) => {
                    if let Err(cleanup_error) = cleanup_failed_request(
                        Path::new(super::UPDATE_REQUEST_PATH),
                        &body,
                        &[
                            archive_bundle(request.attempt_id),
                            members_bundle(request.attempt_id),
                        ],
                    ) {
                        tracing::error!(%cleanup_error,"could not clean terminal update request");
                    }
                }
            }
        }
    }
    verified_result
}

/// The archive's update: root's private copy, hashed while it is copied,
/// then its one verification pass. Returns the closure's NAR bytes and the
/// NAR bytes the store misses.
fn verify_archive_update(
    release: &NixosRelease,
    key: &ed25519_dalek::VerifyingKey,
    inbox: &Path,
    private: &Path,
    cache: &Path,
    floor: u64,
) -> Result<(u64, u64)> {
    let archive_bytes = release.system_closure.size_bytes;
    let store = Path::new("/nix/store");
    // The private copy first. What the update needs beyond it, its
    // extracted cache and the store paths it misses, the archive's own
    // manifest and NARInfos say: the verification pass admits it before it
    // writes a payload.
    ensure_update_space(private, store, archive_bytes, 0, floor)?;
    let archive = private.join("closure.tar.zst");
    let pinned = super::pin_untrusted_bundle(inbox, &archive, release)?;
    let mut missing = 0u64;
    let verified = closure::verify_archive(
        pinned,
        release,
        key,
        Some(cache),
        |manifest, cache_bytes| {
            missing = missing_nar_bytes(manifest)?;
            let staging = cache_bytes
                .checked_add(DATABASE_BACKUP_RESERVE)
                .ok_or_else(|| anyhow!("staging size overflow"))?;
            ensure_update_space(private, store, staging, missing, floor).map_err(|error| {
                match error.downcast::<InsufficientSpace>() {
                    // A new start copies the archive again.
                    Ok(short) => InsufficientSpace {
                        required_available_bytes: short
                            .required_available_bytes
                            .saturating_add(archive_bytes),
                    }
                    .into(),
                    Err(error) => error,
                }
            })
        },
    )?;
    let total_nar_bytes = verified.manifest.total_nar_bytes;
    // The import reads the extracted cache; the private copy is done.
    drop(verified);
    fs::remove_file(&archive)?;
    Ok((total_nar_bytes, missing))
}

/// The update by store path (`members::stage`): the daemon's staged stream,
/// read once from the inbox and verified as it is copied into the private
/// cache. The members it leaves out are the running system's, each with its
/// signed NAR hash; the import adds the others.
fn verify_staged_update(
    release: &NixosRelease,
    key: &ed25519_dalek::VerifyingKey,
    staged: &Path,
    private: &Path,
    cache: &Path,
    floor: u64,
) -> Result<(u64, u64)> {
    let store = Path::new("/nix/store");
    let present = members::running_system()?;
    let (stream, limit) = members::open_staged(staged, release)?;
    let verified = closure::verify_staged(
        stream,
        limit,
        release,
        key,
        cache,
        &present,
        |_, cache_bytes, missing| {
            let staging = cache_bytes
                .checked_add(DATABASE_BACKUP_RESERVE)
                .ok_or_else(|| anyhow!("staging size overflow"))?;
            ensure_update_space(private, store, staging, missing, floor)
        },
    )?;
    Ok((
        verified.manifest.total_nar_bytes,
        verified.missing_nar_bytes,
    ))
}

fn cleanup_failed_request(request: &Path, original: &[u8], bundles: &[PathBuf]) -> Result<bool> {
    let current =
        crate::provisioning::read_bounded_nofollow(request, 256 * 1024, "terminal update request")?;
    if current != original {
        return Ok(false);
    }
    // Only the canonical per-attempt basenames are removed, never a caller
    // path. Unlink does not follow an untrusted symlink at that basename.
    for bundle in bundles {
        match fs::remove_file(bundle) {
            Ok(()) => {
                super::sync_directory(bundle.parent().ok_or_else(|| anyhow!("bundle parent"))?)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    fs::remove_file(request)?;
    super::sync_directory(request.parent().ok_or_else(|| anyhow!("request parent"))?)?;
    Ok(true)
}

/// The installed inventory must be exact and the live history must start with
/// it. Newer rows may follow only as declared expansions a rolled-back
/// candidate left; the snapshot check (`verify_database`) proves their
/// declarations. A candidate with another inventory is admitted here only to
/// be rehearsed: the root updater migrates a copy with the candidate and opens
/// it with this release before preparing anything (`generation_update.py`).
fn validate_migrations(source: &NixosRelease, _candidate: &NixosRelease) -> Result<()> {
    let bytes = crate::provisioning::read_bounded_nofollow(
        Path::new(MIGRATIONS_PATH),
        16 * 1024 * 1024,
        "migration inventory",
    )?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == source.sqlite_migrations_sha256,
        "rollback_database_incompatible: installed inventory digest"
    );
    let inventory = release_v3::strict_json(&bytes)?;
    ensure!(
        inventory["schema"] == "tiaris.nest.sqlite-migrations.v1",
        "migration inventory schema"
    );
    let output=std::process::Command::new("sqlite3").args(["-readonly","-json","/var/lib/tiaris-nest/state/agent/tiaris-nest.sqlite","SELECT version, lower(hex(checksum)) AS sqlx_checksum, success FROM _sqlx_migrations ORDER BY version LIMIT 4097;"]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 16 * 1024 * 1024,
        "rollback_database_incompatible: live SQLite inventory"
    );
    let live: Vec<Value> = serde_json::from_slice(&output.stdout)?;
    let expected = inventory["migrations"]
        .as_array()
        .ok_or_else(|| anyhow!("migration inventory missing"))?;
    live_history_admissible(&live, expected)
}

fn live_history_admissible(live: &[Value], expected: &[Value]) -> Result<()> {
    ensure!(
        live.len() >= expected.len(),
        "rollback_database_incompatible: migration count"
    );
    for (row, entry) in live.iter().zip(expected) {
        ensure!(
            row["version"] == entry["version"]
                && row["sqlx_checksum"] == entry["sqlx_checksum"]
                && row["success"] == 1,
            "rollback_database_incompatible: live migration mismatch"
        );
    }
    let newest = expected
        .last()
        .and_then(|entry| entry["version"].as_i64())
        .unwrap_or(0);
    for row in &live[expected.len()..] {
        ensure!(
            row["version"]
                .as_i64()
                .is_some_and(|version| version > newest)
                && row["success"] == 1,
            "rollback_database_incompatible: unexpected live migration"
        );
    }
    Ok(())
}

pub async fn report(state: &crate::AppState) -> Result<super::ApplianceReport> {
    let actual = fs::canonicalize("/run/current-system")?;
    let actual_generation = booted_generation(&actual)?;
    let mut installed = read_installed()?;
    if actual.to_str() != Some(installed.system_toplevel.as_str()) {
        let pending_path = Path::new("/var/lib/tiaris-nest/control/pending-system-generation.json");
        let pending = if pending_path.exists() {
            let bytes = crate::provisioning::read_bounded_nofollow(
                pending_path,
                512 * 1024,
                "pending NixOS generation",
            )?;
            let pending = release_v3::strict_json(&bytes)?;
            ensure!(
                pending["schema"] == "tiaris.nest.pending-system-generation.v3"
                    && pending["system_toplevel"].as_str() == actual.to_str()
                    && pending["candidate_generation"] == actual_generation,
                "booted candidate differs from protected pending seal"
            );
            pending
        } else {
            // A manual boot of a retained good generation is reported truthfully
            // without reinterpreting an already committed update as rollback.
            let bytes = crate::provisioning::read_bounded_nofollow(
                Path::new("/var/lib/tiaris-nest/control/known-good-system.json"),
                1024 * 1024,
                "known-good NixOS generations",
            )?;
            let known = release_v3::strict_json(&bytes)?;
            ensure!(
                known["schema"] == "tiaris.nest.known-good-system.v3",
                "known-good schema"
            );
            known["generations"]
                .as_array()
                .and_then(|rows| {
                    rows.iter().find(|row| {
                        row["system_generation"] == actual_generation
                            && row["system_toplevel"].as_str() == actual.to_str()
                    })
                })
                .cloned()
                .ok_or_else(|| {
                    anyhow!("booted system is neither installed, pending, nor retained known-good")
                })?
        };
        let candidate: NixosRelease = serde_json::from_value(pending["release"].clone())?;
        candidate.verify_file(Path::new(super::RELEASE_PUBLIC_KEY_PATH))?;
        ensure!(
            candidate.system_toplevel == pending["system_toplevel"]
                && candidate.system_closure.sha256 == pending["system_closure_sha256"],
            "candidate release differs from protected seal"
        );
        installed.system_toplevel = candidate.system_toplevel.clone();
        installed.system_closure_sha256 = candidate.system_closure.sha256.clone();
        installed.system_generation = actual_generation.clone();
        installed.release = candidate;
    }
    ensure!(
        installed.system_generation == actual_generation,
        "booted system generation differs from protected receipt"
    );
    let release = &installed.release;
    let identity = release_v3::strict_json(&crate::provisioning::read_bounded_nofollow(
        Path::new(IDENTITY_PATH),
        64 * 1024,
        "booted system identity",
    )?)?;
    for (field, expected) in [
        ("release_id", &release.release_id),
        ("base_os", &release.base_os),
        ("base_os_version", &release.base_os_version),
        ("source_revision", &release.source_revision),
        ("manage_source_revision", &release.manage_source_revision),
        ("nixpkgs_revision", &release.nixpkgs_revision),
    ] {
        ensure!(
            identity[field].as_str() == Some(expected),
            "immutable system identity differs from signed booted release"
        );
    }
    ensure!(
        identity["required_system_versions"]
            == serde_json::to_value(&release.required_system_versions)?
            && identity["manage_origin"] == crate::provisioning::REQUIRED_MANAGE_ORIGIN,
        "immutable system version/origin mismatch"
    );
    let mut fields = BTreeMap::new();
    for (k, v) in [
        ("nixpkgs_revision", json!(release.nixpkgs_revision)),
        ("system_toplevel", json!(installed.system_toplevel)),
        ("system_generation", json!(installed.system_generation)),
        (
            "system_closure_sha256",
            json!(installed.system_closure_sha256),
        ),
        (
            "sqlite_migrations_sha256",
            json!(release.sqlite_migrations_sha256),
        ),
        ("state_schema", json!(3)),
        (
            "systemd_boot_version",
            json!(systemd_version(
                &super::command_text("bootctl", &["--version"]).await
            )?),
        ),
    ] {
        fields.insert(k.to_string(), v);
    }
    let network = json!({"interfaces":super::command_json("ip",&["-j","address","show"]).await,"network_fallback_active":crate::provisioning::network_fallback_active().unwrap_or(true)});
    Ok(super::ApplianceReport {
        base_os: "nixos".into(),
        base_os_version: release.base_os_version.clone(),
        appliance_release: release.release_id.clone(),
        kernel_version: super::command_text("uname", &["-r"]).await,
        secure_boot: observed_secure_boot(),
        boot_mode: if Path::new("/sys/firmware/efi").is_dir() {
            "uefi"
        } else {
            "legacy"
        }
        .into(),
        firmware_version: nonempty(super::read_trimmed("/sys/class/dmi/id/bios_version")),
        microcode_version: nonempty(super::microcode_version()),
        nix_version: super::command_text("nix", &["--version"]).await,
        at_rest_protection: "none".into(),
        network,
        package_update: super::read_optional_bounded_json(
            Path::new(super::UPDATE_STATUS_PATH),
            128 * 1024,
        )
        .unwrap_or_else(|| json!({"status":"idle"})),
        local_health: super::local_health(crate::readiness::probe(state).await).await,
        nixos: fields,
    })
}
use std::collections::BTreeMap;
fn systemd_version(output: &str) -> Result<String> {
    let mut words = output.lines().next().unwrap_or_default().split_whitespace();
    ensure!(
        words.next() == Some("systemd"),
        "unknown bootctl version output"
    );
    let major = words
        .next()
        .ok_or_else(|| anyhow!("missing bootctl version"))?;
    let numeric = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && value
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    };
    ensure!(numeric(major), "invalid bootctl version");
    if let Some(package) = words
        .next()
        .and_then(|word| word.strip_prefix('('))
        .and_then(|word| word.strip_suffix(')'))
    {
        if numeric(package) {
            return Ok(package.to_owned());
        }
    }
    Ok(major.to_owned())
}
fn nonempty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}
fn observed_secure_boot() -> Option<bool> {
    let path =
        Path::new("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    let bytes = fs::read(path).ok()?;
    if bytes.len() == 5 {
        match bytes[4] {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    } else {
        None
    }
}
pub fn record_manage_contact(device_id: &str, fingerprint: &str, origin: &str) -> Result<()> {
    if !is_nixos() {
        return Ok(());
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    super::write_atomic_json(
        Path::new("/var/lib/tiaris-nest/state/agent/manage-contact.json"),
        &json!({"schema":"tiaris.nest.manage-contact.v1","device_id":device_id,"public_key_fingerprint":fingerprint,"manage_origin":origin,"reported_at":Utc::now(),"boot_id":boot_id.trim()}),
        0o600,
    )
}

fn booted_generation(actual: &Path) -> Result<String> {
    let body = fs::read(
        "/sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f",
    )?;
    ensure!(
        body.len() >= 6 && body.len() <= 1024 && (body.len() - 4) % 2 == 0,
        "invalid selected loader entry variable"
    );
    let utf16: Vec<u16> = body[4..]
        .chunks_exact(2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .take_while(|v| *v != 0)
        .collect();
    let entry = String::from_utf16(&utf16)?;
    let value = entry
        .strip_prefix("nixos-generation-")
        .and_then(|s| s.strip_suffix(".conf"))
        .ok_or_else(|| anyhow!("selected loader entry is not an installed generation"))?;
    generation(value)?;
    ensure!(
        fs::canonicalize(format!("/nix/var/nix/profiles/system-{value}-link"))? == actual,
        "selected loader generation differs from booted toplevel"
    );
    Ok(value.to_string())
}

fn snapshot_database(private: &Path) -> Result<PathBuf> {
    let database = "/var/lib/tiaris-nest/state/agent/tiaris-nest.sqlite";
    let output = std::process::Command::new("timeout")
        .args([
            "60",
            "sqlite3",
            "-readonly",
            database,
            "PRAGMA page_count; PRAGMA page_size;",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 128,
        "cannot measure consistent database backup"
    );
    let values = String::from_utf8(output.stdout)?
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        values.len() == 2
            && values[0]
                .checked_mul(values[1])
                .is_some_and(|n| n <= 1024 * 1024 * 1024),
        "database backup exceeds 1 GiB admission bound"
    );
    let backup = private.join("database-compatibility.sqlite");
    let command = format!(".backup {}", backup.display());
    let output = std::process::Command::new("timeout")
        .args(["60", "sqlite3", "-readonly", database, &command])
        .output()?;
    ensure!(output.status.success(), "consistent database backup failed");
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o600))?;
    let output = std::process::Command::new("timeout")
        .args([
            "60",
            "/run/current-system/sw/bin/tiaris-nest",
            "verify-appliance-database",
            "--database",
        ])
        .arg(&backup)
        .output()?;
    ensure!(
        output.status.success(),
        "rollback_database_incompatible: predecessor cannot open backup"
    );
    Ok(backup)
}

fn check_snapshot(path: &Path) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "database compatibility verification requires root"
    );
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= 1024 * 1024 * 1024,
        "unsafe database compatibility snapshot"
    );
    Ok(())
}

/// Invoked from both the predecessor and imported candidate binaries on one
/// private SQLite snapshot; never migrates or restores the live appliance DB.
/// Without `rollback_target`: this release can start on the snapshot (its
/// history is a prefix of ours, or ours plus newer declared expansions).
/// With it: this release, as the rollback target, still runs on a database
/// the candidate migrated (`crate::schema_evolution`).
pub async fn verify_database(path: &Path, rollback_target: bool) -> Result<()> {
    check_snapshot(path)?;
    if rollback_target {
        crate::schema_evolution::verify_rollback_target(path).await?;
    } else {
        crate::schema_evolution::verify_openable(path).await?;
    }
    Ok(())
}

/// Candidate side of a schema-changing update: migrate a private copy of the
/// root snapshot, as this release's first boot would migrate the live DB.
pub async fn rehearse_database(path: &Path, output: &Path) -> Result<()> {
    check_snapshot(path)?;
    let parent = fs::symlink_metadata(
        output
            .parent()
            .ok_or_else(|| anyhow!("rehearsal output has no directory"))?,
    )?;
    ensure!(
        parent.is_dir() && parent.uid() == 0 && parent.mode() & 0o077 == 0,
        "unsafe database rehearsal directory"
    );
    crate::schema_evolution::rehearse(path, output).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::release_v3::SystemClosure;
    use super::*;
    use std::collections::BTreeMap;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn a_room_request_names_the_attempt_and_what_must_be_free() {
        let release = closure_fixture(b"closure");
        let update = crate::appliance::ManagedApplianceUpdate {
            attempt_id: Uuid::from_u128(7),
            requested_at: Utc::now(),
            release: release.clone(),
            qualification_package_transport_url: None,
        };
        // What root reads from it (`generation_update.make_download_room`).
        // An earlier try left all but 3 bytes.
        let request = room_request(&update, 3);
        assert_eq!(request["attempt_id"], update.attempt_id.to_string());
        assert_eq!(request["release"]["release_id"], release.release_id);
        assert_eq!(
            request["release"]["source_revision"],
            release.source_revision
        );
        assert_eq!(
            request["release"]["system_toplevel"],
            release.system_toplevel
        );
        assert_eq!(
            request["release"]["system_closure"]["sha256"],
            release.system_closure.sha256
        );
        assert_eq!(
            request["required_available_bytes"],
            3 + crate::disk::DISK_HEADROOM_BYTES
        );
    }

    fn closure_fixture(body: &[u8]) -> NixosRelease {
        NixosRelease {
            schema: release_v3::SCHEMA.into(),
            release_id: "0.2.30".into(),
            source_revision: "a".repeat(40),
            base_os: "nixos".into(),
            base_os_version: "26.05".into(),
            nixpkgs_revision: "c".repeat(40),
            manage_source_revision: "b".repeat(40),
            system_toplevel: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system".into(),
            system_closure: SystemClosure {
                url: "https://github.com/CybexHQ/james/releases/download/v0.2.30/cybex-james-appliance-closure-0.2.30-x86_64-linux.tar.zst".into(),
                sha256: hex::encode(Sha256::digest(body)),
                size_bytes: body.len() as u64,
            },
            required_system_versions: BTreeMap::new(),
            sqlite_migrations_sha256: "c".repeat(64),
            minimum_protocol: 4,
            minimum_state_schema: 3,
            rollback_compatible: true,
            release_notes: "https://github.com/CybexHQ/james/releases/tag/v0.2.30".into(),
            signature: String::new(),
        }
    }

    async fn one_response(listener: TcpListener, response: Vec<u8>) -> String {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let read = stream.read(&mut request).await.unwrap();
        stream.write_all(&response).await.unwrap();
        String::from_utf8_lossy(&request[..read]).into_owned()
    }

    #[tokio::test]
    async fn private_closure_override_does_not_follow_or_accept_redirect() {
        let root = std::env::temp_dir().join(format!("tiaris-private-closure-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let path = root.join("closure.tar.zst");
        let release = closure_fixture(b"expected signed bytes");
        let redirect = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = format!("http://{}/signed", redirect.local_addr().unwrap());
        let response = b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
        let redirect_task = tokio::spawn(one_response(redirect, response));
        let error = download(&release, &transport, &path, true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invalid closure HTTP response"));
        assert!(
            redirect_task
                .await
                .unwrap()
                .starts_with("GET /signed HTTP/1.1")
        );
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn closure_download_rejects_equal_length_tampered_bytes() {
        let root = std::env::temp_dir().join(format!("tiaris-closure-hash-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let path = root.join("closure.tar.zst");
        let release = closure_fixture(b"expected");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = format!("http://{}/signed", listener.local_addr().unwrap());
        let server = tokio::spawn(one_response(
            listener,
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntampered".to_vec(),
        ));
        let error = download(&release, &transport, &path, true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("signed size/hash mismatch"));
        server.await.unwrap();
        // Bytes that are not the archive are not continued either.
        assert!(!path.exists());
        assert!(!partial_path(&path, &release).unwrap().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn a_dropped_closure_download_continues_where_it_stopped() {
        let root = std::env::temp_dir().join(format!("tiaris-closure-resume-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let path = root.join("attempt.tar.zst");
        let body = b"0123456789abcdefghij";
        let release = closure_fixture(body);
        // An earlier try left the first 4 bytes; another archive's partial
        // file and the old downloader's temporary file go.
        fs::write(partial_path(&path, &release).unwrap(), &body[..4]).unwrap();
        fs::set_permissions(
            partial_path(&path, &release).unwrap(),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let stale = [
            root.join(format!("{}.part", "f".repeat(64))),
            root.join(format!("attempt.tar.{}.tmp", Uuid::new_v4())),
        ];
        for file in &stale {
            fs::write(file, b"stale").unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = format!("http://{}/signed", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in [
                // Drops after 6 of the 16 bytes it promised.
                &b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 4-19/20\r\nContent-Length: 16\r\nConnection: close\r\n\r\n456789"[..],
                b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 10-19/20\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabcdefghij",
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4096];
                let read = stream.read(&mut request).await.unwrap();
                requests.push(String::from_utf8_lossy(&request[..read]).to_lowercase());
                stream.write_all(response).await.unwrap();
            }
            requests
        });
        let mut seen = Vec::new();
        let archive = download_resuming(
            &release,
            &transport,
            &path,
            true,
            &mut |received, _| seen.push(received),
            Duration::ZERO,
        )
        .await
        .unwrap();
        let requests = server.await.unwrap();
        assert!(requests[0].contains("range: bytes=4-"));
        assert!(requests[1].contains("range: bytes=10-"));
        assert_eq!((seen[0], *seen.last().unwrap()), (4, 20));
        assert_eq!(fs::read(&path).unwrap(), body);
        assert!(!partial_path(&path, &release).unwrap().exists());
        assert!(stale.iter().all(|file| !file.exists()));
        drop(archive);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_history_may_extend_the_installed_inventory_only_with_newer_rows() {
        let row = |version: i64, checksum: &str, success: i64| json!({"version": version, "sqlx_checksum": checksum, "success": success});
        let installed = [row(1, "aa", 1), row(2, "bb", 1)];
        let installed: Vec<Value> = installed
            .iter()
            .map(|entry| json!({"version": entry["version"], "sqlx_checksum": entry["sqlx_checksum"]}))
            .collect();
        assert!(live_history_admissible(&[row(1, "aa", 1), row(2, "bb", 1)], &installed).is_ok());
        // A rolled-back candidate's declared expansion stays behind.
        assert!(
            live_history_admissible(
                &[row(1, "aa", 1), row(2, "bb", 1), row(3, "cc", 1)],
                &installed
            )
            .is_ok()
        );
        for live in [
            vec![row(1, "aa", 1)],
            vec![row(1, "aa", 1), row(2, "xx", 1)],
            vec![row(1, "aa", 1), row(2, "bb", 0)],
            vec![row(1, "aa", 1), row(2, "bb", 1), row(3, "cc", 0)],
            vec![row(0, "zz", 1), row(1, "aa", 1), row(2, "bb", 1)],
        ] {
            let error = live_history_admissible(&live, &installed).unwrap_err();
            assert!(error.to_string().contains("rollback_database_incompatible"));
        }
    }

    #[test]
    fn bootctl_version_report_is_one_numeric_token() {
        let actual = "systemd 260 (260.2)\n+PAM +AUDIT -SELINUX +APPARMOR +IMA +IPE +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL\n";
        assert_eq!(systemd_version(actual).unwrap(), "260.2");
        assert_eq!(systemd_version("systemd 260\n+PAM").unwrap(), "260");
        assert!(systemd_version("unexpected output\n260").is_err());
        assert!(systemd_version("systemd unknown\n+PAM").is_err());
    }

    #[test]
    fn state_16_gib_does_not_receive_bulk_or_workstation_reserve() {
        assert!(UPDATE_BUNDLE_ROOT.starts_with("/var/cache/tiaris-nest/"));
        assert!(UPDATE_PRIVATE_ROOT.starts_with("/var/cache/tiaris-nest/"));
        assert!(super::super::UPDATE_REQUEST_PATH.starts_with("/var/lib/tiaris-nest/state/"));
        assert!(super::super::UPDATE_ROOT.starts_with("/var/lib/tiaris-nest/control/"));
        // The installed 16 GiB STATE is absent from bulk admission: ROOT backs
        // both cache and /nix. Existing staging bytes are already in free-space.
        let floor = 21 * GIB;
        assert!(admit_update_space(true, 64 * GIB, 64 * GIB, 9 * GIB, 4 * GIB, floor).is_ok());
        assert!(admit_update_space(true, 34 * GIB, 34 * GIB, 9 * GIB, 4 * GIB, floor).is_ok());
        // One byte short says how much must be free, for the updater to free.
        let short = admit_update_space(true, 34 * GIB - 1, 34 * GIB - 1, 9 * GIB, 4 * GIB, floor)
            .unwrap_err();
        assert_eq!(
            short
                .downcast_ref::<InsufficientSpace>()
                .unwrap()
                .required_available_bytes,
            34 * GIB
        );
    }

    #[test]
    fn separate_staging_and_store_are_admitted_independently() {
        let floor = 21 * GIB;
        assert!(admit_update_space(false, 12 * GIB, 25 * GIB, 9 * GIB, 4 * GIB, floor).is_ok());
        assert!(admit_update_space(false, 64 * GIB, 24 * GIB, 9 * GIB, 4 * GIB, floor).is_err());
        assert!(admit_update_space(false, 10 * GIB, 64 * GIB, 9 * GIB, 4 * GIB, floor).is_err());
        assert!(admit_update_space(true, u64::MAX, u64::MAX, u64::MAX, 0, floor).is_err());
    }

    #[test]
    fn authenticated_failure_allows_a_corrected_attempt_without_erasing_changed_inbox() {
        let directory =
            std::env::temp_dir().join(format!("tiaris-update-cleanup-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let request = directory.join("request.json");
        let bundle = directory.join("attempt.tar.zst");
        fs::write(&request, b"old authenticated request").unwrap();
        fs::write(&bundle, b"corrupt bytes").unwrap();
        let bundles = [bundle.clone()];
        assert!(cleanup_failed_request(&request, b"old authenticated request", &bundles).unwrap());
        assert!(!request.exists() && !bundle.exists());
        fs::write(&request, b"corrected new request").unwrap();
        fs::write(&bundle, b"new bytes").unwrap();
        assert!(!cleanup_failed_request(&request, b"old authenticated request", &bundles).unwrap());
        assert_eq!(fs::read(&request).unwrap(), b"corrected new request");
        assert_eq!(fs::read(&bundle).unwrap(), b"new bytes");
        fs::remove_dir_all(directory).unwrap();
    }
}
