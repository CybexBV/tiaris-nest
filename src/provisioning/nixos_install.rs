//! Direct NixOS installation of one fully authenticated offline closure.
use super::{
    DurableProvisioningState, SignedInstallPlan,
    setup_status::{InstallStep, SetupStatusReporter},
    storage::{self, PreparedStorage},
};
use crate::appliance::{
    ApplianceRepositorySnapshot, closure, members, nixos,
    release_v3::{NixosRelease, SystemClosure},
    validate_qualification_package_transport_url,
};
use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use std::{
    fs::{self, File},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};
const GIB: u64 = 1024 * 1024 * 1024;
const STAGING: &str = "/run/tiaris-appliance-closure";
pub(super) const ARCHIVE: &str = "/run/tiaris-appliance-closure/closure.tar.zst";
/// The members the ISO lacks (`members::stage`), and their verified cache.
const STAGED_MEMBERS: &str = "/run/tiaris-appliance-closure/closure.members.tar";
const MEMBERS_CACHE: &str = "/run/tiaris-appliance-closure/cache";
pub(super) const TARGET: &str = "/mnt";

/// The approved closure, verified before anything touches the disk.
pub(super) enum StagedClosure {
    /// The whole archive, extracted onto the disk at install.
    Archive(closure::VerifiedArchive),
    /// The members the ISO's own store lacks, verified and extracted into
    /// RAM, and the members the ISO carries with their signed NAR hash
    /// (`members::plan_install`: 571 of 1149, 1,186 of 1,727 MiB for
    /// 0.2.182-dev.1), copied from it with their closures.
    Members {
        manifest: closure::ClosureManifest,
        iso: closure::Present,
    },
}

/// What the ISO fetched while the administrator reviewed the setup
/// (`closure_prefetch`).
pub(super) enum Prefetched {
    /// The whole archive, hashed while it downloaded.
    Archive(closure::AuthenticatedArchive),
    /// The members the ISO lacks, staged ([`stage_members`]).
    Members(members::Plan),
}

fn release(plan: &SignedInstallPlan) -> Result<&NixosRelease> {
    let release = plan
        .appliance_release
        .as_ref()
        .ok_or_else(|| anyhow!("NixOS plan missing closure"))?
        .nixos()?;
    ensure!(
        release.release_id == plan.release_version,
        "plan release identity mismatch"
    );
    Ok(release)
}

pub(super) fn validate_closure_transport(transport: &str, artifact: &SystemClosure) -> Result<()> {
    if transport == artifact.url {
        return Ok(());
    }
    // The signed plan may select the same bounded private bridge accepted by
    // Tiaris qualification and appliance updates. It changes only transport:
    // the independently signed closure identity and NAR checks still apply.
    validate_qualification_package_transport_url(
        transport,
        &ApplianceRepositorySnapshot {
            url: artifact.url.clone(),
            sha256: artifact.sha256.clone(),
            size_bytes: artifact.size_bytes,
        },
    )
}

/// Download (or find) the signed closure in RAM and verify it: its one
/// verification pass, before anything touches the disk. Only the members the
/// ISO's own store lacks when the archive allows it ([`stage_members`]),
/// else the whole archive, which stays open for [`install`] to extract onto
/// the disk. `prefetched` is what the ISO fetched for this release while
/// the administrator reviewed the setup (`closure_prefetch`).
pub(super) async fn stage_closure(
    plan: &SignedInstallPlan,
    key_path: &Path,
    status: &SetupStatusReporter,
    prefetched: Option<Prefetched>,
) -> Result<StagedClosure> {
    let release = release(plan)?;
    let key = release.verify_file(key_path)?;
    let transport = plan
        .package_transport_url
        .as_deref()
        .ok_or_else(|| anyhow!("plan missing transport"))?;
    validate_closure_transport(transport, &release.system_closure)?;
    let available = ram_staging()?;
    match prefetched {
        Some(Prefetched::Archive(prefetched)) => {
            ensure!(
                prefetched.sha256() == release.system_closure.sha256,
                "prefetched closure is not the approved release"
            );
            status.step(InstallStep::VerifyRelease);
            return closure::verify_archive(prefetched, release, &key, None, |_, _| Ok(()))
                .map(StagedClosure::Archive);
        }
        Some(Prefetched::Members(members)) => {
            status.step(InstallStep::VerifyRelease);
            return verify_members(release, &key, &members);
        }
        None => {}
    }
    let archive = Path::new(ARCHIVE);
    // A previous run's archive is not a trust receipt. Hash and verify the
    // same open file's entire contents before reusing it, while charging
    // resident RAM.
    if fs::symlink_metadata(archive).is_ok() {
        status.step(InstallStep::VerifyRelease);
        if available >= 2 * GIB {
            let found = closure::AuthenticatedArchive::open(archive, release).and_then(|found| {
                closure::verify_archive(found, release, &key, None, |_, _| Ok(()))
            });
            if let Ok(verified) = found {
                return Ok(StagedClosure::Archive(verified));
            }
        }
        status.step(InstallStep::StageRelease);
        fs::remove_file(archive)?;
    }
    if let Some(members) = stage_members(release, &key, transport, available).await? {
        status.step(InstallStep::VerifyRelease);
        return verify_members(release, &key, &members);
    }
    ensure_ram_budget(release, available)?;
    let downloaded = nixos::download_with_progress(
        release,
        transport,
        archive,
        transport != release.system_closure.url,
        &mut |received, total| status.download_progress(received, total),
    )
    .await?;
    status.step(InstallStep::VerifyRelease);
    closure::verify_archive(downloaded, release, &key, None, |_, _| Ok(()))
        .map(StagedClosure::Archive)
}

/// Fetch into RAM only the members the ISO's own store lacks, when the
/// archive is stored in raw blocks and the server answers ranges. `None`
/// takes the whole archive; a download that keeps dropping is an error
/// (the next try continues it).
pub(super) async fn stage_members(
    release: &NixosRelease,
    key: &ed25519_dalek::VerifyingKey,
    transport: &str,
    available: u64,
) -> Result<Option<members::Plan>> {
    let whole = |error: anyhow::Error| {
        if error.is::<members::KeepTrying>() {
            return Err(error);
        }
        tracing::warn!(error = %format!("{error:#}"), "setup takes the whole closure archive");
        // Its RAM goes to the archive.
        let _ = fs::remove_file(members::partial_path(Path::new(STAGING), release));
        Ok(None)
    };
    let present = match members::local_store_async().await {
        Ok(present) => present,
        Err(error) => return whole(error),
    };
    let allow_private = transport != release.system_closure.url;
    let plan = match members::plan_install(
        release,
        key,
        transport,
        allow_private,
        Path::new(STAGING),
        &present,
    )
    .await
    {
        Ok(Some(plan)) => plan,
        Ok(None) => return Ok(None),
        Err(error) => return whole(error),
    };
    // Members and their cache take twice their bytes in RAM; when they do
    // not fit, the whole archive (once in RAM, extracted onto the disk) may.
    let staged = plan.bytes - plan.remaining_bytes();
    let tmpfs = crate::disk::stats(Path::new(STAGING)).map_or(0, |stats| stats.available_bytes);
    if !members_fit(plan.bytes, staged, available, tmpfs) {
        return whole(anyhow!(
            "insufficient available memory for the closure members plus bounded runtime"
        ));
    }
    tracing::info!(
        members = plan.members(),
        bytes = plan.bytes,
        reused = plan.present().len(),
        "setup fetches only the closure members this ISO does not carry"
    );
    match members::stage(&plan, Path::new(STAGED_MEMBERS)).await {
        Ok(()) => Ok(Some(plan)),
        Err(error) => whole(error),
    }
}

/// Whether `bytes` of staged members (`staged` of them there already) and
/// their extracted cache fit: in memory beside a bounded runtime, and in the
/// tmpfs that holds them (`/run`, often smaller than the memory).
fn members_fit(bytes: u64, staged: u64, available: u64, tmpfs_available: u64) -> bool {
    let needed = bytes.saturating_mul(2);
    available.saturating_add(staged) >= needed.saturating_add(2 * GIB)
        && tmpfs_available.saturating_add(staged) >= needed
}

/// The staged members' one verification pass, extracting their binary cache
/// into RAM; the members it leaves out are the ISO's, each with its signed
/// NAR hash.
fn verify_members(
    release: &NixosRelease,
    key: &ed25519_dalek::VerifyingKey,
    members: &members::Plan,
) -> Result<StagedClosure> {
    let manifest = verify_staged_members(
        release,
        key,
        members.present(),
        Path::new(STAGED_MEMBERS),
        Path::new(MEMBERS_CACHE),
    )?;
    Ok(StagedClosure::Members {
        manifest,
        iso: members.present().clone(),
    })
}

/// The staged stream goes either way, and so does the cache of a pass that
/// fails: the next try may take the whole archive, which needs that RAM.
fn verify_staged_members(
    release: &NixosRelease,
    key: &ed25519_dalek::VerifyingKey,
    present: &closure::Present,
    staged: &Path,
    cache: &Path,
) -> Result<closure::ClosureManifest> {
    if fs::symlink_metadata(cache).is_ok() {
        fs::remove_dir_all(cache)?;
    }
    let verified = members::open_staged(staged, release).and_then(|(stream, limit)| {
        closure::verify_staged(
            stream,
            limit,
            release,
            key,
            cache,
            present,
            |_, _, _| Ok(()),
        )
    });
    let _ = fs::remove_file(staged);
    if verified.is_err() {
        let _ = fs::remove_dir_all(cache);
    }
    Ok(verified?.manifest)
}

/// Copy the ISO's own members of the closure, with their closures (all
/// left out too: `members::plan_install`), into the target store, checked as
/// the fetched members are: first the release's signatures from the
/// verified NARInfos onto the ISO's paths (Nix takes one only for the same
/// NAR hash, size and references), then a copy that requires the release
/// key and hashes every NAR against its record. The installed store then
/// holds every member signed, as from the archive.
async fn copy_iso_members(iso: &closure::Present, trust: &str) -> Result<()> {
    if iso.is_empty() {
        return Ok(());
    }
    let cache = format!("file://{MEMBERS_CACHE}");
    let mut arguments = vec![
        "--extra-experimental-features",
        "nix-command",
        "store",
        "copy-sigs",
        "--substituter",
        &cache,
    ];
    arguments.extend(iso.keys().map(String::as_str));
    storage::run_checked("nix", &arguments).await?;
    let target = format!("local?root={TARGET}");
    let mut arguments = vec![
        "--extra-experimental-features",
        "nix-command",
        "--option",
        "substituters",
        "",
        "--option",
        "trusted-public-keys",
        trust,
        "copy",
        "--to",
        &target,
    ];
    arguments.extend(iso.keys().map(String::as_str));
    storage::run_checked("nix", &arguments).await
}

/// Make the RAM staging directory safe and return the memory available now.
pub(super) fn ram_staging() -> Result<u64> {
    fs::create_dir_all(STAGING)?;
    let metadata = fs::symlink_metadata(STAGING)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0,
        "unsafe RAM staging directory"
    );
    fs::set_permissions(STAGING, fs::Permissions::from_mode(0o700))?;
    let raw = std::ffi::CString::new(STAGING)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statfs(raw.as_ptr(), &mut stat) } == 0 && stat.f_type == 0x01021994,
        "closure staging must be RAM-backed tmpfs"
    );
    let memory = fs::read_to_string("/proc/meminfo")?;
    memory
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse::<u64>().ok())
        .and_then(|v| v.checked_mul(1024))
        .ok_or_else(|| anyhow!("MemAvailable unavailable"))
}

/// Whether the archive's remaining bytes fit in RAM beside a bounded runtime.
pub(super) fn ensure_ram_budget(release: &NixosRelease, available: u64) -> Result<()> {
    // What a dropped download of this archive left in RAM counts as its own.
    let partial = nixos::partial_bytes(Path::new(ARCHIVE), release);
    ensure!(
        available.saturating_add(partial)
            >= release
                .system_closure
                .size_bytes
                .checked_add(2 * GIB)
                .ok_or_else(|| anyhow!("RAM budget overflow"))?,
        "insufficient available memory for signed closure plus bounded runtime"
    );
    ensure!(
        crate::disk::stats(Path::new(STAGING))?.available_bytes
            >= release.system_closure.size_bytes - partial,
        "insufficient tmpfs capacity"
    );
    Ok(())
}

/// Whether a finished archive already waits in RAM (`stage_closure` verifies it).
pub(super) fn archive_staged() -> bool {
    fs::symlink_metadata(ARCHIVE).is_ok()
}

pub(super) fn calculate_layout(sector: u64, total: u64) -> Result<([u64; 5], [u64; 5])> {
    ensure!(
        matches!(sector, 512 | 4096) && total % sector == 0 && total >= 160 * GIB,
        "unsupported/insufficient disk geometry"
    );
    let alignment = 1024 * 1024 / sector;
    let mut starts = [0; 5];
    let mut ends = [0; 5];
    let mut cursor = alignment;
    for (i, bytes) in [16 * GIB, GIB, 8 * GIB].into_iter().enumerate() {
        starts[i] = cursor;
        ends[i] = cursor
            .checked_add(bytes / sector)
            .and_then(|n| n.checked_sub(1))
            .ok_or_else(|| anyhow!("partition overflow"))?;
        cursor = ends[i]
            .checked_add(1)
            .ok_or_else(|| anyhow!("partition overflow"))?
            .div_ceil(alignment)
            * alignment;
    }
    starts[3] = cursor;
    ends[3] = (total / sector)
        .checked_sub(alignment + 1)
        .ok_or_else(|| anyhow!("GPT capacity"))?;
    let root = ends[3]
        .checked_sub(starts[3])
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(sector))
        .ok_or_else(|| anyhow!("root capacity overflow"))?;
    ensure!(root >= 134 * GIB, "insufficient root capacity");
    Ok((starts, ends))
}
pub(super) async fn create_remaining(prepared: &PreparedStorage) -> Result<()> {
    let disk = prepared
        .disk_path
        .to_str()
        .ok_or_else(|| anyhow!("disk path"))?;
    for (index, kind, label) in [
        (2u8, "ef00", "TIARIS_EFI"),
        (3, "8200", "TIARIS_SWAP"),
        (4, "8300", "TIARIS_ROOT"),
    ] {
        let slot = usize::from(index - 1);
        let start = prepared.partition_starts[slot];
        let end = prepared.partition_ends[slot];
        match storage::inspect_partition(disk, index).await? {
            Some(p) => p.validate(start, end, kind, label)?,
            None => {
                storage::run_checked(
                    "sgdisk",
                    &[
                        &format!("--new={index}:{start}:{end}"),
                        &format!("--typecode={index}:{kind}"),
                        &format!("--change-name={index}:{label}"),
                        disk,
                    ],
                )
                .await?
            }
        }
    }
    storage::settle_partitions(disk).await?;
    Ok(())
}
async fn format_filesystems(
    prepared: &PreparedStorage,
    state: &DurableProvisioningState,
    root: &Path,
    esp: &Path,
    swap: &Path,
) -> Result<()> {
    let marker = prepared.state_mount.join("filesystems-prepared.json");
    let identity = |path: &Path| -> Result<String> {
        let output = Command::new("blkid")
            .args(["-s", "UUID", "-o", "value"])
            .arg(path)
            .output()?;
        ensure!(
            output.status.success() && output.stdout.len() <= 128,
            "target filesystem UUID missing"
        );
        Ok(String::from_utf8(output.stdout)?.trim().into())
    };
    if marker.exists() {
        let body = super::read_bounded_nofollow(&marker, 4096, "prepared target filesystems")?;
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        ensure!(
            value["schema"] == "tiaris.nest.prepared-filesystems.v3"
                && value["plan_sha256"] == state.plan.plan_sha256
                && value["root_uuid"] == identity(root)?
                && value["esp_uuid"] == identity(esp)?
                && value["swap_uuid"] == identity(swap)?,
            "prepared filesystem receipt differs from approved attempt"
        );
        return Ok(());
    }
    // The receipt is created before any import. Without it, restarting this exact
    // approved attempt safely repeats formatting, never adopts an old root/cache.
    for (program, args, partition) in [
        (
            "mkfs.ext4",
            vec!["-F", "-m", "1", "-L", "TIARIS_ROOT"],
            root,
        ),
        ("mkfs.vfat", vec!["-F", "32", "-n", "TIARIS_EFI"], esp),
        ("mkswap", vec!["-L", "TIARIS_SWAP"], swap),
    ] {
        ensure!(
            tokio::process::Command::new(program)
                .args(args)
                .arg(partition)
                .status()
                .await?
                .success(),
            "format target filesystem failed"
        );
    }
    storage::atomic_write(
        &marker,
        &serde_json::to_vec(
            &json!({"schema":"tiaris.nest.prepared-filesystems.v3","plan_sha256":state.plan.plan_sha256,"root_uuid":identity(root)?,"esp_uuid":identity(esp)?,"swap_uuid":identity(swap)?}),
        )?,
        0o600,
    )
}
async fn mount(source: &Path, target: &Path, options: &str) -> Result<()> {
    fs::create_dir_all(target)?;
    let output = Command::new("findmnt")
        .args(["-rn", "-M"])
        .arg(target)
        .args(["-o", "SOURCE"])
        .output()?;
    if output.status.success() {
        if options.starts_with("bind") {
            let from = fs::metadata(source)?;
            let to = fs::metadata(target)?;
            ensure!(
                from.dev() == to.dev() && from.ino() == to.ino(),
                "target bind already points at unrelated directory"
            );
        } else {
            let mounted = String::from_utf8(output.stdout)?;
            ensure!(
                fs::canonicalize(mounted.trim())? == fs::canonicalize(source)?,
                "target mount already bound to unrelated device"
            );
        }
        return Ok(());
    }
    ensure!(
        tokio::process::Command::new("mount")
            .args(["-o", options])
            .arg(source)
            .arg(target)
            .status()
            .await?
            .success(),
        "mount target failed"
    );
    Ok(())
}
/// Install the closure [`stage_closure`] verified onto the prepared disk.
pub(super) async fn install(
    prepared: &PreparedStorage,
    key_path: &Path,
    status: &SetupStatusReporter,
    staged: &mut StagedClosure,
) -> Result<()> {
    let mut state = storage::load_durable_state(&prepared.state_mount)?;
    ensure!(state.identity_active, "permanent identity not yet active");
    let release = release(&state.plan)?.clone();
    let key = release.verify_file(key_path)?;
    let root = storage::partition_path(&prepared.disk_path, 4)?;
    let esp = storage::partition_path(&prepared.disk_path, 2)?;
    let swap = storage::partition_path(&prepared.disk_path, 3)?;
    format_filesystems(prepared, &state, &root, &esp, &swap).await?;
    let target = Path::new(TARGET);
    mount(&root, target, "defaults").await?;
    prepare_installed_layout(target, 0, 0, 985)?;
    mount(&esp, &target.join("boot"), "umask=0077").await?;
    let target_state = target.join("var/lib/tiaris-nest/state");
    mount(&prepared.state_mount, &target_state, "bind,nodev,nosuid").await?;
    let target_nix = target.join("var/cache/tiaris-nest/nix");
    mount(&target_nix, &target.join("nix"), "bind,nodev,nosuid,exec").await?;
    let trust = format!(
        "tiaris-nest-appliance-1:{}",
        super::protocol::standard_base64(key.as_bytes())
    );
    let cache = match staged {
        StagedClosure::Archive(staged) => {
            nixos::ensure_space(
                target,
                staged
                    .manifest
                    .total_nar_bytes
                    .checked_add(staged.cache_bytes)
                    .ok_or_else(|| anyhow!("install space overflow"))?,
            )?;
            let cache = target.join(format!("var/cache/tiaris-nest/.install-{}", state.plan.id));
            if cache.exists() {
                let old = fs::symlink_metadata(&cache)?;
                ensure!(
                    old.is_dir() && old.uid() == 0,
                    "unsafe interrupted installation cache"
                );
                fs::remove_dir_all(&cache)?;
            }
            staged.extract(&release, &key, &cache)?;
            cache
        }
        StagedClosure::Members { manifest, iso } => {
            nixos::ensure_space(target, manifest.total_nar_bytes)?;
            copy_iso_members(iso, &trust).await?;
            PathBuf::from(MEMBERS_CACHE)
        }
    };
    storage::run_checked(
        "nix",
        &[
            "--extra-experimental-features",
            "nix-command",
            "--option",
            "substituters",
            "",
            "--option",
            "trusted-public-keys",
            &trust,
            "copy",
            "--from",
            &format!("file://{}", cache.display()),
            "--to",
            &format!("local?root={TARGET}"),
            &release.system_toplevel,
        ],
    )
    .await?;
    if state.next_event_sequence == 6 {
        super::report_install_stage(
            &prepared.state_mount,
            "installing_packages",
            "succeeded",
            Some(80),
            "Verified NixOS system closure imported",
        )
        .await?;
        state = storage::load_durable_state(&prepared.state_mount)?;
    }
    // STATE exists before activation and contains all runtime trust/config.
    materialize_state(target, &prepared.state_mount, &state, key_path)?;
    run_checked_with_umask(
        "nixos-install",
        &[
            "--root",
            TARGET,
            "--system",
            &release.system_toplevel,
            "--no-root-passwd",
            "--no-channel-copy",
            "--option",
            "substituters",
            "",
            "--option",
            "trusted-public-keys",
            &trust,
        ],
        0o022,
    )
    .await?;
    if state.next_event_sequence == 7 {
        super::report_install_stage(
            &prepared.state_mount,
            "installing_bootloader",
            "succeeded",
            Some(95),
            "NixOS systemd-boot installed",
        )
        .await?;
        state = storage::load_durable_state(&prepared.state_mount)?;
    }
    let profile = fs::read_link(target.join("nix/var/nix/profiles/system"))?;
    let generation = profile
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("system-"))
        .and_then(|n| n.strip_suffix("-link"))
        .ok_or_else(|| anyhow!("installed generation unavailable"))?;
    nixos::generation(generation)?;
    let installed = nixos::InstalledState {
        schema: "tiaris.nest.installed-appliance.v3".into(),
        system_generation: generation.into(),
        system_toplevel: release.system_toplevel.clone(),
        system_closure_sha256: release.system_closure.sha256.clone(),
        base_os: "nixos".into(),
        base_os_version: release.base_os_version.clone(),
        at_rest_protection: "none".into(),
        release,
    };
    let receipt = prepared.state_mount.join("control/appliance-release.json");
    storage::atomic_write(&receipt, &serde_json::to_vec(&installed)?, 0o640)?;
    chown(&receipt, 0, 985)?;
    if state.next_event_sequence == 8 {
        super::report_install_stage(
            &prepared.state_mount,
            "rebooting",
            "succeeded",
            Some(99),
            "Rebooting into the managed NixOS appliance",
        )
        .await?;
        state = storage::load_durable_state(&prepared.state_mount)?;
    }
    state.installation_complete = true;
    storage::save_durable_state(&prepared.state_mount, &state)?;
    fs::remove_dir_all(&cache)?;
    File::open(&prepared.state_mount)?.sync_all()?;
    File::open(target)?.sync_all()?;
    status.rebooting();
    boot_completed(&state, &prepared.state_mount, true).await
}

fn prepare_owned_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    mode: u32,
) -> Result<()> {
    if !path.exists() {
        fs::create_dir(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == expected_uid
            && metadata.permissions().mode() & 0o022 == 0,
        "unsafe installed directory {}",
        path.display()
    );
    chown(path, expected_uid, expected_gid)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == expected_uid
            && metadata.gid() == expected_gid
            && metadata.permissions().mode() & 0o7777 == mode,
        "installed directory permissions are unsafe for {}",
        path.display()
    );
    Ok(())
}

fn prepare_installed_layout(
    target: &Path,
    expected_uid: u32,
    expected_gid: u32,
    service_gid: u32,
) -> Result<()> {
    let directories = [
        ("var", expected_gid, 0o755),
        ("var/cache", expected_gid, 0o755),
        ("var/cache/tiaris-nest", expected_gid, 0o755),
        ("var/cache/tiaris-nest/nix", expected_gid, 0o755),
        ("var/lib", expected_gid, 0o755),
        ("var/lib/tiaris-nest", service_gid, 0o750),
        ("var/lib/tiaris-nest/state", service_gid, 0o750),
        ("usr", expected_gid, 0o755),
        ("usr/share", expected_gid, 0o755),
        ("usr/share/tiaris-nest", expected_gid, 0o755),
    ];
    for (relative, gid, mode) in directories {
        prepare_owned_directory(&target.join(relative), expected_uid, gid, mode)?;
    }
    Ok(())
}

async fn run_checked_with_umask(
    program: &str,
    arguments: &[&str],
    mask: libc::mode_t,
) -> Result<()> {
    let mut command = tokio::process::Command::new(program);
    command.args(arguments);
    // SAFETY: only the post-fork child changes its process-local umask before
    // exec. The multithreaded bootstrap retains 0077 for every private write.
    unsafe {
        command.pre_exec(move || {
            libc::umask(mask);
            Ok(())
        });
    }
    let status = command.status().await?;
    ensure!(status.success(), "{program} failed");
    Ok(())
}

fn materialize_state(
    target: &Path,
    state_mount: &Path,
    state: &DurableProvisioningState,
    key_path: &Path,
) -> Result<()> {
    for (name, uid, mode) in [
        ("agent", 985, 0o700),
        ("inbox", 985, 0o700),
        ("control", 0, 0o750),
        ("status", 0, 0o750),
    ] {
        let path = state_mount.join(name);
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        chown(&path, uid, 985)?;
    }
    let control = state_mount.join("control");
    let managed = json!({"private_key_b64":state.device_private_key_b64,"public_key_b64":state.device_public_key_b64,"public_key_fingerprint":state.device_public_key_fingerprint,"device_id":state.plan.reserved_device_id,"last_reported_event_id":null});
    let agent = state_mount.join("agent/manage-state.json");
    storage::atomic_write(&agent, &serde_json::to_vec(&managed)?, 0o600)?;
    chown(&agent, 985, 985)?;
    for (name, value) in [
        ("provisioning-state.json", serde_json::to_value(state)?),
        ("install-plan.json", serde_json::to_value(&state.plan)?),
        (
            "netplan-approved.json",
            storage::netplan(&state.plan.network, &state.plan),
        ),
        (
            "netplan-dhcp-fallback.json",
            storage::netplan(
                &super::protocol::NestProvisioningNetworkPlan {
                    mode: "dhcp".into(),
                    interface_id: state.plan.network.interface_id.clone(),
                    address_cidr: None,
                    gateway: None,
                    dns_servers: Vec::new(),
                },
                &state.plan,
            ),
        ),
    ] {
        let path = control.join(name);
        storage::atomic_write(&path, &serde_json::to_vec(&value)?, 0o640)?;
        chown(&path, 0, 985)?;
    }
    let key_projection = target.join("usr/share/tiaris-nest/release-public-key");
    storage::atomic_write(&key_projection, &fs::read(key_path)?, 0o644)?;
    let config = storage::nest_config(target, state, &storage::public_base_url(&state.plan))?
        .replace("/usr/bin/nix", "/run/current-system/sw/bin/nix");
    for (name, body) in [
        ("config.toml", config),
        (
            "ssh-ca.pub",
            format!("{}\n", state.plan.ssh_ca_public_keys.join("\n")),
        ),
        ("principals", format!("{}\n", state.plan.reserved_device_id)),
        (
            "management-cidrs.txt",
            format!("{}\n", state.plan.management_cidrs.join("\n")),
        ),
    ] {
        let path = control.join(name);
        storage::atomic_write(&path, body.as_bytes(), 0o640)?;
        chown(&path, 0, 985)?;
    }
    let flat = state_mount.join("provisioning-state.json");
    if flat.exists() {
        fs::remove_file(flat)?;
    }
    File::open(state_mount)?.sync_all()?;
    Ok(())
}
pub(super) fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    ensure!(
        unsafe { libc::chown(path.as_ptr(), uid, gid) } == 0,
        "set persistent state ownership"
    );
    Ok(())
}

pub(super) async fn boot_completed(
    state: &DurableProvisioningState,
    state_mount: &Path,
    restart_unverified: bool,
) -> Result<()> {
    ensure!(
        state.installation_complete && state.identity_active,
        "installation is incomplete"
    );
    hand_off_first_boot(
        restart_unverified,
        || select_installed_boot_next(state),
        |status, message| {
            report_first_boot_handoff(state, state_mount, restart_unverified, status, message)
        },
        reboot_installed,
    )
    .await
}

/// Provisioning event stage that carries a failed UEFI boot-entry selection.
const FIRST_BOOT_HANDOFF_STAGE: &str = "first_boot_handoff";

/// Select the installed entry for the next boot, then reboot.
///
/// When the entry cannot be selected, the run that completed the installation
/// restarts anyway, once: firmware boot order may still reach the installed
/// disk. A later run of a completed installation means the firmware returned
/// to the setup media, so it reports the reason and stops instead of looping.
/// The reason is sent to Tiaris either way; a failed report never blocks the
/// restart. Only a stop is reported as `failed`, because a failed session can
/// no longer become ready when the installed Nest checks in.
async fn hand_off_first_boot<Report: std::future::Future<Output = Result<()>>>(
    restart_unverified: bool,
    select_boot_next: impl FnOnce() -> Result<()>,
    report: impl FnOnce(&'static str, String) -> Report,
    reboot: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if let Err(error) = select_boot_next() {
        let reason = format!("{error:#}");
        let (status, message) = if restart_unverified {
            tracing::warn!(%reason, "installed UEFI boot entry could not be selected; restarting once without it");
            (
                "started",
                format!("Restarting without a verified UEFI boot entry: {reason}"),
            )
        } else {
            tracing::warn!(%reason, "installed UEFI boot entry could not be selected; not restarting again without it");
            (
                "failed",
                format!("Nest could not select its installed UEFI boot entry: {reason}"),
            )
        };
        if let Err(report_error) = report(status, bounded_event_message(message)).await {
            tracing::warn!(error = %format!("{report_error:#}"), "could not report the first boot handoff to Tiaris");
        }
        if !restart_unverified {
            return Err(error.context("installed UEFI boot entry could not be selected"));
        }
    }
    reboot()
}

fn bounded_event_message(mut message: String) -> String {
    let mut end = message.len().min(512);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message
}

/// Send the handoff event. Only the run that completed the installation has
/// STATE writable; it records the sequence so a later run reports next to it.
async fn report_first_boot_handoff(
    state: &DurableProvisioningState,
    state_mount: &Path,
    record: bool,
    status: &'static str,
    message: String,
) -> Result<()> {
    let client = super::protocol::ProvisioningClient::new(&state.manage_origin, state.session_id)?;
    let key = state.signing_key()?;
    send_handoff_event(state.next_event_sequence, !record, |sequence| {
        client.send_event(
            &key,
            &state.plan,
            sequence,
            FIRST_BOOT_HANDOFF_STAGE,
            status,
            None,
            &message,
        )
    })
    .await?;
    if record {
        let mut recorded = state.clone();
        recorded.next_event_sequence += 1;
        storage::save_durable_state(state_mount, &recorded)?;
    }
    Ok(())
}

/// A run that cannot record its event first uses the recorded next sequence.
/// The completing run's handoff event may hold that sequence unrecorded when
/// its response was lost, so the event then goes directly after it.
async fn send_handoff_event<Sent: std::future::Future<Output = Result<()>>>(
    next_sequence: i64,
    after_unrecorded: bool,
    mut send: impl FnMut(i64) -> Sent,
) -> Result<()> {
    match send(next_sequence).await {
        Err(error) if after_unrecorded => send(next_sequence + 1)
            .await
            .map_err(|next| error.context(format!("{next:#}"))),
        result => result,
    }
}

fn select_installed_boot_next(state: &DurableProvisioningState) -> Result<()> {
    let esp = storage::partition_path(Path::new(&state.plan.target_disk.path), 2)?;
    select_esp_boot_next(&esp)
}

/// The number of the one UEFI entry that starts systemd-boot from this ESP,
/// found by the ESP's GPT partition GUID. Reads only.
pub(super) fn installed_boot_entry(esp: &Path) -> Result<String> {
    let output = Command::new("blkid")
        .args(["-s", "PARTUUID", "-o", "value"])
        .arg(esp)
        .output()?;
    ensure!(
        output.status.success(),
        "installed ESP identity unavailable"
    );
    let guid = String::from_utf8(output.stdout)?
        .trim()
        .to_ascii_lowercase();
    let _ = uuid::Uuid::parse_str(&guid)?;
    let output = Command::new("efibootmgr").arg("-v").output()?;
    ensure!(
        output.status.success(),
        "cannot inspect installed UEFI entries"
    );
    boot_entry_for_esp(&String::from_utf8(output.stdout)?, &guid)
}

/// Exactly one `efibootmgr -v` entry may load systemd-boot from partition 2
/// with this GPT partition GUID; its four hex digits.
fn boot_entry_for_esp(entries: &str, guid: &str) -> Result<String> {
    let binding = format!("hd(2,gpt,{guid},");
    let candidates: Vec<_> = entries
        .lines()
        .filter(|l| {
            let l = l.to_ascii_lowercase();
            l.starts_with("boot")
                && l.contains(&binding)
                && l.contains("\\efi\\systemd\\systemd-bootx64.efi")
        })
        .collect();
    ensure!(
        candidates.len() == 1,
        "installed UEFI systemd-boot entry is missing or ambiguous"
    );
    let number = candidates[0]
        .get(4..8)
        .ok_or_else(|| anyhow!("UEFI entry number"))?;
    let _ = u16::from_str_radix(number, 16)?;
    Ok(number.to_string())
}

fn select_esp_boot_next(esp: &Path) -> Result<()> {
    let number = installed_boot_entry(esp)?;
    ensure!(
        Command::new("efibootmgr")
            .args(["-n", &number])
            .status()?
            .success(),
        "set exact installed BootNext failed"
    );
    let verify = Command::new("efibootmgr").output()?;
    ensure!(
        verify.status.success()
            && String::from_utf8(verify.stdout)?
                .lines()
                .any(|l| l.eq_ignore_ascii_case(&format!("BootNext: {number}"))),
        "installed BootNext verification failed"
    );
    Ok(())
}

/// Start an installed NixOS Nest found without its provisioning state: select
/// its entry on this ESP for the next boot and restart. Only the UEFI BootNext
/// variable is written; nothing is mounted or written on a disk.
pub(super) fn boot_installed_esp(esp: &Path) -> Result<()> {
    select_esp_boot_next(esp)?;
    reboot_installed()
}

fn reboot_installed() -> Result<()> {
    ensure!(
        Command::new("sync").status()?.success(),
        "sync installation failed"
    );
    ensure!(
        Command::new("systemctl")
            .args(["reboot", "--no-block"])
            .status()?
            .success(),
        "reboot installed appliance failed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Members that do not fit take the whole archive instead of ending the
    /// setup; the tmpfs that holds them counts as well as the memory.
    #[test]
    fn members_fit_in_memory_and_in_the_tmpfs_that_holds_them() {
        assert!(members_fit(GIB, 0, 4 * GIB, 2 * GIB));
        assert!(!members_fit(GIB, 0, 3 * GIB, 8 * GIB));
        assert!(!members_fit(GIB, 0, 8 * GIB, GIB));
        // What an earlier try staged is there already.
        assert!(members_fit(GIB, GIB / 2, 8 * GIB, 3 * GIB / 2));
    }

    /// The members' cache lives in RAM; the next try may need that RAM for
    /// the whole archive.
    #[test]
    fn a_failed_member_check_leaves_no_cache_behind() {
        let mut fixture = crate::appliance::closure::full_archive_tests::Fixture::new();
        let tar = fixture.tar();
        // The size of a raw-block archive of one block holding `tar`: its
        // frame (6 bytes) and one block header (3 bytes).
        fixture.bind(&vec![0; 6 + 3 + tar.len()]);
        let dir = std::env::temp_dir().join(format!("nest-members-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let (staged, cache) = (dir.join("closure.members.tar"), dir.join("cache"));
        // Cut short: the pass has started extracting when it fails.
        fs::write(&staged, &tar[..tar.len() / 2]).unwrap();
        let key = fixture.key.verifying_key();
        let present = closure::Present::new();
        let verified = verify_staged_members(&fixture.release, &key, &present, &staged, &cache);
        assert!(verified.is_err());
        assert!(!staged.exists());
        assert!(!cache.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    fn closure_artifact() -> SystemClosure {
        SystemClosure {
            url: "https://releases.example/1.2.3/tiaris-nest-appliance-closure-1.2.3-x86_64-linux.tar.zst".into(),
            sha256: "a".repeat(64),
            size_bytes: 1024,
        }
    }

    #[test]
    fn the_installed_entry_is_the_one_systemd_boot_on_that_exact_esp() {
        let esp = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
        let entries = format!(
            "BootCurrent: 0003\nBootOrder: 0003,0001,0002,0000\n\
             Boot0000* UEFI: SanDisk Cruzer\tPciRoot(0x0)/USB(0x1,0x0)/CDROM(0x1,0x9dc,0x2000)\n\
             Boot0001* Linux Boot Manager\tHD(2,GPT,{esp},0x800,0x100000)/File(\\EFI\\systemd\\systemd-bootx64.efi)\n\
             Boot0002* Windows Boot Manager\tHD(1,GPT,9a3c0e3e-0000-4000-8000-000000000001,0x800,0x32000)/File(\\EFI\\Microsoft\\Boot\\bootmgfw.efi)\n\
             Boot0003* Linux Boot Manager\tHD(2,GPT,5c0e1a2b-0000-4000-8000-000000000002,0x800,0x100000)/File(\\EFI\\systemd\\systemd-bootx64.efi)\n"
        );
        // The setup media, another system, and systemd-boot on another ESP
        // are never selected.
        assert_eq!(boot_entry_for_esp(&entries, esp).unwrap(), "0001");
        assert!(boot_entry_for_esp(&entries, "0f0e0d0c-0000-4000-8000-000000000003").is_err());
        let twice = format!(
            "{entries}Boot0004* Copy\tHD(2,GPT,{esp},0x800,0x100000)/File(\\EFI\\systemd\\systemd-bootx64.efi)\n"
        );
        assert!(boot_entry_for_esp(&twice, esp).is_err());
        let grub = format!(
            "Boot0005* ubuntu\tHD(2,GPT,{esp},0x800,0x100000)/File(\\EFI\\ubuntu\\shimx64.efi)\n"
        );
        assert!(boot_entry_for_esp(&grub, esp).is_err());
    }

    #[test]
    fn closure_transport_accepts_signed_url_or_exact_private_qualification_archive() {
        let artifact = closure_artifact();
        assert!(validate_closure_transport(&artifact.url, &artifact).is_ok());
        let filename = "tiaris-nest-appliance-closure-1.2.3-x86_64-linux.tar.zst";
        for authority in [
            "10.20.30.40:8080",
            "192.168.50.1:8080",
            "127.0.0.1:8080",
            "[fd00::10]:8080",
            "[::1]:8080",
        ] {
            let transport = format!("http://{authority}/qualification/{filename}");
            assert!(
                validate_closure_transport(&transport, &artifact).is_ok(),
                "authenticated qualification transport was rejected: {transport}"
            );
        }
    }

    #[test]
    fn closure_transport_rejects_unsafe_or_rebound_qualification_urls() {
        let artifact = closure_artifact();
        let filename = "tiaris-nest-appliance-closure-1.2.3-x86_64-linux.tar.zst";
        for transport in [
            format!("http://bridge.internal:8080/{filename}"),
            format!("http://8.8.8.8:8080/{filename}"),
            format!("http://169.254.169.254:8080/{filename}"),
            format!("http://2130706433:8080/{filename}"),
            format!("https://10.20.30.40:8080/{filename}"),
            format!("https://dev.example.com/qualification/{filename}"),
            format!("http://127.0.0.1/{filename}"),
            format!("http://127.0.0.1:0/{filename}"),
            format!("http://user@10.20.30.40:8080/{filename}"),
            format!("http://user:password@10.20.30.40:8080/{filename}"),
            "http://10.20.30.40:8080/other.tar.zst".into(),
            format!("http://10.20.30.40:8080/{filename}?token=fixture"),
            format!("http://10.20.30.40:8080/{filename}#debug"),
            format!("http://10.20.30.40:8080/path/../{filename}"),
            format!(" http://10.20.30.40:8080/{filename}"),
        ] {
            assert!(
                validate_closure_transport(&transport, &artifact).is_err(),
                "unsafe qualification transport was accepted: {transport}"
            );
        }
    }

    #[test]
    fn geometry_is_byte_correct_for_512_and_4096() {
        for sector in [512, 4096] {
            let (s, e) = calculate_layout(sector, 160 * GIB).unwrap();
            assert_eq!((e[0] - s[0] + 1) * sector, 16 * GIB);
            assert_eq!((e[1] - s[1] + 1) * sector, GIB);
            assert_eq!((e[2] - s[2] + 1) * sector, 8 * GIB);
            assert!((e[3] - s[3] + 1) * sector >= 134 * GIB);
            assert!(e[..3].iter().zip(&s[1..4]).all(|(end, start)| end < start));
        }
    }
    #[test]
    fn undersized_and_invalid_geometry_reject() {
        assert!(calculate_layout(4096, 160 * GIB - 1).is_err());
        assert!(calculate_layout(512, 159 * GIB).is_err());
        assert!(calculate_layout(1024, 160 * GIB).is_err());
    }

    #[test]
    fn installed_layout_repairs_only_explicit_public_and_service_directories() {
        let root =
            std::env::temp_dir().join(format!("tiaris-nest-nix-backing-{}", uuid::Uuid::new_v4()));
        let status = Command::new("sh")
            .args([
                "-c",
                "umask 077; mkdir -p \"$1\"/var/cache/tiaris-nest/nix \"$1\"/var/lib/tiaris-nest/state \"$1\"/usr/share/tiaris-nest",
                "fixture",
            ])
            .arg(&root)
            .status()
            .unwrap();
        assert!(status.success());
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        prepare_installed_layout(&root, uid, gid, gid).unwrap();

        for relative in [
            "var",
            "var/cache",
            "var/cache/tiaris-nest",
            "var/cache/tiaris-nest/nix",
            "var/lib",
            "usr",
            "usr/share",
            "usr/share/tiaris-nest",
        ] {
            assert_eq!(
                fs::symlink_metadata(root.join(relative))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o755,
                "{relative} retained restrictive bootstrap permissions"
            );
        }
        for relative in ["var/lib/tiaris-nest", "var/lib/tiaris-nest/state"] {
            assert_eq!(
                fs::symlink_metadata(root.join(relative))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o750,
                "{relative} lost its protected service boundary"
            );
        }
        let unsafe_root = root.with_extension("unsafe");
        fs::create_dir(&unsafe_root).unwrap();
        std::os::unix::fs::symlink(&root, unsafe_root.join("var")).unwrap();
        assert!(prepare_installed_layout(&unsafe_root, uid, gid, gid).is_err());
        fs::remove_dir_all(unsafe_root).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn activation_child_uses_public_umask_without_changing_parent() {
        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-install-umask-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let before = root.join("parent-before");
        let child = root.join("child");
        let installed = root.join("installed");
        let after = root.join("parent-after");
        Command::new("sh")
            .args(["-c", "umask > \"$1\"", "fixture"])
            .arg(&before)
            .status()
            .unwrap();
        run_checked_with_umask(
            "sh",
            &[
                "-c",
                "umask > \"$1\"; : > \"$2\"",
                "fixture",
                child.to_str().unwrap(),
                installed.to_str().unwrap(),
            ],
            0o022,
        )
        .await
        .unwrap();
        Command::new("sh")
            .args(["-c", "umask > \"$1\"", "fixture"])
            .arg(&after)
            .status()
            .unwrap();
        assert_eq!(fs::read_to_string(&child).unwrap(), "0022\n");
        assert_eq!(
            fs::symlink_metadata(&installed)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            fs::read_to_string(&after).unwrap(),
            fs::read_to_string(&before).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// Tiaris production #20: a Proxmox VM whose persistent UEFI variables
    /// still held the earlier Nest's entries could not select the installed
    /// entry, so setup stopped at First boot instead of restarting.
    async fn first_boot_handoff(
        restart_unverified: bool,
        selected: Result<()>,
        reported: Result<()>,
    ) -> (Result<()>, Vec<(&'static str, String)>, usize) {
        let reports = std::cell::RefCell::new(Vec::new());
        let reboots = std::cell::Cell::new(0);
        let result = hand_off_first_boot(
            restart_unverified,
            || selected,
            |status, message| {
                reports.borrow_mut().push((status, message));
                std::future::ready(reported)
            },
            || {
                reboots.set(reboots.get() + 1);
                Ok(())
            },
        )
        .await;
        (result, reports.into_inner(), reboots.get())
    }

    #[tokio::test]
    async fn completed_install_restarts_once_when_its_uefi_entry_cannot_be_selected() {
        let (result, reports, reboots) = first_boot_handoff(
            true,
            Err(anyhow!(
                "installed UEFI systemd-boot entry is missing or ambiguous"
            )),
            Ok(()),
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(reboots, 1);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].0, "started");
        assert!(
            reports[0]
                .1
                .contains("installed UEFI systemd-boot entry is missing or ambiguous"),
            "{reports:?}"
        );
    }

    #[tokio::test]
    async fn unreported_handoff_reason_does_not_prevent_the_restart() {
        let (result, reports, reboots) = first_boot_handoff(
            true,
            Err(anyhow!("set exact installed BootNext failed")),
            Err(anyhow!("Tiaris is unreachable")),
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(reports.len(), 1);
        assert_eq!(reboots, 1);
    }

    #[tokio::test]
    async fn resumed_install_reports_why_and_never_restarts_again_without_boot_next() {
        let (result, reports, reboots) = first_boot_handoff(
            false,
            Err(anyhow!("installed BootNext verification failed")),
            Ok(()),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(reboots, 0);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].0, "failed");
        assert!(
            reports[0]
                .1
                .contains("installed BootNext verification failed"),
            "{reports:?}"
        );
    }

    #[tokio::test]
    async fn resumed_install_still_stops_when_its_failure_report_is_lost() {
        let (result, reports, reboots) = first_boot_handoff(
            false,
            Err(anyhow!("BootNext is read-only")),
            Err(anyhow!("Tiaris is unreachable")),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("UEFI boot entry"));
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].0, "failed");
        assert_eq!(reboots, 0);
    }

    #[tokio::test]
    async fn first_boot_fallback_propagates_a_failed_restart_without_retrying() {
        let reboots = std::cell::Cell::new(0);
        let result = hand_off_first_boot(
            true,
            || Err(anyhow!("BootNext is unavailable")),
            |status, _| {
                assert_eq!(status, "started");
                std::future::ready(Err(anyhow!("handoff report failed")))
            },
            || {
                reboots.set(reboots.get() + 1);
                Err(anyhow!("systemctl reboot failed"))
            },
        )
        .await;
        assert_eq!(result.unwrap_err().to_string(), "systemctl reboot failed");
        assert_eq!(reboots.get(), 1);
    }

    #[tokio::test]
    async fn verified_boot_next_restarts_without_a_report() {
        for restart_unverified in [true, false] {
            let (result, reports, reboots) =
                first_boot_handoff(restart_unverified, Ok(()), Ok(())).await;
            assert!(result.is_ok(), "{result:?}");
            assert!(reports.is_empty());
            assert_eq!(reboots, 1);
        }
    }

    #[tokio::test]
    async fn handoff_report_fits_a_provisioning_event() {
        let (_, reports, _) = first_boot_handoff(true, Err(anyhow!("é".repeat(600))), Ok(())).await;
        assert_eq!(reports.len(), 1);
        assert!(reports[0].1.len() <= 512);
        assert!(reports[0].1.ends_with('é'));
    }

    async fn handoff_event_sequences(
        after_unrecorded: bool,
        accepted: i64,
    ) -> (Result<()>, Vec<i64>) {
        let sent = std::cell::RefCell::new(Vec::new());
        let result = send_handoff_event(9, after_unrecorded, |sequence| {
            sent.borrow_mut().push(sequence);
            std::future::ready(if sequence == accepted {
                Ok(())
            } else {
                Err(anyhow!("event_id was already used for different evidence"))
            })
        })
        .await;
        (result, sent.into_inner())
    }

    #[tokio::test]
    async fn resumed_report_follows_a_handoff_event_whose_response_was_lost() {
        let (result, sent) = handoff_event_sequences(true, 10).await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(sent, [9, 10]);
        let (result, sent) = handoff_event_sequences(true, 9).await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(sent, [9]);
    }

    #[tokio::test]
    async fn recorded_handoff_event_uses_only_the_recorded_sequence() {
        let (result, sent) = handoff_event_sequences(false, 10).await;
        assert!(result.is_err());
        assert_eq!(sent, [9]);
    }
}
