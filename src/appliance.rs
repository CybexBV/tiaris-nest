pub mod closure;
pub mod nixos;
pub mod release_v3;
pub mod schedule;
// NixOS appliance state, update admission helpers and health projection.

use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use tokio::process::Command;

pub const APPLIANCE_UPDATE_CAPABILITY: &str = "appliance_update_v1";
/// Additive capability for an unsigned, exact-attempt qualification transport
/// hint. Older strict wire decoders must never receive that optional field.
pub const APPLIANCE_UPDATE_QUALIFICATION_TRANSPORT_CAPABILITY: &str =
    "appliance_update_qualification_transport_v1";
const INSTALLED_STATE_PATH: &str = "/var/lib/tiaris-nest/control/appliance-release.json";
const UPDATE_STATUS_PATH: &str = "/var/lib/tiaris-nest/status/appliance-update-status.json";
const UPDATE_REQUEST_PATH: &str = "/var/lib/tiaris-nest/state/inbox/appliance-update-request.json";
const UPDATE_ROOT: &str = "/var/lib/tiaris-nest/control/appliance-updates";
const RELEASE_PUBLIC_KEY_PATH: &str = "/usr/share/tiaris-nest/release-public-key";
const PROVISIONING_STATE_PATH: &str = "/var/lib/tiaris-nest/control/provisioning-state.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplianceRepositorySnapshot {
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedApplianceUpdate<R> {
    pub attempt_id: uuid::Uuid,
    pub requested_at: DateTime<Utc>,
    pub release: R,
    /// Unsigned, exact-attempt transport hint used only by release qualification.
    /// The signed release URL remains the artifact identity and production path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification_package_transport_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplianceReport {
    pub base_os: String,
    pub base_os_version: String,
    pub appliance_release: String,
    pub kernel_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_boot: Option<bool>,
    pub boot_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub microcode_version: Option<String>,
    pub nix_version: String,
    pub at_rest_protection: String,
    pub network: Value,
    pub package_update: Value,
    pub local_health: Value,
    #[serde(flatten)]
    pub nixos: BTreeMap<String, Value>,
}

pub fn is_managed_appliance() -> bool {
    nixos::is_nixos()
}
fn pin_untrusted_bundle(
    source: &Path,
    target: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<()> {
    let mut source = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(source)
        .context("open untrusted appliance update bundle")?;
    let metadata = source.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.len() != expected_size {
        bail!("untrusted appliance update bundle is unsafe")
    }
    let mut destination = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(target)
        .context("create pinned appliance update bundle")?;
    let result = (|| -> Result<()> {
        let mut hasher = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(read as u64)
                .ok_or_else(|| anyhow!("appliance update bundle size overflow"))?;
            if copied > expected_size {
                bail!("appliance update bundle exceeded its signed size")
            }
            hasher.update(&buffer[..read]);
            destination.write_all(&buffer[..read])?;
        }
        if copied != expected_size || hex::encode(hasher.finalize()) != expected_sha256 {
            bail!("appliance update bundle changed before it was pinned")
        }
        destination.sync_all()?;
        sync_directory(
            target
                .parent()
                .ok_or_else(|| anyhow!("pinned bundle has no parent"))?,
        )
    })();
    if result.is_err() {
        let _ = fs::remove_file(target);
    }
    result
}

pub(crate) fn validate_qualification_package_transport_url(
    value: &str,
    snapshot: &ApplianceRepositorySnapshot,
) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.trim() != value {
        bail!("appliance qualification transport URL is invalid")
    }
    let url = Url::parse(value).context("parse appliance qualification transport URL")?;
    let ip = url
        .host_str()
        .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok());
    let expected_filename = Url::parse(&snapshot.url)
        .context("parse signed appliance package snapshot URL")?
        .path_segments()
        .and_then(|mut segments| segments.next_back().map(str::to_string))
        .ok_or_else(|| anyhow!("signed appliance package snapshot URL has no filename"))?;
    let actual_filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back());
    if url.scheme() != "http"
        || url.as_str() != value
        || !ip.is_some_and(qualification_transport_ip)
        || url.port().is_none_or(|port| port == 0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || actual_filename != Some(expected_filename.as_str())
    {
        bail!(
            "appliance qualification transport URL must be canonical private IP-literal HTTP for the exact signed archive filename"
        )
    }
    Ok(())
}

fn qualification_transport_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || ip.is_unique_local() || ip.is_loopback(),
            |ipv4| ipv4.is_private() || ipv4.is_loopback(),
        ),
    }
}

fn read_bounded_snapshot_text(path: &Path, maximum_bytes: u64, label: &str) -> Result<String> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        bail!("{label} is invalid")
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {label}"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect open {label}"))?;
    if !opened.file_type().is_file()
        || opened.nlink() != 1
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        bail!("{label} changed before it was read")
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| anyhow!("{label} is too large"))?;
    let read_limit = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow!("{label} size limit overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > maximum_bytes {
        bail!("{label} changed while it was read")
    }
    String::from_utf8(bytes).map_err(|_| anyhow!("{label} is not UTF-8"))
}

fn write_atomic_json(path: &Path, value: &impl Serialize, mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("appliance state path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("appliance state filename is invalid"))?,
        uuid::Uuid::new_v4()
    ));
    let body = serde_json::to_vec(value)?;
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        if nixos::is_nixos()
            && unsafe { libc::geteuid() } == 0
            && (path.starts_with("/var/lib/tiaris-nest/control")
                || path.starts_with("/var/lib/tiaris-nest/status"))
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::fchown(file.as_raw_fd(), 0, 985) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        file.write_all(&body)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn canonical_base64(value: &str, expected_length: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        bail!("appliance release signature material is not canonical Base64")
    }
    let decoded = STANDARD
        .decode(value.as_bytes())
        .context("decode appliance release signature material")?;
    if decoded.len() != expected_length || STANDARD.encode(&decoded) != value {
        bail!("appliance release signature material is not canonical Base64")
    }
    Ok(decoded)
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                if let Some(value) = object.get(&key) {
                    sorted.insert(key, canonical_json(value.clone()));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        other => other,
    }
}

pub(crate) fn verify_management_signature<T: Serialize>(
    value: &T,
    signature_field: &str,
    signature: &str,
    domain: &str,
    public_key: &str,
) -> Result<()> {
    let key = canonical_base64(public_key, 32)?;
    let key = VerifyingKey::from_bytes(
        key.as_slice()
            .try_into()
            .map_err(|_| anyhow!("Management signing public key length is invalid"))?,
    )?;
    if key.is_weak() {
        bail!("Management signing public key is weak")
    }
    let signature = canonical_url_base64(signature, 64)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow!("Management signature length is invalid"))?;
    let mut unsigned = serde_json::to_value(value)?;
    unsigned
        .as_object_mut()
        .ok_or_else(|| anyhow!("Management signed object is invalid"))?
        .remove(signature_field);
    let body = serde_json::to_vec(&canonical_json(unsigned))?;
    let mut payload = domain.as_bytes().to_vec();
    payload.push(b'\n');
    payload.extend_from_slice(&body);
    key.verify_strict(&payload, &Signature::from_bytes(&signature))?;
    Ok(())
}

fn canonical_url_base64(value: &str, expected_length: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        bail!("Management signature is not canonical URL-safe Base64")
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .context("decode Management signature")?;
    if decoded.len() != expected_length || URL_SAFE_NO_PAD.encode(&decoded) != value {
        bail!("Management signature is not canonical URL-safe Base64")
    }
    Ok(decoded)
}

fn load_provisioning_state() -> Result<crate::provisioning::DurableProvisioningState> {
    let state: crate::provisioning::DurableProvisioningState =
        read_bounded_json(Path::new(PROVISIONING_STATE_PATH), 512 * 1024)?;
    if state.schema != "tiaris.nest.provisioning-state.v1"
        || state.management_signing_public_key_b64.is_empty()
        || !state.identity_active
    {
        bail!("installed provisioning identity cannot verify Management changes")
    }
    Ok(state)
}

pub async fn report(state: &crate::AppState) -> Result<Option<ApplianceReport>> {
    if !nixos::is_nixos() {
        return Ok(None);
    }
    nixos::report(state).await.map(Some)
}

async fn local_health(readiness: crate::readiness::ApplianceReadiness) -> Value {
    let mut checks = serde_json::Map::new();
    for unit in ["nginx", "tftpd-hpa", "nix-daemon"] {
        let healthy = Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .await
            .is_ok_and(|status| status.success());
        checks.insert(unit.to_string(), Value::Bool(healthy));
    }
    checks.insert(
        "appliance_config".to_string(),
        Value::Bool(readiness.appliance_config),
    );
    checks.insert(
        "bootloader_asset".to_string(),
        Value::Bool(readiness.bootloader_asset),
    );
    checks.insert(
        "tftp_bootloader".to_string(),
        Value::Bool(readiness.tftp_bootloader),
    );
    checks.insert(
        "ipxe_chain_script_asset".to_string(),
        Value::Bool(readiness.ipxe_chain_script_asset),
    );
    checks.insert(
        "tftp_ipxe_chain_script".to_string(),
        Value::Bool(readiness.tftp_ipxe_chain_script),
    );
    checks.insert(
        "public_boot_url".to_string(),
        Value::Bool(readiness.public_boot_url),
    );
    let pxe = crate::pxe_discovery::status();
    let pxe_ok = pxe.get("status").and_then(Value::as_str) == Some("active");
    let status =
        if readiness.ready && pxe_ok && checks.values().all(|value| value == &Value::Bool(true)) {
            "healthy"
        } else {
            "degraded"
        };
    let state_storage = crate::disk::stats(Path::new(STATE_DIR)).ok();
    let sync = crate::manage::sync_health();
    let attention = health_attention(state_storage.as_ref(), &sync);
    json!({
        "status":status,"checks":checks,"pxe_discovery":pxe,"resources":crate::resources::latest(),
        // Facts Manage alerts on; none of them changes `status` (which gates
        // Nest updates), so a full STATE or a failing subsystem never blocks
        // the update that would fix it.
        "storage":{"state":state_storage},
        "sync":sync,
        "database":crate::schema_evolution::status(),
        "attention":attention,
    })
}

/// The STATE partition of an installed Nest.
const STATE_DIR: &str = "/var/lib/tiaris-nest/state";
/// STATE (16 GiB: database, identity, receipts) below this is attention.
const STATE_STORAGE_LOW_BYTES: u64 = 512 * 1024 * 1024;
/// Failed sync cycles (about 30 s apart, then backing off) before attention.
const SYNC_FAILING_CYCLES: u32 = 3;

/// Bounded codes for what needs a person even while the Nest still reports.
fn health_attention(
    state: Option<&crate::disk::DiskStats>,
    sync: &crate::manage::SyncHealth,
) -> Vec<&'static str> {
    let mut codes = Vec::new();
    match state {
        Some(state)
            if state.available_bytes < STATE_STORAGE_LOW_BYTES
                || state.available_bytes.saturating_mul(20) < state.total_bytes =>
        {
            codes.push("state_storage_low")
        }
        None => codes.push("state_storage_unknown"),
        _ => {}
    }
    if sync.consecutive_failures >= SYNC_FAILING_CYCLES {
        codes.push("sync_failing");
    }
    let database = crate::schema_evolution::status();
    if database["tolerated_newer"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty())
    {
        // Rolled back from a release that changed the schema.
        codes.push("database_newer_than_release");
    }
    codes
}

fn microcode_version() -> String {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|body| {
            body.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == "microcode").then(|| value.trim().to_string())
            })
        })
        .unwrap_or_default()
}

async fn command_text(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .output()
        .await
        .ok()
        .filter(|output| output.status.success() && output.stdout.len() <= 1024 * 1024)
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default()
}

async fn command_json(program: &str, arguments: &[&str]) -> Value {
    serde_json::from_str(&command_text(program, arguments).await).unwrap_or(Value::Null)
}

fn read_trimmed(path: &str) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().chars().take(256).collect())
        .unwrap_or_default()
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(path: &Path, max: u64) -> Result<T> {
    let body = read_bounded_snapshot_text(path, max, "appliance state file")?;
    serde_json::from_str(&body).with_context(|| format!("parse {}", path.display()))
}

fn read_optional_bounded_json<T: for<'de> Deserialize<'de>>(path: &Path, max: u64) -> Option<T> {
    read_bounded_json(path, max).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_health_names_a_full_state_disk_and_failing_sync_without_changing_status() {
        let gib = 1024 * 1024 * 1024;
        let disk = |available: u64| crate::disk::DiskStats {
            path: STATE_DIR.into(),
            total_bytes: 16 * gib,
            available_bytes: available,
        };
        let quiet = crate::manage::SyncHealth::default();
        assert!(health_attention(Some(&disk(8 * gib)), &quiet).is_empty());
        assert_eq!(
            health_attention(Some(&disk(256 * 1024 * 1024)), &quiet),
            ["state_storage_low"]
        );
        // Under 5% of the partition even with more than 512 MiB free.
        let large = crate::disk::DiskStats {
            path: "/state".into(),
            total_bytes: 400 * gib,
            available_bytes: 19 * gib,
        };
        assert_eq!(
            health_attention(Some(&large), &quiet),
            ["state_storage_low"]
        );
        assert_eq!(health_attention(None, &quiet), ["state_storage_unknown"]);
        let failing = crate::manage::SyncHealth {
            last_success_at: Some("2026-11-13T10:00:00Z".into()),
            consecutive_failures: 3,
            failing_subsystem: Some("boot configuration and report"),
        };
        assert_eq!(
            health_attention(Some(&disk(8 * gib)), &failing),
            ["sync_failing"]
        );
        let reported = serde_json::to_value(&failing).unwrap();
        assert_eq!(
            reported["failing_subsystem"],
            "boot configuration and report"
        );
        assert_eq!(reported["last_success_at"], "2026-11-13T10:00:00Z");
    }

    fn test_directory(label: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("tiaris-nest-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn untrusted_update_bundle_is_pinned_before_later_consumption() {
        let root = test_directory("pinned-update-bundle");
        let source = root.join("inbox.tar.zst");
        let target = root.join("root-owned.tar.zst");
        let body = b"signed bundle bytes";
        fs::write(&source, body).unwrap();
        pin_untrusted_bundle(
            &source,
            &target,
            body.len() as u64,
            &hex::encode(Sha256::digest(body)),
        )
        .unwrap();
        fs::write(&source, b"mutated after pin!").unwrap();
        assert_eq!(fs::read(&target).unwrap(), body);
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o400
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qualification_transport_is_a_private_ip_literal_for_the_signed_filename() {
        let filename = "tiaris-nest-appliance-0.2.200-x86_64-linux.tar.zst";
        let artifact = ApplianceRepositorySnapshot {
            url: format!("https://downloads.example.test/nest/{filename}"),
            sha256: "0".repeat(64),
            size_bytes: 1,
        };
        for value in [
            format!("http://10.20.30.40:8080/{filename}"),
            format!("http://127.0.0.1:8080/{filename}"),
            format!("http://[fd00::10]:8080/{filename}"),
        ] {
            validate_qualification_package_transport_url(&value, &artifact).unwrap();
        }
        for value in [
            format!("http://bridge.internal:8080/{filename}"),
            format!("http://8.8.8.8:8080/{filename}"),
            format!("http://169.254.169.254:8080/{filename}"),
            format!("https://10.20.30.40:8080/{filename}"),
            format!("http://127.0.0.1/{filename}"),
            format!("http://user@10.20.30.40:8080/{filename}"),
            "http://10.20.30.40:8080/other.tar.zst".to_string(),
            format!("http://10.20.30.40:8080/{filename}?token=secret"),
            artifact.url.clone(),
        ] {
            assert!(
                validate_qualification_package_transport_url(&value, &artifact).is_err(),
                "unsafe qualification transport was accepted: {value}"
            );
        }
    }
}
