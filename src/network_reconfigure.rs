//! Signed post-install network reconfiguration (`network_reconfigure_v1`).
//!
//! The unprivileged `tiaris-nest` daemon writes Manage's signed
//! `tiaris.nest.network-supersession.v1` document into
//! `/var/lib/tiaris-nest/state/agent/network-reconfigure.json` (0600) and reads
//! root's status projection from `/run/tiaris-nest-network/reconfigure-status.json`.
//!
//! Root (`tiaris-nest-bootstrap apply-network-reconfigure`) verifies the Ed25519
//! signature, monotonic revision, identity binding, and expiry; pre-validates
//! the candidate firewall rules; stages the candidate Netplan; verifies Manage
//! `/v1/health` JSON reachability within 90 seconds; and either commits
//! `control/network-supersession.json` as a single atomic file (leaving
//! `control/netplan-approved.json` and `control/management-cidrs.txt` untouched
//! for predecessor generation rollback) and materializes effective projections
//! under `/run/tiaris-nest-network/`, or automatically reverts to the previous
//! active network.

use crate::{
    provisioning::{
        DurableProvisioningState, effective_manage_origin,
        protocol::{
            self, NestProvisioningNetworkPlan, SignedInstallPlan, load_trusted_provisioning_keys,
        },
        read_bounded_nofollow,
    },
    state_files,
};
use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::Write,
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub(crate) const CAPABILITY: &str = "network_reconfigure_v1";
pub(crate) const SCHEMA: &str = "tiaris.nest.network-supersession.v1";
pub(crate) const DOMAIN: &str = "TIARIS-NEST-NETWORK-SUPERSESSION-V1";
pub(crate) const REPORT_SCHEMA: &str = "tiaris.nest.network-reconfigure-report.v1";
const INBOX_FILE: &str = "network-reconfigure.json";
const STATUS_DIR: &str = "/run/tiaris-nest-network";
const STATUS_FILE: &str = "reconfigure-status.json";
const PENDING_REVERT_YAML: &str = "pending-revert.yaml";
const PENDING_REVERT_META: &str = "pending-revert.json";
const RETRY_PENDING_FILE: &str = "retry-pending";
const PXE_RESTART_PENDING_FILE: &str = "pxe-restart-pending";
const RECONFIGURE_LOCK_FILE: &str = "reconfigure.lock";
const LAST_OUTCOME_FILE: &str = "network-reconfigure-last.json";
pub(crate) const SUPERSESSION_FILE: &str = "network-supersession.json";
pub(crate) const EFFECTIVE_NETWORK_DIR: &str = "/run/tiaris-nest-network";
pub(crate) const PROVISIONING_KEYS_PATH: &str = "/usr/share/tiaris-nest/provisioning-public-keys";
const ACTIVE_NETPLAN: &str = "/etc/netplan/90-tiaris-nest.yaml";
const MAX_BYTES: u64 = 64 * 1024;
const ADDRESS_WAIT_SECONDS: u64 = 45;
const PROBE_DEADLINE_SECONDS: u64 = 90;
const REVERT_PROBE_DEADLINE_SECONDS: u64 = 30;
const MAX_APPLY_ITERATIONS: usize = 2;
const MAX_DRAIN_START_ELAPSED_SECONDS: u64 = 240;
const CONVERGE_MAX_ATTEMPTS: usize = 3;
const CONVERGE_RETRY_DELAY_SECONDS: u64 = 5;

pub(crate) fn shipped() -> bool {
    crate::appliance::nixos::is_nixos()
        && Path::new("/etc/systemd/system/tiaris-nest-network-reconfigure.service").is_file()
        && Path::new("/var/lib/tiaris-nest/state/agent").is_dir()
}

/// Untyped outer wrapper so a malformed config lane never rejects unrelated
/// Manage settings.
#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct Desired(Value);

impl fmt::Debug for Desired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Desired(…)")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNetworkSupersession {
    pub schema: String,
    pub organization_id: Uuid,
    pub device_id: String,
    pub device_incarnation_id: Uuid,
    pub provisioning_session_id: Uuid,
    pub revision: i64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub network: NestProvisioningNetworkPlan,
    pub management_cidrs: Vec<String>,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Report {
    pub schema: String,
    pub revision: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_revision: Option<i64>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub checked_at: DateTime<Utc>,
}

/// Persist the latest signed supersession from Manage in the unprivileged
/// agent inbox so the root systemd path unit picks it up.
pub(crate) fn apply(data_dir: &Path, desired: Option<Desired>) -> Result<()> {
    apply_with_status_dir(data_dir, Path::new(STATUS_DIR), desired).map(|_| ())
}

fn apply_with_status_dir(
    data_dir: &Path,
    status_dir: &Path,
    desired: Option<Desired>,
) -> Result<bool> {
    let Some(Desired(raw)) = desired else {
        return Ok(false);
    };
    let parsed: SignedNetworkSupersession =
        serde_json::from_value(raw.clone()).context("invalid network reconfiguration document")?;
    if parsed.schema != SCHEMA || parsed.revision <= 0 || parsed.signature.is_empty() {
        bail!("invalid network reconfiguration metadata");
    }
    let body = serde_json::to_vec(&raw)?;
    if body.len() as u64 > MAX_BYTES {
        bail!("network reconfiguration document exceeds size bound");
    }
    let current = state_files::read_bytes(data_dir, INBOX_FILE, MAX_BYTES).unwrap_or_default();
    // Re-trigger PathChanged if root's reported status still lags the desired
    // revision (for example if systemd dropped a PathChanged edge while the
    // oneshot or its ExecStopPost recovery handler was finishing an earlier run).
    let report_lagging = report_from(status_dir).is_none_or(|r| r.revision < parsed.revision);
    if current.as_deref() != Some(body.as_slice()) || report_lagging {
        state_files::write_bytes(data_dir, INBOX_FILE, &body, MAX_BYTES)?;
        return Ok(true);
    }
    Ok(false)
}

/// Read root's latest network reconfiguration report for the Manage telemetry lane.
pub(crate) fn report() -> Option<Report> {
    report_from(Path::new(STATUS_DIR))
}

fn report_from(status_dir: &Path) -> Option<Report> {
    let bytes = state_files::read_bytes(status_dir, STATUS_FILE, 8192)
        .ok()
        .flatten()?;
    let parsed: Report = serde_json::from_slice(&bytes).ok()?;
    if parsed.schema != REPORT_SCHEMA
        || parsed.revision <= 0
        || !matches!(
            parsed.status.as_str(),
            "pending" | "applied" | "reverted" | "rejected"
        )
    {
        return None;
    }
    Some(parsed)
}

/// Verify a signed supersession JSON document against one trusted public key.
#[cfg(test)]
pub(crate) fn verify_supersession_value(
    raw: &Value,
    public_key_b64: &str,
    plan: &SignedInstallPlan,
    check_expiry: bool,
    now: DateTime<Utc>,
) -> Result<SignedNetworkSupersession> {
    verify_supersession_value_any_key(raw, &[public_key_b64.to_string()], plan, check_expiry, now)
}

/// Verify a signed supersession JSON document against any trusted provisioning
/// public key so Management signing key rotations remain supported.
pub(crate) fn verify_supersession_value_any_key(
    raw: &Value,
    public_keys_b64: &[String],
    plan: &SignedInstallPlan,
    check_expiry: bool,
    now: DateTime<Utc>,
) -> Result<SignedNetworkSupersession> {
    if public_keys_b64.is_empty() {
        bail!("no trusted provisioning public keys available");
    }
    let doc: SignedNetworkSupersession =
        serde_json::from_value(raw.clone()).context("parse network supersession")?;
    if doc.schema != SCHEMA {
        bail!("unsupported network supersession schema");
    }
    if doc.revision <= 0 {
        bail!("network supersession revision must be positive");
    }
    if doc.organization_id != plan.organization_id
        || doc.device_id != plan.reserved_device_id
        || doc.provisioning_session_id != plan.session_id
    {
        bail!("network supersession identity does not match this installed Nest");
    }
    if doc.expires_at <= doc.issued_at {
        bail!("network supersession validity window is invalid");
    }
    if check_expiry && now > doc.expires_at {
        bail!("network supersession has expired");
    }
    if doc.network.interface_id != plan.network_interface.id {
        bail!("network supersession references an unknown interface_id");
    }
    validate_network_plan(&doc.network)?;
    validate_management_cidrs(&doc.management_cidrs)?;
    let verified = public_keys_b64.iter().any(|key| {
        crate::appliance::verify_management_signature(raw, "signature", &doc.signature, DOMAIN, key)
            .is_ok()
    });
    if !verified {
        bail!("network supersession signature verification failed");
    }
    Ok(doc)
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0u128
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn validate_network_plan(network: &NestProvisioningNetworkPlan) -> Result<()> {
    match network.mode.as_str() {
        "dhcp" => {
            if network.address_cidr.is_some()
                || network.gateway.is_some()
                || !network.dns_servers.is_empty()
            {
                bail!("DHCP supersession must not carry static address fields");
            }
            Ok(())
        }
        "static" => {
            let cidr = network
                .address_cidr
                .as_deref()
                .ok_or_else(|| anyhow!("static supersession omitted address_cidr"))?;
            let (addr_str, prefix_str) = cidr
                .split_once('/')
                .ok_or_else(|| anyhow!("static supersession address_cidr is invalid"))?;
            let address: Ipv4Addr = addr_str
                .parse()
                .context("static supersession IPv4 address is invalid")?;
            let prefix: u8 = prefix_str
                .parse()
                .context("static supersession prefix is invalid")?;
            if !(1..=30).contains(&prefix) {
                bail!("static supersession prefix must be between 1 and 30");
            }
            if address.is_unspecified()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
            {
                bail!("static supersession IPv4 address must be a unicast host address");
            }
            let mask = ipv4_mask(prefix);
            let addr_raw = u32::from(address);
            let net = addr_raw & mask;
            let bcast = net | !mask;
            if addr_raw == net || addr_raw == bcast {
                bail!("static supersession IPv4 address cannot be network or broadcast");
            }
            let gateway: Ipv4Addr = network
                .gateway
                .as_deref()
                .ok_or_else(|| anyhow!("static supersession omitted gateway"))?
                .parse()
                .context("static supersession gateway is invalid")?;
            let gw_raw = u32::from(gateway);
            if address == gateway
                || gateway.is_link_local()
                || (gw_raw & mask) != net
                || gw_raw == net
                || gw_raw == bcast
            {
                bail!("static supersession gateway is outside the usable subnet");
            }
            if network.dns_servers.is_empty() || network.dns_servers.len() > 4 {
                bail!("static supersession requires 1..=4 DNS servers");
            }
            let mut seen = BTreeSet::new();
            for entry in &network.dns_servers {
                let dns: Ipv4Addr = entry
                    .parse()
                    .context("static supersession DNS server is not IPv4")?;
                if dns == address
                    || dns.is_unspecified()
                    || dns.is_link_local()
                    || dns.is_multicast()
                    || dns.is_broadcast()
                    || !seen.insert(dns)
                {
                    bail!("static supersession DNS servers are invalid");
                }
            }
            Ok(())
        }
        _ => bail!("unsupported network mode"),
    }
}

fn validate_management_cidrs(cidrs: &[String]) -> Result<()> {
    if cidrs.is_empty() || cidrs.len() > 32 {
        bail!("management_cidrs must contain 1..=32 entries");
    }
    let mut v4_ranges: Vec<(u32, u32)> = Vec::new();
    let mut v6_ranges: Vec<(u128, u128)> = Vec::new();
    for entry in cidrs {
        let (addr_str, prefix_str) = entry
            .split_once('/')
            .ok_or_else(|| anyhow!("management_cidrs entry is not CIDR"))?;
        let addr: IpAddr = addr_str
            .parse()
            .context("management_cidrs IP address is invalid")?;
        let prefix: u8 = prefix_str
            .parse()
            .context("management_cidrs prefix is invalid")?;
        match addr {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    bail!("management_cidrs prefix exceeds limit");
                }
                let mask = ipv4_mask(prefix);
                let raw = u32::from(v4);
                if (raw & !mask) != 0 {
                    bail!("management_cidrs entry must not have host bits set");
                }
                let end = raw | !mask;
                v4_ranges.push((raw, end));
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    bail!("management_cidrs prefix exceeds limit");
                }
                let mask = ipv6_mask(prefix);
                let raw = u128::from(v6);
                if (raw & !mask) != 0 {
                    bail!("management_cidrs entry must not have host bits set");
                }
                let end = raw | !mask;
                v6_ranges.push((raw, end));
            }
        }
    }
    v4_ranges.sort_unstable();
    for pair in v4_ranges.windows(2) {
        if pair[1].0 <= pair[0].1 {
            bail!("management_cidrs must not contain duplicate or overlapping subnets");
        }
    }
    v6_ranges.sort_unstable();
    for pair in v6_ranges.windows(2) {
        if pair[1].0 <= pair[0].1 {
            bail!("management_cidrs must not contain duplicate or overlapping subnets");
        }
    }
    Ok(())
}

fn load_trusted_key_b64s(
    keys_path: &Path,
    fallback_b64: &str,
    include_install_fallback: bool,
) -> Result<Vec<String>> {
    let mut keys_file_found = false;
    let mut out = match fs::symlink_metadata(keys_path) {
        Ok(_) => {
            keys_file_found = true;
            let keys = load_trusted_provisioning_keys(keys_path)?;
            keys.iter()
                .map(|key| protocol::standard_base64(key.to_bytes()))
                .collect::<Vec<_>>()
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err).context("inspect trusted provisioning keys"),
    };
    // For already-committed on-disk supersessions (include_install_fallback = true)
    // or when no shipped key file exists in tests, also trust the install-time key.
    // For brand-new incoming supersessions (include_install_fallback = false), only
    // the shipped key list is trusted so key rotation can revoke retired keys.
    if (include_install_fallback || !keys_file_found)
        && !fallback_b64.is_empty()
        && !out.iter().any(|k| k == fallback_b64)
    {
        out.push(fallback_b64.to_string());
    }
    Ok(out)
}

/// Materialize effective network projections into `out_dir` (default
/// `/run/tiaris-nest-network`) from a committed `control/network-supersession.json`.
///
/// Leaves `control/netplan-approved.json` and `control/management-cidrs.txt`
/// immutable so rollback to pre-supersession generations always validates cleanly
/// and a crash during commit can never leave torn files.
pub fn materialize_effective_network(
    control_dir: &Path,
    out_dir: &Path,
    provisioning_keys_path: &Path,
) -> Result<bool> {
    let supersession_path = control_dir.join(SUPERSESSION_FILE);
    match fs::symlink_metadata(&supersession_path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let _ = fs::remove_file(out_dir.join("netplan-approved.json"));
            let _ = fs::remove_file(out_dir.join("management-cidrs.txt"));
            return Ok(false);
        }
        Err(err) => return Err(err).context("inspect committed network supersession"),
    }

    let durable_bytes = read_bounded_nofollow(
        &control_dir.join("provisioning-state.json"),
        512 * 1024,
        "durable provisioning state",
    )?;
    let durable: DurableProvisioningState =
        serde_json::from_slice(&durable_bytes).context("parse durable provisioning state")?;
    let trusted_keys = load_trusted_key_b64s(
        provisioning_keys_path,
        &durable.management_signing_public_key_b64,
        true,
    )?;
    let bytes = read_bounded_nofollow(
        &supersession_path,
        MAX_BYTES,
        "committed network supersession",
    )?;
    let raw: Value = serde_json::from_slice(&bytes).context("parse committed supersession")?;
    let doc =
        verify_supersession_value_any_key(&raw, &trusted_keys, &durable.plan, false, Utc::now())?;

    ensure_runtime_network_dir(out_dir)?;
    let netplan = crate::provisioning::render_netplan_for_plan(&doc.network, &durable.plan);
    let netplan_bytes = serde_json::to_vec(&netplan)?;
    atomic_write_root(
        &out_dir.join("netplan-approved.json"),
        &netplan_bytes,
        0o600,
        0,
    )?;
    let cidrs_body = format!("{}\n", doc.management_cidrs.join("\n"));
    atomic_write_root(
        &out_dir.join("management-cidrs.txt"),
        cidrs_body.as_bytes(),
        0o640,
        985,
    )?;
    Ok(true)
}

fn ensure_runtime_network_dir(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if !meta.file_type().is_dir() {
                bail!("{} must be a directory", dir.display());
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        Err(err) => return Err(err).with_context(|| format!("inspect {}", dir.display())),
    }
    if unsafe { libc::geteuid() } == 0 {
        let dir_fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(dir)?;
        use std::os::fd::AsRawFd;
        if unsafe { libc::fchown(dir_fd.as_raw_fd(), 0, 985) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o750))?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingRevertMeta {
    revision: i64,
    applied_revision: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplyOutcome {
    Complete,
    RetryLater,
}

struct ReconfigureLockGuard(File);

impl Drop for ReconfigureLockGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn acquire_reconfigure_lock(runtime_dir: &Path) -> Result<ReconfigureLockGuard> {
    use std::os::fd::AsRawFd;
    ensure_runtime_network_dir(runtime_dir)?;
    let path = runtime_dir.join(RECONFIGURE_LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file()
        || meta.nlink() != 1
        || (unsafe { libc::geteuid() } == 0 && meta.uid() != 0)
    {
        bail!("network reconfiguration lock file is unsafe");
    }
    if unsafe { libc::geteuid() } == 0 {
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("lock {}", path.display()));
    }
    Ok(ReconfigureLockGuard(file))
}

fn mark_retry_pending(runtime_dir: &Path) {
    if ensure_runtime_network_dir(runtime_dir).is_ok() {
        let _ = atomic_write_root(&runtime_dir.join(RETRY_PENDING_FILE), b"1\n", 0o600, 0);
    }
}

fn clear_retry_pending(runtime_dir: &Path) {
    let _ = fs::remove_file(runtime_dir.join(RETRY_PENDING_FILE));
}

fn mark_pxe_restart_pending(runtime_dir: &Path) {
    if ensure_runtime_network_dir(runtime_dir).is_ok() {
        let _ = atomic_write_root(
            &runtime_dir.join(PXE_RESTART_PENDING_FILE),
            b"1\n",
            0o600,
            0,
        );
    }
}

fn clear_pxe_restart_pending(runtime_dir: &Path) {
    let _ = fs::remove_file(runtime_dir.join(PXE_RESTART_PENDING_FILE));
}

/// Root execution entry point (`tiaris-nest-bootstrap apply-network-reconfigure`).
pub fn apply_reconfiguration_as_root(
    inbox_path: &Path,
    control_dir: &Path,
    status_path: &Path,
) -> Result<()> {
    let runtime_dir = Path::new(EFFECTIVE_NETWORK_DIR);
    // Recover any interrupted candidate left behind by a prior hard crash or kill.
    recover_interrupted_reconfiguration_in(runtime_dir, control_dir, status_path)?;
    drain_reconfiguration_with(
        runtime_dir,
        Duration::from_secs(MAX_DRAIN_START_ELAPSED_SECONDS),
        || read_inbox_bytes(inbox_path),
        |raw_bytes| {
            apply_one_reconfiguration(inbox_path, raw_bytes, control_dir, runtime_dir, status_path)
        },
        || converge_committed_network(control_dir),
    )
}

fn drain_reconfiguration_with<FR, FA, FC>(
    runtime_dir: &Path,
    max_drain_elapsed: Duration,
    mut read_inbox_fn: FR,
    mut apply_one_fn: FA,
    mut converge_fn: FC,
) -> Result<()>
where
    FR: FnMut() -> Result<Option<Vec<u8>>>,
    FA: FnMut(&[u8]) -> Result<ApplyOutcome>,
    FC: FnMut() -> Result<()>,
{
    let started = Instant::now();
    let mut last_processed_inbox: Option<Vec<u8>> = None;
    let mut needs_retry = false;
    for iteration in 0..MAX_APPLY_ITERATIONS {
        if iteration > 0 && started.elapsed() >= max_drain_elapsed {
            needs_retry = true;
            break;
        }
        if let Some(raw_bytes) = read_inbox_fn()? {
            if last_processed_inbox.as_deref() != Some(raw_bytes.as_slice()) {
                match apply_one_fn(&raw_bytes)? {
                    ApplyOutcome::Complete => {
                        last_processed_inbox = Some(raw_bytes);
                    }
                    ApplyOutcome::RetryLater => {
                        needs_retry = true;
                        break;
                    }
                }
            }
        }
        // Check if Manage delivered a newer inbox document while we were
        // applying BEFORE draining unfinished prior convergence, so a valid
        // repair is never blocked behind a failing prior commit.
        let inbox_now = read_inbox_fn()?;
        if inbox_now.is_some() && inbox_now != last_processed_inbox {
            if iteration + 1 >= MAX_APPLY_ITERATIONS {
                needs_retry = true;
                break;
            }
            continue;
        }
        // Inbox is quiet. Drain any unfinished post-commit convergence from an
        // earlier commit (e.g. if a newer revision was rejected/reverted or the
        // inbox was empty), then re-check the inbox in case a repair arrived
        // while convergence ran (systemd drops PathChanged while this oneshot
        // is active).
        if runtime_dir.join(PXE_RESTART_PENDING_FILE).exists() {
            if let Err(err) = converge_fn() {
                mark_retry_pending(runtime_dir);
                return Err(err);
            }
            let inbox_after_converge = read_inbox_fn()?;
            if inbox_after_converge.is_some() && inbox_after_converge != last_processed_inbox {
                if iteration + 1 >= MAX_APPLY_ITERATIONS {
                    needs_retry = true;
                    break;
                }
                continue;
            }
        }
        break;
    }
    if needs_retry || runtime_dir.join(PXE_RESTART_PENDING_FILE).exists() {
        mark_retry_pending(runtime_dir);
    } else {
        clear_retry_pending(runtime_dir);
    }
    Ok(())
}

/// Recovery handler (`tiaris-nest-bootstrap recover-network-reconfigure`), wired
/// as `ExecStopPost=` on `tiaris-nest-network-reconfigure.service`.
///
/// If a prior run was killed or timed out after activating a candidate Netplan
/// and before committing `control/network-supersession.json`, this restores the
/// snapshotted previous Netplan immediately so the Nest cannot be left stranded.
/// If the durable commit already landed before the kill, it skips the revert
/// and finishes post-commit convergence instead.
pub fn recover_interrupted_reconfiguration_as_root(
    control_dir: &Path,
    status_path: &Path,
) -> Result<()> {
    recover_interrupted_reconfiguration_in(
        Path::new(EFFECTIVE_NETWORK_DIR),
        control_dir,
        status_path,
    )
}

fn committed_supersession_revision_best_effort(
    control_dir: &Path,
    provisioning_keys_path: &Path,
) -> Option<i64> {
    let durable_bytes = read_bounded_nofollow(
        &control_dir.join("provisioning-state.json"),
        512 * 1024,
        "durable provisioning state",
    )
    .ok()?;
    let durable: DurableProvisioningState = serde_json::from_slice(&durable_bytes).ok()?;
    let trusted_keys = load_trusted_key_b64s(
        provisioning_keys_path,
        &durable.management_signing_public_key_b64,
        true,
    )
    .ok()?;
    load_current_supersession_revision(control_dir, &durable, &trusted_keys)
        .ok()
        .flatten()
}

fn recover_interrupted_reconfiguration_in(
    runtime_dir: &Path,
    control_dir: &Path,
    status_path: &Path,
) -> Result<()> {
    recover_interrupted_reconfiguration_with(
        runtime_dir,
        control_dir,
        Path::new(PROVISIONING_KEYS_PATH),
        Path::new(ACTIVE_NETPLAN),
        status_path,
        run_netplan_activate,
        || converge_committed_network(control_dir),
        || {
            let _ = Command::new("/usr/lib/tiaris-nest/tiaris-nest-network-runtime").status();
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn recover_interrupted_reconfiguration_with<FA, FC, FR>(
    runtime_dir: &Path,
    control_dir: &Path,
    provisioning_keys_path: &Path,
    active_netplan_path: &Path,
    status_path: &Path,
    mut activate_fn: FA,
    mut converge_fn: FC,
    mut refresh_runtime_fn: FR,
) -> Result<()>
where
    FA: FnMut() -> Result<()>,
    FC: FnMut() -> Result<()>,
    FR: FnMut(),
{
    let pending_yaml = runtime_dir.join(PENDING_REVERT_YAML);
    let pending_meta = runtime_dir.join(PENDING_REVERT_META);
    match fs::symlink_metadata(&pending_yaml) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let _ = fs::remove_file(&pending_meta);
            return Ok(());
        }
        Err(err) => {
            mark_retry_pending(runtime_dir);
            return Err(err).context("inspect pending revert Netplan");
        }
    }
    let lock = acquire_reconfigure_lock(runtime_dir)?;
    let previous = match read_bounded_nofollow(&pending_yaml, 1024 * 1024, "pending revert Netplan")
    {
        Ok(bytes) => bytes,
        Err(err) => {
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::NotFound)
            {
                let _ = fs::remove_file(&pending_meta);
                return Ok(());
            }
            mark_retry_pending(runtime_dir);
            return Err(err).context("read pending revert Netplan");
        }
    };
    let meta: Option<PendingRevertMeta> =
        read_bounded_nofollow(&pending_meta, 4096, "pending meta")
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());

    // If the durable supersession commit already succeeded before the kill,
    // never roll back the live network or record a spurious "reverted" outcome:
    // mark retry-pending + pxe-restart-pending BEFORE dropping the rollback
    // journal so a kill during convergence is still retried automatically.
    if let Some(meta) = meta.as_ref() {
        if let Some(committed) =
            committed_supersession_revision_best_effort(control_dir, provisioning_keys_path)
        {
            if committed >= meta.revision {
                mark_retry_pending(runtime_dir);
                mark_pxe_restart_pending(runtime_dir);
                let _ = fs::remove_file(&pending_yaml);
                let _ = fs::remove_file(&pending_meta);
                drop(lock);
                if let Err(err) = converge_fn() {
                    write_status(
                        status_path,
                        meta.revision,
                        Some(committed),
                        "pending",
                        Some(&format!("post-commit service convergence pending: {err}")),
                    )?;
                    return Err(err);
                }
                write_status(status_path, meta.revision, Some(committed), "applied", None)?;
                if runtime_dir.join(PXE_RESTART_PENDING_FILE).exists() {
                    mark_retry_pending(runtime_dir);
                } else {
                    clear_retry_pending(runtime_dir);
                }
                return Ok(());
            }
        }
    }

    let restore_result =
        atomic_write_root(active_netplan_path, &previous, 0o600, 0).and_then(|()| activate_fn());
    if let Err(err) = restore_result {
        // Retain pending-revert.yaml/.json until the previous profile actually
        // activates so a subsequent retry can finish restoring the network.
        mark_retry_pending(runtime_dir);
        if let Some(meta) = meta {
            let reason = format!(
                "network reconfiguration was interrupted and automatic revert is retrying ({err})"
            );
            write_status(
                status_path,
                meta.revision,
                meta.applied_revision,
                "pending",
                Some(&reason),
            )?;
        }
        return Err(err).context("revert interrupted candidate Netplan");
    }

    if let Some(meta) = meta {
        let report = match record_terminal_outcome(
            control_dir,
            meta.revision,
            meta.applied_revision,
            "reverted",
            Some(
                "network reconfiguration was interrupted while testing the candidate network; reverted to previous network",
            ),
        ) {
            Ok(report) => report,
            Err(err) => {
                mark_retry_pending(runtime_dir);
                return Err(err);
            }
        };
        if let Err(err) = write_report(status_path, &report) {
            mark_retry_pending(runtime_dir);
            return Err(err);
        }
    }
    let _ = fs::remove_file(&pending_yaml);
    let _ = fs::remove_file(&pending_meta);
    // Never clear retry-pending while an earlier committed revision still has
    // unfinished post-commit convergence (pxe-restart-pending), so the retry
    // timer drains that prior commit after this interrupted candidate reverts.
    if runtime_dir.join(PXE_RESTART_PENDING_FILE).exists() {
        mark_retry_pending(runtime_dir);
    } else {
        clear_retry_pending(runtime_dir);
    }
    drop(lock);
    refresh_runtime_fn();
    Ok(())
}

fn read_inbox_bytes(inbox_path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(inbox_path) {
        Ok(meta) => {
            if !meta.file_type().is_file()
                || meta.nlink() != 1
                || meta.len() == 0
                || meta.len() > MAX_BYTES
                || (meta.uid() != 0 && meta.uid() != 985)
                || (meta.mode() & 0o077) != 0
            {
                bail!("network reconfiguration inbox file is unsafe");
            }
            Ok(Some(read_bounded_nofollow(
                inbox_path,
                MAX_BYTES,
                "network reconfiguration inbox",
            )?))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).context("inspect network reconfiguration inbox"),
    }
}

fn acquire_reconfigure_lease(control_dir: &Path) -> Result<Option<crate::maintenance::BuildLease>> {
    if !crate::appliance::nixos::is_nixos() {
        return Ok(None);
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if crate::maintenance::generation_recovery_pending(control_dir) {
            return Ok(None);
        }
        if let Some(lease) = crate::maintenance::try_exclusive()? {
            return Ok(Some(lease));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn apply_one_reconfiguration(
    _inbox_path: &Path,
    raw_bytes: &[u8],
    control_dir: &Path,
    runtime_dir: &Path,
    status_path: &Path,
) -> Result<ApplyOutcome> {
    let durable_bytes = read_bounded_nofollow(
        &control_dir.join("provisioning-state.json"),
        512 * 1024,
        "durable provisioning state",
    )?;
    let durable: DurableProvisioningState =
        serde_json::from_slice(&durable_bytes).context("parse durable provisioning state")?;
    let origin = effective_manage_origin(&durable.manage_origin)
        .ok_or_else(|| anyhow!("durable Management origin is not served by this build"))?;
    let committed_keys = load_trusted_key_b64s(
        Path::new(PROVISIONING_KEYS_PATH),
        &durable.management_signing_public_key_b64,
        true,
    )?;
    let incoming_keys = load_trusted_key_b64s(
        Path::new(PROVISIONING_KEYS_PATH),
        &durable.management_signing_public_key_b64,
        false,
    )?;

    // Consistent with boot fallback: a corrupt or unverifiable optional
    // control/network-supersession.json must never block Manage from delivering
    // a fresh signed supersession to heal the appliance.
    let current_revision = match load_current_supersession_revision(
        control_dir,
        &durable,
        &committed_keys,
    ) {
        Ok(rev) => rev,
        Err(err) => {
            eprintln!(
                "tiaris-nest-bootstrap: ignoring unverifiable committed network supersession ({err}); allowing fresh signed supersession"
            );
            None
        }
    };
    let last_outcome = load_last_outcome(control_dir);

    let raw_value: Value = match serde_json::from_slice(raw_bytes) {
        Ok(val) => val,
        Err(err) => {
            eprintln!(
                "tiaris-nest-bootstrap: ignoring malformed network reconfiguration inbox JSON ({err})"
            );
            return Ok(ApplyOutcome::Complete);
        }
    };
    let requested_revision = raw_value
        .get("revision")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    // Verify signature, identity binding, network, and CIDRs WITHOUT expiry first
    // so an already-committed supersession never flips to "rejected: expired"
    // after 7 days on reboot, and already-handled terminal outcomes are not retried.
    // Brand-new revisions must verify against the shipped rotated key list so key
    // rotation can revoke retired keys; already-committed revisions may still match
    // the install-time key for idempotent convergence.
    let now = Utc::now();
    let doc = match verify_supersession_value_any_key(
        &raw_value,
        &incoming_keys,
        &durable.plan,
        false,
        now,
    ) {
        Ok(doc) => doc,
        Err(err) => {
            let committed_match = verify_supersession_value_any_key(
                &raw_value,
                &committed_keys,
                &durable.plan,
                false,
                now,
            )
            .ok()
            .filter(|doc| current_revision.is_some_and(|applied| doc.revision <= applied));
            if let Some(doc) = committed_match {
                doc
            } else {
                if requested_revision > 0 {
                    if current_revision.is_some_and(|applied| requested_revision <= applied) {
                        return Ok(ApplyOutcome::Complete);
                    }
                    write_status(
                        status_path,
                        requested_revision,
                        current_revision,
                        "rejected",
                        Some(&err.to_string()),
                    )?;
                }
                return Ok(ApplyOutcome::Complete);
            }
        }
    };

    // Already committed: re-run idempotent post-commit convergence steps so any
    // earlier transient firewall/runtime failure is healed before reporting applied.
    if let Some(applied) = current_revision {
        if doc.revision <= applied {
            if let Err(err) = converge_committed_network(control_dir) {
                mark_retry_pending(runtime_dir);
                mark_pxe_restart_pending(runtime_dir);
                write_status(
                    status_path,
                    doc.revision,
                    Some(applied),
                    "pending",
                    Some(&format!("post-commit service convergence pending: {err}")),
                )?;
                return Err(err);
            }
            write_status(status_path, doc.revision, Some(applied), "applied", None)?;
            return Ok(ApplyOutcome::Complete);
        }
    }

    // Already handled as terminal (`reverted` or `rejected`): re-project the
    // durable outcome without re-applying the failed network on reboot.
    if let Some(last) = last_outcome {
        if doc.revision <= last.revision && matches!(last.status.as_str(), "reverted" | "rejected")
        {
            write_report(status_path, &last)?;
            return Ok(ApplyOutcome::Complete);
        }
    }

    // Enforce expiry only for genuinely new revisions that have not been applied or handled.
    if now > doc.expires_at {
        let report = record_terminal_outcome(
            control_dir,
            doc.revision,
            current_revision,
            "rejected",
            Some("network supersession has expired"),
        )?;
        write_report(status_path, &report)?;
        return Ok(ApplyOutcome::Complete);
    }

    // Transient system-update or build-busy conditions keep status "pending"
    // and schedule an automatic retry instead of permanently rejecting the change.
    if crate::maintenance::generation_recovery_pending(control_dir) {
        write_status(
            status_path,
            doc.revision,
            current_revision,
            "pending",
            Some("waiting for system update recovery to finish before applying network change"),
        )?;
        return Ok(ApplyOutcome::RetryLater);
    }

    let _lease = if crate::appliance::nixos::is_nixos() {
        match acquire_reconfigure_lease(control_dir)? {
            Some(lease) => Some(lease),
            None => {
                write_status(
                    status_path,
                    doc.revision,
                    current_revision,
                    "pending",
                    Some(
                        "waiting for active build or maintenance to finish before applying network change",
                    ),
                )?;
                return Ok(ApplyOutcome::RetryLater);
            }
        }
    } else {
        None
    };

    // Pre-validate candidate management CIDRs with nft --check BEFORE switching live network.
    if let Err(err) = prevalidate_firewall_cidrs(control_dir, &doc.management_cidrs) {
        let report = record_terminal_outcome(
            control_dir,
            doc.revision,
            current_revision,
            "rejected",
            Some(&format!(
                "candidate management CIDRs failed firewall validation: {err}"
            )),
        )?;
        write_report(status_path, &report)?;
        return Ok(ApplyOutcome::Complete);
    }

    write_status(status_path, doc.revision, current_revision, "pending", None)?;

    // Acquire the shared network-reconfigure flock BEFORE snapshotting or touching
    // the live link so an in-flight network-runtime timer cannot race candidate activation.
    let net_lock = acquire_reconfigure_lock(runtime_dir)?;

    // Snapshot the ACTUAL active Netplan (preserving DHCP fallback if active)
    // and persist the recovery marker BEFORE touching the live link so any
    // kill/timeout/crash is automatically reverted by ExecStopPost or next start.
    let previous_netplan = snapshot_active_netplan(control_dir)?;
    let pending_yaml = runtime_dir.join(PENDING_REVERT_YAML);
    let pending_meta = runtime_dir.join(PENDING_REVERT_META);
    atomic_write_root(&pending_yaml, &previous_netplan, 0o600, 0)?;
    let meta_bytes = serde_json::to_vec(&PendingRevertMeta {
        revision: doc.revision,
        applied_revision: current_revision,
    })?;
    atomic_write_root(&pending_meta, &meta_bytes, 0o600, 0)?;

    let candidate_netplan =
        crate::provisioning::render_netplan_for_plan(&doc.network, &durable.plan);
    let candidate_bytes = serde_json::to_vec(&candidate_netplan)?;

    let activated = atomic_write_root(Path::new(ACTIVE_NETPLAN), &candidate_bytes, 0o600, 0)
        .and_then(|()| run_netplan_activate());

    let probe_start = Instant::now();
    let candidate_ip = if activated.is_ok() {
        wait_for_candidate_ipv4(
            &durable.plan.network_interface.name,
            &doc.network,
            Duration::from_secs(ADDRESS_WAIT_SECONDS),
        )
    } else {
        None
    };

    let reachable = if let Some(ip) = candidate_ip {
        let remaining =
            Duration::from_secs(PROBE_DEADLINE_SECONDS).saturating_sub(probe_start.elapsed());
        let budget = remaining.max(Duration::from_secs(30));
        probe_manage_reachable(origin, Some(ip), budget)
    } else {
        false
    };

    if !reachable {
        // Automatic revert to the snapshotted active network.
        let restore_result =
            atomic_write_root(Path::new(ACTIVE_NETPLAN), &previous_netplan, 0o600, 0)
                .and_then(|()| run_netplan_activate());
        if let Err(restore_err) = restore_result {
            // Keep pending-revert.yaml/.json intact so recovery retries until
            // the previous network actually activates.
            mark_retry_pending(runtime_dir);
            let reason = format!(
                "candidate network failed and automatic revert is retrying ({restore_err})"
            );
            write_status(
                status_path,
                doc.revision,
                current_revision,
                "pending",
                Some(&reason),
            )?;
            return Err(restore_err).context("revert active Netplan after failed reconfiguration");
        }
        let recovered = probe_manage_reachable(
            origin,
            None,
            Duration::from_secs(REVERT_PROBE_DEADLINE_SECONDS),
        );
        let reason = match (&activated, candidate_ip, recovered) {
            (Err(err), _, true) => {
                format!("candidate network failed to activate ({err}); reverted to previous network")
            }
            (Ok(()), None, true) => {
                "candidate IPv4 address or route did not become active on the managed interface; reverted to previous network".to_string()
            }
            (Ok(()), Some(_), true) => {
                "Manage could not be reached from the candidate network within 90 seconds; reverted to previous network".to_string()
            }
            (_, _, false) => {
                "candidate network could not reach Manage; restored previous network profile (Manage recovery pending)".to_string()
            }
        };
        let report = match record_terminal_outcome(
            control_dir,
            doc.revision,
            current_revision,
            "reverted",
            Some(&reason),
        ) {
            Ok(report) => report,
            Err(err) => {
                mark_retry_pending(runtime_dir);
                return Err(err);
            }
        };
        if let Err(err) = write_report(status_path, &report) {
            mark_retry_pending(runtime_dir);
            return Err(err);
        }
        let _ = fs::remove_file(&pending_yaml);
        let _ = fs::remove_file(&pending_meta);
        drop(net_lock);
        let _ = Command::new("/usr/lib/tiaris-nest/tiaris-nest-network-runtime").status();
        return Ok(ApplyOutcome::Complete);
    }

    // Single atomic durable commit: control/network-supersession.json.
    // control/netplan-approved.json and control/management-cidrs.txt remain
    // unchanged so predecessor generation rollbacks validate cleanly.
    let supersession_bytes = serde_json::to_vec(&raw_value)?;
    if let Err(commit_err) = atomic_write_root(
        &control_dir.join(SUPERSESSION_FILE),
        &supersession_bytes,
        0o600,
        0,
    ) {
        mark_retry_pending(runtime_dir);
        let restore_result =
            atomic_write_root(Path::new(ACTIVE_NETPLAN), &previous_netplan, 0o600, 0)
                .and_then(|()| run_netplan_activate());
        if restore_result.is_ok() {
            let _ = fs::remove_file(&pending_yaml);
            let _ = fs::remove_file(&pending_meta);
            drop(net_lock);
            let _ = Command::new("/usr/lib/tiaris-nest/tiaris-nest-network-runtime").status();
        }
        let _ = write_status(
            status_path,
            doc.revision,
            current_revision,
            "pending",
            Some(&format!(
                "could not save committed network change; retrying ({commit_err})"
            )),
        );
        return Err(commit_err).context("commit durable network supersession");
    }
    let _ = fs::remove_file(control_dir.join("network-fallback-active"));
    let _ = fs::remove_file(control_dir.join(LAST_OUTCOME_FILE));
    let _ = File::open(control_dir).and_then(|d| d.sync_all());
    // Candidate is now durably committed. Write retry-pending and
    // pxe-restart-pending BEFORE deleting the rollback journal so a kill
    // anywhere during post-commit convergence is automatically retried and
    // PXE never misses a restart.
    mark_retry_pending(runtime_dir);
    mark_pxe_restart_pending(runtime_dir);
    let _ = fs::remove_file(&pending_yaml);
    let _ = fs::remove_file(&pending_meta);
    drop(net_lock);

    if let Err(err) = converge_committed_network(control_dir) {
        write_status(
            status_path,
            doc.revision,
            Some(doc.revision),
            "pending",
            Some(&format!("post-commit service convergence pending: {err}")),
        )?;
        return Err(err);
    }

    write_status(
        status_path,
        doc.revision,
        Some(doc.revision),
        "applied",
        None,
    )?;
    Ok(ApplyOutcome::Complete)
}

fn converge_committed_network(control_dir: &Path) -> Result<()> {
    let mut last_err = None;
    for attempt in 0..CONVERGE_MAX_ATTEMPTS {
        match converge_committed_network_once(control_dir) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                if attempt + 1 < CONVERGE_MAX_ATTEMPTS {
                    std::thread::sleep(Duration::from_secs(CONVERGE_RETRY_DELAY_SECONDS));
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("post-commit network convergence failed")))
}

fn converge_committed_network_once(control_dir: &Path) -> Result<()> {
    let effective_dir = Path::new(EFFECTIVE_NETWORK_DIR);
    let effective_netplan_path = effective_dir.join("netplan-approved.json");
    let effective_cidrs_path = effective_dir.join("management-cidrs.txt");
    let prev_netplan =
        read_bounded_nofollow(&effective_netplan_path, 1024 * 1024, "prev netplan").ok();
    let prev_cidrs = read_bounded_nofollow(&effective_cidrs_path, 64 * 1024, "prev cidrs").ok();

    let materialized = materialize_effective_network(
        control_dir,
        effective_dir,
        Path::new(PROVISIONING_KEYS_PATH),
    )
    .context("materialize effective network projections")?;

    if materialized {
        let effective_bytes = read_bounded_nofollow(
            &effective_netplan_path,
            1024 * 1024,
            "effective approved Netplan",
        )?;
        let new_cidrs =
            read_bounded_nofollow(&effective_cidrs_path, 64 * 1024, "effective cidrs").ok();
        if prev_netplan.as_deref() != Some(effective_bytes.as_slice()) || prev_cidrs != new_cidrs {
            mark_pxe_restart_pending(effective_dir);
        }
        // Respect tiaris-nest-network-guard's active DHCP fallback on boot:
        // never overwrite a verified DHCP rescue profile with an unreachable
        // committed static profile, and propagate errors instead of failing open
        // on a corrupt fallback marker. (Live commits remove network-fallback-active
        // above before calling converge_committed_network.)
        let fallback_active =
            crate::provisioning::fallback_marker_matches_bytes(control_dir, &effective_bytes)
                .context("inspect Nest network fallback marker before convergence")?;
        if !fallback_active {
            let active_matches =
                read_bounded_nofollow(Path::new(ACTIVE_NETPLAN), 1024 * 1024, "active Netplan")
                    .ok()
                    .is_some_and(|active| active == effective_bytes);
            if !active_matches {
                atomic_write_root(Path::new(ACTIVE_NETPLAN), &effective_bytes, 0o600, 0)?;
                mark_pxe_restart_pending(effective_dir);
            }
            // Invoke the activator idempotently (without FORCE_RELOAD): when
            // ACTIVE_NETPLAN and .applied-sha256 already match, it is a fast
            // no-op; if a previous attempt wrote ACTIVE_NETPLAN and failed
            // during networkctl reload, the missing stamp forces activation.
            run_checked_cmd("/usr/lib/tiaris-nest/tiaris-nest-netplan-activate", &[])?;
        }
    }

    run_checked_cmd("/usr/lib/tiaris-nest/tiaris-nest-firewall", &[])?;
    // The network-runtime wrapper updates config.toml and queues
    // try-restart tiaris-nest.service plus starts tiaris-nest-assist-turn.service.
    run_checked_cmd("/usr/lib/tiaris-nest/tiaris-nest-network-runtime", &[])?;
    // Restart PXE whenever projections or active Netplan changed (persisted across
    // retry attempts via pxe-restart-pending), while skipping spurious PXE restarts
    // on steady-state boots already converged by network-render/first-boot.
    if effective_dir.join(PXE_RESTART_PENDING_FILE).exists() {
        run_checked_cmd(
            "systemctl",
            &["--no-block", "try-restart", "tiaris-nest-pxe.service"],
        )?;
        run_checked_cmd(
            "systemctl",
            &["--no-block", "start", "tiaris-nest-assist-turn.service"],
        )?;
        clear_pxe_restart_pending(effective_dir);
    }
    Ok(())
}

fn load_last_outcome(control_dir: &Path) -> Option<Report> {
    let bytes =
        read_bounded_nofollow(&control_dir.join(LAST_OUTCOME_FILE), 8192, "last outcome").ok()?;
    let report: Report = serde_json::from_slice(&bytes).ok()?;
    if report.schema != REPORT_SCHEMA || report.revision <= 0 {
        return None;
    }
    Some(report)
}

fn record_terminal_outcome(
    control_dir: &Path,
    revision: i64,
    applied_revision: Option<i64>,
    status: &str,
    error: Option<&str>,
) -> Result<Report> {
    let report = Report {
        schema: REPORT_SCHEMA.to_string(),
        revision,
        applied_revision,
        status: status.to_string(),
        error: error.map(|e| e.trim().chars().take(240).collect()),
        checked_at: Utc::now(),
    };
    let mut body = serde_json::to_vec(&report)?;
    body.push(b'\n');
    atomic_write_root(&control_dir.join(LAST_OUTCOME_FILE), &body, 0o600, 0)?;
    Ok(report)
}

fn snapshot_active_netplan(control_dir: &Path) -> Result<Vec<u8>> {
    for (path, label) in [
        (Path::new(ACTIVE_NETPLAN), "active Netplan"),
        (
            &Path::new(EFFECTIVE_NETWORK_DIR).join("netplan-approved.json"),
            "effective approved Netplan",
        ),
        (
            &control_dir.join("netplan-approved.json"),
            "approved Netplan",
        ),
    ] {
        match read_bounded_nofollow(path, 1024 * 1024, label) {
            Ok(bytes) => return Ok(bytes),
            Err(_) => continue,
        }
    }
    bail!("no active or approved Netplan found to snapshot before reconfiguration")
}

fn prevalidate_firewall_cidrs(control_dir: &Path, cidrs: &[String]) -> Result<()> {
    let tmp = control_dir.join(format!(".firewall-check-{}.tmp", Uuid::new_v4().simple()));
    let body = format!("{}\n", cidrs.join("\n"));
    let write_res = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&tmp)?;
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    let check_res = run_checked_cmd(
        "/usr/lib/tiaris-nest/tiaris-nest-firewall",
        &["--check-file", &tmp.to_string_lossy()],
    );
    let _ = fs::remove_file(&tmp);
    check_res
}

fn run_checked_cmd(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("run {program}"))?;
    if !status.success() {
        bail!("{program} exited with {status}");
    }
    Ok(())
}

fn load_current_supersession_revision(
    control_dir: &Path,
    durable: &DurableProvisioningState,
    trusted_keys: &[String],
) -> Result<Option<i64>> {
    let path = control_dir.join(SUPERSESSION_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_bounded_nofollow(&path, MAX_BYTES, "committed network supersession")?;
            let raw: Value = serde_json::from_slice(&bytes)?;
            let doc = verify_supersession_value_any_key(
                &raw,
                trusted_keys,
                &durable.plan,
                false,
                Utc::now(),
            )?;
            Ok(Some(doc.revision))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).context("inspect committed network supersession"),
    }
}

fn run_netplan_activate() -> Result<()> {
    let status = Command::new("/usr/lib/tiaris-nest/tiaris-nest-netplan-activate")
        .env("TIARIS_NETWORK_FORCE_RELOAD", "1")
        .status()
        .context("run /usr/lib/tiaris-nest/tiaris-nest-netplan-activate")?;
    if !status.success() {
        bail!("/usr/lib/tiaris-nest/tiaris-nest-netplan-activate exited with {status}");
    }
    Ok(())
}

fn is_valid_manage_health_body(body: &[u8]) -> bool {
    if body.is_empty() || body.len() > 16 * 1024 {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    value.get("status").and_then(Value::as_str) == Some("ok")
        && value.get("service").and_then(Value::as_str) == Some("tiaris")
}

fn select_candidate_ipv4_from_ip_json(
    stdout: &[u8],
    network: &NestProvisioningNetworkPlan,
) -> Option<Ipv4Addr> {
    let devices: Value = serde_json::from_slice(stdout).ok()?;
    let expected_static: Option<(Ipv4Addr, u8)> = if network.mode == "static" {
        network
            .address_cidr
            .as_deref()
            .and_then(|cidr| cidr.split_once('/'))
            .and_then(|(addr, prefix)| {
                Some((addr.parse::<Ipv4Addr>().ok()?, prefix.parse::<u8>().ok()?))
            })
    } else {
        None
    };
    for dev in devices.as_array()? {
        let Some(infos) = dev.get("addr_info").and_then(Value::as_array) else {
            continue;
        };
        for info in infos {
            if info.get("family").and_then(Value::as_str) != Some("inet")
                || info.get("scope").and_then(Value::as_str) != Some("global")
            {
                continue;
            }
            let has_disallowed_flag = ["tentative", "dadfailed", "deprecated", "secondary"]
                .iter()
                .any(|flag| info.get(*flag).and_then(Value::as_bool) == Some(true))
                || info
                    .get("flags")
                    .and_then(Value::as_array)
                    .is_some_and(|flags| {
                        flags.iter().filter_map(Value::as_str).any(|flag| {
                            matches!(flag, "tentative" | "dadfailed" | "deprecated" | "secondary")
                        })
                    });
            if has_disallowed_flag {
                continue;
            }
            if info
                .get("preferred_life_time")
                .is_some_and(|v| v.as_u64() == Some(0) || v.as_str() == Some("0sec"))
            {
                continue;
            }
            let Some(local) = info
                .get("local")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
            else {
                continue;
            };
            if local.is_unspecified()
                || local.is_loopback()
                || local.is_link_local()
                || local.is_multicast()
                || local.is_broadcast()
            {
                continue;
            }
            if let Some((target, expected_prefix)) = expected_static {
                let prefixlen = info.get("prefixlen").and_then(Value::as_u64);
                if local == target && prefixlen == Some(u64::from(expected_prefix)) {
                    return Some(local);
                }
            } else {
                let is_dynamic = info.get("dynamic").and_then(Value::as_bool) == Some(true)
                    || info
                        .get("flags")
                        .and_then(Value::as_array)
                        .is_some_and(|flags| {
                            flags
                                .iter()
                                .filter_map(Value::as_str)
                                .any(|f| f == "dynamic")
                        });
                if is_dynamic {
                    return Some(local);
                }
            }
        }
    }
    None
}

fn has_expected_static_default_route_from_ip_json(stdout: &[u8], gateway: Ipv4Addr) -> bool {
    let Ok(routes) = serde_json::from_slice::<Value>(stdout) else {
        return false;
    };
    let Some(list) = routes.as_array() else {
        return false;
    };
    let gw_text = gateway.to_string();
    list.iter().any(|route| {
        route.get("dst").and_then(Value::as_str) == Some("default")
            && route.get("gateway").and_then(Value::as_str) == Some(gw_text.as_str())
    })
}

fn wait_for_candidate_ipv4(
    interface_name: &str,
    network: &NestProvisioningNetworkPlan,
    budget: Duration,
) -> Option<Ipv4Addr> {
    let expected_gateway = if network.mode == "static" {
        network
            .gateway
            .as_deref()
            .and_then(|g| g.parse::<Ipv4Addr>().ok())
    } else {
        None
    };
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if let Ok(output) = Command::new("ip")
            .args([
                "-j",
                "-4",
                "address",
                "show",
                "dev",
                interface_name,
                "scope",
                "global",
            ])
            .output()
        {
            if output.status.success() {
                if let Some(ip) = select_candidate_ipv4_from_ip_json(&output.stdout, network) {
                    if let Some(gw) = expected_gateway {
                        let route_ok = Command::new("ip")
                            .args([
                                "-j",
                                "-4",
                                "route",
                                "show",
                                "dev",
                                interface_name,
                                "default",
                            ])
                            .output()
                            .ok()
                            .is_some_and(|out| {
                                out.status.success()
                                    && has_expected_static_default_route_from_ip_json(
                                        &out.stdout,
                                        gw,
                                    )
                            });
                        if !route_ok {
                            std::thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                    }
                    return Some(ip);
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    None
}

fn probe_manage_reachable(origin: &str, source_ip: Option<Ipv4Addr>, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    let url = format!("{}/v1/health", origin.trim_end_matches('/'));
    let bind_ip = source_ip.map(|ip| ip.to_string());
    while Instant::now() < deadline {
        let mut cmd = Command::new("curl");
        cmd.args([
            "--fail",
            "--silent",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "5",
            "--max-time",
            "10",
            "--noproxy",
            "*",
        ]);
        if let Some(ip) = bind_ip.as_deref() {
            cmd.args(["--interface", ip]);
        }
        cmd.arg(&url);
        if let Ok(out) = cmd.output() {
            if out.status.success() && is_valid_manage_health_body(&out.stdout) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    false
}

fn write_status(
    path: &Path,
    revision: i64,
    applied_revision: Option<i64>,
    status: &str,
    error: Option<&str>,
) -> Result<()> {
    let report = Report {
        schema: REPORT_SCHEMA.to_string(),
        revision,
        applied_revision,
        status: status.to_string(),
        error: error.map(|e| e.trim().chars().take(240).collect()),
        checked_at: Utc::now(),
    };
    write_report(path, &report)
}

fn write_report(path: &Path, report: &Report) -> Result<()> {
    let mut body = serde_json::to_vec(report)?;
    body.push(b'\n');
    if let Some(parent) = path.parent() {
        ensure_runtime_network_dir(parent)?;
    }
    atomic_write_root(path, &body, 0o640, 985)
}

fn atomic_write_root(path: &Path, body: &[u8], mode: u32, gid: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("target path has no parent directory"))?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("target path has invalid filename"))?;
    let tmp = parent.join(format!(".{name}.{}.tmp", Uuid::new_v4().simple()));
    let res = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&tmp)?;
        if unsafe { libc::geteuid() } == 0 {
            use std::os::fd::AsRawFd;
            if unsafe { libc::fchown(file.as_raw_fd(), 0, gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        let _ = File::open(parent).and_then(|d| d.sync_all());
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provisioning::protocol::NestMaintenanceWindowPlan;
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn sample_plan() -> SignedInstallPlan {
        SignedInstallPlan {
            schema: "tiaris.nest.install-plan.v3".into(),
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            organization_slug: Some("demo".into()),
            plan_revision: 1,
            session_id: Uuid::new_v4(),
            session_revision: 1,
            inventory_sha256: "0".repeat(64),
            hardware_digest: "1".repeat(64),
            provisioning_public_key_fingerprint: "2".repeat(64),
            reserved_device_id: "nest-01".into(),
            display_name: "Nest 1".into(),
            target_disk_id: "scsi-1".into(),
            target_disk: crate::provisioning::NestProvisioningDisk {
                id: "scsi-1".into(),
                path: "/dev/sda".into(),
                model: "Disk".into(),
                serial: "S1".into(),
                wwn: String::new(),
                size_bytes: 200 * 1024 * 1024 * 1024,
                removable: false,
                mounted: false,
                held: false,
                eligible: true,
                blocker_codes: vec![],
            },
            network_interface: crate::provisioning::NestProvisioningEthernetInterface {
                id: "pci-0000:00:03.0".into(),
                name: "enp0s3".into(),
                mac: "52:54:00:12:34:56".into(),
                link_up: true,
                addresses: vec!["10.0.0.10/24".into()],
                gateway: Some("10.0.0.1".into()),
            },
            network: NestProvisioningNetworkPlan {
                mode: "dhcp".into(),
                interface_id: "pci-0000:00:03.0".into(),
                address_cidr: None,
                gateway: None,
                dns_servers: vec![],
            },
            maintenance_window: NestMaintenanceWindowPlan {
                timezone: "UTC".into(),
                weekday: 0,
                start: "02:00".into(),
                duration_minutes: 120,
            },
            management_cidrs: vec!["10.0.0.0/24".into()],
            ssh_ca_public_keys: vec![],
            base_os: "nixos".into(),
            base_os_version: "26.05".into(),
            release_version: "0.2.200".into(),
            at_rest_protection: "none".into(),
            package_delivery: None,
            appliance_release: None,
            package_transport_url: None,
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            plan_sha256: "3".repeat(64),
            signature: "sig".into(),
        }
    }

    fn sign_doc(key: &SigningKey, mut doc: Value) -> Value {
        let mut payload = DOMAIN.as_bytes().to_vec();
        payload.push(b'\n');
        // Sort keys canonically to match Manage's canonical_json_value.
        fn canonical(v: Value) -> Value {
            match v {
                Value::Object(map) => {
                    let mut keys: Vec<_> = map.keys().cloned().collect();
                    keys.sort();
                    let mut out = serde_json::Map::new();
                    for k in keys {
                        out.insert(k.clone(), canonical(map[&k].clone()));
                    }
                    Value::Object(out)
                }
                Value::Array(arr) => Value::Array(arr.into_iter().map(canonical).collect()),
                other => other,
            }
        }
        payload.extend(serde_json::to_vec(&canonical(doc.clone())).unwrap());
        let sig = URL_SAFE_NO_PAD.encode(key.sign(&payload).to_bytes());
        doc["signature"] = json!(sig);
        doc
    }

    #[test]
    fn supersession_verification_checks_signature_identity_and_expiry() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pub_b64 = STANDARD.encode(key.verifying_key().to_bytes());
        let plan = sample_plan();
        let now = Utc::now();
        let raw = sign_doc(
            &key,
            json!({
                "schema": SCHEMA,
                "organization_id": plan.organization_id,
                "device_id": plan.reserved_device_id,
                "device_incarnation_id": Uuid::new_v4(),
                "provisioning_session_id": plan.session_id,
                "revision": 1,
                "issued_at": now - chrono::Duration::minutes(5),
                "expires_at": now + chrono::Duration::days(7),
                "network": {
                    "mode": "static",
                    "interface_id": plan.network_interface.id,
                    "address_cidr": "10.20.30.40/24",
                    "gateway": "10.20.30.1",
                    "dns_servers": ["10.20.30.53", "1.1.1.1"]
                },
                "management_cidrs": ["10.20.30.0/24"]
            }),
        );
        let verified = verify_supersession_value(&raw, &pub_b64, &plan, true, now).unwrap();
        assert_eq!(verified.revision, 1);
        assert_eq!(verified.network.mode, "static");

        // Expired document rejected on apply (check_expiry=true) but accepted on boot (check_expiry=false).
        let later = now + chrono::Duration::days(30);
        assert!(verify_supersession_value(&raw, &pub_b64, &plan, true, later).is_err());
        assert!(verify_supersession_value(&raw, &pub_b64, &plan, false, later).is_ok());

        // Tampered CIDR fails signature check.
        let mut tampered = raw.clone();
        tampered["management_cidrs"] = json!(["0.0.0.0/0"]);
        assert!(verify_supersession_value(&tampered, &pub_b64, &plan, true, now).is_err());

        // Multi-key rotation: secondary trusted key validates cleanly.
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let other_pub = STANDARD.encode(other.verifying_key().to_bytes());
        assert!(
            verify_supersession_value_any_key(
                &raw,
                &[other_pub.clone(), pub_b64.clone()],
                &plan,
                true,
                now
            )
            .is_ok()
        );

        // Host bits, overlaps, /31, and broadcast addresses are rejected.
        assert!(validate_management_cidrs(&["192.168.1.20/24".into()]).is_err());
        assert!(validate_management_cidrs(&["10.0.0.0/8".into(), "10.0.1.0/24".into()]).is_err());
        assert!(validate_management_cidrs(&["10.0.0.0/24".into(), "10.0.1.0/24".into()]).is_ok());
        assert!(
            validate_network_plan(&NestProvisioningNetworkPlan {
                mode: "static".into(),
                interface_id: plan.network_interface.id.clone(),
                address_cidr: Some("10.20.30.1/31".into()),
                gateway: Some("10.20.30.0".into()),
                dns_servers: vec!["1.1.1.1".into()],
            })
            .is_err()
        );
        assert!(
            validate_network_plan(&NestProvisioningNetworkPlan {
                mode: "static".into(),
                interface_id: plan.network_interface.id.clone(),
                address_cidr: Some("10.20.30.255/24".into()),
                gateway: Some("10.20.30.1".into()),
                dns_servers: vec!["1.1.1.1".into()],
            })
            .is_err()
        );

        // Health probe rejects SPA HTML fallback and accepts Manage /v1/health JSON.
        assert!(!is_valid_manage_health_body(
            b"<!doctype html><html></html>"
        ));
        assert!(!is_valid_manage_health_body(
            br#"{"status":"degraded","service":"tiaris"}"#
        ));
        assert!(is_valid_manage_health_body(
            br#"{"status":"ok","service":"tiaris","version":"0.1.729"}"#
        ));
    }

    #[test]
    fn materialize_effective_network_keeps_control_files_immutable_for_rollback() {
        let root = std::env::temp_dir().join(format!("tiaris-net-mat-{}", Uuid::new_v4()));
        let control = root.join("control");
        let runtime = root.join("run");
        fs::create_dir_all(&control).unwrap();
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let pub_b64 = STANDARD.encode(key.verifying_key().to_bytes());
        let plan = sample_plan();
        let durable = DurableProvisioningState {
            schema: "tiaris.nest.provisioning-state.v1".into(),
            session_id: plan.session_id,
            manage_origin: crate::provisioning::REQUIRED_MANAGE_ORIGIN.into(),
            management_signing_public_key_b64: pub_b64.clone(),
            device_private_key_b64: "priv".into(),
            device_public_key_b64: "pub".into(),
            device_public_key_fingerprint: "fp".into(),
            next_event_sequence: 1,
            identity_active: true,
            installation_complete: true,
            updated_at: Utc::now(),
            plan: plan.clone(),
        };
        let orig_netplan = serde_json::to_vec(&crate::provisioning::render_netplan_for_plan(
            &plan.network,
            &plan,
        ))
        .unwrap();
        let orig_cidrs = b"10.0.0.0/24\n".to_vec();
        fs::write(
            control.join("provisioning-state.json"),
            serde_json::to_vec(&durable).unwrap(),
        )
        .unwrap();
        fs::write(control.join("netplan-approved.json"), &orig_netplan).unwrap();
        fs::write(control.join("management-cidrs.txt"), &orig_cidrs).unwrap();
        let keys_file = root.join("keys");
        fs::write(&keys_file, format!("{pub_b64}\n")).unwrap();

        // Without a supersession, nothing is materialized.
        assert!(!materialize_effective_network(&control, &runtime, &keys_file).unwrap());
        assert!(!runtime.join("netplan-approved.json").exists());

        // Commit single-file supersession and materialize into runtime dir.
        let now = Utc::now();
        let raw = sign_doc(
            &key,
            json!({
                "schema": SCHEMA,
                "organization_id": plan.organization_id,
                "device_id": plan.reserved_device_id,
                "device_incarnation_id": Uuid::new_v4(),
                "provisioning_session_id": plan.session_id,
                "revision": 1,
                "issued_at": now - chrono::Duration::minutes(5),
                "expires_at": now + chrono::Duration::days(7),
                "network": {
                    "mode": "static",
                    "interface_id": plan.network_interface.id,
                    "address_cidr": "10.20.30.40/24",
                    "gateway": "10.20.30.1",
                    "dns_servers": ["10.20.30.53"]
                },
                "management_cidrs": ["10.20.30.0/24"]
            }),
        );
        fs::write(
            control.join(SUPERSESSION_FILE),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();
        assert!(materialize_effective_network(&control, &runtime, &keys_file).unwrap());
        // Control files stay identical to original install plan (predecessor rollback safe!).
        assert_eq!(
            fs::read(control.join("netplan-approved.json")).unwrap(),
            orig_netplan
        );
        assert_eq!(
            fs::read(control.join("management-cidrs.txt")).unwrap(),
            orig_cidrs
        );
        // Runtime projections carry the superseded network & CIDRs.
        assert_eq!(
            fs::read_to_string(runtime.join("management-cidrs.txt")).unwrap(),
            "10.20.30.0/24\n"
        );
        let eff_netplan: Value =
            serde_json::from_slice(&fs::read(runtime.join("netplan-approved.json")).unwrap())
                .unwrap();
        assert_eq!(
            eff_netplan["network"]["ethernets"]["tiaris-nest"]["addresses"][0],
            "10.20.30.40/24"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn select_candidate_ipv4_matches_exact_static_or_dynamic_dhcp() {
        // Use real iproute2 `ip -j -4 address show` schema: address flags such as
        // `deprecated`, `secondary`, `tentative`, `dadfailed`, and `dynamic` are
        // top-level boolean properties on each addr_info entry (and also verify
        // compatibility with a `flags` array).
        let ip_json = br#"[
            {
                "ifname": "enp0s3",
                "addr_info": [
                    {"family": "inet", "local": "10.0.0.10", "prefixlen": 24, "scope": "global"},
                    {"family": "inet", "local": "10.20.30.40", "prefixlen": 24, "scope": "global"},
                    {"family": "inet", "local": "10.20.30.41", "prefixlen": 24, "scope": "global", "deprecated": true},
                    {"family": "inet", "local": "10.20.30.42", "prefixlen": 24, "scope": "global", "secondary": true, "dynamic": true},
                    {"family": "inet", "local": "10.20.30.43", "prefixlen": 24, "scope": "global", "flags": ["tentative"]},
                    {"family": "inet", "local": "192.168.50.77", "prefixlen": 24, "scope": "global", "dynamic": true}
                ]
            }
        ]"#;
        let static_ok = NestProvisioningNetworkPlan {
            mode: "static".into(),
            interface_id: "pci-0000:00:03.0".into(),
            address_cidr: Some("10.20.30.40/24".into()),
            gateway: Some("10.20.30.1".into()),
            dns_servers: vec!["1.1.1.1".into()],
        };
        assert_eq!(
            select_candidate_ipv4_from_ip_json(ip_json, &static_ok),
            Some(Ipv4Addr::new(10, 20, 30, 40))
        );
        // Same IP with a different prefix length must NOT match.
        let static_wrong_prefix = NestProvisioningNetworkPlan {
            address_cidr: Some("10.20.30.40/25".into()),
            ..static_ok.clone()
        };
        assert_eq!(
            select_candidate_ipv4_from_ip_json(ip_json, &static_wrong_prefix),
            None
        );
        // Deprecated, secondary, and tentative addresses are ignored.
        for bad_cidr in ["10.20.30.41/24", "10.20.30.42/24", "10.20.30.43/24"] {
            let candidate = NestProvisioningNetworkPlan {
                address_cidr: Some(bad_cidr.into()),
                ..static_ok.clone()
            };
            assert_eq!(
                select_candidate_ipv4_from_ip_json(ip_json, &candidate),
                None,
                "{bad_cidr} must be excluded"
            );
        }
        // Link-local gateway in a wide subnet is rejected.
        assert!(
            validate_network_plan(&NestProvisioningNetworkPlan {
                mode: "static".into(),
                interface_id: "pci-0000:00:03.0".into(),
                address_cidr: Some("169.255.0.10/8".into()),
                gateway: Some("169.254.1.1".into()),
                dns_servers: vec!["1.1.1.1".into()],
            })
            .is_err()
        );
        let static_missing = NestProvisioningNetworkPlan {
            address_cidr: Some("10.20.30.99/24".into()),
            ..static_ok.clone()
        };
        assert_eq!(
            select_candidate_ipv4_from_ip_json(ip_json, &static_missing),
            None
        );
        let dhcp = NestProvisioningNetworkPlan {
            mode: "dhcp".into(),
            interface_id: "pci-0000:00:03.0".into(),
            address_cidr: None,
            gateway: None,
            dns_servers: vec![],
        };
        assert_eq!(
            select_candidate_ipv4_from_ip_json(ip_json, &dhcp),
            Some(Ipv4Addr::new(192, 168, 50, 77))
        );

        let route_json = br#"[{"dst":"default","gateway":"10.20.30.1","dev":"enp0s3"}]"#;
        assert!(has_expected_static_default_route_from_ip_json(
            route_json,
            Ipv4Addr::new(10, 20, 30, 1)
        ));
        assert!(!has_expected_static_default_route_from_ip_json(
            route_json,
            Ipv4Addr::new(10, 20, 30, 254)
        ));
    }

    #[test]
    fn terminal_outcome_persists_across_reboots_and_prevents_replay() {
        let root = std::env::temp_dir().join(format!("tiaris-net-last-{}", Uuid::new_v4()));
        let control = root.join("control");
        let status_dir = root.join("run");
        fs::create_dir_all(&control).unwrap();
        let status_path = status_dir.join(STATUS_FILE);

        let key = SigningKey::from_bytes(&[13u8; 32]);
        let pub_b64 = STANDARD.encode(key.verifying_key().to_bytes());
        let plan = sample_plan();
        let durable = DurableProvisioningState {
            schema: "tiaris.nest.provisioning-state.v1".into(),
            session_id: plan.session_id,
            manage_origin: crate::provisioning::REQUIRED_MANAGE_ORIGIN.into(),
            management_signing_public_key_b64: pub_b64.clone(),
            device_private_key_b64: "priv".into(),
            device_public_key_b64: "pub".into(),
            device_public_key_fingerprint: "fp".into(),
            next_event_sequence: 1,
            identity_active: true,
            installation_complete: true,
            updated_at: Utc::now(),
            plan: plan.clone(),
        };
        fs::write(
            control.join("provisioning-state.json"),
            serde_json::to_vec(&durable).unwrap(),
        )
        .unwrap();

        // Malformed inbox JSON must NOT fabricate a revision 1 rejection.
        assert_eq!(
            apply_one_reconfiguration(
                &root.join("inbox"),
                b"{truncated",
                &control,
                &status_dir,
                &status_path,
            )
            .unwrap(),
            ApplyOutcome::Complete
        );
        assert!(report_from(&status_dir).is_none());

        // Persist a reverted outcome for revision 2.
        let recorded = record_terminal_outcome(
            &control,
            2,
            Some(1),
            "reverted",
            Some("Manage unreachable on candidate"),
        )
        .unwrap();
        assert_eq!(recorded.revision, 2);
        assert_eq!(recorded.status, "reverted");
        assert_eq!(load_last_outcome(&control).unwrap().revision, 2);

        // Replaying revision 2 from inbox (even if expired or still valid) re-projects
        // the durable "reverted" outcome without attempting network activation.
        let now = Utc::now();
        let rev2 = sign_doc(
            &key,
            json!({
                "schema": SCHEMA,
                "organization_id": plan.organization_id,
                "device_id": plan.reserved_device_id,
                "device_incarnation_id": Uuid::new_v4(),
                "provisioning_session_id": plan.session_id,
                "revision": 2,
                "issued_at": now - chrono::Duration::days(10),
                "expires_at": now - chrono::Duration::days(3),
                "network": {
                    "mode": "static",
                    "interface_id": plan.network_interface.id,
                    "address_cidr": "10.20.30.40/24",
                    "gateway": "10.20.30.1",
                    "dns_servers": ["10.20.30.53"]
                },
                "management_cidrs": ["10.20.30.0/24"]
            }),
        );
        let rev2_bytes = serde_json::to_vec(&rev2).unwrap();
        assert_eq!(
            apply_one_reconfiguration(
                &root.join("inbox"),
                &rev2_bytes,
                &control,
                &status_dir,
                &status_path,
            )
            .unwrap(),
            ApplyOutcome::Complete
        );
        let projected = report_from(&status_dir).unwrap();
        assert_eq!(projected.revision, 2);
        assert_eq!(projected.status, "reverted");
        assert_eq!(projected.applied_revision, Some(1));

        // A genuinely new expired revision 3 is rejected and persisted durably.
        let rev3 = sign_doc(
            &key,
            json!({
                "schema": SCHEMA,
                "organization_id": plan.organization_id,
                "device_id": plan.reserved_device_id,
                "device_incarnation_id": Uuid::new_v4(),
                "provisioning_session_id": plan.session_id,
                "revision": 3,
                "issued_at": now - chrono::Duration::days(10),
                "expires_at": now - chrono::Duration::days(3),
                "network": {
                    "mode": "dhcp",
                    "interface_id": plan.network_interface.id,
                    "address_cidr": null,
                    "gateway": null,
                    "dns_servers": []
                },
                "management_cidrs": ["10.20.30.0/24"]
            }),
        );
        let rev3_bytes = serde_json::to_vec(&rev3).unwrap();
        assert_eq!(
            apply_one_reconfiguration(
                &root.join("inbox"),
                &rev3_bytes,
                &control,
                &status_dir,
                &status_path,
            )
            .unwrap(),
            ApplyOutcome::Complete
        );
        let projected3 = report_from(&status_dir).unwrap();
        assert_eq!(projected3.revision, 3);
        assert_eq!(projected3.status, "rejected");
        assert_eq!(load_last_outcome(&control).unwrap().revision, 3);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_after_durable_commit_converges_instead_of_reverting() {
        let root = std::env::temp_dir().join(format!("tiaris-net-rec-commit-{}", Uuid::new_v4()));
        let control = root.join("control");
        let runtime = root.join("run");
        let active = root.join("active-netplan.yaml");
        let keys_file = root.join("keys");
        fs::create_dir_all(&control).unwrap();
        fs::create_dir_all(&runtime).unwrap();

        let key = SigningKey::from_bytes(&[17u8; 32]);
        let pub_b64 = STANDARD.encode(key.verifying_key().to_bytes());
        fs::write(&keys_file, format!("{pub_b64}\n")).unwrap();
        let plan = sample_plan();
        let durable = DurableProvisioningState {
            schema: "tiaris.nest.provisioning-state.v1".into(),
            session_id: plan.session_id,
            manage_origin: crate::provisioning::REQUIRED_MANAGE_ORIGIN.into(),
            management_signing_public_key_b64: pub_b64.clone(),
            device_private_key_b64: "priv".into(),
            device_public_key_b64: "pub".into(),
            device_public_key_fingerprint: "fp".into(),
            next_event_sequence: 1,
            identity_active: true,
            installation_complete: true,
            updated_at: Utc::now(),
            plan: plan.clone(),
        };
        fs::write(
            control.join("provisioning-state.json"),
            serde_json::to_vec(&durable).unwrap(),
        )
        .unwrap();

        let now = Utc::now();
        let committed = sign_doc(
            &key,
            json!({
                "schema": SCHEMA,
                "organization_id": plan.organization_id,
                "device_id": plan.reserved_device_id,
                "device_incarnation_id": Uuid::new_v4(),
                "provisioning_session_id": plan.session_id,
                "revision": 4,
                "issued_at": now - chrono::Duration::minutes(2),
                "expires_at": now + chrono::Duration::days(7),
                "network": {
                    "mode": "static",
                    "interface_id": plan.network_interface.id,
                    "address_cidr": "10.20.30.40/24",
                    "gateway": "10.20.30.1",
                    "dns_servers": ["10.20.30.53"]
                },
                "management_cidrs": ["10.20.30.0/24"]
            }),
        );
        fs::write(
            control.join(SUPERSESSION_FILE),
            serde_json::to_vec(&committed).unwrap(),
        )
        .unwrap();

        // Simulate SIGKILL right after SUPERSESSION_FILE commit and before removing pending-revert.
        fs::write(&active, b"candidate-netplan").unwrap();
        fs::write(runtime.join(PENDING_REVERT_YAML), b"old-netplan").unwrap();
        fs::write(
            runtime.join(PENDING_REVERT_META),
            serde_json::to_vec(&PendingRevertMeta {
                revision: 4,
                applied_revision: Some(3),
            })
            .unwrap(),
        )
        .unwrap();

        let mut activated = false;
        let mut converged = false;
        let status_path = runtime.join(STATUS_FILE);
        recover_interrupted_reconfiguration_with(
            &runtime,
            &control,
            &keys_file,
            &active,
            &status_path,
            || {
                activated = true;
                Ok(())
            },
            || {
                converged = true;
                Ok(())
            },
            || {},
        )
        .unwrap();

        assert!(
            !activated,
            "must NOT revert live network after durable commit"
        );
        assert!(converged, "must converge committed supersession");
        assert_eq!(fs::read(&active).unwrap(), b"candidate-netplan");
        assert!(!runtime.join(PENDING_REVERT_YAML).exists());
        assert!(!runtime.join(PENDING_REVERT_META).exists());
        assert!(load_last_outcome(&control).is_none());
        let status = report_from(&runtime).unwrap();
        assert_eq!(status.revision, 4);
        assert_eq!(status.applied_revision, Some(4));
        assert_eq!(status.status, "applied");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_retains_pending_journal_on_failed_restore_and_completes_on_retry() {
        let root = std::env::temp_dir().join(format!("tiaris-net-rec-fail-{}", Uuid::new_v4()));
        let control = root.join("control");
        let runtime = root.join("run");
        let active = root.join("active-netplan.yaml");
        let keys_file = root.join("keys");
        fs::create_dir_all(&control).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        fs::write(&active, b"bad-candidate-netplan").unwrap();
        fs::write(runtime.join(PENDING_REVERT_YAML), b"known-good-netplan").unwrap();
        fs::write(
            runtime.join(PENDING_REVERT_META),
            serde_json::to_vec(&PendingRevertMeta {
                revision: 5,
                applied_revision: Some(4),
            })
            .unwrap(),
        )
        .unwrap();
        let status_path = runtime.join(STATUS_FILE);

        // First recovery attempt fails during activation -> must retain journal,
        // write retry-pending, keep status "pending", and NOT record durable "reverted".
        let err = recover_interrupted_reconfiguration_with(
            &runtime,
            &control,
            &keys_file,
            &active,
            &status_path,
            || bail!("transient networkd reload failure"),
            || Ok(()),
            || {},
        );
        assert!(err.is_err());
        assert!(runtime.join(PENDING_REVERT_YAML).exists());
        assert!(runtime.join(PENDING_REVERT_META).exists());
        assert!(runtime.join(RETRY_PENDING_FILE).exists());
        assert!(load_last_outcome(&control).is_none());
        let pending = report_from(&runtime).unwrap();
        assert_eq!(pending.revision, 5);
        assert_eq!(pending.status, "pending");

        // Second recovery attempt succeeds -> restores known-good Netplan, persists
        // durable "reverted" outcome, and removes the rollback journal.
        let mut refreshed = false;
        recover_interrupted_reconfiguration_with(
            &runtime,
            &control,
            &keys_file,
            &active,
            &status_path,
            || Ok(()),
            || Ok(()),
            || {
                refreshed = true;
            },
        )
        .unwrap();
        assert!(refreshed);
        assert_eq!(fs::read(&active).unwrap(), b"known-good-netplan");
        assert!(!runtime.join(PENDING_REVERT_YAML).exists());
        assert!(!runtime.join(PENDING_REVERT_META).exists());
        assert!(!runtime.join(RETRY_PENDING_FILE).exists());
        let final_status = report_from(&runtime).unwrap();
        assert_eq!(final_status.revision, 5);
        assert_eq!(final_status.status, "reverted");
        assert_eq!(load_last_outcome(&control).unwrap().status, "reverted");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_supersession_file_does_not_block_fresh_signed_reconfiguration_and_key_revocation_works()
     {
        let root = std::env::temp_dir().join(format!("tiaris-net-corrupt-{}", Uuid::new_v4()));
        let control = root.join("control");
        let runtime = root.join("run");
        fs::create_dir_all(&control).unwrap();
        let status_path = runtime.join(STATUS_FILE);

        let key = SigningKey::from_bytes(&[19u8; 32]);
        let pub_b64 = STANDARD.encode(key.verifying_key().to_bytes());
        let rotated_key = SigningKey::from_bytes(&[23u8; 32]);
        let rotated_pub = STANDARD.encode(rotated_key.verifying_key().to_bytes());
        let keys_file = root.join("shipped-keys");
        fs::write(&keys_file, format!("{rotated_pub}\n")).unwrap();

        // Key trust separation: retired install key is excluded for new incoming
        // requests (include_install_fallback = false) and retained only for
        // already-committed on-disk files (include_install_fallback = true).
        let incoming = load_trusted_key_b64s(&keys_file, &pub_b64, false).unwrap();
        assert_eq!(incoming, vec![rotated_pub.clone()]);
        let committed = load_trusted_key_b64s(&keys_file, &pub_b64, true).unwrap();
        assert_eq!(committed, vec![rotated_pub, pub_b64.clone()]);

        let plan = sample_plan();
        let durable = DurableProvisioningState {
            schema: "tiaris.nest.provisioning-state.v1".into(),
            session_id: plan.session_id,
            manage_origin: crate::provisioning::REQUIRED_MANAGE_ORIGIN.into(),
            management_signing_public_key_b64: pub_b64,
            device_private_key_b64: "priv".into(),
            device_public_key_b64: "pub".into(),
            device_public_key_fingerprint: "fp".into(),
            next_event_sequence: 1,
            identity_active: true,
            installation_complete: true,
            updated_at: Utc::now(),
            plan: plan.clone(),
        };
        fs::write(
            control.join("provisioning-state.json"),
            serde_json::to_vec(&durable).unwrap(),
        )
        .unwrap();
        // Plant a corrupt optional control/network-supersession.json.
        fs::write(control.join(SUPERSESSION_FILE), b"{corrupt-json").unwrap();

        // A fresh signed document (here expired so it stops cleanly before touching
        // host networking) must be inspected and handled instead of aborting on the
        // corrupt on-disk override.
        let now = Utc::now();
        let rev = sign_doc(
            &key,
            json!({
                "schema": SCHEMA,
                "organization_id": plan.organization_id,
                "device_id": plan.reserved_device_id,
                "device_incarnation_id": Uuid::new_v4(),
                "provisioning_session_id": plan.session_id,
                "revision": 7,
                "issued_at": now - chrono::Duration::days(10),
                "expires_at": now - chrono::Duration::days(1),
                "network": {
                    "mode": "dhcp",
                    "interface_id": plan.network_interface.id,
                    "address_cidr": null,
                    "gateway": null,
                    "dns_servers": []
                },
                "management_cidrs": ["10.0.0.0/24"]
            }),
        );
        let bytes = serde_json::to_vec(&rev).unwrap();
        assert_eq!(
            apply_one_reconfiguration(
                &root.join("inbox"),
                &bytes,
                &control,
                &runtime,
                &status_path
            )
            .unwrap(),
            ApplyOutcome::Complete
        );
        let projected = report_from(&runtime).unwrap();
        assert_eq!(projected.revision, 7);
        assert_eq!(projected.status, "rejected");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn drain_rechecks_inbox_after_final_convergence_and_processes_mid_convergence_repair() {
        let root = std::env::temp_dir().join(format!("tiaris-net-drain-{}", Uuid::new_v4()));
        let runtime = root.join("run");
        fs::create_dir_all(&runtime).unwrap();
        mark_pxe_restart_pending(&runtime);
        mark_retry_pending(&runtime);

        let inbox = std::cell::RefCell::new(Some(b"rev-1".to_vec()));
        let mut applied = Vec::new();
        let mut converge_calls = 0usize;

        drain_reconfiguration_with(
            &runtime,
            Duration::from_secs(60),
            || Ok(inbox.borrow().clone()),
            |bytes| {
                applied.push(bytes.to_vec());
                Ok(ApplyOutcome::Complete)
            },
            || {
                converge_calls += 1;
                clear_pxe_restart_pending(&runtime);
                // Simulate a repair arriving while final convergence is running
                // (when systemd drops PathChanged on the active oneshot).
                *inbox.borrow_mut() = Some(b"rev-2".to_vec());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(converge_calls, 1);
        assert_eq!(applied, vec![b"rev-1".to_vec(), b"rev-2".to_vec()]);
        assert!(!runtime.join(PXE_RESTART_PENDING_FILE).exists());
        assert!(!runtime.join(RETRY_PENDING_FILE).exists());

        // When final convergence fails, both pxe-restart-pending and retry-pending
        // must remain present so the retry timer retries convergence.
        mark_pxe_restart_pending(&runtime);
        let err = drain_reconfiguration_with(
            &runtime,
            Duration::from_secs(60),
            || Ok(None),
            |_| Ok(ApplyOutcome::Complete),
            || bail!("transient firewall reload failure"),
        );
        assert!(err.is_err());
        assert!(runtime.join(PXE_RESTART_PENDING_FILE).exists());
        assert!(runtime.join(RETRY_PENDING_FILE).exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn recovery_revert_preserves_retry_pending_when_prior_pxe_convergence_is_pending() {
        let root = std::env::temp_dir().join(format!("tiaris-net-rec-pxe-{}", Uuid::new_v4()));
        let control = root.join("control");
        let runtime = root.join("run");
        let active = root.join("active-netplan.yaml");
        let keys_file = root.join("keys");
        fs::create_dir_all(&control).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        fs::write(&active, b"interrupted-candidate-netplan").unwrap();
        fs::write(
            runtime.join(PENDING_REVERT_YAML),
            b"prior-committed-netplan",
        )
        .unwrap();
        fs::write(
            runtime.join(PENDING_REVERT_META),
            serde_json::to_vec(&PendingRevertMeta {
                revision: 6,
                applied_revision: Some(5),
            })
            .unwrap(),
        )
        .unwrap();
        // Earlier committed revision 5 still has unfinished post-commit convergence.
        mark_pxe_restart_pending(&runtime);
        let status_path = runtime.join(STATUS_FILE);

        recover_interrupted_reconfiguration_with(
            &runtime,
            &control,
            &keys_file,
            &active,
            &status_path,
            || Ok(()),
            || Ok(()),
            || {},
        )
        .unwrap();

        assert_eq!(fs::read(&active).unwrap(), b"prior-committed-netplan");
        assert!(!runtime.join(PENDING_REVERT_YAML).exists());
        assert!(!runtime.join(PENDING_REVERT_META).exists());
        assert!(
            runtime.join(PXE_RESTART_PENDING_FILE).exists(),
            "prior commit pxe-restart-pending must stay set for the retry timer"
        );
        assert!(
            runtime.join(RETRY_PENDING_FILE).exists(),
            "retry-pending must stay set after revert when pxe-restart-pending exists"
        );
        let status = report_from(&runtime).unwrap();
        assert_eq!(status.revision, 6);
        assert_eq!(status.status, "reverted");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn agent_inbox_apply_rewrites_same_bytes_when_report_lags_desired_revision() {
        let root = std::env::temp_dir().join(format!("tiaris-net-apply-{}", Uuid::new_v4()));
        let data_dir = root.join("agent");
        let status_dir = root.join("status");
        fs::create_dir_all(&status_dir).unwrap();

        let key = SigningKey::from_bytes(&[31u8; 32]);
        let plan = sample_plan();
        let now = Utc::now();
        let rev10 = sign_doc(
            &key,
            json!({
                "schema": SCHEMA,
                "organization_id": plan.organization_id,
                "device_id": plan.reserved_device_id,
                "device_incarnation_id": Uuid::new_v4(),
                "provisioning_session_id": plan.session_id,
                "revision": 10,
                "issued_at": now,
                "expires_at": now + chrono::Duration::days(7),
                "network": {
                    "mode": "dhcp",
                    "interface_id": plan.network_interface.id,
                    "address_cidr": null,
                    "gateway": null,
                    "dns_servers": []
                },
                "management_cidrs": ["10.0.0.0/24"]
            }),
        );

        // No status report yet -> writes inbox.
        assert!(
            apply_with_status_dir(&data_dir, &status_dir, Some(Desired(rev10.clone()))).unwrap()
        );
        // Status report still lags at revision 9 -> re-writes inbox to re-trigger PathChanged.
        write_status(&status_dir.join(STATUS_FILE), 9, Some(9), "applied", None).unwrap();
        assert!(
            apply_with_status_dir(&data_dir, &status_dir, Some(Desired(rev10.clone()))).unwrap()
        );
        // Once root reports revision 10 (pending or terminal) -> steady state skips redundant write.
        write_status(&status_dir.join(STATUS_FILE), 10, Some(9), "pending", None).unwrap();
        assert!(!apply_with_status_dir(&data_dir, &status_dir, Some(Desired(rev10))).unwrap());

        let _ = fs::remove_dir_all(&root);
    }
}
