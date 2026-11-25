//! Signed post-install network reconfiguration (`network_reconfigure_v1`).
//!
//! The unprivileged `tiaris-nest` daemon writes Manage's signed
//! `tiaris.nest.network-supersession.v1` document into
//! `/var/lib/tiaris-nest/state/agent/network-reconfigure.json` (0600) and reads
//! root's status projection from `/run/tiaris-nest/network-reconfigure-status.json`.
//!
//! Root (`tiaris-nest-bootstrap apply-network-reconfigure`) verifies the Ed25519
//! signature, monotonic revision, identity binding, and expiry; stages the
//! candidate Netplan; verifies Manage HTTPS reachability within 90 seconds;
//! and either commits atomically or automatically reverts to the previous
//! approved network.

use crate::{
    provisioning::{
        DurableProvisioningState, NetworkRuntimeOptions, effective_manage_origin,
        protocol::{NestProvisioningNetworkPlan, SignedInstallPlan},
        read_bounded_nofollow, reconcile_network_runtime,
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
const STATUS_DIR: &str = "/run/tiaris-nest";
const STATUS_FILE: &str = "network-reconfigure-status.json";
pub(crate) const SUPERSESSION_FILE: &str = "network-supersession.json";
const ACTIVE_NETPLAN: &str = "/etc/netplan/90-tiaris-nest.yaml";
const MAX_BYTES: u64 = 64 * 1024;
const PROBE_DEADLINE_SECONDS: u64 = 90;

pub(crate) fn shipped() -> bool {
    crate::appliance::nixos::is_nixos()
        && Path::new("/etc/systemd/system/tiaris-nest-network-reconfigure.service").is_file()
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
    let Some(Desired(raw)) = desired else {
        return Ok(());
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
    if current.as_deref() != Some(body.as_slice()) {
        state_files::write_bytes(data_dir, INBOX_FILE, &body, MAX_BYTES)?;
    }
    Ok(())
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

/// Verify a signed supersession JSON document (verifying the signature over the
/// raw JSON object so timestamp formatting is preserved byte-for-byte).
pub(crate) fn verify_supersession_value(
    raw: &Value,
    public_key_b64: &str,
    plan: &SignedInstallPlan,
    check_expiry: bool,
    now: DateTime<Utc>,
) -> Result<SignedNetworkSupersession> {
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
    crate::appliance::verify_management_signature(
        raw,
        "signature",
        &doc.signature,
        DOMAIN,
        public_key_b64,
    )
    .context("network supersession signature verification failed")?;
    Ok(doc)
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
            if !(1..=32).contains(&prefix) {
                bail!("static supersession prefix out of range");
            }
            let gateway: Ipv4Addr = network
                .gateway
                .as_deref()
                .ok_or_else(|| anyhow!("static supersession omitted gateway"))?
                .parse()
                .context("static supersession gateway is invalid")?;
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            if address == gateway || (u32::from(address) & mask) != (u32::from(gateway) & mask) {
                bail!("static supersession gateway is outside the subnet");
            }
            if network.dns_servers.is_empty() || network.dns_servers.len() > 4 {
                bail!("static supersession requires 1..=4 DNS servers");
            }
            let mut seen = BTreeSet::new();
            for entry in &network.dns_servers {
                let dns: Ipv4Addr = entry
                    .parse()
                    .context("static supersession DNS server is not IPv4")?;
                if dns == address || !seen.insert(dns) {
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
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            bail!("management_cidrs prefix exceeds limit");
        }
    }
    Ok(())
}

/// Root execution entry point (`tiaris-nest-bootstrap apply-network-reconfigure`).
pub fn apply_reconfiguration_as_root(
    inbox_path: &Path,
    control_dir: &Path,
    status_path: &Path,
) -> Result<()> {
    let raw_bytes = match fs::symlink_metadata(inbox_path) {
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
            read_bounded_nofollow(inbox_path, MAX_BYTES, "network reconfiguration inbox")?
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).context("inspect network reconfiguration inbox"),
    };

    let durable_bytes = read_bounded_nofollow(
        &control_dir.join("provisioning-state.json"),
        512 * 1024,
        "durable provisioning state",
    )?;
    let durable: DurableProvisioningState =
        serde_json::from_slice(&durable_bytes).context("parse durable provisioning state")?;
    let origin = effective_manage_origin(&durable.manage_origin)
        .ok_or_else(|| anyhow!("durable Management origin is not served by this build"))?;

    let current_revision = load_current_supersession_revision(control_dir, &durable)?;

    let raw_value: Value = match serde_json::from_slice(&raw_bytes) {
        Ok(val) => val,
        Err(err) => {
            write_status(
                status_path,
                1,
                current_revision,
                "rejected",
                Some(&err.to_string()),
            )?;
            return Ok(());
        }
    };
    let requested_revision = raw_value
        .get("revision")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    let doc = match verify_supersession_value(
        &raw_value,
        &durable.management_signing_public_key_b64,
        &durable.plan,
        true,
        Utc::now(),
    ) {
        Ok(doc) => doc,
        Err(err) => {
            if requested_revision > 0 {
                write_status(
                    status_path,
                    requested_revision,
                    current_revision,
                    "rejected",
                    Some(&err.to_string()),
                )?;
            }
            return Ok(());
        }
    };

    if let Some(applied) = current_revision {
        if doc.revision <= applied {
            write_status(status_path, doc.revision, Some(applied), "applied", None)?;
            return Ok(());
        }
    }

    write_status(status_path, doc.revision, current_revision, "pending", None)?;

    let approved_path = control_dir.join("netplan-approved.json");
    let previous_netplan = read_bounded_nofollow(&approved_path, 1024 * 1024, "approved Netplan")?;
    let candidate_netplan =
        crate::provisioning::render_netplan_for_plan(&doc.network, &durable.plan);
    let candidate_bytes = serde_json::to_vec(&candidate_netplan)?;

    let activated = atomic_write_root(Path::new(ACTIVE_NETPLAN), &candidate_bytes, 0o600, 0)
        .and_then(|()| run_netplan_activate());

    let reachable = if activated.is_ok() {
        probe_manage_reachable(origin, Duration::from_secs(PROBE_DEADLINE_SECONDS))
    } else {
        false
    };

    if !reachable {
        // Automatic revert to the previous approved network.
        let _ = atomic_write_root(Path::new(ACTIVE_NETPLAN), &previous_netplan, 0o600, 0);
        let _ = run_netplan_activate();
        let reason = if let Err(err) = activated {
            format!("candidate network failed to activate ({err}); reverted to previous network")
        } else {
            "Manage could not be reached on the new network within 90 seconds; reverted to previous network".to_string()
        };
        write_status(
            status_path,
            doc.revision,
            current_revision,
            "reverted",
            Some(&reason),
        )?;
        return Ok(());
    }

    // Commit atomically: supersession record, approved Netplan, management CIDRs.
    let supersession_bytes = serde_json::to_vec(&raw_value)?;
    atomic_write_root(
        &control_dir.join(SUPERSESSION_FILE),
        &supersession_bytes,
        0o600,
        0,
    )?;
    atomic_write_root(&approved_path, &candidate_bytes, 0o600, 0)?;
    let cidrs_body = format!("{}\n", doc.management_cidrs.join("\n"));
    atomic_write_root(
        &control_dir.join("management-cidrs.txt"),
        cidrs_body.as_bytes(),
        0o640,
        985,
    )?;
    let _ = fs::remove_file(control_dir.join("network-fallback-active"));
    let _ = File::open(control_dir).and_then(|d| d.sync_all());

    let _ = reconcile_network_runtime(NetworkRuntimeOptions::default());
    let _ = Command::new("/usr/lib/tiaris-nest/tiaris-nest-firewall").status();
    let _ = Command::new("systemctl")
        .args([
            "try-restart",
            "tiaris-nest-pxe.service",
            "tiaris-nest-assist-turn.service",
        ])
        .status();

    write_status(
        status_path,
        doc.revision,
        Some(doc.revision),
        "applied",
        None,
    )?;
    Ok(())
}

fn load_current_supersession_revision(
    control_dir: &Path,
    durable: &DurableProvisioningState,
) -> Result<Option<i64>> {
    let path = control_dir.join(SUPERSESSION_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_bounded_nofollow(&path, MAX_BYTES, "committed network supersession")?;
            let raw: Value = serde_json::from_slice(&bytes)?;
            let doc = verify_supersession_value(
                &raw,
                &durable.management_signing_public_key_b64,
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
        .status()
        .context("run tiaris-nest-netplan-activate")?;
    if !status.success() {
        bail!("tiaris-nest-netplan-activate exited with {status}");
    }
    Ok(())
}

fn probe_manage_reachable(origin: &str, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    let url = format!("{}/healthz", origin.trim_end_matches('/'));
    while Instant::now() < deadline {
        let status = Command::new("curl")
            .args([
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
                "--output",
                "/dev/null",
                &url,
            ])
            .status();
        if status.is_ok_and(|s| s.success()) {
            return true;
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
    let mut body = serde_json::to_vec(&report)?;
    body.push(b'\n');
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    atomic_write_root(path, &body, 0o644, 0)
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
    }
}
