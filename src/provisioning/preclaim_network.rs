//! Pre-claim static IPv4 configuration for Setup ISOs in no-DHCP networks.
//!
//! Accepts L3 network parameters only (`interface_mac`, `address_cidr`,
//! `gateway`, `dns_servers`) from either:
//!   1. A bounded (`<= 4 KiB`) `tiaris-net.toml` file on an unmounted FAT32/ext4
//!      USB partition (preferring label `TIARIS_NET`), mounted read-only with
//!      `nosuid,nodev,noexec` and immediately unmounted; or
//!   2. The guided tty2 interactive configurator (`tiaris-nest-bootstrap
//!      configure-setup-network`), which uses the exact same validator.
//!
//! Trust inputs (Manage origin, TLS roots, keys, scripts) are never accepted.

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    io::{self, BufRead, Write},
    net::Ipv4Addr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};
use tracing::{info, warn};

const MAX_CONFIG_BYTES: u64 = 4096;
const NETWORKD_DIR: &str = "/run/systemd/network";
const PRECLAIM_NETWORK_FILE: &str = "15-tiaris-preclaim.network";
const USB_MOUNT_DIR: &str = "/run/tiaris-preclaim-usb";
const CONFIG_FILENAME: &str = "tiaris-net.toml";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreclaimNetworkConfig {
    #[serde(default)]
    pub interface_mac: Option<String>,
    pub address_cidr: String,
    pub gateway: String,
    pub dns_servers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPreclaimNetwork {
    pub interface_mac: Option<String>,
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
}

impl ValidatedPreclaimNetwork {
    pub fn address_cidr(&self) -> String {
        format!("{}/{}", self.address, self.prefix)
    }

    pub fn render_networkd_unit(&self) -> String {
        let mut lines = vec!["[Match]".to_string()];
        if let Some(mac) = &self.interface_mac {
            lines.push(format!("MACAddress={mac}"));
        } else {
            lines.push("Name=en* eth*".to_string());
        }
        lines.push(String::new());
        lines.push("[Network]".to_string());
        lines.push("DHCP=no".to_string());
        lines.push("IPv6AcceptRA=no".to_string());
        lines.push(format!("Address={}/{}", self.address, self.prefix));
        lines.push(format!("Gateway={}", self.gateway));
        for dns in &self.dns_servers {
            lines.push(format!("DNS={dns}"));
        }
        lines.join("\n") + "\n"
    }
}

pub fn parse_and_validate_toml(raw: &str) -> Result<ValidatedPreclaimNetwork> {
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        bail!("pre-claim network config exceeds {MAX_CONFIG_BYTES} bytes");
    }
    let parsed: PreclaimNetworkConfig =
        toml::from_str(raw).context("parse tiaris-net.toml (only L3 fields are allowed)")?;
    validate_config(parsed)
}

pub fn validate_config(config: PreclaimNetworkConfig) -> Result<ValidatedPreclaimNetwork> {
    let interface_mac = match config.interface_mac {
        Some(raw) if !raw.trim().is_empty() => Some(normalize_unicast_mac(&raw)?),
        _ => None,
    };
    let (address, prefix) = parse_ipv4_cidr(&config.address_cidr)?;
    if address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_link_local()
        || address.is_broadcast()
    {
        bail!("pre-claim address must be a unicast host IPv4 address");
    }
    let gateway: Ipv4Addr = config
        .gateway
        .trim()
        .parse()
        .context("pre-claim gateway must be an IPv4 address")?;
    if gateway == address || !same_ipv4_subnet(address, gateway, prefix) {
        bail!("pre-claim gateway must be a distinct address inside the selected subnet");
    }
    if config.dns_servers.is_empty() || config.dns_servers.len() > 4 {
        bail!("pre-claim config requires between 1 and 4 IPv4 DNS servers");
    }
    let mut seen = BTreeSet::new();
    let mut dns_servers = Vec::with_capacity(config.dns_servers.len());
    for entry in config.dns_servers {
        let dns: Ipv4Addr = entry
            .trim()
            .parse()
            .with_context(|| format!("pre-claim DNS server '{}' is not IPv4", entry.trim()))?;
        if dns == address || dns.is_unspecified() || dns.is_multicast() || dns.is_broadcast() {
            bail!("pre-claim DNS server {dns} is invalid");
        }
        if !seen.insert(dns) {
            bail!("duplicate pre-claim DNS server {dns}");
        }
        dns_servers.push(dns);
    }
    Ok(ValidatedPreclaimNetwork {
        interface_mac,
        address,
        prefix,
        gateway,
        dns_servers,
    })
}

fn normalize_unicast_mac(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase().replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        bail!("interface_mac must be a 6-byte hex MAC address");
    }
    let first = u8::from_str_radix(parts[0], 16).unwrap_or(1);
    if (first & 1) != 0 {
        bail!("interface_mac must be a unicast MAC address");
    }
    Ok(normalized)
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8)> {
    let trimmed = value.trim();
    let (addr_str, prefix_str) = trimmed.split_once('/').ok_or_else(|| {
        anyhow!("address_cidr must use IPv4 CIDR notation (e.g. 192.168.1.20/24)")
    })?;
    let addr: Ipv4Addr = addr_str
        .parse()
        .context("address_cidr IPv4 address is invalid")?;
    let prefix: u8 = prefix_str
        .parse()
        .context("address_cidr prefix length is invalid")?;
    if !(1..=30).contains(&prefix) {
        bail!("address_cidr prefix must be between 1 and 30");
    }
    Ok((addr, prefix))
}

fn same_ipv4_subnet(left: Ipv4Addr, right: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    (u32::from(left) & mask) == (u32::from(right) & mask)
}

pub fn apply_networkd_config(config: &ValidatedPreclaimNetwork) -> Result<()> {
    apply_networkd_config_to(Path::new(NETWORKD_DIR), config, true)
}

fn apply_networkd_config_to(
    networkd_dir: &Path,
    config: &ValidatedPreclaimNetwork,
    reload: bool,
) -> Result<()> {
    fs::create_dir_all(networkd_dir).context("create /run/systemd/network")?;
    let target = networkd_dir.join(PRECLAIM_NETWORK_FILE);
    let body = config.render_networkd_unit();
    if fs::read_to_string(&target).ok().as_deref() == Some(body.as_str()) {
        return Ok(());
    }
    let tmp = networkd_dir.join(format!(".{PRECLAIM_NETWORK_FILE}.tmp"));
    let write_res = (|| -> Result<()> {
        fs::write(&tmp, body.as_bytes()).context("write transient pre-claim network unit")?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))?;
        fs::rename(&tmp, &target).context("activate transient pre-claim network unit")?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_res?;

    if reload {
        let status = Command::new("networkctl")
            .arg("reload")
            .status()
            .context("run networkctl reload")?;
        if !status.success() {
            bail!("networkctl reload failed");
        }
        for iface in wired_interface_names() {
            let _ = Command::new("networkctl")
                .args(["reconfigure", &iface])
                .status();
        }
    }
    Ok(())
}

fn wired_interface_names() -> Vec<String> {
    let mut names = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return names;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let root = entry.path();
        if name == "lo"
            || root.join("wireless").exists()
            || !root.join("device").exists()
            || fs::read_to_string(root.join("type"))
                .map(|v| v.trim() != "1")
                .unwrap_or(true)
        {
            continue;
        }
        names.push(name);
    }
    names.sort();
    names
}

struct UsbCandidate {
    path: PathBuf,
    fstype: String,
    preferred: bool,
}

fn discover_usb_candidates() -> Vec<UsbCandidate> {
    let Ok(output) = Command::new("lsblk")
        .args([
            "--json",
            "--output",
            "PATH,TYPE,FSTYPE,LABEL,MOUNTPOINTS,RM,HOTPLUG",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() || output.stdout.len() > 2 * 1024 * 1024 {
        return Vec::new();
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(&output.stdout) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_usb_candidates_from_lsblk(&parsed, false, &mut out);
    out.sort_by(|a, b| {
        b.preferred
            .cmp(&a.preferred)
            .then_with(|| a.path.cmp(&b.path))
    });
    out
}

fn collect_usb_candidates_from_lsblk(
    value: &Value,
    parent_removable: bool,
    out: &mut Vec<UsbCandidate>,
) {
    let Some(rows) = value
        .get("blockdevices")
        .or_else(|| value.get("children"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for row in rows {
        let removable = parent_removable
            || row.get("rm").and_then(Value::as_bool).unwrap_or(false)
            || row.get("hotplug").and_then(Value::as_bool).unwrap_or(false);
        let kind = row.get("type").and_then(Value::as_str).unwrap_or("");
        let fstype = row
            .get("fstype")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let label = row
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let mounted = row
            .get("mountpoints")
            .and_then(Value::as_array)
            .is_some_and(|m| m.iter().any(|v| !v.is_null()));
        if removable
            && !mounted
            && matches!(kind, "part" | "disk")
            && matches!(fstype.as_str(), "vfat" | "ext4")
        {
            if let Some(path) = row.get("path").and_then(Value::as_str) {
                if path.starts_with("/dev/") {
                    out.push(UsbCandidate {
                        path: PathBuf::from(path),
                        fstype,
                        preferred: label.eq_ignore_ascii_case("TIARIS_NET"),
                    });
                }
            }
        }
        collect_usb_candidates_from_lsblk(row, removable, out);
    }
}

struct UnmountGuard(PathBuf);

impl Drop for UnmountGuard {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
        let _ = fs::remove_dir(&self.0);
    }
}

fn read_bounded_config(path: &Path) -> Result<Option<String>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("inspect tiaris-net.toml"),
    };
    if !meta.file_type().is_file() || meta.nlink() != 1 || meta.len() == 0 {
        bail!("tiaris-net.toml must be a non-empty regular file");
    }
    if meta.len() > MAX_CONFIG_BYTES {
        bail!("tiaris-net.toml exceeds {MAX_CONFIG_BYTES} bytes");
    }
    let body = fs::read_to_string(path).context("read tiaris-net.toml")?;
    Ok(Some(body))
}

/// Best-effort scan of unmounted removable FAT32/ext4 USB media for
/// `tiaris-net.toml`. Applies the first valid L3 configuration to
/// systemd-networkd and unmounts immediately. Never fails setup if absent.
pub fn try_apply_from_usb() -> Option<ValidatedPreclaimNetwork> {
    let candidates = discover_usb_candidates();
    if candidates.is_empty() {
        return None;
    }
    let mount_dir = PathBuf::from(USB_MOUNT_DIR);
    for candidate in candidates {
        if fs::create_dir_all(&mount_dir).is_err() {
            return None;
        }
        let _ = fs::set_permissions(&mount_dir, fs::Permissions::from_mode(0o700));
        let status = Command::new("mount")
            .args(["-t", &candidate.fstype, "-o", "ro,nosuid,nodev,noexec"])
            .arg(&candidate.path)
            .arg(&mount_dir)
            .status();
        if !status.is_ok_and(|s| s.success()) {
            let _ = fs::remove_dir(&mount_dir);
            continue;
        }
        let _guard = UnmountGuard(mount_dir.clone());
        match read_bounded_config(&mount_dir.join(CONFIG_FILENAME)) {
            Ok(Some(raw)) => match parse_and_validate_toml(&raw) {
                Ok(validated) => {
                    if let Err(err) = apply_networkd_config(&validated) {
                        warn!(
                            device = %candidate.path.display(),
                            error = %err,
                            "could not apply USB pre-claim static IPv4 configuration"
                        );
                    } else {
                        info!(
                            device = %candidate.path.display(),
                            address = %validated.address_cidr(),
                            "applied pre-claim static IPv4 configuration from USB"
                        );
                        return Some(validated);
                    }
                }
                Err(err) => {
                    warn!(
                        device = %candidate.path.display(),
                        error = %err,
                        "ignoring invalid tiaris-net.toml on USB device"
                    );
                }
            },
            Ok(None) => {}
            Err(err) => {
                warn!(
                    device = %candidate.path.display(),
                    error = %err,
                    "ignoring unsafe tiaris-net.toml on USB device"
                );
            }
        }
    }
    None
}

/// Guided interactive pre-claim static IPv4 setup for tty2 (no shell access).
pub fn run_interactive_tty() -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut reader = stdin.lock();

    loop {
        writeln!(stdout, "\n=== Tiaris Nest Pre-Claim Static IPv4 Setup ===")?;
        writeln!(
            stdout,
            "Use this screen only on networks without DHCP. Switch back to Alt+F1 for setup status."
        )?;
        let nics = wired_interface_names();
        if nics.is_empty() {
            writeln!(stdout, "Detected wired interfaces: none")?;
        } else {
            writeln!(stdout, "Detected wired interfaces:")?;
            for nic in &nics {
                let mac = fs::read_to_string(format!("/sys/class/net/{nic}/address"))
                    .map(|v| v.trim().to_string())
                    .unwrap_or_default();
                let carrier = fs::read_to_string(format!("/sys/class/net/{nic}/carrier"))
                    .map(|v| v.trim() == "1")
                    .unwrap_or(false);
                writeln!(
                    stdout,
                    "  - {nic} (MAC {mac}, {})",
                    if carrier { "link up" } else { "no link" }
                )?;
            }
        }
        writeln!(stdout)?;
        let Some(cidr) = prompt_line(
            &mut reader,
            &mut stdout,
            "IPv4 address/prefix (e.g. 192.168.1.20/24): ",
        )?
        else {
            return Ok(());
        };
        let Some(gateway) = prompt_line(
            &mut reader,
            &mut stdout,
            "Gateway IPv4 (e.g. 192.168.1.1): ",
        )?
        else {
            return Ok(());
        };
        let Some(dns_raw) = prompt_line(
            &mut reader,
            &mut stdout,
            "DNS servers, comma-separated (e.g. 192.168.1.1, 1.1.1.1): ",
        )?
        else {
            return Ok(());
        };
        let Some(mac_raw) = prompt_line(
            &mut reader,
            &mut stdout,
            "Interface MAC (optional, Enter for all wired): ",
        )?
        else {
            return Ok(());
        };

        let dns_servers: Vec<String> = dns_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let config = PreclaimNetworkConfig {
            interface_mac: (!mac_raw.trim().is_empty()).then(|| mac_raw.trim().to_string()),
            address_cidr: cidr,
            gateway,
            dns_servers,
        };
        match validate_config(config) {
            Ok(validated) => match apply_networkd_config(&validated) {
                Ok(()) => {
                    writeln!(
                        stdout,
                        "\nApplied static IPv4 {} (gateway {}). Switch to Alt+F1 to continue setup.\n",
                        validated.address_cidr(),
                        validated.gateway
                    )?;
                }
                Err(err) => {
                    writeln!(stdout, "\nCould not apply network settings: {err}\n")?;
                }
            },
            Err(err) => {
                writeln!(stdout, "\nInvalid input: {err}\n")?;
            }
        }
    }
}

fn prompt_line<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    label: &str,
) -> Result<Option<String>> {
    write!(writer, "{label}")?;
    writer.flush()?;
    let mut buf = String::new();
    let n = reader.read_line(&mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(buf.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_toml_renders_networkd_unit_and_rejects_unknown_fields() {
        let valid = r#"
interface_mac = "AA:BB:CC:DD:EE:FF"
address_cidr = "192.168.10.25/24"
gateway = "192.168.10.1"
dns_servers = ["192.168.10.53", "1.1.1.1"]
"#;
        let parsed = parse_and_validate_toml(valid).unwrap();
        assert_eq!(parsed.interface_mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        let rendered = parsed.render_networkd_unit();
        assert!(rendered.contains("MACAddress=aa:bb:cc:dd:ee:ff"));
        assert!(rendered.contains("DHCP=no"));
        assert!(rendered.contains("Address=192.168.10.25/24"));
        assert!(rendered.contains("Gateway=192.168.10.1"));
        assert!(rendered.contains("DNS=192.168.10.53"));
        assert!(rendered.contains("DNS=1.1.1.1"));

        // Trust inputs such as manage_origin must be rejected by deny_unknown_fields.
        let with_trust = r#"
address_cidr = "192.168.10.25/24"
gateway = "192.168.10.1"
dns_servers = ["1.1.1.1"]
manage_origin = "https://attacker.example"
"#;
        assert!(parse_and_validate_toml(with_trust).is_err());

        // Gateway outside subnet must fail.
        let bad_gw = r#"
address_cidr = "192.168.10.25/24"
gateway = "192.168.11.1"
dns_servers = ["1.1.1.1"]
"#;
        assert!(parse_and_validate_toml(bad_gw).is_err());

        // Multicast MAC must fail.
        let bad_mac = r#"
interface_mac = "01:00:5e:00:00:01"
address_cidr = "192.168.10.25/24"
gateway = "192.168.10.1"
dns_servers = ["1.1.1.1"]
"#;
        assert!(parse_and_validate_toml(bad_mac).is_err());
    }

    #[test]
    fn usb_candidate_discovery_prefers_tiaris_net_label_and_ignores_mounted_or_internal() {
        let lsblk = serde_json::json!({
            "blockdevices": [
                {
                    "path": "/dev/sda", "type": "disk", "rm": false, "hotplug": false,
                    "children": [
                        {"path": "/dev/sda1", "type": "part", "fstype": "vfat", "label": "TIARIS_NET", "mountpoints": [null]}
                    ]
                },
                {
                    "path": "/dev/sdb", "type": "disk", "rm": true, "hotplug": true,
                    "children": [
                        {"path": "/dev/sdb1", "type": "part", "fstype": "vfat", "label": "OTHER", "mountpoints": [null]},
                        {"path": "/dev/sdb2", "type": "part", "fstype": "ext4", "label": "TIARIS_NET", "mountpoints": [null]},
                        {"path": "/dev/sdb3", "type": "part", "fstype": "vfat", "label": "MOUNTED", "mountpoints": ["/mnt"]}
                    ]
                }
            ]
        });
        let mut found = Vec::new();
        collect_usb_candidates_from_lsblk(&lsblk, false, &mut found);
        found.sort_by(|a, b| {
            b.preferred
                .cmp(&a.preferred)
                .then_with(|| a.path.cmp(&b.path))
        });
        let paths: Vec<String> = found.iter().map(|c| c.path.display().to_string()).collect();
        assert_eq!(paths, vec!["/dev/sdb2", "/dev/sdb1"]);
    }

    #[test]
    fn writing_networkd_unit_is_atomic_and_idempotent() {
        let dir = std::env::temp_dir().join(format!("tiaris-preclaim-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let cfg = parse_and_validate_toml(
            r#"
address_cidr = "10.0.0.50/24"
gateway = "10.0.0.1"
dns_servers = ["10.0.0.1"]
"#,
        )
        .unwrap();
        apply_networkd_config_to(&dir, &cfg, false).unwrap();
        apply_networkd_config_to(&dir, &cfg, false).unwrap();
        let content = fs::read_to_string(dir.join(PRECLAIM_NETWORK_FILE)).unwrap();
        assert!(content.contains("Name=en* eth*"));
        assert!(content.contains("Address=10.0.0.50/24"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
