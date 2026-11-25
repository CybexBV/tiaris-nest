use super::protocol::SignedInstallPlan;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Output},
    time::Duration,
};
use tokio::process::Command;

// Keep this synchronized with Tiaris's provisioning admission and the
// bootstrap partition layout. The final partition is shared by /nix, runtime
// bundles, build work, and the delivery cache; 128 GiB leaves too little
// normal-operating headroom for exact workstation preparation.
pub(super) const MIN_DISK_BYTES: u64 = 160 * 1024 * 1024 * 1024;
const STATIC_PREFLIGHT_ROUTE_TABLE: &str = "42666";
const STATIC_PREFLIGHT_RULE_PRIORITY: &str = "42666";
const STATIC_PREFLIGHT_OUTPUT_LIMIT: usize = 16 * 1024;
// `prepare` runs from the stock Ubuntu live filesystem, before the signed
// appliance package snapshot (and its iputils-arping dependency) is installed.
// The pinned live image ships this BusyBox applet; the ISO builder verifies it.
const LIVE_INSTALLER_BUSYBOX: &str = "/usr/bin/busybox";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NestProvisioningEthernetInterface {
    pub id: String,
    pub name: String,
    pub mac: String,
    pub link_up: bool,
    pub addresses: Vec<String>,
    pub gateway: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NestProvisioningDiskSmartHealth {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wear_percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reallocated_sectors: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature_celsius: Option<i16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NestProvisioningDisk {
    pub id: String,
    pub path: String,
    pub model: String,
    pub serial: String,
    pub wwn: String,
    pub size_bytes: u64,
    pub removable: bool,
    pub mounted: bool,
    pub held: bool,
    pub eligible: bool,
    #[serde(default)]
    pub blocker_codes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestProvisioningInventory {
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub asset_tag: String,
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub memory_bytes: u64,
    pub firmware_version: String,
    pub kernel_version: String,
    pub boot_mode: String,
    pub secure_boot: bool,
    pub virtualization: String,
    #[serde(default)]
    pub ethernet_interfaces: Vec<NestProvisioningEthernetInterface>,
    #[serde(default)]
    pub disks: Vec<NestProvisioningDisk>,
    /// Paths of disks left out of `disks` because they have no serial number
    /// and so no name that stays the same across restarts (e.g., a VirtIO Block
    /// disk on Proxmox). Sent to Manage so the Console can show actionable
    /// remediation, while remaining excluded from `hardware_digest`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks_without_serial: Vec<String>,
    /// Best-effort pre-approval SMART health per eligible disk id. Kept outside
    /// `NestProvisioningDisk` so signed install plans and disk identity checks
    /// never depend on volatile SMART telemetry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub disk_smart_health: BTreeMap<String, NestProvisioningDiskSmartHealth>,
}

pub(crate) async fn collect_inventory() -> Result<NestProvisioningInventory> {
    let mut ethernet_interfaces = collect_ethernet_interfaces().await?;
    ethernet_interfaces.sort_by(|left, right| left.id.cmp(&right.id));
    let (mut disks, disks_without_serial) = collect_disks().await?;
    disks.sort_by(|left, right| left.id.cmp(&right.id));
    let mut disk_smart_health = BTreeMap::new();
    for disk in &disks {
        if disk.eligible {
            if let Some(health) = probe_disk_smart_health(&disk.path).await {
                disk_smart_health.insert(disk.id.clone(), health);
            }
        }
    }
    Ok(NestProvisioningInventory {
        manufacturer: clean(&read_trimmed("/sys/class/dmi/id/sys_vendor"), 256),
        model: clean(&read_trimmed("/sys/class/dmi/id/product_name"), 256),
        serial_number: clean(&read_trimmed("/sys/class/dmi/id/product_serial"), 256),
        asset_tag: clean(&read_trimmed("/sys/class/dmi/id/chassis_asset_tag"), 256),
        cpu_model: clean(&cpu_model(), 256),
        cpu_cores: std::thread::available_parallelism()
            .map(|value| value.get() as u32)
            .unwrap_or(0),
        memory_bytes: memory_bytes(),
        firmware_version: clean(&read_trimmed("/sys/class/dmi/id/bios_version"), 256),
        kernel_version: clean(&command_text("uname", &["-r"]).await, 256),
        boot_mode: if Path::new("/sys/firmware/efi").is_dir() {
            "uefi".to_string()
        } else {
            "legacy".to_string()
        },
        secure_boot: secure_boot_enabled(),
        virtualization: clean(&command_text("systemd-detect-virt", &["--vm"]).await, 256),
        ethernet_interfaces,
        disks,
        disks_without_serial,
        disk_smart_health,
    })
}

/// Manufacturer, model and virtualization, the only hardware a generic ISO
/// names before it is claimed (no serial number). `none` on bare metal.
pub(crate) async fn registration_hardware() -> (String, String, String) {
    let virtualization = command_text("systemd-detect-virt", &["--vm"]).await;
    (
        read_trimmed("/sys/class/dmi/id/sys_vendor"),
        read_trimmed("/sys/class/dmi/id/product_name"),
        if virtualization.is_empty() {
            "none".to_string()
        } else {
            virtualization
        },
    )
}

pub(crate) fn inventory_sha256(inventory: &NestProvisioningInventory) -> Result<String> {
    let bytes = serde_json::to_vec(inventory).context("serialize hardware inventory")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn hardware_digest(inventory: &NestProvisioningInventory) -> Result<String> {
    let value = canonical_json(json!({
        "manufacturer": inventory.manufacturer,
        "model": inventory.model,
        "serial_number": inventory.serial_number,
        "asset_tag": inventory.asset_tag,
        "cpu_model": inventory.cpu_model,
        "cpu_cores": inventory.cpu_cores,
        "memory_bytes": inventory.memory_bytes,
        "ethernet": inventory.ethernet_interfaces.iter().map(|interface| json!({
            "id": interface.id,
            "mac": interface.mac,
        })).collect::<Vec<_>>(),
        "disks": inventory.disks.iter().map(|disk| json!({
            "id": disk.id,
            "serial": disk.serial,
            "wwn": disk.wwn,
            "size_bytes": disk.size_bytes,
        })).collect::<Vec<_>>(),
    }));
    let bytes = serde_json::to_vec(&value).context("serialize hardware identity")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn revalidate_plan_hardware(
    plan: &SignedInstallPlan,
    inventory: &NestProvisioningInventory,
) -> Result<()> {
    if hardware_digest(inventory)? != plan.hardware_digest {
        bail!("stable hardware identity changed after approval")
    }
    if inventory.boot_mode != "uefi" {
        bail!("UEFI boot must remain active")
    }
    let disk = inventory
        .disks
        .iter()
        .find(|disk| disk.id == plan.target_disk_id)
        .ok_or_else(|| anyhow!("approved target disk is missing"))?;
    if disk != &plan.target_disk || !disk.eligible {
        bail!("approved disk identity or eligibility changed")
    }
    let interface = inventory
        .ethernet_interfaces
        .iter()
        .find(|interface| interface.id == plan.network_interface.id)
        .ok_or_else(|| anyhow!("approved wired interface is missing"))?;
    if interface.name != plan.network_interface.name
        || interface.mac != plan.network_interface.mac
        || !interface.link_up
    {
        bail!("approved wired interface identity or link state changed")
    }
    Ok(())
}

pub(crate) fn revalidate_durable_plan_hardware(
    plan: &SignedInstallPlan,
    inventory: &NestProvisioningInventory,
) -> Result<()> {
    if hardware_digest(inventory)? != plan.hardware_digest || inventory.boot_mode != "uefi" {
        bail!("hardware identity or UEFI boot changed during installation recovery")
    }
    let disk = inventory
        .disks
        .iter()
        .find(|disk| disk.id == plan.target_disk_id)
        .ok_or_else(|| anyhow!("approved target disk is missing during recovery"))?;
    if disk.id != plan.target_disk.id
        || disk.path != plan.target_disk.path
        || disk.model != plan.target_disk.model
        || disk.serial != plan.target_disk.serial
        || disk.wwn != plan.target_disk.wwn
        || disk.size_bytes != plan.target_disk.size_bytes
        || disk.removable
        || disk.held
    {
        bail!("approved disk identity changed during installation recovery")
    }
    Ok(())
}

pub(crate) async fn preflight_network(
    plan: &SignedInstallPlan,
    inventory: &NestProvisioningInventory,
    manage_origin: &str,
) -> Result<()> {
    let interface = inventory
        .ethernet_interfaces
        .iter()
        .find(|interface| interface.id == plan.network.interface_id && interface.link_up)
        .ok_or_else(|| anyhow!("approved wired interface is missing or disconnected"))?;
    match plan.network.mode.as_str() {
        "dhcp" => {
            if plan.network.address_cidr.is_some()
                || plan.network.gateway.is_some()
                || !plan.network.dns_servers.is_empty()
            {
                bail!("DHCP plan contains unexpected static settings")
            }
        }
        "static" => {
            let cidr = plan
                .network
                .address_cidr
                .as_deref()
                .ok_or_else(|| anyhow!("static plan omitted address_cidr"))?;
            let (address, prefix) = parse_ipv4_cidr(cidr)?;
            let gateway: Ipv4Addr = plan
                .network
                .gateway
                .as_deref()
                .ok_or_else(|| anyhow!("static plan omitted gateway"))?
                .parse()
                .context("static gateway is invalid")?;
            if !same_ipv4_subnet(address, gateway, prefix) || address == gateway {
                bail!("static gateway is outside the selected subnet")
            }
            let dns_servers = plan
                .network
                .dns_servers
                .iter()
                .map(|server| {
                    server
                        .parse::<Ipv4Addr>()
                        .with_context(|| format!("static DNS server {server} is not IPv4"))
                })
                .collect::<Result<Vec<_>>>()?;
            if dns_servers.is_empty() {
                bail!("static DNS configuration is invalid")
            }
            let (manage_host, manage_port) = manage_https_endpoint(manage_origin)?;
            let duplicate_free = bounded_live_arping_success(
                &[
                    "-D",
                    "-q",
                    "-c",
                    "2",
                    "-I",
                    &interface.name,
                    &address.to_string(),
                ],
                Duration::from_secs(8),
            )
            .await
            .context(
                "Nest setup media cannot run its network safety check; create a new Nest ISO in Tiaris and try again",
            )?;
            if !duplicate_free {
                bail!("static address is already in use or duplicate detection failed")
            }

            ensure_static_probe_namespace_available().await?;
            let address_text = address.to_string();
            let address_cidr = format!("{address}/{prefix}");
            let source_rule = format!("{address}/32");
            let existing_address = interface.addresses.iter().find(|candidate| {
                candidate
                    .split_once('/')
                    .is_some_and(|(candidate, _)| candidate == address_text)
            });
            if existing_address.is_some_and(|candidate| candidate != &address_cidr) {
                bail!("the static address is already configured with a different prefix")
            }
            let mut probe = StaticNetworkProbe::new(
                interface.name.clone(),
                address_cidr.clone(),
                source_rule.clone(),
            );
            if existing_address.is_none() {
                run_ip(&[
                    "-4",
                    "address",
                    "add",
                    &address_cidr,
                    "dev",
                    &interface.name,
                ])
                .await
                .context("install candidate static address for connectivity preflight")?;
                probe.address_added = true;
            }

            let network = ipv4_network(address, prefix);
            let network_cidr = format!("{network}/{prefix}");
            run_ip(&[
                "-4",
                "route",
                "add",
                "table",
                STATIC_PREFLIGHT_ROUTE_TABLE,
                &network_cidr,
                "dev",
                &interface.name,
                "src",
                &address_text,
            ])
            .await
            .context("install candidate static subnet route")?;
            probe.route_owned = true;
            let gateway_text = gateway.to_string();
            run_ip(&[
                "-4",
                "route",
                "add",
                "table",
                STATIC_PREFLIGHT_ROUTE_TABLE,
                "default",
                "via",
                &gateway_text,
                "dev",
                &interface.name,
                "src",
                &address_text,
                "onlink",
            ])
            .await
            .context("install candidate static default route")?;
            run_ip(&[
                "-4",
                "rule",
                "add",
                "priority",
                STATIC_PREFLIGHT_RULE_PRIORITY,
                "from",
                &source_rule,
                "lookup",
                STATIC_PREFLIGHT_ROUTE_TABLE,
            ])
            .await
            .context("install candidate static source-policy rule")?;
            probe.rule_owned = true;

            let gateway_reachable = bounded_live_arping_success(
                &[
                    "-q",
                    "-c",
                    "2",
                    "-I",
                    &interface.name,
                    "-s",
                    &address_text,
                    &gateway_text,
                ],
                Duration::from_secs(8),
            )
            .await
            .context(
                "Nest setup media cannot run its network safety check; create a new Nest ISO in Tiaris and try again",
            )?;
            if !gateway_reachable {
                bail!("approved static gateway did not answer on the selected interface")
            }

            let mut resolved_addresses = Vec::new();
            for dns_server in dns_servers {
                let answers =
                    query_dns_ipv4(address, dns_server, &manage_host, Duration::from_secs(8))
                        .await
                        .with_context(|| {
                            format!("query Management through approved DNS server {dns_server}")
                        })?;
                if answers.is_empty() {
                    bail!("approved DNS server {dns_server} did not resolve the Management origin")
                }
                resolved_addresses.extend(answers);
            }
            resolved_addresses.sort_unstable();
            resolved_addresses.dedup();

            let mut https_reachable = false;
            for resolved in resolved_addresses {
                let resolved = resolved.to_string();
                let resolve = format!("{manage_host}:{manage_port}:{resolved}");
                let reachable = bounded_command_success(
                    "curl",
                    &[
                        "--silent",
                        "--show-error",
                        "--output",
                        "/dev/null",
                        "--connect-timeout",
                        "5",
                        "--max-time",
                        "15",
                        "--proto",
                        "=https",
                        "--tlsv1.2",
                        "--noproxy",
                        "*",
                        "--interface",
                        &address_text,
                        "--resolve",
                        &resolve,
                        manage_origin,
                    ],
                    Duration::from_secs(20),
                )
                .await
                .context("probe Management HTTPS through approved static network")?;
                if reachable {
                    https_reachable = true;
                    break;
                }
            }
            if !https_reachable {
                bail!("approved static network cannot establish Management HTTPS")
            }
        }
        _ => bail!("approved network mode is unsupported"),
    }
    Ok(())
}

struct StaticNetworkProbe {
    interface: String,
    address_cidr: String,
    source_rule: String,
    address_added: bool,
    route_owned: bool,
    rule_owned: bool,
}

impl StaticNetworkProbe {
    fn new(interface: String, address_cidr: String, source_rule: String) -> Self {
        Self {
            interface,
            address_cidr,
            source_rule,
            address_added: false,
            route_owned: false,
            rule_owned: false,
        }
    }
}

impl Drop for StaticNetworkProbe {
    fn drop(&mut self) {
        if self.rule_owned {
            let _ = StdCommand::new("ip")
                .args([
                    "-4",
                    "rule",
                    "del",
                    "priority",
                    STATIC_PREFLIGHT_RULE_PRIORITY,
                    "from",
                    &self.source_rule,
                    "lookup",
                    STATIC_PREFLIGHT_ROUTE_TABLE,
                ])
                .status();
        }
        if self.route_owned {
            let _ = StdCommand::new("ip")
                .args([
                    "-4",
                    "route",
                    "flush",
                    "table",
                    STATIC_PREFLIGHT_ROUTE_TABLE,
                ])
                .status();
        }
        if self.address_added {
            let _ = StdCommand::new("ip")
                .args([
                    "-4",
                    "address",
                    "del",
                    &self.address_cidr,
                    "dev",
                    &self.interface,
                ])
                .status();
        }
    }
}

async fn ensure_static_probe_namespace_available() -> Result<()> {
    let rules = bounded_command_output("ip", &["-4", "rule", "show"], Duration::from_secs(5))
        .await
        .context("inspect IPv4 policy rules")?;
    let table_in_use = String::from_utf8(rules)
        .context("IPv4 policy rule output is not UTF-8")?
        .lines()
        .any(|line| {
            line.split_whitespace()
                .any(|field| field.trim_end_matches(':') == STATIC_PREFLIGHT_RULE_PRIORITY)
                || line
                    .split_whitespace()
                    .any(|field| field == STATIC_PREFLIGHT_ROUTE_TABLE)
        });
    if table_in_use {
        bail!("reserved static-network preflight policy namespace is already in use")
    }
    let routes = bounded_command_output(
        "ip",
        &["-4", "route", "show", "table", STATIC_PREFLIGHT_ROUTE_TABLE],
        Duration::from_secs(5),
    )
    .await
    .context("inspect static-network preflight route table")?;
    if !String::from_utf8(routes)
        .context("IPv4 route output is not UTF-8")?
        .trim()
        .is_empty()
    {
        bail!("reserved static-network preflight route table is already in use")
    }
    Ok(())
}

async fn run_ip(arguments: &[&str]) -> Result<()> {
    bounded_command_output("ip", arguments, Duration::from_secs(5))
        .await
        .map(|_| ())
}

async fn bounded_command_output(
    program: &str,
    arguments: &[&str],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let output = bounded_command(program, arguments, timeout).await?;
    if !output.status.success() {
        bail!("{program} exited unsuccessfully")
    }
    Ok(output.stdout)
}

async fn bounded_command_success(
    program: &str,
    arguments: &[&str],
    timeout: Duration,
) -> Result<bool> {
    Ok(bounded_command(program, arguments, timeout)
        .await?
        .status
        .success())
}

async fn bounded_live_arping_success(arguments: &[&str], timeout: Duration) -> Result<bool> {
    if Path::new("/cdrom/tiaris/nixos-appliance").is_file() {
        return bounded_command_success("arping", arguments, timeout).await;
    }
    let mut busybox_arguments = Vec::with_capacity(arguments.len() + 1);
    busybox_arguments.push("arping");
    busybox_arguments.extend_from_slice(arguments);
    bounded_command_success(LIVE_INSTALLER_BUSYBOX, &busybox_arguments, timeout).await
}

async fn bounded_command(program: &str, arguments: &[&str], timeout: Duration) -> Result<Output> {
    let mut command = Command::new(program);
    command.args(arguments).kill_on_drop(true);
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .with_context(|| format!("{program} timed out"))?
        .with_context(|| format!("run {program}"))?;
    if output.stdout.len() > STATIC_PREFLIGHT_OUTPUT_LIMIT
        || output.stderr.len() > STATIC_PREFLIGHT_OUTPUT_LIMIT
    {
        bail!("{program} returned excessive output")
    }
    Ok(output)
}

fn manage_https_endpoint(manage_origin: &str) -> Result<(String, u16)> {
    let url = reqwest::Url::parse(manage_origin).context("Management origin is not a valid URL")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("Management origin must be a canonical HTTPS origin")
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("Management origin omitted its host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("Management origin omitted its HTTPS port"))?;
    Ok((host, port))
}

fn ipv4_network(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = u32::MAX.checked_shl((32 - prefix).into()).unwrap_or(0);
    Ipv4Addr::from(u32::from(address) & mask)
}

/// Resolve IPv4 A records for `host` directly against `dns_server` from
/// `source_ip` without relying on external tools (`dig` is not shipped on the
/// minimal NixOS setup ISO). Falls back to TCP when the UDP response is
/// truncated (TC bit set).
async fn query_dns_ipv4(
    source_ip: Ipv4Addr,
    dns_server: Ipv4Addr,
    host: &str,
    timeout: Duration,
) -> Result<Vec<Ipv4Addr>> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(vec![ip]);
    }
    let txid: u16 = rand::random();
    let packet = build_dns_a_query(txid, host)?;
    let server_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(dns_server, 53));
    query_dns_ipv4_addr(source_ip, server_addr, txid, &packet, timeout).await
}

async fn query_dns_ipv4_addr(
    source_ip: Ipv4Addr,
    server_addr: std::net::SocketAddr,
    txid: u16,
    packet: &[u8],
    timeout: Duration,
) -> Result<Vec<Ipv4Addr>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpSocket, UdpSocket};

    let bind_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(source_ip, 0));
    let deadline = tokio::time::Instant::now() + timeout;

    let udp_response = {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("bind UDP socket for static DNS preflight")?;
        socket
            .connect(server_addr)
            .await
            .context("connect UDP socket to approved DNS server")?;
        let mut buf = vec![0u8; 4096];
        let mut received = None;
        for attempt in 0..2 {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let wait = remaining.min(Duration::from_secs(3));
            socket
                .send(packet)
                .await
                .context("send DNS query to approved DNS server")?;
            match tokio::time::timeout(wait, socket.recv(&mut buf)).await {
                Ok(Ok(len)) => {
                    buf.truncate(len);
                    received = Some(buf);
                    break;
                }
                Ok(Err(err)) if attempt == 0 => {
                    let _ = err;
                }
                Ok(Err(err)) => return Err(err).context("read DNS UDP response"),
                Err(_) if attempt == 0 => {}
                Err(_) => bail!("DNS query timed out"),
            }
        }
        received.ok_or_else(|| anyhow!("DNS query timed out"))?
    };

    if udp_response.len() >= 4 && (udp_response[2] & 0x02) != 0 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("DNS TCP fallback timed out");
        }
        let tcp_result = tokio::time::timeout(remaining, async {
            let socket = TcpSocket::new_v4().context("create TCP socket for DNS fallback")?;
            socket
                .bind(bind_addr)
                .context("bind TCP socket for DNS fallback")?;
            let mut stream = socket
                .connect(server_addr)
                .await
                .context("connect TCP to approved DNS server")?;
            let len = u16::try_from(packet.len()).context("DNS query too large for TCP")?;
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(packet).await?;
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            if !(12..=16 * 1024).contains(&resp_len) {
                bail!("DNS TCP response length {resp_len} is out of bounds");
            }
            let mut resp = vec![0u8; resp_len];
            stream.read_exact(&mut resp).await?;
            Ok::<_, anyhow::Error>(resp)
        })
        .await
        .context("DNS TCP fallback timed out")??;
        return parse_dns_a_response(&tcp_result, txid);
    }

    parse_dns_a_response(&udp_response, txid)
}

fn build_dns_a_query(txid: u16, host: &str) -> Result<Vec<u8>> {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        bail!("invalid DNS hostname");
    }
    let mut out = Vec::with_capacity(12 + trimmed.len() + 6);
    out.extend_from_slice(&txid.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            bail!("invalid DNS label");
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root label
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    Ok(out)
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Result<usize> {
    let mut jumps = 0usize;
    loop {
        if offset >= packet.len() {
            bail!("truncated DNS name");
        }
        let len = packet[offset];
        if len == 0 {
            return Ok(offset + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                bail!("truncated DNS compression pointer");
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (packet[offset + 1] as usize);
            if ptr >= packet.len() {
                bail!("DNS compression pointer out of bounds");
            }
            jumps += 1;
            if jumps > 32 {
                bail!("DNS compression pointer loop");
            }
            // Validate target lazily enough to reject loops, and return the
            // position immediately after this 2-byte pointer in the caller stream.
            let mut cursor = ptr;
            let mut depth = jumps;
            loop {
                if cursor >= packet.len() {
                    bail!("truncated DNS compressed target");
                }
                let next = packet[cursor];
                if next == 0 {
                    break;
                }
                if (next & 0xC0) == 0xC0 {
                    if cursor + 1 >= packet.len() {
                        bail!("truncated DNS compressed pointer");
                    }
                    cursor = (((next & 0x3F) as usize) << 8) | (packet[cursor + 1] as usize);
                    depth += 1;
                    if depth > 32 || cursor >= packet.len() {
                        bail!("invalid DNS compression pointer");
                    }
                } else if (next & 0xC0) != 0 {
                    bail!("invalid DNS label flags");
                } else {
                    cursor = cursor
                        .checked_add(1 + next as usize)
                        .ok_or_else(|| anyhow!("DNS label overflow"))?;
                }
            }
            return Ok(offset + 2);
        }
        if (len & 0xC0) != 0 {
            bail!("invalid DNS label flags");
        }
        offset = offset
            .checked_add(1 + len as usize)
            .ok_or_else(|| anyhow!("DNS label overflow"))?;
    }
}

fn parse_dns_a_response(packet: &[u8], expected_txid: u16) -> Result<Vec<Ipv4Addr>> {
    if packet.len() < 12 {
        bail!("DNS response is truncated");
    }
    let txid = u16::from_be_bytes([packet[0], packet[1]]);
    if txid != expected_txid {
        bail!("DNS response transaction ID mismatch");
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 {
        bail!("DNS packet is not a response");
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        bail!("DNS server returned error rcode {rcode}");
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..qdcount {
        offset = skip_dns_name(packet, offset)?;
        if offset + 4 > packet.len() {
            bail!("truncated DNS question");
        }
        offset += 4;
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        offset = skip_dns_name(packet, offset)?;
        if offset + 10 > packet.len() {
            bail!("truncated DNS answer header");
        }
        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > packet.len() {
            bail!("truncated DNS answer rdata");
        }
        if rtype == 1 && rclass == 1 && rdlength == 4 {
            answers.push(Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ));
        }
        offset += rdlength;
    }
    Ok(answers)
}

async fn collect_ethernet_interfaces() -> Result<Vec<NestProvisioningEthernetInterface>> {
    let mut interfaces = Vec::new();
    for entry in fs::read_dir("/sys/class/net").context("enumerate network interfaces")? {
        let entry = entry.context("read network interface")?;
        let name = entry.file_name().to_string_lossy().to_string();
        let root = entry.path();
        if name == "lo"
            || root.join("wireless").exists()
            || read_trimmed(root.join("type")) != "1"
            || !root.join("device").exists()
        {
            continue;
        }
        let mac = normalize_mac(&read_trimmed(root.join("address")))?;
        let properties = command_text(
            "udevadm",
            &[
                "info",
                "--query=property",
                &format!("--path={}", root.display()),
            ],
        )
        .await;
        let stable_path = properties
            .lines()
            .find_map(|line| line.strip_prefix("ID_PATH="))
            .unwrap_or("");
        let fallback_id = format!("mac-{mac}");
        let id = clean(
            if stable_path.is_empty() {
                &fallback_id
            } else {
                stable_path
            },
            256,
        );
        let network = command_json("ip", &["-j", "address", "show", "dev", &name]).await;
        let mut addresses = network
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| row.get("addr_info"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|address| {
                let local = address.get("local")?.as_str()?;
                let prefix = address.get("prefixlen")?.as_u64()?;
                Some(format!("{local}/{prefix}"))
            })
            .collect::<Vec<_>>();
        addresses.sort();
        addresses.dedup();
        let routes = command_json("ip", &["-j", "route", "show", "default", "dev", &name]).await;
        let gateway = routes
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|route| route.get("gateway"))
            .and_then(Value::as_str)
            .map(|value| clean(value, 128));
        interfaces.push(NestProvisioningEthernetInterface {
            id,
            name: clean(&name, 64),
            mac,
            link_up: read_trimmed(root.join("carrier")) == "1",
            addresses,
            gateway,
        });
    }
    Ok(interfaces)
}

async fn collect_disks() -> Result<(Vec<NestProvisioningDisk>, Vec<String>)> {
    let output = Command::new("lsblk")
        .args([
            "--json",
            "--bytes",
            "--output",
            "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,RM,MOUNTPOINTS,RO,HOTPLUG",
        ])
        .output()
        .await
        .context("run lsblk")?;
    if !output.status.success() || output.stdout.len() > 4 * 1024 * 1024 {
        bail!("lsblk could not provide bounded disk inventory")
    }
    let value: Value = serde_json::from_slice(&output.stdout).context("parse lsblk inventory")?;
    disks_from_lsblk(&value, stable_disk_id)
}

/// The disks Tiaris may approve, and the paths of disks without a stable
/// name. One such disk must not stop the whole hardware check: it is left
/// out and named, like a removable or small disk is listed and refused.
fn disks_from_lsblk(
    value: &Value,
    stable_id: impl Fn(&Path) -> Result<Option<String>>,
) -> Result<(Vec<NestProvisioningDisk>, Vec<String>)> {
    let rows = value
        .get("blockdevices")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("lsblk inventory omitted blockdevices"))?;
    let mut disks = Vec::new();
    let mut without_serial = Vec::new();
    for row in rows {
        if row.get("type").and_then(Value::as_str) != Some("disk") {
            continue;
        }
        let path = row
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("disk inventory omitted path"))?;
        let size_bytes = value_u64(row.get("size")).unwrap_or(0);
        let removable = value_bool(row.get("rm")) || value_bool(row.get("hotplug"));
        let mounted = has_mountpoint(row);
        let kname = row.get("kname").and_then(Value::as_str).unwrap_or("");
        let held = value_bool(row.get("ro"))
            || fs::read_dir(format!("/sys/class/block/{kname}/holders"))
                .ok()
                .is_some_and(|mut entries| entries.next().is_some());
        let mut blocker_codes = Vec::new();
        if removable {
            blocker_codes.push("removable_disk".to_string());
        }
        if mounted {
            blocker_codes.push("mounted_disk".to_string());
        }
        if held {
            blocker_codes.push("held_disk".to_string());
        }
        if size_bytes < MIN_DISK_BYTES {
            blocker_codes.push("disk_too_small".to_string());
        }
        let Some(id) = stable_id(Path::new(path))? else {
            without_serial.push(clean(path, 256));
            continue;
        };
        disks.push(NestProvisioningDisk {
            id,
            path: clean(path, 256),
            model: clean(value_string(row.get("model")), 128),
            serial: clean(value_string(row.get("serial")), 128),
            wwn: clean(value_string(row.get("wwn")), 128),
            size_bytes,
            removable,
            mounted,
            held,
            eligible: blocker_codes.is_empty(),
            blocker_codes,
        });
    }
    Ok((disks, without_serial))
}

/// The disk's name under `/dev/disk/by-id`, which udev makes from its serial
/// number or WWN; `None` for a disk that reports neither.
fn stable_disk_id(path: &Path) -> Result<Option<String>> {
    let target =
        fs::canonicalize(path).with_context(|| format!("resolve disk path {}", path.display()))?;
    let mut candidates = Vec::new();
    if let Ok(entries) = fs::read_dir("/dev/disk/by-id") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains("-part") {
                continue;
            }
            if fs::canonicalize(entry.path()).ok().as_ref() == Some(&target) {
                candidates.push(name);
            }
        }
    }
    candidates.sort_by_key(|name| (disk_id_priority(name), name.clone()));
    Ok(candidates.into_iter().next().map(|name| clean(&name, 512)))
}

fn disk_id_priority(name: &str) -> u8 {
    if name.starts_with("nvme-eui.") || name.starts_with("wwn-") {
        0
    } else if name.starts_with("ata-") || name.starts_with("scsi-") {
        1
    } else if name.starts_with("virtio-") {
        2
    } else {
        3
    }
}

async fn probe_disk_smart_health(disk_path: &str) -> Option<NestProvisioningDiskSmartHealth> {
    let mut cmd = Command::new("smartctl");
    cmd.args(["-j", "-H", "-A", disk_path]).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(4), cmd.output())
        .await
        .ok()?
        .ok()?;
    if output.stdout.is_empty() || output.stdout.len() > 256 * 1024 {
        return None;
    }
    let payload: Value = serde_json::from_slice(&output.stdout).ok()?;
    let exit_code = output.status.code().unwrap_or(0);
    parse_smartctl_disk_health(&payload, exit_code)
}

fn parse_smartctl_disk_health(
    payload: &Value,
    exit_code: i32,
) -> Option<NestProvisioningDiskSmartHealth> {
    let passed = payload
        .get("smart_status")
        .and_then(|v| v.get("passed"))
        .and_then(Value::as_bool);
    let nvme = payload
        .get("nvme_smart_health_information_log")
        .and_then(Value::as_object);
    let ata_table = payload
        .get("ata_smart_attributes")
        .and_then(|v| v.get("table"))
        .and_then(Value::as_array);
    if passed.is_none() && nvme.is_none() && ata_table.is_none() {
        return None;
    }

    let mut status = "ok";
    if passed == Some(false) || (exit_code & 0x08) != 0 {
        status = "failing";
    }
    let mut wear_percent: Option<u8> = None;
    let mut reallocated_sectors: Option<u64> = None;
    let mut temperature_celsius: Option<i16> = payload
        .get("temperature")
        .and_then(|v| v.get("current"))
        .and_then(Value::as_i64)
        .and_then(|t| i16::try_from(t).ok())
        .filter(|t| (-40..=150).contains(t));

    if let Some(nvme) = nvme {
        if nvme
            .get("critical_warning")
            .and_then(Value::as_u64)
            .is_some_and(|w| w != 0)
        {
            status = "failing";
        }
        if let Some(used) = nvme.get("percentage_used").and_then(Value::as_u64) {
            wear_percent = Some(used.min(100) as u8);
            if used >= 95 {
                status = "failing";
            } else if used >= 85 && status == "ok" {
                status = "warning";
            }
        }
        if nvme
            .get("media_errors")
            .and_then(Value::as_u64)
            .is_some_and(|m| m > 0)
            && status == "ok"
        {
            status = "warning";
        }
        if temperature_celsius.is_none() {
            temperature_celsius = nvme
                .get("temperature")
                .and_then(Value::as_i64)
                .and_then(|t| i16::try_from(t).ok())
                .filter(|t| (-40..=150).contains(t));
        }
    }

    if let Some(rows) = ata_table {
        for row in rows {
            let Some(id) = row.get("id").and_then(Value::as_u64) else {
                continue;
            };
            let raw_val = row
                .get("raw")
                .and_then(|r| r.get("value"))
                .and_then(Value::as_u64);
            match id {
                5 => {
                    if let Some(val) = raw_val {
                        reallocated_sectors = Some(val);
                        if val >= 50 {
                            status = "failing";
                        } else if val > 0 && status == "ok" {
                            status = "warning";
                        }
                    }
                }
                197 | 198 => {
                    if raw_val.is_some_and(|v| v > 0) && status == "ok" {
                        status = "warning";
                    }
                }
                177 | 231 | 233 => {
                    if wear_percent.is_none() {
                        if let Some(norm) = row.get("value").and_then(Value::as_u64) {
                            if norm <= 100 {
                                let used = (100 - norm) as u8;
                                wear_percent = Some(used);
                                if used >= 95 {
                                    status = "failing";
                                } else if used >= 85 && status == "ok" {
                                    status = "warning";
                                }
                            }
                        }
                    }
                }
                190 | 194 => {
                    if temperature_celsius.is_none() {
                        if let Some(raw) = raw_val {
                            let temp = (raw & 0xFF) as i16;
                            if (0..=150).contains(&temp) {
                                temperature_celsius = Some(temp);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if temperature_celsius.is_some_and(|t| t >= 70) && status == "ok" {
        status = "warning";
    }

    Some(NestProvisioningDiskSmartHealth {
        status: status.to_string(),
        wear_percent,
        reallocated_sectors,
        temperature_celsius,
    })
}

fn has_mountpoint(value: &Value) -> bool {
    let mounted_here = value
        .get("mountpoints")
        .and_then(Value::as_array)
        .is_some_and(|mounts| mounts.iter().any(|mount| !mount.is_null()));
    mounted_here
        || value
            .get("children")
            .and_then(Value::as_array)
            .is_some_and(|children| children.iter().any(has_mountpoint))
}

fn value_bool(value: Option<&Value>) -> bool {
    value.is_some_and(|value| {
        value.as_bool().unwrap_or(false)
            || value.as_u64().unwrap_or(0) != 0
            || value.as_str().is_some_and(|value| value == "1")
    })
}

fn value_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })
}

fn value_string(value: Option<&Value>) -> &str {
    value.and_then(Value::as_str).unwrap_or("")
}

fn secure_boot_enabled() -> bool {
    let Ok(entries) = fs::read_dir("/sys/firmware/efi/efivars") else {
        return false;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("SecureBoot-") {
            return false;
        }
        fs::read(entry.path())
            .ok()
            .is_some_and(|value| value.get(4) == Some(&1))
    })
}

fn cpu_model() -> String {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|body| {
            body.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name.trim() == "model name").then(|| value.trim().to_string())
            })
        })
        .unwrap_or_default()
}

fn memory_bytes() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|body| {
            body.lines().find_map(|line| {
                let value = line.strip_prefix("MemTotal:")?.trim();
                value
                    .strip_suffix(" kB")?
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .and_then(|kilobytes| kilobytes.checked_mul(1024))
            })
        })
        .unwrap_or(0)
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
    let body = command_text(program, arguments).await;
    serde_json::from_str(&body).unwrap_or(Value::Null)
}

fn read_trimmed(path: impl Into<PathBuf>) -> String {
    fs::read_to_string(path.into())
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn clean(value: &str, max: usize) -> String {
    value.trim().chars().take(max).collect()
}

fn normalize_mac(value: &str) -> Result<String> {
    let compact = value
        .trim()
        .replace('-', ":")
        .split(':')
        .collect::<Vec<_>>()
        .join("")
        .to_ascii_lowercase();
    if compact.len() != 12 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("wired interface has an invalid MAC address")
    }
    Ok((0..6)
        .map(|index| compact[index * 2..index * 2 + 2].to_string())
        .collect::<Vec<_>>()
        .join(":"))
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8)> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow!("static address must use IPv4 CIDR notation"))?;
    let address = address.parse().context("static IPv4 address is invalid")?;
    let prefix: u8 = prefix.parse().context("static IPv4 prefix is invalid")?;
    if !(1..=32).contains(&prefix) {
        bail!("static IPv4 prefix is invalid")
    }
    Ok((address, prefix))
}

fn same_ipv4_subnet(left: Ipv4Addr, right: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl((32 - prefix).into()).unwrap_or(0);
    u32::from(left) & mask == u32::from(right) & mask
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted = object
                .into_iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stable_inventory_fixture() -> NestProvisioningInventory {
        NestProvisioningInventory {
            manufacturer: "Tiaris".into(),
            model: "Qualification VM".into(),
            serial_number: "vm-1".into(),
            asset_tag: "lab".into(),
            cpu_model: "test cpu".into(),
            cpu_cores: 4,
            memory_bytes: 32 * 1024 * 1024 * 1024,
            firmware_version: "firmware-a".into(),
            kernel_version: "kernel-a".into(),
            boot_mode: "uefi".into(),
            secure_boot: true,
            virtualization: "kvm".into(),
            ethernet_interfaces: vec![NestProvisioningEthernetInterface {
                id: "pci-0000:00:03.0".into(),
                name: "enp0s3".into(),
                mac: "52:54:00:12:34:56".into(),
                link_up: true,
                addresses: vec!["10.62.52.76/24".into()],
                gateway: Some("10.62.52.1".into()),
            }],
            disks: vec![NestProvisioningDisk {
                id: "scsi-qualification".into(),
                path: "/dev/sda".into(),
                model: "QEMU disk".into(),
                serial: "disk-1".into(),
                wwn: String::new(),
                size_bytes: 160 * 1024 * 1024 * 1024,
                removable: false,
                mounted: false,
                held: false,
                eligible: true,
                blocker_codes: Vec::new(),
            }],
            disks_without_serial: Vec::new(),
            disk_smart_health: BTreeMap::new(),
        }
    }

    #[test]
    fn disks_without_serial_and_smart_health_serialize_without_changing_hardware_digest() {
        let mut inv = stable_inventory_fixture();
        let baseline_digest = hardware_digest(&inv).unwrap();
        let empty_json = serde_json::to_value(&inv).unwrap();
        assert!(empty_json.get("disks_without_serial").is_none());
        assert!(empty_json.get("disk_smart_health").is_none());

        inv.disks_without_serial = vec!["/dev/vda".into()];
        inv.disk_smart_health.insert(
            "scsi-qualification".into(),
            NestProvisioningDiskSmartHealth {
                status: "warning".into(),
                wear_percent: Some(88),
                reallocated_sectors: Some(2),
                temperature_celsius: Some(44),
            },
        );
        assert_eq!(hardware_digest(&inv).unwrap(), baseline_digest);
        let with_fields = serde_json::to_value(&inv).unwrap();
        assert_eq!(with_fields["disks_without_serial"], json!(["/dev/vda"]));
        assert_eq!(
            with_fields["disk_smart_health"]["scsi-qualification"]["status"],
            "warning"
        );
    }

    #[test]
    fn smartctl_json_parser_classifies_nvme_ata_and_virtual_disks() {
        let nvme_warn = json!({
            "smart_status": {"passed": true},
            "nvme_smart_health_information_log": {
                "critical_warning": 0,
                "percentage_used": 90,
                "temperature": 42
            }
        });
        let parsed = parse_smartctl_disk_health(&nvme_warn, 0).unwrap();
        assert_eq!(parsed.status, "warning");
        assert_eq!(parsed.wear_percent, Some(90));
        assert_eq!(parsed.temperature_celsius, Some(42));

        let ata_fail = json!({
            "smart_status": {"passed": false},
            "ata_smart_attributes": {
                "table": [
                    {"id": 5, "raw": {"value": 64}},
                    {"id": 194, "raw": {"value": 39}}
                ]
            }
        });
        let parsed = parse_smartctl_disk_health(&ata_fail, 8).unwrap();
        assert_eq!(parsed.status, "failing");
        assert_eq!(parsed.reallocated_sectors, Some(64));
        assert_eq!(parsed.temperature_celsius, Some(39));

        // Virtual disks without SMART return None.
        assert!(parse_smartctl_disk_health(&json!({"device": {"type": "scsi"}}), 2).is_none());
    }

    #[test]
    fn stable_hardware_digest_ignores_volatile_network_and_software_inventory() {
        let inventory = stable_inventory_fixture();
        let expected = hardware_digest(&inventory).unwrap();
        let mut changed = inventory.clone();
        changed.ethernet_interfaces[0].addresses = vec!["10.62.52.99/24".into()];
        changed.ethernet_interfaces[0].gateway = Some("10.62.52.254".into());
        changed.firmware_version = "firmware-b".into();
        changed.kernel_version = "kernel-b".into();
        assert_eq!(hardware_digest(&changed).unwrap(), expected);

        changed.memory_bytes += 1024 * 1024 * 1024;
        assert_ne!(hardware_digest(&changed).unwrap(), expected);
    }

    #[test]
    fn subnet_validation_is_exact() {
        assert!(same_ipv4_subnet(
            "192.0.2.10".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            24
        ));
        assert!(!same_ipv4_subnet(
            "192.0.2.10".parse().unwrap(),
            "192.0.3.1".parse().unwrap(),
            24
        ));
    }

    #[test]
    fn management_connectivity_probe_preserves_an_explicit_https_port() {
        assert_eq!(
            manage_https_endpoint("https://manage.cybex.net").unwrap(),
            ("manage.cybex.net".to_string(), 443)
        );
        assert_eq!(
            manage_https_endpoint("https://manage.cybex.net:8443").unwrap(),
            ("manage.cybex.net".to_string(), 8443)
        );
        for invalid in [
            "http://manage.cybex.net",
            "https://user@manage.cybex.net",
            "https://manage.cybex.net/path",
            "https://manage.cybex.net?query=yes",
        ] {
            assert!(manage_https_endpoint(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn static_network_route_uses_the_approved_subnet() {
        assert_eq!(
            ipv4_network("192.0.2.129".parse().unwrap(), 25),
            "192.0.2.128".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn removable_or_small_disks_cannot_be_eligible() {
        let disk = NestProvisioningDisk {
            id: "ata-test".into(),
            path: "/dev/sda".into(),
            model: String::new(),
            serial: String::new(),
            wwn: String::new(),
            size_bytes: MIN_DISK_BYTES - 1,
            removable: false,
            mounted: false,
            held: false,
            eligible: false,
            blocker_codes: vec!["disk_too_small".into()],
        };
        assert!(!disk.eligible);
    }

    #[test]
    fn a_disk_without_a_stable_name_is_left_out_and_named() {
        // A VirtIO Block disk without a serial has no /dev/disk/by-id name.
        // It used to fail the whole inventory, and setup looped without a cause.
        let lsblk = json!({"blockdevices": [
            {"name": "sda", "kname": "no-such-a", "path": "/dev/sda", "type": "disk",
             "size": MIN_DISK_BYTES, "rm": false, "hotplug": false, "ro": false},
            {"name": "vda", "kname": "no-such-b", "path": "/dev/vda", "type": "disk",
             "size": MIN_DISK_BYTES, "rm": false, "hotplug": false, "ro": false},
            {"name": "sr0", "kname": "sr0", "path": "/dev/sr0", "type": "rom", "size": 0},
        ]});
        let (disks, without_serial) = disks_from_lsblk(&lsblk, |path| {
            Ok((path == Path::new("/dev/sda")).then(|| "scsi-0QEMU_HARDDISK_1".to_string()))
        })
        .unwrap();
        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].id, "scsi-0QEMU_HARDDISK_1");
        assert!(disks[0].eligible);
        assert_eq!(without_serial, vec!["/dev/vda".to_string()]);
    }

    #[test]
    fn appliance_disk_floor_matches_the_shared_cache_layout() {
        assert_eq!(MIN_DISK_BYTES, 160 * 1024 * 1024 * 1024);
    }

    #[test]
    fn dns_a_query_encodes_and_parses_compressed_answers() {
        let query = build_dns_a_query(0x1234, "manage.tiaris.com").unwrap();
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        assert!(build_dns_a_query(1, "").is_err());
        assert!(build_dns_a_query(1, "a..b").is_err());

        // Synthetic response: 1 question + 1 CNAME + 2 A answers using compression pointers.
        let mut resp = query.clone();
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x80; // RA=1, RCODE=0
        resp[6] = 0x00;
        resp[7] = 0x03; // ANCOUNT=3
        // Answer 1: CNAME pointing to 0x0c -> "cdn.tiaris.com"
        resp.extend_from_slice(&[
            0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 5, 3, b'c', b'd', b'n', 0,
        ]);
        // Answer 2: A record 203.0.113.10
        resp.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 10]);
        // Answer 3: A record 203.0.113.11
        resp.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 11]);

        let ips = parse_dns_a_response(&resp, 0x1234).unwrap();
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(203, 0, 113, 10),
                Ipv4Addr::new(203, 0, 113, 11),
            ]
        );
        assert!(parse_dns_a_response(&resp, 0x9999).is_err());

        // Reject NXDOMAIN (rcode 3).
        let mut nx = resp.clone();
        nx[3] = 0x83;
        assert!(parse_dns_a_response(&nx, 0x1234).is_err());

        // Reject pointer loop.
        let mut loop_pkt = query.clone();
        loop_pkt[2] = 0x81;
        loop_pkt[7] = 0x01;
        let ptr_pos = loop_pkt.len() as u16;
        loop_pkt.extend_from_slice(&(0xC000 | ptr_pos).to_be_bytes());
        assert!(parse_dns_a_response(&loop_pkt, 0x1234).is_err());
    }

    #[tokio::test]
    async fn dns_udp_query_resolves_against_loopback_server() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let mut resp = buf[..len].to_vec();
            resp[2] = 0x81;
            resp[3] = 0x80;
            resp[6] = 0x00;
            resp[7] = 0x01;
            resp.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 51, 100, 7]);
            server.send_to(&resp, peer).await.unwrap();
        });

        let packet = build_dns_a_query(0x4321, "manage.tiaris.com").unwrap();
        let ips = query_dns_ipv4_addr(
            Ipv4Addr::LOCALHOST,
            addr,
            0x4321,
            &packet,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        handle.await.unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(198, 51, 100, 7)]);
    }
}
