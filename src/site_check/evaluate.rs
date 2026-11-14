//! Turns probe outcomes into checks: a status, a reason code, a short detail
//! and the remedy a school can act on. Pure functions, no I/O.
use serde::Deserialize;

use super::{
    Check, CheckId, Status,
    probes::{CertificateProblem, Clock, HttpAnswer, NtpOutcome, Resolution, TlsOutcome},
};

/// Supervisor evidence older than this is no evidence
/// (`docs/pxe-discovery.md`: 45 seconds).
const PXE_STATUS_MAX_AGE: i64 = 45;
/// A boot probe older than this is not current.
const BOOT_PROBE_MAX_AGE: i64 = 30 * 60;
/// A clock this far from Manage's is named in the time check.
const CLOCK_SKEW_SECONDS: i64 = 120;

fn check(id: CheckId, status: Status, reason: &str, detail: String, remedy: String) -> Check {
    Check {
        id,
        status,
        reason: reason.to_string(),
        detail,
        remedy,
    }
}

fn pass(id: CheckId, reason: &str) -> Check {
    check(id, Status::Pass, reason, String::new(), String::new())
}

/// `/run/tiaris-nest-pxe/status.json`, written by the PXE supervisor.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct PxeStatus {
    pub(crate) checked_at: i64,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) reason: String,
}

/// `/run/tiaris-nest-pxe/boot-probe.json` (`runtime/site_probe.py`).
#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct BootProbe {
    pub(crate) checked_at: i64,
    pub(crate) outcome: String,
    #[serde(default)]
    pub(crate) error: String,
    #[serde(default)]
    pub(crate) dhcp_servers: Vec<String>,
    #[serde(default)]
    pub(crate) other_boot_servers: Vec<String>,
    #[serde(default)]
    pub(crate) dropped_clients: u32,
    /// The most recent of them (at most eight).
    #[serde(default)]
    pub(crate) dropped: Vec<DroppedClient>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct DroppedClient {
    pub(crate) mac: String,
    pub(crate) at: i64,
}

/// The dropped count without the computers that booted from the Nest after
/// their answers were dropped (`booted_at`: their latest boot, Unix seconds).
pub(crate) fn still_dropped(probe: &BootProbe, booted_at: impl Fn(&str) -> Option<i64>) -> u32 {
    let listed = probe.dropped.len() as u32;
    let unlisted = probe.dropped_clients.saturating_sub(listed);
    let blocked = probe
        .dropped
        .iter()
        .filter(|client| booted_at(&client.mac).is_none_or(|booted| booted < client.at))
        .count() as u32;
    unlisted + blocked
}

pub(crate) fn network_boot(
    appliance: bool,
    pxe: Option<&PxeStatus>,
    probe: Option<&BootProbe>,
    now: i64,
) -> Check {
    let id = CheckId::NetworkBoot;
    if !appliance {
        return check(
            id,
            Status::NotApplicable,
            "not_an_appliance",
            String::new(),
            String::new(),
        );
    }
    let Some(pxe) = pxe.filter(|pxe| (0..=PXE_STATUS_MAX_AGE).contains(&(now - pxe.checked_at)))
    else {
        return check(
            id,
            Status::Fail,
            "boot_service_unavailable",
            "supervisor_unavailable".into(),
            BOOT_SERVICE_REMEDY.into(),
        );
    };
    match pxe.status.as_str() {
        "external" => {
            return check(
                id,
                Status::NotApplicable,
                "external_pxe",
                "This Nest leaves network boot to your own PXE service.".into(),
                String::new(),
            );
        }
        "starting" => {
            return check(
                id,
                Status::CouldNotCheck,
                "boot_service_starting",
                "The Nest is still choosing which Nest answers network boot.".into(),
                String::new(),
            );
        }
        "active" | "standby" => {}
        _ => {
            return check(
                id,
                Status::Fail,
                "boot_service_unavailable",
                code(&pxe.reason),
                BOOT_SERVICE_REMEDY.into(),
            );
        }
    }
    let Some(probe) = probe.filter(|probe| {
        probe.outcome == "ok" && (0..=BOOT_PROBE_MAX_AGE).contains(&(now - probe.checked_at))
    }) else {
        return check(
            id,
            Status::CouldNotCheck,
            "boot_probe_unavailable",
            probe
                .map(|probe| code(&probe.error))
                .filter(|error| !error.is_empty())
                .unwrap_or_default(),
            String::new(),
        );
    };
    if probe.dhcp_servers.is_empty() {
        return check(
            id,
            Status::Fail,
            "no_dhcp_server",
            String::new(),
            "No DHCP server answered on this network. Computers get their address from your DHCP server; the Nest only adds the boot information. Make sure DHCP serves this network, also for computers it does not know yet.".into(),
        );
    }
    if !probe.other_boot_servers.is_empty() {
        return check(
            id,
            Status::Fail,
            "other_boot_server",
            format!("Also answered by {}.", addresses(&probe.other_boot_servers)),
            "Another server on this network also answers network boot, so computers may start its boot program instead of the Nest's. Remove the boot options (66, 67 and next-server) from your DHCP server, or turn off the other PXE service.".into(),
        );
    }
    if probe.dropped_clients > 0 {
        let computers = match probe.dropped_clients {
            1 => "1 computer".to_string(),
            count => format!("{count} computers"),
        };
        return check(
            id,
            Status::Fail,
            "boot_answer_dropped",
            format!("{computers} asked to start from the network but never received the Nest's answer."),
            "Something between the Nest and the computers drops the Nest's boot answers, usually a switch DHCP guard (DHCP snooping). Mark the Nest's switch port as trusted, or allow DHCP replies from the Nest's address.".into(),
        );
    }
    if pxe.status == "standby" {
        return check(
            id,
            Status::Pass,
            "peer_answers",
            "Another Nest of yours answers network boot on this network.".into(),
            String::new(),
        );
    }
    pass(id, "boot_answer_served")
}

const BOOT_SERVICE_REMEDY: &str = "The Nest is not answering network boot requests. It retries by itself; if this stays, restart the Nest.";

fn addresses(values: &[String]) -> String {
    values
        .iter()
        .take(4)
        .map(|value| code_like(value, 45))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A reason code from another component: lower-case letters, digits and `_`.
fn code(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
        .take(64)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn code_like(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '-')
        })
        .take(limit)
        .collect()
}

pub(crate) fn dns(results: &[(String, Resolution)]) -> Check {
    let missing: Vec<&str> = results
        .iter()
        .filter(|(_, resolution)| *resolution == Resolution::NotResolved)
        .map(|(host, _)| host.as_str())
        .collect();
    if missing.is_empty() {
        return pass(CheckId::Dns, "resolved");
    }
    check(
        CheckId::Dns,
        Status::Fail,
        "name_not_resolved",
        missing.join(", "),
        "The Nest's DNS server cannot find these names. Check the DNS server your DHCP hands out, and that it may look up internet names.".into(),
    )
}

pub(crate) fn time(clock: Clock, ntp: &[NtpOutcome], manage_skew_seconds: Option<i64>) -> Check {
    let id = CheckId::Time;
    let skew = manage_skew_seconds
        .filter(|skew| skew.abs() >= CLOCK_SKEW_SECONDS)
        .map(|skew| format!("The clock is {} off.", duration(skew.abs())))
        .unwrap_or_default();
    match clock {
        Clock::Synchronized => return pass(id, "synchronized"),
        Clock::Unknown => {
            return check(
                id,
                Status::CouldNotCheck,
                "clock_unknown",
                skew,
                String::new(),
            );
        }
        Clock::NotSynchronized => {}
    }
    if ntp.contains(&NtpOutcome::Answered) {
        return check(
            id,
            Status::Fail,
            "clock_not_synchronized",
            skew,
            "The Nest reaches a time server but its clock is not synchronized yet. This usually settles within minutes; if it stays, restart the Nest.".into(),
        );
    }
    if ntp.is_empty()
        || ntp
            .iter()
            .all(|outcome| *outcome == NtpOutcome::NotResolved)
    {
        return check(
            id,
            Status::CouldNotCheck,
            "ntp_server_not_resolved",
            skew,
            String::new(),
        );
    }
    check(
        id,
        Status::Fail,
        "ntp_blocked",
        skew,
        "The Nest cannot reach a time server: outbound NTP (UDP port 123) is blocked. Allow UDP 123 from the Nest to the internet, or hand out a time server on your network with DHCP option 42.".into(),
    )
}

fn duration(seconds: i64) -> String {
    match seconds {
        ..120 => format!("{seconds} seconds"),
        120..7200 => format!("{} minutes", seconds / 60),
        7200..172_800 => format!("{} hours", seconds / 3600),
        _ => format!("{} days", seconds / 86_400),
    }
}

/// What the TLS connection to an HTTPS service says, before its answer.
fn https_connection(id: CheckId, host: &str, tls: &TlsOutcome, clock: Clock) -> Option<Check> {
    let allow = format!("Allow HTTPS (TCP 443) from the Nest to {host}.");
    match tls {
        TlsOutcome::Trusted => None,
        TlsOutcome::NotResolved => Some(check(
            id,
            Status::CouldNotCheck,
            "name_not_resolved",
            host.into(),
            String::new(),
        )),
        TlsOutcome::Unreachable | TlsOutcome::Refused => Some(check(
            id,
            Status::Fail,
            "unreachable",
            host.into(),
            format!("The Nest cannot open a connection to {host}. {allow}"),
        )),
        TlsOutcome::Untrusted { problem, issuer } => Some(untrusted_https(
            id,
            host,
            *problem,
            issuer.as_deref(),
            clock,
        )),
        TlsOutcome::HandshakeFailed => Some(check(
            id,
            Status::Fail,
            "tls_failed",
            host.into(),
            format!(
                "The secure connection to {host} was cut off, usually by a firewall or proxy. {allow} Do not inspect it."
            ),
        )),
    }
}

fn issued_by(issuer: Option<&str>) -> String {
    issuer
        .map(|issuer| format!("The certificate the Nest received was issued by \"{issuer}\"."))
        .unwrap_or_default()
}

fn untrusted_https(
    id: CheckId,
    host: &str,
    problem: CertificateProblem,
    issuer: Option<&str>,
    clock: Clock,
) -> Check {
    if matches!(
        problem,
        CertificateProblem::Expired | CertificateProblem::NotYetValid
    ) && clock != Clock::Synchronized
    {
        return clock_wrong(id, host);
    }
    let reason = match problem {
        CertificateProblem::UnknownIssuer | CertificateProblem::Other => "https_intercepted",
        CertificateProblem::WrongName => "certificate_mismatch",
        CertificateProblem::Expired | CertificateProblem::NotYetValid => "certificate_expired",
    };
    check(
        id,
        Status::Fail,
        reason,
        issued_by(issuer),
        format!(
            "Something on this network replaces the certificate of {host}, usually a firewall or proxy that inspects HTTPS. Exempt {host} from HTTPS inspection for the Nest's address."
        ),
    )
}

fn clock_wrong(id: CheckId, host: &str) -> Check {
    check(
        id,
        Status::Fail,
        "clock_wrong",
        host.into(),
        "The Nest's clock is wrong, so valid certificates look invalid. Fix the time check first."
            .into(),
    )
}

pub(crate) fn manage(
    host: &str,
    tls: &TlsOutcome,
    http: Option<&HttpAnswer>,
    clock: Clock,
) -> Check {
    let id = CheckId::Manage;
    if let Some(check) = https_connection(id, host, tls, clock) {
        return check;
    }
    match http {
        Some(answer) if answer.status == 200 => pass(id, "reachable"),
        Some(answer) => unexpected(id, host, answer.status),
        None => check(
            id,
            Status::Fail,
            "unreachable",
            host.into(),
            format!(
                "The Nest connected to {host} but got no answer. Allow HTTPS (TCP 443) from the Nest to {host}."
            ),
        ),
    }
}

fn unexpected(id: CheckId, host: &str, status: u16) -> Check {
    check(
        id,
        Status::Fail,
        "unexpected_answer",
        format!("HTTP {status}"),
        format!(
            "{host} answered, but not as expected. A proxy or web filter may be blocking it: allow {host} for the Nest's address."
        ),
    )
}

pub(crate) fn software_cache(
    host: &str,
    tls: &TlsOutcome,
    http: Option<&HttpAnswer>,
    clock: Clock,
) -> Check {
    let id = CheckId::SoftwareCache;
    if let Some(check) = https_connection(id, host, tls, clock) {
        return check;
    }
    match http {
        // 401: the cache answered and wants the Nest's token, which Nix sends.
        Some(answer) if answer.status == 401 || (answer.status == 200 && answer.body_matches) => {
            pass(id, "reachable")
        }
        Some(answer) => unexpected(id, host, answer.status),
        None => check(
            id,
            Status::Fail,
            "unreachable",
            host.into(),
            format!(
                "The Nest connected to {host} but got no answer. Allow HTTPS (TCP 443) from the Nest to {host}."
            ),
        ),
    }
}

pub(crate) fn directory(results: &[(String, u16, TlsOutcome)], clock: Clock) -> Check {
    let id = CheckId::Directory;
    if results.is_empty() {
        return check(
            id,
            Status::NotApplicable,
            "no_directory",
            String::new(),
            String::new(),
        );
    }
    for (host, port, tls) in results {
        let allow = format!("Allow LDAPS (TCP {port}) from the computer network to {host}.");
        let failed = match tls {
            TlsOutcome::Trusted => continue,
            TlsOutcome::NotResolved => check(
                id,
                Status::CouldNotCheck,
                "name_not_resolved",
                host.clone(),
                String::new(),
            ),
            TlsOutcome::Unreachable | TlsOutcome::Refused => check(
                id,
                Status::Fail,
                "unreachable",
                format!("{host}:{port}"),
                format!("The Nest cannot open a connection to the directory. {allow}"),
            ),
            TlsOutcome::HandshakeFailed => check(
                id,
                Status::Fail,
                "tls_failed",
                format!("{host}:{port}"),
                format!(
                    "The directory did not complete a secure (LDAPS) connection. Check that {host}:{port} serves LDAPS, not plain LDAP, and that no firewall cuts it off."
                ),
            ),
            TlsOutcome::Untrusted { problem, issuer } => {
                if matches!(
                    problem,
                    CertificateProblem::Expired | CertificateProblem::NotYetValid
                ) && clock != Clock::Synchronized
                {
                    clock_wrong(id, host)
                } else {
                    let (reason, why) = match problem {
                        CertificateProblem::WrongName => (
                            "certificate_mismatch",
                            format!("The directory's certificate is not made out to {host}."),
                        ),
                        CertificateProblem::Expired | CertificateProblem::NotYetValid => (
                            "certificate_expired",
                            "The directory's certificate is expired or not yet valid.".to_string(),
                        ),
                        _ => (
                            "certificate_untrusted",
                            "Computers will not trust the directory's certificate.".to_string(),
                        ),
                    };
                    check(
                        id,
                        Status::Fail,
                        reason,
                        issued_by(issuer.as_deref()),
                        format!(
                            "{why} Use a certificate from a public authority, or add your private CA under Settings, Sign-in sources."
                        ),
                    )
                }
            }
        };
        return failed;
    }
    pass(id, "reachable")
}
