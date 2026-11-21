use std::{io::Write, net::TcpListener, sync::Arc};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::json;

use super::{
    probes::{CertificateProblem, Clock, HttpAnswer, NtpOutcome, Resolution, TlsOutcome},
    *,
};

const INSPECTION_CA: &str = include_str!("fixtures/inspection-ca.pem");
const LOCALHOST_CERT: &str = include_str!("fixtures/localhost.pem");
const LOCALHOST_KEY: &str = include_str!("fixtures/localhost.key.pem");
const NOW: i64 = 1_800_000_000;

fn pxe(status: &str, reason: &str) -> PxeStatus {
    serde_json::from_value(json!({"checked_at": NOW - 3, "status": status, "reason": reason}))
        .unwrap()
}

fn probe(value: serde_json::Value) -> BootProbe {
    let mut base = json!({"schema": "tiaris.nest.boot-probe.v1", "checked_at": NOW - 5, "outcome": "ok",
        "own_answer": true, "dhcp_servers": ["192.0.2.1"], "other_boot_servers": [],
        "dropped_clients": 0, "dropped_last_at": null, "booted_clients": 0, "booted_last_at": null});
    for (key, item) in value.as_object().unwrap() {
        base[key] = item.clone();
    }
    serde_json::from_value(base).unwrap()
}

fn boot(pxe_status: Option<&PxeStatus>, boot_probe: Option<&BootProbe>) -> Check {
    evaluate::network_boot(true, pxe_status, boot_probe, NOW)
}

fn outcome(check: &Check) -> (Status, &str) {
    (check.status, check.reason.as_str())
}

#[test]
fn network_boot_passes_when_the_answer_is_served() {
    let check = boot(Some(&pxe("active", "proxy_ready")), Some(&probe(json!({}))));
    assert_eq!(outcome(&check), (Status::Pass, "boot_answer_served"));
    assert!(check.remedy.is_empty());
}

#[test]
fn network_boot_names_each_blocker() {
    let active = pxe("active", "proxy_ready");
    let no_dhcp = boot(Some(&active), Some(&probe(json!({"dhcp_servers": []}))));
    assert_eq!(outcome(&no_dhcp), (Status::Fail, "no_dhcp_server"));
    assert!(no_dhcp.remedy.contains("DHCP"));
    let other = boot(
        Some(&active),
        Some(&probe(json!({"other_boot_servers": ["192.0.2.9"]}))),
    );
    assert_eq!(outcome(&other), (Status::Fail, "other_boot_server"));
    assert!(other.detail.contains("192.0.2.9"));
    let dropped = boot(Some(&active), Some(&probe(json!({"dropped_clients": 2}))));
    assert_eq!(outcome(&dropped), (Status::Fail, "boot_answer_dropped"));
    assert!(dropped.detail.starts_with("2 computers"));
    assert!(dropped.remedy.contains("DHCP snooping"));
}

#[test]
fn network_boot_without_evidence_is_not_a_pass() {
    assert_eq!(
        outcome(&evaluate::network_boot(false, None, None, NOW)),
        (Status::NotApplicable, "not_an_appliance")
    );
    assert_eq!(
        outcome(&boot(None, None)),
        (Status::Fail, "boot_service_unavailable")
    );
    let mut stale = pxe("active", "proxy_ready");
    stale.checked_at = NOW - 120;
    assert_eq!(
        outcome(&boot(Some(&stale), Some(&probe(json!({}))))),
        (Status::Fail, "boot_service_unavailable")
    );
    let down = boot(
        Some(&pxe("unavailable", "inventory_incomplete")),
        Some(&probe(json!({}))),
    );
    assert_eq!(outcome(&down), (Status::Fail, "boot_service_unavailable"));
    assert_eq!(down.detail, "inventory_incomplete");
    let active = pxe("active", "proxy_ready");
    assert_eq!(
        outcome(&boot(Some(&active), None)),
        (Status::CouldNotCheck, "boot_probe_unavailable")
    );
    let busy = boot(
        Some(&active),
        Some(&probe(
            json!({"outcome": "error", "error": "probe_port_busy"}),
        )),
    );
    assert_eq!(
        outcome(&busy),
        (Status::CouldNotCheck, "boot_probe_unavailable")
    );
    assert_eq!(busy.detail, "probe_port_busy");
    let old = boot(
        Some(&active),
        Some(&probe(json!({"checked_at": NOW - 3 * 3600}))),
    );
    assert_eq!(
        outcome(&old),
        (Status::CouldNotCheck, "boot_probe_unavailable")
    );
}

#[test]
fn computers_that_booted_later_are_not_dropped() {
    let probe = probe(json!({"dropped_clients": 3, "dropped": [
        {"mac": "02:00:00:00:00:01", "at": NOW - 100},
        {"mac": "02:00:00:00:00:02", "at": NOW - 100},
    ]}));
    let booted = |mac: &str| match mac {
        "02:00:00:00:00:01" => Some(NOW - 50),
        "02:00:00:00:00:02" => Some(NOW - 200),
        _ => None,
    };
    // One unlisted, one booted before the drop: two still blocked.
    assert_eq!(evaluate::still_dropped(&probe, booted), 2);
    assert_eq!(evaluate::still_dropped(&probe, |_| None), 3);
}

#[test]
fn dns_names_the_hosts_that_do_not_resolve() {
    let resolved = Resolution::Resolved(vec!["192.0.2.10".parse().unwrap()]);
    assert_eq!(
        outcome(&evaluate::dns(&[(
            "manage.tiaris.com".into(),
            resolved.clone()
        )])),
        (Status::Pass, "resolved")
    );
    let check = evaluate::dns(&[
        ("manage.tiaris.com".into(), resolved),
        ("cache.tiaris.com".into(), Resolution::NotResolved),
        ("ldap.school.example".into(), Resolution::NotResolved),
    ]);
    assert_eq!(outcome(&check), (Status::Fail, "name_not_resolved"));
    assert_eq!(check.detail, "cache.tiaris.com, ldap.school.example");
}

#[test]
fn time_tells_blocked_ntp_from_a_clock_still_settling() {
    assert_eq!(
        outcome(&evaluate::time(Clock::Synchronized, &[], None)),
        (Status::Pass, "synchronized")
    );
    let blocked = evaluate::time(
        Clock::NotSynchronized,
        &[NtpOutcome::NoAnswer, NtpOutcome::NoAnswer],
        Some(3 * 3600),
    );
    assert_eq!(outcome(&blocked), (Status::Fail, "ntp_blocked"));
    assert!(blocked.remedy.contains("UDP 123"));
    assert_eq!(blocked.detail, "The clock is 3 hours off.");
    assert_eq!(
        outcome(&evaluate::time(
            Clock::NotSynchronized,
            &[NtpOutcome::NoAnswer, NtpOutcome::Answered],
            None
        )),
        (Status::Fail, "clock_not_synchronized")
    );
    assert_eq!(
        outcome(&evaluate::time(
            Clock::NotSynchronized,
            &[NtpOutcome::NotResolved],
            None
        )),
        (Status::CouldNotCheck, "ntp_server_not_resolved")
    );
    assert_eq!(
        outcome(&evaluate::time(Clock::Unknown, &[], None)),
        (Status::CouldNotCheck, "clock_unknown")
    );
}

fn answer(status: u16, body_matches: bool) -> HttpAnswer {
    HttpAnswer {
        status,
        date: None,
        body_matches,
    }
}

#[test]
fn manage_detects_https_interception_and_names_the_issuer() {
    let host = "manage.tiaris.com";
    assert_eq!(
        outcome(&evaluate::manage(
            host,
            &TlsOutcome::Trusted,
            Some(&answer(200, false)),
            Clock::Synchronized
        )),
        (Status::Pass, "reachable")
    );
    let intercepted = evaluate::manage(
        host,
        &TlsOutcome::Untrusted {
            problem: CertificateProblem::UnknownIssuer,
            issuer: Some("FortiGate CA".into()),
        },
        None,
        Clock::Synchronized,
    );
    assert_eq!(outcome(&intercepted), (Status::Fail, "https_intercepted"));
    assert!(intercepted.detail.contains("FortiGate CA"));
    assert!(intercepted.remedy.contains(host));
    let mismatch = evaluate::manage(
        host,
        &TlsOutcome::Untrusted {
            problem: CertificateProblem::WrongName,
            issuer: None,
        },
        None,
        Clock::Synchronized,
    );
    assert_eq!(outcome(&mismatch), (Status::Fail, "certificate_mismatch"));
    let expired = TlsOutcome::Untrusted {
        problem: CertificateProblem::Expired,
        issuer: None,
    };
    assert_eq!(
        outcome(&evaluate::manage(
            host,
            &expired,
            None,
            Clock::NotSynchronized
        )),
        (Status::Fail, "clock_wrong")
    );
    assert_eq!(
        outcome(&evaluate::manage(host, &expired, None, Clock::Synchronized)),
        (Status::Fail, "certificate_expired")
    );
    for (tls, expected) in [
        (TlsOutcome::Unreachable, (Status::Fail, "unreachable")),
        (TlsOutcome::Refused, (Status::Fail, "unreachable")),
        (TlsOutcome::HandshakeFailed, (Status::Fail, "tls_failed")),
        (
            TlsOutcome::NotResolved,
            (Status::CouldNotCheck, "name_not_resolved"),
        ),
    ] {
        assert_eq!(
            outcome(&evaluate::manage(host, &tls, None, Clock::Synchronized)),
            expected
        );
    }
    let blocked = evaluate::manage(
        host,
        &TlsOutcome::Trusted,
        Some(&answer(403, false)),
        Clock::Synchronized,
    );
    assert_eq!(outcome(&blocked), (Status::Fail, "unexpected_answer"));
    assert_eq!(blocked.detail, "HTTP 403");
}

#[test]
fn software_cache_accepts_its_own_answers_only() {
    let host = "cache.tiaris.com";
    for (http, expected) in [
        (answer(200, true), (Status::Pass, "reachable")),
        (answer(401, false), (Status::Pass, "reachable")),
        (answer(200, false), (Status::Fail, "unexpected_answer")),
        (answer(403, false), (Status::Fail, "unexpected_answer")),
    ] {
        assert_eq!(
            outcome(&evaluate::software_cache(
                host,
                &TlsOutcome::Trusted,
                Some(&http),
                Clock::Synchronized
            )),
            expected
        );
    }
}

#[test]
fn directory_needs_a_certificate_computers_trust() {
    assert_eq!(
        outcome(&evaluate::directory(&[], Clock::Synchronized)),
        (Status::NotApplicable, "no_directory")
    );
    let trusted = ("ldap.school.example".to_string(), 636, TlsOutcome::Trusted);
    assert_eq!(
        outcome(&evaluate::directory(
            &[trusted.clone()],
            Clock::Synchronized
        )),
        (Status::Pass, "reachable")
    );
    let untrusted = (
        "ldap2.school.example".to_string(),
        636,
        TlsOutcome::Untrusted {
            problem: CertificateProblem::UnknownIssuer,
            issuer: Some("School CA".into()),
        },
    );
    let check = evaluate::directory(&[trusted, untrusted], Clock::Synchronized);
    assert_eq!(outcome(&check), (Status::Fail, "certificate_untrusted"));
    assert!(check.remedy.contains("Sign-in sources"));
    let closed = ("ldap.school.example".to_string(), 636, TlsOutcome::Refused);
    let check = evaluate::directory(&[closed], Clock::Synchronized);
    assert_eq!(outcome(&check), (Status::Fail, "unreachable"));
    assert!(check.remedy.contains("TCP 636"));
}

/// A TLS server presenting `localhost` signed by the inspection CA.
fn tls_server() -> u16 {
    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(LOCALHOST_CERT.as_bytes())
            .chain(CertificateDer::pem_slice_iter(INSPECTION_CA.as_bytes()))
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(LOCALHOST_KEY.as_bytes()).unwrap();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let Ok(mut stream) = stream else { continue };
            let mut connection = rustls::ServerConnection::new(config.clone()).unwrap();
            while connection.is_handshaking() {
                if connection.complete_io(&mut stream).is_err() {
                    break;
                }
            }
            let _ = stream.flush();
        }
    });
    port
}

#[tokio::test]
async fn tls_probe_names_an_inspecting_authority_and_trusts_a_configured_ca() {
    let port = tls_server();
    let intercepted = probes::tls("localhost".into(), port, None).await;
    assert_eq!(
        intercepted,
        TlsOutcome::Untrusted {
            problem: CertificateProblem::UnknownIssuer,
            issuer: Some("Example Inspection CA".into())
        }
    );
    let trusted = probes::tls("localhost".into(), port, Some(INSPECTION_CA.into())).await;
    assert_eq!(trusted, TlsOutcome::Trusted);
}

#[tokio::test]
async fn tls_probe_tells_a_closed_port() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert_eq!(
        probes::tls("127.0.0.1".into(), port, None).await,
        TlsOutcome::Refused
    );
}

#[test]
fn issuer_name_reads_the_common_name() {
    let certificate = CertificateDer::from_pem_slice(LOCALHOST_CERT.as_bytes()).unwrap();
    assert_eq!(
        probes::issuer_name(&certificate).as_deref(),
        Some("Example Inspection CA")
    );
    assert_eq!(probes::issuer_name(b"not a certificate"), None);
    assert_eq!(probes::issuer_name(&certificate[..40]), None);
}

#[test]
fn ntp_answers_must_echo_the_request() {
    let mut request = [0u8; 48];
    request[0] = 0x23;
    request[40..48].copy_from_slice(b"NONCE123");
    let mut answer = [0u8; 48];
    answer[0] = 0x24;
    answer[1] = 2;
    answer[24..32].copy_from_slice(b"NONCE123");
    assert!(probes::valid_ntp_answer(&request, &answer));
    let mut unsynchronized = answer;
    unsynchronized[0] = 0xe4;
    assert!(!probes::valid_ntp_answer(&request, &unsynchronized));
    let mut kiss = answer;
    kiss[1] = 0;
    assert!(!probes::valid_ntp_answer(&request, &kiss));
    let mut other = answer;
    other[24] = b'X';
    assert!(!probes::valid_ntp_answer(&request, &other));
    assert!(!probes::valid_ntp_answer(&request, &answer[..47]));
}

#[test]
fn ntp_servers_come_from_dhcp_leases_first() {
    let dir = tempfile_dir();
    std::fs::write(
        dir.join("2"),
        "ADDRESS=192.0.2.50\nNTP=192.0.2.123 ntp.school.example\n",
    )
    .unwrap();
    let servers = probes::ntp_servers(&dir);
    assert_eq!(
        servers,
        vec!["192.0.2.123", "ntp.school.example", "0.nixos.pool.ntp.org"]
    );
    let empty = probes::ntp_servers(&dir.join("missing"));
    assert_eq!(empty, vec!["0.nixos.pool.ntp.org", "1.nixos.pool.ntp.org"]);
}

fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tiaris-site-check-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_software_cache_is_checked_only_where_manage_names_one() {
    // Where the cache is off Manage sends no address; the built-in
    // cache.tiaris.com used to be checked anyway and failed behind a filter.
    assert_eq!(software_cache_target(&Targets::default()), None);
    let on = Targets {
        software_cache_url: Some("https://cache.tiaris.com/".into()),
        ..Targets::default()
    };
    assert_eq!(
        software_cache_target(&on),
        Some((
            "https://cache.tiaris.com".to_string(),
            ("cache.tiaris.com".to_string(), 443)
        ))
    );
}

#[test]
fn manage_targets_are_validated() {
    let targets = validate_targets(&json!({
        "requested_at": "2026-11-14T10:00:00Z",
        "directories": [{"host": "ldap.school.example", "port": 636, "ca_certificate": INSPECTION_CA}],
        "software_cache_url": "https://cache.tiaris.com",
        "a_future_field": true,
    }))
    .unwrap();
    assert_eq!(targets.directories[0].host, "ldap.school.example");
    for invalid in [
        json!({"requested_at": "yesterday"}),
        json!({"directories": [{"host": "bad host", "port": 636}]}),
        json!({"directories": [{"host": "ldap.example", "port": 0}]}),
        json!({"software_cache_url": "http://cache.tiaris.com"}),
        json!({"directories": (0..5).map(|_| json!({"host": "ldap.example", "port": 636})).collect::<Vec<_>>()}),
        json!("not an object"),
    ] {
        assert!(validate_targets(&invalid).is_err(), "{invalid}");
    }
}

#[tokio::test]
async fn check_again_is_pending_until_a_run_answers_it() {
    let dir = tempfile_dir();
    apply_managed(&dir, Some(&json!({"requested_at": "2026-11-14T10:00:00Z"})))
        .await
        .unwrap();
    assert_eq!(
        pending_request(&load(&dir)).as_deref(),
        Some("2026-11-14T10:00:00Z")
    );
    update(&dir, |state| {
        state.handled_request = Some("2026-11-14T10:00:00Z".into())
    })
    .await
    .unwrap();
    assert_eq!(pending_request(&load(&dir)), None);
    apply_managed(&dir, Some(&json!({"requested_at": "2026-11-14T10:05:00Z"})))
        .await
        .unwrap();
    assert_eq!(
        pending_request(&load(&dir)).as_deref(),
        Some("2026-11-14T10:05:00Z")
    );
    // An older Manage sends no lane: default targets, no request.
    apply_managed(&dir, None).await.unwrap();
    assert_eq!(load(&dir).targets, Targets::default());
    assert!(
        apply_managed(&dir, Some(&json!({"requested_at": 5})))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_report_contract_is_stable() {
    let dir = tempfile_dir();
    assert_eq!(report(&dir), None);
    let stored = Report {
        schema: REPORT_SCHEMA.into(),
        checked_at: "2026-11-14T10:00:05Z".into(),
        trigger: Trigger::Requested,
        requested_at: Some("2026-11-14T10:00:00Z".into()),
        checks: vec![
            Check {
                id: CheckId::NetworkBoot,
                status: Status::Pass,
                reason: "boot_answer_served".into(),
                detail: String::new(),
                remedy: String::new(),
            },
            Check {
                id: CheckId::Time,
                status: Status::Fail,
                reason: "ntp_blocked".into(),
                detail: String::new(),
                remedy: "Allow UDP 123.".into(),
            },
            Check {
                id: CheckId::Directory,
                status: Status::NotApplicable,
                reason: "no_directory".into(),
                detail: String::new(),
                remedy: String::new(),
            },
            Check {
                id: CheckId::SoftwareCache,
                status: Status::CouldNotCheck,
                reason: "name_not_resolved".into(),
                detail: "cache.tiaris.com".into(),
                remedy: String::new(),
            },
        ],
    };
    update(&dir, |state| state.last = Some(stored.clone()))
        .await
        .unwrap();
    let reported = report(&dir).unwrap();
    assert_eq!(
        serde_json::to_value(&reported).unwrap(),
        json!({
            "schema": "tiaris.nest.site-check.v1",
            "checked_at": "2026-11-14T10:00:05Z",
            "trigger": "requested",
            "requested_at": "2026-11-14T10:00:00Z",
            "checks": [
                {"id": "network_boot", "status": "pass", "reason": "boot_answer_served"},
                {"id": "time", "status": "fail", "reason": "ntp_blocked", "remedy": "Allow UDP 123."},
                {"id": "directory", "status": "not_applicable", "reason": "no_directory"},
                {"id": "software_cache", "status": "could_not_check", "reason": "name_not_resolved", "detail": "cache.tiaris.com"},
            ],
        })
    );
}

#[test]
fn hosts_are_names_or_addresses() {
    for valid in [
        "manage.tiaris.com",
        "ldap",
        "192.0.2.1",
        "2001:db8::1",
        "a-b.example",
    ] {
        assert!(valid_host(valid), "{valid}");
    }
    for invalid in [
        "",
        "bad host",
        "-a.example",
        "a..b",
        "a/b",
        &"x".repeat(254),
    ] {
        assert!(!valid_host(invalid), "{invalid}");
    }
}
