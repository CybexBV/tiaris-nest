# Site check

Before a school installs a classroom, the Nest tests the school network from
where the computers are and names the exact blocker (`src/site_check.rs`).
Each check is `pass`, `fail`, `not_applicable` or `could_not_check`, with a
machine-readable reason, a short detail and a plain-English remedy.

| Check | What it tests | Reasons it fails |
| --- | --- | --- |
| `network_boot` | The Nest's boot answer is served; the school's DHCP answers; no other server hands out boot information; computers do not keep asking without receiving the answer | `boot_service_unavailable`, `no_dhcp_server`, `other_boot_server`, `boot_answer_dropped` |
| `dns` | Manage, the software cache (where it is on) and directory hosts resolve | `name_not_resolved` |
| `time` | The clock is synchronized; when not, whether NTP is blocked | `ntp_blocked`, `clock_not_synchronized` |
| `manage` | HTTPS to Manage with a trusted certificate and a Tiaris answer | `unreachable`, `https_intercepted` (names the issuer), `certificate_mismatch`, `certificate_expired`, `clock_wrong`, `tls_failed`, `unexpected_answer` |
| `software_cache` | The same for the software cache Manage names (`site_check.software_cache_url`). Where the cache is off Manage names none, computers never use the host, and the check is `not_applicable` (`software_cache_off`) | the same |
| `directory` | LDAPS with a certificate computers trust (public roots plus the private CA Manage holds), when the organization uses a directory | `unreachable`, `certificate_untrusted`, `certificate_mismatch`, `certificate_expired`, `tls_failed` |

## Link speed

The Nest's own link speed is not one of the checks: a slow link is not a
blocker, and a failing check would repeat every 15 minutes and ask the school
to act at once. The Nest reports the negotiated speed of its default-route
interface with its host metrics instead (`host.network_link_mbps` in the
report, read from `/sys/class/net/<interface>/speed`; 0 when the card reports
none, as virtual cards do). Manage's Network check card notes a known speed
below 1 Gbit/s. A school that installs whole classrooms at once should use
2.5 Gbit/s (2.5GbE) on the Nest and its switch port.

## When it runs

A minute after the service starts, every six hours, every 15 minutes while a
check does not pass, and when Manage asks ("Check again", the configuration's
`site_check.requested_at`), at most once a minute.

## Network boot evidence

The unprivileged service never touches the network boot path. The root PXE
supervisor (`nixos-appliance/runtime/site_probe.py`) does, every 15 minutes
and when the service writes `site-check-request.json` next to its PXE
inventory, at most every 30 seconds:

- a boot probe: one DHCPDISCOVER like a UEFI computer's, from a fixed locally
  administered address derived from the Nest's identity, answered by the
  school's DHCP, this Nest, or another boot server (a site has one Nest, so a
  second Nest counts as one);
- a dropped-answer monitor over dnsmasq's `log-dhcp` lines: firmware repeats
  one DISCOVER only while no boot answer reached it, so one transaction the
  Nest answered three times within two minutes did not get through. That is
  a switch DHCP guard (DHCP snooping) that does not trust the Nest's port.
  A computer that later fetched its boot script from the Nest no longer
  counts.

The result is `/run/tiaris-nest-pxe/boot-probe.json`.

## Time for computers

`tiaris-nest-time` answers NTP on UDP 123 with the clock systemd-timesyncd
keeps (including time servers the school's DHCP hands out), only while the
kernel reports it synchronized within one second, only to private IPv4
addresses, and at most a small burst per address. Computers do not use it by
themselves yet: a school can hand out the Nest's address with DHCP option 42.

## Reporting

The latest result is a state file (`<data_dir>/site-check/site-check.json`),
not SQLite. It travels in the Nest report's `site_check` lane, and the report
lists `site_check_v1`, only to a Manage whose Nest configuration says
`site_check_supported`; an older Manage would reject both.

## Qualification

`nixos-appliance/qualification/run-site-check.py` needs no root and no VM: in
its own user, network and mount namespace it builds a school network with its
own DHCP and time server, a Nest running the supervisor's real dnsmasq
configuration, monitor, probe and time service, and a computer behaving like
UEFI firmware. Cases: a working network, quick healthy restarts, another boot
server, no DHCP server, a switch DHCP guard dropping the Nest's answers, and
blocked NTP. It needs dnsmasq, nft and `cargo build --example site-check-probe`.
