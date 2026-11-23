//! Managed TURN configuration and the root service's public status.
use crate::state_files;
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt, net::Ipv4Addr, path::Path};

pub(crate) const CAPABILITY: &str = "assist_turn_v1";
const SCHEMA: &str = "tiaris.nest.assist-turn.v1";
const FILE: &str = "assist-turn.json";
const STATUS_DIR: &str = "/run/tiaris-nest-turn";
const MAX_BYTES: u64 = 4096;
const PORT: u16 = 3478;
const RELAY_PORTS: [u16; 2] = [61000, 61040];

pub(crate) fn shipped() -> bool {
    crate::appliance::nixos::is_nixos()
        && Path::new("/etc/systemd/system/tiaris-nest-assist-turn.service").is_file()
}

// Keep the lane untyped at the outer configuration boundary so malformed
// settings cannot reject the rest. It contains secrets even when invalid.
#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct Desired(Value);

impl fmt::Debug for Desired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Desired(…)")
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    secrets: Option<Vec<Secret>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_ports: Option<[u16; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_bps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bps_capacity: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_quota: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_quota: Option<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Secret {
    id: String,
    value: String,
}

fn valid_id(id: &str) -> bool {
    id.split_once('-').is_some_and(|(date, suffix)| {
        date.len() == 8
            && date.bytes().all(|byte| byte.is_ascii_digit())
            && suffix.len() == 8
            && suffix
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn valid_config(config: &Config) -> bool {
    if config.schema != SCHEMA {
        return false;
    }
    if !config.enabled {
        return config.secrets.is_none()
            && config.port.is_none()
            && config.relay_ports.is_none()
            && config.max_bps.is_none()
            && config.bps_capacity.is_none()
            && config.total_quota.is_none()
            && config.user_quota.is_none();
    }
    config.port == Some(PORT)
        && config.relay_ports == Some(RELAY_PORTS)
        && config.max_bps == Some(3_000_000)
        && config.bps_capacity == Some(30_000_000)
        && config.total_quota == Some(40)
        && config.user_quota == Some(2)
        && config.secrets.as_ref().is_some_and(|secrets| {
            (1..=2).contains(&secrets.len())
                && secrets.iter().all(|secret| {
                    valid_id(&secret.id)
                        && secret.value.len() == 43
                        && secret
                            .value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                })
                && (secrets.len() == 1
                    || (secrets[0].id != secrets[1].id && secrets[0].value != secrets[1].value))
        })
}

const DISABLED: &[u8] = br#"{"schema":"tiaris.nest.assist-turn.v1","enabled":false}"#;

pub(crate) fn withdraw(data_dir: &Path) -> Result<()> {
    if shipped() {
        apply(data_dir, None)?;
    }
    Ok(())
}

pub(crate) fn apply(data_dir: &Path, desired: Option<Desired>) -> Result<()> {
    let current = state_files::read_bytes(data_dir, FILE, MAX_BYTES).unwrap_or_default();
    let Some(Desired(desired)) = desired else {
        if current.as_deref() != Some(DISABLED) && data_dir.join(FILE).symlink_metadata().is_ok() {
            state_files::write_bytes(data_dir, FILE, DISABLED, MAX_BYTES)?;
        }
        return Ok(());
    };
    match serde_json::from_value::<Config>(desired) {
        Ok(config) if valid_config(&config) => {
            let body = serde_json::to_vec(&config)?;
            if current.as_deref() != Some(&body) {
                state_files::write_bytes(data_dir, FILE, &body, MAX_BYTES)?;
            }
            Ok(())
        }
        _ => {
            if current.as_deref() != Some(DISABLED) {
                state_files::write_bytes(data_dir, FILE, DISABLED, MAX_BYTES)?;
            }
            bail!("invalid managed TURN configuration");
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum State {
    Running,
    Stopped,
    Failed,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Report {
    state: State,
    listen_ipv4: Option<Ipv4Addr>,
    port: Option<u16>,
    relay_ports: Option<[u16; 2]>,
    secret_ids: Vec<String>,
    error: Option<String>,
    checked_at: DateTime<Utc>,
}

pub(crate) fn report(data_dir: &Path, public_url: &str) -> Report {
    report_from(data_dir, Path::new(STATUS_DIR), public_url, Utc::now())
}

fn report_from(data_dir: &Path, status_dir: &Path, public_url: &str, now: DateTime<Utc>) -> Report {
    let status = state_files::read_bytes(status_dir, "status.json", MAX_BYTES)
        .ok()
        .flatten()
        .and_then(|body| serde_json::from_slice::<Report>(&body).ok());
    if let Some(status) = status.filter(|status| {
        (now - status.checked_at).num_seconds().abs() <= 90
            && match status.state {
                State::Running => {
                    state_files::read_bytes(data_dir, FILE, MAX_BYTES)
                        .ok()
                        .flatten()
                        .and_then(|body| serde_json::from_slice::<Config>(&body).ok())
                        .is_some_and(|config| config.enabled && valid_config(&config))
                        && status
                            .listen_ipv4
                            .is_some_and(|ip| format!("http://{ip}") == public_url)
                        && status.port == Some(PORT)
                        && status.relay_ports == Some(RELAY_PORTS)
                        && (1..=2).contains(&status.secret_ids.len())
                        && status.secret_ids.iter().all(|id| valid_id(id))
                        && status.error.is_none()
                }
                State::Stopped => status.error.is_none(),
                State::Failed => status.error.as_ref().is_some_and(|error| {
                    (2..=60).contains(&error.len())
                        && error
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                }),
            }
    }) {
        return status;
    }
    Report {
        state: State::Stopped,
        listen_ipv4: None,
        port: None,
        relay_ports: None,
        secret_ids: vec![],
        error: None,
        checked_at: now,
    }
}

#[cfg(test)]
mod tests;
