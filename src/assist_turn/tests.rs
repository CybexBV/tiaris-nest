use super::*;
use rand::{RngCore as _, rngs::OsRng};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("nest-turn-test-{}", uuid::Uuid::new_v4()));
        state_files::ensure_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config() -> Value {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    let secret = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);
    json!({
        "schema": SCHEMA, "enabled": true,
        "secrets": [{"id": "20261123-abcdef01", "value": secret}],
        "port": PORT, "relay_ports": RELAY_PORTS,
        "max_bps": 3_000_000, "bps_capacity": 30_000_000, "total_quota": 40, "user_quota": 2,
    })
}

#[test]
fn atomic_configuration_is_private_and_withdraws_invalid_or_missing_settings() {
    let tmp = TestDirectory::new();
    let path = tmp.path().join(FILE);
    let valid = config();
    let secret = valid["secrets"][0]["value"].as_str().unwrap();
    assert!(!format!("{:?}", Desired(valid.clone())).contains(secret));
    apply(tmp.path(), Some(Desired(valid.clone()))).unwrap();
    assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    let saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(saved == valid, "wrong TURN configuration was written");

    for (field, bad_value) in [
        ("port", json!(3479)),
        ("relay_ports", json!([61000, 61041])),
        ("secrets", json!([])),
        ("schema", json!("unknown")),
        ("unknown", json!(true)),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = bad_value;
        assert!(apply(tmp.path(), Some(Desired(invalid))).is_err());
        assert!(
            fs::read(&path).unwrap() == DISABLED,
            "invalid TURN config persisted"
        );
    }
    apply(tmp.path(), Some(Desired(valid))).unwrap();
    apply(tmp.path(), None).unwrap();
    assert!(
        fs::read(&path).unwrap() == DISABLED,
        "stale TURN config persisted"
    );
}

#[test]
fn report_is_bound_to_running_status_current_address_and_local_enablement() {
    let tmp = TestDirectory::new();
    let dir = tmp.path();
    let valid = config();
    let now = Utc::now();
    apply(dir, Some(Desired(valid))).unwrap();
    let status = json!({
        "state": "running", "listen_ipv4": "100.64.50.10", "port": PORT,
        "relay_ports": RELAY_PORTS, "secret_ids": ["20261123-abcdef01"],
        "error": null, "checked_at": now,
    });
    let report = |url, clock| report_from(dir, dir, url, clock);
    let status_path = dir.join("status.json");
    fs::write(&status_path, serde_json::to_vec(&status).unwrap()).unwrap();
    assert_eq!(report("http://100.64.50.10", now).state, State::Running);
    assert_eq!(report("http://100.64.50.11", now).state, State::Stopped);
    assert_eq!(
        report("http://100.64.50.10", now + chrono::TimeDelta::seconds(91)).state,
        State::Stopped
    );
    apply(dir, None).unwrap();
    assert_eq!(report("http://100.64.50.10", now).state, State::Stopped);
}
