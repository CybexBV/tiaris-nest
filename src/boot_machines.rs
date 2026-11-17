//! Which computer a network boot is, beyond the MAC address it boots with.
//!
//! Several laptops can start through one USB network adapter or dock, so its
//! MAC names no single computer. iPXE also reports the computer's SMBIOS
//! system UUID, which the Nest turns into the hardware fingerprint the Tiaris
//! agent reports (`boot_identity::uuid_fingerprint`), and its serial number.
//! Manage tells the Nest in its boot configuration:
//!
//! - for each network reinstall it arms, the fingerprints of the computer the
//!   reinstall is for, and whether that MAC is shared by several computers
//!   (then a boot that cannot prove to be that computer never gets it);
//! - the fingerprints of the computers Tiaris knows, and whether each one is
//!   installed or still being installed.
//!
//! This is kept as a state file, not in SQLite: Nests before schema evolution
//! refuse a release that adds migrations (`docs/sqlite-schema-evolution.md`).
//! The record is written before the boot configuration that needs it is
//! committed, so a reinstall binding is never served without the computer it
//! is for.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::boot_identity::{is_fingerprint, usable_uuid, uuid_fingerprint};

/// Advertised to a Manage that says it supports it: this Nest gives a
/// reinstall only to the computer Manage names.
pub const CAPABILITY: &str = "boot_machine_identity_v1";

const DIR: &str = "boot-identity";
const FILE: &str = "boot-identity.json";
const SCHEMA: &str = "tiaris.nest.boot-identity";
const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REINSTALL_FINGERPRINTS: usize = 16;
const MAX_REINSTALLS: usize = 4096;
const MAX_MACHINES: usize = 16_384;

/// What Manage last said about the computers behind network boots.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The computer each armed network reinstall is for, by request id.
    #[serde(default)]
    pub reinstalls: BTreeMap<String, ReinstallMachine>,
    /// The computers Tiaris knows, by fingerprint: `true` when installed.
    #[serde(default)]
    pub machines: BTreeMap<String, bool>,
}

/// The computer one network reinstall is for.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReinstallMachine {
    pub fingerprints: Vec<String>,
    /// The reinstall's MAC is shared: a boot without a matching fingerprint
    /// is never that computer, even when its serial looks right.
    pub required: bool,
}

/// What a boot request says about its own computer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootIdentity {
    /// The usable system UUID, for menu links.
    pub uuid: Option<String>,
    /// The UUID as a hardware fingerprint.
    pub fingerprint: Option<String>,
    /// The serial number as reported, untruncated.
    pub serial: Option<String>,
}

impl BootIdentity {
    pub fn from_reported(uuid: Option<&str>, serial: Option<String>) -> Self {
        let uuid = uuid.and_then(usable_uuid);
        Self {
            fingerprint: uuid.as_deref().map(uuid_fingerprint),
            uuid,
            serial,
        }
    }
}

/// Whether a boot may take the reinstall armed on its MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReinstallCheck {
    /// Its UUID is the one of the computer the reinstall is for.
    Proven,
    /// It is another computer, or a shared MAC and nothing proves it.
    NotThisComputer,
    /// Manage named no computer: the serial rule decides, as before.
    Unnamed,
}

impl Record {
    pub fn reinstall_check(&self, request_id: &str, identity: &BootIdentity) -> ReinstallCheck {
        let Some(named) = self.reinstalls.get(request_id) else {
            return ReinstallCheck::Unnamed;
        };
        match identity.fingerprint.as_deref() {
            Some(fingerprint) if named.fingerprints.iter().any(|item| item == fingerprint) => {
                ReinstallCheck::Proven
            }
            Some(_) => ReinstallCheck::NotThisComputer,
            None if named.required => ReinstallCheck::NotThisComputer,
            None => ReinstallCheck::Unnamed,
        }
    }

    /// `Some(installed)` when Tiaris knows the computer behind this boot.
    pub fn known_machine(&self, identity: &BootIdentity) -> Option<bool> {
        identity
            .fingerprint
            .as_deref()
            .and_then(|fingerprint| self.machines.get(fingerprint).copied())
    }
}

/// One armed reinstall as Manage's boot configuration names its computer.
pub struct NamedReinstall<'a> {
    pub fingerprints: &'a [String],
    pub required: bool,
}

/// The record after a boot configuration sync. `named` holds every reinstall
/// the configuration carries, with or without a computer; reinstalls it does
/// not carry (a truncated configuration) keep what the previous record said
/// while their binding is still on a row (`live_request_ids`).
pub fn merge(
    previous: &Record,
    named: &[(&str, Option<NamedReinstall<'_>>)],
    live_request_ids: &BTreeSet<String>,
    machines: impl IntoIterator<Item = (String, bool)>,
) -> Record {
    let mut record = Record::default();
    let mentioned: BTreeSet<&str> = named.iter().map(|(request_id, _)| *request_id).collect();
    for (request_id, reinstall) in named {
        let Some(reinstall) = reinstall else {
            continue;
        };
        if !live_request_ids.contains(*request_id) {
            continue;
        }
        let mut fingerprints: Vec<String> = reinstall
            .fingerprints
            .iter()
            .filter(|value| is_fingerprint(value))
            .cloned()
            .collect();
        fingerprints.sort();
        fingerprints.dedup();
        fingerprints.truncate(MAX_REINSTALL_FINGERPRINTS);
        record.reinstalls.insert(
            request_id.to_string(),
            ReinstallMachine {
                fingerprints,
                required: reinstall.required,
            },
        );
    }
    for (request_id, reinstall) in &previous.reinstalls {
        if record.reinstalls.len() >= MAX_REINSTALLS {
            break;
        }
        if !mentioned.contains(request_id.as_str()) && live_request_ids.contains(request_id) {
            record
                .reinstalls
                .insert(request_id.clone(), reinstall.clone());
        }
    }
    for (fingerprint, installed) in machines {
        if record.machines.len() >= MAX_MACHINES {
            break;
        }
        if is_fingerprint(&fingerprint) {
            // A computer that is installed and also being installed again
            // may have a blank disk: it counts as being installed.
            let entry = record.machines.entry(fingerprint).or_insert(installed);
            *entry &= installed;
        }
    }
    record
}

fn dir(data_dir: &Path) -> PathBuf {
    data_dir.join(DIR)
}

/// The last record; empty when there is none or it cannot be read.
pub fn load(data_dir: &Path) -> Record {
    crate::state_files::read::<Record>(&dir(data_dir), FILE, SCHEMA, MAX_BYTES).unwrap_or_default()
}

pub async fn save(data_dir: &Path, record: &Record) -> Result<()> {
    let dir = dir(data_dir);
    let _guard = crate::state_files::lock(&dir).await;
    crate::state_files::write(&dir, FILE, SCHEMA, MAX_BYTES, record)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{BootIdentity, NamedReinstall, Record, ReinstallCheck, load, merge, save};
    use crate::boot_identity::uuid_fingerprint;

    const UUID_A: &str = "4c4c4544-0042-3510-8051-b4c04f4e3732";
    const UUID_B: &str = "6a1e2f3c-9b8d-4e7f-a1b2-c3d4e5f60718";

    fn identity(uuid: Option<&str>, serial: Option<&str>) -> BootIdentity {
        BootIdentity::from_reported(uuid, serial.map(str::to_string))
    }

    fn record_for_a(required: bool) -> Record {
        let fingerprints = vec![uuid_fingerprint(UUID_A), "b".repeat(64)];
        merge(
            &Record::default(),
            &[(
                "req-a",
                Some(NamedReinstall {
                    fingerprints: &fingerprints,
                    required,
                }),
            )],
            &BTreeSet::from(["req-a".to_string()]),
            [],
        )
    }

    #[test]
    fn a_reinstall_goes_only_to_the_computer_manage_names() {
        let record = record_for_a(false);
        assert_eq!(
            record.reinstall_check("req-a", &identity(Some(UUID_A), Some("5CG1234BBB"))),
            ReinstallCheck::Proven
        );
        assert_eq!(
            record.reinstall_check("req-a", &identity(Some(UUID_B), Some("5CG1234AAA"))),
            ReinstallCheck::NotThisComputer
        );
        // Without a UUID on an unshared MAC the serial rule still decides.
        assert_eq!(
            record.reinstall_check("req-a", &identity(None, Some("5CG1234AAA"))),
            ReinstallCheck::Unnamed
        );
        assert_eq!(
            record.reinstall_check(
                "req-a",
                &identity(Some("00000000-0000-0000-0000-000000000000"), None)
            ),
            ReinstallCheck::Unnamed
        );
        assert_eq!(
            record.reinstall_check("other", &identity(Some(UUID_B), None)),
            ReinstallCheck::Unnamed
        );
    }

    #[test]
    fn on_a_shared_mac_a_boot_without_a_uuid_never_gets_the_reinstall() {
        let record = record_for_a(true);
        assert_eq!(
            record.reinstall_check("req-a", &identity(None, Some("5CG1234AAA"))),
            ReinstallCheck::NotThisComputer
        );
        assert_eq!(
            record.reinstall_check("req-a", &identity(Some(UUID_A), None)),
            ReinstallCheck::Proven
        );
    }

    #[test]
    fn merge_keeps_live_reinstalls_a_truncated_configuration_left_out() {
        let previous = record_for_a(true);
        let fingerprints = vec![uuid_fingerprint(UUID_B), "not-a-fingerprint".to_string()];
        let live = BTreeSet::from(["req-a".to_string(), "req-b".to_string()]);
        let merged = merge(
            &previous,
            &[(
                "req-b",
                Some(NamedReinstall {
                    fingerprints: &fingerprints,
                    required: false,
                }),
            )],
            &live,
            [
                (uuid_fingerprint(UUID_A), true),
                (uuid_fingerprint(UUID_A), false),
                ("short".to_string(), true),
            ],
        );
        assert_eq!(merged.reinstalls["req-a"], previous.reinstalls["req-a"]);
        assert_eq!(
            merged.reinstalls["req-b"].fingerprints,
            vec![uuid_fingerprint(UUID_B)]
        );
        assert_eq!(merged.machines.len(), 1);
        assert!(!merged.machines[&uuid_fingerprint(UUID_A)]);

        // A reinstall the configuration carries without a computer, or whose
        // binding left every row, is forgotten.
        let forgotten = merge(&merged, &[("req-a", None)], &BTreeSet::new(), []);
        assert!(forgotten.reinstalls.is_empty());
        let unnamed = merge(&merged, &[("req-a", None)], &live, []);
        assert_eq!(unnamed.reinstalls.len(), 1);
        assert!(unnamed.reinstalls.contains_key("req-b"));
    }

    #[test]
    fn known_machines_are_found_by_the_boot_uuid() {
        let record = merge(
            &Record::default(),
            &[],
            &BTreeSet::new(),
            [
                (uuid_fingerprint(UUID_A), true),
                (uuid_fingerprint(UUID_B), false),
            ],
        );
        assert_eq!(
            record.known_machine(&identity(Some(UUID_A), None)),
            Some(true)
        );
        assert_eq!(
            record.known_machine(&identity(Some(&UUID_B.to_uppercase()), None)),
            Some(false)
        );
        assert_eq!(
            record.known_machine(&identity(None, Some("5CG1234AAA"))),
            None
        );
    }

    #[tokio::test]
    async fn the_record_survives_a_restart_and_a_missing_one_is_empty() {
        let dir = std::env::temp_dir().join(format!(
            "tiaris-nest-boot-machines-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        assert_eq!(load(&dir), Record::default());
        let record = record_for_a(true);
        save(&dir, &record).await.unwrap();
        assert_eq!(load(&dir), record);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
