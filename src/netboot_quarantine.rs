//! Quarantined workstation runtime trees, removed after a week.
//!
//! A tree goes to `netboot-quarantine/<sha256>.<id>` when it fails its
//! integrity check (its bundle row then says `quarantined`) or when a tree
//! found where a new one goes does not verify (no row). Each is about 1.4 GB
//! and nothing reads it again: the Nest downloads a bundle it needs anew. A
//! week leaves time to look at one; then maintenance removes it.
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use chrono::{DateTime, Utc};

use super::{BUNDLE_UNREFERENCED, sync_directory};
use crate::AppState;

/// How long a quarantined tree stays.
const RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Remove the trees quarantined longer than [`RETENTION`] before `now`,
/// with their bundle rows. Returns how many trees went.
pub(super) async fn prune(state: &AppState, now: DateTime<Utc>) -> Result<usize> {
    let root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot-quarantine");
    if !fs::symlink_metadata(&root).is_ok_and(|metadata| metadata.is_dir()) {
        return Ok(0);
    }
    let cutoff = now - chrono::Duration::from_std(RETENTION)?;
    let rows: Vec<(String, String, bool)> = sqlx::query_as(&format!(
        "SELECT bundle.bundle_sha256, bundle.root_path,
                COALESCE(bundle.quarantined_at < ? AND {BUNDLE_UNREFERENCED}, 0)
         FROM workstation_netboot_bundles bundle
         JOIN workstation_netboot_runtime runtime ON runtime.singleton_id = 1
         WHERE bundle.retention_state = 'quarantined'"
    ))
    .bind(cutoff.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    .bind(now.timestamp())
    .fetch_all(&state.db)
    .await?;
    let mut removed = 0;
    let mut named = BTreeSet::new();
    for (bundle_sha256, root_path, expired) in rows {
        let tree = PathBuf::from(&root_path);
        named.insert(tree.clone());
        if !expired || quarantined_tree(&root, &tree).is_none_or(|sha| sha != bundle_sha256) {
            continue;
        }
        if remove_tree(&tree)? {
            removed += 1;
        }
        sqlx::query(
            "DELETE FROM workstation_netboot_bundles
             WHERE bundle_sha256 = ? AND retention_state = 'quarantined' AND root_path = ?",
        )
        .bind(&bundle_sha256)
        .bind(&root_path)
        .execute(&state.db)
        .await?;
    }
    // Trees without a row: their quarantine (a rename) is the last change
    // to them.
    let cutoff = cutoff.timestamp();
    for entry in fs::read_dir(&root)? {
        let tree = entry?.path();
        if named.contains(&tree) || quarantined_tree(&root, &tree).is_none() {
            continue;
        }
        let quarantined = fs::symlink_metadata(&tree)?;
        if quarantined.is_dir() && quarantined.ctime() < cutoff && remove_tree(&tree)? {
            removed += 1;
        }
    }
    if removed > 0 {
        sync_directory(&root)?;
    }
    Ok(removed)
}

/// The bundle a quarantined tree holds: `<root>/<sha256>.<32 hex>`.
fn quarantined_tree<'a>(root: &Path, tree: &'a Path) -> Option<&'a str> {
    if tree.parent() != Some(root) {
        return None;
    }
    let (sha256, id) = tree.file_name()?.to_str()?.split_once('.')?;
    let hex = |value: &str, length: usize| {
        value.len() == length
            && value
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    (hex(sha256, 64) && hex(id, 32)).then_some(sha256)
}

/// Remove a quarantined directory; never follows a link in its place.
fn remove_tree(tree: &Path) -> Result<bool> {
    match fs::symlink_metadata(tree) {
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(tree)?;
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
