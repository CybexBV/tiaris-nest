//! What a Nest would have to build itself for one configuration at one
//! nixpkgs commit.
//!
//! A dry run in an empty private store, which may substitute only from the
//! public NixOS cache, lists the derivations no cache has: the Nest would
//! build those. The answer does not depend on what this Nest has built
//! before or on the caches Manage gave it access to, so the same commit gets
//! the same answer on every Nest of a release.
//!
//! The software-update check (`super`) runs it for each shipped reference at
//! the release's own nixpkgs commit and at a new channel commit, and holds
//! the commit back only for work the release's commit does not ask for.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use rand::{RngCore, rngs::OsRng};
use serde_json::Value;

use crate::{config::AppConfig, nix_log::derivation_display_name, subprocess::run_bounded_command};

/// The only cache a dry run may substitute from.
const PUBLIC_CACHE: &str = "https://cache.nixos.org/";
const DRY_RUN_TIMEOUT: Duration = Duration::from_secs(600);
const DRY_RUN_STDOUT_MAX_BYTES: usize = 1024 * 1024;
const DRY_RUN_STDERR_MAX_BYTES: usize = 4 * 1024 * 1024;
const DERIVATION_SHOW_TIMEOUT: Duration = Duration::from_secs(120);
const DERIVATION_SHOW_CHUNK: usize = 100;
const DERIVATION_SHOW_STDOUT_MAX_BYTES: usize = 64 * 1024 * 1024;
const DERIVATION_SHOW_STDERR_MAX_BYTES: usize = 1024 * 1024;
/// A configuration with more local derivations than this is not judged.
const MAX_LOCAL_DERIVATIONS: usize = 4096;
const STORE_DIR_PREFIX: &str = "dry-run-store-";

/// The derivations a dry run says "will be built", with the `nix derivation
/// show` record of each.
#[derive(Clone, Debug, Default)]
pub(crate) struct LocalWork {
    would_build: Vec<String>,
    derivations: BTreeMap<String, Value>,
}

impl LocalWork {
    pub(crate) fn len(&self) -> usize {
        self.would_build.len()
    }

    /// The role of every derivation that would be built.
    pub(crate) fn roles(&self) -> BTreeSet<String> {
        self.would_build.iter().map(|path| role(path)).collect()
    }

    /// The derivations that may be a compile, as `(role, name)` in dry-run
    /// order: not a download, and not marked by nixpkgs as cheap local work.
    /// A derivation without a record counts.
    pub(crate) fn possible_compiles(&self) -> Vec<(String, String)> {
        self.would_build
            .iter()
            .filter(|path| {
                !self
                    .derivations
                    .get(*path)
                    .is_some_and(|drv| is_download(drv) || is_marked_local(drv))
            })
            .map(|path| (role(path), derivation_display_name(path)))
            .collect()
    }
}

/// The role of a derivation: its name up to its version, as Nix's
/// `parseDrvName` splits it (up to the first `-` followed by a digit), so
/// `firefox-153.6.0esr` and `firefox-152.4.0esr` have one role. The system
/// closure is named after the host and the nixpkgs commit; its role is the
/// same whatever they are.
pub(crate) fn role(drv_path: &str) -> String {
    let name = derivation_display_name(drv_path);
    if name.starts_with("nixos-system-") {
        return "nixos-system".to_string();
    }
    let bytes = name.as_bytes();
    let end = (0..bytes.len().saturating_sub(1))
        .find(|index| bytes[*index] == b'-' && bytes[index + 1].is_ascii_digit())
        .unwrap_or(bytes.len());
    name[..end].to_string()
}

/// A fixed-output derivation: an output with a declared content hash. It
/// downloads; it does not compile.
fn is_download(drv: &Value) -> bool {
    drv.get("outputs")
        .and_then(Value::as_object)
        .is_some_and(|outputs| {
            outputs.values().any(|output| {
                ["hash", "hashAlgo", "method"].iter().any(|key| {
                    output
                        .get(*key)
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                })
            })
        })
}

/// nixpkgs sets `preferLocalBuild` on work that is cheaper to do than to
/// download: generated configuration files, units, link farms and wrappers.
/// Nix 2.26 keeps structured attributes in `env.__json`; newer releases in
/// `structuredAttrs`.
fn is_marked_local(drv: &Value) -> bool {
    fn truthy(attributes: Option<&Value>) -> bool {
        attributes
            .and_then(|attributes| attributes.get("preferLocalBuild"))
            .is_some_and(|value| {
                value.as_bool() == Some(true) || matches!(value.as_str(), Some("1" | "true"))
            })
    }
    let env = drv.get("env");
    truthy(env)
        || truthy(drv.get("structuredAttrs"))
        || env
            .and_then(|env| env.get("__json"))
            .and_then(Value::as_str)
            .and_then(|encoded| serde_json::from_str::<Value>(encoded).ok())
            .is_some_and(|structured| truthy(Some(&structured)))
}

/// Dry-run `installable` in a fresh private store below the build work
/// directory. Nothing is built; the store is removed again, also when the
/// run fails or is cancelled.
pub(crate) async fn dry_run(config: &AppConfig, installable: &str) -> Result<LocalWork> {
    let store = PrivateStore::create(&config.build.work_dir).await?;
    let result = dry_run_in_store(config, installable, &store.root).await;
    let cleanup = store.remove().await;
    let work = result?;
    cleanup?;
    Ok(work)
}

/// `--store` arguments for the private store. Nix collects garbage in any
/// store whose file system has less free space than `min-free`; the store
/// lives in the build work directory (a tmpfs on many hosts), and collection
/// there would delete the derivations the dry run just evaluated.
fn private_store_args(store_root: &Path) -> [String; 5] {
    [
        "--store".to_string(),
        format!("local?root={}", store_root.display()),
        "--option".to_string(),
        "min-free".to_string(),
        "0".to_string(),
    ]
}

async fn dry_run_in_store(
    config: &AppConfig,
    installable: &str,
    store_root: &Path,
) -> Result<LocalWork> {
    let program = &config.build.nix_binary;
    let mut dry_run = crate::nix_command::tokio_command(program);
    dry_run
        .args(private_store_args(store_root))
        // No build while evaluating, no settings from the flake, and only
        // signed paths of the public cache count as present. nixpkgs prefers
        // to build some cached wrappers locally: take those from the cache
        // too, so what is left is what no cache has.
        .args(["--option", "allow-import-from-derivation", "false"])
        .args(["--option", "accept-flake-config", "false"])
        .args(["--option", "substituters", PUBLIC_CACHE])
        .args(["--option", "always-allow-substitutes", "true"])
        .args(["--option", "require-sigs", "true"])
        .args(["build", installable, "--dry-run", "--no-write-lock-file"])
        .current_dir(&config.build.work_dir)
        .env("LC_ALL", "C")
        .env("LANG", "C");
    let output = run_bounded_command(
        dry_run,
        DRY_RUN_TIMEOUT,
        DRY_RUN_STDOUT_MAX_BYTES,
        DRY_RUN_STDERR_MAX_BYTES,
        "nix build --dry-run",
    )
    .await?;
    if !output.status.success() {
        bail!("nix build --dry-run failed: {}", tail(&output.stderr, 500));
    }
    let mut listing = String::from_utf8_lossy(&output.stdout).into_owned();
    listing.push('\n');
    listing.push_str(&String::from_utf8_lossy(&output.stderr));
    let would_build = would_build_derivations(&listing)?;
    let mut derivations = BTreeMap::new();
    for chunk in would_build.chunks(DERIVATION_SHOW_CHUNK) {
        let mut show = crate::nix_command::tokio_command(program);
        show.args(private_store_args(store_root))
            .args(["derivation", "show"])
            .args(chunk)
            .env("LC_ALL", "C")
            .env("LANG", "C");
        let output = run_bounded_command(
            show,
            DERIVATION_SHOW_TIMEOUT,
            DERIVATION_SHOW_STDOUT_MAX_BYTES,
            DERIVATION_SHOW_STDERR_MAX_BYTES,
            "nix derivation show",
        )
        .await?;
        if !output.status.success() {
            bail!("nix derivation show failed: {}", tail(&output.stderr, 500));
        }
        let shown: Value =
            serde_json::from_slice(&output.stdout).context("parse nix derivation show JSON")?;
        for path in chunk {
            if let Some(drv) = shown_derivation(&shown, path) {
                derivations.insert(path.clone(), drv.clone());
            }
        }
    }
    Ok(LocalWork {
        would_build,
        derivations,
    })
}

/// The `.drv` paths of nix's "these N derivations will be built:" block. A
/// listing that is longer than the bound, or that does not hold exactly the
/// advertised paths, is an error: a part of it is not judged.
fn would_build_derivations(listing: &str) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    let mut unique = BTreeSet::new();
    let mut advertised = 0usize;
    let mut in_block = false;
    for line in listing.lines() {
        let line = line.trim();
        let count = if line == "this derivation will be built:" {
            Some(1)
        } else {
            line.strip_prefix("these ")
                .and_then(|rest| rest.strip_suffix(" derivations will be built:"))
                .and_then(|count| count.parse::<usize>().ok())
        };
        if let Some(count) = count {
            in_block = true;
            advertised = advertised.saturating_add(count);
            continue;
        }
        if in_block && line.starts_with("/nix/store/") && line.ends_with(".drv") {
            if unique.insert(line.to_string()) {
                paths.push(line.to_string());
            }
            continue;
        }
        in_block = false;
    }
    if advertised > MAX_LOCAL_DERIVATIONS {
        bail!("the dry run lists more than {MAX_LOCAL_DERIVATIONS} local derivations");
    }
    if advertised != paths.len() {
        bail!("the dry run did not list the derivations it announced");
    }
    Ok(paths)
}

/// One derivation in `nix derivation show` JSON. Older nix keys the object
/// by full store path; nix 2.30 and later nest the entries under
/// `derivations`, keyed by the `.drv` file name.
fn shown_derivation<'value>(shown: &'value Value, drv_path: &str) -> Option<&'value Value> {
    let map = shown
        .get("derivations")
        .and_then(Value::as_object)
        .or_else(|| shown.as_object())?;
    map.get(drv_path)
        .or_else(|| map.get(drv_path.rsplit('/').next().unwrap_or(drv_path)))
}

fn tail(bytes: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let skip = text.chars().count().saturating_sub(max_chars);
    text.chars().skip(skip).collect()
}

/// A private store below `work_dir`, removed by `remove` or, failing that,
/// when dropped (for example when a timeout cancels the check).
struct PrivateStore {
    root: PathBuf,
    removed: bool,
}

impl PrivateStore {
    async fn create(work_dir: &Path) -> Result<Self> {
        tokio::fs::create_dir_all(work_dir)
            .await
            .with_context(|| format!("create build work directory {}", work_dir.display()))?;
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let root = work_dir.join(format!("{STORE_DIR_PREFIX}{}", hex::encode(nonce)));
        tokio::fs::create_dir(&root)
            .await
            .with_context(|| format!("create private store {}", root.display()))?;
        Ok(Self {
            root,
            removed: false,
        })
    }

    async fn remove(mut self) -> Result<()> {
        self.removed = true;
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            make_directories_owner_writable(&root)?;
            fs::remove_dir_all(&root)
        })
        .await
        .context("join private store cleanup")?
        .with_context(|| format!("remove private store {}", self.root.display()))
    }
}

impl Drop for PrivateStore {
    fn drop(&mut self) {
        if !self.removed {
            remove_private_tree(&self.root);
        }
    }
}

/// Remove a private directory tree that may contain read-only store
/// directories. Best effort: failures leave it for the next startup.
pub(crate) fn remove_private_tree(path: &Path) {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
        let _ = make_directories_owner_writable(path);
        let _ = fs::remove_dir_all(path);
    }
}

/// Nix store directories are read-only; give the owner write access so the
/// tree can be removed. Symlinks are never followed.
fn make_directories_owner_writable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the cleanup root must be a real directory",
        ));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | 0o700);
    fs::set_permissions(path, permissions)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            make_directories_owner_writable(&entry.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn drv(name: &str) -> String {
        format!("/nix/store/{}-{name}.drv", "a".repeat(32))
    }

    #[test]
    fn a_role_is_the_name_without_its_version_host_or_commit() {
        assert_eq!(role(&drv("firefox-153.6.0esr")), "firefox");
        assert_eq!(role(&drv("initrd-linux-6.18.64")), "initrd-linux");
        assert_eq!(role(&drv("unit-dbus.service")), "unit-dbus.service");
        assert_eq!(
            role(&drv("nixos-system-tiaris-26.05.20261118.3457b69")),
            "nixos-system"
        );
    }

    #[test]
    fn downloads_and_marked_local_work_are_never_a_compile() {
        let fetch = json!({"outputs": {"out": {"hash": "0".repeat(64), "hashAlgo": "sha256"}}});
        let plain = json!({"outputs": {"out": {"path": "/nix/store/x"}}, "env": {}});
        let derivations = BTreeMap::from([
            (drv("initrd-linux-6.18.64"), plain.clone()),
            (drv("libreoffice-26.2.1.2"), plain),
            (drv("libreoffice-26.2.1.2.tar.xz"), fetch),
            (
                drv("unit-new.service"),
                json!({"env": {"preferLocalBuild": "1"}}),
            ),
            (
                drv("etc"),
                json!({"structuredAttrs": {"preferLocalBuild": true}}),
            ),
            (
                drv("users-groups.json"),
                json!({"env": {"__json": "{\"preferLocalBuild\":true}"}}),
            ),
        ]);
        let mut would_build = derivations.keys().cloned().collect::<Vec<_>>();
        // A derivation without a record counts as a possible compile.
        would_build.push(drv("rustc-1.93.0"));
        let work = LocalWork {
            would_build,
            derivations,
        };
        assert_eq!(
            work.possible_compiles(),
            [
                (
                    "initrd-linux".to_string(),
                    "initrd-linux-6.18.64".to_string()
                ),
                (
                    "libreoffice".to_string(),
                    "libreoffice-26.2.1.2".to_string()
                ),
                ("rustc".to_string(), "rustc-1.93.0".to_string()),
            ]
        );
        assert!(work.roles().contains("unit-new.service"));
    }

    #[test]
    fn the_dry_run_listing_must_hold_exactly_what_it_announces() {
        let listing = format!(
            "these 2 derivations will be built:\n  {}\n  {}\nthese 3 paths will be fetched (1.0 MiB download):\n  /nix/store/{}-hello\n",
            drv("a"),
            drv("b"),
            "b".repeat(32)
        );
        assert_eq!(
            would_build_derivations(&listing).unwrap(),
            [drv("a"), drv("b")]
        );
        assert!(would_build_derivations("").unwrap().is_empty());
        assert!(
            would_build_derivations(&format!(
                "these 2 derivations will be built:\n  {}\n",
                drv("a")
            ))
            .is_err()
        );
        assert!(
            would_build_derivations(&format!(
                "these {} derivations will be built:\n",
                MAX_LOCAL_DERIVATIONS + 1
            ))
            .is_err()
        );
    }

    #[test]
    fn derivation_show_is_read_in_both_shapes() {
        let path = drv("etc");
        let old = json!({ path.clone(): {"name": "etc"} });
        let new = json!({"derivations": { path.rsplit('/').next().unwrap(): {"name": "etc"} }});
        assert!(shown_derivation(&old, &path).is_some());
        assert!(shown_derivation(&new, &path).is_some());
        assert!(shown_derivation(&new, &drv("other")).is_none());
    }
}
