//! The software inventory of a build: the versions of the kernel and the
//! Blueprint's packages at the build's nixpkgs commit.
//!
//! One `nix eval` reads every version, so nixpkgs is evaluated once per build
//! instead of once per package. A commit's packages never change, so the
//! versions are remembered per (commit, system) and a later build at the same
//! commit evaluates only packages it has not seen. A package that is missing,
//! throws or has no short string version is left out, as before. When the
//! combined evaluation fails as a whole, each package is evaluated on its own
//! so one broken package cannot hide the others.
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use super::{
    AppConfig, ValidatedBuildSpec, append_build_isolation_nix_options, nixpkgs_flake_ref,
    run_bounded_command,
};

const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
const STDOUT_MAX_BYTES: usize = 64 * 1024;
const STDERR_MAX_BYTES: usize = 64 * 1024;
const MAX_VERSION_BYTES: usize = 160;
/// Commits whose versions are kept; a Nest builds at one or two at a time.
const REMEMBERED_COMMITS: usize = 8;

/// The Nix function applied to `legacyPackages.<system>` and the package
/// references: one attribute per reference, its version string or null.
/// The length bound is [`MAX_VERSION_BYTES`].
const VERSIONS_FUNCTION: &str = r#"pkgs: refs: let
  find = path: builtins.foldl' (value: name:
    if value != null && builtins.isAttrs value && builtins.hasAttr name value
    then value.${name} else null) pkgs path;
  version = ref: let
    path = builtins.filter builtins.isString (builtins.split "\\." ref);
    result = builtins.tryEval (let v = (find path).version or null; in
      if builtins.isString v && builtins.stringLength v <= 160 then v else null);
  in if result.success then result.value else null;
in builtins.listToAttrs (map (ref: { name = ref; value = version ref; }) refs)"#;

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub(super) total_timeout: Duration,
    pub(super) stdout_max_bytes: usize,
    pub(super) stderr_max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            total_timeout: TOTAL_TIMEOUT,
            stdout_max_bytes: STDOUT_MAX_BYTES,
            stderr_max_bytes: STDERR_MAX_BYTES,
        }
    }
}

type Versions = HashMap<String, Option<String>>;

fn remembered() -> &'static Mutex<HashMap<(String, String), Versions>> {
    static REMEMBERED: OnceLock<Mutex<HashMap<(String, String), Versions>>> = OnceLock::new();
    REMEMBERED.get_or_init(Mutex::default)
}

/// Probe package versions at the job's commit, from the narHash-pinned
/// source at a detected commit.
pub(super) async fn evaluate(
    config: &AppConfig,
    spec: &ValidatedBuildSpec,
    nixpkgs_nar_hash: Option<&str>,
    limits: Limits,
) -> Value {
    let Some(commit) = spec.nixpkgs_commit.as_deref() else {
        return json!([]);
    };
    let Ok(nixpkgs) = nixpkgs_flake_ref(commit, nixpkgs_nar_hash) else {
        return json!([]);
    };
    let mut refs = vec![(
        "linux-kernel".to_string(),
        "linuxPackages.kernel".to_string(),
    )];
    for package_ref in &spec.software_package_refs {
        if !refs.iter().any(|(_, existing)| existing == package_ref) {
            refs.push((package_ref.clone(), package_ref.clone()));
        }
    }
    let key = (commit.to_string(), spec.system.clone());
    let mut versions = remembered()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned()
        .unwrap_or_default();
    let missing = refs
        .iter()
        .map(|(_, package_ref)| package_ref.as_str())
        .filter(|package_ref| !versions.contains_key(*package_ref))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        let deadline = Instant::now() + limits.total_timeout;
        let mut found =
            evaluate_versions(config, &nixpkgs, &spec.system, &missing, limits, deadline).await;
        if found.is_none() && missing.len() > 1 {
            let mut each = Versions::new();
            for package_ref in missing {
                let single = [package_ref];
                let version =
                    evaluate_versions(config, &nixpkgs, &spec.system, &single, limits, deadline);
                each.extend(version.await.unwrap_or_default());
            }
            found = Some(each);
        }
        if let Some(found) = found.filter(|found| !found.is_empty()) {
            let mut remembered = remembered().lock().unwrap_or_else(|e| e.into_inner());
            if remembered.len() >= REMEMBERED_COMMITS && !remembered.contains_key(&key) {
                remembered.clear();
            }
            remembered.entry(key).or_default().extend(found.clone());
            versions.extend(found);
        }
    }
    Value::Array(
        refs.into_iter()
            .filter_map(|(name, package_ref)| {
                let version = versions.get(&package_ref)?.clone()?;
                Some(json!({ "name": name, "package_ref": package_ref, "version": version }))
            })
            .collect(),
    )
}

/// The versions of `refs` from one `nix eval`, or `None` when it fails.
async fn evaluate_versions(
    config: &AppConfig,
    nixpkgs: &str,
    system: &str,
    refs: &[&str],
    limits: Limits,
    deadline: Instant,
) -> Option<Versions> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    let mut command = crate::nix_command::tokio_command(&config.build.nix_binary);
    command.args(eval_args(nixpkgs, system, refs));
    let output = run_bounded_command(
        command,
        remaining,
        limits.stdout_max_bytes,
        limits.stderr_max_bytes,
        "nix software inventory eval",
    )
    .await
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let reported =
        serde_json::from_slice::<HashMap<String, Option<String>>>(&output.stdout).ok()?;
    Some(
        refs.iter()
            .filter_map(|package_ref| {
                let version = reported.get(*package_ref)?.as_deref().and_then(|version| {
                    let version = version.split_whitespace().collect::<Vec<_>>().join(" ");
                    (!version.is_empty() && version.len() <= MAX_VERSION_BYTES).then_some(version)
                });
                Some((package_ref.to_string(), version))
            })
            .collect(),
    )
}

fn eval_args(nixpkgs: &str, system: &str, refs: &[&str]) -> Vec<String> {
    let mut args = Vec::new();
    // Inventory is metadata, but `nix eval` can still realize an
    // import-from-derivation before returning that metadata. Keep it inside
    // the same isolation boundary as the real build.
    append_build_isolation_nix_options(&mut args);
    // The references pass as one JSON argument, never as Nix source: the
    // function reads them with `builtins.fromJSON`.
    let refs = serde_json::to_string(refs).expect("package references serialize");
    args.extend([
        "eval".to_string(),
        "--json".to_string(),
        "--no-write-lock-file".to_string(),
        format!("{nixpkgs}#legacyPackages.{system}"),
        "--apply".to_string(),
        format!(
            "pkgs: ({VERSIONS_FUNCTION}) pkgs (builtins.fromJSON {})",
            nix_string(&refs)
        ),
    ]);
    args
}

/// A Nix string literal of `value`.
fn nix_string(value: &str) -> String {
    let mut literal = String::with_capacity(value.len() + 2);
    literal.push('"');
    for character in value.chars() {
        match character {
            '"' | '\\' | '$' => {
                literal.push('\\');
                literal.push(character);
            }
            '\n' => literal.push_str("\\n"),
            '\r' => literal.push_str("\\r"),
            '\t' => literal.push_str("\\t"),
            _ => literal.push(character),
        }
    }
    literal.push('"');
    literal
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    use super::*;
    use crate::build::tests::{build_sandbox_is_required, flake_config_is_rejected};

    fn spec(commit: char) -> ValidatedBuildSpec {
        ValidatedBuildSpec {
            artifact_type: "nixos_closure".to_string(),
            target: "blueprint".to_string(),
            system: "x86_64-linux".to_string(),
            input_revision: "rev".to_string(),
            input_config_hash: "a".repeat(64),
            blueprint_id: None,
            blueprint_revision_id: None,
            blueprint_revision_config_hash: None,
            nixpkgs_commit: Some(commit.to_string().repeat(40)),
            source_lock_sha256: Some("d".repeat(64)),
            software_package_refs: vec!["firefox".to_string()],
            build_input: None,
            closure_source: None,
        }
    }

    /// A fake `nix` running `script` after checking the build isolation.
    fn fake_nix(name: &str, script: &str) -> (PathBuf, AppConfig) {
        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-software-inventory-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let fake_nix = root.join("fake-nix");
        std::fs::write(
            &fake_nix,
            format!(
                r#"#!/bin/sh
set -eu
case " $* " in
  *" --option accept-flake-config false "*) ;;
  *) exit 91 ;;
esac
echo call >> '{}'
{script}
"#,
                root.join("calls").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_nix, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = AppConfig::default();
        config.build.nix_binary = fake_nix.display().to_string();
        (root, config)
    }

    fn calls(root: &std::path::Path) -> usize {
        std::fs::read_to_string(root.join("calls"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    #[test]
    fn eval_keeps_the_build_isolation() {
        let args = eval_args(
            "github:NixOS/nixpkgs/reviewed",
            "x86_64-linux",
            &["firefox"],
        );
        assert!(flake_config_is_rejected(&args));
        assert!(build_sandbox_is_required(&args));
    }

    #[tokio::test]
    async fn one_eval_reads_every_version_and_a_commit_is_evaluated_once() {
        let (root, config) = fake_nix(
            "once",
            r#"printf '{"linuxPackages.kernel":"6.1","firefox":" 123.4 "}'"#,
        );
        let expected = json!([
            {"name": "linux-kernel", "package_ref": "linuxPackages.kernel", "version": "6.1"},
            {"name": "firefox", "package_ref": "firefox", "version": "123.4"},
        ]);
        let spec = spec('1');
        assert_eq!(
            evaluate(&config, &spec, None, Limits::default()).await,
            expected
        );
        assert_eq!(
            evaluate(&config, &spec, None, Limits::default()).await,
            expected
        );
        assert_eq!(calls(&root), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_failed_combined_eval_still_reports_each_package() {
        let (root, config) = fake_nix(
            "fallback",
            r#"case "$*" in
  *kernel*firefox*) exit 1 ;;
  *firefox*) printf '{"firefox":"123.4"}' ;;
  *) printf '{"linuxPackages.kernel":null}' ;;
esac"#,
        );
        let inventory = evaluate(&config, &spec('2'), None, Limits::default()).await;
        assert_eq!(
            inventory,
            json!([{"name": "firefox", "package_ref": "firefox", "version": "123.4"}])
        );
        assert_eq!(calls(&root), 3);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_timed_out_eval_leaves_no_process_behind() {
        let root = std::env::temp_dir().join(format!(
            "tiaris-nest-software-inventory-timeout-{}",
            std::process::id()
        ));
        let marker = root.join("orphan-survived");
        let (root, config) = fake_nix(
            "timeout",
            &format!(
                "( sleep 0.25; printf survived > '{}' ) &\nsleep 5",
                marker.display()
            ),
        );
        let started = Instant::now();
        let limits = Limits {
            total_timeout: Duration::from_millis(80),
            ..Limits::default()
        };
        assert_eq!(evaluate(&config, &spec('3'), None, limits).await, json!([]));
        assert!(started.elapsed() < Duration::from_secs(1));
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(
            !marker.exists(),
            "a timed-out inventory eval left a descendant process running"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
