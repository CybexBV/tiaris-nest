//! Why a `nix build` of a closure failed, read from the log the Nest captured.
//!
//! The log is Nix's `internal-json` stream rendered by
//! [`crate::nix_log::InternalJsonParser`] and redacted by `SharedLog`: Nix's
//! own messages keep their ANSI colour codes and lose their indentation. The
//! result is the report's `error_kind`, a plain reason, and, when one package
//! is at fault, `failed_packages`: the derivation names (without the store
//! hash) whose own build or fetch failed, never the parents that failed
//! only because of them.

use crate::nix_log::derivation_display_name;

use super::{
    SOURCE_BUILD_CANDIDATE_CAP, extract_would_build_derivations, source_build_blocked_message,
};

/// At most this many names travel in one report.
const FAILED_PACKAGE_CAP: usize = 20;
const FAILED_PACKAGE_NAME_MAX_BYTES: usize = 211;

/// Result-metadata key that names the failed packages, beside `error_kind`.
pub(super) const FAILED_PACKAGES_KEY: &str = "failed_packages";

#[derive(Debug, PartialEq, Eq)]
pub(super) struct NixBuildFailure {
    pub(super) kind: &'static str,
    pub(super) message: String,
    /// Only for `package_build_failed`; empty when the log did not name one.
    pub(super) failed_packages: Vec<String>,
}

impl NixBuildFailure {
    fn plain(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            failed_packages: Vec::new(),
        }
    }
}

pub(super) fn classify_nix_build_failure(logs: &str, oom_killed: bool) -> NixBuildFailure {
    let plain_log = strip_ansi(logs);
    let lower = plain_log.to_ascii_lowercase();
    if lower.contains("daemon-socket")
        || lower.contains("cannot connect to socket")
        || lower.contains("error connecting to the nix daemon")
    {
        return NixBuildFailure::plain(
            "nix_daemon_unavailable",
            "The Nix daemon is unavailable; restore nix-daemon.socket and retry",
        );
    }
    if oom_killed || lower.contains("out of memory") || lower.contains("oom-kill") {
        return NixBuildFailure::plain(
            "out_of_memory",
            "Nest exhausted its build memory; increase memory/swap or reduce max_build_cores",
        );
    }
    if lower.contains("no space left on device") || lower.contains("disk full") {
        return NixBuildFailure::plain(
            "insufficient_disk_space",
            "Nest ran out of disk space while building the Nix closure",
        );
    }
    if network_unavailable(&lower) {
        return NixBuildFailure::plain(
            "network_unavailable",
            "Nest could not reach the network to download software; check its internet connection and retry",
        );
    }
    if lower.contains("unable to start any build") {
        let candidates: Vec<String> =
            extract_would_build_derivations(logs, SOURCE_BUILD_CANDIDATE_CAP)
                .paths
                .iter()
                .map(|path| derivation_display_name(path))
                .collect();
        return NixBuildFailure::plain(
            "source_build_blocked",
            source_build_blocked_message(&candidates),
        );
    }
    let failed_packages = extract_failed_packages(&plain_log);
    if !failed_packages.is_empty()
        || lower.contains("builder for '")
        || lower.contains("failed to build")
        || lower.contains("dependencies of derivation")
        || lower.contains("cannot build '")
    {
        let message = match failed_packages.as_slice() {
            [] => "A package in the pinned nixpkgs revision failed to build; inspect the bounded build log"
                .to_string(),
            [only] => format!(
                "Package {only} failed to build in the pinned nixpkgs revision; inspect the bounded build log"
            ),
            [first, rest @ ..] => format!(
                "Package {first} and {} more failed to build in the pinned nixpkgs revision; inspect the bounded build log",
                rest.len()
            ),
        };
        return NixBuildFailure {
            kind: "package_build_failed",
            message,
            failed_packages,
        };
    }
    if evaluation_failed(&lower) {
        return NixBuildFailure::plain(
            "evaluation_failed",
            "Nix could not evaluate the Blueprint's configuration; inspect the bounded build log",
        );
    }
    NixBuildFailure::plain(
        "nix_build_failed",
        "Nix failed to build the requested closure; inspect the bounded build log",
    )
}

/// Nix itself could not download (a substituter or an input), or a fetcher
/// could not resolve or reach its host. Warnings that Nix retried are not
/// enough: a later success would make them noise.
fn network_unavailable(lower: &str) -> bool {
    const NETWORK_ERRORS: [&str; 7] = [
        "couldn't resolve host",
        "could not resolve host",
        "temporary failure in name resolution",
        "couldn't connect to server",
        "failed to connect to",
        "network is unreachable",
        "timeout was reached",
    ];
    if lower.contains("usually happens due to networking issues") {
        return true;
    }
    lower.lines().any(|line| {
        let line = line.trim_start();
        let nix_download_error =
            line.starts_with("error:") && line.contains("unable to download '");
        // A fetcher's own output, rendered as `<derivation>> curl: (6) …`.
        let fetcher_error = line.starts_with("curl: (") || line.contains("> curl: (");
        (nix_download_error || fetcher_error)
            && NETWORK_ERRORS.iter().any(|error| line.contains(error))
    })
}

fn evaluation_failed(lower: &str) -> bool {
    const EVALUATION_ERRORS: [&str; 9] = [
        "… while evaluating",
        "… while calling",
        "undefined variable '",
        "infinite recursion encountered",
        "syntax error, unexpected",
        "evaluation aborted with the following error message",
        "cannot coerce ",
        "' missing",
        "error: assertion '",
    ];
    EVALUATION_ERRORS.iter().any(|error| lower.contains(error))
}

/// Derivations whose own builder or fetch failed, in log order, deduplicated.
///
/// - `builder for '<drv>' failed …` (Nix up to 2.2x, Lix)
/// - `Cannot build '<drv>'.` followed by `Reason: builder failed …` (newer
///   Nix); a `Reason: N dependencies failed` names a parent and is skipped,
///   like the older `N dependencies of derivation '<drv>' failed to build`
/// - `hash mismatch in fixed-output derivation '<drv>'` (a source changed)
/// - `Package ‘<name>’ in … refusing to evaluate` (broken, unfree, insecure
///   or unsupported at this pin)
fn extract_failed_packages(plain_log: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut lines = plain_log.lines().map(str::trim).peekable();
    while let Some(line) = lines.next() {
        let failed = if let Some(path) = quoted_after(line, "builder for '") {
            Some(path)
        } else if let Some(path) = quoted_after(line, "hash mismatch in fixed-output derivation '")
        {
            Some(path)
        } else if let Some(path) = quoted_after(line, "Cannot build '") {
            let reason = lines.peek().copied().unwrap_or_default();
            let parent_only = reason
                .strip_prefix("Reason:")
                .is_some_and(|reason| reason.contains("dependenc"));
            (!parent_only).then_some(path)
        } else {
            None
        };
        let name = match failed {
            Some(path) if path.starts_with("/nix/store/") && path.ends_with(".drv") => {
                Some(derivation_display_name(path))
            }
            Some(_) => None,
            None => refused_package(line).map(str::to_string),
        };
        let Some(name) = name.filter(|name| valid_package_name(name)) else {
            continue;
        };
        if !names.contains(&name) {
            names.push(name);
            if names.len() == FAILED_PACKAGE_CAP {
                break;
            }
        }
    }
    names
}

fn quoted_after<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = &line[line.find(prefix)? + prefix.len()..];
    Some(&rest[..rest.find('\'')?])
}

fn refused_package(line: &str) -> Option<&str> {
    if !line.contains("refusing to evaluate") {
        return None;
    }
    let rest = &line[line.find("Package ‘")? + "Package ‘".len()..];
    Some(&rest[..rest.find('’')?])
}

/// A Nix store name: what Manage can match against an App List package.
fn valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= FAILED_PACKAGE_NAME_MAX_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte))
}

/// Remove ANSI escape sequences (`ESC [ … final`, and lone `ESC x`).
fn strip_ansi(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            plain.push(ch);
            continue;
        }
        if chars.next() == Some('[') {
            for code in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&code) {
                    break;
                }
            }
        }
    }
    plain
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nix_log::InternalJsonParser;

    /// The log exactly as the Nest stores it: each `internal-json` line
    /// rendered by the parser, then redacted line by line.
    fn captured(nix_stderr: &[&str]) -> String {
        let mut parser = InternalJsonParser::new();
        let mut rendered = String::new();
        for line in nix_stderr {
            if let Some(text) = parser.feed_line(line) {
                rendered.push_str(&text);
                rendered.push('\n');
            }
        }
        let mut redact_following = 0;
        super::super::redact_log_text(&rendered, &mut redact_following)
    }

    const WILL_BUILD: [&str; 4] = [
        r#"@nix {"action":"msg","level":3,"msg":"these 3 derivations will be built:"}"#,
        r#"@nix {"action":"msg","level":3,"msg":"  /nix/store/48innrrg4sbw9wsphnhxj1cdp1i0yrz6-firefox-esr-128.5.0esr.drv"}"#,
        r#"@nix {"action":"msg","level":3,"msg":"  /nix/store/ykdrc7f6ss2xq2p0jglmgpsr49j7jcih-system-path.drv"}"#,
        r#"@nix {"action":"msg","level":3,"msg":"  /nix/store/08r40qjz58b4ns5p50p8vbzh4sx60fjd-nixos-system-test.drv"}"#,
    ];

    /// Nix 2.35.6, captured on 19 November 2026 (the Nest's pin runs 2.34).
    const NIX_2_35_BUILDER_FAILED: [&str; 3] = [
        r#"@nix {"action":"msg","column":null,"file":null,"level":0,"line":null,"msg":"\u001b[31;1merror:\u001b[0m Cannot build '\u001b[35;1m/nix/store/48innrrg4sbw9wsphnhxj1cdp1i0yrz6-firefox-esr-128.5.0esr.drv\u001b[0m'.\n       Reason: \u001b[31;1mbuilder failed with exit code 2\u001b[0m.\n       Output paths:\n         \u001b[35;1m/nix/store/3gba0g7w1p01mzkbxjxymqq7b7inaiza-firefox-esr-128.5.0esr\u001b[0m","raw_msg":"Cannot build"}"#,
        r#"@nix {"action":"msg","column":null,"file":null,"level":0,"line":null,"msg":"\u001b[31;1merror:\u001b[0m Cannot build '\u001b[35;1m/nix/store/ykdrc7f6ss2xq2p0jglmgpsr49j7jcih-system-path.drv\u001b[0m'.\n       Reason: \u001b[31;1m1 dependency failed\u001b[0m.\n       Output paths:\n         \u001b[35;1m/nix/store/mka6wdi8cqlb4h1875ypyf9vigy8g11y-system-path\u001b[0m","raw_msg":"Cannot build"}"#,
        r#"@nix {"action":"msg","column":null,"file":null,"level":0,"line":null,"msg":"\u001b[31;1merror:\u001b[0m Cannot build '\u001b[35;1m/nix/store/08r40qjz58b4ns5p50p8vbzh4sx60fjd-nixos-system-test.drv\u001b[0m'.\n       Reason: \u001b[31;1m1 dependency failed\u001b[0m.\n       Output paths:\n         \u001b[35;1m/nix/store/nkiflaz06432a7r2frfbknrwq7jad2pk-nixos-system-test\u001b[0m","raw_msg":"Cannot build"}"#,
    ];

    /// Nix 2.26.3, captured on 19 November 2026.
    const NIX_2_26_BUILDER_FAILED: [&str; 3] = [
        r#"@nix {"action":"msg","level":0,"msg":"\u001b[31;1merror:\u001b[0m builder for '\u001b[35;1m/nix/store/48innrrg4sbw9wsphnhxj1cdp1i0yrz6-firefox-esr-128.5.0esr.drv\u001b[0m' failed with exit code 2;\n       last 2 log lines:\n       > compiling\n       > error: oops\n       For full logs, run:\n         \u001b[1mnix-store -l /nix/store/48innrrg4sbw9wsphnhxj1cdp1i0yrz6-firefox-esr-128.5.0esr.drv\u001b[0m"}"#,
        r#"@nix {"action":"msg","level":0,"msg":"\u001b[31;1merror:\u001b[0m \u001b[35;1m1\u001b[0m dependencies of derivation '\u001b[35;1m/nix/store/ykdrc7f6ss2xq2p0jglmgpsr49j7jcih-system-path.drv\u001b[0m' failed to build"}"#,
        r#"@nix {"action":"msg","column":null,"file":null,"level":0,"line":null,"msg":"\u001b[31;1merror:\u001b[0m \u001b[35;1m\u001b[0m\u001b[35;1m1\u001b[0m dependencies of derivation '\u001b[35;1m/nix/store/08r40qjz58b4ns5p50p8vbzh4sx60fjd-nixos-system-test.drv\u001b[0m' failed to build\u001b[0m","raw_msg":"failed to build"}"#,
    ];

    fn with_will_build(failure: &[&str]) -> String {
        let mut lines = WILL_BUILD.to_vec();
        lines.extend_from_slice(failure);
        captured(&lines)
    }

    #[test]
    fn a_failed_package_build_reports_the_package_name() {
        for failure in [&NIX_2_35_BUILDER_FAILED, &NIX_2_26_BUILDER_FAILED] {
            let classified = classify_nix_build_failure(&with_will_build(failure), false);
            assert_eq!(classified.kind, "package_build_failed");
            assert_eq!(classified.failed_packages, vec!["firefox-esr-128.5.0esr"]);
            assert!(
                classified
                    .message
                    .contains("Package firefox-esr-128.5.0esr failed"),
                "{}",
                classified.message
            );
        }
    }

    #[test]
    fn a_changed_source_names_its_fixed_output_derivation() {
        let log = captured(&[
            r#"@nix {"action":"msg","level":3,"msg":"this derivation will be built:"}"#,
            r#"@nix {"action":"msg","level":3,"msg":"  /nix/store/dnd4r9nr72i5wdkld0n2mvk6w8bwyhgl-vlc-3.0.21.tar.xz.drv"}"#,
            r#"@nix {"action":"msg","column":null,"file":null,"level":0,"line":null,"msg":"\u001b[31;1merror:\u001b[0m hash mismatch in fixed-output derivation '\u001b[35;1m/nix/store/dnd4r9nr72i5wdkld0n2mvk6w8bwyhgl-vlc-3.0.21.tar.xz.drv\u001b[0m':\n         specified: \u001b[35;1msha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\u001b[0m\n            got:    \u001b[35;1msha256-mOpuTyFvL7S2n/+bOkSELDhobKaF8/VdxIxdP7EQe+Q=\u001b[0m","raw_msg":"hash mismatch"}"#,
        ]);
        let classified = classify_nix_build_failure(&log, false);
        assert_eq!(classified.kind, "package_build_failed");
        assert_eq!(classified.failed_packages, vec!["vlc-3.0.21.tar.xz"]);
    }

    #[test]
    fn a_package_refused_at_evaluation_is_named() {
        let log = captured(&[
            r#"@nix {"action":"msg","column":null,"file":null,"level":0,"line":null,"msg":"\u001b[31;1merror:\u001b[0m\n       … while evaluating the attribute '\u001b[35;1mconfig.system.build.toplevel\u001b[0m'\n\n       \u001b[31;1merror:\u001b[0m Package ‘zoom-6.2.11.5069’ in /nix/store/k0qyqrnzbf4ykjmaaq5yb2j3xr8hi0bk-source/pkgs/by-name/zo/zoom-us/package.nix:212 has an unfree license (‘unfree’), refusing to evaluate.","raw_msg":"Package"}"#,
        ]);
        let classified = classify_nix_build_failure(&log, false);
        assert_eq!(classified.kind, "package_build_failed");
        assert_eq!(classified.failed_packages, vec!["zoom-6.2.11.5069"]);
    }

    #[test]
    fn several_failed_packages_are_named_once_each_and_bounded() {
        let mut stderr = Vec::new();
        for index in 0..30 {
            stderr.push(format!(
                r#"@nix {{"action":"msg","level":0,"msg":"error: builder for '/nix/store/{}-app{index}-1.0.drv' failed with exit code 1;"}}"#,
                "a".repeat(32)
            ));
        }
        stderr.push(stderr[0].clone());
        let stderr: Vec<&str> = stderr.iter().map(String::as_str).collect();
        let classified = classify_nix_build_failure(&captured(&stderr), false);
        assert_eq!(classified.failed_packages.len(), FAILED_PACKAGE_CAP);
        assert_eq!(classified.failed_packages[0], "app0-1.0");
        assert_eq!(classified.failed_packages[1], "app1-1.0");
        assert!(
            classified
                .message
                .contains("Package app0-1.0 and 19 more failed")
        );
    }

    #[test]
    fn a_package_failure_without_a_readable_name_keeps_the_plain_reason() {
        let classified = classify_nix_build_failure(
            "error: 1 dependencies of derivation '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system-path.drv' failed to build",
            false,
        );
        assert_eq!(classified.kind, "package_build_failed");
        assert!(classified.failed_packages.is_empty());
        assert!(classified.message.starts_with("A package in the pinned"));
    }

    #[test]
    fn failures_that_are_not_a_package_keep_their_own_reason() {
        let cases: [(&str, Vec<&str>, bool); 6] = [
            (
                "out_of_memory",
                vec![
                    r#"@nix {"action":"msg","level":0,"msg":"\u001b[31;1merror:\u001b[0m Cannot build '\u001b[35;1m/nix/store/48innrrg4sbw9wsphnhxj1cdp1i0yrz6-firefox-esr-128.5.0esr.drv\u001b[0m'.\n       Reason: \u001b[31;1mbuilder failed due to signal 9 (Killed)\u001b[0m."}"#,
                ],
                true,
            ),
            (
                "insufficient_disk_space",
                vec![
                    r#"@nix {"action":"result","id":12,"type":101,"fields":["cc1plus: fatal error: error writing to /build/ccXyZ.s: No space left on device"]}"#,
                    r#"@nix {"action":"msg","level":0,"msg":"\u001b[31;1merror:\u001b[0m builder for '\u001b[35;1m/nix/store/48innrrg4sbw9wsphnhxj1cdp1i0yrz6-firefox-esr-128.5.0esr.drv\u001b[0m' failed with exit code 1"}"#,
                    r#"@nix {"action":"msg","level":0,"msg":"\u001b[31;1merror:\u001b[0m writing to file: \u001b[35;1mNo space left on device\u001b[0m"}"#,
                ],
                false,
            ),
            (
                "network_unavailable",
                vec![
                    r#"@nix {"action":"msg","level":1,"msg":"\u001b[35;1mwarning:\u001b[0m error: unable to download 'https://cache.nixos.org/nix-cache-info': Couldn't resolve host name (6); retrying in 281 ms"}"#,
                    r#"@nix {"action":"msg","level":0,"msg":"\u001b[31;1merror:\u001b[0m some substitutes for the outputs of derivation '\u001b[35;1m/nix/store/48innrrg4sbw9wsphnhxj1cdp1i0yrz6-firefox-esr-128.5.0esr.drv\u001b[0m' failed (usually happens due to networking issues); try '--fallback' to build derivation from source "}"#,
                ],
                false,
            ),
            (
                "network_unavailable",
                vec![
                    r#"@nix {"action":"start","id":14,"level":3,"type":105,"text":"building '/nix/store/9d0v8c3ylqg3q0g7r1hlmq3d9q4vxmrz-firefox-128.5.0esr.source.tar.xz.drv'","fields":["/nix/store/9d0v8c3ylqg3q0g7r1hlmq3d9q4vxmrz-firefox-128.5.0esr.source.tar.xz.drv","",1,1],"parent":0}"#,
                    r#"@nix {"action":"result","id":14,"type":101,"fields":["curl: (6) Could not resolve host: archive.mozilla.org"]}"#,
                    r#"@nix {"action":"msg","level":0,"msg":"\u001b[31;1merror:\u001b[0m Cannot build '\u001b[35;1m/nix/store/9d0v8c3ylqg3q0g7r1hlmq3d9q4vxmrz-firefox-128.5.0esr.source.tar.xz.drv\u001b[0m'.\n       Reason: \u001b[31;1mbuilder failed with exit code 1\u001b[0m."}"#,
                ],
                false,
            ),
            (
                "evaluation_failed",
                vec![
                    r#"@nix {"action":"msg","column":112,"file":"/build/eval.nix:1:112","level":0,"line":1,"msg":"\u001b[31;1merror:\u001b[0m\n       … while calling the '\u001b[35;1mderivationStrict\u001b[0m' builtin\n         \u001b[34;1mat \u001b[35;1m<nix/derivation-internal.nix>:37:12\u001b[0m:\n\n       … while evaluating attribute '\u001b[35;1margs\u001b[0m' of derivation '\u001b[35;1my\u001b[0m'\n\n       \u001b[31;1merror:\u001b[0m attribute '\u001b[35;1mmissing\u001b[0m' missing\n       \u001b[34;1mat \u001b[35;1m/build/eval.nix:1:112\u001b[0m:","raw_msg":"attribute missing"}"#,
                ],
                false,
            ),
            (
                "nix_daemon_unavailable",
                vec![
                    r#"@nix {"action":"msg","level":0,"msg":"\u001b[31;1merror:\u001b[0m cannot connect to socket at '\u001b[35;1m/nix/var/nix/daemon-socket/socket\u001b[0m': \u001b[35;1mConnection refused\u001b[0m"}"#,
                ],
                false,
            ),
        ];
        for (kind, stderr, oom_killed) in cases {
            let classified = classify_nix_build_failure(&captured(&stderr), oom_killed);
            assert_eq!(classified.kind, kind, "{stderr:?}");
            assert!(classified.failed_packages.is_empty(), "{kind}");
        }
    }

    #[test]
    fn a_retried_download_warning_does_not_hide_a_package_failure() {
        let mut stderr = vec![
            r#"@nix {"action":"msg","level":1,"msg":"\u001b[35;1mwarning:\u001b[0m error: unable to download 'https://cache.nixos.org/abc.narinfo': Couldn't resolve host name (6); retrying in 281 ms"}"#,
        ];
        stderr.extend_from_slice(&NIX_2_35_BUILDER_FAILED);
        let classified = classify_nix_build_failure(&captured(&stderr), false);
        assert_eq!(classified.kind, "package_build_failed");
        assert_eq!(classified.failed_packages, vec!["firefox-esr-128.5.0esr"]);
    }

    #[test]
    fn an_unknown_failure_stays_generic() {
        let classified = classify_nix_build_failure(
            &captured(&[
                r#"@nix {"action":"msg","level":0,"msg":"\u001b[31;1merror:\u001b[0m something unexpected"}"#,
            ]),
            false,
        );
        assert_eq!(classified.kind, "nix_build_failed");
    }

    #[test]
    fn strip_ansi_removes_colour_codes_only() {
        assert_eq!(
            strip_ansi("\u{1b}[31;1merror:\u{1b}[0m Cannot build '\u{1b}[35;1m/x.drv\u{1b}[0m'."),
            "error: Cannot build '/x.drv'."
        );
        assert_eq!(strip_ansi("plain ‘text’"), "plain ‘text’");
    }
}
