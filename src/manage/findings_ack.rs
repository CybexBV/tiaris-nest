//! The software-update findings lane, sent once per change.
//!
//! Every report carried the whole lane (about 350 KiB on development, some
//! 0.9 GiB a day). The Nest sends the lane's SHA-256 with it; a Manage that
//! holds every finding of the lane answers that digest
//! (`software_update_findings_acknowledged`). While the lane is unchanged the
//! Nest then sends only the digest, which Manage reads as "unchanged". The
//! acknowledgement lives in memory and lasts six hours: a restarted Nest, or
//! one six hours on, sends the lane again. A Manage that does not answer the
//! digest gets the lane every time, as before.
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use crate::software_updates::findings::FindingReport;

/// How long an acknowledgement saves the lane.
const LASTS: Duration = Duration::from_secs(6 * 60 * 60);

/// The digest Manage acknowledged last, and when.
static ACKNOWLEDGED: Mutex<Option<(String, Instant)>> = Mutex::new(None);

/// What a report carries: the lane, unless Manage holds this very lane, and
/// its digest.
pub(super) fn lane(
    findings: Option<Vec<FindingReport>>,
) -> (Option<Vec<FindingReport>>, Option<String>) {
    let Some(findings) = findings else {
        return (None, None);
    };
    let Ok(body) = serde_json::to_vec(&findings) else {
        return (Some(findings), None);
    };
    let digest = hex::encode(Sha256::digest(body));
    let acknowledged = ACKNOWLEDGED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if held(acknowledged.as_ref(), &digest, Instant::now()) {
        return (None, Some(digest));
    }
    (Some(findings), Some(digest))
}

fn held(acknowledged: Option<&(String, Instant)>, digest: &str, now: Instant) -> bool {
    acknowledged.is_some_and(|(held, at)| held == digest && now.duration_since(*at) < LASTS)
}

/// After an accepted report: Manage's answer to a report that carried the
/// lane. An answer to a digest-only report changes nothing.
pub(super) fn record(sent_lane: bool, digest: Option<&str>, answer: Option<&str>) {
    if !sent_lane {
        return;
    }
    let mut acknowledged = ACKNOWLEDGED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *acknowledged = digest
        .filter(|digest| answer == Some(*digest))
        .map(|digest| (digest.to_string(), Instant::now()));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lane stays out only for the digest Manage acknowledged, and only
    /// for six hours.
    #[test]
    fn an_acknowledgement_holds_one_digest_for_six_hours() {
        let at = Instant::now();
        let acknowledged = ("a".repeat(64), at);
        assert!(held(Some(&acknowledged), &"a".repeat(64), at + Duration::from_secs(60)));
        assert!(!held(Some(&acknowledged), &"b".repeat(64), at));
        assert!(!held(Some(&acknowledged), &"a".repeat(64), at + LASTS));
        assert!(!held(None, &"a".repeat(64), at));
    }
}
