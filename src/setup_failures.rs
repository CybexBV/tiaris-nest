//! Setup attempts that failed on this Nest before Tiaris was asked: the Nest
//! could not start the installer for a computer (no verified runtime, no
//! signed session, no installer profile). Tiaris never hears of these
//! computers, so the boot report carries them (`state.setup_failures`) and
//! Add computers lists them with the computers Tiaris refused.
//!
//! Kept in memory: how many failed, the last reason, MAC and time. A start
//! that works clears it (the fault is gone, the computer can be restarted),
//! and so does a day without a failure.

use std::sync::{Mutex, MutexGuard};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{Value, json};

/// A failure is reported for this long after the last one.
const REPORTED_FOR_HOURS: i64 = 24;

/// Why the Nest could not start the installer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupFailure {
    /// The Nest has no verified workstation runtime to start.
    RuntimeUnavailable,
    /// The Nest could not sign a boot session for the computer.
    SessionUnavailable,
    /// The Nest has no installer profile switched on.
    ProfileUnavailable,
}

impl SetupFailure {
    fn code(self) -> &'static str {
        match self {
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::SessionUnavailable => "session_unavailable",
            Self::ProfileUnavailable => "profile_unavailable",
        }
    }
}

#[derive(Clone, Debug)]
struct Failures {
    count: u32,
    reason: SetupFailure,
    mac: String,
    first_at: DateTime<Utc>,
    last_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct SetupFailures(Mutex<Option<Failures>>);

impl SetupFailures {
    fn lock(&self) -> MutexGuard<'_, Option<Failures>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn record(&self, reason: SetupFailure, mac: &str, now: DateTime<Utc>) {
        let mut failures = self.lock();
        match failures.as_mut() {
            Some(current) if now - current.last_at < Duration::hours(REPORTED_FOR_HOURS) => {
                current.count = current.count.saturating_add(1);
                current.reason = reason;
                current.mac = mac.to_string();
                current.last_at = now;
            }
            _ => {
                *failures = Some(Failures {
                    count: 1,
                    reason,
                    mac: mac.to_string(),
                    first_at: now,
                    last_at: now,
                })
            }
        }
    }

    pub fn clear(&self) {
        *self.lock() = None;
    }

    /// `{count, reason, mac, first_at, last_at}`, or nothing to report.
    pub fn report(&self, now: DateTime<Utc>) -> Option<Value> {
        let failures = self.lock();
        let current = failures.as_ref()?;
        if now - current.last_at >= Duration::hours(REPORTED_FOR_HOURS) {
            return None;
        }
        Some(json!({
            "count": current.count,
            "reason": current.reason.code(),
            "mac": current.mac,
            "first_at": current.first_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            "last_at": current.last_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        }))
    }
}

static NEST_SETUP_FAILURES: std::sync::LazyLock<SetupFailures> =
    std::sync::LazyLock::new(SetupFailures::default);

/// The Nest could not start the installer for the computer with `mac`.
pub fn record(reason: SetupFailure, mac: &str) {
    NEST_SETUP_FAILURES.record(reason, mac, Utc::now());
}

/// The Nest started the installer: what failed before is over.
pub fn clear() {
    NEST_SETUP_FAILURES.clear();
}

/// What the next boot report carries.
pub fn report() -> Option<Value> {
    NEST_SETUP_FAILURES.report(Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_are_counted_until_a_start_works_or_a_day_passes() {
        let failures = SetupFailures::default();
        let start = Utc::now();
        failures.record(SetupFailure::RuntimeUnavailable, "52:54:00:00:00:01", start);
        failures.record(
            SetupFailure::SessionUnavailable,
            "52:54:00:00:00:02",
            start + Duration::minutes(5),
        );
        let reported = failures.report(start + Duration::minutes(6)).unwrap();
        assert_eq!(reported["count"], 2);
        assert_eq!(reported["reason"], "session_unavailable");
        assert_eq!(reported["mac"], "52:54:00:00:00:02");
        assert_eq!(
            reported["first_at"],
            start.to_rfc3339_opts(SecondsFormat::Secs, true)
        );
        assert!(failures.report(start + Duration::hours(25)).is_none());
        failures.record(
            SetupFailure::ProfileUnavailable,
            "52:54:00:00:00:03",
            start + Duration::hours(26),
        );
        assert_eq!(
            failures.report(start + Duration::hours(26)).unwrap()["count"],
            1,
            "a failure a day later starts again"
        );
        failures.clear();
        assert!(failures.report(start + Duration::hours(26)).is_none());
    }
}
