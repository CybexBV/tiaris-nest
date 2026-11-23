//! The setup ISO starts before network time has set its clock.
//!
//! It used to wait up to a minute for NTP (`systemd-time-wait-sync`; 30
//! seconds in the install journey of 21 November 2026). A server's own clock
//! is nearly always right, and the first HTTPS request to Tiaris checks
//! Tiaris's certificate against it. While network time has not set the clock
//! yet, the `Date` of Tiaris's answers over that verified connection sets it,
//! so signed requests (Tiaris accepts five minutes) and the envelope's window
//! hold even where a school blocks NTP. A clock too far off for the
//! certificate gets no answer at all: then only network time sets it, as
//! before. An unauthenticated time never sets the clock.

use chrono::{DateTime, Utc};
use reqwest::header::HeaderValue;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tracing::{info, warn};

/// Closer than this the clock is left alone: `Date` counts whole seconds and
/// the answer took a moment to arrive.
const TOLERANCE_SECONDS: i64 = 5;

static FOLLOW_MANAGE: AtomicBool = AtomicBool::new(false);

/// Lets this process set the clock from Tiaris's answers: only the setup
/// ISO's bootstrap, which runs as root before network time.
pub(super) fn follow_manage() {
    FOLLOW_MANAGE.store(true, Ordering::Relaxed);
}

/// The time to set the clock to: Tiaris's, when network time has not set
/// the clock and it is off.
pub(super) fn correction(
    own: DateTime<Utc>,
    manage: DateTime<Utc>,
    network_time_set: bool,
) -> Option<DateTime<Utc>> {
    (!network_time_set && (manage - own).num_seconds().abs() > TOLERANCE_SECONDS).then_some(manage)
}

/// Takes the clock from one HTTPS answer of Tiaris that took `travel`.
pub(super) fn observe(date: Option<&HeaderValue>, travel: Duration) {
    if !FOLLOW_MANAGE.load(Ordering::Relaxed) {
        return;
    }
    let Some(date) = date
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 40)
        .and_then(|value| DateTime::parse_from_rfc2822(value).ok())
    else {
        return;
    };
    // Tiaris read its clock about halfway through the request.
    let manage =
        date.with_timezone(&Utc) + chrono::Duration::from_std(travel / 2).unwrap_or_default();
    let own = Utc::now();
    let Some(time) = correction(own, manage, !crate::site_check::clock_not_synchronized()) else {
        return;
    };
    match set_system_clock(time) {
        Ok(()) => info!(
            moved_seconds = (time - own).num_seconds(),
            "set the clock from Tiaris's answer; network time has not set it yet"
        ),
        Err(error) => warn!(%error, "could not set the clock from Tiaris's answer"),
    }
}

fn set_system_clock(time: DateTime<Utc>) -> std::io::Result<()> {
    let time = libc::timespec {
        tv_sec: time.timestamp() as libc::time_t,
        tv_nsec: time.timestamp_subsec_nanos() as libc::c_long,
    };
    // SAFETY: `time` is a valid timespec that outlives the call.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_clock_network_time_has_not_set_follows_tiaris() {
        let own = DateTime::parse_from_rfc3339("2026-11-23T08:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let manage = own + chrono::Duration::minutes(7);
        assert_eq!(correction(own, manage, false), Some(manage));
        // Network time is the authority once it has set the clock.
        assert_eq!(correction(own, manage, true), None);
        // Whole-second `Date` and the request's travel are no reason to move.
        let close = own + chrono::Duration::seconds(TOLERANCE_SECONDS);
        assert_eq!(correction(own, close, false), None);
    }
}
