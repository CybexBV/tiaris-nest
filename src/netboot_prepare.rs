//! The workstation runtime of the appliance release this Nest is updating
//! to, prepared before the restart (`workstation_netboot_prepare`, sent by
//! Tiaris only together with that `appliance_update`).
//!
//! It is downloaded, hashed, extracted and checked like any runtime and kept
//! as a verified bundle, but never made active here: Tiaris selects it only
//! after the Nest reports that release, and `reconcile_desired` then finds it
//! verified and promotes it at once instead of downloading 1.3 GB after the
//! restart. A Nest that rolls back is never told to use it; retention removes
//! it like any unused bundle. The runtime in use, the progress the Nest
//! reports for it and the anti-rollback watermarks stay as they are.
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Deserialize;
use tokio::sync::watch;
use tracing::{info, warn};

use super::{
    COMPATIBILITY_EPOCH, RuntimeReconcileRequest, WorkstationNetbootDescriptor,
    default_compatibility_epoch, enforce_watermark, import_bundle_reporting,
    queue_runtime_reconciliation, safe_failure_kind, safe_failure_message, sha256_bytes, transport,
    validate_compatibility_epoch,
};
use crate::AppState;

#[derive(Clone, Debug, Deserialize)]
pub struct PreparedWorkstationNetboot {
    pub appliance_release: String,
    #[serde(default = "default_compatibility_epoch")]
    pub compatibility_epoch: u32,
    pub descriptor: WorkstationNetbootDescriptor,
    #[serde(default)]
    pub bundle_transport_url: Option<String>,
}

/// The longest an appliance update waits for its runtime. It then goes ahead
/// and the Nest fetches the runtime after the restart, as it always did.
const WAIT_LIMIT: Duration = Duration::from_secs(30 * 60);
/// A runtime that failed to prepare is tried again on a later sync, not on
/// every one: the appliance update does not wait for it meanwhile.
const RETRY_AFTER: Duration = Duration::from_secs(10 * 60);

/// The appliance release whose runtime is being prepared, and whether that
/// ended (prepared or failed).
static PREPARING: LazyLock<watch::Sender<Option<(String, bool)>>> =
    LazyLock::new(|| watch::channel(None).0);
/// The bundle that last failed to prepare, and when.
static FAILED: Mutex<Option<(String, Instant)>> = Mutex::new(None);

/// Prepare the runtime Tiaris sent with the appliance update to
/// `update_release`; one for another release is never prepared.
pub fn queue(state: &AppState, value: serde_json::Value, update_release: &str) {
    let prepare = match serde_json::from_value::<PreparedWorkstationNetboot>(value) {
        Ok(prepare) if prepare.appliance_release == update_release => prepare,
        Ok(_) => return,
        Err(error) => {
            warn!(error = %error, "ignored an unreadable workstation runtime to prepare");
            return;
        }
    };
    let failed_recently = FAILED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .is_some_and(|(bundle, at)| {
            *bundle == prepare.descriptor.sha256 && at.elapsed() < RETRY_AFTER
        });
    if failed_recently {
        return;
    }
    let preparing = Some((prepare.appliance_release.clone(), false));
    PREPARING.send_if_modified(|current| {
        let changed = *current != preparing;
        *current = preparing;
        changed
    });
    queue_runtime_reconciliation(RuntimeReconcileRequest::Prepare {
        state: state.clone(),
        prepare: Box::new(prepare),
    });
}

/// Wait until the runtime of `appliance_release` is prepared or failed, at
/// most `WAIT_LIMIT`; at once when none is being prepared for it.
pub async fn wait(appliance_release: &str) {
    let mut preparing = PREPARING.subscribe();
    let ended = preparing.wait_for(
        |current| !matches!(current, Some((release, false)) if release == appliance_release),
    );
    if tokio::time::timeout(WAIT_LIMIT, ended).await.is_err() {
        warn!(
            appliance_release,
            "the appliance update goes ahead before its workstation runtime is prepared"
        );
    }
}

/// Run by the runtime worker, after the runtime in use.
pub(super) async fn run(state: &AppState, prepare: &PreparedWorkstationNetboot) {
    match prepare_bundle(state, prepare).await {
        Ok(true) => info!(
            appliance_release = %prepare.appliance_release,
            runtime_version = %prepare.descriptor.runtime_version,
            "prepared the workstation runtime of the coming appliance release"
        ),
        Ok(false) => {}
        Err(error) => {
            warn!(
                appliance_release = %prepare.appliance_release,
                failure_kind = safe_failure_kind(&error),
                safe_detail = %safe_failure_message(&error),
                "could not prepare the workstation runtime of the coming appliance release; the Nest fetches it after the restart"
            );
            *FAILED
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some((prepare.descriptor.sha256.clone(), Instant::now()));
        }
    }
    PREPARING.send_if_modified(|current| match current {
        Some((release, done)) if *release == prepare.appliance_release && !*done => {
            *done = true;
            true
        }
        _ => false,
    });
}

/// Whether the bundle was imported now. The same checks as for the desired
/// runtime, except the packaged Tiaris source: the coming appliance release
/// brings that, and `reconcile_desired` checks it after the restart.
async fn prepare_bundle(state: &AppState, prepare: &PreparedWorkstationNetboot) -> Result<bool> {
    validate_compatibility_epoch(prepare.compatibility_epoch)?;
    transport::validate_signed(
        &prepare.descriptor,
        prepare.bundle_transport_url.as_deref(),
        &state.config.update.trusted_public_key,
        state.config.workstation_netboot.allow_private_release_urls,
    )?;
    // One this Nest would refuse after the restart is not worth the bytes.
    let descriptor_sha256 = sha256_bytes(serde_json::to_string(&prepare.descriptor)?.as_bytes());
    enforce_watermark(
        state,
        &prepare.descriptor,
        &descriptor_sha256,
        prepare.compatibility_epoch,
    )
    .await?;
    let verified: Option<(String,)> = sqlx::query_as(
        "SELECT bundle_sha256 FROM workstation_netboot_bundles
         WHERE bundle_sha256 = ? AND compatibility_epoch = ? AND retention_state = 'verified'",
    )
    .bind(&prepare.descriptor.sha256)
    .bind(COMPATIBILITY_EPOCH)
    .fetch_optional(&state.db)
    .await?;
    // During maintenance the update is already being installed.
    if verified.is_some() || crate::maintenance::lease_active()? {
        return Ok(false);
    }
    import_bundle_reporting(
        state,
        &prepare.descriptor,
        prepare.compatibility_epoch,
        prepare.bundle_transport_url.as_deref(),
        false,
    )
    .await
}
