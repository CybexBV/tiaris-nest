//! While an administrator reviews a claimed Nest, the ISO downloads the
//! signed closure its setup will install into RAM, so approval starts from a
//! finished or partly finished download instead of from nothing.
//!
//! Tiaris offers the release the session pinned at the claim
//! (`closure_offer`), the one its approved plan carries too. The download
//! writes only the RAM staging of `nixos_install`, under the same memory limit
//! as the install itself: nothing touches the disk before approval. The
//! archive is hashed while it downloads and verified once, after approval
//! (`nixos_install::stage_closure`).
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::{SignedInstallPlan, nixos_install, setup_status::SetupStatusReporter};
use crate::appliance::{closure::AuthenticatedArchive, nixos, release_v3::ReleaseDescriptor};

#[derive(Deserialize)]
struct ClosureOffer {
    appliance_release: ReleaseDescriptor,
    package_transport_url: String,
}

struct Download {
    closure_sha256: String,
    /// Bytes received and the signed total, shown once the plan is approved.
    progress: Arc<(AtomicU64, AtomicU64)>,
    task: JoinHandle<Result<AuthenticatedArchive>>,
}

pub(super) struct ClosurePrefetch {
    key_path: PathBuf,
    /// The release this setup installs (its envelope's).
    release_version: String,
    offered: bool,
    download: Option<Download>,
}

impl ClosurePrefetch {
    pub(super) fn new(key_path: &Path, release_version: &str) -> Self {
        Self {
            key_path: key_path.to_path_buf(),
            release_version: release_version.to_string(),
            offered: false,
            download: None,
        }
    }

    /// Start downloading the first offer; later ones change nothing.
    pub(super) fn offer(&mut self, offer: Option<&Value>) {
        let Some(offer) = offer.filter(|_| !self.offered) else {
            return;
        };
        self.offered = true;
        match self.start(offer) {
            Ok(download) => self.download = download,
            Err(error) => warn!(
                error = %error,
                "the closure is downloaded after approval: it cannot be downloaded ahead"
            ),
        }
    }

    fn start(&self, offer: &Value) -> Result<Option<Download>> {
        let offer: ClosureOffer = serde_json::from_value(offer.clone())?;
        let release = offer.appliance_release.nixos()?.clone();
        ensure!(
            release.release_id == self.release_version,
            "the offered release is not the one this setup installs"
        );
        release.verify_file(&self.key_path)?;
        let transport = offer.package_transport_url;
        nixos_install::validate_closure_transport(&transport, &release.system_closure)?;
        let available = nixos_install::ram_staging()?;
        if nixos_install::archive_staged() {
            return Ok(None);
        }
        nixos_install::ensure_ram_budget(&release, available)?;
        info!(release = %release.release_id, "downloading the closure while the setup waits for approval");
        let progress = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
        let shown = progress.clone();
        let closure_sha256 = release.system_closure.sha256.clone();
        let task = tokio::spawn(async move {
            nixos::download_with_progress(
                &release,
                &transport,
                Path::new(nixos_install::ARCHIVE),
                transport != release.system_closure.url,
                &mut |received, total| {
                    shown.0.store(received, Ordering::Relaxed);
                    shown.1.store(total, Ordering::Relaxed);
                },
            )
            .await
        });
        Ok(Some(Download {
            closure_sha256,
            progress,
            task,
        }))
    }

    /// Before the approved `plan` stages its closure. A download of its
    /// archive finishes first, its progress shown as the plan's, and is
    /// handed over hashed; a failed one leaves its bytes for `stage_closure`
    /// to continue. A download of another archive stops: its partial file is
    /// another file, which `stage_closure` removes.
    pub(super) async fn hand_over(
        &mut self,
        plan: &SignedInstallPlan,
        status: &SetupStatusReporter,
    ) -> Option<AuthenticatedArchive> {
        let mut download = self.download.take()?;
        let approved = plan
            .appliance_release
            .as_ref()
            .and_then(|release| release.nixos().ok())
            .is_some_and(|release| release.system_closure.sha256 == download.closure_sha256);
        if !approved {
            download.task.abort();
            return None;
        }
        let mut shown = tokio::time::interval(Duration::from_millis(500));
        let finished = loop {
            tokio::select! {
                finished = &mut download.task => break finished,
                _ = shown.tick() => {
                    let total = download.progress.1.load(Ordering::Relaxed);
                    if total > 0 {
                        status.download_progress(download.progress.0.load(Ordering::Relaxed), total);
                    }
                }
            }
        };
        match finished {
            Ok(Ok(archive)) => Some(archive),
            Ok(Err(error)) => {
                warn!(error = %error, "the closure downloaded ahead is continued after approval");
                None
            }
            Err(error) => {
                warn!(error = %error, "the closure download ahead stopped");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provisioning::protocol::tests::signed_plan_fixture;

    fn download(closure_sha256: &str, task: JoinHandle<Result<AuthenticatedArchive>>) -> Download {
        Download {
            closure_sha256: closure_sha256.to_string(),
            progress: Arc::new((AtomicU64::new(0), AtomicU64::new(0))),
            task,
        }
    }

    /// Never two writers on one partial file: approval waits for the
    /// download of its own archive and stops one of another archive.
    #[tokio::test(start_paused = true)]
    async fn approval_waits_for_its_own_download_and_stops_another() {
        let plan: SignedInstallPlan = serde_json::from_value(signed_plan_fixture().0).unwrap();
        let approved = plan.appliance_release.as_ref().unwrap().nixos().unwrap();
        let approved = approved.system_closure.sha256.clone();
        let status = SetupStatusReporter::new(None);
        let mut prefetch = ClosurePrefetch::new(Path::new("/nonexistent"), "1.2.3");

        let other = tokio::spawn(std::future::pending::<Result<AuthenticatedArchive>>());
        let stopped = other.abort_handle();
        prefetch.download = Some(download(&"0".repeat(64), other));
        assert!(prefetch.hand_over(&plan, &status).await.is_none());
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(stopped.is_finished());

        let (finish, finished) = tokio::sync::oneshot::channel::<()>();
        let own = tokio::spawn(async move {
            finished.await.ok();
            Err(anyhow::anyhow!("the connection dropped"))
        });
        prefetch.download = Some(download(&approved, own));
        let hand_over = prefetch.hand_over(&plan, &status);
        tokio::pin!(hand_over);
        assert!(
            tokio::time::timeout(Duration::from_secs(3600), &mut hand_over)
                .await
                .is_err(),
            "approval stages nothing while its download runs"
        );
        finish.send(()).unwrap();
        // A failed download leaves its bytes for `stage_closure` to continue.
        assert!(hand_over.await.is_none());
    }
}
