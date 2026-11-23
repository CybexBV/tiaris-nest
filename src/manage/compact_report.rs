//! Compact reports to a Manage that says `compact_report_supported`.
//!
//! Manage acknowledges what it holds in its report answer: the complete cache
//! inventory at one identity (`cache_inventory_acknowledged`) and terminal
//! build results that sending again would not change (`build_jobs_settled`).
//! Until that changes, the Nest leaves it out:
//!
//! - With the acknowledged inventory unchanged, the cache lane goes empty at
//!   that identity: Manage keeps every artifact present through its
//!   inventory lease and renews the replicas bound to it.
//! - When the inventory changed, each artifact Manage acknowledged unchanged
//!   goes without its closure manifest (well over a megabyte each), so the
//!   whole inventory fits one report and completes at once.
//! - Settled build results stay out until the job changes, so the next report
//!   carries the new results of running installs and rollouts first.
//!
//! The inventory generation advances on every local write to the cache table,
//! also when the integrity check only records that it verified an artifact.
//! The Nest reports the generation at which what it reports (each artifact's
//! id and last change) last changed, for every Manage: a check alone neither
//! restarts a traversal nor withdraws an acknowledgement.
//!
//! When Manage does not hold what a compact entry names
//! (`cache_evidence_required`), or does not acknowledge an empty cache lane (a
//! restored database, rows it removed itself), the Nest forgets the
//! acknowledgement and starts its inventory again with every closure manifest.
use super::{ManagedState, NestAgentReportRequest, NestReportResponse, nest_build_job_is_terminal};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// What the report sees of one artifact: its local id and when its reported
/// content last changed.
pub(super) type InventoryMember = (i64, String);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CacheInventoryContent {
    pub(super) instance_id: String,
    pub(super) generation: i64,
    pub(super) members: Vec<InventoryMember>,
}

/// The generation to report for this inventory: the one at which its members
/// were first seen. Records the content when it is new.
pub(super) fn content_generation(
    managed: &mut ManagedState,
    instance_id: &str,
    local_generation: i64,
    members: Vec<InventoryMember>,
) -> i64 {
    // A generation below what this Nest (or a release before it) last
    // reported would be refused as stale: start again from the local one.
    let reported_floor = (managed.nest_cache_report_instance_id.as_deref() == Some(instance_id))
        .then_some(managed.nest_cache_report_generation)
        .flatten()
        .unwrap_or(i64::MIN);
    if let Some(content) = &managed.nest_cache_content {
        if content.instance_id == instance_id
            && content.members == members
            && content.generation <= local_generation
            && content.generation >= reported_floor
        {
            return content.generation;
        }
    }
    managed.nest_cache_content = Some(CacheInventoryContent {
        instance_id: instance_id.to_string(),
        generation: local_generation,
        members,
    });
    local_generation
}

/// Manage acknowledged exactly the inventory this Nest holds now.
pub(super) fn inventory_acknowledged(managed: &ManagedState) -> bool {
    managed.nest_cache_content.is_some()
        && managed.nest_cache_acknowledged == managed.nest_cache_content
}

/// Artifacts whose closure evidence Manage acknowledged, as `(id, updated_at)`.
pub(super) fn acknowledged_members(
    managed: &ManagedState,
    instance_id: &str,
) -> Vec<InventoryMember> {
    managed
        .nest_cache_acknowledged
        .as_ref()
        .filter(|acknowledged| acknowledged.instance_id == instance_id)
        .map(|acknowledged| acknowledged.members.clone())
        .unwrap_or_default()
}

/// Terminal build jobs Manage settled, as `(id, updated_at)`.
pub(super) fn settled_build_jobs(managed: &ManagedState) -> Vec<InventoryMember> {
    managed
        .nest_build_jobs_settled
        .iter()
        .map(|(id, updated_at)| (*id, updated_at.clone()))
        .collect()
}

/// A Manage that no longer says it supports compact reports gets everything.
pub(super) fn forget(managed: &mut ManagedState) {
    managed.nest_cache_acknowledged = None;
    managed.nest_build_jobs_settled.clear();
}

/// Moves the closure manifest digest of an acknowledged artifact (its
/// manifest already left out of the page) to the entry, so Manage checks it
/// still holds that exact manifest.
pub(super) fn compact_entry(cache_metadata: &mut Value, acknowledged: bool) -> Option<String> {
    if !acknowledged || cache_metadata.get("closure_manifest").is_some() {
        return None;
    }
    let digest = cache_metadata
        .as_object_mut()?
        .remove("closure_manifest_sha256")?;
    digest.as_str().map(str::to_string)
}

/// Records what Manage acknowledged in its answer to `body`.
pub(super) fn record(
    managed: &mut ManagedState,
    body: &NestAgentReportRequest,
    compact_refresh: bool,
    response: &NestReportResponse,
) {
    let acknowledged = response
        .cache_inventory_acknowledged
        .as_ref()
        .and_then(|value| serde_json::from_value::<Acknowledgement>(value.clone()).ok())
        .is_some_and(|ack| {
            ack.instance_id == body.cache_inventory_instance_id
                && ack.generation == body.cache_inventory_generation
        });
    let evidence_required = response.cache_evidence_required.as_ref() == Some(&Value::Bool(true));
    let content = managed.nest_cache_content.clone().filter(|content| {
        content.instance_id == body.cache_inventory_instance_id
            && content.generation == body.cache_inventory_generation
    });
    match content {
        _ if evidence_required => {
            managed.nest_cache_acknowledged = None;
            managed.nest_cache_artifact_report_cursor = None;
        }
        Some(content) if acknowledged => managed.nest_cache_acknowledged = Some(content),
        _ if compact_refresh => managed.nest_cache_acknowledged = None,
        _ => {}
    }
    let settled: BTreeSet<&str> = response
        .build_jobs_settled
        .as_ref()
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for job in &body.build_jobs {
        if nest_build_job_is_terminal(job)
            && job
                .managed_job_id
                .as_deref()
                .is_some_and(|id| settled.contains(id))
        {
            managed
                .nest_build_jobs_settled
                .insert(job.local_id, job.updated_at.clone());
        }
    }
}

#[derive(Deserialize)]
struct Acknowledgement {
    instance_id: String,
    generation: i64,
}

#[cfg(test)]
mod tests {
    use super::super::{
        NestBuildJobReport,
        tests::{sample_build_job, sample_nest_report},
    };
    use super::*;
    use serde_json::json;

    fn members(ids: &[i64]) -> Vec<InventoryMember> {
        ids.iter()
            .map(|id| (*id, format!("2026-11-23T10:00:0{id}Z")))
            .collect()
    }

    #[test]
    fn the_integrity_check_alone_never_changes_the_reported_generation() {
        let mut managed = ManagedState::default();
        assert_eq!(
            content_generation(&mut managed, "inst", 10, members(&[1, 2])),
            10
        );
        // The check marked artifacts verified: the local generation moved,
        // nothing the report says did.
        assert_eq!(
            content_generation(&mut managed, "inst", 14, members(&[1, 2])),
            10
        );
        // A new artifact, a removed one or a changed one is new content.
        assert_eq!(
            content_generation(&mut managed, "inst", 15, members(&[1, 2, 3])),
            15
        );
        assert_eq!(
            content_generation(&mut managed, "inst", 16, members(&[2, 3])),
            16
        );
        let changed = vec![(2, "later".to_string()), (3, members(&[3])[0].1.clone())];
        assert_eq!(content_generation(&mut managed, "inst", 17, changed), 17);
        // Another local database starts again.
        assert_eq!(
            content_generation(&mut managed, "other", 3, members(&[1])),
            3
        );
    }

    #[test]
    fn the_reported_generation_never_falls_below_what_was_reported_before() {
        // An older release reported the local generation and did not keep
        // this record: never go back below it, or Manage refuses the report.
        let mut managed = ManagedState::default();
        content_generation(&mut managed, "inst", 10, members(&[1]));
        managed.nest_cache_report_instance_id = Some("inst".into());
        managed.nest_cache_report_generation = Some(12);
        assert_eq!(
            content_generation(&mut managed, "inst", 12, members(&[1])),
            12
        );
    }

    fn body(
        generation: i64,
        complete: bool,
        jobs: Vec<NestBuildJobReport>,
    ) -> NestAgentReportRequest {
        let mut body = sample_nest_report(jobs);
        body.cache_inventory_instance_id = "inst".into();
        body.cache_inventory_generation = generation;
        body.cache_artifacts_complete = complete;
        body
    }

    fn response(value: Value) -> NestReportResponse {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn an_acknowledgement_is_kept_only_for_the_inventory_it_names() {
        let mut managed = ManagedState::default();
        content_generation(&mut managed, "inst", 10, members(&[1]));
        let ack = |generation| {
            response(json!({"status": "ok", "cache_inventory_acknowledged":
                {"instance_id": "inst", "generation": generation}}))
        };
        // An acknowledgement of another generation is not this inventory's.
        record(&mut managed, &body(10, true, vec![]), false, &ack(9));
        assert!(!inventory_acknowledged(&managed));
        record(&mut managed, &body(10, true, vec![]), false, &ack(10));
        assert!(inventory_acknowledged(&managed));
        assert_eq!(acknowledged_members(&managed, "inst"), members(&[1]));
        // A page Manage does not acknowledge (a traversal not yet complete,
        // an artifact it refused) withdraws nothing.
        let unacknowledged = response(json!({"status": "ok"}));
        record(
            &mut managed,
            &body(10, true, vec![]),
            false,
            &unacknowledged,
        );
        assert!(inventory_acknowledged(&managed));
        // An empty cache lane Manage does not acknowledge (its database was
        // restored) sends every manifest again.
        record(
            &mut managed,
            &body(10, false, vec![]),
            true,
            &unacknowledged,
        );
        assert!(!inventory_acknowledged(&managed));
        assert!(acknowledged_members(&managed, "inst").is_empty());
        // So does a compact entry for evidence Manage does not hold, from the
        // start of the inventory.
        record(&mut managed, &body(10, true, vec![]), false, &ack(10));
        managed.nest_cache_artifact_report_cursor = Some(4);
        let missing = response(json!({"status": "ok", "cache_evidence_required": true}));
        record(&mut managed, &body(10, false, vec![]), false, &missing);
        assert!(acknowledged_members(&managed, "inst").is_empty());
        assert_eq!(managed.nest_cache_artifact_report_cursor, None);
    }

    #[test]
    fn only_terminal_results_manage_settled_stay_out() {
        let mut managed = ManagedState::default();
        let job = |local_id: i64, status: &str| {
            let mut job = NestBuildJobReport::from(sample_build_job(""));
            job.local_id = local_id;
            job.managed_job_id = Some(format!("job-{local_id}"));
            job.status = status.to_string();
            job.updated_at = format!("t{local_id}");
            job
        };
        let jobs = vec![job(1, "succeeded"), job(2, "running"), job(3, "failed")];
        let answer = response(json!({"status": "ok", "build_jobs_settled": ["job-1", "job-2"]}));
        record(&mut managed, &body(1, false, jobs), false, &answer);
        assert_eq!(settled_build_jobs(&managed), vec![(1, "t1".to_string())]);
        forget(&mut managed);
        assert!(settled_build_jobs(&managed).is_empty());
    }

    #[test]
    fn an_acknowledged_entry_carries_its_manifest_digest_instead_of_the_manifest() {
        let mut stripped = json!({"closure_manifest_sha256": "abc", "cache": "exported"});
        assert_eq!(compact_entry(&mut stripped, true).as_deref(), Some("abc"));
        assert_eq!(stripped, json!({"cache": "exported"}));
        // Not acknowledged, or still with its manifest: sent as it is.
        let mut full = json!({"closure_manifest": {}, "closure_manifest_sha256": "abc"});
        assert_eq!(compact_entry(&mut full, true), None);
        assert_eq!(compact_entry(&mut full, false), None);
        assert!(full.get("closure_manifest_sha256").is_some());
    }
}
