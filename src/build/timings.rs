//! How long each stage of a Nest build took.
//!
//! A finished build reports its stages under [`KEY`] in its result metadata,
//! which Manage keeps as sent, and logs them. Durations are whole
//! milliseconds; byte counts say how much of the closure manifest was read.
//!
//! - `preparing_ms`: from the claim to the start of `nix build` (spec,
//!   capacity and daemon checks).
//! - `nix_build_ms`: the whole `nix build`; `evaluation_ms` is its part
//!   before Nix began realising paths, when Nix reported that.
//! - `inspection_ms`: output hash and closure size; `inventory_ms`: the
//!   package versions.
//! - `export_copy_ms` (or `replica_copy_ms`) and `manifest_ms`: copying the
//!   closure into the cache and checking it, with `manifest_hashed_bytes` of
//!   `closure_file_bytes` read again.
//! - `publish_ms`: recording the cache artifact; `total_ms`: claim to end.
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::cache::ExportTimings;

pub(super) const KEY: &str = "stage_timings";
const SCHEMA: &str = "tiaris.nest.build-stage-timings.v1";

#[derive(Debug)]
pub(super) struct StageTimings {
    started: Instant,
    stage_started: Instant,
    values: Map<String, Value>,
}

impl StageTimings {
    pub(super) fn start() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            stage_started: now,
            values: Map::new(),
        }
    }

    /// Ends the running stage as `name` and starts the next one.
    pub(super) fn finish(&mut self, name: &str) {
        let now = Instant::now();
        self.record(name, now.saturating_duration_since(self.stage_started));
        self.stage_started = now;
    }

    /// Ends `nix build`, started when the previous stage finished.
    pub(super) fn finish_nix_build(&mut self, realisation_started_at: Option<Instant>) {
        if let Some(realising) = realisation_started_at {
            self.record(
                "evaluation",
                realising.saturating_duration_since(self.stage_started),
            );
        }
        self.finish("nix_build");
    }

    /// Records a cache export or replica copy, which ends the running stage.
    pub(super) fn finish_export(&mut self, copy: &str, export: &ExportTimings) {
        self.record(copy, export.copy);
        self.record("manifest", export.manifest);
        self.values.insert(
            "manifest_hashed_bytes".into(),
            json!(export.hashed_file_size_bytes),
        );
        self.values.insert(
            "closure_file_bytes".into(),
            json!(export.total_file_size_bytes),
        );
        self.stage_started = Instant::now();
    }

    fn record(&mut self, name: &str, duration: Duration) {
        let milliseconds = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        self.values
            .insert(format!("{name}_ms"), Value::from(milliseconds));
    }

    /// The stages so far and the total, for the result metadata and the log.
    pub(super) fn report(&self) -> Value {
        let mut values = self.values.clone();
        values.insert("schema".into(), json!(SCHEMA));
        let total = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        values.insert("total_ms".into(), json!(total));
        Value::Object(values)
    }

    /// Adds the report to `metadata` and logs it.
    pub(super) fn attach(&self, metadata: &mut Value, job_id: i64, status: &str) {
        let report = self.report();
        tracing::info!(job_id, status, stage_timings = %report, "Nest build stage timings");
        if let Some(object) = metadata.as_object_mut() {
            object.insert(KEY.into(), report);
        }
    }
}
