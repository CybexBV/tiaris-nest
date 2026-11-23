//! Hashes of cached NAR files, remembered while the file stays unchanged.
//!
//! A closure manifest checks each member's compressed bytes against the
//! FileHash of its signed NARInfo. Closures share nearly all of their
//! members (about 2,000 files, 4–6 GB per workstation closure), so hashing
//! every member for every export and for every root's daily check read the
//! same bytes many times a day. A member hashed within [`MAX_AGE`] is not
//! read again while its file keeps the same device, inode, size and
//! modification and change times. Once that day has passed it is hashed
//! again, so every member's bytes are still checked at least daily.
//!
//! The record only ever confirms the expected FileHash: a mismatch is always
//! decided by reading the file again. It lives in memory, so after a restart
//! each member is hashed once more.
//!
//! Linux advances file times in clock ticks. A write in the same tick as a
//! hash could keep the times that hash was remembered with, so a file whose
//! change time is less than [`SETTLE`] before its hash started is not
//! remembered (as Git treats "racily clean" index entries).
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::MetadataExt,
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime},
};

/// How long a member's hash is reused: the cadence of the cache scrub.
pub(crate) const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const SETTLE: Duration = Duration::from_secs(2);
/// Far above the members of a full cache; reached only by churn.
const MAX_ENTRIES: usize = 1 << 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileVersion {
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileVersion {
    fn of(metadata: &fs::Metadata) -> (FileIdentity, Self) {
        (
            FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            Self {
                size: metadata.len(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            },
        )
    }

    fn changed_at(&self) -> Option<SystemTime> {
        let (seconds, nanos) = self.changed;
        let seconds = u64::try_from(seconds).ok()?;
        let nanos = u32::try_from(nanos).ok()?;
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(seconds, nanos))
    }
}

struct Entry {
    version: FileVersion,
    sha256: [u8; 32],
    /// Wall-clock time, as the scrub's due times: a clock step can never
    /// make a root due while its member hashes still count as fresh.
    hashed_at: SystemTime,
}

impl Entry {
    fn current(&self, max_age: Duration) -> bool {
        SystemTime::now()
            .duration_since(self.hashed_at)
            .is_ok_and(|age| age < max_age)
    }
}

pub(crate) struct MemberHashes {
    entries: Mutex<HashMap<FileIdentity, Entry>>,
    max_age: Duration,
    settle: Duration,
}

impl MemberHashes {
    pub(crate) fn global() -> &'static Self {
        static GLOBAL: OnceLock<MemberHashes> = OnceLock::new();
        GLOBAL.get_or_init(|| Self::new(MAX_AGE, SETTLE))
    }

    pub(crate) fn new(max_age: Duration, settle: Duration) -> Self {
        Self {
            entries: Mutex::default(),
            max_age,
            settle,
        }
    }

    /// When the open file described by `metadata` was hashed to `sha256`,
    /// if that was within the maximum age and the file has not changed since.
    pub(crate) fn confirmed(
        &self,
        metadata: &fs::Metadata,
        sha256: &[u8; 32],
    ) -> Option<SystemTime> {
        let (identity, version) = FileVersion::of(metadata);
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.get(&identity)?;
        (entry.version == version && &entry.sha256 == sha256 && entry.current(self.max_age))
            .then_some(entry.hashed_at)
    }

    /// Remember the hash of a file read from `started`, given its metadata
    /// before and after the read. A file that changed during the read, or
    /// so shortly before it that a later write could keep its times, is
    /// forgotten instead.
    pub(crate) fn remember(
        &self,
        before: &fs::Metadata,
        after: &fs::Metadata,
        sha256: [u8; 32],
        started: SystemTime,
    ) {
        let (identity, version) = FileVersion::of(before);
        let settled = version
            .changed_at()
            .and_then(|changed| changed.checked_add(self.settle))
            .is_some_and(|settled| settled <= started)
            && FileVersion::of(after) == (identity, version);
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if !settled {
            entries.remove(&identity);
            return;
        }
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&identity) {
            let max_age = self.max_age;
            entries.retain(|_, entry| entry.current(max_age));
            if entries.len() >= MAX_ENTRIES {
                entries.clear();
            }
        }
        entries.insert(
            identity,
            Entry {
                version,
                sha256,
                hashed_at: started,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_member(name: &str) -> (std::path::PathBuf, fs::Metadata) {
        let dir = std::env::temp_dir().join(format!(
            "tiaris-nest-member-hashes-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("member.nar");
        fs::write(&path, b"member").unwrap();
        let metadata = fs::File::open(&path).unwrap().metadata().unwrap();
        (dir, metadata)
    }

    #[test]
    fn only_a_current_hash_of_the_same_bytes_is_confirmed() {
        let (dir, metadata) = fresh_member("confirm");
        let hash = [7; 32];
        let hashes = MemberHashes::new(MAX_AGE, Duration::ZERO);
        hashes.remember(&metadata, &metadata, hash, SystemTime::now());
        assert!(hashes.confirmed(&metadata, &hash).is_some());
        assert!(hashes.confirmed(&metadata, &[8; 32]).is_none());

        let expired = MemberHashes::new(Duration::ZERO, Duration::ZERO);
        expired.remember(&metadata, &metadata, hash, SystemTime::now());
        assert!(expired.confirmed(&metadata, &hash).is_none());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_file_changed_just_before_its_hash_is_not_remembered() {
        let (dir, metadata) = fresh_member("settle");
        let hash = [7; 32];
        let changed = FileVersion::of(&metadata).1.changed_at().unwrap();
        let hashes = MemberHashes::new(MAX_AGE, SETTLE);
        hashes.remember(&metadata, &metadata, hash, changed + SETTLE / 2);
        assert!(hashes.confirmed(&metadata, &hash).is_none());
        hashes.remember(&metadata, &metadata, hash, changed + SETTLE);
        assert!(hashes.confirmed(&metadata, &hash).is_some());
        fs::remove_dir_all(dir).ok();
    }
}
