//! Nest updates by store path.
//!
//! A release's closure archive is one zstd frame of raw 128 KiB blocks
//! (`tools/pack-system-closure.py`): its tar stream as it is, so every tar
//! byte sits at a fixed place in the archive. A Nest that runs an earlier
//! release lacks few of the new release's members (35 of 1149, 118 MiB of
//! 1.69 GiB from 0.2.181 to 0.2.182). It fetches the archive's metadata and
//! just those members' bytes with HTTP Range, checks each against its
//! NARInfo signed with the release key, and stages them as an archive-shaped
//! tar stream (`<attempt>.members.tar`): the metadata, then the payloads of
//! exactly the members the running system lacks. Root verifies that stream
//! in one pass (`closure::verify_staged`); the members it leaves out must be
//! in the running system with their signed NAR hash.
//!
//! The full archive stays the way for an archive packed another way (before
//! this layout), for an update where most members are new, and when the
//! server does not answer ranges or sends bytes that do not verify. A dropped
//! connection costs the member it was fetching; the next try continues.
//!
//! Each member has its fixed place in the staged stream, so a few are fetched
//! at once ([`AT_ONCE`]): every answer starts slowly (a redirect, a new
//! connection), and one member at a time left the line idle meanwhile.
use super::{
    closure::{self, Metadata, NarInfo, Present},
    release_v3::NixosRelease,
};
use anyhow::{Result, anyhow, bail, ensure};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io::Read,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
    time::Duration,
};

const FRAME: [u8; 6] = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38];
const BLOCK: u64 = 128 * 1024;
/// The first metadata request, and each further one when the manifest does
/// not say how far the metadata goes (2.2 MiB for 1149 members; the
/// manifest, 0.6 MiB of it, comes first).
const METADATA_STEP: u64 = 1024 * 1024;
/// Members or coalesced batches fetched at once.
const AT_ONCE: usize = 4;
/// Coalesce adjacent/nearby small wanted members into one Range request up to
/// this combined tar span and inter-member gap, eliminating hundreds of tiny
/// round trips while keeping unwanted gap transfer minimal.
const MAX_COALESCE_SPAN: u64 = 4 * 1024 * 1024;
const MAX_COALESCE_GAP: u64 = 64 * 1024;
const MAX_METADATA: u64 = 64 * 1024 * 1024;
const RESUMES: u32 = 8;
const RESUME_PAUSE: Duration = Duration::from_secs(5);

/// Where the tar stream of a raw-block archive of a given size sits in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub tar_bytes: u64,
}
impl Layout {
    /// The layout an archive of `archive_bytes` has if it is raw blocks.
    pub fn of(archive_bytes: u64) -> Option<Self> {
        let body = archive_bytes.checked_sub(FRAME.len() as u64)?;
        let blocks = body.div_ceil(BLOCK + 3);
        let tar_bytes = body.checked_sub(3 * blocks)?;
        (tar_bytes > 0 && tar_bytes.div_ceil(BLOCK) == blocks).then_some(Self { tar_bytes })
    }

    /// The archive offset of tar byte `tar`.
    fn offset(self, tar: u64) -> u64 {
        FRAME.len() as u64 + tar / BLOCK * (BLOCK + 3) + 3 + tar % BLOCK
    }

    fn block_header(self, index: u64) -> [u8; 3] {
        let size = (self.tar_bytes - index * BLOCK).min(BLOCK);
        let last = u64::from(index + 1 == self.tar_bytes.div_ceil(BLOCK));
        let value = ((size << 3) | last).to_le_bytes();
        [value[0], value[1], value[2]]
    }
}

/// The archive is not raw blocks (packed before this layout): take it whole.
#[derive(Debug, thiserror::Error)]
#[error("the closure archive is not stored in raw blocks")]
struct NotRawBlocks;

/// The connection kept dropping; the next try continues where this stopped.
#[derive(Debug, thiserror::Error)]
#[error("the update download kept dropping; the next try continues it: {0:#}")]
pub struct KeepTrying(anyhow::Error);

/// Archive bytes in, tar bytes `position..end` out: drops the frame header
/// (when the range starts at the archive's start) and each block header,
/// checking each is the raw block this layout has there.
struct Deblock {
    layout: Layout,
    position: u64,
    end: u64,
    expect: Vec<u8>,
    matched: usize,
}
impl Deblock {
    fn new(layout: Layout, position: u64, end: u64) -> Self {
        let expect = if position == 0 {
            [FRAME.as_slice(), &layout.block_header(0)].concat()
        } else if position % BLOCK == 0 {
            // The range starts at its block's header.
            layout.block_header(position / BLOCK).to_vec()
        } else {
            Vec::new()
        };
        Self {
            layout,
            position,
            end,
            expect,
            matched: 0,
        }
    }

    /// The archive bytes to ask for, inclusive.
    fn range(&self) -> (u64, u64) {
        let first = self.layout.offset(self.position) - self.expect.len() as u64;
        (first, self.layout.offset(self.end - 1))
    }

    fn push(&mut self, mut chunk: &[u8], out: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        while !chunk.is_empty() {
            if self.matched < self.expect.len() {
                let n = (self.expect.len() - self.matched).min(chunk.len());
                if chunk[..n] != self.expect[self.matched..self.matched + n] {
                    return Err(NotRawBlocks.into());
                }
                self.matched += n;
                chunk = &chunk[n..];
                continue;
            }
            ensure!(self.position < self.end, "the range answer is too long");
            let boundary = (self.position / BLOCK + 1) * BLOCK;
            let n = (boundary.min(self.end) - self.position).min(chunk.len() as u64) as usize;
            out(&chunk[..n])?;
            self.position += n as u64;
            chunk = &chunk[n..];
            if self.position == boundary && self.position < self.end {
                self.expect = self.layout.block_header(self.position / BLOCK).to_vec();
                self.matched = 0;
            }
        }
        Ok(())
    }
}

/// Where the archive is fetched from.
struct Source {
    url: String,
    allow_private: bool,
    layout: Layout,
    archive_bytes: u64,
    /// After a drop without new bytes, this long times the drops in a row.
    pause: Duration,
}

enum Transfer {
    /// The connection or the server failed: the bytes so far stand.
    Dropped(anyhow::Error),
    /// The server answered a range that does not start at the archive's
    /// start with the whole archive. A proxy does that now and then; a
    /// server that always does cannot serve members.
    Whole,
    /// The answer is not the archive's bytes: take the archive whole.
    Refused(anyhow::Error),
}

/// Whole-archive answers to a range taken as passing before giving up, each
/// after a longer pause: a Cloudflare edge answers its first range request
/// for a new file with the whole file and later ones with the range, and a
/// school's requests reach more than one edge (release 2 of 23 November
/// 2026 took the whole archive after three such answers).
const WHOLE_ANSWERS: u32 = 5;

impl Source {
    /// Fetch tar bytes `*got..end` through `out`, advancing `got`; after a
    /// drop, again from where it stopped.
    async fn fill(
        &self,
        got: &mut u64,
        end: u64,
        out: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
    ) -> Result<()> {
        let (mut drops, mut whole) = (0, 0);
        while *got < end {
            let before = *got;
            let error = match self.fetch(got, end, out).await {
                Ok(()) if *got == end => break,
                Ok(()) => anyhow!("the range answer ended early"),
                Err(Transfer::Dropped(error)) => error,
                Err(Transfer::Whole) if whole < WHOLE_ANSWERS => {
                    whole += 1;
                    tracing::info!(
                        whole,
                        "the server answered a range with the whole archive; asking again"
                    );
                    tokio::time::sleep(self.pause * whole).await;
                    continue;
                }
                Err(Transfer::Whole) => bail!("the server does not serve parts of the archive"),
                Err(Transfer::Refused(error)) => return Err(error),
            };
            drops = if *got > before { 1 } else { drops + 1 };
            if drops > RESUMES {
                return Err(KeepTrying(error).into());
            }
            tracing::warn!(error = %error, "closure member download dropped; resuming");
            tokio::time::sleep(self.pause * drops).await;
        }
        Ok(())
    }

    async fn fetch(
        &self,
        got: &mut u64,
        end: u64,
        out: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
    ) -> std::result::Result<(), Transfer> {
        use reqwest::{StatusCode, header};
        let refused = |message: &str| Transfer::Refused(anyhow!("closure range answer: {message}"));
        let mut deblock = Deblock::new(self.layout, *got, end);
        let (first, last) = deblock.range();
        let mut response = crate::release_transport::get_range(
            &self.url,
            self.allow_private,
            !self.allow_private,
            Duration::from_secs(60 * 60),
            first,
            last,
        )
        .await
        .map_err(Transfer::Dropped)?;
        let status = response.status();
        if status.is_server_error()
            || status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::TOO_MANY_REQUESTS
        {
            return Err(Transfer::Dropped(anyhow!(
                "closure range answered {status}"
            )));
        }
        // A range from the archive's start is the start of a whole answer:
        // read as far as the range goes.
        let whole = status == StatusCode::OK;
        if whole
            && (first != 0
                || response
                    .content_length()
                    .is_some_and(|length| length != self.archive_bytes))
        {
            return Err(Transfer::Whole);
        }
        let expected = format!("bytes {first}-{last}/{}", self.archive_bytes);
        if !whole
            && (status != StatusCode::PARTIAL_CONTENT
                || response
                    .headers()
                    .get(header::CONTENT_RANGE)
                    .and_then(|value| value.to_str().ok())
                    != Some(expected.as_str())
                || response
                    .content_length()
                    .is_some_and(|length| length != last - first + 1))
        {
            return Err(refused("the server does not serve this range"));
        }
        if response
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_some_and(|value| value != "identity")
        {
            return Err(refused("encoded body"));
        }
        let mut left = last - first + 1;
        while left > 0 {
            let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| Transfer::Dropped(error.into()))?
            else {
                break;
            };
            let chunk = &chunk[..chunk.len().min(usize::try_from(left).unwrap_or(usize::MAX))];
            left -= chunk.len() as u64;
            deblock
                .push(chunk, &mut |bytes| {
                    out(bytes)?;
                    *got += bytes.len() as u64;
                    Ok(())
                })
                .map_err(Transfer::Refused)?;
        }
        Ok(())
    }
}

/// The store paths of the running system with their NAR hashes. Its closure
/// stays rooted while an update runs.
pub fn running_system() -> Result<Present> {
    let output = crate::nix_command::std_command("nix")
        .args(["path-info", "--json", "--recursive", "/run/current-system"])
        .env("LC_ALL", "C")
        .output()?;
    ensure!(
        output.status.success(),
        "the running system's store paths are unknown"
    );
    present(&output.stdout)
}

pub async fn running_system_async() -> Result<Present> {
    store_paths_async(&["--recursive", "/run/current-system"]).await
}

/// Every valid path of this system's store with its NAR hash: on the setup
/// ISO, what the ISO itself carries.
pub async fn local_store_async() -> Result<Present> {
    store_paths_async(&["--all"]).await
}

async fn store_paths_async(selection: &[&str]) -> Result<Present> {
    let mut command = crate::nix_command::tokio_command("nix");
    command
        .args(["path-info", "--json"])
        .args(selection)
        .env("LC_ALL", "C");
    let output = crate::subprocess::run_bounded_command(
        command,
        Duration::from_secs(600),
        64 * 1024 * 1024,
        64 * 1024,
        "query the local store paths",
    )
    .await?;
    present(&output.stdout)
}

/// `nix path-info --json` in any of its shapes: an object by path (or by
/// store path base name) or a list of rows with `path`.
fn present(json: &[u8]) -> Result<Present> {
    let value: Value = serde_json::from_slice(json)?;
    let rows: Vec<(&str, &Value)> = match &value {
        Value::Object(rows) => rows
            .iter()
            .map(|(path, row)| (path.as_str(), row))
            .collect(),
        Value::Array(rows) => rows
            .iter()
            .map(|row| Ok((row["path"].as_str().ok_or_else(|| anyhow!("path"))?, row)))
            .collect::<Result<_>>()?,
        _ => bail!("unexpected nix path-info output"),
    };
    let mut present = Present::new();
    for (path, row) in rows {
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/nix/store/{path}")
        };
        let hash = row["narHash"]
            .as_str()
            .ok_or_else(|| anyhow!("store path without a NAR hash"))?;
        let hash = crate::cache::parse_strong_sha256(hash, "NarHash")?;
        present.insert(path, closure::nix_hash(&hash));
    }
    ensure!(!present.is_empty(), "the running system has no store paths");
    Ok(present)
}

/// The end of the metadata in `prefix`: the tar offset of the first
/// payload's header, once `prefix` reaches it. Only finds the place; the
/// metadata is verified when it is read.
fn metadata_end(prefix: &[u8]) -> Result<Option<usize>> {
    let mut at = 0usize;
    while let Some(raw) = prefix.get(at..at + 512) {
        let raw: &[u8; 512] = raw.try_into()?;
        ensure!(raw != &[0; 512], "the closure has no payload");
        let (name, length, _, _) = closure::header(raw)?;
        if name.starts_with("nar/") && name != "nar/" {
            return Ok(Some(at));
        }
        at = at
            .checked_add(512 + usize::try_from(length.div_ceil(512) * 512)?)
            .ok_or_else(|| anyhow!("closure metadata size overflow"))?;
    }
    Ok(None)
}

/// How much of the tar stream the metadata in `prefix` needs, through the
/// first payload's header: the manifest comes first and names every store
/// path, and each NARInfo is the export's (`nixos-appliance/export-cache.py`,
/// signed by `tools/pack-system-closure.py`) with its file size at most one
/// digit longer than the NAR size. Before the manifest is complete, its own
/// end. Only an estimate: the metadata is verified when it is read, and a
/// short estimate continues in steps.
fn metadata_want(prefix: &[u8]) -> Option<u64> {
    let raw: &[u8; 512] = prefix.get(..512)?.try_into().ok()?;
    let (name, length, _, _) = closure::header(raw).ok()?;
    if name != "manifest.json" {
        return None;
    }
    let padded = |bytes: u64| bytes.div_ceil(512) * 512;
    let manifest_end = 512 + length;
    let Some(manifest) = prefix.get(512..usize::try_from(manifest_end).ok()?) else {
        return Some(manifest_end);
    };
    let manifest: Value = serde_json::from_slice(manifest).ok()?;
    let line = |name: &str, value: usize| (name.len() + 2 + value + 1) as u64;
    let digits = |value: u64| value.to_string().len();
    // The manifest, then nix-cache-info (one block), the NARInfos, `nar/`.
    let mut end = 512 + padded(length) + 1024;
    for path in manifest["store_paths"].as_array()? {
        let (store_path, nar_hash) = (path["path"].as_str()?, path["nar_hash"].as_str()?);
        let nar_size = path["nar_size"].as_u64()?;
        let mut references = 0;
        for (index, reference) in path["references"].as_array()?.iter().enumerate() {
            let base = reference.as_str()?.len().checked_sub("/nix/store/".len())?;
            references += usize::from(index > 0) + base;
        }
        let body = line("StorePath", store_path.len())
            + line("URL", "nar/".len() + 32 + ".nar.zst".len())
            + line("Compression", "zstd".len())
            + line("FileHash", "sha256:".len() + 52)
            + line("FileSize", digits(nar_size) + 1)
            + line("NarHash", nar_hash.len())
            + line("NarSize", digits(nar_size))
            + line("References", references)
            + line("Sig", "tiaris-nest-appliance-1:".len() + 88);
        end += 512 + padded(body);
    }
    Some(end + 512 + 512)
}

/// The end of the next metadata request once `want` was not enough: as far
/// as the manifest says, else a step further. Never past the archive or
/// [`MAX_METADATA`]: the headers it goes by are not verified yet.
fn next_metadata_want(prefix: &[u8], want: u64, tar_bytes: u64) -> u64 {
    metadata_want(prefix)
        .filter(|next| *next > want)
        .unwrap_or(want + METADATA_STEP)
        .min(tar_bytes)
        .min(MAX_METADATA)
}

struct Wanted {
    name: String,
    /// The tar offset of its header.
    offset: u64,
}

/// What an update fetches: the archive's verified metadata and the members
/// the running system lacks.
pub struct Plan {
    source: Source,
    prefix: Vec<u8>,
    metadata: Metadata,
    wanted: Vec<Wanted>,
    /// The members it leaves out, each with its signed NAR hash.
    present: Present,
    partial: PathBuf,
    /// The staged stream's size once complete.
    pub bytes: u64,
}
impl Plan {
    /// The bytes still to download: an earlier try may have left part
    /// (counted as written, for the stream has holes where members were
    /// still coming).
    pub fn remaining_bytes(&self) -> u64 {
        let have = fs::symlink_metadata(&self.partial)
            .ok()
            .filter(|metadata| metadata.is_file())
            .map_or(0, |metadata| metadata.len().min(metadata.blocks() * 512));
        self.bytes.saturating_sub(have)
    }

    /// Where each wanted member's entry starts in the staged stream.
    fn slots(&self) -> Result<Vec<u64>> {
        let mut at = self.prefix.len() as u64;
        let mut slots = Vec::with_capacity(self.wanted.len());
        for wanted in &self.wanted {
            slots.push(at);
            at += 512 + self.info(wanted)?.file_size.div_ceil(512) * 512;
        }
        Ok(slots)
    }

    pub fn members(&self) -> usize {
        self.wanted.len()
    }

    /// The members the plan leaves out: the store holds each with its signed
    /// NAR hash.
    pub fn present(&self) -> &Present {
        &self.present
    }

    fn info(&self, wanted: &Wanted) -> Result<&NarInfo> {
        self.metadata
            .infos
            .get(&wanted.name)
            .ok_or_else(|| anyhow!("planned member without its NARInfo"))
    }
}

/// The partial staged stream of a release, named for its archive like the
/// archive's own partial download.
pub fn partial_path(inbox: &Path, release: &NixosRelease) -> PathBuf {
    inbox.join(format!("{}.members.part", release.system_closure.sha256))
}

/// Plan an update by store path for a Nest that holds `present`
/// ([`running_system_async`]), or `None` for the full archive. Errors are
/// [`KeepTrying`] or any other reason to take the full archive.
pub async fn plan(
    release: &NixosRelease,
    key: &VerifyingKey,
    url: &str,
    allow_private: bool,
    inbox: &Path,
    present: &Present,
) -> Result<Option<Plan>> {
    plan_from(release, key, url, allow_private, inbox, present, false).await
}

/// [`plan`] for an install into an empty store from `present`, another
/// store ([`local_store_async`] on the setup ISO): it leaves out only the
/// members whose every reference it leaves out too, so each left out member
/// can be copied over with its whole closure.
pub async fn plan_install(
    release: &NixosRelease,
    key: &VerifyingKey,
    url: &str,
    allow_private: bool,
    inbox: &Path,
    present: &Present,
) -> Result<Option<Plan>> {
    plan_from(release, key, url, allow_private, inbox, present, true).await
}

async fn plan_from(
    release: &NixosRelease,
    key: &VerifyingKey,
    url: &str,
    allow_private: bool,
    inbox: &Path,
    present: &Present,
    closed: bool,
) -> Result<Option<Plan>> {
    let archive_bytes = release.system_closure.size_bytes;
    let Some(layout) = Layout::of(archive_bytes) else {
        return Ok(None);
    };
    let source = Source {
        url: url.to_string(),
        allow_private,
        layout,
        archive_bytes,
        pause: RESUME_PAUSE,
    };
    let mut prefix = Vec::new();
    let mut want = METADATA_STEP.min(layout.tar_bytes);
    let end = loop {
        let mut got = prefix.len() as u64;
        match source
            .fill(&mut got, want, &mut |bytes| {
                prefix.extend_from_slice(bytes);
                Ok(())
            })
            .await
        {
            Err(error) if error.is::<NotRawBlocks>() => return Ok(None),
            result => result?,
        }
        if let Some(end) = metadata_end(&prefix)? {
            break end;
        }
        ensure!(
            want < layout.tar_bytes && want < MAX_METADATA,
            "the closure metadata is unbounded"
        );
        want = next_metadata_want(&prefix, want, layout.tar_bytes);
    };
    prefix.truncate(end);
    let metadata = closure::read_metadata(&prefix, release, key)?;
    let present = held(&metadata.manifest, present, closed);
    let mut offset = end as u64;
    let mut wanted = Vec::new();
    let mut bytes = offset + 1024;
    for (name, info) in &metadata.infos {
        let entry = 512 + info.file_size.div_ceil(512) * 512;
        if !present.contains_key(&info.entry.path) {
            wanted.push(Wanted {
                name: name.clone(),
                offset,
            });
            bytes += entry;
        }
        offset += entry;
    }
    ensure!(
        offset + 1024 <= layout.tar_bytes && layout.tar_bytes - offset - 1024 < 10240,
        "the closure's payloads do not fill its archive"
    );
    // Most members and most bytes new (a new NixOS): one request each would
    // cost more than the few bytes it saves; one stream of the whole
    // archive is cheaper. The setup ISO carries half the members, but 69 %
    // of the bytes.
    if wanted.len() * 2 > metadata.infos.len() && bytes * 2 > layout.tar_bytes {
        return Ok(None);
    }
    Ok(Some(Plan {
        source,
        prefix,
        metadata,
        wanted,
        present,
        partial: partial_path(inbox, release),
        bytes,
    }))
}

/// The closure's members `present` holds with their signed NAR hash; with
/// `closed`, only those whose references (the manifest's verified graph) it
/// keeps too.
fn held(manifest: &closure::ClosureManifest, present: &Present, closed: bool) -> Present {
    let mut held: Present = manifest
        .store_paths
        .iter()
        .filter(|path| present.get(&path.path) == Some(&path.nar_hash))
        .map(|path| (path.path.clone(), path.nar_hash.clone()))
        .collect();
    if !closed {
        return held;
    }
    loop {
        let open: Vec<String> = manifest
            .store_paths
            .iter()
            .filter(|path| {
                held.contains_key(&path.path)
                    && path
                        .references
                        .iter()
                        .any(|reference| !held.contains_key(reference))
            })
            .map(|path| path.path.clone())
            .collect();
        if open.is_empty() {
            break;
        }
        for path in open {
            held.remove(&path);
        }
    }
    held
}

/// Fetch what `plan` wants into its partial stream and complete it as
/// `target`, [`AT_ONCE`] batches at a time, each member into its own place.
/// Nearby small members are coalesced into bounded HTTP Range requests while
/// each member is still individually verified against its signed NARInfo.
pub async fn stage(plan: &Plan, target: &Path) -> Result<()> {
    stage_with_progress(plan, target, &|_, _| {}).await
}

/// [`stage`] with a progress callback `(received_bytes, total_bytes)`.
pub async fn stage_with_progress(
    plan: &Plan,
    target: &Path,
    on_progress: &(dyn Fn(u64, u64) + Send + Sync),
) -> Result<()> {
    let partial = &plan.partial;
    let file = open_partial(partial)?;
    let slots = plan.slots()?;
    let done = resume(&file, plan, &slots)?;
    let mut initial = plan.prefix.len() as u64;
    let mut pending = Vec::new();
    for ((wanted, &at), is_done) in plan.wanted.iter().zip(&slots).zip(&done) {
        let info = plan.info(wanted)?;
        let padded = 512 + info.file_size.div_ceil(512) * 512;
        if *is_done {
            initial = initial.saturating_add(padded);
        } else {
            pending.push(BatchItem {
                wanted,
                slot: at,
                file_size: info.file_size,
            });
        }
    }
    let progress = AtomicU64::new(initial.min(plan.bytes));
    on_progress(progress.load(Ordering::Relaxed), plan.bytes);
    let batches = coalesce_batches(pending);
    let fetches: Vec<Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>> = batches
        .into_iter()
        .map(|batch| {
            Box::pin(fetch_batch(plan, &file, batch, &progress, on_progress))
                as Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>
        })
        .collect();
    let mut keep_trying = None;
    // A member that does not verify, or a server that does not serve
    // ranges, ends this way: no further batch starts.
    let ends = |result: &Result<()>| {
        result
            .as_ref()
            .is_err_and(|error| !error.is::<KeepTrying>())
    };
    for result in at_most(AT_ONCE, fetches, ends).await {
        match result {
            Ok(()) => {}
            // What verified stays; the next try fetches the rest.
            Err(error) if error.is::<KeepTrying>() => keep_trying = Some(error),
            Err(error) => return Err(error),
        }
    }
    if let Some(error) = keep_trying {
        return Err(error);
    }
    file.write_all_at(&[0; 1024], plan.bytes - 1024)?;
    file.set_len(plan.bytes)?;
    file.sync_all()?;
    ensure!(
        file.metadata()?.len() == plan.bytes,
        "the staged update has an unexpected size"
    );
    on_progress(plan.bytes, plan.bytes);
    fs::rename(partial, target)?;
    super::sync_directory(target.parent().ok_or_else(|| anyhow!("inbox"))?)?;
    Ok(())
}

struct BatchItem<'a> {
    wanted: &'a Wanted,
    slot: u64,
    file_size: u64,
}

impl BatchItem<'_> {
    fn tar_start(&self) -> u64 {
        self.wanted.offset
    }

    fn tar_end(&self) -> u64 {
        self.wanted.offset + 512 + self.file_size
    }
}

struct Batch<'a> {
    items: Vec<BatchItem<'a>>,
    tar_start: u64,
    tar_end: u64,
}

fn coalesce_batches(items: Vec<BatchItem<'_>>) -> Vec<Batch<'_>> {
    let mut batches: Vec<Batch<'_>> = Vec::new();
    for item in items {
        let start = item.tar_start();
        let end = item.tar_end();
        if let Some(current) = batches.last_mut() {
            let gap = start.saturating_sub(current.tar_end);
            let combined_span = end.saturating_sub(current.tar_start);
            if start >= current.tar_end
                && gap <= MAX_COALESCE_GAP
                && combined_span <= MAX_COALESCE_SPAN
            {
                current.tar_end = end;
                current.items.push(item);
                continue;
            }
        }
        batches.push(Batch {
            items: vec![item],
            tar_start: start,
            tar_end: end,
        });
    }
    batches
}

/// Fetch one member or coalesced batch into each member's slot and verify every member.
async fn fetch_batch(
    plan: &Plan,
    file: &File,
    batch: Batch<'_>,
    progress: &AtomicU64,
    on_progress: &(dyn Fn(u64, u64) + Send + Sync),
) -> Result<()> {
    let mut got = batch.tar_start;
    let mut written_tar_pos = batch.tar_start;
    plan.source
        .fill(&mut got, batch.tar_end, &mut |bytes| {
            let chunk_start = written_tar_pos;
            let chunk_end = chunk_start + bytes.len() as u64;
            let mut written_for_progress = 0u64;
            for item in &batch.items {
                let item_start = item.tar_start();
                let item_end = item.tar_end();
                if item_end <= chunk_start || item_start >= chunk_end {
                    continue;
                }
                let copy_start = chunk_start.max(item_start);
                let copy_end = chunk_end.min(item_end);
                let src_from = (copy_start - chunk_start) as usize;
                let src_to = (copy_end - chunk_start) as usize;
                let dst_offset = item.slot + (copy_start - item_start);
                file.write_all_at(&bytes[src_from..src_to], dst_offset)?;
                written_for_progress += copy_end - copy_start;
            }
            written_tar_pos = chunk_end;
            if written_for_progress > 0 {
                let total_received = progress
                    .fetch_add(written_for_progress, Ordering::Relaxed)
                    .saturating_add(written_for_progress)
                    .min(plan.bytes);
                on_progress(total_received, plan.bytes);
            }
            Ok(())
        })
        .await?;
    for item in &batch.items {
        verify_entry(file, item.slot, item.wanted, plan)?;
        let padding = item.file_size.div_ceil(512) * 512 - item.file_size;
        if padding > 0 {
            file.write_all_at(&vec![0; padding as usize], item.slot + 512 + item.file_size)?;
            let total_received = progress
                .fetch_add(padding, Ordering::Relaxed)
                .saturating_add(padding)
                .min(plan.bytes);
            on_progress(total_received, plan.bytes);
        }
    }
    Ok(())
}

/// Run `tasks` on this task, at most `limit` at once; their results in
/// their order. Once a result `ends` it, no further task starts and those
/// still running are dropped: only the finished ones' results come back.
async fn at_most<'a, T>(
    limit: usize,
    tasks: Vec<Pin<Box<dyn Future<Output = T> + Send + 'a>>>,
    ends: impl Fn(&T) -> bool,
) -> Vec<T> {
    let mut results: Vec<Option<T>> = tasks.iter().map(|_| None).collect();
    let mut waiting = tasks.into_iter().enumerate();
    let mut running = Vec::new();
    let mut ended = false;
    std::future::poll_fn(|context| {
        loop {
            while running.len() < limit {
                let Some(task) = waiting.next() else { break };
                running.push(task);
            }
            if running.is_empty() {
                return Poll::Ready(());
            }
            let before = running.len();
            running.retain_mut(|(index, task)| match task.as_mut().poll(context) {
                Poll::Ready(result) => {
                    ended |= ends(&result);
                    results[*index] = Some(result);
                    false
                }
                Poll::Pending => true,
            });
            if ended {
                running.clear();
                return Poll::Ready(());
            }
            if running.len() == before {
                return Poll::Pending;
            }
        }
    })
    .await;
    results.into_iter().flatten().collect()
}

/// Written only at explicit places, never in append mode: on Linux a write
/// at a place in a file opened to append lands at its end instead, so
/// members fetched at once ended up in the order they arrived.
fn open_partial(partial: &Path) -> Result<File> {
    let open = || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(partial)
    };
    let file = open()?;
    let metadata = file.metadata()?;
    if metadata.is_file()
        && metadata.nlink() == 1
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o777 == 0o600
    {
        return Ok(file);
    }
    fs::remove_file(partial)?;
    Ok(open()?)
}

/// Keep what an earlier try staged: the same metadata, then each member in
/// its place that still verifies. Returns which members are there.
fn resume(file: &File, plan: &Plan, slots: &[u64]) -> Result<Vec<bool>> {
    let length = file.metadata()?.len();
    let mut found = vec![0; plan.prefix.len().min(length as usize)];
    file.read_exact_at(&mut found, 0)?;
    if found != plan.prefix {
        file.set_len(0)?;
        file.write_all_at(&plan.prefix, 0)?;
        return Ok(vec![false; plan.wanted.len()]);
    }
    plan.wanted
        .iter()
        .zip(slots)
        .map(|(wanted, at)| {
            let entry = 512 + plan.info(wanted)?.file_size.div_ceil(512) * 512;
            Ok(length >= at + entry && verify_entry(file, *at, wanted, plan).is_ok())
        })
        .collect()
}

/// Reads `file` from `position` on, without its shared offset: members are
/// read and written at once.
struct At<'a> {
    file: &'a File,
    position: u64,
}
impl Read for At<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.file.read_at(buffer, self.position)?;
        self.position += read as u64;
        Ok(read)
    }
}

/// The entry at `at` is `wanted`'s: its header, then its payload as its
/// signed NARInfo says.
fn verify_entry(file: &File, at: u64, wanted: &Wanted, plan: &Plan) -> Result<()> {
    let info = plan.info(wanted)?;
    let mut raw = [0; 512];
    file.read_exact_at(&mut raw, at)?;
    let (name, length, directory, _) = closure::header(&raw)?;
    ensure!(
        name == wanted.name && length == info.file_size && !directory,
        "the fetched member is not the one asked for"
    );
    let payload = At {
        file,
        position: at + 512,
    };
    plan.metadata
        .verify_payload(info, payload.take(length), None)
        .map_err(|error| error.context("a fetched closure member does not verify"))
}

/// Root opens the daemon's staged stream once: an ordinary file of at most
/// the archive's tar size, read in one pass that verifies what it copies.
pub fn open_staged(path: &Path, release: &NixosRelease) -> Result<(File, u64)> {
    let layout = Layout::of(release.system_closure.size_bytes)
        .ok_or_else(|| anyhow!("the release has no per-member layout"))?;
    // Not blocking: a FIFO in its place must not hold root.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= layout.tar_bytes,
        "the staged update is unsafe"
    );
    Ok((file, layout.tar_bytes))
}

#[cfg(test)]
#[path = "members_tests.rs"]
mod tests;
