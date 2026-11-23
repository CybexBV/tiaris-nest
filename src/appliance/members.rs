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
use super::{
    closure::{self, Metadata, NarInfo, Present},
    release_v3::NixosRelease,
};
use anyhow::{Result, anyhow, bail, ensure};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

const FRAME: [u8; 6] = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38];
const BLOCK: u64 = 128 * 1024;
/// The metadata is fetched in steps (2.2 MiB for 1149 members).
const METADATA_STEP: u64 = 4 * 1024 * 1024;
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
    /// The server answered with the whole archive. A proxy does that now
    /// and then (Cloudflare before development, once); a server that
    /// always does cannot serve members.
    Whole,
    /// The answer is not the archive's bytes: take the archive whole.
    Refused(anyhow::Error),
}

/// Whole-archive answers to a range taken as passing before giving up.
const WHOLE_ANSWERS: u32 = 2;

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
        if status == StatusCode::OK {
            return Err(Transfer::Whole);
        }
        let expected = format!("bytes {first}-{last}/{}", self.archive_bytes);
        if status != StatusCode::PARTIAL_CONTENT
            || response
                .headers()
                .get(header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                != Some(expected.as_str())
            || response
                .content_length()
                .is_some_and(|length| length != last - first + 1)
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
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| Transfer::Dropped(error.into()))?
        {
            deblock
                .push(&chunk, &mut |bytes| {
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
    let mut command = crate::nix_command::tokio_command("nix");
    command
        .args(["path-info", "--json", "--recursive", "/run/current-system"])
        .env("LC_ALL", "C");
    let output = crate::subprocess::run_bounded_command(
        command,
        Duration::from_secs(600),
        64 * 1024 * 1024,
        64 * 1024,
        "query the running system's store paths",
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
    partial: PathBuf,
    /// The staged stream's size once complete.
    pub bytes: u64,
}
impl Plan {
    /// The bytes still to download: an earlier try may have left part.
    pub fn remaining_bytes(&self) -> u64 {
        let have = fs::symlink_metadata(&self.partial)
            .ok()
            .filter(|metadata| metadata.is_file())
            .map_or(0, |metadata| metadata.len());
        self.bytes.saturating_sub(have)
    }

    pub fn members(&self) -> usize {
        self.wanted.len()
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
    let end = loop {
        let mut got = prefix.len() as u64;
        let want = (got + METADATA_STEP).min(layout.tar_bytes);
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
    };
    prefix.truncate(end);
    let metadata = closure::read_metadata(&prefix, release, key)?;
    let mut offset = end as u64;
    let mut wanted = Vec::new();
    let mut bytes = offset + 1024;
    for (name, info) in &metadata.infos {
        let entry = 512 + info.file_size.div_ceil(512) * 512;
        if present.get(&info.entry.path) != Some(&info.entry.nar_hash) {
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
    // Most members new (a new NixOS): one request each would cost more than
    // the few bytes it saves; one stream of the whole archive is cheaper.
    if wanted.len() * 2 > metadata.infos.len() {
        return Ok(None);
    }
    Ok(Some(Plan {
        source,
        prefix,
        metadata,
        wanted,
        partial: partial_path(inbox, release),
        bytes,
    }))
}

/// Fetch what `plan` wants into its partial stream and complete it as
/// `target`. Each member is checked against its signed NARInfo once its
/// bytes are there; a member that does not verify ends this way (take the
/// full archive). Errors are [`KeepTrying`] or such a reason.
pub async fn stage(plan: &Plan, target: &Path) -> Result<()> {
    let partial = &plan.partial;
    let mut file = open_partial(partial)?;
    let (mut position, resumed) = resume(&mut file, plan)?;
    for wanted in &plan.wanted[resumed..] {
        let info = plan.info(wanted)?;
        let start = position;
        let end = wanted.offset + 512 + info.file_size;
        let mut got = wanted.offset;
        let fetched = plan
            .source
            .fill(&mut got, end, &mut |bytes| Ok(file.write_all(bytes)?))
            .await;
        let checked = fetched.and_then(|()| verify_entry(&file, start, wanted, plan));
        if let Err(error) = checked {
            // A drop keeps what verified before this member; the next try
            // continues from there.
            file.set_len(start)?;
            return Err(error);
        }
        let padding = info.file_size.div_ceil(512) * 512 - info.file_size;
        file.write_all(&vec![0; padding as usize])?;
        position = start + 512 + info.file_size + padding;
    }
    file.write_all(&[0; 1024])?;
    file.sync_all()?;
    ensure!(
        file.metadata()?.len() == plan.bytes,
        "the staged update has an unexpected size"
    );
    fs::rename(partial, target)?;
    super::sync_directory(target.parent().ok_or_else(|| anyhow!("inbox"))?)?;
    Ok(())
}

fn open_partial(partial: &Path) -> Result<File> {
    let open = || {
        OpenOptions::new()
            .read(true)
            .append(true)
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

/// Keep what an earlier try staged: the same metadata, then each complete
/// entry that still verifies. Returns where the stream continues and the
/// first member it still lacks.
fn resume(file: &mut File, plan: &Plan) -> Result<(u64, usize)> {
    let length = file.metadata()?.len();
    let mut found = vec![0; plan.prefix.len().min(length as usize)];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut found)?;
    if found != plan.prefix {
        file.set_len(0)?;
        file.write_all(&plan.prefix)?;
        return Ok((plan.prefix.len() as u64, 0));
    }
    let mut position = plan.prefix.len() as u64;
    let mut next = 0;
    for wanted in &plan.wanted {
        let size = plan.info(wanted)?.file_size;
        let entry = 512 + size.div_ceil(512) * 512;
        if length < position + entry || verify_entry(file, position, wanted, plan).is_err() {
            break;
        }
        position += entry;
        next += 1;
    }
    file.set_len(position)?;
    Ok((position, next))
}

/// The entry at `at` is `wanted`'s: its header, then its payload as its
/// signed NARInfo says.
fn verify_entry(file: &File, at: u64, wanted: &Wanted, plan: &Plan) -> Result<()> {
    let info = plan.info(wanted)?;
    let mut reader = file;
    reader.seek(SeekFrom::Start(at))?;
    let mut raw = [0; 512];
    reader.read_exact(&mut raw)?;
    let (name, length, directory, _) = closure::header(&raw)?;
    ensure!(
        name == wanted.name && length == info.file_size && !directory,
        "the fetched member is not the one asked for"
    );
    plan.metadata
        .verify_payload(info, reader.take(length), None)
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
