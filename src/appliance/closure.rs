//! Bounded offline closure verification. No extraction, import, or disk mutation
//! is needed to authenticate the full archive and every inner NAR.
//!
//! An archive is read twice at most, and verified once:
//! - its one SHA-256 pass is taken where the bytes arrive
//!   ([`AuthenticatedArchive`]): while they are downloaded, while root pins
//!   its private copy, or when an archive found on disk is opened;
//! - its one verification pass ([`verify_archive`]) checks the manifest,
//!   every NARInfo signature and every NAR, and extracts the binary cache
//!   when it is given somewhere to put it (an update);
//! - setup verifies before it touches the disk and extracts onto the disk
//!   later ([`VerifiedArchive::extract`]), copying the payloads it verified.
use super::release_v3::{NixosRelease, canonical_base64, store_path, strict_json};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Seek, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// The parser's bound on the expanded tar stream. It is not a size estimate:
/// space admission uses the archive's own sizes ([`VerifiedArchive::cache_bytes`]).
pub const MAX_EXPANDED: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_NAR_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_MEMBERS: usize = 65536;
const MAX_MANIFEST: u64 = 16 * 1024 * 1024;
const MAX_NARINFO: u64 = 1024 * 1024;
const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorePath {
    pub path: String,
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: Vec<String>,
    pub narinfo: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManageSource {
    pub revision: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub store_path: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureManifest {
    pub schema: String,
    pub release_id: String,
    pub base_os: String,
    pub base_os_version: String,
    pub source_revision: String,
    pub manage_source_revision: String,
    pub nixpkgs_revision: String,
    pub system_toplevel: String,
    pub required_system_versions: BTreeMap<String, String>,
    pub sqlite_migrations_sha256: String,
    pub nix_signing_public_key: String,
    pub manage_source: ManageSource,
    pub microcode_versions: BTreeMap<String, String>,
    pub store_paths: Vec<StorePath>,
    pub total_nar_bytes: u64,
}
impl ClosureManifest {
    fn validate(&self, release: &NixosRelease, key: &VerifyingKey) -> Result<()> {
        ensure!(
            self.schema == "tiaris.nest.system-closure.v1",
            "closure manifest schema"
        );
        ensure!(
            self.release_id == release.release_id
                && self.base_os == release.base_os
                && self.base_os_version == release.base_os_version
                && self.source_revision == release.source_revision
                && self.manage_source_revision == release.manage_source_revision
                && self.nixpkgs_revision == release.nixpkgs_revision
                && self.system_toplevel == release.system_toplevel
                && self.required_system_versions == release.required_system_versions
                && self.sqlite_migrations_sha256 == release.sqlite_migrations_sha256,
            "closure manifest does not match signed descriptor"
        );
        ensure!(
            self.nix_signing_public_key
                == format!(
                    "tiaris-nest-appliance-1:{}",
                    STANDARD.encode(key.as_bytes())
                ),
            "archive Nix key differs from independently trusted key"
        );
        ensure!(
            self.manage_source.revision == release.manage_source_revision
                && self.manage_source.size_bytes > 0,
            "Tiaris source identity mismatch"
        );
        super::release_v3::require_hex(&self.manage_source.sha256, 64)?;
        let (source_root, _) = source_location(&self.manage_source)?;
        ensure!(
            self.microcode_versions
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                == ["amd", "intel"]
                && self
                    .microcode_versions
                    .values()
                    .all(|v| super::release_v3::safe_token(v, 256)),
            "microcode package identities"
        );
        ensure!(
            !self.store_paths.is_empty() && self.store_paths.len() < MAX_MEMBERS / 2,
            "invalid store path count"
        );
        let mut previous = "";
        let mut total = 0u64;
        let mut all = BTreeSet::new();
        for path in &self.store_paths {
            let name = store_path(&path.path)?;
            ensure!(
                path.path.as_str() > previous,
                "store paths must be unique and sorted"
            );
            previous = &path.path;
            ensure!(
                path.narinfo == format!("{}.narinfo", &name[..32]),
                "NARInfo basename mismatch"
            );
            require_nix_hash(&path.nar_hash)?;
            ensure!(path.nar_size > 0, "zero NAR size");
            total = total
                .checked_add(path.nar_size)
                .ok_or_else(|| anyhow!("NAR size overflow"))?;
            ensure!(total <= MAX_NAR_BYTES, "closure NAR size limit");
            let mut prev = "";
            for reference in &path.references {
                store_path(reference)?;
                ensure!(
                    reference.as_str() > prev,
                    "references must be sorted and unique"
                );
                prev = reference;
            }
            all.insert(path.path.as_str());
        }
        ensure!(total == self.total_nar_bytes, "total NAR size mismatch");
        ensure!(
            all.contains(self.system_toplevel.as_str()) && all.contains(source_root),
            "closure missing toplevel/source"
        );
        let paths: BTreeMap<_, _> = self
            .store_paths
            .iter()
            .map(|p| (p.path.as_str(), p))
            .collect();
        let mut reachable = BTreeSet::new();
        let mut pending = vec![self.system_toplevel.as_str()];
        while let Some(path) = pending.pop() {
            if !reachable.insert(path) {
                continue;
            }
            let entry = paths
                .get(path)
                .ok_or_else(|| anyhow!("incomplete closure reference graph"))?;
            pending.extend(entry.references.iter().map(String::as_str));
        }
        ensure!(
            reachable == all,
            "closure contains paths outside exact toplevel graph"
        );
        Ok(())
    }
}

fn source_location(source: &ManageSource) -> Result<(&str, &str)> {
    store_path(&source.store_path)?;
    Ok((&source.store_path, ""))
}

pub(super) struct NarInfo {
    pub(super) entry: StorePath,
    file_hash: String,
    pub(super) file_size: u64,
}
fn narinfo(body: &[u8], entry: &StorePath, key: &VerifyingKey) -> Result<(String, NarInfo)> {
    let text = std::str::from_utf8(body)?;
    ensure!(
        text.ends_with('\n') && !text.contains('\r'),
        "NARInfo line encoding"
    );
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("malformed NARInfo field"))?;
        let value = value
            .strip_prefix(' ')
            .ok_or_else(|| anyhow!("NARInfo separator"))?;
        ensure!(
            matches!(
                name,
                "StorePath"
                    | "URL"
                    | "Compression"
                    | "FileHash"
                    | "FileSize"
                    | "NarHash"
                    | "NarSize"
                    | "References"
                    | "Sig"
                    | "Deriver"
            ),
            "unknown NARInfo field"
        );
        ensure!(
            fields.insert(name, value).is_none(),
            "duplicate NARInfo field"
        );
    }
    let field = |name| {
        fields
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("missing NARInfo {name}"))
    };
    ensure!(
        field("StorePath")? == entry.path
            && field("NarHash")? == entry.nar_hash
            && field("Compression")? == "zstd",
        "NARInfo identity mismatch"
    );
    ensure!(
        decimal(field("NarSize")?)? == entry.nar_size,
        "NARInfo NAR size mismatch"
    );
    let references = entry
        .references
        .iter()
        .map(|v| store_path(v))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    ensure!(
        field("References")? == references,
        "NARInfo references mismatch"
    );
    let url = field("URL")?;
    ensure!(valid_nar_name(url), "unsafe NAR payload URL");
    let file_hash = field("FileHash")?.to_string();
    require_nix_hash(&file_hash)?;
    let file_size = decimal(field("FileSize")?)?;
    ensure!(
        file_size > 0 && file_size <= super::release_v3::MAX_ARCHIVE_BYTES,
        "compressed NAR size limit"
    );
    let sig = field("Sig")?
        .strip_prefix("tiaris-nest-appliance-1:")
        .ok_or_else(|| anyhow!("NARInfo signer is untrusted"))?;
    let sig: [u8; 64] = canonical_base64(sig, 64)?
        .try_into()
        .map_err(|_| anyhow!("NARInfo signature length"))?;
    let fingerprint = format!(
        "1;{};{};{};{}",
        entry.path,
        entry.nar_hash,
        entry.nar_size,
        entry.references.join(",")
    );
    key.verify_strict(fingerprint.as_bytes(), &Signature::from_bytes(&sig))
        .context("untrusted NARInfo signature")?;
    Ok((
        url.to_owned(),
        NarInfo {
            entry: entry.clone(),
            file_hash,
            file_size,
        },
    ))
}
fn decimal(text: &str) -> Result<u64> {
    let v: u64 = text.parse()?;
    ensure!(v.to_string() == text, "noncanonical decimal");
    Ok(v)
}
fn valid_nar_name(name: &str) -> bool {
    name.strip_prefix("nar/").is_some_and(|n| {
        n.ends_with(".nar.zst") && super::release_v3::safe_token(n, 255) && !n.starts_with('.')
    })
}
fn require_nix_hash(hash: &str) -> Result<()> {
    let h = hash
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("unsupported Nix hash"))?;
    ensure!(
        h.len() == 52 && h.bytes().all(|b| NIX32.contains(&b)) && h.as_bytes()[0] <= b'1',
        "noncanonical Nix SHA-256"
    );
    Ok(())
}
pub fn nix_hash(bytes: &[u8]) -> String {
    let mut out = String::from("sha256:");
    for n in (0..bytes.len().saturating_mul(8).div_ceil(5)).rev() {
        let bit = n * 5;
        let i = bit / 8;
        let j = bit % 8;
        let mut v = (bytes[i] as u16) >> j;
        if i + 1 < bytes.len() {
            v |= (bytes[i + 1] as u16) << (8 - j)
        }
        out.push(NIX32[(v & 31) as usize] as char);
    }
    out
}

struct Counting<R> {
    inner: R,
    bytes: u64,
    limit: u64,
    /// Only where a signed hash is compared; the tar stream itself is
    /// authenticated by the archive's hash.
    hash: Option<Sha256>,
}
impl<R: Read> Read for Counting<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(out)?;
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("stream size overflow"))?;
        if self.bytes > self.limit {
            return Err(io::Error::other("stream exceeded verified limit"));
        }
        if let Some(hash) = &mut self.hash {
            hash.update(&out[..n]);
        }
        Ok(n)
    }
}
impl<R> Counting<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            bytes: 0,
            limit,
            hash: Some(Sha256::new()),
        }
    }
    fn unhashed(inner: R, limit: u64) -> Self {
        Self {
            hash: None,
            ..Self::new(inner, limit)
        }
    }
    fn digest(&mut self) -> String {
        nix_hash(&self.hash.take().unwrap_or_default().finalize())
    }
}

/// What identifies the open archive file between its hash and its reads.
#[derive(Debug, PartialEq, Eq)]
struct FileState {
    device: u64,
    inode: u64,
    len: u64,
    modified: (i64, i64),
}
impl FileState {
    fn of(file: &File) -> Result<Self> {
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.nlink() == 1,
            "archive is not one ordinary file"
        );
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
            len: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
        })
    }
}

/// An open closure archive whose bytes are exactly the signed size and
/// SHA-256. This is the archive's one hash pass, taken where the bytes
/// arrive: while they are downloaded (`nixos::download_with_progress`),
/// while root pins its private copy (`appliance::pin_untrusted_bundle`), or
/// by [`Self::open`] for an archive found on disk. Only its owner can write
/// where it lives, and every later read is of this same open file, refused
/// once the file changed.
#[derive(Debug)]
pub struct AuthenticatedArchive {
    file: File,
    sha256: String,
    state: FileState,
}
impl AuthenticatedArchive {
    /// The signed archive this is.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Hash an archive found on disk, for example one an earlier run left.
    pub fn open(path: &Path, release: &NixosRelease) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        ensure!(
            FileState::of(&file)?.len == release.system_closure.size_bytes,
            "archive is not the exact ordinary signed file"
        );
        let mut hash = Sha256::new();
        let size = io::copy(
            &mut (&file).take(release.system_closure.size_bytes + 1),
            &mut hash,
        )?;
        Self::hashed(file, hash, size, release)
    }

    /// `hash` and `size` cover every byte of `file`, taken as the caller
    /// wrote or copied them.
    pub(crate) fn hashed(
        file: File,
        hash: Sha256,
        size: u64,
        release: &NixosRelease,
    ) -> Result<Self> {
        let sha256 = hex::encode(hash.finalize());
        ensure!(
            size == release.system_closure.size_bytes && sha256 == release.system_closure.sha256,
            "archive signed size/hash mismatch"
        );
        let state = FileState::of(&file)?;
        ensure!(state.len == size, "archive changed while it was hashed");
        Ok(Self {
            file,
            sha256,
            state,
        })
    }

    fn unchanged(&self) -> Result<()> {
        ensure!(
            FileState::of(&self.file)? == self.state,
            "archive changed during verification"
        );
        Ok(())
    }
}

/// An archive that passed [`verify_archive`], still open.
#[derive(Debug)]
pub struct VerifiedArchive {
    archive: AuthenticatedArchive,
    pub manifest: ClosureManifest,
    /// The bytes its binary cache takes once extracted (its files).
    pub cache_bytes: u64,
}
impl VerifiedArchive {
    /// The signed archive this is.
    pub fn sha256(&self) -> &str {
        &self.archive.sha256
    }

    /// Extract the binary cache of an archive verified without extracting:
    /// setup verifies before it touches the disk and extracts onto the disk
    /// later. This reads the same open file, unchanged since its
    /// verification, and checks its structure, manifest and NARInfo
    /// signatures as that pass did. Each NAR payload is copied at its signed
    /// size, not decompressed and hashed again: that pass did so for these
    /// bytes, and Nix checks every NAR against its signed NARInfo when it
    /// imports it.
    pub fn extract(
        &mut self,
        release: &NixosRelease,
        key: &VerifyingKey,
        output: &Path,
    ) -> Result<()> {
        let (manifest, cache_bytes) = walk(
            &mut self.archive,
            release,
            key,
            Some(output),
            Payloads::Copy,
            &mut |_, _| Ok(()),
        )?;
        ensure!(
            cache_bytes == self.cache_bytes
                && manifest.total_nar_bytes == self.manifest.total_nar_bytes,
            "archive differs from its verification"
        );
        Ok(())
    }
}

/// The archive's one verification pass: the manifest against the signed
/// descriptor, every NARInfo's signature, every NAR's compressed and
/// uncompressed size and hash, the embedded Tiaris source and the exact
/// reference graph. With `output`, it extracts the binary cache as it goes
/// into a new private directory.
///
/// `admit` runs once, after the manifest and every NARInfo are verified and
/// before the first payload is read: with the manifest and the bytes the
/// extracted cache takes (manifest, NARInfos and payloads). Space admission
/// belongs there; its error ends the pass.
pub fn verify_archive(
    mut archive: AuthenticatedArchive,
    release: &NixosRelease,
    key: &VerifyingKey,
    output: Option<&Path>,
    admit: impl FnOnce(&ClosureManifest, u64) -> Result<()>,
) -> Result<VerifiedArchive> {
    let mut admit = Some(admit);
    let (manifest, cache_bytes) = walk(
        &mut archive,
        release,
        key,
        output,
        Payloads::Verify,
        &mut |manifest, bytes| admit.take().map_or(Ok(()), |admit| admit(manifest, bytes)),
    )?;
    Ok(VerifiedArchive {
        archive,
        manifest,
        cache_bytes,
    })
}

#[derive(Clone, Copy)]
enum Payloads<'a> {
    Verify,
    /// Only [`VerifiedArchive::extract`]: the same file passed `Verify`.
    Copy,
    /// Only [`verify_staged`]: the payloads of exactly the members the
    /// store lacks, verified as `Verify` does.
    Missing(&'a Present),
    /// Only [`read_metadata`]: the stream ends before the first payload.
    None,
}
impl Payloads<'_> {
    /// Whether the stream carries the payload of `info`.
    fn carries(self, info: &NarInfo) -> bool {
        match self {
            Self::Missing(present) => present.get(&info.entry.path) != Some(&info.entry.nar_hash),
            Self::None => false,
            Self::Verify | Self::Copy => true,
        }
    }
}

/// Store paths a Nest holds, each with the NAR hash its store records in
/// the manifest's form (`sha256:` and Nix base32).
pub type Present = BTreeMap<String, String>;

fn walk(
    archive: &mut AuthenticatedArchive,
    release: &NixosRelease,
    key: &VerifyingKey,
    output: Option<&Path>,
    mode: Payloads,
    admit: &mut dyn FnMut(&ClosureManifest, u64) -> Result<()>,
) -> Result<(ClosureManifest, u64)> {
    release.verify(key)?;
    ensure!(
        archive.sha256 == release.system_closure.sha256
            && archive.state.len == release.system_closure.size_bytes,
        "archive is not the exact ordinary signed file"
    );
    archive.unchanged()?;
    archive.file.rewind()?;
    let mut decoder = zstd::stream::read::Decoder::new(&mut archive.file)?.single_frame();
    decoder.window_log_max(27)?;
    let mut tar = Counting::unhashed(decoder, MAX_EXPANDED);
    let read = read_tar(&mut tar, release, key, output, mode, admit)?;
    let mut compressed = tar.inner.finish();
    ensure!(
        compressed.fill_buf()?.is_empty(),
        "concatenated zstd frame or trailing compressed garbage"
    );
    archive.unchanged()?;
    Ok((read.manifest, read.cache_bytes))
}

/// The metadata at the start of a closure archive's tar stream (manifest,
/// cache metadata, NARInfos, the `nar/` directory), verified as the
/// archive's own pass verifies it: the manifest against the signed
/// descriptor and its exact reference graph, every NARInfo's signature.
pub struct Metadata {
    pub manifest: ClosureManifest,
    /// NAR payload name (`nar/….nar.zst`) to its NARInfo, in tar order.
    pub(super) infos: BTreeMap<String, NarInfo>,
}
impl Metadata {
    /// Verify one payload's NAR as the archive's pass does, copying the
    /// compressed bytes it reads to `output`.
    pub(super) fn verify_payload(
        &self,
        info: &NarInfo,
        payload: impl Read,
        output: Option<File>,
    ) -> Result<()> {
        let source = &self.manifest.manage_source;
        let (source_root, source_relative) = source_location(source)?;
        verify_nar(
            payload,
            info,
            output,
            (info.entry.path == source_root).then_some((source_relative, source)),
        )
    }
}

/// Read the metadata `prefix` of a closure archive's tar stream: every byte
/// before the first payload's header.
pub fn read_metadata(
    prefix: &[u8],
    release: &NixosRelease,
    key: &VerifyingKey,
) -> Result<Metadata> {
    release.verify(key)?;
    let stream = io::Cursor::new(prefix).chain(&[0u8; 1024][..]);
    let mut tar = Counting::unhashed(stream, MAX_EXPANDED);
    let read = read_tar(&mut tar, release, key, None, Payloads::None, &mut |_, _| {
        Ok(())
    })?;
    Ok(Metadata {
        manifest: read.manifest,
        infos: read.infos,
    })
}

/// A staged update's cache, verified and extracted by [`verify_staged`].
pub struct StagedCache {
    pub manifest: ClosureManifest,
    /// The NAR bytes of the members the store lacks, which the import adds.
    pub missing_nar_bytes: u64,
}

/// Root's one pass over a staged update (`members::stage`): an archive's
/// tar stream as it is (no zstd frame), with the metadata and the payloads
/// of exactly the members `present` lacks. Verified as the archive's own
/// pass verifies it and extracted into the new private `output`; the
/// members it leaves out are in the store with their signed NAR hash. The
/// stream is read once, so each payload is verified as it is copied.
/// `admit` runs as in [`verify_archive`], with the missing NAR bytes too.
pub fn verify_staged(
    stream: impl Read,
    limit: u64,
    release: &NixosRelease,
    key: &VerifyingKey,
    output: &Path,
    present: &Present,
    admit: impl FnOnce(&ClosureManifest, u64, u64) -> Result<()>,
) -> Result<StagedCache> {
    release.verify(key)?;
    let missing = |manifest: &ClosureManifest| {
        manifest
            .store_paths
            .iter()
            .filter(|path| present.get(&path.path) != Some(&path.nar_hash))
            .map(|path| path.nar_size)
            .sum::<u64>()
    };
    let mut admit = Some(admit);
    let mut tar = Counting::unhashed(io::BufReader::new(stream), limit);
    let read = read_tar(
        &mut tar,
        release,
        key,
        Some(output),
        Payloads::Missing(present),
        &mut |manifest, bytes| {
            admit
                .take()
                .map_or(Ok(()), |admit| admit(manifest, bytes, missing(manifest)))
        },
    )?;
    Ok(StagedCache {
        missing_nar_bytes: missing(&read.manifest),
        manifest: read.manifest,
    })
}

struct TarRead {
    manifest: ClosureManifest,
    cache_bytes: u64,
    infos: BTreeMap<String, NarInfo>,
}

/// One pass over a closure's tar stream. Optional extraction targets only a
/// new private root-owned cache directory.
fn read_tar<R: Read>(
    tar: &mut Counting<R>,
    release: &NixosRelease,
    key: &VerifyingKey,
    output: Option<&Path>,
    mode: Payloads,
    admit: &mut dyn FnMut(&ClosureManifest, u64) -> Result<()>,
) -> Result<TarRead> {
    let mut block = [0u8; 64 * 1024];
    if let Some(root) = output {
        fs::create_dir(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    let mut manifest: Option<ClosureManifest> = None;
    let mut paths = BTreeMap::new();
    let mut infos = BTreeMap::new();
    let mut members = BTreeSet::new();
    let mut payloads = BTreeSet::new();
    let mut saw_cache = false;
    let mut payload_started = false;
    // The extracted cache: its metadata files as they come, then every
    // payload's signed size once all are known.
    let mut cache_bytes = 0u64;
    let mut timestamp = None;
    loop {
        let mut raw = [0u8; 512];
        tar.read_exact(&mut raw)
            .context("incomplete USTAR header")?;
        if raw == [0; 512] {
            let mut second = [0u8; 512];
            tar.read_exact(&mut second)?;
            ensure!(second == [0; 512], "USTAR requires two end blocks");
            let mut trailing = 0u64;
            loop {
                let n = tar.read(&mut block)?;
                if n == 0 {
                    break;
                }
                trailing += n as u64;
                ensure!(
                    trailing <= 10240 && block[..n].iter().all(|b| *b == 0),
                    "unexpected trailing tar data"
                );
            }
            ensure!(trailing % 512 == 0, "unaligned trailing tar data");
            break;
        }
        ensure!(members.len() < MAX_MEMBERS, "too many archive members");
        let (name, length, directory, mtime) = header(&raw)?;
        ensure!(
            timestamp.is_none_or(|t| t == mtime),
            "unstable archive timestamps"
        );
        timestamp = Some(mtime);
        ensure!(members.insert(name.clone()), "duplicate archive member");
        let allowed = name == "manifest.json"
            || name == "nix-cache-info"
            || name == "nar/"
            || paths.contains_key(&name)
            || valid_nar_name(&name);
        ensure!(allowed, "unexpected archive member");
        ensure!(length <= MAX_EXPANDED, "archive entry size limit");
        if directory {
            ensure!(
                name == "nar/" && length == 0,
                "unexpected archive directory"
            );
            if let Some(root) = output {
                fs::create_dir(root.join("nar"))?;
            }
            continue;
        }
        let mut entry = (&mut *tar).take(length);
        if name == "manifest.json" {
            ensure!(
                members.len() == 1 && length <= MAX_MANIFEST,
                "manifest must be first and bounded"
            );
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let value = strict_json(&bytes)?;
            let mut canonical = serde_json::to_vec(&super::canonical_json(value.clone()))?;
            canonical.push(b'\n');
            ensure!(
                bytes == canonical,
                "closure manifest must be canonical JSON plus LF"
            );
            let m: ClosureManifest = serde_json::from_value(value)?;
            m.validate(release, key)?;
            cache_bytes += length;
            for p in &m.store_paths {
                paths.insert(p.narinfo.clone(), p.clone());
            }
            if let Some(root) = output {
                write_new(&root.join(&name), &bytes)?;
            }
            manifest = Some(m);
        } else if name == "nix-cache-info" {
            ensure!(
                !payload_started && length <= 1024,
                "cache metadata ordering/size"
            );
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let text = std::str::from_utf8(&bytes)?;
            ensure!(
                text == "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"
                    || text == "StoreDir: /nix/store\n",
                "unexpected Nix cache metadata"
            );
            cache_bytes += length;
            if let Some(root) = output {
                write_new(&root.join(&name), &bytes)?;
            }
            saw_cache = true;
        } else if let Some(path) = paths.get(&name) {
            ensure!(
                !payload_started && length <= MAX_NARINFO,
                "NARInfos must precede payloads and be bounded"
            );
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let (url, info) = narinfo(&bytes, path, key)?;
            ensure!(
                infos.insert(url, info).is_none(),
                "duplicate NAR payload identity"
            );
            cache_bytes += length;
            if let Some(root) = output {
                write_new(&root.join(&name), &bytes)?;
            }
        } else {
            ensure!(
                infos.len() == paths.len() && saw_cache,
                "payload before complete metadata"
            );
            if !payload_started {
                payload_started = true;
                cache_bytes = start_payloads(&manifest, &infos, cache_bytes, mode, admit)?;
            }
            let info = infos
                .get(&name)
                .ok_or_else(|| anyhow!("unreferenced NAR payload"))?;
            ensure!(length == info.file_size, "compressed NAR size mismatch");
            ensure!(
                mode.carries(info),
                "the stream carries a payload it must not"
            );
            let destination = output.map(|root| root.join(&name));
            let target = destination
                .as_ref()
                .map(|path| {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(path)
                })
                .transpose()?;
            ensure!(
                members.contains("nar/"),
                "NAR directory must precede payloads"
            );
            let source = manifest
                .as_ref()
                .map(|m| &m.manage_source)
                .ok_or_else(|| anyhow!("manifest missing"))?;
            let (source_root, source_relative) = source_location(source)?;
            match (mode, target) {
                (Payloads::Verify | Payloads::Missing(_), target) => verify_nar(
                    &mut entry,
                    info,
                    target,
                    if info.entry.path == source_root {
                        Some((source_relative, source))
                    } else {
                        None
                    },
                )?,
                (Payloads::Copy, Some(mut target)) => {
                    ensure!(
                        io::copy(&mut entry, &mut target)? == length,
                        "short archive member"
                    );
                }
                (Payloads::Copy, None) => bail!("extraction needs a directory"),
                (Payloads::None, _) => unreachable!("metadata carries no payload"),
            }
            payloads.insert(name);
        }
        ensure!(entry.limit() == 0, "short archive member");
        let pad = (512 - length % 512) % 512;
        let mut padding = [0u8; 512];
        tar.read_exact(&mut padding[..pad as usize])?;
        ensure!(
            padding[..pad as usize].iter().all(|b| *b == 0),
            "nonzero USTAR padding"
        );
    }
    ensure!(
        infos.len() == paths.len() && saw_cache,
        "incomplete closure archive"
    );
    if !payload_started && matches!(mode, Payloads::Missing(_)) {
        // Every member is in the store already: admission still decides.
        cache_bytes = start_payloads(&manifest, &infos, cache_bytes, mode, admit)?;
    }
    let carried = infos
        .iter()
        .filter(|(_, info)| mode.carries(info))
        .map(|(name, _)| name);
    ensure!(payloads.iter().eq(carried), "incomplete closure archive");
    Ok(TarRead {
        manifest: manifest.ok_or_else(|| anyhow!("missing closure manifest"))?,
        cache_bytes,
        infos,
    })
}

/// Once every NARInfo is verified and before the first payload: the bytes
/// the extracted cache takes with the payloads the stream carries, admitted.
fn start_payloads(
    manifest: &Option<ClosureManifest>,
    infos: &BTreeMap<String, NarInfo>,
    mut cache_bytes: u64,
    mode: Payloads,
    admit: &mut dyn FnMut(&ClosureManifest, u64) -> Result<()>,
) -> Result<u64> {
    for info in infos.values().filter(|info| mode.carries(info)) {
        cache_bytes = cache_bytes
            .checked_add(info.file_size)
            .ok_or_else(|| anyhow!("cache size overflow"))?;
    }
    let verified = manifest
        .as_ref()
        .ok_or_else(|| anyhow!("manifest missing"))?;
    admit(verified, cache_bytes)?;
    Ok(cache_bytes)
}

struct Tee<R> {
    reader: R,
    output: Option<File>,
}
impl<R: Read> Read for Tee<R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(b)?;
        if let Some(out) = &mut self.output {
            out.write_all(&b[..n])?;
        }
        Ok(n)
    }
}
fn verify_nar(
    reader: impl Read,
    info: &NarInfo,
    output: Option<File>,
    source: Option<(&str, &ManageSource)>,
) -> Result<()> {
    let compressed = Counting::new(Tee { reader, output }, info.file_size);
    let mut decoder = zstd::stream::read::Decoder::new(compressed)?.single_frame();
    decoder.window_log_max(27)?;
    let mut nar = Counting::new(decoder, info.entry.nar_size);
    ensure!(
        nar_string(&mut nar, 64)? == b"nix-archive-1",
        "invalid NAR header"
    );
    let components = source
        .map(|(path, _)| {
            path.split('/')
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut found_source = false;
    nar_node(
        &mut nar,
        0,
        source.map(|(_, source)| (components.as_slice(), source)),
        &mut found_source,
    )?;
    ensure!(
        source.is_none() || found_source,
        "embedded Tiaris source file is absent from its NAR"
    );
    let mut one = [0];
    ensure!(nar.read(&mut one)? == 0, "trailing NAR bytes");
    ensure!(
        nar.bytes == info.entry.nar_size && nar.digest() == info.entry.nar_hash,
        "NAR size/hash mismatch"
    );
    let mut buffered = nar.inner.finish();
    ensure!(
        buffered.fill_buf()?.is_empty(),
        "trailing or concatenated NAR frame"
    );
    let mut compressed = buffered.into_inner();
    ensure!(
        compressed.bytes == info.file_size && compressed.digest() == info.file_hash,
        "compressed NAR hash/size mismatch"
    );
    Ok(())
}
fn nar_string(reader: &mut impl Read, max: u64) -> Result<Vec<u8>> {
    let mut len = [0u8; 8];
    reader.read_exact(&mut len)?;
    let len = u64::from_le_bytes(len);
    ensure!(len <= max, "NAR token size limit");
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes)?;
    nar_padding(reader, len)?;
    Ok(bytes)
}
fn nar_padding(reader: &mut impl Read, len: u64) -> Result<()> {
    let mut pad = [0u8; 8];
    let n = ((8 - len % 8) % 8) as usize;
    reader.read_exact(&mut pad[..n])?;
    ensure!(pad[..n].iter().all(|b| *b == 0), "invalid NAR padding");
    Ok(())
}
fn nar_expect(reader: &mut impl Read, value: &[u8]) -> Result<()> {
    ensure!(nar_string(reader, 256)? == value, "invalid NAR structure");
    Ok(())
}
fn nar_node(
    reader: &mut impl Read,
    depth: usize,
    source: Option<(&[&str], &ManageSource)>,
    found_source: &mut bool,
) -> Result<()> {
    ensure!(depth <= 256, "NAR recursion limit");
    nar_expect(reader, b"(")?;
    nar_expect(reader, b"type")?;
    match nar_string(reader, 32)?.as_slice() {
        b"regular" => {
            let mut token = nar_string(reader, 32)?;
            if token == b"executable" {
                nar_expect(reader, b"")?;
                token = nar_string(reader, 32)?;
            }
            ensure!(token == b"contents", "invalid regular NAR");
            let mut len = [0u8; 8];
            reader.read_exact(&mut len)?;
            let len = u64::from_le_bytes(len);
            ensure!(len <= MAX_NAR_BYTES, "NAR contents limit");
            let mut contents = reader.take(len);
            let mut hash = Sha256::new();
            let mut copied = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let n = contents.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                copied += n as u64;
                if source.is_some() {
                    hash.update(&buffer[..n]);
                }
            }
            ensure!(copied == len, "truncated NAR file");
            if let Some((remaining, metadata)) = source {
                ensure!(
                    remaining.is_empty()
                        && len == metadata.size_bytes
                        && hex::encode(hash.finalize()) == metadata.sha256,
                    "embedded Tiaris source bytes do not match manifest"
                );
                *found_source = true;
            }
            nar_padding(reader, len)?;
            nar_expect(reader, b")")?;
        }
        b"directory" => {
            let mut previous = Vec::new();
            loop {
                let token = nar_string(reader, 32)?;
                if token == b")" {
                    break;
                }
                ensure!(token == b"entry", "invalid NAR directory");
                nar_expect(reader, b"(")?;
                nar_expect(reader, b"name")?;
                let name = nar_string(reader, 255)?;
                ensure!(
                    !name.is_empty()
                        && name != b"."
                        && name != b".."
                        && !name.contains(&b'/')
                        && !name.contains(&0)
                        && name > previous,
                    "invalid or unordered NAR entry name"
                );
                let child_source = source.and_then(|(remaining, metadata)| {
                    remaining.split_first().and_then(|(first, tail)| {
                        if first.as_bytes() == name {
                            Some((tail, metadata))
                        } else {
                            None
                        }
                    })
                });
                previous = name;
                nar_expect(reader, b"node")?;
                nar_node(reader, depth + 1, child_source, found_source)?;
                nar_expect(reader, b")")?;
            }
        }
        b"symlink" => {
            ensure!(
                source.is_none(),
                "embedded Tiaris source cannot be a symlink"
            );
            nar_expect(reader, b"target")?;
            let target = nar_string(reader, 4096)?;
            ensure!(!target.contains(&0), "NAR symlink NUL");
            nar_expect(reader, b")")?;
        }
        _ => bail!("unsupported NAR node"),
    }
    Ok(())
}
pub(super) fn header(raw: &[u8; 512]) -> Result<(String, u64, bool, u64)> {
    ensure!(
        &raw[257..263] == b"ustar\0" && &raw[263..265] == b"00",
        "archive is not canonical USTAR"
    );
    let recorded = octal(&raw[148..156])?;
    let sum: u64 = raw
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                *b as u64
            }
        })
        .sum();
    ensure!(recorded == sum, "USTAR checksum mismatch");
    ensure!(
        octal(&raw[108..116])? == 0 && octal(&raw[116..124])? == 0,
        "archive ownership must be root"
    );
    ensure!(
        raw[157..257].iter().all(|b| *b == 0) && raw[345..512].iter().all(|b| *b == 0),
        "links, prefixes and extensions forbidden"
    );
    let name_end = raw[..100].iter().position(|b| *b == 0).unwrap_or(100);
    ensure!(
        raw[name_end..100].iter().all(|b| *b == 0),
        "noncanonical USTAR filename"
    );
    let name = std::str::from_utf8(&raw[..name_end])?.to_string();
    ensure!(
        name.len() <= 100
            && !name.starts_with('/')
            && !name.contains("..")
            && !name.bytes().any(|b| b.is_ascii_control()),
        "unsafe archive name"
    );
    let directory = raw[156] == b'5';
    ensure!(
        directory || raw[156] == b'0',
        "only ordinary files and nar directory are permitted"
    );
    ensure!(
        octal(&raw[100..108])? == if directory { 0o755 } else { 0o644 },
        "noncanonical archive mode"
    );
    Ok((
        name,
        octal(&raw[124..136])?,
        directory,
        octal(&raw[136..148])?,
    ))
}
fn octal(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes)?.trim_matches(['\0', ' ']);
    ensure!(
        !text.is_empty() && text.bytes().all(|b| (b'0'..=b'7').contains(&b)),
        "noncanonical tar numeric field"
    );
    Ok(u64::from_str_radix(text, 8)?)
}
/// Extracted files are not synced one by one: nothing reads an extraction
/// after an interruption. Setup and the updater remove it and extract again.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nix_base32_matches_known_sha256() {
        assert_eq!(nix_hash(&[0; 32]), format!("sha256:{}", "0".repeat(52)));
        assert_eq!(nix_hash(&[255; 32]), format!("sha256:1{}", "z".repeat(51)));
    }
    #[test]
    fn archive_header_rejects_links_and_traversal() {
        for name in ["../secret", "/etc/shadow"] {
            let mut h = tar::Header::new_ustar();
            h.set_path("manifest.json").unwrap();
            h.set_size(1);
            h.set_mode(0o644);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            h.set_entry_type(tar::EntryType::Regular);
            h.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            h.set_cksum();
            assert!(header(h.as_bytes()).is_err());
        }
        let mut h = tar::Header::new_ustar();
        h.set_path("nar/test.nar.zst").unwrap();
        h.set_size(0);
        h.set_mode(0o644);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_cksum();
        assert!(header(h.as_bytes()).is_err());
    }
    #[test]
    fn nar_rejects_oversized_tokens_without_allocating() {
        let mut b = &u64::MAX.to_le_bytes()[..];
        assert!(nar_string(&mut b, 256).is_err());
    }
}

#[cfg(test)]
#[path = "closure_tests.rs"]
pub(crate) mod full_archive_tests;
