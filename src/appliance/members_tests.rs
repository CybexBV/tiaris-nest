use super::*;
use crate::appliance::closure::full_archive_tests::{Fixture, files};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use uuid::Uuid;

/// The archive `tools/pack-system-closure.py` writes (`RawFrame`).
fn raw_frame(tar: &[u8]) -> Vec<u8> {
    let mut out = FRAME.to_vec();
    let blocks = tar.len().div_ceil(BLOCK as usize);
    for (index, chunk) in tar.chunks(BLOCK as usize).enumerate() {
        let last = u32::from(index + 1 == blocks);
        out.extend(&(((chunk.len() as u32) << 3) | last).to_le_bytes()[..3]);
        out.extend(chunk);
    }
    out
}

fn tar_range(layout: Layout, archive: &[u8], start: u64, end: u64) -> Result<Vec<u8>> {
    let mut deblock = Deblock::new(layout, start, end);
    let (first, last) = deblock.range();
    let mut out = Vec::new();
    for chunk in archive[first as usize..=last as usize].chunks(1000) {
        deblock.push(chunk, &mut |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })?;
    }
    ensure!(deblock.position == end, "short");
    Ok(out)
}

#[test]
fn raw_blocks_put_every_tar_byte_where_the_layout_says() {
    let tar: Vec<u8> = (0..400_000u32).map(|i| (i * 31 % 251) as u8).collect();
    let archive = raw_frame(&tar);
    // Every Nest reads it as the one zstd frame it always read.
    let mut decoder = zstd::stream::read::Decoder::new(&archive[..])
        .unwrap()
        .single_frame();
    decoder.window_log_max(27).unwrap();
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, tar);
    let layout = Layout::of(archive.len() as u64).unwrap();
    assert_eq!(layout.tar_bytes, tar.len() as u64);
    for (start, end) in [
        (0, 10),
        (0, 400_000),
        (131_067, 131_077),
        (131_072, 262_144),
        (262_143, 262_145),
        (399_999, 400_000),
    ] {
        assert_eq!(
            tar_range(layout, &archive, start, end).unwrap(),
            tar[start as usize..end as usize]
        );
    }
    let mut changed = archive.clone();
    changed[6 + 3 + BLOCK as usize] ^= 1;
    assert!(tar_range(layout, &changed, 100_000, 200_000).is_err());
    // A compressed archive is no raw-block archive.
    let compressed = zstd::stream::encode_all(&tar[..], 3).unwrap();
    let mut deblock = Deblock::new(layout, 0, 10);
    let error = deblock.push(&compressed[..9], &mut |_| Ok(())).unwrap_err();
    assert!(error.is::<NotRawBlocks>());
}

/// Serves `archive` at a loopback URL: byte ranges, or the whole file when
/// `ranges` is false. With `drop_once`, the first range not at the start
/// ends halfway. Records the requested ranges.
async fn serve(
    archive: Vec<u8>,
    ranges: bool,
    drop_once: bool,
) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/tiaris-nest-appliance-closure.tar.zst",
        listener.local_addr().unwrap()
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let dropped = Arc::new(AtomicBool::new(!drop_once));
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let range = requested_range(&mut stream).await;
            log.lock().unwrap().push(range.clone());
            let response = match range.split_once('-') {
                Some((first, last)) if ranges => {
                    let (first, last): (usize, usize) =
                        (first.parse().unwrap(), last.parse().unwrap());
                    let length = last + 1 - first;
                    if first > 0 && !dropped.swap(true, Ordering::SeqCst) {
                        partial_content(&archive, first, last, length / 2)
                    } else {
                        partial_content(&archive, first, last, length)
                    }
                }
                _ => {
                    let mut head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        archive.len()
                    )
                    .into_bytes();
                    head.extend(&archive);
                    head
                }
            };
            let _ = stream.write_all(&response).await;
        }
    });
    (url, seen, server)
}

/// The byte range a request asks for (`first-last`), or "" for none.
async fn requested_range(stream: &mut tokio::net::TcpStream) -> String {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut buffer = [0; 1024];
        let read = stream.read(&mut buffer).await.unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8_lossy(&request)
        .to_lowercase()
        .lines()
        .find_map(|line| line.strip_prefix("range: bytes="))
        .unwrap_or("")
        .to_string()
}

/// A 206 answer for `archive[first..=last]` that sends only its first
/// `sent` bytes.
fn partial_content(archive: &[u8], first: usize, last: usize, sent: usize) -> Vec<u8> {
    let mut answer = format!(
        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {first}-{last}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        archive.len(),
        last + 1 - first
    )
    .into_bytes();
    answer.extend(&archive[first..first + sent]);
    answer
}

fn temporary(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}", Uuid::new_v4()));
    fs::create_dir(&path).unwrap();
    path
}

#[tokio::test]
async fn an_update_fetches_and_stages_only_what_the_running_system_lacks() {
    let mut fixture = Fixture::new();
    let archive = raw_frame(&fixture.tar());
    fixture.bind(&archive);
    let key = fixture.key.verifying_key();
    let manifest = fixture.verify(&archive).unwrap();
    // The running system holds the source; the new system is missing.
    let (source, system) = (&manifest.store_paths[1], &manifest.store_paths[0]);
    let present = Present::from([(source.path.clone(), source.nar_hash.clone())]);
    let (url, seen, server) = serve(archive.clone(), true, true).await;
    let inbox = temporary("tiaris-members-inbox");
    let mut plan = plan(&fixture.release, &key, &url, true, &inbox, &present)
        .await
        .unwrap()
        .unwrap();
    plan.source.pause = Duration::ZERO;
    assert_eq!(plan.members(), 1);
    let target = inbox.join("attempt.members.tar");
    stage(&plan, &target).await.unwrap();
    server.abort();
    // The metadata, then the member twice: dropped halfway, continued.
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3);
    assert!(seen[0].starts_with("0-"));
    let resumed = |range: &str| range.split('-').next().unwrap().parse::<u64>().unwrap();
    assert!(resumed(&seen[2]) > resumed(&seen[1]));
    assert!(!plan.partial.exists());

    let limit = Layout::of(archive.len() as u64).unwrap().tar_bytes;
    let cache = inbox.join("cache");
    let mut admitted = None;
    let staged =
        verify_staged_file(&target, limit, &fixture, &cache, &present, &mut admitted).unwrap();
    assert_eq!(staged.missing_nar_bytes, system.nar_size);
    assert_eq!(admitted, Some(system.nar_size));
    let system_payload = format!("nar/{}.nar.zst", &system.path[11..43]);
    let extracted = files(&cache);
    assert!(extracted.contains_key(&system_payload));
    assert_eq!(
        extracted
            .keys()
            .filter(|name| name.starts_with("nar/"))
            .count(),
        1
    );
    assert!(extracted.contains_key(&source.narinfo) && extracted.contains_key("manifest.json"));
    // Root holds the Nest to what it stages: a member that is neither in
    // the stream nor in the store refuses the update.
    let refused = verify_staged_file(
        &target,
        limit,
        &fixture,
        &inbox.join("refused"),
        &Present::new(),
        &mut None,
    );
    assert!(refused.is_err());
    fs::remove_dir_all(inbox).unwrap();
}

fn verify_staged_file(
    target: &Path,
    limit: u64,
    fixture: &Fixture,
    cache: &Path,
    present: &Present,
    admitted: &mut Option<u64>,
) -> Result<closure::StagedCache> {
    closure::verify_staged(
        File::open(target)?,
        limit,
        &fixture.release,
        &fixture.key.verifying_key(),
        cache,
        present,
        |_, _, missing| {
            *admitted = Some(missing);
            Ok(())
        },
    )
}

#[tokio::test]
async fn an_older_archive_or_a_server_without_ranges_takes_the_whole_archive() {
    let mut fixture = Fixture::new();
    let key = fixture.key.verifying_key();
    let inbox = temporary("tiaris-members-whole");
    let present = Present::new();
    let compressed = zstd::stream::encode_all(&fixture.tar()[..], 3).unwrap();
    fixture.bind(&compressed);
    let (url, _, server) = serve(compressed, true, false).await;
    let planned = plan(&fixture.release, &key, &url, true, &inbox, &present).await;
    server.abort();
    assert!(planned.unwrap().is_none());

    let archive = raw_frame(&fixture.tar());
    fixture.bind(&archive);
    let (url, _, server) = serve(archive, false, false).await;
    let planned = plan(&fixture.release, &key, &url, true, &inbox, &present).await;
    server.abort();
    let error = planned.err().unwrap();
    assert!(!error.is::<KeepTrying>());
    fs::remove_dir_all(inbox).unwrap();
}

#[test]
fn the_running_system_is_read_from_every_path_info_shape() {
    let raw = [7u8; 32];
    let path = "/nix/store/00000000000000000000000000000000-system";
    let expected = Present::from([(path.to_string(), closure::nix_hash(&raw))]);
    let sri = format!("sha256-{}", STANDARD.encode(raw));
    for json in [
        serde_json::json!({ (path): { "narHash": sri } }),
        serde_json::json!({ (&path[11..]): { "narHash": sri } }),
        serde_json::json!([{ "path": path, "narHash": closure::nix_hash(&raw) }]),
    ] {
        assert_eq!(present(json.to_string().as_bytes()).unwrap(), expected);
    }
    assert!(present(b"{}").is_err());
}

/// The manifest says how far the metadata goes: the request after it asks
/// for the rest of the metadata and the first payload's header, at most a
/// block per member more, instead of fixed steps.
#[test]
fn the_manifest_sizes_the_rest_of_the_metadata_request() {
    let fixture = Fixture::new();
    let tar = fixture.tar();
    let end = metadata_end(&tar).unwrap().unwrap() as u64;
    let (_, manifest_length, _, _) = closure::header(tar[..512].try_into().unwrap()).unwrap();
    let manifest_end = 512 + manifest_length;
    assert_eq!(metadata_want(&tar[..300]), None);
    assert_eq!(
        metadata_want(&tar[..manifest_end as usize - 1]),
        Some(manifest_end)
    );
    let want = metadata_want(&tar[..manifest_end as usize]).unwrap();
    let members = fixture
        .members
        .iter()
        .filter(|(name, _)| name.ends_with(".narinfo"))
        .count() as u64;
    assert!(
        want >= end + 512 && want - (end + 512) < 512 * members,
        "{want} for metadata ending at {end}"
    );
}

/// Members run a few at a time, and every result comes back in its order.
#[tokio::test]
async fn members_are_fetched_a_few_at_a_time() {
    let running = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let most = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tasks: Vec<Pin<Box<dyn Future<Output = usize> + Send>>> = (0..10usize)
        .map(|index| {
            let (running, most) = (running.clone(), most.clone());
            Box::pin(async move {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                running.fetch_sub(1, Ordering::SeqCst);
                index
            }) as Pin<Box<dyn Future<Output = usize> + Send>>
        })
        .collect();
    assert_eq!(at_most(AT_ONCE, tasks).await, (0..10).collect::<Vec<_>>());
    assert_eq!(most.load(Ordering::SeqCst), AT_ONCE);
}

/// Serves ranges of `archive` like [`serve`], but holds the first `wave`
/// requests and answers them last first, each once the client has read the
/// one before and closed it: members fetched at once arrive in the reverse
/// of their order.
async fn serve_last_first(archive: Vec<u8>, wave: usize) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/tiaris-nest-appliance-closure.tar.zst",
        listener.local_addr().unwrap()
    );
    let server = tokio::spawn(async move {
        let (mut held, mut wave) = (Vec::new(), wave);
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let range = requested_range(&mut stream).await;
            let (first, last) = range.split_once('-').unwrap();
            let (first, last): (usize, usize) = (first.parse().unwrap(), last.parse().unwrap());
            held.push((first, last, stream));
            if held.len() < wave {
                continue;
            }
            wave = 1;
            held.sort_by_key(|(first, _, _)| std::cmp::Reverse(*first));
            for (first, last, mut stream) in held.drain(..) {
                let answer = partial_content(&archive, first, last, last + 1 - first);
                let _ = stream.write_all(&answer).await;
                let _ = stream.read(&mut [0; 1]).await;
            }
        }
    });
    (url, server)
}

/// Members fetched at once each land in their own place, whatever order
/// their bytes arrive in (0.2.183-dev.2: the staged stream was opened to
/// append, so they landed in the order they arrived and the update took the
/// whole archive). The archive has the real shape: payloads crossing 128 KiB
/// blocks, with the members the running system holds between the missing.
#[tokio::test]
async fn members_fetched_at_once_land_in_their_places() {
    // Incompressible, so each payload crosses a block.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut noise = |bytes: usize| -> Vec<u8> {
        (0..bytes)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    };
    let paths: Vec<String> = (2..8)
        .map(|digit| format!("/nix/store/{}-member", digit.to_string().repeat(32)))
        .collect();
    let extra: Vec<(&str, Vec<u8>)> = paths
        .iter()
        .zip(0..)
        .map(|(path, index)| (path.as_str(), noise(150_000 + index * 20_000)))
        .collect();
    let mut fixture = Fixture::with(&extra);
    let tar = fixture.tar();
    let archive = raw_frame(&tar);
    fixture.bind(&archive);
    let key = fixture.key.verifying_key();
    let manifest = fixture.verify(&archive).unwrap();
    // The system and every other store path after it are missing.
    let present: Present = manifest
        .store_paths
        .iter()
        .skip(1)
        .step_by(2)
        .map(|path| (path.path.clone(), path.nar_hash.clone()))
        .collect();
    let (url, _, server) = serve(archive.clone(), true, false).await;
    let inbox = temporary("tiaris-members-at-once");
    let mut plan = plan(&fixture.release, &key, &url, true, &inbox, &present)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    assert_eq!(plan.members(), 4);
    let (url, server) = serve_last_first(archive, plan.members().min(AT_ONCE)).await;
    plan.source.url = url;
    let target = inbox.join("attempt.members.tar");
    tokio::time::timeout(Duration::from_secs(30), stage(&plan, &target))
        .await
        .expect("the members were fetched at once")
        .unwrap();
    server.abort();
    // The archive's tar stream without the payloads the system holds.
    let held: Vec<String> = present
        .keys()
        .map(|path| format!("nar/{}.nar.zst", &path[11..43]))
        .collect();
    let mut expected = Vec::new();
    for entry in tar::Archive::new(&tar[..]).entries().unwrap() {
        let entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().into_owned();
        if !held.contains(&name) {
            let start = entry.raw_header_position() as usize;
            expected.extend(&tar[start..start + 512 + entry.size().div_ceil(512) as usize * 512]);
        }
    }
    expected.extend([0; 1024]);
    assert_eq!(fs::read(&target).unwrap(), expected);
    fs::remove_dir_all(inbox).unwrap();
}

/// An install leaves out only members whose whole closure it leaves out:
/// a member the ISO carries whose reference must be fetched is fetched too,
/// so every left out member can be copied over with its closure.
#[test]
fn an_install_leaves_out_only_members_whose_closure_it_holds() {
    let mut fixture = Fixture::new();
    let archive = raw_frame(&fixture.tar());
    fixture.bind(&archive);
    let manifest = fixture.verify(&archive).unwrap();
    let (system, source) = (&manifest.store_paths[0], &manifest.store_paths[1]);
    assert_eq!(system.references, vec![source.path.clone()]);
    let carries = |paths: &[&closure::StorePath]| -> Present {
        paths
            .iter()
            .map(|path| (path.path.clone(), path.nar_hash.clone()))
            .collect()
    };
    let system_only = carries(&[system]);
    // An update keeps what the running system holds.
    assert_eq!(held(&manifest, &system_only, false), system_only);
    assert!(held(&manifest, &system_only, true).is_empty());
    let both = carries(&[system, source]);
    assert_eq!(held(&manifest, &both, true), both);
    // A member with another NAR hash is not held.
    let mut changed = both.clone();
    changed.insert(source.path.clone(), system.nar_hash.clone());
    assert!(held(&manifest, &changed, true).is_empty());
}
