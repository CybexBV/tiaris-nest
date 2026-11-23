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
        out.extend(&((chunk.len() as u32) << 3 | last).to_le_bytes()[..3]);
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
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut buffer = [0; 1024];
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8_lossy(&request).to_lowercase();
            let range = request
                .lines()
                .find_map(|line| line.strip_prefix("range: bytes="))
                .unwrap_or("")
                .to_string();
            log.lock().unwrap().push(range.clone());
            let total = archive.len();
            let response = match range.split_once('-') {
                Some((first, last)) if ranges => {
                    let (first, last): (usize, usize) =
                        (first.parse().unwrap(), last.parse().unwrap());
                    let mut body = archive[first..=last].to_vec();
                    let length = body.len();
                    if first > 0 && !dropped.swap(true, Ordering::SeqCst) {
                        body.truncate(length / 2);
                    }
                    let mut head = format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {first}-{last}/{total}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                    )
                    .into_bytes();
                    head.extend(body);
                    head
                }
                _ => {
                    let mut head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n"
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
