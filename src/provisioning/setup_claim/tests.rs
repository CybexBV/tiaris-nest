use super::*;
use crate::provisioning::{inventory, recovery, setup_status::SetupStatusReporter};
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method as HttpMethod, StatusCode, Uri},
    response::IntoResponse,
    routing::any,
};
use ed25519_dalek::{Signature, Verifier};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};

const ORIGIN: &str = "https://manage.example.test";
const LETTERS: &str = "KXQM";
const CODE: &str = "KX-4821-QM";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("tiaris-nest-claim-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn provisioning_key() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

fn envelope(session_id: Uuid, days: i64) -> Vec<u8> {
    let now = Utc::now();
    let issued = if days > 0 {
        now
    } else {
        now - chrono::Duration::days(31)
    };
    let expires = if days > 0 {
        now + chrono::Duration::days(days)
    } else {
        now - chrono::Duration::days(1)
    };
    protocol::tests::signed_envelope_bytes(&provisioning_key(), session_id, ORIGIN, issued, expires)
}

fn status_body(value: Value) -> StatusBody {
    serde_json::from_value(value).unwrap()
}

fn claimable(id: Uuid) -> Value {
    json!({"schema":STATUS_SCHEMA,"registration_id":id,"state":"claimable","poll_after_seconds":5,
           "claim_url":"dev.tiaris.com/nest","letters":LETTERS,"code":CODE})
}

fn backoff(id: Uuid) -> Value {
    json!({"schema":STATUS_SCHEMA,"registration_id":id,"state":"backoff","poll_after_seconds":5,
           "claim_url":"dev.tiaris.com/nest","retry_at":"2026-11-17T10:00:00Z"})
}

fn claimed(id: Uuid, session: Uuid, envelope: &[u8]) -> Value {
    json!({"schema":STATUS_SCHEMA,"registration_id":id,"state":"claimed","poll_after_seconds":5,
           "claim_url":"dev.tiaris.com/nest","organization_name":"Greenfield School",
           "session_id":session,"envelope":STANDARD.encode(envelope)})
}

fn refusal(status: StatusCode, code: &str) -> (StatusCode, Value) {
    (status, json!({"error":"refused","error_code":code}))
}

#[test]
fn only_an_all_zero_slot_is_generic() {
    assert!(bytes_are_generic_slot(&[0; 8192]));
    assert!(!bytes_are_generic_slot(&[0; 8191]));
    assert!(!bytes_are_generic_slot(&[0; 8193]));
    let mut personalized = [0; 8192];
    personalized[8191] = 1;
    assert!(!bytes_are_generic_slot(&personalized));
    let bytes = envelope(Uuid::new_v4(), 30);
    assert!(!bytes_are_generic_slot(&bytes));

    let dir = TempDir::new();
    let slot = dir.0.join("TIARIS_PROVISIONING.BIN");
    fs::write(&slot, [0; 8192]).unwrap();
    assert!(slot_is_generic(&slot).unwrap());
    fs::write(&slot, &bytes).unwrap();
    assert!(!slot_is_generic(&slot).unwrap());
    assert!(slot_is_generic(&dir.0.join("missing")).is_err());
}

#[test]
fn every_status_state_carries_exactly_its_fields() {
    let id = Uuid::new_v4();
    let reply = validate_reply(status_body(claimable(id)), Some(id)).unwrap();
    assert_eq!(reply.claim_url.as_deref(), Some("dev.tiaris.com/nest"));
    assert_eq!(reply.poll_after_seconds, 5);
    assert!(
        matches!(reply.answer, Answer::Claimable { ref letters, ref code } if letters == LETTERS && code == CODE)
    );

    let reply = validate_reply(status_body(backoff(id)), None).unwrap();
    assert!(matches!(reply.answer, Answer::Backoff { .. }));

    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let reply = validate_reply(status_body(claimed(id, session, &bytes)), Some(id)).unwrap();
    assert!(
        matches!(reply.answer, Answer::Claimed { ref envelope, session_id, .. }
        if envelope == &bytes && session_id == session)
    );

    // Unknown fields are accepted: a generic ISO must outlive Manage changes.
    let mut extended = claimable(id);
    extended["future_field"] = json!(true);
    assert!(validate_reply(status_body(extended), Some(id)).is_ok());

    // poll_after_seconds is held to 2-60; a scheme in claim_url is dropped.
    for (given, used) in [(0, 2), (1, 2), (5, 5), (60, 60), (3600, 60), (-4, 2)] {
        let mut body = claimable(id);
        body["poll_after_seconds"] = json!(given);
        body["claim_url"] = json!("https://dev.tiaris.com/nest");
        let reply = validate_reply(status_body(body), Some(id)).unwrap();
        assert_eq!(reply.poll_after_seconds, used);
        assert_eq!(reply.claim_url, None);
    }
}

#[test]
fn malformed_statuses_are_refused_without_repeating_their_values() {
    let id = Uuid::new_v4();
    let mut cases = Vec::new();
    for letters in [
        "KXQ", "KXQMM", "KXQI", "kxqm", "KXQO", "KXQS", "KXQZ", "KXQU", "KXQL",
    ] {
        let mut body = claimable(id);
        body["letters"] = json!(letters);
        cases.push(body);
    }
    for code in [
        "KX-482-QM",
        "KX-4821234-QM",
        "KX4821QM",
        "QM-4821-KX",
        "KX-48a1-QM",
        "",
    ] {
        let mut body = claimable(id);
        body["code"] = json!(code);
        cases.push(body);
    }
    let mut body = claimable(id);
    body.as_object_mut().unwrap().remove("letters");
    cases.push(body);
    let mut body = backoff(id);
    body.as_object_mut().unwrap().remove("retry_at");
    cases.push(body);
    let session = Uuid::new_v4();
    let mut body = claimed(id, session, &envelope(session, 30));
    body["envelope"] = json!(STANDARD.encode([1; 100]));
    cases.push(body);
    let mut body = claimed(id, session, &envelope(session, 30));
    body.as_object_mut().unwrap().remove("session_id");
    cases.push(body);
    let mut body = claimable(id);
    body["state"] = json!("teleported");
    cases.push(body);
    let mut body = claimable(id);
    body["schema"] = json!("tiaris.other.v1");
    cases.push(body);
    for case in cases {
        let error = validate_reply(status_body(case), Some(id))
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("KX") && !error.contains("4821"), "{error}");
    }
    // A poll answered for another registration is not this registration.
    assert!(validate_reply(status_body(claimable(Uuid::new_v4())), Some(id)).is_err());
}

#[test]
fn refusals_are_classified_by_the_contract() {
    let refused =
        |status, code: &str| -> Result<Reply> { Err(protocol::tests::http_error(status, code)) };
    assert!(matches!(
        classify(
            refused(StatusCode::NOT_FOUND, "nest_setup_registration_not_found"),
            true
        ),
        Step::Gone
    ));
    // Registering into a disabled Manage is retried, never "forgotten".
    assert!(matches!(
        classify(refused(StatusCode::NOT_FOUND, "not_found"), false),
        Step::Retry {
            rate_limited: false
        }
    ));
    for polling in [true, false] {
        assert!(matches!(
            classify(
                refused(StatusCode::GONE, "nest_installer_outdated"),
                polling
            ),
            Step::Outdated
        ));
        assert!(matches!(
            classify(
                refused(StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
                polling
            ),
            Step::Retry { rate_limited: true }
        ));
        assert!(matches!(
            classify(
                refused(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                polling
            ),
            Step::Retry {
                rate_limited: false
            }
        ));
        assert!(matches!(
            classify(Err(anyhow!("send provisioning request")), polling),
            Step::Retry {
                rate_limited: false
            }
        ));
    }
}

#[test]
fn retries_back_off_within_their_bounds() {
    let waits = (1..=12)
        .map(|failures| retry_ticks(failures, false))
        .collect::<Vec<_>>();
    assert_eq!(waits, [1, 2, 4, 8, 16, 32, 60, 60, 60, 60, 60, 60]);
    assert_eq!(retry_ticks(u32::MAX, false), 60);
    assert_eq!(retry_ticks(11, true), 900);
    assert_eq!(retry_ticks(u32::MAX, true), 900);
}

#[test]
fn one_family_answering_is_enough() {
    let id = Uuid::new_v4();
    let network = || -> Result<StatusBody> { Err(anyhow!("send provisioning request")) };
    let gone = || -> Result<StatusBody> {
        Err(protocol::tests::http_error(
            StatusCode::NOT_FOUND,
            "nest_setup_registration_not_found",
        ))
    };
    let answer = || -> Result<StatusBody> { Ok(status_body(claimable(id))) };
    assert!(prefer_answer(network(), answer()).is_ok());
    assert!(prefer_answer(answer(), network()).is_ok());
    assert!(prefer_answer(gone(), answer()).is_ok());
    let refusal = prefer_answer(network(), gone()).err().unwrap();
    assert!(protocol::http_refusal(&refusal).is_some());
    let refusal = prefer_answer(gone(), network()).err().unwrap();
    assert!(protocol::http_refusal(&refusal).is_some());
    assert!(protocol::http_refusal(&prefer_answer(network(), network()).err().unwrap()).is_none());
}

#[test]
fn ipv6_is_used_only_with_a_default_route_and_a_global_address() {
    let default = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n";
    let link_local = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n";
    let rejected = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n";
    let global = "20010db8000000000000000000000010 02 40 00 80     eth0\n";
    let only_link = "fe80000000000000021122fffe334455 02 40 20 80     eth0\n";
    assert!(ipv6_route_present(
        &format!("{link_local}{default}"),
        global
    ));
    assert!(!ipv6_route_present(link_local, global));
    assert!(!ipv6_route_present(rejected, global));
    assert!(!ipv6_route_present(default, only_link));
    assert!(!ipv6_route_present("", ""));
}

#[test]
fn run_store_keeps_its_secrets_private_and_forgets_cleanly() {
    let dir = TempDir::new();
    let store = RunStore::new(dir.0.join("claim"));
    store.prepare().unwrap();
    store.prepare().unwrap();
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir.0.join("claim")), 0o700);
    assert!(store.load_registration().unwrap().is_none());

    let registration = Registration {
        key: SigningKey::from_bytes(&[3; 32]),
        id: Some(Uuid::from_bytes([4; 16])),
    };
    store.save_registration(&registration).unwrap();
    store.save_envelope(&[1; 8192]).unwrap();
    assert_eq!(mode(&dir.0.join("claim").join(REGISTRATION_FILE)), 0o600);
    assert_eq!(mode(&dir.0.join("claim").join(ENVELOPE_FILE)), 0o600);
    let loaded = store.load_registration().unwrap().unwrap();
    assert_eq!(loaded.key.to_bytes(), registration.key.to_bytes());
    assert_eq!(loaded.id, registration.id);
    assert_eq!(store.load_envelope().unwrap().unwrap(), vec![1; 8192]);

    store.forget().unwrap();
    store.forget().unwrap();
    assert!(store.load_registration().unwrap().is_none());
    assert!(store.load_envelope().unwrap().is_none());

    // A damaged registration is forgotten, never trusted.
    fs::write(
        dir.0.join("claim").join(REGISTRATION_FILE),
        b"{\"schema\":1}",
    )
    .unwrap();
    assert!(store.load_registration().unwrap().is_none());
    assert!(!dir.0.join("claim").join(REGISTRATION_FILE).exists());

    // A directory others can read is refused.
    fs::set_permissions(dir.0.join("claim"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(store.prepare().is_err());
}

/// What the fake Manage saw: method, path, signed headers and body, plus the
/// kiosk status published when the request arrived.
#[derive(Clone)]
struct Seen {
    method: HttpMethod,
    path: String,
    headers: HeaderMap,
    body: Bytes,
    screen: Option<Value>,
}

#[derive(Default)]
struct Fake {
    replies: VecDeque<(StatusCode, Value)>,
    seen: Vec<Seen>,
    status_path: Option<PathBuf>,
}

async fn handle(
    State(state): State<Arc<Mutex<Fake>>>,
    method: HttpMethod,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let mut fake = state.lock().unwrap();
    let screen = fake
        .status_path
        .as_ref()
        .and_then(|path| fs::read(path).ok())
        .and_then(|body| serde_json::from_slice(&body).ok());
    fake.seen.push(Seen {
        method,
        path: uri.path().to_string(),
        headers,
        body,
        screen,
    });
    let (status, body) = fake.replies.pop_front().unwrap_or((
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"error_code":"script_ended"}),
    ));
    (status, Json(body))
}

async fn fake_manage(
    replies: Vec<(StatusCode, Value)>,
    status_path: Option<PathBuf>,
) -> (String, Arc<Mutex<Fake>>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Mutex::new(Fake {
        replies: replies.into(),
        status_path,
        ..Default::default()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new()
        .fallback(any(handle))
        .with_state(state.clone());
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (origin, state, handle)
}

/// The exact provisioning request signature, checked like Manage does.
fn assert_signed_by(seen: &Seen, key: &VerifyingKey) {
    let header = |name: &str| {
        seen.headers
            .get(name)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    };
    let canonical = format!(
        "TIARIS-NEST-PROVISIONING-V1\n{}\n{}\n{}\n{}\n{}",
        seen.method.as_str(),
        seen.path,
        header("x-tiaris-timestamp"),
        header("x-tiaris-request-id"),
        hex::encode(Sha256::digest(&seen.body)),
    );
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header("x-tiaris-signature"))
        .unwrap();
    key.verify(
        canonical.as_bytes(),
        &Signature::from_bytes(signature.as_slice().try_into().unwrap()),
    )
    .unwrap();
}

fn registration_key(seen: &Seen) -> VerifyingKey {
    let body: Value = serde_json::from_slice(&seen.body).unwrap();
    let bytes = STANDARD
        .decode(body["public_key"].as_str().unwrap())
        .unwrap();
    VerifyingKey::from_bytes(bytes.as_slice().try_into().unwrap()).unwrap()
}

struct Harness {
    dir: TempDir,
    transport: Transport,
    store: RunStore,
    status: SetupStatusReporter,
    status_path: PathBuf,
    keys: Vec<VerifyingKey>,
    hardware: Hardware,
}

impl Harness {
    fn new(origin: String) -> Self {
        let dir = TempDir::new();
        let status_path = dir.0.join("setup/status.json");
        Self {
            transport: Transport::test(origin),
            store: RunStore::new(dir.0.join("claim")),
            status: SetupStatusReporter::new(Some(status_path.clone())),
            status_path,
            keys: vec![provisioning_key().verifying_key()],
            hardware: Hardware::new("Dell Inc.\u{7}", " PowerEdge T150 ", "none"),
            dir,
        }
    }

    fn context(&self) -> ClaimContext<'_> {
        ClaimContext {
            transport: &self.transport,
            store: &self.store,
            trusted_keys: &self.keys,
            required_origin: ORIGIN,
            status: &self.status,
            hardware: &self.hardware,
            tick: Duration::from_micros(100),
        }
    }

    fn screen(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.status_path).unwrap()).unwrap()
    }
}

#[tokio::test]
async fn generic_iso_registers_is_claimed_and_continues_with_the_existing_session_claim() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let (_, _, inventory, _) = protocol::tests::signed_plan_fixture(
        protocol::INSTALL_PLAN_SCHEMA_V2,
        "TIARIS-NEST-INSTALL-PLAN-V2",
    );
    let dir = TempDir::new();
    let status_path = dir.0.join("setup/status.json");
    let (origin, fake, server) = fake_manage(
        vec![
            refusal(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            (StatusCode::CREATED, claimable(id)),
            (StatusCode::OK, backoff(id)),
            refusal(StatusCode::BAD_GATEWAY, "upstream"),
            (StatusCode::OK, claimed(id, session, &bytes)),
            // The existing flow: the new session is not claimed yet ...
            refusal(StatusCode::UNAUTHORIZED, "unauthorized"),
            // ... so the media secret claims it.
            (
                StatusCode::OK,
                json!({"session_id":session,"state":"awaiting_approval","session_revision":1,
                       "poll_after_seconds":2,"plan":null}),
            ),
        ],
        Some(status_path.clone()),
    )
    .await;
    let mut harness = Harness::new(origin.clone());
    harness.status = SetupStatusReporter::new(Some(status_path.clone()));
    harness.status_path = status_path;

    let result = claim(&harness.context()).await.unwrap();
    assert_eq!(result.bytes, bytes);
    assert_eq!(result.verified.envelope.session_id, session);
    assert_eq!(harness.store.load_envelope().unwrap().unwrap(), bytes);
    assert_eq!(
        harness.store.load_registration().unwrap().unwrap().id,
        Some(id)
    );
    assert_eq!(
        harness.screen()["claim"],
        json!({"state":"claimed","url":"dev.tiaris.com/nest","organization":"Greenfield School"})
    );

    // The existing flow takes over with the handed-over envelope.
    let key = protocol::derive_provisioning_key(&result.verified.envelope.media_secret).unwrap();
    let client = protocol::ProvisioningClient::test_client(origin, session);
    let hardware = inventory::hardware_digest(&inventory).unwrap();
    let (session_state, recovering) =
        recovery::initial_session(&client, &result.verified, &key, &inventory, &hardware)
            .await
            .unwrap();
    assert!(!recovering);
    assert_eq!(session_state.state, "awaiting_approval");
    harness.status.media_verified(ORIGIN);
    assert_eq!(harness.screen()["state"], "checking");
    assert!(harness.screen().get("claim").is_none());

    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    let paths = seen
        .iter()
        .map(|seen| seen.path.as_str())
        .collect::<Vec<_>>();
    let status_path = format!("/v1/agent/nest/setup-registrations/{id}/status");
    assert_eq!(
        paths,
        [
            "/v1/agent/nest/setup-registrations",
            "/v1/agent/nest/setup-registrations",
            status_path.as_str(),
            status_path.as_str(),
            status_path.as_str(),
            &*format!("/v1/agent/nest/provisioning-sessions/{session}/plan"),
            "/v1/agent/nest/provisioning-sessions/claim",
        ]
    );

    // Registration: the contract body, the same key both times, every
    // request signed by it and none carrying a media secret.
    let registration = registration_key(&seen[0]);
    assert_eq!(registration_key(&seen[1]), registration);
    let body: Value = serde_json::from_slice(&seen[1].body).unwrap();
    assert_eq!(
        body,
        json!({"schema":"tiaris.nest.setup-registration.v1",
               "public_key":STANDARD.encode(registration.to_bytes()),
               "setup_claim_protocol":1,
               "installer_release_version":env!("CARGO_PKG_VERSION"),
               "hardware":{"manufacturer":"Dell Inc.","model":"PowerEdge T150","virtualization":"none"}})
    );
    for request in &seen[..5] {
        assert_eq!(request.method, HttpMethod::POST);
        assert_signed_by(request, &registration);
        assert!(
            request
                .headers
                .get("x-tiaris-nest-provisioning-secret")
                .is_none()
        );
    }
    assert_eq!(&seen[2].body[..], b"{}");
    // The existing session claim is signed by the media key and carries the secret.
    assert_signed_by(&seen[6], &key.verifying_key());
    assert!(
        seen[6]
            .headers
            .get("x-tiaris-nest-provisioning-secret")
            .is_some()
    );

    // The screen at each request: connecting, claimable with the code,
    // backoff without it, and still backoff through one failed poll.
    let claims = seen
        .iter()
        .map(|seen| seen.screen.as_ref().map(|screen| screen["claim"].clone()))
        .collect::<Vec<_>>();
    assert_eq!(claims[0], Some(json!({"state":"connecting"})));
    assert_eq!(claims[1], Some(json!({"state":"connecting"})));
    assert_eq!(
        claims[2],
        Some(
            json!({"state":"claimable","letters":LETTERS,"code":CODE,"url":"dev.tiaris.com/nest"})
        )
    );
    assert_eq!(
        claims[3],
        Some(
            json!({"state":"backoff","url":"dev.tiaris.com/nest","retry_at":"2026-11-17T10:00:00Z"})
        )
    );
    assert_eq!(claims[4], claims[3]);
    let screen = seen[2].screen.as_ref().unwrap();
    assert_eq!(screen["state"], "claim");
    assert_eq!(screen["tiaris_host"], "manage.example.test");
    let mut keys = screen
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        ["claim", "schema", "state", "tiaris_host", "updated_at"]
    );
    drop(harness.dir);
}

#[tokio::test]
async fn a_vanished_registration_is_forgotten_and_registered_again_with_a_new_key() {
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let mut fresh = claimable(second);
    fresh["letters"] = json!("PQRT");
    fresh["code"] = json!("PQ-0007-RT");
    let (origin, fake, server) = fake_manage(
        vec![
            (StatusCode::CREATED, claimable(first)),
            refusal(StatusCode::NOT_FOUND, "nest_setup_registration_not_found"),
            (StatusCode::CREATED, fresh),
            (StatusCode::OK, claimed(second, session, &bytes)),
        ],
        None,
    )
    .await;
    let harness = Harness::new(origin);
    let result = claim(&harness.context()).await.unwrap();
    assert_eq!(result.verified.envelope.session_id, session);
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    assert_eq!(seen.len(), 4);
    assert_ne!(registration_key(&seen[0]), registration_key(&seen[2]));
    assert_signed_by(&seen[3], &registration_key(&seen[2]));
    assert!(seen[3].path.contains(&second.to_string()));
}

#[tokio::test]
async fn an_outdated_installer_says_so_keeps_running_and_retries() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let dir = TempDir::new();
    let status_path = dir.0.join("setup/status.json");
    let (origin, fake, server) = fake_manage(
        vec![
            refusal(StatusCode::GONE, "nest_installer_outdated"),
            (StatusCode::CREATED, claimable(id)),
            (StatusCode::OK, claimed(id, session, &bytes)),
        ],
        Some(status_path.clone()),
    )
    .await;
    let mut harness = Harness::new(origin);
    harness.status = SetupStatusReporter::new(Some(status_path.clone()));
    harness.status_path = status_path;
    let started = std::time::Instant::now();
    claim(&harness.context()).await.unwrap();
    // 3600 ticks of 100 µs: the hourly retry, scaled.
    assert!(started.elapsed() >= Duration::from_millis(360));
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    assert_eq!(
        seen[1].screen.as_ref().unwrap()["claim"],
        json!({"state":"outdated"})
    );
    // The same key registers again: the hour did not start a new identity.
    assert_eq!(registration_key(&seen[0]), registration_key(&seen[1]));
}

#[tokio::test]
async fn an_expired_handed_over_envelope_is_a_setup_that_ended() {
    let id = Uuid::new_v4();
    let again = Uuid::new_v4();
    let old = Uuid::new_v4();
    let session = Uuid::new_v4();
    let (origin, fake, server) = fake_manage(
        vec![
            (StatusCode::CREATED, claimed(id, old, &envelope(old, -1))),
            (
                StatusCode::CREATED,
                claimed(again, session, &envelope(session, 30)),
            ),
        ],
        None,
    )
    .await;
    let harness = Harness::new(origin);
    let result = claim(&harness.context()).await.unwrap();
    assert_eq!(result.verified.envelope.session_id, session);
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    assert_eq!(seen.len(), 2);
    assert_ne!(registration_key(&seen[0]), registration_key(&seen[1]));
}

#[tokio::test]
async fn an_unverifiable_envelope_stops_instead_of_installing() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let foreign = protocol::tests::signed_envelope_bytes(
        &SigningKey::from_bytes(&[1; 32]),
        session,
        ORIGIN,
        Utc::now(),
        Utc::now() + chrono::Duration::days(30),
    );
    let mismatched = envelope(Uuid::new_v4(), 30);
    for bytes in [foreign, mismatched] {
        let (origin, _, server) = fake_manage(
            vec![(StatusCode::CREATED, claimed(id, session, &bytes))],
            None,
        )
        .await;
        let harness = Harness::new(origin);
        let error = claim(&harness.context()).await.err().unwrap();
        server.abort();
        assert!(!format!("{error:#}").contains("media_secret"));
        assert!(harness.store.load_envelope().unwrap().is_none());
    }
}

#[tokio::test]
async fn a_restarted_service_continues_this_boots_claim_without_a_new_code() {
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    // Nothing listens: the restart must not need Manage to continue.
    let harness = Harness::new("http://127.0.0.1:9".to_string());
    harness.store.prepare().unwrap();
    harness
        .store
        .save_registration(&Registration {
            key: SigningKey::from_bytes(&[2; 32]),
            id: Some(Uuid::new_v4()),
        })
        .unwrap();
    harness.store.save_envelope(&bytes).unwrap();
    let result = claim(&harness.context()).await.unwrap();
    assert_eq!(result.bytes, bytes);

    // A registration alone is polled, not replaced.
    let id = Uuid::new_v4();
    let (origin, fake, server) =
        fake_manage(vec![(StatusCode::OK, claimed(id, session, &bytes))], None).await;
    let harness = Harness::new(origin);
    harness.store.prepare().unwrap();
    let key = SigningKey::from_bytes(&[2; 32]);
    harness
        .store
        .save_registration(&Registration {
            key: key.clone(),
            id: Some(id),
        })
        .unwrap();
    claim(&harness.context()).await.unwrap();
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].path.ends_with(&format!("{id}/status")));
    assert_signed_by(&seen[0], &key.verifying_key());

    // An expired /run envelope is forgotten and the server registers again.
    let (origin, fake, server) = fake_manage(
        vec![(StatusCode::CREATED, claimed(id, session, &bytes))],
        None,
    )
    .await;
    let harness = Harness::new(origin);
    harness.store.prepare().unwrap();
    harness
        .store
        .save_registration(&Registration {
            key: key.clone(),
            id: Some(id),
        })
        .unwrap();
    harness.store.save_envelope(&envelope(session, -1)).unwrap();
    claim(&harness.context()).await.unwrap();
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    assert_eq!(seen[0].path, "/v1/agent/nest/setup-registrations");
    assert_ne!(registration_key(&seen[0]), key.verifying_key());
}

#[tokio::test]
async fn a_revoked_setup_is_recognised_by_its_vanished_registration() {
    let id = Uuid::new_v4();
    let (origin, _, server) = fake_manage(
        vec![
            refusal(StatusCode::NOT_FOUND, "nest_setup_registration_not_found"),
            refusal(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        ],
        None,
    )
    .await;
    let harness = Harness::new(origin);
    harness.store.prepare().unwrap();
    harness
        .store
        .save_registration(&Registration {
            key: SigningKey::from_bytes(&[2; 32]),
            id: Some(id),
        })
        .unwrap();
    assert!(registration_gone(&harness.context()).await);
    // A transport or server failure is not proof the setup ended.
    assert!(!registration_gone(&harness.context()).await);
    server.abort();
    harness.store.forget().unwrap();
    assert!(!registration_gone(&harness.context()).await);
}
