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
fn run_store_keeps_the_claiming_organization_for_its_session_only() {
    let dir = TempDir::new();
    let store = RunStore::new(dir.0.join("claim"));
    let session = Uuid::from_bytes([5; 16]);
    let other = Uuid::from_bytes([6; 16]);
    assert_eq!(store.load_organization(session), None);

    store.save_organization(session, Some("Greenfield School"));
    let path = dir.0.join("claim").join(ORGANIZATION_FILE);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        store.load_organization(session).as_deref(),
        Some("Greenfield School")
    );
    assert_eq!(store.load_organization(other), None);

    // Whatever the file holds is shown as one bounded line.
    fs::write(&path, format!("{session}\nGreen\u{7}field\nSchool")).unwrap();
    assert_eq!(
        store.load_organization(session).as_deref(),
        Some("GreenfieldSchool")
    );
    fs::write(&path, "not a session\nGreenfield School").unwrap();
    assert_eq!(store.load_organization(session), None);

    store.save_organization(session, Some("Greenfield School"));
    store.save_organization(session, None);
    assert_eq!(store.load_organization(session), None);
    store.save_organization(session, Some("Greenfield School"));
    store.forget_claimed().unwrap();
    assert_eq!(store.load_organization(session), None);
    store.save_organization(session, Some("Greenfield School"));
    store.forget().unwrap();
    assert_eq!(store.load_organization(session), None);
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

/// The tests' tick: one second in production.
const TICK: Duration = Duration::from_micros(100);

/// What the fake Manage saw: method, path, signed headers and body, the
/// kiosk status published when the request arrived, and its answer.
#[derive(Clone)]
struct Seen {
    method: HttpMethod,
    path: String,
    headers: HeaderMap,
    body: Bytes,
    screen: Option<Value>,
    answered: StatusCode,
}

struct Fake {
    replies: VecDeque<(StatusCode, Value)>,
    seen: Vec<Seen>,
    status_path: Option<PathBuf>,
    /// Manage's poll limit, one tick: a registration's poll within it of the
    /// one before is answered `429` with `Retry-After: 1`, without a reply.
    poll_interval: Duration,
    last_poll: std::collections::HashMap<String, std::time::Instant>,
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
    let path = uri.path().to_string();
    let now = std::time::Instant::now();
    let too_fast = path.ends_with("/status")
        && fake
            .last_poll
            .get(&path)
            .is_some_and(|last| now.duration_since(*last) < fake.poll_interval);
    let mut reply_headers = HeaderMap::new();
    let (status, reply) = if too_fast {
        reply_headers.insert("retry-after", "1".parse().unwrap());
        refusal(StatusCode::TOO_MANY_REQUESTS, "nest_setup_poll_too_fast")
    } else {
        if path.ends_with("/status") {
            fake.last_poll.insert(path.clone(), now);
        }
        fake.replies.pop_front().unwrap_or((
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error_code":"script_ended"}),
        ))
    };
    fake.seen.push(Seen {
        method,
        path,
        headers,
        body,
        screen,
        answered: status,
    });
    (status, reply_headers, Json(reply))
}

async fn fake_manage(
    replies: Vec<(StatusCode, Value)>,
    status_path: Option<PathBuf>,
) -> (String, Arc<Mutex<Fake>>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Mutex::new(Fake {
        replies: replies.into(),
        seen: Vec::new(),
        status_path,
        poll_interval: TICK,
        last_poll: Default::default(),
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
            tick: TICK,
            starts_installed_at: None,
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

#[test]
fn every_installed_nest_is_offered_for_a_claim_before_it_starts() {
    use RetainedChoice::*;
    let envelope = |current, completed| Some(RetainedEnvelope { current, completed });
    let no_entry = || false;
    let entry = || true;
    let unasked = || -> bool { panic!("a usable envelope never needs a boot entry") };
    // A completed installation: a claim first, then its envelope starts it,
    // whether or not the old setup window is open.
    assert_eq!(
        retained_choice(envelope(true, Some(true)), unasked),
        StartRetained
    );
    assert_eq!(
        retained_choice(envelope(false, Some(true)), unasked),
        StartRetained
    );
    // An interrupted installation resumes while its window is open (and
    // Management has not closed it) and is claimed again once it ended.
    assert_eq!(
        retained_choice(envelope(true, Some(false)), unasked),
        Resume
    );
    assert_eq!(retained_choice(envelope(true, None), unasked), Resume);
    assert_eq!(
        retained_choice(envelope(false, Some(false)), unasked),
        Claim
    );
    // No usable envelope (every Nest a personalized ISO installed): the
    // installed Nest's UEFI entry starts it after the claim screen; without
    // one the claim screen stays.
    assert_eq!(retained_choice(None, entry), StartBootEntry);
    assert_eq!(
        retained_choice(envelope(false, None), entry),
        StartBootEntry
    );
    assert_eq!(retained_choice(None, no_entry), Claim);
    assert_eq!(retained_choice(envelope(false, None), no_entry), Claim);
}

#[test]
fn the_start_deadline_survives_a_service_restart() {
    let dir = TempDir::new();
    let store = RunStore::new(dir.0.join("claim"));
    let wait = chrono::Duration::minutes(10);
    let first = Utc::now();
    let deadline = store.starts_installed_at(first, wait).unwrap();
    assert_eq!(deadline, first + wait);
    let path = dir.0.join("claim").join(STARTS_INSTALLED_FILE);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // A restarted service, minutes later and after forgetting a vanished
    // registration, keeps the first claim screen's deadline.
    store.forget().unwrap();
    let later = first + chrono::Duration::minutes(4);
    assert_eq!(store.starts_installed_at(later, wait).unwrap(), deadline);
    let past = first + chrono::Duration::minutes(12);
    assert_eq!(store.starts_installed_at(past, wait).unwrap(), deadline);
    // A damaged or implausibly late deadline starts the wait again.
    fs::write(&path, b"soon").unwrap();
    assert_eq!(
        store.starts_installed_at(later, wait).unwrap(),
        later + wait
    );
    fs::write(&path, (later + chrono::Duration::hours(2)).to_rfc3339()).unwrap();
    assert_eq!(
        store.starts_installed_at(later, wait).unwrap(),
        later + wait
    );
    // A claimed setup that ended gives the installed Nest its full wait again.
    store.forget_claimed().unwrap();
    assert!(!path.exists());
    let after = later + chrono::Duration::minutes(9);
    assert_eq!(
        store.starts_installed_at(after, wait).unwrap(),
        after + wait
    );
}

#[tokio::test]
async fn an_unclaimed_nest_starts_the_installed_one_at_its_deadline() {
    let id = Uuid::new_v4();
    let dir = TempDir::new();
    let status_path = dir.0.join("setup/status.json");
    let (origin, fake, server) = fake_manage(
        vec![
            (StatusCode::CREATED, claimable(id)),
            (StatusCode::OK, backoff(id)),
        ],
        Some(status_path.clone()),
    )
    .await;
    let mut harness = Harness::new(origin);
    harness.status = SetupStatusReporter::new(Some(status_path.clone()));
    harness.status_path = status_path;
    let deadline = room_from_now();
    let mut context = harness.context();
    context.starts_installed_at = Some(deadline);
    let started = std::time::Instant::now();
    assert!(claim_until(&context, deadline).await.unwrap().is_none());
    assert!(started.elapsed() >= ROOM - Duration::from_millis(50));
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    let at = json!(deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    // Every waiting state says when the installed Nest starts.
    assert_eq!(
        seen[0].screen.as_ref().unwrap()["claim"]["state"],
        "connecting"
    );
    assert_eq!(
        seen[0].screen.as_ref().unwrap()["claim"]["starts_installed_at"],
        at
    );
    assert_eq!(
        seen[1].screen.as_ref().unwrap()["claim"]["state"],
        "claimable"
    );
    assert_eq!(
        seen[1].screen.as_ref().unwrap()["claim"]["starts_installed_at"],
        at
    );
    assert_eq!(
        seen[2].screen.as_ref().unwrap()["claim"]["state"],
        "backoff"
    );
    assert_eq!(
        seen[2].screen.as_ref().unwrap()["claim"]["starts_installed_at"],
        at
    );

    // A network that is down does not stop the clock.
    let harness = Harness::new("http://127.0.0.1:9".to_string());
    let deadline = Utc::now() + chrono::Duration::milliseconds(100);
    assert!(
        claim_until(&harness.context(), deadline)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_claim_before_the_deadline_wins() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let (origin, _, server) = fake_manage(
        vec![
            (StatusCode::CREATED, claimable(id)),
            (StatusCode::OK, claimed(id, session, &bytes)),
        ],
        None,
    )
    .await;
    let harness = Harness::new(origin);
    let deadline = Utc::now() + chrono::Duration::minutes(10);
    let mut context = harness.context();
    context.starts_installed_at = Some(deadline);
    let claimed = claim_until(&context, deadline).await.unwrap().unwrap();
    server.abort();
    assert_eq!(claimed.bytes, bytes);
    assert_eq!(claimed.verified.envelope.session_id, session);
    // The claimed screen no longer announces a start.
    assert!(
        harness.screen()["claim"]
            .get("starts_installed_at")
            .is_none()
    );

    // A claim this boot already holds wins after a restart, even past the
    // deadline.
    let late = Utc::now() - chrono::Duration::seconds(1);
    let claimed = claim_until(&harness.context(), late)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed.bytes, bytes);
}

fn installed_entry() -> Installed {
    Installed::BootEntry(PathBuf::from("/dev/nvme0n1p2"))
}

/// What `claim_installed` asked the injected start to do.
type Starts = Arc<Mutex<Vec<String>>>;

fn recording_start(
    starts: &Starts,
    result: fn() -> Result<()>,
) -> impl FnOnce(Installed) -> std::future::Ready<Result<()>> {
    let starts = starts.clone();
    move |installed| {
        starts.lock().unwrap().push(match installed {
            Installed::Retained(claimed) => {
                format!("retained {}", claimed.verified.envelope.session_id)
            }
            Installed::BootEntry(esp) => format!("boot entry {}", esp.display()),
        });
        std::future::ready(result())
    }
}

#[tokio::test]
async fn an_unclaimed_server_starts_its_installed_nest_with_the_chosen_way_at_the_deadline() {
    let id = Uuid::new_v4();
    let (origin, _, server) = fake_manage(vec![(StatusCode::CREATED, claimable(id))], None).await;
    let harness = Harness::new(origin);
    // The deadline this boot already set has passed.
    harness
        .store
        .starts_installed_at(
            Utc::now() - chrono::Duration::minutes(11),
            chrono::Duration::minutes(10),
        )
        .unwrap();
    let starts = Starts::default();
    let mut context = harness.context();
    let outcome = claim_installed(
        &mut context,
        installed_entry(),
        recording_start(&starts, || Ok(())),
    )
    .await
    .unwrap();
    assert!(outcome.is_none());
    assert_eq!(*starts.lock().unwrap(), ["boot entry /dev/nvme0n1p2"]);

    // With a retained envelope, the completed-install path gets that envelope.
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let retained = Installed::Retained(Box::new(Claimed {
        verified: protocol::verify_envelope_bytes(&bytes, &harness.keys, ORIGIN).unwrap(),
        bytes,
    }));
    let starts = Starts::default();
    assert!(
        claim_installed(&mut context, retained, recording_start(&starts, || Ok(())))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(*starts.lock().unwrap(), [format!("retained {session}")]);
    server.abort();
}

#[tokio::test]
async fn a_server_claimed_before_the_deadline_never_starts_its_installed_nest() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let (origin, _, server) = fake_manage(
        vec![
            (StatusCode::CREATED, claimable(id)),
            (StatusCode::OK, claimed(id, session, &bytes)),
        ],
        None,
    )
    .await;
    let harness = Harness::new(origin);
    let starts = Starts::default();
    let mut context = harness.context();
    let claimed = claim_installed(
        &mut context,
        installed_entry(),
        recording_start(&starts, || Ok(())),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(claimed.verified.envelope.session_id, session);
    assert!(starts.lock().unwrap().is_empty());
    // After a restart of the service, past the deadline, this boot's claim
    // still wins.
    harness
        .store
        .starts_installed_at(
            Utc::now() - chrono::Duration::minutes(11),
            chrono::Duration::minutes(10),
        )
        .unwrap();
    let claimed = claim_installed(
        &mut context,
        installed_entry(),
        recording_start(&starts, || Ok(())),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(claimed.bytes, bytes);
    assert!(starts.lock().unwrap().is_empty());
    server.abort();
}

#[tokio::test]
async fn an_installed_nest_that_cannot_start_leaves_the_claim_screen_without_a_deadline() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let dir = TempDir::new();
    let status_path = dir.0.join("setup/status.json");
    let (origin, fake, server) = fake_manage(
        vec![
            (StatusCode::CREATED, claimable(id)),
            (StatusCode::OK, claimable(id)),
            (StatusCode::OK, claimed(id, session, &bytes)),
        ],
        Some(status_path.clone()),
    )
    .await;
    let mut harness = Harness::new(origin);
    harness.status = SetupStatusReporter::new(Some(status_path.clone()));
    harness.status_path = status_path;
    harness
        .store
        .starts_installed_at(
            Utc::now() - chrono::Duration::minutes(11),
            chrono::Duration::minutes(10),
        )
        .unwrap();
    let starts = Starts::default();
    let mut context = harness.context();
    let claimed = claim_installed(
        &mut context,
        installed_entry(),
        recording_start(&starts, || {
            Err(anyhow!(
                "installed UEFI systemd-boot entry is missing or ambiguous"
            ))
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(claimed.verified.envelope.session_id, session);
    assert_eq!(starts.lock().unwrap().len(), 1);
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    // The claim screen after the failed start announces no start.
    let last = seen.last().unwrap().screen.as_ref().unwrap();
    assert_eq!(last["claim"]["state"], "claimable");
    assert!(last["claim"].get("starts_installed_at").is_none());
}

#[tokio::test]
async fn a_claimed_setup_that_ended_gives_the_installed_nest_its_full_wait_again() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let (origin, _, server) = fake_manage(vec![], None).await;
    let harness = Harness::new(origin);
    // Claimed at minute 9, then the setup ended: this boot's envelope expired
    // and the old deadline has passed.
    harness.store.prepare().unwrap();
    harness
        .store
        .save_registration(&Registration {
            key: SigningKey::from_bytes(&[2; 32]),
            id: Some(id),
        })
        .unwrap();
    harness.store.save_envelope(&envelope(session, 0)).unwrap();
    harness
        .store
        .starts_installed_at(
            Utc::now() - chrono::Duration::minutes(11),
            chrono::Duration::minutes(10),
        )
        .unwrap();
    let starts = Starts::default();
    let mut context = harness.context();
    let before = Utc::now();
    // Manage is unreachable here, so the claim screen simply waits.
    let waited = tokio::time::timeout(
        Duration::from_millis(300),
        claim_installed(
            &mut context,
            installed_entry(),
            recording_start(&starts, || Ok(())),
        ),
    )
    .await;
    assert!(waited.is_err());
    assert!(starts.lock().unwrap().is_empty());
    let deadline = context.starts_installed_at.unwrap();
    assert!(deadline >= before + chrono::Duration::minutes(START_INSTALLED_AFTER_MINUTES));
    server.abort();
}

#[test]
fn only_managements_refusal_of_a_closed_session_ends_a_generic_setup() {
    use protocol::tests::manage_refusal;
    // Manage's plan poll for a revoked, superseded or expired session, and its
    // claim of one.
    for closed in [
        manage_refusal(StatusCode::CONFLICT, None),
        manage_refusal(StatusCode::CONFLICT, Some("provisioning_session_expired")),
    ] {
        assert!(protocol::closed_session_refusal(&closed));
        let ended = ended_if_closed(true, closed);
        assert!(ended.downcast_ref::<SetupEnded>().is_some());
        // The personalized path is unchanged.
        let closed = manage_refusal(StatusCode::CONFLICT, None);
        assert!(
            ended_if_closed(false, closed)
                .downcast_ref::<SetupEnded>()
                .is_none()
        );
    }
    for open in [
        manage_refusal(StatusCode::CONFLICT, Some("provisioning_recovery_required")),
        manage_refusal(StatusCode::CONFLICT, Some("media_already_claimed")),
        manage_refusal(StatusCode::UNAUTHORIZED, None),
        manage_refusal(StatusCode::FORBIDDEN, None),
        manage_refusal(StatusCode::NOT_FOUND, None),
        manage_refusal(StatusCode::SERVICE_UNAVAILABLE, None),
        anyhow!("send provisioning request"),
    ] {
        assert!(!protocol::closed_session_refusal(&open));
        assert!(
            ended_if_closed(true, open)
                .downcast_ref::<SetupEnded>()
                .is_none()
        );
    }
}

#[test]
fn the_organization_name_is_display_text_that_never_refuses_a_claim() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let organization = |name: Option<Value>| {
        let mut body = claimed(id, session, &bytes);
        match name {
            Some(name) => body["organization_name"] = name,
            None => {
                body.as_object_mut().unwrap().remove("organization_name");
            }
        }
        match validate_reply(status_body(body), Some(id)).unwrap().answer {
            Answer::Claimed {
                organization,
                envelope,
                ..
            } => {
                assert_eq!(envelope, bytes);
                organization
            }
            _ => panic!("a claimed reply stays claimed"),
        }
    };
    // Manage accepts names of up to 255 characters: cut to 80.
    let long = "G".repeat(255);
    assert_eq!(
        organization(Some(json!(long))),
        Some("G".repeat(MAX_DISPLAY_CHARS))
    );
    assert_eq!(
        organization(Some(json!(" Green\u{7}field\nSchool "))),
        Some("GreenfieldSchool".to_string())
    );
    assert_eq!(organization(None), None);
    assert_eq!(organization(Some(json!(""))), None);
    assert_eq!(organization(Some(json!("\u{7}  "))), None);
    assert_eq!(organization(Some(Value::Null)), None);
}

#[tokio::test]
async fn claimed_by_is_shown_only_after_the_envelope_verified() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let mut nameless = claimed(id, session, &bytes);
    nameless
        .as_object_mut()
        .unwrap()
        .remove("organization_name");
    let mut long = claimed(id, session, &bytes);
    long["organization_name"] = json!(format!("Green\u{7}field {}", "x".repeat(250)));
    let foreign = protocol::tests::signed_envelope_bytes(
        &SigningKey::from_bytes(&[1; 32]),
        session,
        ORIGIN,
        Utc::now(),
        Utc::now() + chrono::Duration::days(30),
    );
    // A missing name: no claimed screen, the setup goes straight on.
    // A long name with a control character: shown cleaned and cut.
    // An unverifiable envelope: never "Claimed by".
    for (reply, verifies, shown) in [
        (nameless, true, None),
        (
            long,
            true,
            Some(format!("Greenfield {}", "x".repeat(MAX_DISPLAY_CHARS - 11))),
        ),
        (claimed(id, session, &foreign), false, None),
    ] {
        let (origin, _, server) = fake_manage(
            vec![
                (StatusCode::CREATED, claimable(id)),
                (StatusCode::OK, reply),
            ],
            None,
        )
        .await;
        let harness = Harness::new(origin);
        let result = claim(&harness.context()).await;
        server.abort();
        assert_eq!(result.is_ok(), verifies);
        let screen = harness.screen()["claim"].clone();
        match shown {
            Some(name) => {
                assert_eq!(screen["state"], "claimed");
                assert_eq!(screen["organization"], json!(name));
            }
            None => assert_eq!(screen["state"], "claimable"),
        }
    }
}

#[test]
fn a_claim_seen_on_either_family_wins() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let waiting = || -> Result<StatusBody> { Ok(status_body(claimable(id))) };
    let taken = || -> Result<StatusBody> { Ok(status_body(claimed(id, session, &bytes))) };
    assert_eq!(prefer_answer(waiting(), taken()).unwrap().state, "claimed");
    assert_eq!(prefer_answer(taken(), waiting()).unwrap().state, "claimed");
    assert_eq!(
        prefer_answer(waiting(), waiting()).unwrap().state,
        "claimable"
    );
}

#[tokio::test]
async fn a_claim_that_lands_just_before_the_deadline_wins() {
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let (origin, fake, server) = fake_manage(
        vec![
            (StatusCode::CREATED, claimable(id)),
            // Claimed while the loop waits for its next poll.
            (StatusCode::OK, claimed(id, session, &bytes)),
        ],
        None,
    )
    .await;
    let mut harness = Harness::new(origin);
    // Polls far apart: the deadline comes before the next one.
    let deadline = room_from_now();
    let mut context = harness.context();
    context.tick = Duration::from_secs(5);
    context.starts_installed_at = Some(deadline);
    let claimed = claim_until(&context, deadline).await.unwrap().unwrap();
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    assert_eq!(claimed.bytes, bytes);
    assert_eq!(seen.len(), 2);
    assert!(seen[1].path.ends_with(&format!("{id}/status")));
    assert_eq!(harness.store.load_envelope().unwrap().unwrap(), bytes);

    // Still unclaimed at the deadline: the installed Nest starts.
    let (origin, fake, server) = fake_manage(
        vec![
            (StatusCode::CREATED, claimable(id)),
            (StatusCode::OK, claimable(id)),
        ],
        None,
    )
    .await;
    harness = Harness::new(origin);
    let deadline = room_from_now();
    let mut context = harness.context();
    context.tick = Duration::from_secs(5);
    assert!(claim_until(&context, deadline).await.unwrap().is_none());
    assert_eq!(fake.lock().unwrap().seen.len(), 2);
    server.abort();
}

#[tokio::test]
async fn start_over_without_a_reboot_forgets_this_boots_claim_and_registers_again() {
    let old_id = Uuid::new_v4();
    let new_id = Uuid::new_v4();
    let closed = Uuid::new_v4();
    let (origin, fake, server) =
        fake_manage(vec![(StatusCode::CREATED, claimable(new_id))], None).await;
    let harness = Harness::new(origin);
    // This boot claimed the setup that STATE resumed; it is still current.
    harness.store.prepare().unwrap();
    let old_key = SigningKey::from_bytes(&[2; 32]);
    harness
        .store
        .save_registration(&Registration {
            key: old_key.clone(),
            id: Some(old_id),
        })
        .unwrap();
    harness.store.save_envelope(&envelope(closed, 30)).unwrap();
    // A claim of another setup is kept.
    forget_closed_run_claim(&harness.context(), Uuid::new_v4()).unwrap();
    assert!(harness.store.load_envelope().unwrap().is_some());
    // The refused resume forgets this boot's claim of that setup.
    forget_closed_run_claim(&harness.context(), closed).unwrap();
    assert!(harness.store.load_envelope().unwrap().is_none());
    assert!(harness.store.load_registration().unwrap().is_none());
    // Polls far apart: the claim screen stays while the test looks.
    let mut context = harness.context();
    context.tick = Duration::from_secs(5);
    let waited = tokio::time::timeout(ROOM, claim(&context)).await;
    assert!(waited.is_err());
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    // A new registration with a new key, and the claim screen shows its code.
    assert_eq!(seen[0].path, "/v1/agent/nest/setup-registrations");
    assert_ne!(registration_key(&seen[0]), old_key.verifying_key());
    assert_eq!(
        harness.store.load_registration().unwrap().unwrap().id,
        Some(new_id)
    );
    assert_eq!(harness.screen()["claim"]["state"], "claimable");
    assert_eq!(harness.screen()["claim"]["letters"], LETTERS);
}

/// Room for one step on a busy test machine. Only lower bounds of time are
/// certain there (a wait lasts at least its length); every upper bound a test
/// needs (a poll before the deadline, a deadline's poll within Manage's poll
/// limit of the one before) gets this much, never a few milliseconds.
const ROOM: Duration = Duration::from_secs(1);

fn room_from_now() -> DateTime<Utc> {
    Utc::now() + chrono::Duration::from_std(ROOM).unwrap()
}

/// The fake Manage just answered a regular poll of `id`.
fn polled_just_now(fake: &Arc<Mutex<Fake>>, id: Uuid, interval: Duration) {
    let mut fake = fake.lock().unwrap();
    fake.poll_interval = interval;
    fake.last_poll.insert(
        format!("{REGISTRATIONS_PATH}/{id}/status"),
        std::time::Instant::now(),
    );
}

fn saved_registration(harness: &Harness, id: Uuid) {
    harness.store.prepare().unwrap();
    harness
        .store
        .save_registration(&Registration {
            key: SigningKey::from_bytes(&[3; 32]),
            id: Some(id),
        })
        .unwrap();
}

#[tokio::test]
async fn a_claim_in_the_deadlines_last_second_is_not_lost_to_the_poll_limit() {
    // A regular poll was answered a moment before the deadline, the
    // administrator claimed right after it, and the deadline's poll comes
    // within the same second: Manage answers `429`, which is no answer.
    // Manage's limit is one tick here: the deadline's poll lands within it
    // (ROOM), and its retry waits the tick `Retry-After` names.
    let id = Uuid::new_v4();
    let session = Uuid::new_v4();
    let bytes = envelope(session, 30);
    let (origin, fake, server) =
        fake_manage(vec![(StatusCode::OK, claimed(id, session, &bytes))], None).await;
    let harness = Harness::new(origin);
    saved_registration(&harness, id);
    let mut context = harness.context();
    context.tick = ROOM;
    polled_just_now(&fake, id, context.tick);
    let taken = last_poll(&context).await.unwrap().unwrap();
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    assert_eq!(taken.verified.envelope.session_id, session);
    assert_eq!(
        seen.iter().map(|seen| seen.answered).collect::<Vec<_>>(),
        [StatusCode::TOO_MANY_REQUESTS, StatusCode::OK]
    );

    // The same through the deadline: the loop's regular poll lands before
    // it, the claim right after. The regular poll is the loop's first request
    // (the registration is known) and its answer puts the next one far past
    // the deadline. Polled at once, deadline at ROOM, Manage's limit (one
    // tick) lifts at 2 × ROOM: the regular poll has ROOM to land before the
    // deadline, and the deadline's poll ROOM to land within the limit.
    let mut slow = claimable(id);
    slow["poll_after_seconds"] = json!(60);
    let (origin, fake, server) = fake_manage(
        vec![
            (StatusCode::OK, slow),
            (StatusCode::OK, claimed(id, session, &bytes)),
        ],
        None,
    )
    .await;
    let harness = Harness::new(origin);
    saved_registration(&harness, id);
    let mut context = harness.context();
    context.tick = ROOM * 2;
    fake.lock().unwrap().poll_interval = context.tick;
    let taken = claim_until(&context, room_from_now())
        .await
        .unwrap()
        .unwrap();
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    assert_eq!(taken.verified.envelope.session_id, session);
    assert!(
        seen.iter()
            .all(|seen| seen.path == format!("{REGISTRATIONS_PATH}/{id}/status"))
    );
    assert_eq!(
        seen.iter().map(|seen| seen.answered).collect::<Vec<_>>(),
        [
            StatusCode::OK,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::OK
        ]
    );
}

#[tokio::test]
async fn a_deadline_without_an_answer_asks_a_bounded_number_of_times() {
    let id = Uuid::new_v4();
    let (origin, fake, server) = fake_manage(vec![], None).await;
    let harness = Harness::new(origin);
    saved_registration(&harness, id);
    // Manage never lets a poll through: the installed Nest still starts.
    polled_just_now(&fake, id, Duration::from_secs(3600));
    assert!(last_poll(&harness.context()).await.unwrap().is_none());
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    assert_eq!(seen.len(), DECIDING_POLL_ATTEMPTS as usize);
    assert!(
        seen.iter()
            .all(|seen| seen.answered == StatusCode::TOO_MANY_REQUESTS)
    );

    // No network at all: asked again too, and then the Nest starts.
    let harness = Harness::new("http://127.0.0.1:9".to_string());
    saved_registration(&harness, id);
    assert!(last_poll(&harness.context()).await.unwrap().is_none());
}

#[tokio::test]
async fn a_poll_refused_as_too_fast_never_reads_as_a_registration_still_there() {
    let id = Uuid::new_v4();
    let (origin, fake, server) = fake_manage(
        vec![refusal(
            StatusCode::NOT_FOUND,
            "nest_setup_registration_not_found",
        )],
        None,
    )
    .await;
    let harness = Harness::new(origin);
    saved_registration(&harness, id);
    let mut context = harness.context();
    context.tick = ROOM;
    polled_just_now(&fake, id, context.tick);
    assert!(registration_gone(&context).await);
    let seen = fake.lock().unwrap().seen.clone();
    server.abort();
    assert_eq!(
        seen.iter().map(|seen| seen.answered).collect::<Vec<_>>(),
        [StatusCode::TOO_MANY_REQUESTS, StatusCode::NOT_FOUND]
    );
}

#[test]
fn a_retained_envelope_from_the_future_waits_for_the_clock_instead_of_claiming() {
    let keys = [provisioning_key().verifying_key()];
    let session = Uuid::new_v4();
    let now = Utc::now();
    let signed = |key: &SigningKey, origin: &str, issued, expires| {
        protocol::tests::signed_envelope_bytes(key, session, origin, issued, expires)
    };
    let not_yet = |result: Result<Option<VerifiedEnvelope>>| match result {
        Err(error) => error.is::<protocol::EnvelopeIssuedInFuture>(),
        Ok(_) => false,
    };
    // Issued more than five minutes ahead of this clock (it is behind): the
    // run fails and the service retries; nothing is claimed again.
    let ahead = now + chrono::Duration::hours(2);
    let future = signed(
        &provisioning_key(),
        ORIGIN,
        ahead,
        ahead + chrono::Duration::days(30),
    );
    assert!(not_yet(verify_retained(&future, &keys, ORIGIN)));
    // Within the five-minute allowance it verifies.
    let soon = now + chrono::Duration::minutes(4);
    let allowed = signed(
        &provisioning_key(),
        ORIGIN,
        soon,
        soon + chrono::Duration::days(30),
    );
    assert!(verify_retained(&allowed, &keys, ORIGIN).unwrap().is_some());
    // Any other fault keeps today's answer: ignored, claimed again.
    let other = SigningKey::from_bytes(&[4; 32]);
    let untrusted = signed(&other, ORIGIN, ahead, ahead + chrono::Duration::days(30));
    assert!(
        verify_retained(&untrusted, &keys, ORIGIN)
            .unwrap()
            .is_none()
    );
    let elsewhere = "https://other.example.test";
    let foreign = signed(
        &provisioning_key(),
        elsewhere,
        ahead,
        ahead + chrono::Duration::days(30),
    );
    assert!(verify_retained(&foreign, &keys, ORIGIN).unwrap().is_none());
    let mut tampered = future.clone();
    let at = tampered
        .windows(7)
        .position(|window| window == b"0.2.141")
        .unwrap();
    tampered[at + 6] = b'2';
    assert!(verify_retained(&tampered, &keys, ORIGIN).unwrap().is_none());
    let too_long = signed(
        &provisioning_key(),
        ORIGIN,
        ahead,
        ahead + chrono::Duration::days(60),
    );
    assert!(verify_retained(&too_long, &keys, ORIGIN).unwrap().is_none());
    // An ended window (or a clock far ahead) verifies; `retained_choice`
    // decides, exactly as before.
    let ended = envelope(session, 0);
    let verified = verify_retained(&ended, &keys, ORIGIN).unwrap().unwrap();
    assert!(protocol::require_current_envelope(&verified).is_err());
}

#[test]
fn a_completed_installation_whose_envelope_is_ahead_of_the_clock_still_starts() {
    let keys = [provisioning_key().verifying_key()];
    let session = Uuid::new_v4();
    let ahead = Utc::now() + chrono::Duration::hours(2);
    let future = protocol::tests::signed_envelope_bytes(
        &provisioning_key(),
        session,
        ORIGIN,
        ahead,
        ahead + chrono::Duration::days(30),
    );
    let behind = || match verify_retained(&future, &keys, ORIGIN) {
        Err(error) => error,
        Ok(_) => panic!("an envelope ahead of the clock verified"),
    };
    let asked = |completed| {
        move |asked: Uuid| {
            assert_eq!(asked, session);
            Ok(completed)
        }
    };
    // Completed: no usable envelope, so the claim screen with its deadline
    // and then the installed Nest's boot entry, as `retained_choice` decides.
    ahead_of_clock(behind(), asked(true)).unwrap();
    assert_eq!(
        retained_choice(None, || true),
        RetainedChoice::StartBootEntry
    );
    // Incomplete or without durable state: the run fails and is retried.
    let error = ahead_of_clock(behind(), asked(false)).unwrap_err();
    assert!(error.is::<protocol::EnvelopeIssuedInFuture>());
    // A STATE that cannot be read fails the run too.
    let unreadable = ahead_of_clock(behind(), |_| Err(anyhow::anyhow!("STATE")));
    assert!(unreadable.is_err());
    // Any other error is never treated as the clock's.
    let other = ahead_of_clock(anyhow::anyhow!("other"), |_| -> Result<bool> {
        panic!("STATE is not asked")
    });
    assert!(other.is_err());
}
