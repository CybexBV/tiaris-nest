use super::*;
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::any,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

fn fixture() -> (Value, protocol::VerifiedEnvelope, NestProvisioningInventory) {
    let (mut plan, envelope, inventory, signing) = protocol::tests::signed_plan_fixture();
    let release: Value = serde_json::from_str(include_str!(
        "../../../protocol/fixtures/nest-appliance-v3.json"
    ))
    .unwrap();
    plan["schema"] = protocol::INSTALL_PLAN_SCHEMA_V3.into();
    plan["base_os"] = "nixos".into();
    plan["base_os_version"] = "26.05".into();
    plan["package_delivery"] = "system-closure-v1".into();
    plan["appliance_release"] = release["appliance_release"].clone();
    plan["package_transport_url"] = release["appliance_release"]["system_closure"]["url"].clone();
    // Model a server-acknowledged plan after its short approval window passed.
    plan["issued_at"] = json!(chrono::Utc::now() - chrono::Duration::hours(2));
    plan["expires_at"] = json!(chrono::Utc::now() - chrono::Duration::minutes(100));
    (
        protocol::tests::resign_plan(plan, "TIARIS-NEST-INSTALL-PLAN-V3", &signing),
        protocol::VerifiedEnvelope {
            envelope,
            signing_key: signing.verifying_key(),
        },
        inventory,
    )
}

fn response(plan: &Value, state: &str) -> protocol::AgentSessionResponse {
    serde_json::from_value(
        json!({"session_id":plan["session_id"],"state":state,"session_revision":3,
        "poll_after_seconds":2,"plan":plan}),
    )
    .unwrap()
}

#[test]
fn expired_retained_media_boots_completed_identity_without_network_or_closure() {
    let (plan, mut verified, mut inventory) = fixture();
    verified.envelope.issued_at = chrono::Utc::now() - chrono::Duration::days(2);
    verified.envelope.expires_at = verified.envelope.issued_at + chrono::Duration::hours(24);
    // A completed boot must not need the original install-time network.
    inventory.ethernet_interfaces[0].link_up = false;
    inventory.ethernet_interfaces[0].addresses.clear();
    inventory.ethernet_interfaces[0].gateway = None;
    let key = SigningKey::from_bytes(&[81; 32]);
    let mut durable = super::super::DurableProvisioningState {
        schema: "tiaris.nest.provisioning-state.v1".into(),
        session_id: verified.envelope.session_id,
        plan: serde_json::from_value(plan).unwrap(),
        manage_origin: verified.envelope.manage_origin.clone(),
        management_signing_public_key_b64: protocol::standard_base64(
            verified.signing_key.to_bytes(),
        ),
        device_private_key_b64: protocol::standard_base64(key.to_bytes()),
        device_public_key_b64: protocol::standard_base64(key.verifying_key().to_bytes()),
        device_public_key_fingerprint: protocol::sha256_hex(key.verifying_key().to_bytes()),
        next_event_sequence: 9,
        identity_active: true,
        installation_complete: true,
        updated_at: chrono::Utc::now(),
    };
    assert!(durable_plan(&durable, &verified, &inventory).is_ok());
    // One reported restart without a verified UEFI BootNext (production #20).
    durable.next_event_sequence = 10;
    assert!(durable_plan(&durable, &verified, &inventory).is_ok());
    durable.next_event_sequence = 11;
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
    durable.next_event_sequence = 9;
    assert!(protocol::require_current_envelope(&verified).is_err()); // no new install
    durable.installation_complete = false;
    durable.next_event_sequence = 6;
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
    verified.envelope.issued_at = chrono::Utc::now();
    verified.envelope.expires_at = verified.envelope.issued_at + chrono::Duration::hours(1);
    for sequence in 7..=9 {
        durable.next_event_sequence = sequence;
        assert!(
            durable_plan(&durable, &verified, &inventory).is_ok(),
            "resume seq{sequence}"
        );
    }
    durable.next_event_sequence = 10;
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
    durable.installation_complete = true;
    durable.next_event_sequence = 9;
    durable.identity_active = false;
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
    durable.identity_active = true;
    inventory.disks[0].path = "/dev/sdz".into();
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
    inventory.disks[0].path = durable.plan.target_disk.path.clone();
    durable.plan.target_disk.path = "/dev/sdz".into();
    assert!(durable_plan(&durable, &verified, &inventory).is_err());
}

#[test]
fn acknowledged_plan_recovers_missing_state_across_each_interruption_boundary() {
    let (plan, verified, mut inventory) = fixture();
    // Poll returns the same authority whether GPT is empty, STATE is unformatted,
    // or mkfs finished before the random permanent key was durably persisted.
    for boundary in [
        "ack1 accepted",
        "ack2 accepted",
        "GPT erased",
        "STATE partition created",
        "STATE formatted",
    ] {
        inventory.kernel_version = boundary.to_owned(); // volatile inventory may change
        let recovered = active_plan(&response(&plan, "installing"), &verified, &inventory).unwrap();
        assert_eq!(recovered.plan_sha256, plan["plan_sha256"]);
    }
    assert!(
        protocol::verify_install_plan(plan, &verified.signing_key, &verified.envelope, &inventory)
            .is_err()
    );
}

#[test]
fn missing_state_never_authorizes_foreign_media_disk_or_terminal_sessions() {
    let (plan, mut verified, inventory) = fixture();
    for state in [
        "created",
        "awaiting_approval",
        "failed",
        "revoked",
        "expired",
        "ready",
    ] {
        assert!(
            active_plan(&response(&plan, state), &verified, &inventory).is_err(),
            "{state}"
        );
    }
    let session = response(&plan, "installing");
    let original = verified.envelope.session_id;
    verified.envelope.session_id = Uuid::new_v4();
    assert!(active_plan(&session, &verified, &inventory).is_err());
    verified.envelope.session_id = original;
    let mut changed = inventory.clone();
    changed.disks[0].path = "/dev/sdz".into();
    assert!(active_plan(&session, &verified, &changed).is_err());
    changed = inventory.clone();
    changed.disks[0].serial = "replacement".into();
    assert!(active_plan(&session, &verified, &changed).is_err());
    changed = inventory.clone();
    changed.disks[0].mounted = true;
    assert!(active_plan(&session, &verified, &changed).is_err());
    changed = inventory.clone();
    changed.disks[0].eligible = false;
    assert!(active_plan(&session, &verified, &changed).is_err());
    let mut altered = plan.clone();
    altered["target_disk"]["path"] = "/dev/sdz".into();
    assert!(active_plan(&response(&altered, "installing"), &verified, &inventory).is_err());
    verified.signing_key = SigningKey::from_bytes(&[44; 32]).verifying_key();
    assert!(active_plan(&session, &verified, &inventory).is_err());
}

#[derive(Default)]
struct Server {
    replies: VecDeque<(StatusCode, Value)>,
    requests: Vec<(Method, Value)>,
    events: BTreeMap<i64, Value>,
    lose_response: Option<i64>,
}
async fn handle(
    State(state): State<Arc<Mutex<Server>>>,
    method: Method,
    body: Bytes,
) -> impl IntoResponse {
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    let mut server = state.lock().unwrap();
    server.requests.push((method, value.clone()));
    if let Some(reply) = server.replies.pop_front() {
        return (reply.0, Json(reply.1));
    }
    let sequence = value["sequence"].as_i64().unwrap();
    let existing = server.events.get(&sequence);
    if existing.is_some_and(|old| old != &value) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"code":"different_event_evidence"})),
        );
    }
    let accepted = existing.is_none();
    server.events.insert(sequence, value);
    if server.lose_response == Some(sequence) {
        server.lose_response = None;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"code":"response_lost"})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({"accepted":accepted,"session_state":"installing","session_revision":3})),
    )
}
async fn server(
    state: Arc<Mutex<Server>>,
    session_id: Uuid,
) -> (protocol::ProvisioningClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(handle)).with_state(state),
        )
        .await
        .unwrap()
    });
    (
        protocol::ProvisioningClient::test_client(origin, session_id),
        handle,
    )
}

#[tokio::test]
async fn only_an_unclaimed_session_can_fall_back_from_poll_to_claim() {
    let (plan, verified, inventory) = fixture();
    let key = protocol::derive_provisioning_key(&verified.envelope.media_secret).unwrap();
    let hardware = inventory::hardware_digest(&inventory).unwrap();
    for status in [
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::CONFLICT,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let state = Arc::new(Mutex::new(Server {
            replies: VecDeque::from([
                (status, json!({"code":"request_rejected"})),
                (
                    StatusCode::OK,
                    json!({"session_id":verified.envelope.session_id,"state":"awaiting_approval","session_revision":1,"poll_after_seconds":2,"plan":null}),
                ),
            ]),
            ..Default::default()
        }));
        let (client, handle) = server(state.clone(), verified.envelope.session_id).await;
        let result = initial_session(&client, &verified, &key, &inventory, &hardware).await;
        assert_eq!(result.is_ok(), status == StatusCode::UNAUTHORIZED);
        let state = state.lock().unwrap();
        assert_eq!(state.requests[0].0, Method::GET);
        assert_eq!(
            state.requests.len(),
            if status == StatusCode::UNAUTHORIZED {
                2
            } else {
                1
            }
        );
        assert!(state.events.is_empty()); // retired/wrong authority cannot reach disk authorization
        handle.abort();
    }
    let state = Arc::new(Mutex::new(Server {
        replies: VecDeque::from([(
            StatusCode::OK,
            json!({
        "session_id":verified.envelope.session_id,"state":"installing","session_revision":3,
        "poll_after_seconds":2,"plan":plan}),
        )]),
        ..Default::default()
    }));
    let (client, handle) = server(state.clone(), verified.envelope.session_id).await;
    assert!(
        initial_session(&client, &verified, &key, &inventory, &hardware)
            .await
            .unwrap()
            .1
    );
    assert_eq!(state.lock().unwrap().requests.len(), 1);
    handle.abort();
}

#[tokio::test]
async fn lost_acknowledgements_replay_identical_bytes_before_target_creation() {
    let (plan, verified, inventory) = fixture();
    let plan = active_plan(&response(&plan, "installing"), &verified, &inventory).unwrap();
    let key = protocol::derive_provisioning_key(&verified.envelope.media_secret).unwrap();
    for lose_response in [1, 2] {
        let state = Arc::new(Mutex::new(Server {
            lose_response: Some(lose_response),
            ..Default::default()
        }));
        let (client, handle) = server(state.clone(), verified.envelope.session_id).await;
        assert!(
            client
                .authorize_storage_creation(&key, &plan)
                .await
                .is_err()
        );
        client
            .authorize_storage_creation(&key, &plan)
            .await
            .unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.events.len(), 2);
        for (_, event) in &state.requests {
            assert_eq!(
                event,
                state
                    .events
                    .get(&event["sequence"].as_i64().unwrap())
                    .unwrap()
            );
        }
        assert_eq!(
            state.events[&1]["message"],
            "Approved install plan validated"
        );
        assert_eq!(
            state.events[&2]["message"],
            "Creating plan-bound appliance storage"
        );
        handle.abort();
    }
}

/// Manage's real refusal bodies: a generic `error_code` and, sometimes, a
/// `diagnostic_code`.
fn manage_refusal(diagnostic: Option<&str>) -> (StatusCode, Value) {
    (
        StatusCode::CONFLICT,
        json!({"error":"refused","error_code":"conflict","diagnostic_code":diagnostic,"retryable":false}),
    )
}

#[tokio::test]
async fn a_resumed_generic_setup_asks_whether_management_closed_it() {
    use super::super::setup_claim::resumed_setup_closed;
    let (plan, verified, _) = fixture();
    let session = |state: &str| {
        (
            StatusCode::OK,
            json!({"session_id":verified.envelope.session_id,"state":state,"session_revision":4,"poll_after_seconds":2,"plan":null}),
        )
    };
    // Before identity activation: the media key's plan poll.
    for (reply, closed) in [
        (manage_refusal(None), true),
        (session("revoked"), true),
        (session("expired"), true),
        (session("installing"), false),
        (
            manage_refusal(Some("provisioning_recovery_required")),
            false,
        ),
        (
            (StatusCode::FORBIDDEN, json!({"error_code":"forbidden"})),
            false,
        ),
        (
            (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error_code":"service_unavailable"}),
            ),
            false,
        ),
    ] {
        let state = Arc::new(Mutex::new(Server {
            replies: VecDeque::from([reply]),
            ..Default::default()
        }));
        let (client, handle) = server(state.clone(), verified.envelope.session_id).await;
        assert_eq!(resumed_setup_closed(&client, &verified, None).await, closed);
        assert_eq!(state.lock().unwrap().requests[0].0, Method::GET);
        handle.abort();
    }
    // After it: an unchanged replay of event 3 with the device key.
    let key = SigningKey::from_bytes(&[81; 32]);
    let durable = super::super::DurableProvisioningState {
        schema: "tiaris.nest.provisioning-state.v1".into(),
        session_id: verified.envelope.session_id,
        plan: serde_json::from_value(plan).unwrap(),
        manage_origin: verified.envelope.manage_origin.clone(),
        management_signing_public_key_b64: protocol::standard_base64(
            verified.signing_key.to_bytes(),
        ),
        device_private_key_b64: protocol::standard_base64(key.to_bytes()),
        device_public_key_b64: protocol::standard_base64(key.verifying_key().to_bytes()),
        device_public_key_fingerprint: protocol::sha256_hex(key.verifying_key().to_bytes()),
        next_event_sequence: 6,
        identity_active: true,
        installation_complete: false,
        updated_at: chrono::Utc::now(),
    };
    let state = Arc::new(Mutex::new(Server::default()));
    let (client, handle) = server(state.clone(), verified.envelope.session_id).await;
    assert!(!resumed_setup_closed(&client, &verified, Some(&durable)).await);
    {
        let state = state.lock().unwrap();
        assert_eq!(state.requests[0].0, Method::POST);
        assert_eq!(state.events[&3]["stage"], "state_partition_created");
    }
    handle.abort();
    let state = Arc::new(Mutex::new(Server {
        replies: VecDeque::from([manage_refusal(None)]),
        ..Default::default()
    }));
    let (client, handle) = server(state, verified.envelope.session_id).await;
    assert!(resumed_setup_closed(&client, &verified, Some(&durable)).await);
    handle.abort();

    // Power failed after Management activated the identity but before the
    // flag was saved. Manage answers the media key's plan poll with 403
    // (retired identity) before it looks at revocation, so the device key
    // asks again: 409 is a closed setup, a duplicate is an open one.
    let mut stale = durable.clone();
    stale.identity_active = false;
    let retired = (
        StatusCode::FORBIDDEN,
        json!({"error":"the media-derived provisioning identity has been retired","error_code":"forbidden"}),
    );
    for (replies, closed) in [
        (vec![retired.clone(), manage_refusal(None)], true),
        (vec![retired.clone()], false),
        (
            vec![
                retired,
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({"error_code":"service_unavailable"}),
                ),
            ],
            false,
        ),
        // Before activation the plan poll alone decides.
        (vec![manage_refusal(None)], true),
        (vec![session("awaiting_approval")], false),
    ] {
        let state = Arc::new(Mutex::new(Server {
            replies: VecDeque::from(replies),
            ..Default::default()
        }));
        let (client, handle) = server(state.clone(), verified.envelope.session_id).await;
        assert_eq!(
            resumed_setup_closed(&client, &verified, Some(&stale)).await,
            closed
        );
        let state = state.lock().unwrap();
        assert_eq!(state.requests[0].0, Method::GET);
        if state.requests.len() > 1 {
            assert_eq!(state.requests[1].0, Method::POST);
            assert_eq!(state.requests[1].1["sequence"], 3);
        }
        handle.abort();
    }
}

#[tokio::test]
async fn a_generic_setup_closed_while_waiting_for_a_retry_claims_again() {
    let (plan, verified, inventory) = fixture();
    let plan = active_plan(&response(&plan, "installing"), &verified, &inventory).unwrap();
    let key = protocol::derive_provisioning_key(&verified.envelope.media_secret).unwrap();
    let wait = |generic: bool| {
        let (plan, verified, inventory, key) = (&plan, &verified, &inventory, &key);
        async move {
            let state = Arc::new(Mutex::new(Server {
                replies: VecDeque::from([
                    (
                        StatusCode::OK,
                        json!({"accepted":true,"session_state":"failed","session_revision":3}),
                    ),
                    manage_refusal(None),
                ]),
                ..Default::default()
            }));
            let (client, handle) = server(state, verified.envelope.session_id).await;
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(8),
                super::super::report_failure_and_wait_for_retry(
                    &client,
                    key,
                    verified,
                    inventory,
                    plan,
                    super::super::PreDestructiveFailure::new(
                        "network_preflight_failed",
                        "Nest could not verify the approved wired network before disk preparation.",
                        anyhow::anyhow!("no link"),
                    ),
                    generic,
                ),
            )
            .await;
            handle.abort();
            result
        }
    };
    let (generic, personalized) = tokio::join!(wait(true), wait(false));
    // A generic ISO stops waiting and claims again.
    let error = generic.unwrap().err().unwrap();
    assert!(
        error
            .downcast_ref::<super::super::setup_claim::SetupEnded>()
            .is_some()
    );
    // The personalized path keeps waiting, as before.
    assert!(personalized.is_err());
}
