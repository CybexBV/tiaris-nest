//! Generic Nest ISO: register with Management, show a claim code, and take
//! the envelope Management hands over once an administrator claims this
//! server. Everything after that is the personalized flow, unchanged.
//!
//! The ISO slot stays all zeros. Before the claim nothing is written to a
//! disk: the registration key and the claimed envelope live in a private
//! `/run` directory (a service restart continues, a reboot registers again).
//! From the moment STATE exists the envelope is kept there too, so resuming
//! an interrupted installation never needs the ISO slot.
//!
//! Letters, codes, the envelope and its media secret never reach a log: every
//! message here is fixed text, and errors are logged by their top-level
//! context only, never with a response body.
use super::{
    PrepareOptions,
    packages::MediaLayout,
    protocol::{self, VerifiedEnvelope},
    setup_status::{ClaimState, ClaimView, SetupStatusReporter},
    storage,
};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::{Method, StatusCode, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// This bootstrap's setup claim protocol; the release tooling signs it into
/// the ISO template as `setup_claim_protocol`.
pub const SETUP_CLAIM_PROTOCOL: u32 = 1;
pub const DEFAULT_SETUP_CLAIM_DIR: &str = "/run/tiaris-nest-claim";
const REGISTRATION_SCHEMA: &str = "tiaris.nest.setup-registration.v1";
const STATUS_SCHEMA: &str = "tiaris.nest.setup-registration-status.v1";
const STORED_SCHEMA: &str = "tiaris.nest.setup-registration-state.v1";
const REGISTRATIONS_PATH: &str = "/v1/agent/nest/setup-registrations";
const REGISTRATION_FILE: &str = "registration.json";
const ENVELOPE_FILE: &str = "envelope.bin";
const LETTER_ALPHABET: &str = "ABCDEFGHJKMNPQRTVWXY";
const MAX_HARDWARE_CHARS: usize = 80;
const MAX_TEXT_CHARS: usize = 200;
/// Waits are counted in ticks: one second in production.
const OUTDATED_RETRY_TICKS: u32 = 3600;
const FAILURE_BACKOFF_CAP_TICKS: u32 = 60;
const RATE_LIMIT_BACKOFF_CAP_TICKS: u32 = 900;
/// Failed attempts in a row before the screen says it is connecting again.
const FAILURES_BEFORE_CONNECTING: u32 = 3;

/// The slot of a generic ISO: exactly 8192 zero bytes. Anything else is a
/// personalized envelope and takes the existing path.
pub(super) fn slot_is_generic(path: &Path) -> Result<bool> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(bytes_are_generic_slot(&bytes))
}

fn bytes_are_generic_slot(bytes: &[u8]) -> bool {
    bytes.len() == protocol::ENVELOPE_SIZE && bytes.iter().all(|byte| *byte == 0)
}

/// The setup flow of a generic ISO, in the contract's order: (a) STATE holds
/// a retained envelope of an installation that may continue, (b) `/run` holds
/// this boot's registration, (c) register.
pub(super) async fn prepare_generic(
    options: &PrepareOptions,
    status: &SetupStatusReporter,
    media_layout: MediaLayout,
    trusted_keys: &[VerifyingKey],
) -> Result<()> {
    let store = RunStore::new(options.setup_claim_dir.clone());
    let transport = Transport::new(&options.required_manage_origin)?;
    let hardware = Hardware::collect().await;
    let context = ClaimContext {
        transport: &transport,
        store: &store,
        trusted_keys,
        required_origin: &options.required_manage_origin,
        status,
        hardware: &hardware,
        tick: Duration::from_secs(1),
    };
    loop {
        if let Some(retained) = retained_from_state(options, trusted_keys)? {
            info!("resuming a claimed Nest setup from its retained STATE envelope");
            return super::prepare_verified(
                options,
                status,
                media_layout,
                retained.verified,
                Some(&retained.bytes),
            )
            .await;
        }
        let claimed = claim(&context).await?;
        let result = super::prepare_verified(
            options,
            status,
            media_layout,
            claimed.verified,
            Some(&claimed.bytes),
        )
        .await;
        let Err(error) = result else {
            return Ok(());
        };
        if status.disk_may_be_changed() || !registration_gone(&context).await {
            return Err(error);
        }
        // Management deletes a claimed registration when its setup is
        // revoked, expires or fails before the disk was changed.
        warn!(error = %error, "the claimed Nest setup ended before the disk was changed; registering again");
        storage::release_state_mounts(&options.state_mount);
        store.forget()?;
    }
}

pub(super) struct Claimed {
    pub bytes: Vec<u8>,
    pub verified: VerifiedEnvelope,
}

/// A STATE envelope resumes only while it can still act: an installation
/// that completed (the ISO booted again) or a setup whose window is open.
/// An expired, unverifiable or orphaned copy is a setup that ended: STATE is
/// released and the server is claimed again, after which the existing flow
/// treats that STATE as foreign.
fn retained_from_state(
    options: &PrepareOptions,
    trusted_keys: &[VerifyingKey],
) -> Result<Option<Claimed>> {
    let Some(bytes) = storage::retained_setup_envelope(&options.state_mount)? else {
        return Ok(None);
    };
    let verified = match protocol::verify_envelope_bytes(
        &bytes,
        trusted_keys,
        &options.required_manage_origin,
    ) {
        Ok(verified) => verified,
        Err(error) => {
            warn!(error = %error, "ignoring a retained setup envelope that does not verify");
            storage::release_state_probe(&options.state_mount)?;
            return Ok(None);
        }
    };
    let probe =
        storage::existing_state_for_session(&options.state_mount, verified.envelope.session_id)?;
    let current = protocol::require_current_envelope(&verified).is_ok();
    if current
        || probe
            .as_ref()
            .is_some_and(|probe| probe.state.installation_complete)
    {
        return Ok(Some(Claimed { bytes, verified }));
    }
    info!("the retained Nest setup has ended; this server is claimed again");
    storage::release_state_probe(&options.state_mount)?;
    Ok(None)
}

pub(super) struct ClaimContext<'a> {
    pub transport: &'a Transport,
    pub store: &'a RunStore,
    pub trusted_keys: &'a [VerifyingKey],
    pub required_origin: &'a str,
    pub status: &'a SetupStatusReporter,
    pub hardware: &'a Hardware,
    pub tick: Duration,
}

impl ClaimContext<'_> {
    fn show(&self, state: ClaimState, url: Option<&str>) {
        self.status.claim(
            self.required_origin,
            &ClaimView {
                state,
                letters: None,
                code: None,
                url,
                retry_at: None,
                organization: None,
            },
        );
    }

    async fn wait(&self, ticks: u32) {
        tokio::time::sleep(self.tick * ticks).await;
    }
}

/// Register (or continue this boot's registration) and poll until claimed.
/// Returns the verified, current envelope, already kept in `/run`.
pub(super) async fn claim(context: &ClaimContext<'_>) -> Result<Claimed> {
    let store = context.store;
    store.prepare()?;
    if let Some(claimed) = run_envelope(context)? {
        info!("continuing this boot's claimed Nest setup");
        return Ok(claimed);
    }
    let mut registration = store.load_registration()?;
    let mut url: Option<String> = None;
    let mut failures = 0_u32;
    context.show(ClaimState::Connecting, None);
    loop {
        let mut current = match registration.take() {
            Some(current) => current,
            None => {
                let fresh = Registration::generate();
                store.save_registration(&fresh)?;
                fresh
            }
        };
        let outcome = match current.id {
            None => {
                context
                    .transport
                    .register(&current.key, context.hardware)
                    .await
            }
            Some(id) => context.transport.poll(&current.key, id).await,
        };
        let reply = outcome.and_then(|body| validate_reply(body, current.id));
        match classify(reply, current.id.is_some()) {
            Step::Reply(reply) => {
                failures = 0;
                if current.id != Some(reply.registration_id) {
                    current.id = Some(reply.registration_id);
                    store.save_registration(&current)?;
                }
                if reply.claim_url.is_some() {
                    url = reply.claim_url;
                }
                let poll_after = reply.poll_after_seconds;
                match reply.answer {
                    Answer::Claimable { letters, code } => context.status.claim(
                        context.required_origin,
                        &ClaimView {
                            state: ClaimState::Claimable,
                            letters: Some(&letters),
                            code: Some(&code),
                            url: url.as_deref(),
                            retry_at: None,
                            organization: None,
                        },
                    ),
                    Answer::Backoff { retry_at } => context.status.claim(
                        context.required_origin,
                        &ClaimView {
                            state: ClaimState::Backoff,
                            letters: None,
                            code: None,
                            url: url.as_deref(),
                            retry_at: Some(retry_at),
                            organization: None,
                        },
                    ),
                    Answer::Claimed {
                        organization,
                        session_id,
                        envelope,
                    } => {
                        context.status.claim(
                            context.required_origin,
                            &ClaimView {
                                state: ClaimState::Claimed,
                                letters: None,
                                code: None,
                                url: url.as_deref(),
                                retry_at: None,
                                organization: Some(&organization),
                            },
                        );
                        let verified = verify_claimed(context, &envelope, session_id)?;
                        if protocol::require_current_envelope(&verified).is_err() {
                            info!("the claimed Nest setup has already ended; registering again");
                            store.forget()?;
                            context.show(ClaimState::Connecting, url.as_deref());
                            context.wait(1).await;
                            continue;
                        }
                        store.save_envelope(&envelope)?;
                        info!("this Nest was claimed; continuing setup");
                        return Ok(Claimed {
                            bytes: envelope,
                            verified,
                        });
                    }
                }
                registration = Some(current);
                context.wait(poll_after).await;
            }
            Step::Gone => {
                info!("the Nest setup registration is gone; registering again");
                store.forget()?;
                failures = 0;
                context.wait(1).await;
            }
            Step::Outdated => {
                warn!("Management no longer accepts this Nest installer; retrying hourly");
                context.show(ClaimState::Outdated, url.as_deref());
                registration = Some(current);
                context.wait(OUTDATED_RETRY_TICKS).await;
            }
            Step::Retry { rate_limited } => {
                failures = failures.saturating_add(1);
                if failures >= FAILURES_BEFORE_CONNECTING {
                    context.show(ClaimState::Connecting, url.as_deref());
                }
                registration = Some(current);
                context.wait(retry_ticks(failures, rate_limited)).await;
            }
        }
    }
}

/// This boot already holds a claimed envelope: continue with it while its
/// setup is open. A revoked setup fails the existing flow, which then finds
/// the registration gone and registers again.
fn run_envelope(context: &ClaimContext<'_>) -> Result<Option<Claimed>> {
    let Some(bytes) = context.store.load_envelope()? else {
        return Ok(None);
    };
    let registration = context.store.load_registration()?;
    let verified =
        protocol::verify_envelope_bytes(&bytes, context.trusted_keys, context.required_origin);
    match (registration, verified) {
        (Some(registration), Ok(verified))
            if registration.id.is_some()
                && protocol::require_current_envelope(&verified).is_ok() =>
        {
            Ok(Some(Claimed { bytes, verified }))
        }
        _ => {
            info!("this boot's claimed Nest setup cannot continue; registering again");
            context.store.forget()?;
            Ok(None)
        }
    }
}

fn verify_claimed(
    context: &ClaimContext<'_>,
    envelope: &[u8],
    session_id: Uuid,
) -> Result<VerifiedEnvelope> {
    let verified =
        protocol::verify_envelope_bytes(envelope, context.trusted_keys, context.required_origin)
            .context("Management handed over a setup envelope this installer cannot verify")?;
    if verified.envelope.session_id != session_id {
        bail!("the handed-over setup envelope belongs to another session")
    }
    Ok(verified)
}

/// After the existing flow failed before any disk write: did Management
/// delete this registration (its setup was revoked, expired or failed)?
async fn registration_gone(context: &ClaimContext<'_>) -> bool {
    let Ok(Some(registration)) = context.store.load_registration() else {
        return false;
    };
    let Some(id) = registration.id else {
        return false;
    };
    let outcome = context.transport.poll(&registration.key, id).await;
    matches!(
        classify(
            outcome.and_then(|body| validate_reply(body, Some(id))),
            true
        ),
        Step::Gone
    )
}

fn retry_ticks(failures: u32, rate_limited: bool) -> u32 {
    let cap = if rate_limited {
        RATE_LIMIT_BACKOFF_CAP_TICKS
    } else {
        FAILURE_BACKOFF_CAP_TICKS
    };
    1_u32
        .checked_shl(failures.saturating_sub(1).min(16))
        .unwrap_or(cap)
        .min(cap)
}

pub(super) enum Step {
    Reply(Reply),
    Gone,
    Outdated,
    Retry { rate_limited: bool },
}

pub(super) fn classify(outcome: Result<Reply>, polling: bool) -> Step {
    match outcome {
        Ok(reply) => Step::Reply(reply),
        Err(error) => match protocol::http_refusal(&error) {
            // A poll's 404 means the registration is unknown or gone. A
            // registration's 404 means Nest provisioning is disabled.
            Some((StatusCode::NOT_FOUND, _)) if polling => Step::Gone,
            Some((StatusCode::GONE, _)) => Step::Outdated,
            Some((StatusCode::TOO_MANY_REQUESTS, _)) => {
                debug!("Nest setup registration is rate-limited; waiting");
                Step::Retry { rate_limited: true }
            }
            _ => {
                debug!(error = %error, "Nest setup registration attempt failed; retrying");
                Step::Retry {
                    rate_limited: false,
                }
            }
        },
    }
}

/// Status body of both registration endpoints. Lenient about fields it does
/// not know: a generic ISO never expires, Management will grow. No `Debug`:
/// it carries letters, code and the envelope.
#[derive(Deserialize)]
pub(super) struct StatusBody {
    schema: String,
    registration_id: Uuid,
    state: String,
    poll_after_seconds: i64,
    #[serde(default)]
    claim_url: Option<String>,
    #[serde(default)]
    letters: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    retry_at: Option<DateTime<Utc>>,
    #[serde(default)]
    organization_name: Option<String>,
    #[serde(default)]
    session_id: Option<Uuid>,
    #[serde(default)]
    envelope: Option<String>,
}

pub(super) struct Reply {
    pub registration_id: Uuid,
    pub poll_after_seconds: u32,
    pub claim_url: Option<String>,
    pub answer: Answer,
}

pub(super) enum Answer {
    Claimable {
        letters: String,
        code: String,
    },
    Backoff {
        retry_at: DateTime<Utc>,
    },
    Claimed {
        organization: String,
        session_id: Uuid,
        envelope: Vec<u8>,
    },
}

/// Check a status body against the contract. Error text never repeats a
/// value from the body.
pub(super) fn validate_reply(body: StatusBody, expected: Option<Uuid>) -> Result<Reply> {
    if body.schema != STATUS_SCHEMA {
        bail!("setup registration status schema is unsupported")
    }
    if expected.is_some_and(|expected| expected != body.registration_id) {
        bail!("Management answered for another setup registration")
    }
    let claim_url = body
        .claim_url
        .filter(|url| public_text(url) && !url.contains("://") && !url.contains(' '));
    let answer = match body.state.as_str() {
        "claimable" => {
            let letters = body
                .letters
                .filter(|letters| valid_letters(letters))
                .ok_or_else(|| anyhow!("claimable status lacks valid letters"))?;
            let code = body
                .code
                .filter(|code| code_matches_letters(code, &letters))
                .ok_or_else(|| anyhow!("claimable status lacks a valid code"))?;
            Answer::Claimable { letters, code }
        }
        "backoff" => Answer::Backoff {
            retry_at: body
                .retry_at
                .ok_or_else(|| anyhow!("backoff status lacks its retry time"))?,
        },
        "claimed" => {
            let organization = body
                .organization_name
                .filter(|name| public_text(name))
                .ok_or_else(|| anyhow!("claimed status lacks its organization"))?;
            let session_id = body
                .session_id
                .ok_or_else(|| anyhow!("claimed status lacks its session"))?;
            let envelope = body
                .envelope
                .as_deref()
                .and_then(|envelope| STANDARD.decode(envelope).ok())
                .filter(|envelope| envelope.len() == protocol::ENVELOPE_SIZE)
                .ok_or_else(|| anyhow!("claimed status lacks a valid envelope"))?;
            Answer::Claimed {
                organization,
                session_id,
                envelope,
            }
        }
        _ => bail!("setup registration state is unsupported"),
    };
    Ok(Reply {
        registration_id: body.registration_id,
        poll_after_seconds: u32::try_from(body.poll_after_seconds.clamp(2, 60)).unwrap_or(5),
        claim_url,
        answer,
    })
}

fn public_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= MAX_TEXT_CHARS
        && !value.chars().any(char::is_control)
}

fn valid_letters(letters: &str) -> bool {
    letters.len() == 4
        && letters
            .chars()
            .all(|letter| LETTER_ALPHABET.contains(letter))
}

/// `L1L2-NNNN-L3L4`, 4 to 6 digits, with the letters of this status.
fn code_matches_letters(code: &str, letters: &str) -> bool {
    let mut parts = code.split('-');
    let (Some(first), Some(digits), Some(last), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    (4..=6).contains(&digits.len())
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && letters.len() == 4
        && first == &letters[..2]
        && last == &letters[2..]
}

#[derive(Serialize)]
struct RegistrationRequest<'a> {
    schema: &'static str,
    public_key: String,
    setup_claim_protocol: u32,
    installer_release_version: &'static str,
    hardware: &'a Hardware,
}

/// What an administrator on the same network sees before claiming.
#[derive(Clone, Debug, Serialize)]
pub(super) struct Hardware {
    pub manufacturer: String,
    pub model: String,
    pub virtualization: String,
}

impl Hardware {
    async fn collect() -> Self {
        let (manufacturer, model, virtualization) = super::inventory::registration_hardware().await;
        Self::new(&manufacturer, &model, &virtualization)
    }

    pub(super) fn new(manufacturer: &str, model: &str, virtualization: &str) -> Self {
        let bounded = |value: &str| {
            value
                .trim()
                .chars()
                .filter(|character| !character.is_control())
                .take(MAX_HARDWARE_CHARS)
                .collect::<String>()
        };
        Self {
            manufacturer: bounded(manufacturer),
            model: bounded(model),
            virtualization: bounded(virtualization),
        }
    }
}

/// The registration endpoints over IPv4 and, while this server has a global
/// IPv6 route, also over IPv6, so Management sees it on the family an
/// administrator's browser uses. One family failing is not an error.
pub(super) struct Transport {
    origin: String,
    ipv4: reqwest::Client,
    ipv6: Option<reqwest::Client>,
}

impl Transport {
    fn new(origin: &str) -> Result<Self> {
        let client = |local: IpAddr| {
            reqwest::Client::builder()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(30))
                .https_only(true)
                .local_address(local)
                .user_agent(concat!("tiaris-nest-bootstrap/", env!("CARGO_PKG_VERSION")))
                .build()
                .context("build setup registration HTTP client")
        };
        Ok(Self {
            origin: origin.trim_end_matches('/').to_string(),
            ipv4: client(IpAddr::V4(Ipv4Addr::UNSPECIFIED))?,
            ipv6: Some(client(IpAddr::V6(Ipv6Addr::UNSPECIFIED))?),
        })
    }

    #[cfg(test)]
    pub(super) fn test(origin: String) -> Self {
        Self {
            origin,
            ipv4: reqwest::Client::builder()
                .no_proxy()
                .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                .build()
                .unwrap(),
            ipv6: None,
        }
    }

    fn ipv6(&self) -> Option<&reqwest::Client> {
        self.ipv6.as_ref().filter(|_| has_global_ipv6_route())
    }

    /// Register over IPv4, falling back to IPv6. Idempotent per public key.
    pub(super) async fn register(
        &self,
        key: &SigningKey,
        hardware: &Hardware,
    ) -> Result<StatusBody> {
        let request = RegistrationRequest {
            schema: REGISTRATION_SCHEMA,
            public_key: protocol::standard_base64(key.verifying_key().to_bytes()),
            setup_claim_protocol: SETUP_CLAIM_PROTOCOL,
            installer_release_version: env!("CARGO_PKG_VERSION"),
            hardware,
        };
        let first = self
            .send(&self.ipv4, REGISTRATIONS_PATH, key, &request)
            .await;
        match (&first, self.ipv6()) {
            (Err(error), Some(ipv6)) if protocol::http_refusal(error).is_none() => {
                self.send(ipv6, REGISTRATIONS_PATH, key, &request).await
            }
            _ => first,
        }
    }

    /// Poll, keep alive and record a sighting, on both families at once.
    pub(super) async fn poll(&self, key: &SigningKey, id: Uuid) -> Result<StatusBody> {
        let path = format!("{REGISTRATIONS_PATH}/{id}/status");
        let body = serde_json::json!({});
        let ipv4 = self.send(&self.ipv4, &path, key, &body);
        let Some(ipv6) = self.ipv6() else {
            return ipv4.await;
        };
        let (ipv4, ipv6) = tokio::join!(ipv4, self.send(ipv6, &path, key, &body));
        prefer_answer(ipv4, ipv6)
    }

    async fn send<B: Serialize>(
        &self,
        http: &reqwest::Client,
        path: &str,
        key: &SigningKey,
        body: &B,
    ) -> Result<StatusBody> {
        protocol::signed_json(
            http,
            &self.origin,
            Method::POST,
            path,
            key,
            None,
            Some(body),
        )
        .await
    }
}

/// A status beats a refusal, and a refusal beats a transport failure.
pub(super) fn prefer_answer(
    first: Result<StatusBody>,
    second: Result<StatusBody>,
) -> Result<StatusBody> {
    match (first, second) {
        (Ok(answer), _) | (Err(_), Ok(answer)) => Ok(answer),
        (Err(first), Err(second))
            if protocol::http_refusal(&first).is_none()
                && protocol::http_refusal(&second).is_some() =>
        {
            Err(second)
        }
        (Err(first), Err(_)) => Err(first),
    }
}

/// A default IPv6 route and a global IPv6 address outside loopback.
fn has_global_ipv6_route() -> bool {
    let routes = fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default();
    let addresses = fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
    ipv6_route_present(&routes, &addresses)
}

pub(super) fn ipv6_route_present(routes: &str, addresses: &str) -> bool {
    const RTF_UP: u32 = 0x1;
    const RTF_REJECT: u32 = 0x200;
    let default_route = routes.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.len() == 10
            && fields[0].bytes().all(|byte| byte == b'0')
            && fields[1] == "00"
            && fields[9] != "lo"
            && u32::from_str_radix(fields[8], 16)
                .is_ok_and(|flags| flags & RTF_UP != 0 && flags & RTF_REJECT == 0)
    });
    let global_address = addresses.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.len() == 6 && fields[3] == "00" && fields[5] != "lo"
    });
    default_route && global_address
}

/// The registration key lives only in memory and in the private `/run`
/// directory. No `Debug`: it holds a private key.
pub(super) struct Registration {
    pub key: SigningKey,
    pub id: Option<Uuid>,
}

impl Registration {
    fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
            id: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRegistration {
    schema: String,
    private_key_b64: String,
    registration_id: Option<Uuid>,
}

/// The private `/run` directory: mode 0700, files 0600, atomic writes.
pub(super) struct RunStore {
    dir: PathBuf,
}

impl RunStore {
    pub(super) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Create the directory, or accept it only when it is this user's own
    /// private directory.
    pub(super) fn prepare(&self) -> Result<()> {
        match fs::DirBuilder::new().mode(0o700).create(&self.dir) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("create the setup claim directory"),
        }
        let metadata =
            fs::symlink_metadata(&self.dir).context("inspect the setup claim directory")?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            bail!("the setup claim directory is not private")
        }
        Ok(())
    }

    /// The registration of this boot. A damaged file is forgotten, never
    /// trusted.
    pub(super) fn load_registration(&self) -> Result<Option<Registration>> {
        let path = self.dir.join(REGISTRATION_FILE);
        if !exists(&path)? {
            return Ok(None);
        }
        let parsed = super::read_bounded_nofollow(&path, 4096, "setup registration")
            .and_then(|body| {
                serde_json::from_slice::<StoredRegistration>(&body)
                    .map_err(|_| anyhow!("setup registration is not valid"))
            })
            .and_then(|stored| {
                if stored.schema != STORED_SCHEMA {
                    bail!("setup registration schema is unsupported")
                }
                Ok(Registration {
                    key: protocol::signing_key_from_standard_base64(&stored.private_key_b64)?,
                    id: stored.registration_id,
                })
            });
        match parsed {
            Ok(registration) => Ok(Some(registration)),
            Err(error) => {
                warn!(error = %error, "forgetting an unusable setup registration");
                self.forget()?;
                Ok(None)
            }
        }
    }

    pub(super) fn save_registration(&self, registration: &Registration) -> Result<()> {
        let stored = StoredRegistration {
            schema: STORED_SCHEMA.to_string(),
            private_key_b64: protocol::standard_base64(registration.key.to_bytes()),
            registration_id: registration.id,
        };
        let body = serde_json::to_vec(&stored).context("serialize setup registration")?;
        storage::atomic_write(&self.dir.join(REGISTRATION_FILE), &body, 0o600)
    }

    pub(super) fn save_envelope(&self, envelope: &[u8]) -> Result<()> {
        storage::atomic_write(&self.dir.join(ENVELOPE_FILE), envelope, 0o600)
    }

    pub(super) fn load_envelope(&self) -> Result<Option<Vec<u8>>> {
        let path = self.dir.join(ENVELOPE_FILE);
        if !exists(&path)? {
            return Ok(None);
        }
        match super::read_bounded_nofollow(
            &path,
            protocol::ENVELOPE_SIZE as u64,
            "claimed setup envelope",
        ) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) => {
                warn!(error = %error, "forgetting an unusable claimed setup envelope");
                self.forget()?;
                Ok(None)
            }
        }
    }

    /// Forget the registration and the envelope; the next attempt registers
    /// with a new key and shows a new code.
    pub(super) fn forget(&self) -> Result<()> {
        for name in [ENVELOPE_FILE, REGISTRATION_FILE] {
            match fs::remove_file(self.dir.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("forget the setup registration"),
            }
        }
        Ok(())
    }
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect the setup claim directory"),
    }
}

#[cfg(test)]
mod tests;
