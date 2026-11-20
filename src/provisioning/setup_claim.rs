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
//! On a server that already holds an installed Nest the ISO is there to
//! reinstall or recover it (or was left in): it shows the claim screen and
//! starts the installed Nest only when nobody claims it within 3 minutes.
//! A setup that Management closed before this run changed the disk always
//! leads back to the claim screen with a new code.
//!
//! Letters, codes, the envelope and its media secret never reach a log: every
//! message here is fixed text, and errors are logged by their top-level
//! context only, never with a response body.
use super::{
    DurableProvisioningState, PrepareOptions,
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
    future::Future,
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
const ORGANIZATION_FILE: &str = "organization";
const STARTS_INSTALLED_FILE: &str = "starts-installed-at";
/// How long a server that already runs a Nest waits for a new claim. Long
/// enough to type the code when someone started the ISO on purpose, short for
/// a restart that only found the ISO still attached (the running Nest names
/// its own boot entry for the next start: nixos-appliance/runtime/boot_next.py).
const START_INSTALLED_AFTER_MINUTES: i64 = 3;
const LETTER_ALPHABET: &str = "ABCDEFGHJKMNPQRTVWXY";
const MAX_HARDWARE_CHARS: usize = 80;
const MAX_TEXT_CHARS: usize = 200;
/// The kiosk's limit for a shown name.
const MAX_DISPLAY_CHARS: usize = 80;
/// Waits are counted in ticks: one second in production.
const OUTDATED_RETRY_TICKS: u32 = 3600;
const FAILURE_BACKOFF_CAP_TICKS: u32 = 60;
const RATE_LIMIT_BACKOFF_CAP_TICKS: u32 = 900;
/// Failed attempts in a row before the screen says it is connecting again.
const FAILURES_BEFORE_CONNECTING: u32 = 3;
/// A poll that decides (at the deadline, or whether the registration is
/// gone) is asked at most this often when it gets no answer.
const DECIDING_POLL_ATTEMPTS: u32 = 3;
/// The longest `Retry-After` such a poll waits for, in ticks.
const DECIDING_RETRY_CAP_TICKS: u32 = 5;

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
/// a retained envelope of an installation that may continue, or an installed
/// Nest, (b) `/run` holds this boot's registration, (c) register.
pub(super) async fn prepare_generic(
    options: &PrepareOptions,
    status: &SetupStatusReporter,
    media_layout: MediaLayout,
    trusted_keys: &[VerifyingKey],
) -> Result<()> {
    let store = RunStore::new(options.setup_claim_dir.clone());
    let transport = Transport::new(&options.required_manage_origin)?;
    let hardware = Hardware::collect().await;
    let mut context = ClaimContext {
        transport: &transport,
        store: &store,
        trusted_keys,
        required_origin: &options.required_manage_origin,
        status,
        hardware: &hardware,
        tick: Duration::from_secs(1),
        starts_installed_at: None,
    };
    loop {
        context.starts_installed_at = None;
        let claimed = match retained_from_state(options, trusted_keys)? {
            Retained::Resume { claimed, durable } => {
                let envelope = &claimed.verified.envelope;
                let client = protocol::ProvisioningClient::new(
                    &envelope.manage_origin,
                    envelope.session_id,
                )?;
                if resumed_setup_closed(&client, &claimed.verified, durable.as_deref()).await {
                    // "Start over": the existing flow later treats this STATE
                    // as another session's and asks for a new disk approval.
                    info!(
                        "Management closed the retained Nest setup; this server is claimed again"
                    );
                    storage::release_state_probe(&options.state_mount)?;
                    forget_closed_run_claim(&context, envelope.session_id)?;
                    claim(&context).await?
                } else {
                    info!("resuming a claimed Nest setup from its retained STATE envelope");
                    *claimed
                }
            }
            Retained::Installed(installed) => {
                storage::release_state_probe(&options.state_mount)?;
                info!("this server already runs a Nest; it starts unless claimed in time");
                let start = |installed| start_installed(options, status, media_layout, installed);
                match claim_installed(&mut context, installed, start).await? {
                    Some(claimed) => claimed,
                    None => return Ok(()),
                }
            }
            Retained::None => claim(&context).await?,
        };
        // Who claimed it, for the approval and install screens. Kept in
        // `/run`, so a restarted bootstrap in this boot still knows it.
        status.claimed_by(
            store
                .load_organization(claimed.verified.envelope.session_id)
                .as_deref(),
        );
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
        if status.disk_may_be_changed() {
            return Err(error);
        }
        // Management refused the session as closed, or deleted this boot's
        // claimed registration (its setup was revoked, expired or failed).
        if error.downcast_ref::<SetupEnded>().is_none() && !registration_gone(&context).await {
            return Err(error);
        }
        warn!(error = %error, "the claimed Nest setup ended before the disk was changed; registering again");
        storage::release_state_mounts(&options.state_mount);
        store.forget_claimed()?;
    }
}

/// Management closed this generic ISO's claimed setup before the disk was
/// changed: the bootstrap registers again and shows a new code.
#[derive(Debug, thiserror::Error)]
#[error("Management closed this claimed Nest setup")]
pub(super) struct SetupEnded;

/// Mark Management's refusal of a closed session (a plan poll or claim
/// error, `protocol::closed_session_refusal`) on a generic ISO.
pub(super) fn ended_if_closed(generic: bool, error: anyhow::Error) -> anyhow::Error {
    if generic && protocol::closed_session_refusal(&error) {
        error.context(SetupEnded)
    } else {
        error
    }
}

/// Before an interrupted installation resumes from its retained envelope:
/// did Management close that setup? Asked without changing anything, and
/// decided by Management's answers, not by the saved `identity_active` flag
/// alone (power may fail after Management activated the device identity but
/// before the flag was saved). Unless the flag says the identity is active,
/// the media key's plan poll asks first: `409` means closed, a session state
/// is read as it is, and `403` means Management retired the media identity
/// (it says so before it looks at revocation), so the device key asks again.
/// The device key asks by replaying event 3, which Management answers
/// unchanged, as a duplicate, while the session is open and with `409` once
/// it is closed. Only Management's refusal of a closed session counts; a
/// network failure or any other answer resumes as before.
pub(super) async fn resumed_setup_closed(
    client: &protocol::ProvisioningClient,
    verified: &VerifiedEnvelope,
    durable: Option<&DurableProvisioningState>,
) -> bool {
    if !durable.is_some_and(|durable| durable.identity_active) {
        let Ok(key) = protocol::derive_provisioning_key(&verified.envelope.media_secret) else {
            return false;
        };
        match client.poll_plan(&key).await {
            Ok(session) => return matches!(session.state.as_str(), "revoked" | "expired"),
            Err(error)
                if protocol::http_refusal(&error)
                    .is_some_and(|(status, _)| status == StatusCode::FORBIDDEN) => {}
            Err(error) => return protocol::closed_session_refusal(&error),
        }
    }
    // Without durable state no device identity was ever activated.
    let Some(durable) = durable else {
        return false;
    };
    let Ok(key) = durable.signing_key() else {
        return false;
    };
    match super::report_state_created(client, &key, &durable.plan).await {
        Ok(()) => false,
        Err(error) => protocol::closed_session_refusal(&error),
    }
}

pub(super) struct Claimed {
    pub bytes: Vec<u8>,
    pub verified: VerifiedEnvelope,
}

/// What STATE allows on this start.
pub(super) enum Retained {
    /// Nothing to continue: register and wait for a claim.
    None,
    /// Continue that installation (its durable state, when STATE has one)
    /// unless Management closed its setup.
    Resume {
        claimed: Box<Claimed>,
        durable: Option<Box<DurableProvisioningState>>,
    },
    /// An installed Nest: offer a new claim first and start it when nobody
    /// claims it in time.
    Installed(Installed),
}

/// How an installed Nest is started when nobody claims the server.
pub(super) enum Installed {
    /// A completed installation with its retained envelope: the
    /// completed-install path.
    Retained(Box<Claimed>),
    /// No usable retained envelope: select the installed NixOS Nest's UEFI
    /// entry on this ESP and restart, changing nothing on disk.
    BootEntry(PathBuf),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RetainedChoice {
    Claim,
    Resume,
    StartRetained,
    StartBootEntry,
}

/// What a retained envelope tells: whether its setup window is open and,
/// when STATE holds that session's durable state, whether it completed.
pub(super) struct RetainedEnvelope {
    pub current: bool,
    pub completed: Option<bool>,
}

/// A completed installation always offers a claim first and then starts with
/// its envelope. An incomplete one resumes while its window is open and is
/// claimed again once it ended. Without a usable envelope (none, an expired
/// one with no durable state of its session, or a completed installation's
/// that this server's clock is behind) a STATE disk whose
/// installed Nest has a UEFI entry is offered for a claim and then started
/// by that entry; anything else is claimed.
pub(super) fn retained_choice(
    retained: Option<RetainedEnvelope>,
    boot_entry: impl FnOnce() -> bool,
) -> RetainedChoice {
    match retained {
        Some(RetainedEnvelope {
            completed: Some(true),
            ..
        }) => RetainedChoice::StartRetained,
        Some(RetainedEnvelope { current: true, .. }) => RetainedChoice::Resume,
        Some(RetainedEnvelope {
            completed: Some(false),
            ..
        }) => RetainedChoice::Claim,
        _ if boot_entry() => RetainedChoice::StartBootEntry,
        _ => RetainedChoice::Claim,
    }
}

/// Read STATE through the read-only probe. With `Resume` and a durable state,
/// or `Installed(Retained)`, the probe stays mounted; otherwise STATE is
/// released. Only `StartBootEntry` looks at UEFI entries, read-only.
fn retained_from_state(
    options: &PrepareOptions,
    trusted_keys: &[VerifyingKey],
) -> Result<Retained> {
    let mut found = None;
    if let Some(bytes) = storage::retained_setup_envelope(&options.state_mount)? {
        match verify_retained(&bytes, trusted_keys, &options.required_manage_origin) {
            Ok(Some(verified)) => {
                let probe = storage::existing_state_for_session(
                    &options.state_mount,
                    verified.envelope.session_id,
                )?;
                found = Some((Claimed { bytes, verified }, probe.map(|probe| probe.state)));
            }
            Ok(None) => storage::release_state_probe(&options.state_mount)?,
            Err(error) => {
                let behind = ahead_of_clock(error, |session| {
                    Ok(
                        storage::existing_state_for_session(&options.state_mount, session)?
                            .is_some_and(|probe| probe.state.installation_complete),
                    )
                });
                storage::release_state_probe(&options.state_mount)?;
                behind?;
            }
        }
    }
    let envelope = found.as_ref().map(|(claimed, durable)| RetainedEnvelope {
        current: protocol::require_current_envelope(&claimed.verified).is_ok(),
        completed: durable
            .as_ref()
            .map(|durable| durable.installation_complete),
    });
    let mut esp = None;
    let choice = retained_choice(envelope, || {
        esp = installed_boot_entry();
        esp.is_some()
    });
    match (choice, found, esp) {
        (RetainedChoice::Resume, Some((claimed, durable)), _) => Ok(Retained::Resume {
            claimed: Box::new(claimed),
            durable: durable.map(Box::new),
        }),
        (RetainedChoice::StartRetained, Some((claimed, _)), _) => {
            Ok(Retained::Installed(Installed::Retained(Box::new(claimed))))
        }
        (RetainedChoice::StartBootEntry, _, Some(esp)) => {
            storage::release_state_probe(&options.state_mount)?;
            Ok(Retained::Installed(Installed::BootEntry(esp)))
        }
        (_, found, _) => {
            if found.is_some() {
                info!("the retained Nest setup has ended; this server is claimed again");
            }
            storage::release_state_probe(&options.state_mount)?;
            Ok(Retained::None)
        }
    }
}

/// Verify STATE's retained envelope. One that does not verify is ignored
/// (`None`: this server is claimed again). One that is fine except that it
/// looks issued in the future (this server's clock is behind, for example
/// before NTP answered) is "not yet", never a reason to claim again: the run
/// fails like the slot path's and the service retries until the clock is
/// right, unless `ahead_of_clock` finds its installation completed. Whether its window is still open is `require_current_envelope`'s.
pub(super) fn verify_retained(
    bytes: &[u8],
    trusted_keys: &[VerifyingKey],
    required_origin: &str,
) -> Result<Option<VerifiedEnvelope>> {
    match protocol::verify_envelope_bytes(bytes, trusted_keys, required_origin) {
        Ok(verified) => Ok(Some(verified)),
        Err(error) if error.is::<protocol::EnvelopeIssuedInFuture>() => Err(error.context(
            "the retained setup envelope looks issued in the future; \
             waiting for this server's clock",
        )),
        Err(error) => {
            warn!(error = %error, "ignoring a retained setup envelope that does not verify");
            Ok(None)
        }
    }
}

/// `verify_retained`'s error for an envelope this server's clock is behind,
/// once STATE was asked whether that session's installation `completed`. A
/// completed one is `Ok`: a retained envelope it cannot use yet, so the
/// installed Nest is offered for a claim and started by its boot entry
/// (amendment 11), as one without a usable envelope is; its completed-install
/// path needs the envelope verified. An incomplete one, or any other error,
/// fails the run until the clock is right.
pub(super) fn ahead_of_clock(
    error: anyhow::Error,
    completed: impl FnOnce(Uuid) -> Result<bool>,
) -> Result<()> {
    let Some(session) = error
        .downcast_ref::<protocol::EnvelopeIssuedInFuture>()
        .map(|ahead| ahead.session_id)
    else {
        return Err(error);
    };
    if !completed(session)? {
        return Err(error);
    }
    warn!(error = %format!("{error:#}"), "the installed Nest's retained setup envelope cannot be used before this server's clock is right");
    Ok(())
}

/// The ESP of an installed NixOS Nest with exactly one UEFI entry for it, or
/// `None` (logged) when the installed Nest cannot be started that way.
fn installed_boot_entry() -> Option<PathBuf> {
    let found = storage::installed_nest_esp().and_then(|esp| match esp {
        Some(esp) => super::nixos_install::installed_boot_entry(&esp).map(|_| Some(esp)),
        None => Ok(None),
    });
    match found {
        Ok(esp) => esp,
        Err(error) => {
            info!(error = %format!("{error:#}"), "no installed Nest boot entry can be selected");
            None
        }
    }
}

/// Offer the claim until the deadline, then start the installed
/// Nest with `start`. `None` once it is starting. When it cannot be started
/// the claim screen stays, without a deadline.
pub(super) async fn claim_installed<Started>(
    context: &mut ClaimContext<'_>,
    installed: Installed,
    start: impl FnOnce(Installed) -> Started,
) -> Result<Option<Claimed>>
where
    Started: Future<Output = Result<()>>,
{
    // A claim this boot holds continues; one that ended restarts the wait.
    if let Some(claimed) = run_envelope(context)? {
        info!("continuing this boot's claimed Nest setup");
        return Ok(Some(claimed));
    }
    let deadline = context.store.starts_installed_at(
        Utc::now(),
        chrono::Duration::minutes(START_INSTALLED_AFTER_MINUTES),
    )?;
    context.starts_installed_at = Some(deadline);
    if let Some(claimed) = claim_until(context, deadline).await? {
        return Ok(Some(claimed));
    }
    info!("not claimed in time; starting the installed Nest");
    match start(installed).await {
        Ok(()) => Ok(None),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "the installed Nest could not be started; waiting for a claim");
            context.starts_installed_at = None;
            claim(context).await.map(Some)
        }
    }
}

/// Start the installed Nest. Neither way writes to a target disk: the
/// completed-install path selects its UEFI entry and reports, the boot entry
/// path only selects that entry.
async fn start_installed(
    options: &PrepareOptions,
    status: &SetupStatusReporter,
    media_layout: MediaLayout,
    installed: Installed,
) -> Result<()> {
    let result = match installed {
        Installed::Retained(installed) => {
            super::prepare_verified(
                options,
                status,
                media_layout,
                installed.verified,
                Some(&installed.bytes),
            )
            .await
        }
        Installed::BootEntry(esp) => {
            status.rebooting();
            super::nixos_install::boot_installed_esp(&esp)
        }
    };
    if result.is_err() {
        storage::release_state_mounts(&options.state_mount);
        status.installed_start_failed();
    }
    result
}

pub(super) struct ClaimContext<'a> {
    pub transport: &'a Transport,
    pub store: &'a RunStore,
    pub trusted_keys: &'a [VerifyingKey],
    pub required_origin: &'a str,
    pub status: &'a SetupStatusReporter,
    pub hardware: &'a Hardware,
    pub tick: Duration,
    /// When this server, which already runs a Nest, starts it unclaimed.
    pub starts_installed_at: Option<DateTime<Utc>>,
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
                starts_installed_at: self.starts_installed_at,
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
                            starts_installed_at: context.starts_installed_at,
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
                            starts_installed_at: context.starts_installed_at,
                        },
                    ),
                    Answer::Claimed {
                        organization,
                        session_id,
                        envelope,
                    } => {
                        let taken = take_claimed(
                            context,
                            organization.as_deref(),
                            session_id,
                            envelope,
                            url.as_deref(),
                        )?;
                        if let Some(claimed) = taken {
                            return Ok(claimed);
                        }
                        context.show(ClaimState::Connecting, url.as_deref());
                        context.wait(1).await;
                        continue;
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

/// Verify a handed-over envelope, keep it in `/run` and only then say who
/// claimed this server (no name, no claimed screen: the setup goes straight
/// on). `None` when its setup has already ended; it is forgotten.
fn take_claimed(
    context: &ClaimContext<'_>,
    organization: Option<&str>,
    session_id: Uuid,
    envelope: Vec<u8>,
    url: Option<&str>,
) -> Result<Option<Claimed>> {
    let verified = verify_claimed(context, &envelope, session_id)?;
    if protocol::require_current_envelope(&verified).is_err() {
        info!("the claimed Nest setup has already ended; registering again");
        context.store.forget_claimed()?;
        return Ok(None);
    }
    context.store.save_envelope(&envelope)?;
    context.store.save_organization(session_id, organization);
    if let Some(organization) = organization {
        context.status.claim(
            context.required_origin,
            &ClaimView {
                state: ClaimState::Claimed,
                letters: None,
                code: None,
                url,
                retry_at: None,
                organization: Some(organization),
                starts_installed_at: None,
            },
        );
    }
    info!("this Nest was claimed; continuing setup");
    Ok(Some(Claimed {
        bytes: envelope,
        verified,
    }))
}

/// `claim`, but only until `deadline`: `None` when nobody claimed this
/// server in time. A network that is down does not stop the clock. A claim
/// this boot already holds wins even after the deadline, and so does one
/// that landed since the last poll: the deadline polls once more.
pub(super) async fn claim_until(
    context: &ClaimContext<'_>,
    deadline: DateTime<Utc>,
) -> Result<Option<Claimed>> {
    let remaining = (deadline - Utc::now()).to_std().unwrap_or_default();
    tokio::select! {
        biased;
        claimed = claim(context) => return claimed.map(Some),
        () = tokio::time::sleep(remaining) => {}
    }
    last_poll(context).await
}

/// One deciding poll at the deadline: a claim that landed since the last
/// poll wins. Any other answer, or still none after its retries, lets the
/// installed Nest start.
pub(super) async fn last_poll(context: &ClaimContext<'_>) -> Result<Option<Claimed>> {
    if let Some(claimed) = run_envelope(context)? {
        return Ok(Some(claimed));
    }
    let Some(Registration { key, id: Some(id) }) = context.store.load_registration()? else {
        return Ok(None);
    };
    match deciding_poll(context, &key, id).await {
        Ok(Reply {
            claim_url,
            answer:
                Answer::Claimed {
                    organization,
                    session_id,
                    envelope,
                },
            ..
        }) => take_claimed(
            context,
            organization.as_deref(),
            session_id,
            envelope,
            claim_url.as_deref(),
        ),
        _ => Ok(None),
    }
}

/// Management closed `session_id`, the setup STATE would have resumed:
/// forget this boot's claim of that same setup in `/run` too, so `claim`
/// registers again and shows a new code instead of continuing it. A claim
/// of another setup stays.
pub(super) fn forget_closed_run_claim(context: &ClaimContext<'_>, session_id: Uuid) -> Result<()> {
    let Some(bytes) = context.store.load_envelope()? else {
        return Ok(());
    };
    let same =
        protocol::verify_envelope_bytes(&bytes, context.trusted_keys, context.required_origin)
            .is_ok_and(|verified| verified.envelope.session_id == session_id);
    if same {
        info!("forgetting this boot's claim of the closed Nest setup");
        context.store.forget_claimed()?;
    }
    Ok(())
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
            context.store.forget_claimed()?;
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
    let reply = deciding_poll(context, &registration.key, id).await;
    matches!(classify(reply, true), Step::Gone)
}

/// A poll whose answer decides something. Management answers a poll in the
/// same second as the one before `429` (`Retry-After: 1`) without reading
/// it, and a transport failure says nothing either: neither is an answer.
/// Wait as `Retry-After` says (one tick without it, at most
/// `DECIDING_RETRY_CAP_TICKS`) and ask again, at most
/// `DECIDING_POLL_ATTEMPTS` times in all; then the last outcome stands.
pub(super) async fn deciding_poll(
    context: &ClaimContext<'_>,
    key: &SigningKey,
    id: Uuid,
) -> Result<Reply> {
    let mut attempt = 1;
    loop {
        let reply = context
            .transport
            .poll(key, id)
            .await
            .and_then(|body| validate_reply(body, Some(id)));
        let error = match reply {
            Err(error) if attempt < DECIDING_POLL_ATTEMPTS && no_answer(&error) => error,
            reply => return reply,
        };
        let ticks = protocol::retry_after_seconds(&error)
            .map_or(1, |seconds| u32::try_from(seconds).unwrap_or(u32::MAX))
            .clamp(1, DECIDING_RETRY_CAP_TICKS);
        debug!(error = %error, "a deciding Nest setup poll got no answer; asking again");
        context.wait(ticks).await;
        attempt += 1;
    }
}

/// Too fast, or no HTTP answer at all (connection, timeout, a body that
/// could not be read).
fn no_answer(error: &anyhow::Error) -> bool {
    match protocol::http_refusal(error) {
        Some((status, _)) => status == StatusCode::TOO_MANY_REQUESTS,
        None => error.chain().any(|cause| cause.is::<reqwest::Error>()),
    }
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
        /// Display text only: never a reason to refuse a claim.
        organization: Option<String>,
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
                .as_deref()
                .map(display_text)
                .filter(|name| !name.is_empty());
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

/// Text only shown, never checked: control characters removed, trimmed,
/// cut to 80 characters.
fn display_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_DISPLAY_CHARS)
        .collect::<String>()
        .trim_end()
        .to_string()
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

/// A status beats a refusal, and a refusal beats a transport failure. When
/// both families answer and only one says `claimed` (the claim landed
/// between them), `claimed` wins.
pub(super) fn prefer_answer(
    first: Result<StatusBody>,
    second: Result<StatusBody>,
) -> Result<StatusBody> {
    match (first, second) {
        (Ok(first), Ok(second)) if first.state != "claimed" && second.state == "claimed" => {
            Ok(second)
        }
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

    /// When a server that already runs a Nest starts it unclaimed: counted
    /// from this boot's first claim screen and kept across service restarts.
    /// `forget` keeps it, `forget_claimed` starts it again; a damaged or
    /// implausibly late time starts again too.
    pub(super) fn starts_installed_at(
        &self,
        now: DateTime<Utc>,
        wait: chrono::Duration,
    ) -> Result<DateTime<Utc>> {
        self.prepare()?;
        let path = self.dir.join(STARTS_INSTALLED_FILE);
        if exists(&path)? {
            let kept = super::read_bounded_nofollow(&path, 64, "setup claim deadline")
                .ok()
                .and_then(|body| String::from_utf8(body).ok())
                .and_then(|text| DateTime::parse_from_rfc3339(text.trim()).ok())
                .map(|at| at.with_timezone(&Utc))
                .filter(|at| *at <= now + wait);
            if let Some(at) = kept {
                return Ok(at);
            }
        }
        let at = now + wait;
        storage::atomic_write(&path, at.to_rfc3339().as_bytes(), 0o600)?;
        Ok(at)
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

    /// The claiming organization's name for `session_id`: display text
    /// only, so it is best effort and never stops the setup.
    pub(super) fn save_organization(&self, session_id: Uuid, name: Option<&str>) {
        let result = match name {
            Some(name) => self.prepare().and_then(|()| {
                storage::atomic_write(
                    &self.dir.join(ORGANIZATION_FILE),
                    format!("{session_id}\n{name}").as_bytes(),
                    0o600,
                )
            }),
            None => self.remove(&[ORGANIZATION_FILE]),
        };
        if let Err(error) = result {
            warn!(error = %error, "could not keep the claiming organization's name");
        }
    }

    /// The name saved for `session_id`, if any; another setup's is ignored.
    pub(super) fn load_organization(&self, session_id: Uuid) -> Option<String> {
        let body = super::read_bounded_nofollow(
            &self.dir.join(ORGANIZATION_FILE),
            1024,
            "claiming organization name",
        )
        .ok()?;
        let text = String::from_utf8(body).ok()?;
        let (saved, name) = text.split_once('\n')?;
        let name = display_text(name);
        (saved.parse::<Uuid>().ok()? == session_id && !name.is_empty()).then_some(name)
    }

    /// Forget the registration and the envelope; the next attempt registers
    /// with a new key and shows a new code.
    pub(super) fn forget(&self) -> Result<()> {
        self.remove(&[ENVELOPE_FILE, REGISTRATION_FILE, ORGANIZATION_FILE])
    }

    /// A claimed setup ended: forget it, and the claim screen that returns
    /// gives an installed Nest its full wait again.
    pub(super) fn forget_claimed(&self) -> Result<()> {
        self.remove(&[
            ENVELOPE_FILE,
            REGISTRATION_FILE,
            STARTS_INSTALLED_FILE,
            ORGANIZATION_FILE,
        ])
    }

    fn remove(&self, names: &[&str]) -> Result<()> {
        for name in names {
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
