use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::{
    AppState, boot as boot_logic,
    boot_identity::{serial_from_hex, usable_serial},
    boot_machines::{self, BootIdentity, ReinstallCheck},
    db,
    error::{AppError, AppResult},
    models::{BootProfile, BootProfileType, Device, NewBootEvent, normalize_mac},
};

const MAX_BOOT_SERIAL_LEN: usize = 128;
const MAX_BOOT_USER_AGENT_LEN: usize = 256;

#[derive(Debug, Deserialize)]
pub struct BootQuery {
    pub mac: Option<String>,
    pub serial: Option<String>,
    /// `${serial:hexraw}` from `autoexec.ipxe` and menu links rendered before
    /// the serial was known.
    pub serial_hex: Option<String>,
    /// `${uuid}`, the SMBIOS system UUID, from `autoexec.ipxe` and menu links.
    pub uuid: Option<String>,
    pub tiaris_check: Option<String>,
}

impl BootQuery {
    /// The SMBIOS serial the request reported, untruncated. A plain value
    /// from a Nest-rendered menu link wins over iPXE's hex expansion.
    pub(super) fn reported_serial(&self) -> Option<String> {
        self.serial
            .clone()
            .filter(|serial| !serial.trim().is_empty())
            .or_else(|| self.serial_hex.as_deref().and_then(serial_from_hex))
    }

    /// Everything the request says about its own computer.
    pub(super) fn reported_identity(&self) -> BootIdentity {
        BootIdentity::from_reported(self.uuid.as_deref(), self.reported_serial())
    }
}

pub async fn boot_root(
    State(state): State<AppState>,
    Query(query): Query<BootQuery>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let checker = is_local_checker_request(&query, &headers, connect.as_ref().map(|value| value.0));
    let identity = query.reported_identity();
    let script = build_boot_script(
        &state,
        query.mac,
        identity,
        &headers,
        connect.map(|value| value.0),
        checker,
    )
    .await?;
    Ok(ipxe_response(script))
}

pub async fn boot_mac(
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Query(query): Query<BootQuery>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let checker = is_local_checker_request(&query, &headers, connect.as_ref().map(|value| value.0));
    let identity = query.reported_identity();
    let script = build_boot_script(
        &state,
        Some(mac),
        identity,
        &headers,
        connect.map(|value| value.0),
        checker,
    )
    .await?;
    Ok(ipxe_response(script))
}

pub async fn boot_serial(
    State(state): State<AppState>,
    Path(serial): Path<String>,
    Query(query): Query<BootQuery>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let checker = is_local_checker_request(&query, &headers, connect.as_ref().map(|value| value.0));
    let identity = BootIdentity::from_reported(query.uuid.as_deref(), Some(serial));
    let script = build_boot_script(
        &state,
        query.mac,
        identity,
        &headers,
        connect.map(|value| value.0),
        checker,
    )
    .await?;
    Ok(ipxe_response(script))
}

pub async fn boot_select_profile(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    Query(query): Query<BootQuery>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let profile_id = boot_profile_id_from_path(&profile_id)?;
    let profile = db::get_profile(&state.db, profile_id).await?;
    if !profile.enabled || !boot_logic::profile_has_boot_action(&profile) {
        return Err(AppError::NotFound);
    }

    let checker = is_local_checker_request(&query, &headers, connect.as_ref().map(|value| value.0));
    let identity = query.reported_identity();
    let mac = normalized_optional_mac(query.mac)?;
    let serial = clean_optional(identity.serial.clone());
    let (device, known_device) = if checker {
        (None, false)
    } else {
        identify_selecting_client(&state, mac.as_deref(), &identity, profile.id).await?
    };

    let selected_mac = mac
        .as_deref()
        .or_else(|| device.as_ref().map(|device| device.mac.as_str()));
    let script = render_selected_profile(
        &state,
        &profile,
        selected_mac,
        device.as_ref(),
        Some(&identity),
    )
    .await?;

    if !checker {
        record_boot_event(
            &state,
            &BootEventInput {
                mac: mac.as_deref(),
                serial: serial.as_deref(),
                device: device.as_ref(),
                known_device,
                selected_profile: Some(&profile),
            },
            connect.map(|value| value.0),
            &headers,
        )
        .await?;
    }

    Ok(ipxe_response(script))
}

/// The computer that chose `profile_id` from a menu, and whether it was
/// known. The choice is recorded on its row. When another computer boots
/// through the MAC's adapter, the choice is not recorded on that row, and the
/// installer grant carries no reinstall binding.
pub(super) async fn identify_selecting_client(
    state: &AppState,
    mac: Option<&str>,
    identity: &BootIdentity,
    profile_id: i64,
) -> AppResult<(Option<Device>, bool)> {
    if let Some(mac) = mac {
        if let Some((device, known)) = resolve_mac_request(state, mac, identity).await? {
            db::set_device_last_selected(&state.db, device.id, profile_id).await?;
            return Ok((Some(device), known));
        }
    } else if let Some(found) = device_by_serial_alone(state, identity).await? {
        let touched = db::touch_device_seen(&state.db, found.id).await?;
        db::set_device_last_selected(&state.db, touched.id, profile_id).await?;
        return Ok((Some(touched), true));
    }
    Ok((None, false))
}

pub async fn boot_kexec(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> AppResult<Response> {
    let mac = normalize_mac(&mac)?;
    let device = db::get_device_by_mac(&state.db, &mac)
        .await?
        .ok_or(AppError::NotFound)?;
    let profile_id = device.one_time_profile_id.ok_or(AppError::NotFound)?;
    let profile = db::get_profile(&state.db, profile_id).await?;
    if !profile.enabled || profile.profile_type != BootProfileType::NestInstaller {
        return Err(AppError::NotFound);
    }
    // The computer's own agent asks, on Manage's signed command: there is no
    // network boot whose identity could be checked.
    let launch =
        create_installer_launch(&state, &profile, &device.mac, Some(&device), None).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(launch),
    )
        .into_response())
}

async fn build_boot_script(
    state: &AppState,
    mac: Option<String>,
    identity: BootIdentity,
    headers: &HeaderMap,
    connect: Option<SocketAddr>,
    checker: bool,
) -> AppResult<String> {
    let mac = normalized_optional_mac(mac)?;
    let client = identify_boot_client(state, mac, identity, checker).await?;
    let BootClient {
        mac,
        identity,
        serial,
        device,
        known_device,
        other_computer,
    } = client;

    let profiles = db::list_enabled_profiles(&state.db).await?;
    let selection = choose_boot_profile(
        &profiles,
        device.as_ref(),
        known_device,
        other_computer.is_some(),
        mac.as_deref(),
        checker,
    );

    let selected_profile = selection.profile.cloned();
    let selected_script = if let Some(profile) = selected_profile.as_ref() {
        let selected_mac = mac
            .as_deref()
            .or_else(|| device.as_ref().map(|device| device.mac.as_str()));
        match render_selected_profile(
            state,
            profile,
            selected_mac,
            device.as_ref(),
            Some(&identity),
        )
        .await
        {
            Ok(script) => Some(script),
            Err(error) => {
                if selection.source == boot_logic::SelectionSource::AutomaticEnrollment {
                    if let Some(device) = device.as_ref() {
                        // A transient runtime/session failure must not turn a
                        // fresh MAC into a permanent manual-menu recovery. The
                        // conditional delete preserves any row claimed by a
                        // concurrent managed sync or operator assignment.
                        let _ =
                            db::remove_unclaimed_auto_discovered_device(&state.db, device.id).await;
                    }
                }
                return Err(error);
            }
        }
    } else {
        None
    };

    if !checker {
        if let (Some(device), Some(profile)) = (device.as_ref(), selected_profile.as_ref()) {
            record_selection(state, device, profile, selection.source).await?;
        }
        record_boot_event(
            state,
            &BootEventInput {
                mac: mac.as_deref(),
                serial: serial.as_deref(),
                device: device.as_ref(),
                known_device,
                selected_profile: selected_profile.as_ref(),
            },
            connect,
            headers,
        )
        .await?;
    }

    if selected_profile.is_some() {
        Ok(selected_script.expect("selected profile has a rendered script"))
    } else {
        let runtime = state.runtime_settings();
        // Nest does not need to guess whether installation finished. A real,
        // known MAC first boots local drive 0x80; UEFI falls back to its next
        // BootOrder entry if direct chaining fails, while legacy BIOS falls
        // through to the menu. Health checks and MAC-less requests never hand
        // off automatically. Neither does a computer booting through another
        // computer's adapter, unless Tiaris knows it as installed: on UEFI the
        // handoff would leave a blank laptop in firmware without ever showing
        // it the menu.
        let context = match other_computer {
            Some(OtherComputer::Installed) => boot_logic::MenuContext::KnownComputer,
            Some(OtherComputer::Known) => boot_logic::MenuContext::KnownOnSharedAdapter,
            Some(OtherComputer::Unknown) => boot_logic::MenuContext::AdapterOfAnotherComputer,
            None if automatic_local_handoff_allowed(checker, known_device, mac.as_deref()) => {
                boot_logic::MenuContext::KnownComputer
            }
            None => boot_logic::MenuContext::Unrecognized,
        };
        // Menu links carry only a usable serial and UUID; otherwise iPXE
        // re-sends its own, so a truncated or placeholder value never reaches
        // selection.
        let link_serial = identity.serial.as_deref().and_then(usable_serial);
        Ok(boot_logic::render_menu(
            &runtime.public_base_url,
            &profiles,
            boot_logic::MenuIdentity {
                mac: mac.as_deref(),
                serial: link_serial.as_deref(),
                uuid: identity.uuid.as_deref(),
            },
            runtime.menu_timeout_ms,
            context,
        ))
    }
}

/// What the Nest knows about the computer behind one boot request.
pub(super) struct BootClient {
    pub mac: Option<String>,
    /// What the request said about its computer; identity uses the
    /// untruncated serial.
    pub identity: BootIdentity,
    /// The bounded serial for boot events and menu links.
    pub serial: Option<String>,
    pub device: Option<Device>,
    pub known_device: bool,
    /// Another computer boots through this MAC's network adapter.
    pub other_computer: Option<OtherComputer>,
}

/// Who boots through another computer's network adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OtherComputer {
    /// Tiaris knows it as an installed computer.
    Installed,
    /// Tiaris knows it while it is being installed, or this Nest knows its
    /// serial from another adapter.
    Known,
    /// Nothing says which computer it is.
    Unknown,
}

pub(super) async fn identify_boot_client(
    state: &AppState,
    mac: Option<String>,
    identity: BootIdentity,
    checker: bool,
) -> AppResult<BootClient> {
    // Identity uses the untruncated value; the event and menu links the
    // bounded one.
    let serial = clean_optional(identity.serial.clone());
    let mut client = BootClient {
        mac,
        identity,
        serial,
        device: None,
        known_device: false,
        other_computer: None,
    };
    if checker {
        return Ok(client);
    }
    if let Some(mac) = client.mac.as_deref() {
        match resolve_mac_request(state, mac, &client.identity).await? {
            Some((device, known)) => {
                client.known_device = known;
                client.device = Some(device);
            }
            None => {
                client.other_computer = Some(other_computer(state, &client.identity).await?);
            }
        }
    } else if let Some(found) = device_by_serial_alone(state, &client.identity).await? {
        client.known_device = true;
        client.device = Some(db::touch_device_seen(&state.db, found.id).await?);
    }
    Ok(client)
}

/// A request without a MAC address names its computer by serial alone; a
/// reinstall armed on that row still goes only to the computer Manage names.
async fn device_by_serial_alone(
    state: &AppState,
    identity: &BootIdentity,
) -> AppResult<Option<Device>> {
    let Some(serial) = identity.serial.as_deref().and_then(usable_serial) else {
        return Ok(None);
    };
    let Some(found) = db::get_device_by_serial(&state.db, &serial).await? else {
        return Ok(None);
    };
    if let Some(request_id) = db::reinstall_request_for_mac(&state.db, &found.mac).await? {
        let record = boot_machines::load(&state.config.paths.data_dir);
        if record.reinstall_check(&request_id, identity) == ReinstallCheck::NotThisComputer {
            return Ok(None);
        }
    }
    Ok(Some(found))
}

pub(super) fn choose_boot_profile<'a>(
    profiles: &'a [BootProfile],
    device: Option<&Device>,
    known_device: bool,
    other_computer: bool,
    mac: Option<&str>,
    checker: bool,
) -> boot_logic::ProfileSelection<'a> {
    let selection_device = if known_device { device } else { None };
    // A first request from a new MAC may enter the sole default enrollment
    // profile automatically. This only starts the signed installer runtime;
    // destructive installation still requires explicit approval in Tiaris.
    // A computer that is not the one registered for its MAC is booting
    // through another computer's network adapter. It is neither that
    // computer nor provably new: it gets the menu, so an installed laptop
    // passing through a shared adapter never enters the installer by itself.
    let allow_automatic_enrollment =
        automatic_enrollment_allowed(checker, known_device, other_computer, mac);
    boot_logic::choose_profile(selection_device, profiles, allow_automatic_enrollment)
}

/// Records which profile a computer received: a one-time profile is
/// consumed, an assigned or automatic one becomes its last selection.
pub(super) async fn record_selection(
    state: &AppState,
    device: &Device,
    profile: &BootProfile,
    source: boot_logic::SelectionSource,
) -> AppResult<()> {
    match source {
        boot_logic::SelectionSource::OneTime => {
            db::consume_one_time_profile(&state.db, device.id, profile.id).await?;
        }
        boot_logic::SelectionSource::Assigned
        | boot_logic::SelectionSource::AutomaticEnrollment => {
            db::set_device_last_selected(&state.db, device.id, profile.id).await?;
        }
        boot_logic::SelectionSource::Menu => {}
    }
    Ok(())
}

pub(super) struct BootEventInput<'a> {
    pub mac: Option<&'a str>,
    pub serial: Option<&'a str>,
    pub device: Option<&'a Device>,
    pub known_device: bool,
    pub selected_profile: Option<&'a BootProfile>,
}

pub(super) async fn record_boot_event(
    state: &AppState,
    input: &BootEventInput<'_>,
    connect: Option<SocketAddr>,
    headers: &HeaderMap,
) -> AppResult<()> {
    db::insert_boot_event(
        &state.db,
        NewBootEvent {
            device_id: input.device.map(|device| device.id),
            mac: input
                .mac
                .map(ToOwned::to_owned)
                .or_else(|| input.device.map(|device| device.mac.clone())),
            serial_number: input
                .serial
                .map(ToOwned::to_owned)
                .or_else(|| input.device.and_then(|device| device.serial_number.clone())),
            ip_address: remote_ip(connect, headers),
            user_agent: user_agent(headers),
            selected_profile_id: input.selected_profile.map(|profile| profile.id),
            selected_profile_name: input.selected_profile.map(|profile| profile.name.clone()),
            known_device: input.known_device,
        },
    )
    .await?;
    Ok(())
}

fn automatic_enrollment_allowed(
    checker: bool,
    known_device: bool,
    other_computer: bool,
    mac: Option<&str>,
) -> bool {
    !checker && !known_device && !other_computer && mac.is_some()
}

/// Which computer a request with a MAC address is: the MAC's row and
/// whether it existed, or `None` when another computer is booting through
/// that network adapter (the row is left untouched). A network reinstall armed
/// on the MAC goes only to the computer Manage says it is for: its system
/// UUID decides when the boot reports one, even when the serial stored for
/// the MAC is another laptop's; on a shared MAC a boot that cannot prove it
/// never gets it. Otherwise a usable serial that differs from the row's means
/// another computer, as before.
async fn resolve_mac_request(
    state: &AppState,
    mac: &str,
    identity: &BootIdentity,
) -> AppResult<Option<(Device, bool)>> {
    let pool = &state.db;
    let serial = identity.serial.as_deref();
    if let Some(request_id) = db::reinstall_request_for_mac(pool, mac).await? {
        let record = boot_machines::load(&state.config.paths.data_dir);
        match record.reinstall_check(&request_id, identity) {
            ReinstallCheck::Proven => {
                return Ok(Some(
                    match db::upsert_seen_device(pool, mac, serial).await? {
                        db::SeenDevice::Device { device, known } => (device, known),
                        // The row holds another laptop's serial: its reinstall
                        // is this computer's, the row's own assignment is not.
                        db::SeenDevice::SerialConflict { registered } => {
                            let mut device = db::touch_device_seen(pool, registered.id).await?;
                            device.default_profile_id = None;
                            (device, true)
                        }
                    },
                ));
            }
            ReinstallCheck::NotThisComputer => {
                tracing::warn!(
                    mac,
                    "another computer than the one this MAC's reinstall is for is booting through it; showing the menu without the reinstall"
                );
                return Ok(None);
            }
            ReinstallCheck::Unnamed => {}
        }
    }
    match db::upsert_seen_device(pool, mac, serial).await? {
        db::SeenDevice::Device { device, known } => Ok(Some((device, known))),
        db::SeenDevice::SerialConflict { .. } => {
            // Serial numbers stay out of logs, like the query strings that
            // carry them; the boot event records the reported one.
            tracing::warn!(
                mac,
                "network boot serial differs from the computer registered for this MAC; showing the menu without its assignment"
            );
            Ok(None)
        }
    }
}

/// Who boots through another computer's adapter: a computer Tiaris knows by
/// its system UUID, one whose serial this Nest knows from another adapter,
/// or nobody known.
async fn other_computer(state: &AppState, identity: &BootIdentity) -> AppResult<OtherComputer> {
    let record = boot_machines::load(&state.config.paths.data_dir);
    match record.known_machine(identity) {
        Some(true) => return Ok(OtherComputer::Installed),
        Some(false) => return Ok(OtherComputer::Known),
        None => {}
    }
    if let Some(serial) = identity.serial.as_deref().and_then(usable_serial) {
        if db::serial_is_registered(&state.db, &serial).await? {
            return Ok(OtherComputer::Known);
        }
    }
    Ok(OtherComputer::Unknown)
}

fn automatic_local_handoff_allowed(checker: bool, known_device: bool, mac: Option<&str>) -> bool {
    !checker && known_device && mac.is_some()
}

async fn render_selected_profile(
    state: &AppState,
    profile: &BootProfile,
    mac: Option<&str>,
    device: Option<&Device>,
    identity: Option<&BootIdentity>,
) -> AppResult<String> {
    if profile.profile_type != BootProfileType::NestInstaller {
        let runtime = state.runtime_settings();
        return boot_logic::render_profile_script(profile, &runtime.public_base_url);
    }
    let mac = mac.ok_or_else(|| {
        AppError::Validation("a normalized MAC is required for Nest installer boot".to_string())
    })?;
    let launch = create_installer_launch(state, profile, mac, device, identity).await?;
    Ok(crate::netboot::render_ipxe_launch(&launch))
}

async fn create_installer_launch(
    state: &AppState,
    profile: &BootProfile,
    mac: &str,
    device: Option<&Device>,
    identity: Option<&BootIdentity>,
) -> AppResult<crate::netboot::BootSessionLaunch> {
    create_installer_launch_for_runtime(state, profile, mac, device, identity)
        .await
        .map(|(launch, _)| launch)
}

/// The signed installer session for `profile`, bound to the device row's
/// managed identity and reinstall request exactly as the iPXE path binds it,
/// with the identity of the runtime it launches. A network boot (`identity`)
/// that is not the computer Manage named for the reinstall gets no binding,
/// whatever chose the row.
pub(super) async fn create_installer_launch_for_runtime(
    state: &AppState,
    profile: &BootProfile,
    mac: &str,
    device: Option<&Device>,
    identity: Option<&BootIdentity>,
) -> AppResult<(
    crate::netboot::BootSessionLaunch,
    crate::netboot::ActiveRuntimeIdentity,
)> {
    let profile_id = profile.managed_profile_id.as_deref().ok_or_else(|| {
        AppError::Config("Nest installer profile has no managed identity".to_string())
    })?;
    let binding: Option<(Option<String>, Option<String>)> = if let Some(device) = device {
        sqlx::query_as("SELECT managed_device_id, reinstall_request_id FROM devices WHERE id = ?")
            .bind(device.id)
            .fetch_optional(&state.db)
            .await?
    } else {
        None
    };
    let binding = binding.filter(|(_, request_id)| {
        let (Some(identity), Some(request_id)) = (identity, request_id.as_deref()) else {
            return true;
        };
        boot_machines::load(&state.config.paths.data_dir).reinstall_check(request_id, identity)
            != ReinstallCheck::NotThisComputer
    });
    crate::netboot::create_boot_session_for_runtime(
        state,
        mac,
        Some(profile_id),
        binding.as_ref().and_then(|value| value.0.as_deref()),
        binding.as_ref().and_then(|value| value.1.as_deref()),
    )
    .await
    .map_err(|_| AppError::Config("could not create signed Nest boot session".to_string()))
}

fn normalized_optional_mac(mac: Option<String>) -> AppResult<Option<String>> {
    mac.map(|mac| normalize_mac(&mac)).transpose()
}

pub(super) fn boot_profile_id_from_path(value: &str) -> AppResult<i64> {
    let parsed = value.parse::<i64>().map_err(|_| AppError::NotFound)?;
    if parsed <= 0 {
        return Err(AppError::NotFound);
    }
    Ok(parsed)
}

pub(super) fn clean_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| clean_text(&value, MAX_BOOT_SERIAL_LEN))
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| clean_text(value, MAX_BOOT_USER_AGENT_LEN))
}

fn remote_ip(connect: Option<SocketAddr>, headers: &HeaderMap) -> Option<String> {
    let peer_is_loopback = connect.map(|addr| addr.ip().is_loopback()).unwrap_or(false);
    if peer_is_loopback {
        if let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(last_valid_forwarded_ip)
        {
            return Some(forwarded);
        }
    }

    connect.map(|addr| addr.ip().to_string())
}

fn is_local_checker_request(
    query: &BootQuery,
    headers: &HeaderMap,
    connect: Option<SocketAddr>,
) -> bool {
    if !matches!(query.tiaris_check.as_deref(), Some("1")) {
        return false;
    }
    if !connect.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return false;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(last_valid_forwarded_ip)
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        .map(|ip| ip.is_loopback())
        .unwrap_or(true)
}

fn last_valid_forwarded_ip(value: &str) -> Option<String> {
    value
        .split(',')
        .rev()
        .find_map(|part| part.trim().parse::<IpAddr>().ok().map(|ip| ip.to_string()))
}

fn clean_text(value: &str, max_chars: usize) -> Option<String> {
    let cleaned = value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(max_chars).collect())
    }
}

fn ipxe_response(script: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
            (header::PRAGMA, "no-cache"),
            (header::EXPIRES, "0"),
        ],
        script,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{
        BootQuery, automatic_enrollment_allowed, automatic_local_handoff_allowed,
        boot_profile_id_from_path, clean_optional, ipxe_response, is_local_checker_request,
        remote_ip, user_agent,
    };

    #[test]
    fn automatic_enrollment_is_limited_to_a_real_first_mac_request() {
        let mac = Some("aa:bb:cc:dd:ee:ff");
        assert!(automatic_enrollment_allowed(false, false, false, mac));
        assert!(!automatic_enrollment_allowed(true, false, false, mac));
        assert!(!automatic_enrollment_allowed(false, true, false, mac));
        assert!(!automatic_enrollment_allowed(false, false, true, mac));
        assert!(!automatic_enrollment_allowed(false, false, false, None));
    }

    #[test]
    fn automatic_local_handoff_is_limited_to_a_real_known_mac_request() {
        assert!(automatic_local_handoff_allowed(
            false,
            true,
            Some("aa:bb:cc:dd:ee:ff")
        ));
        assert!(!automatic_local_handoff_allowed(
            true,
            true,
            Some("aa:bb:cc:dd:ee:ff")
        ));
        assert!(!automatic_local_handoff_allowed(
            false,
            false,
            Some("aa:bb:cc:dd:ee:ff")
        ));
        assert!(!automatic_local_handoff_allowed(false, true, None));
    }

    #[test]
    fn ipxe_responses_are_not_cached() {
        let response = ipxe_response("#!ipxe\n".to_string());

        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store, max-age=0"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(response.headers().get(header::EXPIRES).unwrap(), "0");
    }

    #[test]
    fn boot_request_serial_is_bounded_and_control_characters_are_removed() {
        let serial = format!(" serial\n{} ", "x".repeat(200));

        let cleaned = clean_optional(Some(serial)).unwrap();

        assert_eq!(cleaned.chars().count(), 128);
        assert!(!cleaned.contains('\n'));
        assert!(cleaned.starts_with("serial "));
    }

    #[test]
    fn boot_request_user_agent_is_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_str(&format!("ipxe/1.0 {}", "x".repeat(400))).unwrap(),
        );

        let value = user_agent(&headers).unwrap();

        assert_eq!(value.chars().count(), 256);
        assert!(value.starts_with("ipxe/1.0 "));
    }

    #[test]
    fn boot_select_profile_id_rejects_invalid_values_as_not_found() {
        assert_eq!(boot_profile_id_from_path("42").unwrap(), 42);
        assert!(boot_profile_id_from_path("0").is_err());
        assert!(boot_profile_id_from_path("-1").is_err());
        assert!(boot_profile_id_from_path("not-a-number").is_err());
        assert!(boot_profile_id_from_path("999999999999999999999999999999").is_err());
    }

    #[test]
    fn forwarded_ip_is_trusted_only_from_loopback_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 198.51.100.20"),
        );
        let loopback: SocketAddr = "127.0.0.1:50200".parse().unwrap();
        let remote: SocketAddr = "192.0.2.55:50200".parse().unwrap();

        assert_eq!(
            remote_ip(Some(loopback), &headers).as_deref(),
            Some("198.51.100.20")
        );
        assert_eq!(
            remote_ip(Some(remote), &headers).as_deref(),
            Some("192.0.2.55")
        );
    }

    #[test]
    fn forwarded_ip_ignores_invalid_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("spoofed, 2001:db8::12"),
        );
        let loopback: SocketAddr = "127.0.0.1:50200".parse().unwrap();

        assert_eq!(
            remote_ip(Some(loopback), &headers).as_deref(),
            Some("2001:db8::12")
        );
    }

    #[test]
    fn checker_marker_requires_loopback_request() {
        let query = BootQuery {
            mac: None,
            serial: None,
            serial_hex: None,
            uuid: None,
            tiaris_check: Some("1".to_string()),
        };
        let mut headers = HeaderMap::new();
        let loopback: SocketAddr = "127.0.0.1:50200".parse().unwrap();
        let remote: SocketAddr = "192.0.2.55:50200".parse().unwrap();

        assert!(is_local_checker_request(&query, &headers, Some(loopback)));
        assert!(!is_local_checker_request(&query, &headers, Some(remote)));

        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.20"));
        assert!(!is_local_checker_request(&query, &headers, Some(loopback)));

        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.20, 127.0.0.1"),
        );
        assert!(is_local_checker_request(&query, &headers, Some(loopback)));
    }

    #[test]
    fn reported_serial_prefers_a_menu_link_value_over_the_ipxe_hex_expansion() {
        let query = |serial: Option<&str>, serial_hex: Option<&str>| BootQuery {
            mac: None,
            serial: serial.map(str::to_string),
            serial_hex: serial_hex.map(str::to_string),
            uuid: None,
            tiaris_check: None,
        };

        assert_eq!(
            query(Some("5CG1"), Some("4142"))
                .reported_serial()
                .as_deref(),
            Some("5CG1")
        );
        assert_eq!(
            query(Some(" "), Some("4142")).reported_serial().as_deref(),
            Some("AB")
        );
        assert_eq!(query(None, Some("")).reported_serial(), None);
        assert_eq!(query(None, Some("not-hex")).reported_serial(), None);
        assert_eq!(query(None, None).reported_serial(), None);
    }

    #[test]
    fn checker_marker_requires_exact_value() {
        let query = BootQuery {
            mac: None,
            serial: None,
            serial_hex: None,
            uuid: None,
            tiaris_check: Some("true".to_string()),
        };
        let headers = HeaderMap::new();
        let loopback: SocketAddr = "127.0.0.1:50200".parse().unwrap();

        assert!(!is_local_checker_request(&query, &headers, Some(loopback)));
    }
}
