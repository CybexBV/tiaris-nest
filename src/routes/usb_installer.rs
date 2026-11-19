//! `/usb-installer/v1/*`: the USB installer stick protocol.
//!
//! The stick asks the question iPXE asks `/boot/<mac>` and gets the same
//! answer: one selection rule set, one boot-session signer, one boot-event
//! log. Only the shape differs: JSON instead of an iPXE script, and always an
//! installer, because a stick can start nothing else. A running installer
//! asks the same question to renew its boot grant.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use super::boot::{
    BootEventInput, BootQuery, choose_boot_profile, create_installer_launch_for_runtime,
    identify_boot_client, record_boot_event, record_selection,
};
use crate::{
    AppState, boot as boot_logic,
    boot_machines::BootIdentity,
    db,
    error::AppError,
    models::{BootProfile, BootProfileType, normalize_mac},
    usb_installer::{
        self, ERROR_INTERNAL, ERROR_INVALID_REQUEST, ERROR_PROFILE_UNAVAILABLE,
        ERROR_RUNTIME_UNAVAILABLE, ERROR_SESSION_UNAVAILABLE, PROTOCOL_SCHEMA, UsbBootResponse,
        UsbLaunch, UsbRuntimeResponse, error_response, json_response,
    },
};

fn internal_error(error: AppError) -> Response {
    tracing::warn!(error = %error, "USB installer request failed");
    error_response(StatusCode::INTERNAL_SERVER_ERROR, ERROR_INTERNAL)
}

fn launchable(profile: &BootProfile) -> bool {
    profile.enabled
        && profile.profile_type == BootProfileType::NestInstaller
        && boot_logic::profile_has_boot_action(profile)
}

fn required_mac(query: &BootQuery) -> Option<String> {
    query.mac.as_deref().and_then(|mac| normalize_mac(mac).ok())
}

fn launch_response(launch: UsbLaunch) -> Response {
    json_response(
        StatusCode::OK,
        &UsbBootResponse {
            schema: PROTOCOL_SCHEMA,
            action: "launch",
            launch: Box::new(launch),
        },
    )
}

/// `GET /usb-installer/v1/boot?mac=&serial_hex=&uuid=`: the launch of the
/// installer for this computer.
pub async fn usb_boot(
    State(state): State<AppState>,
    Query(query): Query<BootQuery>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    if let Some(rejected) = usb_installer::reject_outdated_stick(&headers) {
        return rejected;
    }
    let Some(mac) = required_mac(&query) else {
        return error_response(StatusCode::BAD_REQUEST, ERROR_INVALID_REQUEST);
    };
    let connect = connect.map(|value| value.0);
    match usb_boot_inner(&state, mac, query.reported_identity(), &headers, connect).await {
        Ok(response) => response,
        Err(error) => internal_error(error),
    }
}

async fn usb_boot_inner(
    state: &AppState,
    mac: String,
    identity: BootIdentity,
    headers: &HeaderMap,
    connect: Option<SocketAddr>,
) -> Result<Response, AppError> {
    let client = identify_boot_client(state, Some(mac.clone()), identity, false).await?;
    let profiles = db::list_enabled_profiles(&state.db).await?;
    let selection = choose_boot_profile(&profiles, &client, false);

    // A selection the stick can start runs exactly as on PXE. Where PXE
    // would start the disk, custom iPXE or the menu, the stick starts the
    // Nest's installer: someone started the installer stick on this computer
    // on purpose, and nothing is erased before an administrator approves it
    // in Tiaris.
    let chosen = match selection.profile.filter(|profile| launchable(profile)) {
        Some(profile) => Some((profile, selection.source)),
        None => boot_logic::default_installer_profile(&profiles)
            .map(|profile| (profile, boot_logic::SelectionSource::AutomaticEnrollment)),
    };
    let event = |selected_profile| BootEventInput {
        mac: Some(&mac),
        serial: client.serial.as_deref(),
        device: client.device.as_ref(),
        known_device: client.known_device,
        selected_profile,
    };
    let Some((profile, source)) = chosen else {
        record_boot_event(state, &event(None), connect, headers).await?;
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            ERROR_PROFILE_UNAVAILABLE,
        ));
    };
    let launch = match create_installer_launch_for_runtime(
        state,
        profile,
        &mac,
        client.device.as_ref(),
        Some(&client.identity),
    )
    .await
    {
        Ok((session, runtime)) => UsbLaunch::new(session, runtime),
        Err(error) => {
            if source == boot_logic::SelectionSource::AutomaticEnrollment && !client.known_device {
                if let Some(device) = client.device.as_ref() {
                    // As on PXE: a transient failure must not leave a
                    // fresh MAC behind as seen before.
                    let _ = db::remove_unclaimed_auto_discovered_device(&state.db, device.id).await;
                }
            }
            tracing::warn!(error = %error, "USB installer session could not be created");
            return Ok(session_unavailable(state).await);
        }
    };
    if let Some(device) = client.device.as_ref() {
        record_selection(state, device, profile, source).await?;
    }
    record_boot_event(state, &event(Some(profile)), connect, headers).await?;
    Ok(launch_response(launch))
}

/// No verified runtime is a different answer from a failed session: the
/// administrator waits for the Nest runtime, not for a retry.
async fn session_unavailable(state: &AppState) -> Response {
    if crate::netboot::active_runtime_identity(state)
        .await
        .is_err()
    {
        error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_RUNTIME_UNAVAILABLE)
    } else {
        error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_SESSION_UNAVAILABLE)
    }
}

/// `GET /usb-installer/v1/runtime`: the active runtime's identity without a
/// session, so a stick on Wi-Fi can fetch the large root file system before
/// it asks for a ten-minute grant.
pub async fn usb_runtime(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(rejected) = usb_installer::reject_outdated_stick(&headers) {
        return rejected;
    }
    match crate::netboot::active_runtime_identity(&state).await {
        Ok(runtime) => json_response(
            StatusCode::OK,
            &UsbRuntimeResponse {
                schema: PROTOCOL_SCHEMA,
                runtime,
            },
        ),
        Err(_) => error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_RUNTIME_UNAVAILABLE),
    }
}
