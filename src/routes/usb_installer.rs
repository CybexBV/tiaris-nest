//! `/usb-installer/v1/*`: the USB installer stick protocol.
//!
//! The stick asks the same questions iPXE asks `/boot/<mac>` and
//! `/boot/select/<profile>`, and gets the same answers: one selection rule
//! set, one boot-session signer, one boot-event log. Only the shape differs:
//! JSON instead of an iPXE script, and only Nest installer profiles, because
//! a stick can start nothing else.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use super::boot::{
    BootEventInput, BootQuery, boot_profile_id_from_path, choose_boot_profile, clean_optional,
    create_installer_launch_for_runtime, identify_boot_client, identify_selecting_client,
    record_boot_event, record_selection,
};
use crate::{
    AppState, boot as boot_logic, db,
    error::AppError,
    models::{BootProfile, BootProfileType, normalize_mac},
    usb_installer::{
        self, ERROR_INTERNAL, ERROR_INVALID_REQUEST, ERROR_PROFILE_UNAVAILABLE,
        ERROR_RUNTIME_UNAVAILABLE, ERROR_SESSION_UNAVAILABLE, NOTICE_ADAPTER_OF_ANOTHER_COMPUTER,
        NOTICE_KNOWN_COMPUTER, PROTOCOL_SCHEMA, UsbBootAction, UsbBootResponse, UsbLaunch,
        UsbMenuProfile, UsbRuntimeResponse, error_response, json_response,
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
            action: UsbBootAction::Launch {
                launch: Box::new(launch),
            },
        },
    )
}

/// `GET /usb-installer/v1/boot?mac=&serial_hex=`: what `/boot/<mac>` would
/// start, as a launch, or the installer menu.
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
    match usb_boot_inner(&state, mac, query.reported_serial(), &headers, connect).await {
        Ok(response) => response,
        Err(error) => internal_error(error),
    }
}

async fn usb_boot_inner(
    state: &AppState,
    mac: String,
    reported_serial: Option<String>,
    headers: &HeaderMap,
    connect: Option<SocketAddr>,
) -> Result<Response, AppError> {
    let client = identify_boot_client(state, Some(mac.clone()), reported_serial, false).await?;
    let profiles = db::list_enabled_profiles(&state.db).await?;
    let selection = choose_boot_profile(
        &profiles,
        client.device.as_ref(),
        client.known_device,
        client.serial_conflict,
        Some(&mac),
        false,
    );

    // A selection the stick can start runs exactly as on PXE. A known
    // computer assigned to its local disk or to custom iPXE gets the menu:
    // someone chose to start the installer stick on it.
    if let Some(profile) = selection.profile.filter(|profile| launchable(profile)) {
        let launch =
            match create_installer_launch_for_runtime(state, profile, &mac, client.device.as_ref())
                .await
            {
                Ok((session, runtime)) => UsbLaunch::new(session, runtime),
                Err(error) => {
                    if selection.source == boot_logic::SelectionSource::AutomaticEnrollment {
                        if let Some(device) = client.device.as_ref() {
                            // As on PXE: a transient failure must not leave a
                            // fresh MAC behind as a known computer.
                            let _ =
                                db::remove_unclaimed_auto_discovered_device(&state.db, device.id)
                                    .await;
                        }
                    }
                    tracing::warn!(error = %error, "USB installer session could not be created");
                    return Ok(session_unavailable(state).await);
                }
            };
        if let Some(device) = client.device.as_ref() {
            record_selection(state, device, profile, selection.source).await?;
        }
        record_boot_event(
            state,
            &BootEventInput {
                mac: Some(&mac),
                serial: client.serial.as_deref(),
                device: client.device.as_ref(),
                known_device: client.known_device,
                selected_profile: Some(profile),
            },
            connect,
            headers,
        )
        .await?;
        return Ok(launch_response(launch));
    }

    record_boot_event(
        state,
        &BootEventInput {
            mac: Some(&mac),
            serial: client.serial.as_deref(),
            device: client.device.as_ref(),
            known_device: client.known_device,
            selected_profile: None,
        },
        connect,
        headers,
    )
    .await?;
    let notice = if client.serial_conflict {
        Some(NOTICE_ADAPTER_OF_ANOTHER_COMPUTER)
    } else if client.known_device {
        Some(NOTICE_KNOWN_COMPUTER)
    } else {
        None
    };
    let menu = boot_logic::installer_menu_profiles(&profiles)
        .into_iter()
        .map(|profile| UsbMenuProfile {
            id: profile.id,
            name: profile.name.clone(),
        })
        .collect();
    Ok(json_response(
        StatusCode::OK,
        &UsbBootResponse {
            schema: PROTOCOL_SCHEMA,
            action: UsbBootAction::Menu {
                notice,
                profiles: menu,
            },
        },
    ))
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

/// `GET /usb-installer/v1/select/<profile>?mac=&serial_hex=`: the launch for
/// a profile chosen from the stick's menu, bound as `/boot/select` binds it.
pub async fn usb_select(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
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
    let Ok(profile_id) = boot_profile_id_from_path(&profile_id) else {
        return error_response(StatusCode::NOT_FOUND, ERROR_PROFILE_UNAVAILABLE);
    };
    let profile = match db::get_profile(&state.db, profile_id).await {
        Ok(profile) => profile,
        Err(AppError::NotFound) => {
            return error_response(StatusCode::NOT_FOUND, ERROR_PROFILE_UNAVAILABLE);
        }
        Err(error) => return internal_error(error),
    };
    // One-time profiles belong to one computer's network reinstall; the
    // menu never offers them.
    if !launchable(&profile) || profile.one_time {
        return error_response(StatusCode::NOT_FOUND, ERROR_PROFILE_UNAVAILABLE);
    }
    let connect = connect.map(|value| value.0);
    let reported_serial = query.reported_serial();
    let result = async {
        let (device, known_device) =
            identify_selecting_client(&state, Some(&mac), reported_serial.as_deref(), profile.id)
                .await?;
        let launch = match create_installer_launch_for_runtime(
            &state,
            &profile,
            &mac,
            device.as_ref(),
        )
        .await
        {
            Ok((session, runtime)) => UsbLaunch::new(session, runtime),
            Err(error) => {
                tracing::warn!(error = %error, "USB installer session could not be created");
                return Ok(session_unavailable(&state).await);
            }
        };
        let serial = clean_optional(reported_serial.clone());
        record_boot_event(
            &state,
            &BootEventInput {
                mac: Some(&mac),
                serial: serial.as_deref(),
                device: device.as_ref(),
                known_device,
                selected_profile: Some(&profile),
            },
            connect,
            &headers,
        )
        .await?;
        Ok::<_, AppError>(launch_response(launch))
    }
    .await;
    result.unwrap_or_else(internal_error)
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
