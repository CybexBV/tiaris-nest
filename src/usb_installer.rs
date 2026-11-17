//! USB installer stick support: the stick protocol's response bodies.
//!
//! The stick is a small boot program for computers that cannot network-boot
//! (Tiaris `docs/design/usb-installer.md`). It reaches this Nest over a USB
//! Ethernet adapter, built-in Ethernet or Wi-Fi and asks for exactly what iPXE
//! would load: the same selection rules, the same signed boot session, the
//! same runtime. It then starts that runtime with `kexec`.
//!
//! The stick is generic: one image for every Nest, downloaded from Tiaris.
//! It finds its Nest on the local network or from the Nest address file the
//! administrator saves on it; this Nest does not serve or personalize it.

use axum::{
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::netboot::{ActiveRuntimeIdentity, BootSessionLaunch, ComponentDescriptors};

pub const PROTOCOL_SCHEMA: &str = "tiaris.nest.usb-installer.v1";
/// The oldest stick protocol this Nest still answers. A stick reports its
/// protocol as `User-Agent: tiaris-usb-installer/<protocol> ...`; an older
/// one gets `410` and tells the administrator to download a new stick.
pub const MINIMUM_STICK_PROTOCOL: u32 = 1;
const STICK_USER_AGENT_PREFIX: &str = "tiaris-usb-installer/";

pub const ERROR_INVALID_REQUEST: &str = "invalid_request";
pub const ERROR_OUTDATED_STICK: &str = "usb_installer_outdated";
pub const ERROR_PROFILE_UNAVAILABLE: &str = "profile_unavailable";
pub const ERROR_RUNTIME_UNAVAILABLE: &str = "runtime_unavailable";
pub const ERROR_SESSION_UNAVAILABLE: &str = "session_unavailable";
pub const ERROR_INTERNAL: &str = "internal_error";

pub const NOTICE_KNOWN_COMPUTER: &str = "known_computer";
pub const NOTICE_ADAPTER_OF_ANOTHER_COMPUTER: &str = "adapter_of_another_computer";

/// The existing `tiaris.nest.kexec.v1` launch plus the identity of the runtime
/// it starts, so the stick can verify the kernel and initrd it downloads.
#[derive(Clone, Debug, Serialize)]
pub struct UsbLaunch {
    #[serde(flatten)]
    pub session: BootSessionLaunch,
    pub runtime_version: String,
    pub components: ComponentDescriptors,
}

impl UsbLaunch {
    pub fn new(session: BootSessionLaunch, runtime: ActiveRuntimeIdentity) -> Self {
        Self {
            session,
            runtime_version: runtime.runtime_version,
            components: runtime.components,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UsbMenuProfile {
    pub id: i64,
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum UsbBootAction {
    Launch {
        launch: Box<UsbLaunch>,
    },
    Menu {
        notice: Option<&'static str>,
        profiles: Vec<UsbMenuProfile>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct UsbBootResponse {
    pub schema: &'static str,
    #[serde(flatten)]
    pub action: UsbBootAction,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsbRuntimeResponse {
    pub schema: &'static str,
    pub runtime: ActiveRuntimeIdentity,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsbErrorResponse {
    pub schema: &'static str,
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_stick_protocol: Option<u32>,
}

pub fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(body),
    )
        .into_response()
}

pub fn error_response(status: StatusCode, error: &'static str) -> Response {
    json_response(
        status,
        &UsbErrorResponse {
            schema: PROTOCOL_SCHEMA,
            error,
            minimum_stick_protocol: (error == ERROR_OUTDATED_STICK)
                .then_some(MINIMUM_STICK_PROTOCOL),
        },
    )
}

/// The stick protocol a request's `User-Agent` reports, when it comes from a
/// stick. Other clients (a curl check, a browser) report none.
pub fn stick_protocol(headers: &HeaderMap) -> Option<u32> {
    let agent = headers.get(header::USER_AGENT)?.to_str().ok()?;
    let rest = agent.strip_prefix(STICK_USER_AGENT_PREFIX)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() || digits.len() > 6 {
        return None;
    }
    digits.parse().ok()
}

/// `410` for a stick whose protocol this Nest no longer answers.
pub fn reject_outdated_stick(headers: &HeaderMap) -> Option<Response> {
    let protocol = stick_protocol(headers)?;
    (protocol < MINIMUM_STICK_PROTOCOL)
        .then(|| error_response(StatusCode::GONE, ERROR_OUTDATED_STICK))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_agent(agent: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_str(agent).unwrap());
        headers
    }

    #[test]
    fn stick_protocol_is_read_from_the_user_agent() {
        assert_eq!(
            stick_protocol(&headers_with_agent("tiaris-usb-installer/1 (abc123)")),
            Some(1)
        );
        assert_eq!(
            stick_protocol(&headers_with_agent("tiaris-usb-installer/12")),
            Some(12)
        );
        assert_eq!(stick_protocol(&headers_with_agent("curl/8.0")), None);
        assert_eq!(
            stick_protocol(&headers_with_agent("tiaris-usb-installer/x")),
            None
        );
        assert_eq!(stick_protocol(&HeaderMap::new()), None);
    }

    #[test]
    fn only_a_stick_older_than_the_minimum_is_rejected() {
        assert!(reject_outdated_stick(&headers_with_agent("tiaris-usb-installer/1")).is_none());
        assert!(reject_outdated_stick(&headers_with_agent("curl/8.0")).is_none());
        let rejected = reject_outdated_stick(&headers_with_agent("tiaris-usb-installer/0"))
            .expect("protocol 0 is outdated");
        assert_eq!(rejected.status(), StatusCode::GONE);
    }
}
