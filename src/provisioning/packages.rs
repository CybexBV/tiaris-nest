//! The installer media and the one way it delivers the system: a signed NixOS
//! closure (`nixos_install`).
use super::protocol::{INSTALL_PLAN_SCHEMA_V3, SignedInstallPlan};
use anyhow::{Result, bail};
use std::path::Path;

pub(crate) const RELEASE_PUBLIC_KEY_PATH: &str = "/cdrom/tiaris/release-public-key";
const SYSTEM_CLOSURE_DELIVERY: &str = "system-closure-v1";

/// Only NixOS installer media can install a Nest.
pub(crate) fn require_nixos_media() -> Result<()> {
    if !Path::new("/cdrom/tiaris/nixos-appliance").is_file() {
        bail!("this installer media is not a NixOS Nest ISO")
    }
    Ok(())
}

/// The approved plan installs a signed NixOS system closure.
pub(crate) fn validate_plan_delivery(plan: &SignedInstallPlan) -> Result<()> {
    if plan.schema != INSTALL_PLAN_SCHEMA_V3
        || plan.package_delivery.as_deref() != Some(SYSTEM_CLOSURE_DELIVERY)
    {
        bail!("install plan package delivery does not match this Nest media")
    }
    Ok(())
}
