use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tiaris_nest::provisioning::{
    LEGACY_MANAGE_ORIGIN, MAX_ENVELOPE_VALIDITY_HOURS, NetworkRuntimeOptions, PrepareOptions,
    REQUIRED_MANAGE_ORIGIN, SETUP_CLAIM_PROTOCOL, SETUP_STATUS_PATH, effective_manage_origin,
    prepare, reconcile_network_runtime, validate_installed_state, validate_legacy_state_promotion,
};

#[derive(Debug, Parser)]
#[command(
    name = "tiaris-nest-bootstrap",
    about = "Fail-closed signed appliance bootstrap",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the immutable Management origin compiled into this bootstrap.
    RequiredManageOrigin,
    /// Print the one older Management origin whose state this build accepts
    /// (empty when none).
    LegacyManageOrigin,
    /// Print the origin this build uses for a durably recorded origin, or
    /// fail when the recorded origin is neither its own nor its legacy name.
    EffectiveManageOrigin { stored: String },
    /// Print the longest setup-ISO validity, in hours, this bootstrap accepts.
    EnvelopeMaxValidityHours,
    /// Print the setup claim protocol a generic (all-zero slot) ISO speaks.
    SetupClaimProtocol,
    /// Claim this provisioned ISO (or, from an all-zero slot, register and wait
    /// to be claimed), wait for approval, and install.
    Prepare {
        #[arg(long, default_value = "/cdrom/TIARIS_PROVISIONING.BIN")]
        envelope: PathBuf,
        #[arg(long, default_value = "/cdrom/tiaris/provisioning-public-keys")]
        provisioning_keys: PathBuf,
        #[arg(long, default_value = "/cdrom/tiaris/release-public-key")]
        release_public_key: PathBuf,
        #[arg(long, default_value = "/run/tiaris-state")]
        state_mount: PathBuf,
        /// Public progress projection read by the tty1 setup kiosk.
        #[arg(long, default_value = SETUP_STATUS_PATH)]
        setup_status: PathBuf,
    },
    /// Reconcile the appliance's advertised boot URL with its active wired IPv4 address.
    ReconcileNetworkRuntime {
        #[arg(long, default_value = "/etc/tiaris-nest/config.toml")]
        config: PathBuf,
        #[arg(
            long,
            default_value = "/var/lib/tiaris-nest/control/netplan-approved.json"
        )]
        network_plan: PathBuf,
    },
    /// Verify recurring installed identity and an acknowledged managed network.
    ValidateInstalledState {
        #[arg(long, default_value = "/var/lib/tiaris-nest/state")]
        state_mount: PathBuf,
        #[arg(long, default_value = "/etc/tiaris-nest/config.toml")]
        config: PathBuf,
        #[arg(
            long,
            default_value = "/usr/share/tiaris-nest/provisioning-public-keys"
        )]
        provisioning_keys: PathBuf,
    },
    /// Authenticate a dev.3 flat state migration against installed trust anchors.
    ValidateLegacyStatePromotion {
        #[arg(long, default_value = "/var/lib/tiaris-nest/state")]
        state_mount: PathBuf,
        #[arg(long, default_value = "/etc/tiaris-nest/config.toml")]
        config: PathBuf,
        #[arg(
            long,
            default_value = "/usr/share/tiaris-nest/provisioning-public-keys"
        )]
        provisioning_keys: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::RequiredManageOrigin => {
            println!("{REQUIRED_MANAGE_ORIGIN}");
            Ok(())
        }
        Command::LegacyManageOrigin => {
            println!("{}", LEGACY_MANAGE_ORIGIN.unwrap_or_default());
            Ok(())
        }
        Command::EffectiveManageOrigin { stored } => match effective_manage_origin(&stored) {
            Some(origin) => {
                println!("{origin}");
                Ok(())
            }
            None => bail!("recorded Management origin is not served by this build"),
        },
        Command::EnvelopeMaxValidityHours => {
            println!("{MAX_ENVELOPE_VALIDITY_HOURS}");
            Ok(())
        }
        Command::SetupClaimProtocol => {
            println!("{SETUP_CLAIM_PROTOCOL}");
            Ok(())
        }
        Command::Prepare {
            envelope,
            provisioning_keys,
            release_public_key,
            state_mount,
            setup_status,
        } => {
            require_root()?;
            let options = PrepareOptions {
                envelope_path: envelope,
                provisioning_keys_path: provisioning_keys,
                release_public_key_path: release_public_key,
                state_mount,
                setup_status_path: Some(setup_status),
                ..PrepareOptions::default()
            };
            prepare(options).await
        }
        Command::ReconcileNetworkRuntime {
            config,
            network_plan,
        } => {
            require_root()?;
            let outcome =
                reconcile_network_runtime(NetworkRuntimeOptions::new(config, network_plan))?;
            println!("{}", outcome.as_str());
            Ok(())
        }
        Command::ValidateInstalledState {
            state_mount,
            config,
            provisioning_keys,
        } => {
            require_root()?;
            validate_installed_state(&state_mount, &config, &provisioning_keys)
        }
        Command::ValidateLegacyStatePromotion {
            state_mount,
            config,
            provisioning_keys,
        } => {
            require_root()?;
            validate_legacy_state_promotion(&state_mount, &config, &provisioning_keys)
        }
    }
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("the provisioned installer must run as root")
    }
    Ok(())
}
