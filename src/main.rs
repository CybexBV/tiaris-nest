use std::net::SocketAddr;

use anyhow::{Context, bail};
use axum::serve as axum_serve;
use clap::Parser;
use tiaris_nest::{
    AppState,
    appliance::nixos::InsufficientSpace,
    config::{Cli, Command},
    db, router,
};
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let command = cli.command.clone().unwrap_or(Command::Serve);
    if let Command::VerifyApplianceDatabase {
        database,
        rollback_target,
    } = &command
    {
        return tiaris_nest::appliance::nixos::verify_database(database, *rollback_target).await;
    }
    if let Command::RehearseApplianceDatabase { database, output } = &command {
        return tiaris_nest::appliance::nixos::rehearse_database(database, output).await;
    }
    if matches!(command, Command::VerifyApplianceUpdatePolicy) {
        println!(
            "{}",
            tiaris_nest::appliance::schedule::verify_stored()?.display()
        );
        return Ok(());
    }
    if let Command::VerifyApplianceUpdate { space_freed } = &command {
        #[cfg(unix)]
        if effective_uid() != 0 {
            anyhow::bail!("appliance package verification must run as root");
        }
        // The floor follows the Nest's configuration. A configuration that
        // cannot be read must not stop the update that may repair it.
        let build = tiaris_nest::config::AppConfig::load(&cli.config)
            .map(|config| config.build)
            .unwrap_or_default();
        let floor = tiaris_nest::disk::free_space_floor(&build);
        match tiaris_nest::appliance::nixos::verify_update(floor, *space_freed) {
            Ok(packages) => println!("{}", packages.display()),
            Err(error) => match error.downcast_ref::<InsufficientSpace>() {
                Some(short) if !*space_freed => {
                    println!("{}", short.required_available_bytes);
                    std::process::exit(75);
                }
                _ => return Err(error),
            },
        }
        return Ok(());
    }
    let config = tiaris_nest::config::AppConfig::load(&cli.config)
        .with_context(|| format!("failed to load config from {}", cli.config.display()))?;

    if matches!(command, Command::ValidateApplianceConfig) {
        config.validate_appliance_config()?;
        return Ok(());
    }

    if matches!(command, Command::PrintConfig) {
        println!(
            "{}",
            toml::to_string_pretty(&config.redacted_for_display())?
        );
        return Ok(());
    }

    ensure_managed_command_is_not_root(&config, &command)?;

    if !config.manage.enabled && config.auth.admin_token == "change-me" {
        warn!("admin token is still set to the example value");
    }

    db::ensure_directories(&config).context("failed to create service directories")?;
    let pool = db::connect(&config)
        .await
        .context("failed to open database")?;
    db::migrate(&pool)
        .await
        .context("database migration failed")?;
    tiaris_nest::cache::remediate_protected_build_jobs(&pool, &config)
        .await
        .context("protected build cache remediation failed")?;

    match command {
        Command::Serve => run_server(config, pool).await,
        Command::Migrate => {
            info!("database migrations completed");
            Ok(())
        }
        Command::SyncOnce => {
            let state = AppState::new(config, pool);
            let outcome = tiaris_nest::manage::sync_once(&state).await?;
            println!("{}", serde_json::to_string(&outcome)?);
            Ok(())
        }
        Command::PrintConfig => unreachable!("print-config exits before database setup"),
        Command::ValidateApplianceConfig => {
            unreachable!("validate-appliance-config exits before database setup")
        }
        Command::VerifyApplianceDatabase { .. } | Command::RehearseApplianceDatabase { .. } => {
            unreachable!("database commands exit before config loading")
        }
        Command::VerifyApplianceUpdatePolicy => {
            unreachable!("policy verification exits before config loading")
        }
        Command::VerifyApplianceUpdate { .. } => {
            unreachable!("appliance update verification exits before database setup")
        }
        Command::FreeCacheSpace { available_bytes } => {
            tiaris_nest::cache::free_space(&pool, &config, available_bytes).await
        }
    }
}

fn ensure_managed_command_is_not_root(
    config: &tiaris_nest::config::AppConfig,
    command: &Command,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        if managed_command_requires_service_user(config, command) && effective_uid() == 0 {
            bail!(
                "managed Tiaris Nest stateful commands must not run as root; use systemctl for the service"
            );
        }
    }
    let _ = (config, command);
    Ok(())
}

fn managed_command_requires_service_user(
    config: &tiaris_nest::config::AppConfig,
    command: &Command,
) -> bool {
    config.manage.enabled
        && !matches!(
            command,
            Command::PrintConfig
                | Command::ValidateApplianceConfig
                | Command::VerifyApplianceUpdate { .. }
                | Command::VerifyApplianceUpdatePolicy
                | Command::VerifyApplianceDatabase { .. }
                | Command::RehearseApplianceDatabase { .. }
        )
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

async fn run_server(
    config: tiaris_nest::config::AppConfig,
    pool: sqlx::SqlitePool,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config
        .server
        .listen_addr
        .parse()
        .with_context(|| format!("invalid listen address {}", config.server.listen_addr))?;
    let state = AppState::new(config, pool);
    if let Err(err) = tiaris_nest::cache::initialize(&state.config).await {
        // Degraded, not fatal: exports re-run key setup and `nix copy`
        // rewrites nix-cache-info, so the cache can still heal later.
        warn!(error = %err, "Nest Cache initialization failed; substituters will reject this cache until resolved");
    }
    // Reserve the HTTP socket before any background worker can trigger a
    // readiness report. Requests may wait briefly in the listen backlog, but
    // they cannot observe a synthetic connection-refused startup failure.
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}"))?;
    // The build worker and the reporter read the detected commits: the ready
    // ones of an older Nest are taken over first.
    let taken_over =
        tiaris_nest::software_updates::take_over_commits_of_older_nests(&state.config).await;
    tiaris_nest::build::spawn(state.clone(), taken_over);
    // Publish the shipped workstation cache seeds without waiting for a build
    // job; failures are logged and retried in the background.
    tiaris_nest::cache::seeds::spawn(state.clone());
    tiaris_nest::software_updates::spawn(state.clone());
    tiaris_nest::netboot::spawn_maintenance(state.clone());
    if state.config.manage.enabled {
        tiaris_nest::manage::spawn(state.clone(), taken_over);
        tiaris_nest::software_cache_upload::spawn(state.clone());
        tiaris_nest::site_check::spawn(state.clone());
    }
    tiaris_nest::console_status::spawn(state.clone());
    tiaris_nest::activity::spawn(state.clone());
    tiaris_nest::resources::spawn(
        state.db.clone(),
        state.config.paths.data_dir.join("resources.json"),
    );
    db::spawn_maintenance(state.db.clone(), state.config.paths.database_path.clone());
    let app = router(state.clone());

    info!(%listen_addr, "tiaris-nest listening");
    spawn_systemd_watchdog(listener.local_addr()?);

    axum_serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server failed")
}

/// Tells systemd the service lives only while its own HTTP server answers a
/// trivial request on loopback, so a hung daemon is restarted. Liveness only:
/// readiness, PXE, Tiaris contact, locks and builds never count, and the
/// unit's `WatchdogSec` (5 minutes) leaves room for a busy Nest.
///
/// Writes directly to `$NOTIFY_SOCKET` from the main process instead of
/// spawning `systemd-notify`, which also allows `NotifyAccess=main`.
fn spawn_systemd_watchdog(listening: SocketAddr) {
    let Some(notify_socket) = std::env::var_os("NOTIFY_SOCKET").filter(|value| !value.is_empty())
    else {
        return;
    };
    let target = liveness_target(listening);
    tokio::spawn(async move {
        if let Err(err) = send_systemd_notify(&notify_socket, "READY=1") {
            warn!(error = %err, "failed to notify systemd readiness");
        }
        loop {
            if tiaris_nest::routes::server_answers(target).await {
                if let Err(err) = send_systemd_notify(&notify_socket, "WATCHDOG=1") {
                    warn!(error = %err, "failed to notify systemd watchdog");
                }
            } else {
                warn!("the Nest's own HTTP server did not answer its liveness request");
            }
            sleep(Duration::from_secs(10)).await;
        }
    });
}

#[cfg(unix)]
fn send_systemd_notify(notify_socket: &std::ffi::OsStr, state: &str) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr as UnixSocketAddr, UnixDatagram};

    let raw = notify_socket.as_bytes();
    let addr = if let Some(abstract_name) = raw.strip_prefix(b"@") {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            UnixSocketAddr::from_abstract_name(abstract_name)?
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = abstract_name;
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "abstract unix sockets are only supported on Linux",
            ));
        }
    } else {
        UnixSocketAddr::from_pathname(std::path::Path::new(notify_socket))?
    };

    let socket = UnixDatagram::unbound()?;
    socket.send_to_addr(state.as_bytes(), &addr)?;
    Ok(())
}

#[cfg(not(unix))]
fn send_systemd_notify(_notify_socket: &std::ffi::OsStr, _state: &str) -> std::io::Result<()> {
    Ok(())
}

/// Where the server answers locally: loopback for a wildcard listener.
fn liveness_target(listening: SocketAddr) -> SocketAddr {
    let mut target = listening;
    if target.ip().is_unspecified() {
        target.set_ip(match target {
            SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
            SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
        });
    }
    target
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("tiaris_nest=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(env_filter)
        // Operational logs belong on stderr so one-shot commands can reserve
        // stdout for stable machine-readable results.
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();
}

#[cfg(test)]
mod tests {
    use tiaris_nest::config::AppConfig;

    use super::{Command, managed_command_requires_service_user};

    #[test]
    fn managed_stateful_commands_require_service_user() {
        let mut config = AppConfig::default();
        config.manage.enabled = true;

        for command in [Command::Serve, Command::Migrate, Command::SyncOnce] {
            assert!(managed_command_requires_service_user(&config, &command));
        }
        assert!(!managed_command_requires_service_user(
            &config,
            &Command::PrintConfig
        ));
        assert!(!managed_command_requires_service_user(
            &config,
            &Command::ValidateApplianceConfig
        ));
        config.manage.enabled = false;
        assert!(!managed_command_requires_service_user(
            &config,
            &Command::SyncOnce
        ));
    }

    #[cfg(unix)]
    #[test]
    fn systemd_notify_writes_to_pathname_socket() {
        use std::os::unix::net::UnixDatagram;

        let dir =
            std::env::temp_dir().join(format!("tiaris-nest-notify-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("notify.sock");
        let receiver = UnixDatagram::bind(&sock_path).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        super::send_systemd_notify(sock_path.as_os_str(), "READY=1").unwrap();
        super::send_systemd_notify(sock_path.as_os_str(), "WATCHDOG=1").unwrap();

        let mut buf = [0u8; 64];
        let n1 = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n1], b"READY=1");
        let n2 = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n2], b"WATCHDOG=1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_notify_writes_to_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr as UnixSocketAddr, UnixDatagram};

        let name = format!("tiaris-nest-notify-abstract-{}", uuid::Uuid::new_v4());
        let addr = UnixSocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&addr).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let env_value = std::ffi::OsString::from(format!("@{name}"));
        super::send_systemd_notify(&env_value, "WATCHDOG=1").unwrap();

        let mut buf = [0u8; 64];
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");
    }
}
