//! Runs one site check against a disposable network for the qualification
//! (`nixos-appliance/qualification/run-site-check.py`). Usage:
//!   site-check-probe time [--unsynchronized] SERVER...
//!   site-check-probe boot STATUS_JSON PROBE_JSON
use anyhow::{Result, bail};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let check = match args.first().map(String::as_str) {
        Some("time") => {
            let unsynchronized = args.iter().any(|arg| arg == "--unsynchronized");
            let servers = args[1..]
                .iter()
                .filter(|arg| !arg.starts_with("--"))
                .cloned()
                .collect();
            tiaris_nest::site_check::time_check(servers, unsynchronized).await
        }
        Some("boot") if args.len() == 3 => tiaris_nest::site_check::network_boot_from_files(
            Path::new(&args[1]),
            Path::new(&args[2]),
            chrono::Utc::now().timestamp(),
        ),
        _ => bail!("usage: site-check-probe time [--unsynchronized] SERVER... | boot STATUS PROBE"),
    };
    println!("{}", serde_json::to_string(&check)?);
    Ok(())
}
