// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
#![forbid(unsafe_code)]

use afas_entra_sync::config::Config;
use afas_entra_sync::entra::{Credential, TokenProvider, read_logs};
use afas_entra_sync::error::{AppError, exit};
use afas_entra_sync::http::build_client;
use afas_entra_sync::sync::{RunOptions, run};
use chrono::NaiveDate;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "AFAS Profit → Entra ID / AD via API-driven inbound provisioning"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "afas-entra-sync.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Only check the configuration.
    CheckConfig,
    /// Fetch AFAS, build the plan and (with --apply) upload to Entra.
    Sync {
        /// Actually upload. Without this flag: dry-run only.
        #[arg(long)]
        apply: bool,
        /// Dry-run as if it is this date (YYYY-MM-DD). Cannot be combined with --apply.
        #[arg(long)]
        as_of: Option<NaiveDate>,
        /// Deliberately proceed when the disable threshold is hit.
        #[arg(long)]
        allow_mass_disable: bool,
        /// Write the SCIM payloads to this file (contains personal data!).
        #[arg(long)]
        dump_payload: Option<PathBuf>,
    },
    /// Turn the GUI back on after it was turned off from the GUI. Only works if
    /// `[gui] enabled = true` is set in the config file.
    GuiEnable,
    /// Start the admin GUI. Requires `[gui] enabled = true` in the config file.
    Serve {
        /// Address and port. Local only by default.
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: std::net::SocketAddr,
        /// View only, change nothing.
        #[arg(long)]
        read_only: bool,
        /// IP address of the reverse proxy (Traefik). Required for a non-local address;
        /// the Authentik header X-authentik-username is then required too.
        #[arg(long)]
        trusted_proxy: Option<std::net::IpAddr>,
    },
    /// Handshake with AFAS, Entra login and Graph using the `[tls]` policy and report the
    /// negotiated TLS version, cipher suite and key exchange; exit 60 if one fails.
    CheckTls,
    /// Read the provisioning logs of the last minutes; exit 50 on failures.
    CheckLogs {
        #[arg(long, default_value_t = 120)]
        since_minutes: i64,
    },
}

fn main() {
    // Colour codes only on a terminal; in Semaphore, journald or Graylog they produce garbage.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_target(false)
        .init();
    std::process::exit(real_main());
}

fn real_main() -> i32 {
    let cli = Cli::parse();
    if matches!(cli.cmd, Cmd::GuiEnable) {
        return gui_enable(&cli.config);
    }
    let cfg = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let sleep = |d: std::time::Duration| std::thread::sleep(d);
    match cli.cmd {
        Cmd::CheckConfig => {
            println!("configuration OK");
            exit::OK
        }
        Cmd::Sync {
            apply,
            as_of,
            allow_mass_disable,
            dump_payload,
        } => {
            let opts = RunOptions {
                apply,
                as_of,
                allow_mass_disable,
                dump_payload,
                use_system_proxy: true,
            };
            match run(&cfg, &opts, &sleep) {
                Ok(r) => {
                    print_json(&r.report);
                    r.report.exit_code
                }
                Err((e, report)) => {
                    if let Some(r) = report {
                        print_json(&r);
                    }
                    fail(&e)
                }
            }
        }
        Cmd::Serve {
            listen,
            read_only,
            trusted_proxy,
        } => {
            let opts = afas_entra_sync::web::WebOptions {
                config_path: cli.config.clone(),
                listen,
                read_only,
                trusted_proxy,
            };
            match afas_entra_sync::web::App::new(opts).and_then(afas_entra_sync::web::serve) {
                Ok(()) => exit::OK,
                Err(e) => fail(&AppError::Config(e)),
            }
        }
        Cmd::GuiEnable => exit::INTERNAL,
        Cmd::CheckTls => check_tls(&cfg),
        Cmd::CheckLogs { since_minutes } => {
            if !(1..=10_080).contains(&since_minutes) {
                return fail(&AppError::Config(
                    "--since-minutes must be between 1 and 10080".into(),
                ));
            }
            let res = (|| {
                let client = build_client(cfg.entra.timeout_secs, true, &cfg.tls)
                    .map_err(AppError::Config)?;
                let cred = Credential::from_config(&cfg.entra)?;
                let tokens = TokenProvider::new(&cfg.entra, &client, cred, &sleep);
                let since = chrono::Utc::now() - chrono::Duration::minutes(since_minutes);
                read_logs(&cfg.entra, &client, &tokens, since)
            })();
            match res {
                Ok(sum) => {
                    print_json(&sum);
                    if sum.failure > 0 {
                        exit::LOG_FAILURES
                    } else {
                        exit::OK
                    }
                }
                Err(e) => fail(&e),
            }
        }
    }
}

/// Removes `gui.enabled = false` from the GUI layer. The base config stays the master switch.
fn gui_enable(path: &std::path::Path) -> i32 {
    let layers = match Config::load_layers(path) {
        Ok(l) => l,
        Err(e) => return fail(&e),
    };
    let base_on = layers
        .base
        .get("gui")
        .and_then(|g| g.get("enabled"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    if !base_on {
        return fail(&AppError::Config(
            "the GUI is off in the config file; set [gui] enabled = true there".into(),
        ));
    }
    let mut ov = layers.overrides.clone();
    if let Some(toml::Value::Table(g)) = ov.get_mut("gui") {
        g.remove("enabled");
        if g.is_empty() {
            ov.remove("gui");
        }
    }
    let file = layers
        .config
        .state
        .dir
        .join(afas_entra_sync::config::OVERRIDES_FILE);
    let res = if ov.is_empty() {
        match std::fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
            _ => Ok(()),
        }
    } else {
        toml::to_string(&ov)
            .map_err(|e| e.to_string())
            .and_then(|t| {
                afas_entra_sync::state::write_atomic(&file, t.as_bytes()).map_err(|e| e.to_string())
            })
    };
    match res {
        Ok(()) => {
            afas_entra_sync::web::audit(&layers.config.state.dir, "cli", "gui on", "gui-enable");
            println!("GUI turned on; start it with 'serve'");
            exit::OK
        }
        Err(e) => fail(&AppError::Internal(e)),
    }
}

fn check_tls(cfg: &Config) -> i32 {
    let probes = match afas_entra_sync::tls::check_endpoints(cfg) {
        Ok(p) => p,
        Err(e) => return fail(&AppError::Config(e)),
    };
    let all_ok = probes.iter().all(|p| p.ok);
    let all_pq = probes.iter().all(|p| p.post_quantum);
    let out = serde_json::json!({
        "policy": {
            "min_version": cfg.tls.min_version,
            "post_quantum": cfg.tls.post_quantum,
        },
        "endpoints": probes,
        "all_ok": all_ok,
        "post_quantum_everywhere": all_pq,
        "note": if probes.iter().any(|p| p.via_proxy.is_some()) {
            "Connections went through a proxy. A TLS-inspecting proxy shows its own TLS settings, not those of the endpoint."
        } else { "" },
    });
    print_json(&out);
    if all_ok { exit::OK } else { exit::TLS }
}

fn print_json<T: serde::Serialize>(v: &T) {
    match serde_json::to_string_pretty(v) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("cannot serialise report: {e}"),
    }
}

fn fail(e: &AppError) -> i32 {
    tracing::error!("{e}");
    e.exit_code()
}
