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
        /// Actually upload. Without this flag: test run (dry-run), nothing is sent or changed.
        #[arg(long)]
        apply: bool,
        /// Test run (dry-run) as if it is this date (YYYY-MM-DD). Cannot be combined with --apply.
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
    /// Install on this Linux host without Ansible: service user, directories, binary,
    /// AFAS token, validated config, Entra certificate and systemd timers. Safe to run again.
    /// Missing values are asked interactively; give them as flags for unattended use.
    Install {
        /// AFAS environment number (the 12345 in 12345.rest.afas.online) or the full REST URL.
        #[arg(long)]
        afas_env: Option<String>,
        /// GetConnector name (default Entra_Medewerkers).
        #[arg(long)]
        connector: Option<String>,
        /// Entra tenant ID.
        #[arg(long)]
        tenant_id: Option<String>,
        /// Application (client) ID of the app registration.
        #[arg(long)]
        client_id: Option<String>,
        /// Object ID of the provisioning app's service principal.
        #[arg(long)]
        service_principal_id: Option<String>,
        /// Provisioning job ID (API2AD.…).
        #[arg(long)]
        job_id: Option<String>,
        /// Allowed UPN domain; repeat for more.
        #[arg(long = "upn-domain")]
        upn_domains: Vec<String>,
        /// Current number of employees; min_records becomes 90% of it.
        #[arg(long)]
        employee_count: Option<u32>,
        /// Read the AFAS token from this file (or set AFAS_TOKEN). Otherwise it is asked.
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Write a new config.toml (the old one is kept as a backup).
        #[arg(long)]
        reconfigure: bool,
        /// Replace the stored AFAS token.
        #[arg(long)]
        replace_token: bool,
        /// Create a new certificate (the old one is kept as *.pem.old).
        #[arg(long)]
        renew_cert: bool,
        /// Enable the hourly sync (--apply) and check-logs timers. Do this after the dry-run.
        #[arg(long)]
        enable_sync: bool,
        /// New config only: turn on the admin GUI (127.0.0.1:8080).
        #[arg(long)]
        gui: bool,
        #[arg(long, hide = true, default_value = "/")]
        root: PathBuf,
    },
    /// Remove the binary and systemd units. With --purge also config, token, key, state and the user.
    Uninstall {
        #[arg(long)]
        purge: bool,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
        #[arg(long, hide = true, default_value = "/")]
        root: PathBuf,
    },
    /// Read the provisioning logs of the last minutes; exit 50 on failures.
    CheckLogs {
        #[arg(long, default_value_t = 120)]
        since_minutes: i64,
    },
    /// Access history from the modules: who got or lost which access, when.
    Report {
        /// Only this employee number.
        #[arg(long)]
        employee: Option<String>,
        /// From this date (YYYY-MM-DD).
        #[arg(long)]
        since: Option<NaiveDate>,
        /// CSV instead of JSON.
        #[arg(long)]
        csv: bool,
    },
    /// Manual, time-limited exceptions to the role rules.
    #[command(subcommand)]
    Exception(ExceptionCmd),
}

#[derive(Subcommand)]
enum ExceptionCmd {
    /// Add an exception: keep someone in (include) or out of (exclude) a group until a date.
    Add {
        #[arg(long)]
        employee: String,
        /// Object ID of a group from the role rules.
        #[arg(long)]
        group: String,
        #[arg(long, value_parser = ["include", "exclude"])]
        kind: String,
        /// Last day (inclusive), at most one year ahead.
        #[arg(long)]
        until: NaiveDate,
        #[arg(long)]
        reason: String,
    },
    /// List exceptions (expired ones are marked).
    List,
    /// Remove an exception by id.
    Remove {
        #[arg(long)]
        id: String,
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
    match cli.cmd {
        Cmd::GuiEnable => return gui_enable(&cli.config),
        Cmd::Install { .. } | Cmd::Uninstall { .. } => return install_cmd(cli.cmd),
        _ => {}
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
                actor: if std::env::var_os("INVOCATION_ID").is_some() {
                    "systemd".into()
                } else {
                    "cli".into()
                },
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
        Cmd::GuiEnable | Cmd::Install { .. } | Cmd::Uninstall { .. } => exit::INTERNAL,
        Cmd::CheckTls => check_tls(&cfg),
        Cmd::Report {
            employee,
            since,
            csv,
        } => {
            use afas_entra_sync::modules::records::{access_csv, read_access};
            match read_access(&cfg.state.dir, employee.as_deref(), since) {
                Ok(entries) => {
                    if csv {
                        print!("{}", access_csv(&entries));
                    } else {
                        print_json(&entries);
                    }
                    exit::OK
                }
                Err(e) => fail(&AppError::Config(e)),
            }
        }
        Cmd::Exception(x) => exception_cmd(&cfg, x),
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

fn exception_cmd(cfg: &Config, x: ExceptionCmd) -> i32 {
    use afas_entra_sync::modules::records::{
        ExceptionKind, add_exception, load_exceptions, remove_exception,
    };
    let dir = &cfg.state.dir;
    let today = chrono::Utc::now().with_timezone(&cfg.tz()).date_naive();
    let who = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "cli".into());
    let res = match x {
        ExceptionCmd::Add {
            employee,
            group,
            kind,
            until,
            reason,
        } => {
            let k = if kind == "include" {
                ExceptionKind::Include
            } else {
                ExceptionKind::Exclude
            };
            afas_entra_sync::modules::records::check_new_exception(cfg, &employee, &group)
                .and_then(|()| {
                    add_exception(dir, &employee, &group, k, until, &reason, &who, today)
                })
                .map(|id| {
                    afas_entra_sync::web::audit(
                        dir,
                        &format!("cli:{who}"),
                        "exception added",
                        &format!("{id}: {kind} {employee} in {group} until {until}: {reason}"),
                    );
                    println!("{id}");
                })
        }
        ExceptionCmd::List => load_exceptions(dir).map(|x| {
            let rows: Vec<_> = x
                .items
                .iter()
                .map(|e| {
                    let mut v = serde_json::to_value(e).unwrap_or_default();
                    v["expired"] = serde_json::json!(e.until < today);
                    v
                })
                .collect();
            print_json(&rows);
        }),
        ExceptionCmd::Remove { id } => remove_exception(dir, &id).map(|e| {
            afas_entra_sync::web::audit(
                dir,
                &format!("cli:{who}"),
                "exception removed",
                &format!("{}: {} {}", e.id, e.employee_id, e.group_id),
            );
            println!("removed {}", e.id);
        }),
    };
    match res {
        Ok(()) => exit::OK,
        Err(e) => fail(&AppError::Config(e)),
    }
}

fn install_cmd(cmd: Cmd) -> i32 {
    use afas_entra_sync::install::{
        Answers, InstallOptions, RealSystem, UninstallOptions, install, uninstall,
    };
    let res = match cmd {
        Cmd::Install {
            afas_env,
            connector,
            tenant_id,
            client_id,
            service_principal_id,
            job_id,
            upn_domains,
            employee_count,
            token_file,
            reconfigure,
            replace_token,
            renew_cert,
            enable_sync,
            gui,
            root,
        } => {
            let token = match token_file {
                Some(f) => match std::fs::read_to_string(&f) {
                    Ok(t) => Some(t.trim().to_string()),
                    Err(e) => {
                        return fail(&AppError::Config(format!(
                            "cannot read {}: {e}",
                            f.display()
                        )));
                    }
                },
                None => std::env::var("AFAS_TOKEN")
                    .ok()
                    .filter(|t| !t.trim().is_empty()),
            };
            let binary = match std::env::current_exe() {
                Ok(b) => b,
                Err(e) => return fail(&AppError::Internal(e.to_string())),
            };
            install(
                &RealSystem,
                &InstallOptions {
                    root,
                    binary,
                    answers: Answers {
                        afas_env,
                        connector,
                        tenant_id,
                        client_id,
                        service_principal_id,
                        job_id,
                        upn_domains,
                        employee_count,
                        token,
                    },
                    reconfigure,
                    replace_token,
                    renew_cert,
                    enable_sync,
                    gui,
                },
            )
            .map(|_| ())
        }
        Cmd::Uninstall { purge, yes, root } => {
            uninstall(&RealSystem, &UninstallOptions { root, purge, yes })
        }
        _ => Ok(()),
    };
    match res {
        Ok(()) => exit::OK,
        Err(e) => fail(&AppError::Config(e)),
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
