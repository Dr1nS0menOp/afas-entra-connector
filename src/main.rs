// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
#![forbid(unsafe_code)]
// No panics in production code: errors are values. (Tests may use unwrap.)
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use afas_entra_sync::config::Config;
use afas_entra_sync::error::{AppError, exit};
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
    /// Configuration file. Default: $AFAS_ENTRA_SYNC_CONFIG, else
    /// /etc/afas-entra-sync/config.toml if it exists, else ./afas-entra-sync.toml.
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check everything (config, secrets, AFAS, Entra, permissions, certificates, TLS,
    /// schedule) and say how to fix what is wrong. Read-only. Exit 0 all good, 3 warnings,
    /// 61 something to fix.
    Doctor {
        /// JSON instead of readable text.
        #[arg(long)]
        json: bool,
    },
    /// List the fields the AFAS GetConnector returns, the kind of data in each and which
    /// setting they are mapped to. Shows no personal data, so safe to share.
    AfasFields {
        /// JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
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
        /// Deliberately proceed when more employees are new than policy.max_new_per_run.
        #[arg(long)]
        allow_mass_create: bool,
        /// Deliberately proceed when more sign-in names (UPN) change than
        /// policy.max_upn_changes_per_run.
        #[arg(long)]
        allow_upn_changes: bool,
        /// Write the SCIM payloads to this file (contains personal data!).
        #[arg(long)]
        dump_payload: Option<PathBuf>,
        /// Also write what happens per account as a page you can open in a browser
        /// (contains personal data!).
        #[arg(long)]
        preview_html: Option<PathBuf>,
        /// Test run: also send the notifications from [notify] (a sync always does).
        #[arg(long)]
        notify: bool,
        /// Print the full report as JSON (the default when the output is not a terminal,
        /// e.g. in Ansible, Semaphore or systemd).
        #[arg(long)]
        json: bool,
    },
    /// What the last test run would do (or, with --sync, what the last sync did), account
    /// by account: create, enable, disable, update or nothing, where, and what changes.
    Preview {
        /// Every account, also those without changes and those not sent.
        #[arg(long)]
        all: bool,
        /// Only the accounts that need attention.
        #[arg(long)]
        problems: bool,
        /// The last sync instead of the last test run.
        #[arg(long)]
        sync: bool,
        /// Write a page to open in a browser, with the table filling up call by call
        /// (contains personal data!).
        #[arg(long)]
        html: Option<PathBuf>,
        /// Write a CSV file (contains personal data!).
        #[arg(long)]
        csv: Option<PathBuf>,
        /// JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Example data with fictional people: see what the preview looks like without
        /// AFAS or a configuration.
        #[arg(long)]
        demo: bool,
        /// Print the table at once instead of filling it line by line.
        #[arg(long)]
        no_animation: bool,
    },
    /// Employees who were sent as active and are no longer in AFAS. Their accounts are
    /// not disabled automatically and are reported on every run until handled.
    #[command(subcommand)]
    Missing(MissingCmd),
    /// Send a test message (with fictional example points) to every channel in [notify].
    NotifyTest {
        /// Only this channel (its name, or kind-number such as teams-2).
        #[arg(long)]
        channel: Option<String>,
        /// Send nothing: write example messages (email as HTML, Teams, Slack and webhook as
        /// JSON) to this directory, to see what reports look like. Needs no configuration.
        #[arg(long)]
        render: Option<PathBuf>,
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
    /// Set up the app registration for a module (roles, joiner or leaver): creates its
    /// certificate and key with the right owner and permissions, and prints the steps in
    /// Entra and the config section to add. Run as root.
    ModuleSetup {
        /// roles, joiner (new hires), leaver (departing employees), notify (email
        /// notifications) or preview (read-only look-up for the test-run preview).
        #[arg(value_parser = ["roles", "joiner", "leaver", "notify", "preview"])]
        module: String,
        /// Create a new certificate (the old one is kept as *.pem.old).
        #[arg(long)]
        renew: bool,
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
enum MissingCmd {
    /// List them, with since when.
    List,
    /// Mark as handled (for example after disabling the account in AD by hand): they are
    /// no longer reported. They come back as new if they reappear in AFAS and disappear again.
    Ack {
        /// Employee numbers.
        ids: Vec<String>,
        /// All of them.
        #[arg(long)]
        all: bool,
    },
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
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::prelude::*;
    // Colour codes only on a terminal; in Semaphore, journald or Graylog they produce garbage.
    // At a terminal only warnings and errors (the summary is on stdout); elsewhere the
    // whole run, so the journal holds the full log. The run log file always has it all.
    let tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let stderr = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(tty)
        .with_target(false)
        .with_filter(if tty {
            LevelFilter::WARN
        } else {
            LevelFilter::INFO
        });
    tracing_subscriber::registry()
        .with(stderr)
        .with(afas_entra_sync::logcap::Layer.with_filter(LevelFilter::INFO))
        .init();
    std::process::exit(real_main());
}

/// Prints lines; at a terminal they appear one by one, so the table visibly fills up.
fn print_filling(lines: &[String], animate: bool) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let per_line = if animate && !lines.is_empty() {
        std::time::Duration::from_millis((2500 / lines.len() as u64).clamp(2, 18))
    } else {
        std::time::Duration::ZERO
    };
    for l in lines {
        let _ = writeln!(out, "{l}");
        if !per_line.is_zero() {
            let _ = out.flush();
            std::thread::sleep(per_line);
        }
    }
}

fn color_ok() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
}

/// `notify-test --render <dir>`: example messages as files, nothing sent.
fn render_samples(dir: &std::path::Path) -> i32 {
    use afas_entra_sync::notify::{render, sample};
    if let Err(e) = std::fs::create_dir_all(dir) {
        return fail(&AppError::Config(format!(
            "cannot create {}: {e}",
            dir.display()
        )));
    }
    let attention = sample(render::Event::Attention, true);
    let failure = sample(render::Event::Failure, true);
    let numbers = sample(render::Event::Attention, false);
    let pretty = |v: &serde_json::Value| serde_json::to_vec_pretty(v).unwrap_or_default();
    let files: Vec<(&str, Vec<u8>)> = vec![
        (
            "email-attention.html",
            render::email(&attention).1.into_bytes(),
        ),
        ("email-failure.html", render::email(&failure).1.into_bytes()),
        (
            "email-employee-numbers-only.html",
            render::email(&numbers).1.into_bytes(),
        ),
        ("teams-attention.json", pretty(&render::teams(&numbers))),
        ("teams-failure.json", pretty(&render::teams(&failure))),
        ("slack-attention.json", pretty(&render::slack(&numbers))),
        ("slack-failure.json", pretty(&render::slack(&failure))),
        ("webhook-attention.json", pretty(&render::webhook(&numbers))),
    ];
    for (name, body) in files {
        let p = dir.join(name);
        if let Err(e) = afas_entra_sync::state::write_atomic(&p, &body) {
            return fail(&e);
        }
        println!("{}", p.display());
    }
    println!(
        "\nExamples with fictional people. Paste a Teams file's \"content\" into adaptivecards.io/designer, a Slack file into app.slack.com/block-kit-builder."
    );
    exit::OK
}

fn real_main() -> i32 {
    let cli = Cli::parse();
    if let Cmd::NotifyTest {
        render: Some(dir), ..
    } = &cli.cmd
    {
        return render_samples(dir);
    }
    if let Cmd::Preview {
        demo: true,
        all,
        problems,
        html,
        csv,
        json,
        no_animation,
        ..
    } = &cli.cmd
    {
        return show_preview(
            &afas_entra_sync::preview::demo(),
            *all,
            *problems,
            html.as_deref(),
            csv.as_deref(),
            *json,
            !*no_animation,
            None,
        );
    }
    let config_path = afas_entra_sync::ux::resolve_config(
        cli.config.clone(),
        std::env::var_os(afas_entra_sync::ux::CONFIG_ENV),
        &|p| p.exists(),
    );
    if matches!(
        cli.cmd,
        Cmd::Install { .. } | Cmd::Uninstall { .. } | Cmd::ModuleSetup { .. }
    ) {
        return install_cmd(cli.cmd);
    }
    let cfg = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            if cli.config.is_none() && !config_path.exists() {
                return fail(&AppError::Config(format!(
                    "no configuration found at {}. Give one with -c <file>, set {}, or install with: sudo afas-entra-sync install",
                    config_path.display(),
                    afas_entra_sync::ux::CONFIG_ENV
                )));
            }
            return fail(&e);
        }
    };
    // Commands that write to the state directory: never as root when it belongs to the
    // service user (root-owned files would break the service).
    let writes = matches!(
        cli.cmd,
        Cmd::Sync { .. }
            | Cmd::Serve { .. }
            | Cmd::GuiEnable
            | Cmd::CheckLogs { .. }
            | Cmd::Missing(MissingCmd::Ack { .. })
            | Cmd::Exception(ExceptionCmd::Add { .. } | ExceptionCmd::Remove { .. })
    );
    if writes {
        // Only echoed back in the suggested `sudo -u` command; never used for a decision.
        // nosemgrep (args): message text only
        let args: Vec<String> = std::env::args().collect();
        if let Err(m) = afas_entra_sync::ux::check_running_user(&cfg, &args) {
            eprintln!("{m}");
            return exit::CONFIG;
        }
    }
    if let Cmd::GuiEnable = cli.cmd {
        return gui_enable(&config_path);
    }
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
            allow_mass_create,
            allow_upn_changes,
            dump_payload,
            preview_html,
            notify,
            json,
        } => {
            let human = !json && std::io::IsTerminal::is_terminal(&std::io::stdout());
            let opts = RunOptions {
                apply,
                as_of,
                allow_mass_disable,
                allow_mass_create,
                allow_upn_changes,
                dump_payload,
                preview_html: preview_html.clone(),
                notify,
                use_system_proxy: true,
                actor: if std::env::var_os("INVOCATION_ID").is_some() {
                    "systemd".into()
                } else {
                    "cli".into()
                },
            };
            let show = |r: &afas_entra_sync::sync::Report| {
                if !human {
                    print_json(r);
                    return;
                }
                print!("{}", afas_entra_sync::ux::sync_summary(r));
                // What happens per account, as a table that fills up.
                let file = afas_entra_sync::state::preview_file(apply);
                if let Some(p) = std::fs::read(cfg.state.dir.join(file))
                    .ok()
                    .and_then(|b| {
                        serde_json::from_slice::<afas_entra_sync::preview::Preview>(&b).ok()
                    })
                    .filter(|p| p.created_utc >= r.started_utc)
                {
                    println!();
                    let lines = afas_entra_sync::preview::render_text(
                        &p,
                        afas_entra_sync::preview::Show::Changes,
                        color_ok(),
                        60,
                    );
                    print_filling(&lines, true);
                    println!(
                        "\nWhole table: afas-entra-sync preview{} --all, or --html <file> to open it in a browser.",
                        if apply { " --sync" } else { "" }
                    );
                    if let Some(h) = &preview_html {
                        println!(
                            "Page written: {} (contains personal data; delete it after use).",
                            h.display()
                        );
                    }
                }
            };
            match run(&cfg, &opts, &sleep) {
                Ok(r) => {
                    show(&r.report);
                    r.report.exit_code
                }
                Err((e, report)) => {
                    if let Some(r) = report {
                        show(&r);
                    }
                    fail(&e)
                }
            }
        }
        Cmd::Preview {
            all,
            problems,
            sync,
            html,
            csv,
            json,
            no_animation,
            demo: _,
        } => {
            let file = afas_entra_sync::state::preview_file(sync);
            match std::fs::read(cfg.state.dir.join(file)) {
                Err(_) => {
                    eprintln!(
                        "no preview yet ({} in {}): run {} first",
                        file,
                        cfg.state.dir.display(),
                        if sync {
                            "a sync (sync --apply)"
                        } else {
                            "a test run (sync)"
                        }
                    );
                    exit::CONFIG
                }
                Ok(b) => match serde_json::from_slice::<afas_entra_sync::preview::Preview>(&b) {
                    Ok(p) => show_preview(
                        &p,
                        all,
                        problems,
                        html.as_deref(),
                        csv.as_deref(),
                        json,
                        !no_animation,
                        Some(cfg.tz()),
                    ),
                    Err(e) => fail(&AppError::Config(format!("{file} cannot be read: {e}"))),
                },
            }
        }
        Cmd::Missing(MissingCmd::List) => {
            let store = match afas_entra_sync::state::StateStore::new(&cfg.state.dir) {
                Ok(s) => s,
                Err(e) => return fail(&e),
            };
            match store.load() {
                Ok(st) => {
                    let list: Vec<serde_json::Value> = st
                        .map(|s| {
                            s.records
                                .iter()
                                .filter(|(_, r)| r.is_missing())
                                .map(|(id, r)| {
                                    serde_json::json!({
                                        "employee_id": id,
                                        "missing_since": r.missing_since,
                                        "upn": r.upn(),
                                        "display_name": r.sent.get("displayName"),
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    print_json(&list);
                    exit::OK
                }
                Err(e) => fail(&e),
            }
        }
        Cmd::Missing(MissingCmd::Ack { ids, all }) => {
            if ids.is_empty() != all {
                eprintln!("give employee numbers, or --all (not both)");
                return exit::CONFIG;
            }
            let store = match afas_entra_sync::state::StateStore::new(&cfg.state.dir) {
                Ok(s) => s,
                Err(e) => return fail(&e),
            };
            match store.acknowledge_missing(&ids) {
                Ok(done) => {
                    let who = if std::env::var_os("SUDO_USER").is_some() {
                        format!("cli:{}", std::env::var("SUDO_USER").unwrap_or_default())
                    } else {
                        "cli".into()
                    };
                    afas_entra_sync::web::audit(
                        &cfg.state.dir,
                        &who,
                        "missing acknowledged",
                        &done.join(", "),
                    );
                    println!(
                        "{} marked as handled: {}",
                        done.len(),
                        if done.is_empty() {
                            "(none)".to_string()
                        } else {
                            done.join(", ")
                        }
                    );
                    exit::OK
                }
                Err(e) => fail(&e),
            }
        }
        Cmd::NotifyTest { channel, render: _ } => notify_test(&cfg, channel.as_deref(), &sleep),
        Cmd::Serve {
            listen,
            read_only,
            trusted_proxy,
        } => {
            let opts = afas_entra_sync::web::WebOptions {
                config_path: config_path.clone(),
                listen,
                read_only,
                trusted_proxy,
            };
            match afas_entra_sync::web::App::new(opts).and_then(afas_entra_sync::web::serve) {
                Ok(()) => exit::OK,
                Err(e) => fail(&AppError::Config(e)),
            }
        }
        Cmd::GuiEnable | Cmd::Install { .. } | Cmd::Uninstall { .. } | Cmd::ModuleSetup { .. } => {
            exit::INTERNAL
        }
        Cmd::CheckTls => check_tls(&cfg),
        Cmd::Doctor { json } => {
            use afas_entra_sync::doctor;
            let o = doctor::Options {
                sleep: &sleep,
                use_system_proxy: true,
                now: chrono::Utc::now(),
                systemctl: &doctor::real_systemctl,
                tls: true,
            };
            let checks = doctor::run(&cfg, &config_path, &o);
            if json || !std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                print_json(&checks);
            } else {
                print!("{}", doctor::render(&checks));
            }
            doctor::exit_code(&checks)
        }
        Cmd::AfasFields { json } => {
            use afas_entra_sync::doctor;
            match doctor::fields_report(&cfg, &sleep, true) {
                Ok(f) => {
                    if json || !std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                        print_json(&f);
                    } else {
                        print!("{}", doctor::render_fields(&f));
                    }
                    if f.iter().any(|x| !x.present) {
                        exit::CONFIG
                    } else {
                        exit::OK
                    }
                }
                Err(e) => fail(&AppError::Config(e)),
            }
        }
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
            let rep = afas_entra_sync::sync::check_logs(&cfg, since_minutes, true, &sleep);
            // Same shape as before (the summary), plus warnings, error and exit code.
            let mut v =
                serde_json::to_value(rep.summary.clone().unwrap_or_default()).unwrap_or_default();
            if let Some(o) = v.as_object_mut() {
                o.insert("warnings".into(), serde_json::json!(rep.warnings));
                if let Some(e) = &rep.error {
                    o.insert("error".into(), serde_json::json!(e));
                }
                o.insert("exit_code".into(), serde_json::json!(rep.exit_code));
            }
            print_json(&v);
            if let Some(e) = &rep.error {
                eprintln!("error: {e}");
            }
            rep.exit_code
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn show_preview(
    p: &afas_entra_sync::preview::Preview,
    all: bool,
    problems: bool,
    html: Option<&std::path::Path>,
    csv: Option<&std::path::Path>,
    json: bool,
    animate: bool,
    tz: Option<chrono_tz::Tz>,
) -> i32 {
    use afas_entra_sync::preview::{Show, render_csv, render_page, render_text};
    use afas_entra_sync::state::write_atomic;
    let mut wrote = false;
    if let Some(h) = html {
        if let Err(e) = write_atomic(h, render_page(p, tz).as_bytes()) {
            return fail(&e);
        }
        println!(
            "Page written: {} (open it in a browser; contains personal data, delete it after use).",
            h.display()
        );
        wrote = true;
    }
    if let Some(c) = csv {
        if let Err(e) = write_atomic(c, render_csv(p).as_bytes()) {
            return fail(&e);
        }
        println!("CSV written: {} (contains personal data).", c.display());
        wrote = true;
    }
    if json {
        print_json(p);
        return exit::OK;
    }
    if wrote {
        return exit::OK;
    }
    let show = if all {
        Show::All
    } else if problems {
        Show::Problems
    } else {
        Show::Changes
    };
    let tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let lines = render_text(p, show, color_ok(), if all { usize::MAX } else { 300 });
    print_filling(&lines, animate && tty);
    exit::OK
}

fn notify_test(cfg: &Config, only: Option<&str>, sleep: &dyn Fn(std::time::Duration)) -> i32 {
    use afas_entra_sync::notify;
    let Some(n) = cfg.notify.as_ref() else {
        eprintln!("there is no [notify] section in the configuration");
        return exit::CONFIG;
    };
    let mut test_cfg = cfg.clone();
    if let Some(name) = only {
        let Some(nc) = test_cfg.notify.as_mut() else {
            return exit::CONFIG;
        };
        let keep: Vec<_> = n
            .channels
            .iter()
            .enumerate()
            .filter(|(i, c)| c.id(*i) == name)
            .map(|(_, c)| c.clone())
            .collect();
        if keep.is_empty() {
            eprintln!(
                "no channel '{name}'; channels: {}",
                n.channels
                    .iter()
                    .enumerate()
                    .map(|(i, c)| c.id(i))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return exit::CONFIG;
        }
        // Keep the name, so the message says which channel it is.
        nc.channels = keep
            .into_iter()
            .map(|mut c| {
                c.name = Some(name.to_string());
                c
            })
            .collect();
    }
    if let Some(nc) = test_cfg.notify.as_mut() {
        nc.enabled = true;
    }
    let host = notify::host_name();
    let ctx = notify::Context {
        cfg: &test_cfg,
        source: "Test message".into(),
        host: host.clone(),
        log: vec![afas_entra_sync::logcap::format_line(
            &tracing::Level::INFO,
            "this is a test message from notify-test",
            "",
        )],
        log_path: None,
        report: None,
        use_system_proxy: true,
        sleep,
        now: chrono::Utc::now(),
    };
    let facts = vec![
        (
            "Run".to_string(),
            "notify-test (nothing was synchronised)".to_string(),
        ),
        ("Server".to_string(), host),
    ];
    let res = notify::dispatch(
        &ctx,
        "test",
        notify::Outcome::Attention,
        &|_| Vec::new(),
        &facts,
        None,
        Some(notify::render::Event::Test),
    );
    let mut ok = true;
    for d in &res {
        println!(
            "{:<20} {}",
            d.channel,
            if d.ok {
                "sent".to_string()
            } else {
                format!("FAILED: {}", d.detail)
            }
        );
        ok &= d.ok;
    }
    if ok { exit::OK } else { exit::MODULE_FAILED }
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
            // Install exactly the program that is running: /proc/self/exe is its image,
            // even if the file at its path was replaced since it started.
            let proc_exe = std::path::PathBuf::from("/proc/self/exe");
            let binary = if proc_exe.exists() {
                proc_exe
            } else {
                // Only where /proc is missing (not Linux, which the installer targets).
                // nosemgrep (current-exe): fallback only, see above
                match std::env::current_exe() {
                    Ok(b) => b,
                    Err(e) => return fail(&AppError::Internal(e.to_string())),
                }
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
        Cmd::ModuleSetup {
            module,
            renew,
            root,
        } => afas_entra_sync::install::SetupModule::parse(&module).and_then(|module| {
            afas_entra_sync::install::module_setup(
                &RealSystem,
                &afas_entra_sync::install::ModuleSetupOptions {
                    root,
                    module,
                    renew,
                },
            )
            .map(|_| ())
        }),
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
