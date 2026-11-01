// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Admin GUI (`afas-entra-sync serve`).
//!
//! - Covers every setting of the tool. Changes go to the GUI layer
//!   `<state.dir>/overrides.toml`; the base file (Ansible) is never touched.
//!   Keys in [`LOCKED_KEYS`] (secrets, addresses, state, GUI switch) are read-only.
//! - Can run everything the CLI can: dry-run (also for a date, with payload), sync
//!   (with confirmation), check-config and check-logs. Runs execute in the background.
//! - Master switch `[gui] enabled` in the base file, off by default. When it is off
//!   (or the GUI turns itself off), every page is refused and the server stops.
//!
//! All logic lives in `handle()`, without networking, so it is fully testable.

use crate::config::{Config, Layers, OVERRIDES_FILE, is_locked};
use crate::entra::{Credential, TokenProvider, read_logs};
use crate::http::build_client;
use crate::state::{REPORT_FILE, write_atomic};
use crate::sync::{RunOptions, run};
use chrono::NaiveDate;
use serde_json::Value;
use std::fmt::Write as _;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const AUDIT_FILE: &str = "audit.log";
pub const PAYLOAD_FILE: &str = "payload.json";
const MAX_BODY: usize = 64 * 1024;
/// Header sent by Authentik (forward auth via Traefik).
const USER_HEADER: &str = "x-authentik-username";
pub const CONFIRM_APPLY: &str = "APPLY";
pub const CONFIRM_MASS: &str = "ALLOW DISABLE";

pub struct WebOptions {
    pub config_path: PathBuf,
    pub listen: SocketAddr,
    pub read_only: bool,
    /// Only accept connections from this address (the reverse proxy). Required for a
    /// non-loopback `listen`; the Authentik header is then required too.
    pub trusted_proxy: Option<IpAddr>,
}

pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub remote: Option<IpAddr>,
    /// Header names in lower case.
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub location: Option<String>,
    pub disposition: Option<String>,
    pub set_cookie: Option<String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Debug, Clone)]
pub struct RunInfo {
    pub kind: String,
    pub user: String,
    pub started: String,
}

#[derive(Debug, Clone)]
pub struct RunDone {
    pub kind: String,
    pub user: String,
    pub finished: String,
    pub exit_code: i32,
    pub summary: String,
}

#[derive(Debug, Default)]
pub struct RunState {
    pub current: Option<RunInfo>,
    pub last: Option<RunDone>,
}

pub type Sleep = Arc<dyn Fn(Duration) + Send + Sync>;

pub struct App {
    pub opts: WebOptions,
    pub csrf: String,
    /// Local mode only (no trusted proxy): secret in the login link that `serve` writes to
    /// `<state.dir>/gui-login-url`. Opening that link sets the session cookie.
    pub login_token: String,
    /// Value of the session cookie in local mode.
    pub session: String,
    pub sleep: Sleep,
    /// For tests: no system proxy for runs.
    pub use_system_proxy: bool,
    pub runs: Arc<Mutex<RunState>>,
    /// Set when the GUI is off or turns itself off: the server stops after this request.
    pub shutdown: Arc<AtomicBool>,
    /// For tests: run synchronously instead of on a thread.
    pub run_inline: bool,
}

impl App {
    pub fn new(opts: WebOptions) -> Result<App, String> {
        validate_listen(&opts)?;
        let layers = Config::load_layers(&opts.config_path).map_err(|e| e.to_string())?;
        if !layers.config.gui.enabled {
            return Err(
                "the GUI is off: set [gui] enabled = true in the config file to start it".into(),
            );
        }
        Ok(App {
            opts,
            csrf: random_hex()?,
            login_token: random_hex()?,
            session: random_hex()?,
            sleep: Arc::new(std::thread::sleep),
            use_system_proxy: true,
            runs: Arc::default(),
            shutdown: Arc::default(),
            run_inline: false,
        })
    }
}

/// 256 bits from the operating system's random source, as hex.
fn random_hex() -> Result<String, String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| format!("no random source: {e}"))?;
    Ok(b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    }))
}

/// Comparison whose duration does not depend on where the inputs differ.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub const SESSION_COOKIE: &str = "afas_gui_session";
pub const LOGIN_FILE: &str = "gui-login-url";

fn cookie<'a>(r: &'a Request<'_>, name: &str) -> Option<&'a str> {
    header(r, "cookie")?.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

/// Local mode: only the listen address as Host (blocks DNS rebinding), and a valid
/// session cookie or the login link. `None` = access granted.
fn local_access(app: &App, r: &Request<'_>, path: &str, query: &str) -> Option<Response> {
    let port = app.opts.listen.port();
    let host_ok = header(r, "host").is_some_and(|h| {
        [
            format!("127.0.0.1:{port}"),
            format!("localhost:{port}"),
            format!("[::1]:{port}"),
            app.opts.listen.to_string(),
        ]
        .iter()
        .any(|ok| h.eq_ignore_ascii_case(ok))
    });
    if !host_ok {
        return Some(text(421, "Unexpected Host header."));
    }
    if path == "/login" {
        let token = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("token="))
            .unwrap_or("");
        if !ct_eq(token, &app.login_token) {
            return Some(text(403, "Invalid login link."));
        }
        let mut resp = redirect("/");
        resp.set_cookie = Some(format!(
            "{SESSION_COOKIE}={}; HttpOnly; SameSite=Strict; Path=/",
            app.session
        ));
        return Some(resp);
    }
    if cookie(r, SESSION_COOKIE).is_some_and(|c| ct_eq(c, &app.session)) {
        return None;
    }
    Some(text(
        401,
        "Not signed in. Open the login link from the file gui-login-url in the state directory (readable by the service user only).",
    ))
}

/// Non-loopback only with a trusted proxy: then nobody else can forge the
/// Authentik header.
pub fn validate_listen(o: &WebOptions) -> Result<(), String> {
    if !o.listen.ip().is_loopback() && o.trusted_proxy.is_none() {
        return Err(
            "listening on a non-loopback address requires --trusted-proxy (the Traefik address)"
                .into(),
        );
    }
    Ok(())
}

fn header<'a>(r: &'a Request<'_>, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

// ===================================================================== fields

#[derive(Clone, Copy)]
enum Kind {
    Text { max: usize },
    LongText { max: usize },
    Int { min: i64, max: i64 },
    Bool,
    List,
    Toggle,
}

struct Field {
    path: &'static str,
    label: &'static str,
    help: &'static str,
    kind: Kind,
}

struct Section {
    slug: &'static str,
    title: &'static str,
    intro: &'static str,
    /// Module section that must exist in the config file before this page can edit it.
    requires: Option<&'static str>,
    fields: &'static [Field],
}

const fn f(path: &'static str, label: &'static str, help: &'static str, kind: Kind) -> Field {
    Field {
        path,
        label,
        help,
        kind,
    }
}
const T: Kind = Kind::Text { max: 256 };

static SECTIONS: &[Section] = &[
    Section {
        slug: "source",
        title: "AFAS source",
        intro: "Where the employees come from and how they are fetched.",
        requires: None,
        fields: &[
            f(
                "afas.base_url",
                "REST address",
                "Address of the AFAS REST service.",
                T,
            ),
            f(
                "afas.connector",
                "GetConnector",
                "Name of the GetConnector with one row per employee.",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.token_env",
                "Token from variable",
                "Environment variable holding the AFAS token.",
                T,
            ),
            f(
                "afas.token_file",
                "Token from file",
                "File holding the AFAS token.",
                T,
            ),
            f(
                "afas.page_size",
                "Rows per page",
                "How many rows are fetched per request.",
                Kind::Int {
                    min: 1,
                    max: 10_000,
                },
            ),
            f(
                "afas.order_by_field",
                "Sort field",
                "Unique field for stable paging, usually the employee number.",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.timeout_secs",
                "Timeout (s)",
                "Maximum wait per request.",
                Kind::Int { min: 1, max: 3600 },
            ),
            f(
                "afas.max_attempts",
                "Attempts",
                "How often a failed request is retried.",
                Kind::Int { min: 1, max: 20 },
            ),
        ],
    },
    Section {
        slug: "fields",
        title: "Fields",
        intro: "Which AFAS field holds which value. Names must match the GetConnector exactly.",
        requires: None,
        fields: &[
            f(
                "afas.fields.employee_id",
                "Employee number",
                "Unique key; matches employeeID in AD.",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.fields.given_name",
                "Given name",
                "",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.fields.name_prefix",
                "Name prefix",
                "E.g. \"van der\"; goes before the family name.",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.fields.family_name",
                "Family name",
                "",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.fields.display_name",
                "Display name",
                "Optional; otherwise given name + family name.",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.fields.upn",
                "UPN",
                "The UPN generated by AFAS; leading for AD and the group sync.",
                Kind::Text { max: 64 },
            ),
            f("afas.fields.email", "Email", "", Kind::Text { max: 64 }),
            f(
                "afas.fields.job_title",
                "Job title",
                "",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.fields.department",
                "Department",
                "",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.fields.manager_id",
                "Manager",
                "Employee number of the manager.",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.fields.cost_center",
                "Cost center",
                "",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.fields.start_date",
                "Start date",
                "",
                Kind::Text { max: 64 },
            ),
            f(
                "afas.fields.end_date",
                "End date",
                "",
                Kind::Text { max: 64 },
            ),
        ],
    },
    Section {
        slug: "attributes",
        title: "Extra attributes",
        intro: "On = read from AFAS and send. Off = not read and not sent; the value in AD then stays, unless clear attribute values is on in the provisioning app.",
        requires: None,
        fields: &[
            f(
                "afas.fields.extra.phone_work",
                "Work phone",
                "To telephoneNumber.",
                Kind::Toggle,
            ),
            f(
                "afas.fields.extra.phone_mobile",
                "Mobile phone",
                "Custom extension mobilePhone; needs a mapping in the provisioning app.",
                Kind::Toggle,
            ),
            f(
                "afas.fields.extra.office",
                "Office",
                "Custom extension officeLocation.",
                Kind::Toggle,
            ),
            f(
                "afas.fields.extra.company",
                "Company",
                "To company.",
                Kind::Toggle,
            ),
            f(
                "afas.fields.extra.employee_type",
                "Employee type",
                "To employeeType.",
                Kind::Toggle,
            ),
            f(
                "afas.fields.extra.job_profile",
                "Job profile",
                "Custom extension jobProfile, for dynamic groups.",
                Kind::Toggle,
            ),
            f(
                "afas.fields.extra.street",
                "Street",
                "Work address.",
                Kind::Toggle,
            ),
            f(
                "afas.fields.extra.postal_code",
                "Postal code",
                "Work address.",
                Kind::Toggle,
            ),
            f(
                "afas.fields.extra.city",
                "City",
                "Work address.",
                Kind::Toggle,
            ),
            f(
                "afas.fields.extra.country",
                "Country",
                "2-letter country code, e.g. NL.",
                Kind::Toggle,
            ),
            f(
                "afas.fields.extra.send_hire_date",
                "Send hire date",
                "Custom extension hireDate.",
                Kind::Bool,
            ),
            f(
                "afas.fields.extra.send_leave_date",
                "Send leave date",
                "Custom extension leaveDate.",
                Kind::Bool,
            ),
        ],
    },
    Section {
        slug: "entra",
        title: "Entra ID",
        intro: "The provisioning app the employees are sent to.",
        requires: None,
        fields: &[
            f("entra.tenant_id", "Tenant", "", T),
            f("entra.client_id", "App registration", "", T),
            f("entra.auth", "Sign in with", "", T),
            f("entra.certificate_pem", "Certificate", "", T),
            f("entra.private_key_pem", "Private key", "", T),
            f("entra.client_secret_env", "Secret from variable", "", T),
            f(
                "entra.service_principal_id",
                "Service principal",
                "Object ID of the provisioning app.",
                Kind::Text { max: 36 },
            ),
            f(
                "entra.job_id",
                "Provisioning job",
                "Shown in the endpoint URL under View technical information.",
                Kind::Text { max: 128 },
            ),
            f("entra.authority", "Login address", "", T),
            f("entra.graph_base", "Graph address", "", T),
            f(
                "entra.timeout_secs",
                "Timeout (s)",
                "",
                Kind::Int { min: 1, max: 3600 },
            ),
        ],
    },
    Section {
        slug: "safety",
        title: "Safety and windows",
        intro: "When accounts are created and disabled, and when a run stops without uploading anything.",
        requires: None,
        fields: &[
            f(
                "policy.timezone",
                "Time zone",
                "IANA name, e.g. Europe/Amsterdam.",
                Kind::Text { max: 64 },
            ),
            f(
                "policy.allowed_upn_domains",
                "Allowed UPN domains",
                "Comma-separated, e.g. example.com.",
                Kind::List,
            ),
            f(
                "policy.prehire_days",
                "Days to create new hires in advance",
                "New hires (joiners) get their account this many days before the start date, still disabled.",
                Kind::Int { min: 0, max: 365 },
            ),
            f(
                "policy.leaver_lookback_days",
                "Days to keep sending departing employees",
                "How long after the end date a departing employee (leaver) is still sent, as disabled.",
                Kind::Int { min: 0, max: 365 },
            ),
            f(
                "policy.min_records",
                "Minimum records",
                "Fewer to send: the run stops.",
                Kind::Int {
                    min: 1,
                    max: 1_000_000,
                },
            ),
            f(
                "policy.max_drop_percent",
                "Maximum drop (%)",
                "Compared with the last successful run.",
                Kind::Int { min: 0, max: 100 },
            ),
            f(
                "policy.max_disables_per_run",
                "Maximum new disables",
                "More: the run stops, unless you deliberately proceed under Run.",
                Kind::Int {
                    min: 0,
                    max: 1_000_000,
                },
            ),
            f(
                "policy.max_invalid_percent",
                "Maximum invalid records (%)",
                "More usually points to a wrong field name.",
                Kind::Int { min: 0, max: 100 },
            ),
            f(
                "policy.max_calls_per_run",
                "Maximum API calls per run",
                "Protects the Microsoft daily limit.",
                Kind::Int { min: 1, max: 6000 },
            ),
        ],
    },
    Section {
        slug: "tls",
        title: "TLS",
        intro: "How connections to AFAS, Entra login and Graph are secured. Fixed in the config file; the GUI cannot weaken it. Without a [tls] section: TLS 1.3 minimum, post-quantum key exchange preferred. Use Check TLS under Run to see what each endpoint negotiates.",
        requires: None,
        fields: &[
            f(
                "tls.min_version",
                "Minimum TLS version",
                "1.3 or 1.2.",
                Kind::Text { max: 8 },
            ),
            f(
                "tls.post_quantum",
                "Post-quantum key exchange",
                "prefer: X25519MLKEM768 first, classical fallback. require: servers without ML-KEM are refused.",
                Kind::Text { max: 16 },
            ),
        ],
    },
    Section {
        slug: "upload",
        title: "Upload",
        intro: "Pace and retry behaviour towards Microsoft. The defaults follow the Microsoft limits.",
        requires: None,
        fields: &[
            f(
                "upload.batch_size",
                "Records per call",
                "At most 50.",
                Kind::Int { min: 1, max: 50 },
            ),
            f(
                "upload.pace_ms",
                "Pause between calls (ms)",
                "Microsoft allows 40 calls per 5 seconds.",
                Kind::Int {
                    min: 0,
                    max: 60_000,
                },
            ),
            f(
                "upload.max_attempts",
                "Attempts per call",
                "",
                Kind::Int { min: 1, max: 20 },
            ),
            f(
                "upload.backoff_base_ms",
                "First wait (ms)",
                "Doubles with every next attempt.",
                Kind::Int {
                    min: 0,
                    max: 600_000,
                },
            ),
            f(
                "upload.backoff_max_ms",
                "Maximum wait (ms)",
                "",
                Kind::Int {
                    min: 0,
                    max: 3_600_000,
                },
            ),
            f(
                "upload.bucket_full_wait_secs",
                "Wait when queue is full (s)",
                "Microsoft advises 5 to 10 minutes.",
                Kind::Int { min: 0, max: 3600 },
            ),
            f(
                "upload.max_retry_after_secs",
                "Maximum Retry-After (s)",
                "",
                Kind::Int { min: 0, max: 3600 },
            ),
        ],
    },
    Section {
        slug: "roles",
        title: "Roles and licences",
        intro: "Group membership follows AFAS attributes; licences follow through group-based licensing. The app registration, group prefix and rules are in the config file; the rules are listed under Modules.",
        requires: Some("roles"),
        fields: &[
            f("roles.enabled", "Module on", "", Kind::Bool),
            f(
                "roles.include_prehires",
                "Groups before the start date",
                "Also give groups to new hires (pre-hires) before their first working day. Licences then start counting earlier.",
                Kind::Bool,
            ),
            f(
                "roles.keep_leavers_days",
                "Keep departing employees in groups (days)",
                "Days after the end date before groups and licences are removed, e.g. to keep a mailbox while it is converted.",
                Kind::Int { min: 0, max: 365 },
            ),
            f(
                "roles.remove_unknown_members",
                "Remove members not from AFAS",
                "Off: admin and service accounts in managed groups are left alone.",
                Kind::Bool,
            ),
            f(
                "roles.max_changes_per_run",
                "Maximum group changes per run",
                "More: nothing is changed.",
                Kind::Int {
                    min: 1,
                    max: 100_000,
                },
            ),
        ],
    },
    Section {
        slug: "joiner",
        title: "New hires (joiners)",
        intro: "A one-time sign-in code (Temporary Access Pass) for the first day, valid from the start date, mailed to the manager or a fixed address. The new colleague uses it to sign in and set up MFA; no password is sent. Sender and recipients are fixed in the config file.",
        requires: Some("joiner"),
        fields: &[
            f("joiner.enabled", "Module on", "", Kind::Bool),
            f(
                "joiner.days_before_start",
                "Send the code days before start",
                "The code only works from the start date.",
                Kind::Int { min: 0, max: 14 },
            ),
            f(
                "joiner.start_hour",
                "Valid from (hour)",
                "Local time on the start date.",
                Kind::Int { min: 0, max: 23 },
            ),
            f(
                "joiner.lifetime_minutes",
                "Valid for (minutes)",
                "Also limited by the Temporary Access Pass policy in Entra.",
                Kind::Int {
                    min: 60,
                    max: 43_200,
                },
            ),
            f("joiner.usable_once", "Single use", "", Kind::Bool),
            f(
                "joiner.max_per_run",
                "Maximum codes per run",
                "More: none are sent.",
                Kind::Int {
                    min: 1,
                    max: 10_000,
                },
            ),
            f(
                "joiner.subject",
                "Mail subject",
                "{display_name} {upn} {start_date}; never {tap} (the code).",
                Kind::Text { max: 200 },
            ),
            f(
                "joiner.body",
                "Mail text",
                "Must contain {tap} (the code). Also {display_name} {upn} {start_date} {valid_from} {valid_until}.",
                Kind::LongText { max: 4000 },
            ),
        ],
    },
    Section {
        slug: "leaver",
        title: "Departing employees (leavers)",
        intro: "The day after the end date: sign out on every device and set an automatic reply. The account itself is disabled by the upload to Entra; groups and licences are removed by Roles and licences.",
        requires: Some("leaver"),
        fields: &[
            f("leaver.enabled", "Module on", "", Kind::Bool),
            f(
                "leaver.revoke_sessions",
                "Sign out everywhere (revoke sessions)",
                "Phones and laptops must sign in again, which fails because the account is disabled.",
                Kind::Bool,
            ),
            f(
                "leaver.auto_reply",
                "Automatic reply",
                "{display_name} {manager_name} {manager_email}. Empty in the config file = none.",
                Kind::LongText { max: 4000 },
            ),
            f(
                "leaver.auto_reply_external",
                "Also reply to external senders",
                "",
                Kind::Bool,
            ),
            f(
                "leaver.grace_days",
                "Act on end dates up to (days ago)",
                "",
                Kind::Int { min: 1, max: 90 },
            ),
            f(
                "leaver.max_per_run",
                "Maximum departing employees per run",
                "More: nothing is done.",
                Kind::Int {
                    min: 1,
                    max: 10_000,
                },
            ),
        ],
    },
    Section {
        slug: "population",
        title: "Staff category (population)",
        intro: "For contractors, externals and interns: each category gets its own config, recognisable by name and employee number prefix.",
        requires: None,
        fields: &[
            f(
                "population.name",
                "Name",
                "Shown in reports, e.g. contractors.",
                Kind::Text { max: 32 },
            ),
            f(
                "population.id_prefix",
                "Employee number prefix",
                "E.g. CTR-; only A-Z, 0-9 and -.",
                Kind::Text { max: 8 },
            ),
            f(
                "population.employee_type",
                "Fixed employee type",
                "E.g. Contractor.",
                Kind::Text { max: 64 },
            ),
        ],
    },
];

fn lookup<'a>(t: &'a toml::Table, path: &str) -> Option<&'a toml::Value> {
    let mut cur: Option<&toml::Value> = None;
    let mut tab = t;
    for (i, part) in path.split('.').enumerate() {
        let v = tab.get(part)?;
        if i + 1 == path.split('.').count() {
            cur = Some(v);
        } else {
            tab = v.as_table()?;
        }
    }
    cur
}

fn set_path(t: &mut toml::Table, path: &str, v: toml::Value) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut tab = t;
    for p in &parts[..parts.len() - 1] {
        let entry = tab
            .entry((*p).to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if !entry.is_table() {
            *entry = toml::Value::Table(toml::Table::new());
        }
        tab = entry.as_table_mut().expect("just created a table");
    }
    tab.insert(parts[parts.len() - 1].to_string(), v);
}

/// Removes a path and cleans up empty tables.
fn remove_path(t: &mut toml::Table, path: &str) {
    fn rec(t: &mut toml::Table, parts: &[&str]) {
        if parts.len() == 1 {
            t.remove(parts[0]);
            return;
        }
        if let Some(toml::Value::Table(sub)) = t.get_mut(parts[0]) {
            rec(sub, &parts[1..]);
            if sub.is_empty() {
                t.remove(parts[0]);
            }
        }
    }
    let parts: Vec<&str> = path.split('.').collect();
    rec(t, &parts);
}

// ===================================================================== routing

pub fn handle(app: &App, r: &Request<'_>) -> Response {
    // Access
    if let Some(proxy) = app.opts.trusted_proxy {
        if r.remote != Some(proxy) {
            return text(403, "Connection not via the trusted proxy.");
        }
        if header(r, USER_HEADER).is_none_or(|u| u.trim().is_empty()) {
            return text(403, "No user received from Authentik.");
        }
    }
    let user = header(r, USER_HEADER).map_or_else(|| "local".to_string(), str::to_string);

    let (path, query) = r.path.split_once('?').unwrap_or((r.path, ""));
    if path == "/health" {
        return text(200, "ok");
    }
    if app.opts.trusted_proxy.is_none()
        && let Some(deny) = local_access(app, r, path, query)
    {
        return deny;
    }

    // Master switch: checked on every request, fail-closed.
    let layers = match Config::load_layers(&app.opts.config_path) {
        Ok(l) => l,
        Err(e) => {
            app.shutdown.store(true, Ordering::SeqCst);
            return text(
                503,
                &format!("GUI stopped: configuration cannot be loaded ({e})."),
            );
        }
    };
    if !layers.config.gui.enabled {
        app.shutdown.store(true, Ordering::SeqCst);
        return text(503, "The GUI is off. The server is stopping.");
    }

    if r.method == "POST" {
        if app.opts.read_only {
            return text(403, "The GUI is in read-only mode.");
        }
        if r.body.len() > MAX_BODY {
            return text(413, "Request too large.");
        }
        let form = parse_form(r.body);
        if form_get(&form, "csrf") != Some(app.csrf.as_str()) {
            return text(403, "Form expired. Reload the page and try again.");
        }
        return match path {
            "/run/dry" => post_dry_run(app, &form, &user),
            "/run/apply" => post_apply(app, &layers, &form, &user),
            "/run/check-config" => post_check_config(app, &user),
            "/run/check-logs" => post_check_logs(app, &form, &user),
            "/run/check-tls" => post_check_tls(app, &user),
            "/payload/delete" => post_payload_delete(&layers, &user),
            "/gui/off" => post_gui_off(app, &layers, &user),
            "/exceptions/add" => post_exception_add(app, &layers, &form, &user),
            "/exceptions/remove" => post_exception_remove(&layers, &form, &user),
            p => {
                if let Some(slug) = p.strip_prefix("/settings/reset/") {
                    post_settings_reset(&layers, slug, &user)
                } else if let Some(slug) = p.strip_prefix("/settings/") {
                    post_settings(app, &layers, slug, &form, &user)
                } else {
                    text(404, "Not found.")
                }
            }
        };
    }
    if r.method != "GET" {
        return text(405, "Method not allowed.");
    }
    match path {
        "/" => html(200, &page_overview(app, &layers)),
        "/run" => html(200, &(flash_into(page_run(app, &layers, None), query))),
        "/audit" => html(200, &page_audit(app, &layers)),
        "/gui" => html(200, &page_gui(app, &layers)),
        "/modules" => html(200, &page_modules(app, &layers)),
        "/access" => html(200, &page_access(app, &layers, query)),
        "/access.csv" => get_access_csv(&layers, query, &user),
        "/exceptions" => html(200, &flash_into(page_exceptions(app, &layers, None), query)),
        "/payload" => get_payload(&layers, &user),
        p => match p.strip_prefix("/settings/").and_then(find_section) {
            Some(sec) => html(
                200,
                &flash_into(page_section(app, &layers, sec, None), query),
            ),
            None => text(404, "Not found."),
        },
    }
}

/// Puts a flash message right below the page title.
fn flash_into(page: String, query: &str) -> String {
    let f = flash_html(query);
    if f.is_empty() {
        return page;
    }
    page.replacen("</h1>", &format!("</h1>{f}"), 1)
}

fn find_section(slug: &str) -> Option<&'static Section> {
    SECTIONS.iter().find(|s| s.slug == slug)
}

// ===================================================================== settings

fn post_settings(
    app: &App,
    l: &Layers,
    slug: &str,
    form: &[(String, String)],
    user: &str,
) -> Response {
    let Some(sec) = find_section(slug) else {
        return text(404, "Not found.");
    };
    if let Some(m) = sec.requires
        && !l.base.contains_key(m)
    {
        return text(409, "This module is not set up in the config file.");
    }
    let mut ov = l.overrides.clone();
    let mut changed: Vec<String> = Vec::new();
    // What applies without any GUI change: the config file plus the program defaults.
    let without_gui = Config::combine(l.base.clone(), toml::Table::new())
        .map(|x| x.effective)
        .unwrap_or_default();
    for fld in sec.fields {
        if is_locked(fld.path) {
            continue;
        }
        let base = lookup(&l.base, fld.path);
        let fallback = base.or_else(|| lookup(&without_gui, fld.path));
        let new = match parse_field(fld, form, base) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => {
                return html(
                    400,
                    &page_section(app, l, sec, Some(&format!("{}: {e}", fld.label))),
                );
            }
        };
        let before = lookup(&l.merged, fld.path)
            .or_else(|| lookup(&l.effective, fld.path))
            .cloned();
        if fallback == Some(&new) {
            remove_path(&mut ov, fld.path);
        } else {
            set_path(&mut ov, fld.path, new.clone());
        }
        if before.as_ref() != Some(&new) {
            changed.push(fld.path.to_string());
        }
    }
    if let Err(e) = Config::combine(l.base.clone(), ov.clone()) {
        return html(400, &page_section(app, l, sec, Some(&e.to_string())));
    }
    if changed.is_empty() {
        return redirect(&format!("/settings/{slug}?ok=none"));
    }
    if let Err(e) = write_overrides(l, &ov) {
        return html(500, &page_section(app, l, sec, Some(&e)));
    }
    audit(&l.config.state.dir, user, "settings", &changed.join(", "));
    redirect(&format!("/settings/{slug}?ok=1"))
}

/// Reads one field from the form. `Ok(None)` = nothing to set (not configured).
fn parse_field(
    fld: &Field,
    form: &[(String, String)],
    base: Option<&toml::Value>,
) -> Result<Option<toml::Value>, String> {
    let raw = form_get(form, fld.path).unwrap_or("").trim();
    match fld.kind {
        Kind::Bool => Ok(Some(toml::Value::Boolean(raw == "on"))),
        Kind::Int { min, max } => {
            let n: i64 = raw
                .parse()
                .map_err(|_| format!("'{raw}' is not a whole number"))?;
            if n < min || n > max {
                return Err(format!("must be between {min} and {max}"));
            }
            Ok(Some(toml::Value::Integer(n)))
        }
        Kind::Text { max } => {
            if raw.is_empty() {
                return if base.is_some() {
                    Err("clearing is only possible in the config file".into())
                } else {
                    Ok(None)
                };
            }
            if raw.chars().count() > max || raw.chars().any(char::is_control) {
                return Err(format!("at most {max} characters, no control characters"));
            }
            Ok(Some(toml::Value::String(raw.to_string())))
        }
        Kind::LongText { max } => {
            let full = form_get(form, fld.path).unwrap_or("").replace("\r\n", "\n");
            let v = full.trim_end();
            if v.trim().is_empty() {
                return if base.is_some() {
                    Err("clearing is only possible in the config file".into())
                } else {
                    Ok(None)
                };
            }
            if v.chars().count() > max
                || v.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
            {
                return Err(format!("at most {max} characters, no control characters"));
            }
            Ok(Some(toml::Value::String(v.to_string())))
        }
        Kind::List => {
            let items: Vec<toml::Value> = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| toml::Value::String(s.to_string()))
                .collect();
            if items.is_empty() {
                return Err("at least one value needed".into());
            }
            Ok(Some(toml::Value::Array(items)))
        }
        Kind::Toggle => {
            let field = form_get(form, &format!("{}.field", fld.path))
                .unwrap_or("")
                .trim();
            let on = form_get(form, &format!("{}.enabled", fld.path)) == Some("on");
            if field.is_empty() {
                if on {
                    return Err("fill in the AFAS field first".into());
                }
                return if base.is_some() {
                    Err("clearing is only possible in the config file".into())
                } else {
                    Ok(None)
                };
            }
            if field.chars().count() > 64 || field.chars().any(char::is_control) {
                return Err("field name at most 64 characters".into());
            }
            let mut t = toml::Table::new();
            t.insert("enabled".into(), toml::Value::Boolean(on));
            t.insert("field".into(), toml::Value::String(field.to_string()));
            Ok(Some(toml::Value::Table(t)))
        }
    }
}

fn post_settings_reset(l: &Layers, slug: &str, user: &str) -> Response {
    let Some(sec) = find_section(slug) else {
        return text(404, "Not found.");
    };
    let mut ov = l.overrides.clone();
    let mut removed = Vec::new();
    for fld in sec.fields {
        if lookup(&ov, fld.path).is_some() {
            remove_path(&mut ov, fld.path);
            removed.push(fld.path);
        }
    }
    if removed.is_empty() {
        return redirect(&format!("/settings/{slug}"));
    }
    if let Err(e) = Config::combine(l.base.clone(), ov.clone())
        .map_err(|e| e.to_string())
        .and_then(|_| write_overrides(l, &ov))
    {
        return text(500, &e);
    }
    audit(&l.config.state.dir, user, "reset", &removed.join(", "));
    redirect(&format!("/settings/{slug}?ok=reset"))
}

fn write_overrides(l: &Layers, ov: &toml::Table) -> Result<(), String> {
    let path = l.config.state.dir.join(OVERRIDES_FILE);
    if ov.is_empty() {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        };
    }
    let body = toml::to_string(ov).map_err(|e| e.to_string())?;
    let text = format!("# GUI layer of afas-entra-sync. Managed by the GUI.\n{body}");
    write_atomic(&path, text.as_bytes()).map_err(|e| e.to_string())
}

fn post_gui_off(app: &App, l: &Layers, user: &str) -> Response {
    let mut ov = l.overrides.clone();
    set_path(&mut ov, "gui.enabled", toml::Value::Boolean(false));
    if let Err(e) = write_overrides(l, &ov) {
        return text(500, &e);
    }
    audit(
        &l.config.state.dir,
        user,
        "gui off",
        "GUI turned off from the GUI",
    );
    app.shutdown.store(true, Ordering::SeqCst);
    html(
        200,
        &layout_bare(
            "GUI turned off",
            "<p>The GUI is turned off and the server is stopping now.</p><p>To turn it back on, run <code>afas-entra-sync -c &lt;config&gt; gui-enable</code> on the server.</p>",
        ),
    )
}

// ===================================================================== runs

fn start_run<F>(app: &App, kind: &str, user: &str, dir: &Path, job: F) -> Response
where
    F: FnOnce() -> (i32, String) + Send + 'static,
{
    {
        let mut st = app
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cur) = &st.current {
            let _ = cur;
            return redirect("/run?m=busy");
        }
        st.current = Some(RunInfo {
            kind: kind.into(),
            user: user.into(),
            started: now(),
        });
    }
    audit(dir, user, kind, "started");
    let runs = app.runs.clone();
    let (kind_s, user_s, dir_s) = (kind.to_string(), user.to_string(), dir.to_path_buf());
    let finish = move || {
        let (exit_code, summary) = job();
        audit(
            &dir_s,
            &user_s,
            &kind_s,
            &format!("finished, exit {exit_code}"),
        );
        let mut st = runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.current = None;
        st.last = Some(RunDone {
            kind: kind_s,
            user: user_s,
            finished: now(),
            exit_code,
            summary,
        });
    };
    if app.run_inline {
        finish();
    } else {
        std::thread::spawn(finish);
    }
    redirect("/run")
}

fn post_dry_run(app: &App, form: &[(String, String)], user: &str) -> Response {
    let as_of = match form_get(form, "as_of")
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(s) => match NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            Ok(d) => Some(d),
            Err(_) => return redirect("/run?m=date"),
        },
    };
    let keep_payload = form_get(form, "payload") == Some("on");
    let (cfg_path, sleep, proxy) = (
        app.opts.config_path.clone(),
        app.sleep.clone(),
        app.use_system_proxy,
    );
    let dir = match Config::load(&cfg_path) {
        Ok(c) => c.state.dir,
        Err(e) => return text(500, &e.to_string()),
    };
    let label = match as_of {
        Some(d) => format!("test run as of {d}"),
        None => "test run".into(),
    };
    let dir2 = dir.clone();
    let actor = format!("gui:{user}");
    start_run(app, &label, user, &dir, move || {
        let cfg = match Config::load(&cfg_path) {
            Ok(c) => c,
            Err(e) => return (e.exit_code(), e.to_string()),
        };
        let opts = RunOptions {
            apply: false,
            as_of,
            allow_mass_disable: false,
            dump_payload: keep_payload.then(|| dir2.join(PAYLOAD_FILE)),
            use_system_proxy: proxy,
            actor: actor.clone(),
        };
        let s = |d: Duration| sleep(d);
        match run(&cfg, &opts, &s) {
            Ok(r) => (r.report.exit_code, r.report.result),
            Err((e, _)) => (e.exit_code(), e.to_string()),
        }
    })
}

fn post_apply(app: &App, l: &Layers, form: &[(String, String)], user: &str) -> Response {
    let allow_mass = form_get(form, "allow_mass_disable") == Some("on");
    let want = if allow_mass {
        CONFIRM_MASS
    } else {
        CONFIRM_APPLY
    };
    if form_get(form, "confirm").map(str::trim) != Some(want) {
        return html(
            400,
            &page_run(app, l, Some(&format!("Type {want} to confirm."))),
        );
    }
    let (cfg_path, sleep, proxy) = (
        app.opts.config_path.clone(),
        app.sleep.clone(),
        app.use_system_proxy,
    );
    let label = if allow_mass {
        "sync with mass disable"
    } else {
        "sync"
    };
    let actor = format!("gui:{user}");
    start_run(app, label, user, &l.config.state.dir, move || {
        let cfg = match Config::load(&cfg_path) {
            Ok(c) => c,
            Err(e) => return (e.exit_code(), e.to_string()),
        };
        let opts = RunOptions {
            apply: true,
            as_of: None,
            allow_mass_disable: allow_mass,
            dump_payload: None,
            use_system_proxy: proxy,
            actor: actor.clone(),
        };
        let s = |d: Duration| sleep(d);
        match run(&cfg, &opts, &s) {
            Ok(r) => (r.report.exit_code, r.report.result),
            Err((e, _)) => (e.exit_code(), e.to_string()),
        }
    })
}

fn post_check_config(app: &App, user: &str) -> Response {
    let (code, msg) = match Config::load(&app.opts.config_path) {
        Ok(_) => (0, "Configuration OK.".to_string()),
        Err(e) => (e.exit_code(), e.to_string()),
    };
    if let Ok(c) = Config::load(&app.opts.config_path) {
        audit(&c.state.dir, user, "check-config", &format!("exit {code}"));
    }
    let mut st = app
        .runs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    st.last = Some(RunDone {
        kind: "check-config".into(),
        user: user.into(),
        finished: now(),
        exit_code: code,
        summary: msg,
    });
    redirect("/run")
}

fn post_check_logs(app: &App, form: &[(String, String)], user: &str) -> Response {
    let minutes: i64 = match form_get(form, "minutes").unwrap_or("60").trim().parse() {
        Ok(m) if (1..=10_080).contains(&m) => m,
        _ => return redirect("/run?m=minutes"),
    };
    let (cfg_path, sleep, proxy) = (
        app.opts.config_path.clone(),
        app.sleep.clone(),
        app.use_system_proxy,
    );
    let dir = match Config::load(&cfg_path) {
        Ok(c) => c.state.dir,
        Err(e) => return text(500, &e.to_string()),
    };
    start_run(app, "check-logs", user, &dir, move || {
        let res = (|| {
            let cfg = Config::load(&cfg_path)?;
            let client = build_client(cfg.entra.timeout_secs, proxy, &cfg.tls)
                .map_err(crate::error::AppError::Config)?;
            let cred = Credential::from_config(&cfg.entra)?;
            let s = |d: Duration| sleep(d);
            let tokens = TokenProvider::new(&cfg.entra, &client, cred, &s);
            read_logs(
                &cfg.entra,
                &client,
                &tokens,
                chrono::Utc::now() - chrono::Duration::minutes(minutes),
            )
        })();
        match res {
            Ok(s) => {
                let code = if s.failure > 0 {
                    crate::error::exit::LOG_FAILURES
                } else {
                    0
                };
                let mut msg = format!(
                    "{} records: {} succeeded, {} failed, {} skipped, {} warnings.",
                    s.total, s.success, s.failure, s.skipped, s.warning
                );
                for fl in s.failures.iter().take(20) {
                    let _ = write!(msg, "\n{} {}: {}", fl.source_id, fl.action, fl.reason);
                }
                (code, msg)
            }
            Err(e) => (e.exit_code(), e.to_string()),
        }
    })
}

fn post_check_tls(app: &App, user: &str) -> Response {
    let cfg_path = app.opts.config_path.clone();
    let dir = match Config::load(&cfg_path) {
        Ok(c) => c.state.dir,
        Err(e) => return text(500, &e.to_string()),
    };
    start_run(app, "check-tls", user, &dir, move || {
        let res = Config::load(&cfg_path)
            .map_err(|e| e.to_string())
            .and_then(|c| crate::tls::check_endpoints(&c).map(|p| (c.tls, p)));
        match res {
            Err(e) => (crate::error::exit::CONFIG, e),
            Ok((policy, probes)) => {
                let mut msg = format!(
                    "Policy: TLS {} minimum, post-quantum {}.",
                    match policy.min_version {
                        crate::config::TlsVersion::V12 => "1.2",
                        crate::config::TlsVersion::V13 => "1.3",
                    },
                    match policy.post_quantum {
                        crate::config::PostQuantum::Prefer => "preferred",
                        crate::config::PostQuantum::Require => "required",
                    }
                );
                for p in &probes {
                    if p.ok {
                        let _ = write!(
                            msg,
                            "\n{} ({}): {}, {}, {}{}",
                            p.endpoint,
                            p.host,
                            p.protocol.as_deref().unwrap_or("?"),
                            p.cipher_suite.as_deref().unwrap_or("?"),
                            p.key_exchange.as_deref().unwrap_or("?"),
                            if p.post_quantum { ", post-quantum" } else { "" }
                        );
                    } else {
                        let _ = write!(
                            msg,
                            "\n{} ({}): FAILED: {}",
                            p.endpoint,
                            p.host,
                            p.error.as_deref().unwrap_or("?")
                        );
                    }
                }
                if probes.iter().any(|p| p.via_proxy.is_some()) {
                    msg.push_str(
                        "\nThrough a proxy: a TLS-inspecting proxy shows its own TLS settings.",
                    );
                }
                let code = if probes.iter().all(|p| p.ok) {
                    0
                } else {
                    crate::error::exit::TLS
                };
                (code, msg)
            }
        }
    })
}

fn get_payload(l: &Layers, user: &str) -> Response {
    let p = l.config.state.dir.join(PAYLOAD_FILE);
    match std::fs::read(&p) {
        Ok(b) => {
            audit(&l.config.state.dir, user, "payload downloaded", "");
            Response {
                status: 200,
                content_type: "application/json",
                location: None,
                disposition: Some("attachment; filename=\"payload.json\"".into()),
                set_cookie: None,
                body: b,
            }
        }
        Err(_) => text(
            404,
            "No saved upload data. Start a test run with 'Keep the data that would be sent'.",
        ),
    }
}

fn post_payload_delete(l: &Layers, user: &str) -> Response {
    let _ = std::fs::remove_file(l.config.state.dir.join(PAYLOAD_FILE));
    audit(&l.config.state.dir, user, "payload deleted", "");
    redirect("/run")
}

/// One JSON line per action. Write errors do not crash the GUI, but are logged.
pub fn audit(dir: &Path, user: &str, action: &str, detail: &str) {
    use std::io::Write;
    let line =
        serde_json::json!({ "utc": now(), "user": user, "action": action, "detail": detail });
    let res = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(AUDIT_FILE))
        .and_then(|mut f| writeln!(f, "{line}"));
    if let Err(e) = res {
        tracing::error!("writing audit log failed: {e}");
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ===================================================================== pages

fn page_overview(app: &App, l: &Layers) -> String {
    let mut b = String::new();
    let rep: Option<Value> = std::fs::read(l.config.state.dir.join(REPORT_FILE))
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok());
    let Some(r) = rep else {
        b.push_str(
            "<section class=empty><h2>No runs yet</h2><p>There is no report yet. Start a test run (dry-run) to see what the sync would do; nothing is sent to Microsoft.</p>\
             <p><a class=btn href=/run>Go to Run</a></p></section>",
        );
        return layout(app, l, "overview", "Overview", &b);
    };
    let code = r["exit_code"].as_i64().unwrap_or(-1);
    let (tone, verdict) = match code {
        0 => ("ok", "Succeeded"),
        3 => ("warn", "Succeeded, with records that need attention"),
        20 => ("bad", "Stopped by a safety threshold; nothing was uploaded"),
        _ => ("bad", "Failed"),
    };
    let mode = if r["mode"] == "apply" {
        "Sync"
    } else {
        "Test run"
    };
    let c = &r["counts"];
    let n = |k: &str| c[k].as_u64().unwrap_or(0);
    // On success the technical result text adds nothing; on failure it is the explanation.
    let detail = match code {
        0 => String::new(),
        3 => "See the skipped and missing records below.".to_string(),
        _ => r["result"].as_str().unwrap_or("").to_string(),
    };
    let _ = write!(
        b,
        "<section class=\"verdict {tone}\"><p class=kicker>{mode} of {}, reference date {}</p><h2>{verdict}</h2><p>{}</p></section>",
        esc(&fmt_time(r["started_utc"].as_str().unwrap_or(""))),
        esc(r["today"].as_str().unwrap_or("?")),
        esc(&detail),
    );

    // The flow strip: how the AFAS rows were distributed.
    let parts = [
        ("Active", n("sent_active"), "s-active"),
        (
            "New hires, not started yet",
            n("sent_inactive_prehire"),
            "s-pre",
        ),
        ("Departed, disabled", n("sent_inactive_leaver"), "s-leave"),
        ("Skipped (data errors)", n("excluded_errors"), "s-excl"),
        (
            "Not sent (outside date window)",
            n("skipped_future_start") + n("skipped_old_leaver"),
            "s-skip",
        ),
    ];
    let total: u64 = parts.iter().map(|p| p.1).sum();
    let _ = write!(
        b,
        "<section><h2>What happened to {} AFAS rows</h2><div class=flow role=img aria-label=\"Distribution of the AFAS rows\">",
        n("rows_fetched")
    );
    for (label, v, cls) in parts {
        if v > 0 && total > 0 {
            let _ = write!(
                b,
                "<span class={cls} style=\"flex-grow:{v}\" title=\"{label}: {v}\"></span>"
            );
        }
    }
    b.push_str("</div><dl class=legend>");
    for (label, v, cls) in parts {
        let _ = write!(
            b,
            "<div><dt><i class={cls}></i>{label}</dt><dd>{v}</dd></div>"
        );
    }
    let _ = write!(
        b,
        "</dl><p class=note>{} sent in {} API calls. {} new disables.</p></section>",
        n("sent_total"),
        n("api_calls_needed"),
        n("new_disables")
    );

    list_section(
        &mut b,
        "Safety stops",
        &r["violations"],
        &[("guard", "Threshold"), ("message", "What happened")],
    );
    list_section(
        &mut b,
        "Skipped records (exclusions)",
        &r["exclusions"],
        &[("employee_id", "Employee number"), ("reason", "Reason")],
    );
    if let Some(d) = r["disappeared_while_active"]
        .as_array()
        .filter(|a| !a.is_empty())
    {
        let _ = write!(
            b,
            "<section><h2>Missing from AFAS while active ({})</h2><p class=note>These accounts are not disabled automatically. Check them in AD.</p><p class=ids>",
            d.len()
        );
        for id in d {
            let _ = write!(b, "<code>{}</code> ", esc(id.as_str().unwrap_or("?")));
        }
        b.push_str("</p></section>");
    }
    list_section(
        &mut b,
        "Warnings",
        &r["warnings"],
        &[("employee_id", "Employee number"), ("message", "Message")],
    );
    layout(app, l, "overview", "Overview", &b)
}

fn list_section(b: &mut String, title: &str, v: &Value, cols: &[(&str, &str)]) {
    let Some(items) = v.as_array().filter(|a| !a.is_empty()) else {
        return;
    };
    let _ = write!(
        b,
        "<section><h2>{} ({})</h2><table><thead><tr>",
        esc(title),
        items.len()
    );
    for (_, h) in cols {
        let _ = write!(b, "<th>{h}</th>");
    }
    b.push_str("</tr></thead><tbody>");
    for it in items {
        b.push_str("<tr>");
        for (c, _) in cols {
            let cell = match &it[*c] {
                Value::String(s) => s.clone(),
                Value::Null => "—".into(),
                other => other.to_string(),
            };
            let _ = write!(b, "<td>{}</td>", esc(&cell));
        }
        b.push_str("</tr>");
    }
    b.push_str("</tbody></table></section>");
}

fn page_run(app: &App, l: &Layers, error: Option<&str>) -> String {
    let mut b = String::new();
    if let Some(e) = error {
        let _ = write!(b, "<p class=\"msg bad\" role=alert>{}</p>", esc(e));
    }
    {
        let st = app
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cur) = &st.current {
            let _ = write!(
                b,
                "<section class=\"verdict busy\"><p class=kicker>Started at {} by {}</p><h2>{} running</h2><p>Reload this page for the status. A run can take minutes if Microsoft asks to wait.</p></section>",
                esc(&fmt_time(&cur.started)),
                esc(&cur.user),
                esc(&capital(&cur.kind))
            );
        } else if let Some(d) = &st.last {
            let tone = match d.exit_code {
                0 => "ok",
                3 => "warn",
                _ => "bad",
            };
            let _ = write!(
                b,
                "<section class=\"verdict {tone}\"><p class=kicker>{} by {}, finished at {}, exit code {}</p><h2>{}</h2><pre>{}</pre></section>",
                esc(&capital(&d.kind)),
                esc(&d.user),
                esc(&fmt_time(&d.finished)),
                d.exit_code,
                match d.exit_code {
                    0 => "Succeeded",
                    3 => "Succeeded, with points of attention",
                    _ => "Failed",
                },
                esc(&d.summary)
            );
        }
    }
    let ro = app.opts.read_only;
    let dis = if ro { " disabled" } else { "" };
    let csrf = &app.csrf;
    let has_payload = l.config.state.dir.join(PAYLOAD_FILE).exists();

    let _ = write!(
        b,
        "<section class=action><div><h2>Test run (dry-run)</h2><p>Fetches AFAS and shows what the sync would do. Nothing is sent to Microsoft and nothing changes.</p></div>\
<form method=post action=/run/dry><input type=hidden name=csrf value={csrf}>\
<label>Pretend it is this date <small>optional, YYYY-MM-DD</small><input name=as_of placeholder=2026-12-01 inputmode=numeric{dis}></label>\
<label class=check><input type=checkbox name=payload{dis}><span>Keep the data that would be sent (payload)<small>For download. Contains personal data.</small></span></label>\
<button{dis}>Start test run</button></form></section>"
    );
    if has_payload {
        let _ = write!(
            b,
            "<section class=action><div><h2>Saved upload data (payload)</h2><p>Exactly what Microsoft would receive in the last test run. Delete it after use.</p></div>\
<div class=row><a class=btn href=/payload>Download data</a><form method=post action=/payload/delete><input type=hidden name=csrf value={csrf}><button class=quiet{dis}>Delete data</button></form></div></section>"
        );
    }
    let _ = write!(
        b,
        "<section class=\"action danger\"><div><h2>Run sync</h2><p>Sends all employees to Microsoft. Microsoft creates, updates or disables accounts. The safety thresholds still apply.</p></div>\
<form method=post action=/run/apply><input type=hidden name=csrf value={csrf}>\
<label class=check><input type=checkbox name=allow_mass_disable{dis}><span>Proceed if the disable threshold is hit<small>Only after checking the list in the test run.</small></span></label>\
<label>Type <b>{CONFIRM_APPLY}</b> to confirm <small>or <b>{CONFIRM_MASS}</b> if you ticked proceed above</small><input name=confirm autocomplete=off{dis}></label>\
<button class=danger{dis}>Run sync</button></form></section>"
    );
    let _ = write!(
        b,
        "<section class=action><div><h2>Checks</h2><p>Check the configuration, see which TLS version and key exchange AFAS and Microsoft negotiate, or go through the Microsoft provisioning logs for failed records.</p></div>\
<div class=row><form method=post action=/run/check-config><input type=hidden name=csrf value={csrf}><button class=quiet{dis}>Check configuration</button></form>\
<form method=post action=/run/check-tls><input type=hidden name=csrf value={csrf}><button class=quiet{dis}>Check TLS</button></form>\
<form method=post action=/run/check-logs class=inline><input type=hidden name=csrf value={csrf}><label>Last <input name=minutes value=60 size=5 inputmode=numeric{dis}> minutes</label><button class=quiet{dis}>Check logs</button></form></div></section>"
    );
    layout(app, l, "run", "Run", &b)
}

fn page_section(app: &App, l: &Layers, sec: &Section, error: Option<&str>) -> String {
    let mut b = String::new();
    let _ = write!(b, "<p class=lead>{}</p>", esc(sec.intro));
    if let Some(m) = sec.requires
        && !l.base.contains_key(m)
    {
        let _ = write!(
            b,
            "<section class=empty><h2>Not set up</h2><p>Add a <code>[{m}]</code> section with its own app registration to the config file first; see the guide. Then its settings can be changed here.</p></section>"
        );
        return layout(app, l, sec.slug, sec.title, &b);
    }
    if let Some(e) = error {
        let _ = write!(
            b,
            "<p class=\"msg bad\" role=alert>Not saved. {}</p>",
            esc(e)
        );
    }
    let ro = app.opts.read_only;
    let _ = write!(
        b,
        "<form method=post action=/settings/{} class=settings><input type=hidden name=csrf value={}>",
        sec.slug, app.csrf
    );
    let mut any_override = false;
    for fld in sec.fields {
        // Keys left out of the config file show the value the program actually uses.
        let cur = lookup(&l.merged, fld.path).or_else(|| lookup(&l.effective, fld.path));
        let locked = is_locked(fld.path);
        let from_gui = lookup(&l.overrides, fld.path).is_some();
        any_override |= from_gui;
        if locked && cur.is_none() {
            continue; // not used in this config
        }
        let id = fld.path.replace('.', "-");
        let badge = if locked {
            "<span class=\"badge lock\">fixed in config file</span>"
        } else if from_gui {
            "<span class=\"badge gui\">changed in GUI</span>"
        } else {
            ""
        };
        let help = if fld.help.is_empty() {
            String::new()
        } else {
            format!("<small>{}</small>", esc(fld.help))
        };
        let dis = if ro || locked { " disabled" } else { "" };
        let _ = write!(
            b,
            "<div class=field><div class=label><label for={id}>{}</label>{badge}{help}</div><div class=control>",
            esc(fld.label)
        );
        match fld.kind {
            Kind::Bool => {
                let chk = if cur.and_then(toml::Value::as_bool).unwrap_or(false) {
                    " checked"
                } else {
                    ""
                };
                let _ = write!(
                    b,
                    "<label class=switch><input type=checkbox id={id} name=\"{}\"{chk}{dis}><span></span></label>",
                    fld.path
                );
            }
            Kind::Toggle => {
                let t = cur.and_then(toml::Value::as_table);
                let on = t
                    .and_then(|t| t.get("enabled"))
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false);
                let field = t
                    .and_then(|t| t.get("field"))
                    .and_then(toml::Value::as_str)
                    .unwrap_or("");
                let chk = if on { " checked" } else { "" };
                let _ = write!(
                    b,
                    "<label class=switch><input type=checkbox id={id} name=\"{p}.enabled\"{chk}{dis} aria-label=\"{l} on\"><span></span></label>\
<input class=fieldname name=\"{p}.field\" value=\"{v}\" placeholder=\"AFAS field\" aria-label=\"AFAS field for {l}\"{dis}>",
                    p = fld.path,
                    l = esc(fld.label),
                    v = esc(field)
                );
            }
            Kind::Int { min, max } => {
                let v = cur
                    .and_then(toml::Value::as_integer)
                    .map(|i| i.to_string())
                    .unwrap_or_default();
                let _ = write!(
                    b,
                    "<input id={id} name=\"{}\" value=\"{}\" inputmode=numeric min={min} max={max} class=num{dis}>",
                    fld.path,
                    esc(&v)
                );
            }
            Kind::List => {
                let v = cur
                    .and_then(toml::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(toml::Value::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let _ = write!(
                    b,
                    "<input id={id} name=\"{}\" value=\"{}\"{dis}>",
                    fld.path,
                    esc(&v)
                );
            }
            Kind::Text { .. } => {
                let v = cur.and_then(toml::Value::as_str).unwrap_or("");
                let _ = write!(
                    b,
                    "<input id={id} name=\"{}\" value=\"{}\"{dis}>",
                    fld.path,
                    esc(v)
                );
            }
            Kind::LongText { .. } => {
                let v = cur.and_then(toml::Value::as_str).unwrap_or("");
                let _ = write!(
                    b,
                    "<textarea id={id} name=\"{}\" rows=7{dis}>{}</textarea>",
                    fld.path,
                    esc(v)
                );
            }
        }
        b.push_str("</div></div>");
    }
    if !ro {
        b.push_str("<div class=bar><button>Save changes</button></div>");
    }
    b.push_str("</form>");
    if any_override && !ro {
        let _ = write!(
            b,
            "<form method=post action=/settings/reset/{} class=reset><input type=hidden name=csrf value={}>\
<button class=quiet>Reset to config file</button> <small>Removes the GUI changes on this page.</small></form>",
            sec.slug, app.csrf
        );
    }
    layout(app, l, sec.slug, sec.title, &b)
}

fn page_gui(app: &App, l: &Layers) -> String {
    let mut b = String::new();
    let _ = write!(
        b,
        "<p class=lead>The GUI only runs when <code>[gui] enabled = true</code> is set in the config file. Turn it off here and the server stops right away; it stays off until someone runs <code>gui-enable</code> on the server.</p>\
<dl class=facts><div><dt>Address</dt><dd>{}</dd></div><div><dt>Access</dt><dd>{}</dd></div><div><dt>Mode</dt><dd>{}</dd></div><div><dt>Config file</dt><dd><code>{}</code></dd></div><div><dt>GUI layer</dt><dd><code>{}</code></dd></div></dl>",
        esc(&app.opts.listen.to_string()),
        app.opts.trusted_proxy.map_or_else(
            || "this server only".to_string(),
            |p| format!("via proxy {p}, with Authentik")
        ),
        if app.opts.read_only {
            "read only"
        } else {
            "read and change"
        },
        esc(&app.opts.config_path.display().to_string()),
        esc(&l
            .config
            .state
            .dir
            .join(OVERRIDES_FILE)
            .display()
            .to_string()),
    );
    if !app.opts.read_only {
        let _ = write!(
            b,
            "<section class=\"action danger\"><div><h2>Turn off GUI</h2><p>For extra security when you do not need the GUI for a while. The scheduled sync keeps running.</p></div>\
<form method=post action=/gui/off><input type=hidden name=csrf value={}><button class=danger>Turn off GUI</button></form></section>",
            app.csrf
        );
    }
    layout(app, l, "gui", "GUI", &b)
}

fn page_audit(app: &App, l: &Layers) -> String {
    let mut b =
        String::from("<p class=lead>Every change and every run through the GUI, newest first.</p>");
    let lines = std::fs::read_to_string(l.config.state.dir.join(AUDIT_FILE)).unwrap_or_default();
    if lines.trim().is_empty() {
        b.push_str("<p class=note>Nothing recorded yet.</p>");
        return layout(app, l, "audit", "Audit log", &b);
    }
    b.push_str("<table><thead><tr><th>Time</th><th>Who</th><th>What</th><th>Details</th></tr></thead><tbody>");
    for line in lines.lines().rev().take(300) {
        let v: Value = serde_json::from_str(line).unwrap_or(Value::Null);
        let _ = write!(
            b,
            "<tr><td class=nowrap>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&fmt_time(v["utc"].as_str().unwrap_or("?"))),
            esc(v["user"].as_str().unwrap_or("?")),
            esc(v["action"].as_str().unwrap_or("?")),
            esc(v["detail"].as_str().unwrap_or(""))
        );
    }
    b.push_str("</tbody></table>");
    layout(app, l, "audit", "Audit log", &b)
}

fn fmt_time(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339).map_or_else(
        |_| rfc3339.to_string(),
        |t| {
            t.with_timezone(&chrono_tz::Europe::Amsterdam)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        },
    )
}

fn capital(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| {
        f.to_uppercase().collect::<String>() + c.as_str()
    })
}

// ===================================================================== modules

fn module_status(on: Option<bool>) -> &'static str {
    match on {
        None => "not set up",
        Some(false) => "off",
        Some(true) => "on",
    }
}

fn page_modules(app: &App, l: &Layers) -> String {
    let c = &l.config;
    let mut b = String::from(
        "<p class=lead>Optional modules that run after the upload to Entra. Each signs in with its own app registration and stops by itself when it would change more than its maximum.</p>",
    );
    let rep: Option<Value> = std::fs::read(c.state.dir.join(REPORT_FILE))
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok());
    b.push_str(
        "<section><table><thead><tr><th>Module</th><th>Status</th><th>Last run</th></tr></thead><tbody>",
    );
    for (key, label, on) in [
        (
            "roles",
            "Roles and licences",
            c.roles.as_ref().map(|m| m.enabled),
        ),
        (
            "joiner",
            "New hires (joiners): first sign-in code",
            c.joiner.as_ref().map(|m| m.enabled),
        ),
        (
            "leaver",
            "Departing employees (leavers)",
            c.leaver.as_ref().map(|m| m.enabled),
        ),
        (
            "webhook",
            "Notify other systems (webhook)",
            c.webhook.as_ref().map(|m| m.enabled),
        ),
    ] {
        let m = rep.as_ref().map(|r| &r["modules"][key]);
        let last = match m {
            Some(m) if !m.is_null() => {
                if let Some(e) = m["error"].as_str() {
                    format!("error: {e}")
                } else if let Some(v) = m["violations"].as_array().and_then(|v| v.first()) {
                    format!("stopped: {}", v.as_str().unwrap_or(""))
                } else {
                    format!(
                        "{} planned, {} applied, {} failed, {} notes",
                        m["planned"].as_array().map_or(0, Vec::len),
                        m["applied"].as_u64().unwrap_or(0),
                        m["failed"].as_array().map_or(0, Vec::len),
                        m["notes"].as_array().map_or(0, Vec::len)
                    )
                }
            }
            _ => "—".into(),
        };
        let _ = write!(
            b,
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(label),
            module_status(on),
            esc(&last)
        );
    }
    b.push_str("</tbody></table></section>");
    if let Some(r) = &c.roles {
        let _ = write!(
            b,
            "<section><h2>Role rules ({})</h2><p class=note>Managed groups must start with <code>{}</code>. Rules are changed in the config file.</p><table><thead><tr><th>Group</th><th>Who</th></tr></thead><tbody>",
            r.rules.len(),
            esc(&r.group_prefix)
        );
        for rule in &r.rules {
            let who = if rule.all {
                "everyone".to_string()
            } else {
                rule.criteria()
                    .iter()
                    .filter(|(_, v)| !v.is_empty())
                    .map(|(k, v)| format!("{}: {}", criterion_label(k), v.join(" or ")))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            let _ = write!(
                b,
                "<tr><td>{}<small>{}</small></td><td>{}</td></tr>",
                esc(rule.name.as_deref().unwrap_or("")),
                esc(&rule.group_id),
                esc(&who)
            );
        }
        b.push_str("</tbody></table></section>");
        if !r.sod.is_empty() {
            b.push_str("<section><h2>Conflicting groups (segregation of duties)</h2><p class=note>Nobody gets two groups from the same line; such a person keeps the groups they already have and is reported.</p><table><thead><tr><th>Name</th><th>Never together</th></tr></thead><tbody>");
            let name = |g: &str| {
                r.rules
                    .iter()
                    .find(|x| x.group_id.eq_ignore_ascii_case(g))
                    .and_then(|x| x.name.clone())
                    .unwrap_or_else(|| g.to_string())
            };
            for s in &r.sod {
                let names: Vec<String> = s.groups.iter().map(|g| name(g)).collect();
                let _ = write!(
                    b,
                    "<tr><td>{}</td><td>{}</td></tr>",
                    esc(&s.name),
                    esc(&names.join(", "))
                );
            }
            b.push_str("</tbody></table></section>");
        }
    }
    layout(app, l, "modules", "Modules", &b)
}

fn query_get(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(url_decode)
        .filter(|v| !v.trim().is_empty())
}

/// Plain-language names for what the access log records; the HR term in brackets.
fn module_label(m: &str) -> &str {
    match m {
        "roles" => "roles and licences",
        "joiner" => "new hires (joiners)",
        "leaver" => "departing employees (leavers)",
        "webhook" => "webhook",
        other => other,
    }
}

fn action_label(a: &str) -> String {
    match a {
        "add_to_group" => "added to group".into(),
        "remove_from_group" => "removed from group".into(),
        "issue_temporary_access_pass" => "first sign-in code sent (Temporary Access Pass)".into(),
        "leaver_actions" => "signed out and automatic reply (leaver actions)".into(),
        other => other.replace('_', " "),
    }
}

fn criterion_label(k: &str) -> &str {
    match k {
        "department" => "department",
        "job_title" => "job title",
        "job_profile" => "job profile",
        "office" => "office",
        "company" => "company",
        "employee_type" => "employee type",
        "cost_center" => "cost center",
        "population" => "staff category (population)",
        other => other,
    }
}

fn page_access(app: &App, l: &Layers, query: &str) -> String {
    use crate::modules::records::read_access;
    let emp = query_get(query, "employee").filter(|e| e.len() <= 16);
    let mut b = String::from(
        "<p class=lead>Every group change, first sign-in code (Temporary Access Pass) and action for departing employees (leavers) the modules made, newest first.</p>",
    );
    let _ = write!(
        b,
        "<form method=get action=/access class=row><label>Employee number <input name=employee value=\"{}\" size=12></label><button class=quiet>Filter</button><a class=btn href=\"/access.csv{}\">Download CSV</a></form>",
        esc(emp.as_deref().unwrap_or("")),
        emp.as_deref()
            .map(|e| format!("?employee={}", esc(&url_encode(e))))
            .unwrap_or_default()
    );
    match read_access(&l.config.state.dir, emp.as_deref(), None) {
        Err(e) => {
            let _ = write!(b, "<p class=\"msg bad\">{}</p>", esc(&e));
        }
        Ok(v) if v.is_empty() => b.push_str("<p class=note>Nothing recorded yet.</p>"),
        Ok(v) => {
            b.push_str("<table><thead><tr><th>Time</th><th>Employee</th><th>What</th><th>Target</th><th>Result</th></tr></thead><tbody>");
            for e in v.iter().rev().take(500) {
                let _ = write!(
                    b,
                    "<tr><td class=nowrap>{}</td><td>{}<small>{}</small></td><td>{}<small>{}</small></td><td>{}</td><td>{}</td></tr>",
                    esc(&fmt_time(&e.utc)),
                    esc(e.employee_id.as_deref().unwrap_or("—")),
                    esc(e.upn.as_deref().unwrap_or("")),
                    esc(&action_label(&e.action)),
                    esc(module_label(&e.module)),
                    esc(e.target.as_deref().unwrap_or("")),
                    if e.ok {
                        esc(e.detail.as_deref().unwrap_or("ok"))
                    } else {
                        format!("<b>failed</b> {}", esc(e.detail.as_deref().unwrap_or("")))
                    }
                );
            }
            b.push_str("</tbody></table>");
        }
    }
    layout(app, l, "access", "Access log", &b)
}

fn get_access_csv(l: &Layers, query: &str, user: &str) -> Response {
    use crate::modules::records::{access_csv, read_access};
    let emp = query_get(query, "employee").filter(|e| e.len() <= 16);
    match read_access(&l.config.state.dir, emp.as_deref(), None) {
        Ok(v) => {
            audit(
                &l.config.state.dir,
                user,
                "access log exported",
                emp.as_deref().unwrap_or("all"),
            );
            Response {
                status: 200,
                content_type: "text/csv; charset=utf-8",
                location: None,
                disposition: Some("attachment; filename=\"access-log.csv\"".into()),
                set_cookie: None,
                body: access_csv(&v).into_bytes(),
            }
        }
        Err(e) => text(500, &e),
    }
}

fn page_exceptions(app: &App, l: &Layers, error: Option<&str>) -> String {
    use crate::modules::records::{ExceptionKind, load_exceptions};
    let today = chrono::Utc::now()
        .with_timezone(&l.config.tz())
        .date_naive();
    let mut b = String::from(
        "<p class=lead>Manual deviations from the role rules, each with an end date and a reason. After the end date the rules apply again.</p>",
    );
    if let Some(e) = error {
        let _ = write!(
            b,
            "<p class=\"msg bad\" role=alert>Not saved. {}</p>",
            esc(e)
        );
    }
    let ro = app.opts.read_only;
    let names: std::collections::HashMap<String, String> = l
        .config
        .roles
        .as_ref()
        .map(|r| {
            r.rules
                .iter()
                .map(|x| {
                    (
                        x.group_id.to_ascii_lowercase(),
                        x.name.clone().unwrap_or_else(|| x.group_id.clone()),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    match load_exceptions(&l.config.state.dir) {
        Err(e) => {
            let _ = write!(b, "<p class=\"msg bad\">{}</p>", esc(&e));
        }
        Ok(x) if x.items.is_empty() => b.push_str("<p class=note>No exceptions.</p>"),
        Ok(x) => {
            b.push_str("<section><table><thead><tr><th>Employee</th><th>Group</th><th>Kind</th><th>Until</th><th>Reason</th><th></th></tr></thead><tbody>");
            for e in &x.items {
                let expired = e.until < today;
                let _ = write!(
                    b,
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td class=nowrap>{}{}</td><td>{}<small>{}, {}</small></td><td>",
                    esc(&e.employee_id),
                    esc(names
                        .get(&e.group_id.to_ascii_lowercase())
                        .unwrap_or(&e.group_id)),
                    if e.kind == ExceptionKind::Include {
                        "keep in"
                    } else {
                        "keep out"
                    },
                    e.until,
                    if expired {
                        " <small>expired</small>"
                    } else {
                        ""
                    },
                    esc(&e.reason),
                    esc(&e.created_by),
                    esc(&fmt_time(&e.created_utc))
                );
                if !ro {
                    let _ = write!(
                        b,
                        "<form method=post action=/exceptions/remove><input type=hidden name=csrf value={}><input type=hidden name=id value=\"{}\"><button class=quiet>Remove</button></form>",
                        app.csrf,
                        esc(&e.id)
                    );
                }
                b.push_str("</td></tr>");
            }
            b.push_str("</tbody></table></section>");
        }
    }
    if !ro && !names.is_empty() {
        let mut opts = String::new();
        let mut sorted: Vec<_> = names.iter().collect();
        sorted.sort_by(|a, b| a.1.cmp(b.1));
        for (id, n) in sorted {
            let _ = write!(opts, "<option value=\"{}\">{}</option>", esc(id), esc(n));
        }
        let _ = write!(
            b,
            "<section class=action><div><h2>Add exception</h2><p>Only groups from the role rules. At most one year ahead.</p></div>\
<form method=post action=/exceptions/add><input type=hidden name=csrf value={}>\
<label>Employee number<input name=employee required maxlength=16></label>\
<label>Group<select name=group>{opts}</select></label>\
<label>Kind<select name=kind><option value=include>keep in the group</option><option value=exclude>keep out of the group</option></select></label>\
<label>Until (last day)<input name=until type=date required></label>\
<label>Reason<input name=reason required maxlength=500></label>\
<button>Add exception</button></form></section>",
            app.csrf
        );
    } else if names.is_empty() {
        b.push_str("<p class=note>Set up the roles module to use exceptions.</p>");
    }
    layout(app, l, "exceptions", "Exceptions", &b)
}

fn post_exception_add(app: &App, l: &Layers, form: &[(String, String)], user: &str) -> Response {
    use crate::modules::records::{ExceptionKind, add_exception};
    let today = chrono::Utc::now()
        .with_timezone(&l.config.tz())
        .date_naive();
    let g = |k: &str| form_get(form, k).unwrap_or("").trim().to_string();
    let group = g("group");
    let in_rules = l.config.roles.as_ref().is_some_and(|r| {
        r.rules
            .iter()
            .any(|x| x.group_id.eq_ignore_ascii_case(&group))
    });
    let res = (|| {
        if !in_rules {
            return Err("group is not in the role rules".to_string());
        }
        let kind = match g("kind").as_str() {
            "include" => ExceptionKind::Include,
            "exclude" => ExceptionKind::Exclude,
            _ => return Err("kind must be include or exclude".into()),
        };
        let until = NaiveDate::parse_from_str(&g("until"), "%Y-%m-%d")
            .map_err(|_| "until must be a date (YYYY-MM-DD)".to_string())?;
        add_exception(
            &l.config.state.dir,
            &g("employee"),
            &group,
            kind,
            until,
            &g("reason"),
            user,
            today,
        )
    })();
    match res {
        Ok(id) => {
            audit(
                &l.config.state.dir,
                user,
                "exception added",
                &format!(
                    "{id}: {} {} in {} until {}: {}",
                    g("kind"),
                    g("employee"),
                    group,
                    g("until"),
                    g("reason")
                ),
            );
            redirect("/exceptions?ok=1")
        }
        Err(e) => html(400, &page_exceptions(app, l, Some(&e))),
    }
}

fn post_exception_remove(l: &Layers, form: &[(String, String)], user: &str) -> Response {
    let id = form_get(form, "id").unwrap_or("");
    match crate::modules::records::remove_exception(&l.config.state.dir, id) {
        Ok(e) => {
            audit(
                &l.config.state.dir,
                user,
                "exception removed",
                &format!("{}: {} {}", e.id, e.employee_id, e.group_id),
            );
            redirect("/exceptions?ok=1")
        }
        Err(e) => text(404, &e),
    }
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

// ===================================================================== styling

const CSS: &str = r#"
:root{--bg:#e9eef1;--surface:#fff;--ink:#132430;--muted:#566874;--line:#cfd8de;--accent:#0b6b70;--accent-ink:#fff;
--ok:#1d7546;--warn:#975400;--bad:#b0261e;--s-active:#0b6b70;--s-pre:#6aa8ab;--s-leave:#8a96a0;--s-excl:#b0261e;--s-skip:#d5dde2;
--font:"Seravek","Gill Sans Nova",Ubuntu,Calibri,"DejaVu Sans",source-sans-pro,sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#0e191f;--surface:#15242c;--ink:#e3ecf0;--muted:#93a5b0;--line:#28404b;--accent:#4fb0b3;--accent-ink:#06282a;
--ok:#5cc28a;--warn:#e0a24a;--bad:#ef7b72;--s-active:#4fb0b3;--s-pre:#2f7a7d;--s-leave:#5d6c76;--s-excl:#ef7b72;--s-skip:#2a3b44}}
*{box-sizing:border-box}html{background:var(--bg)}
body{margin:0;font:16px/1.55 var(--font);color:var(--ink);background:var(--bg);font-variant-numeric:tabular-nums}
a{color:var(--accent)}a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.shell{display:grid;grid-template-columns:232px 1fr;min-height:100vh}
nav.side{background:var(--surface);border-right:1px solid var(--line);padding:28px 20px;position:sticky;top:0;height:100vh;overflow:auto}
.brand{font-size:19px;font-weight:600;letter-spacing:-.01em;margin:0}
.pop{color:var(--muted);font-size:14px;margin:2px 0 28px}
nav.side ul{list-style:none;margin:0 0 20px;padding:0}nav.side li a{display:block;padding:7px 10px;margin:1px -10px;border-radius:6px;color:var(--ink);text-decoration:none}
nav.side li a:hover{background:var(--bg)}nav.side li a[aria-current]{background:var(--accent);color:var(--accent-ink);font-weight:600}
nav.side .group{color:var(--muted);font-size:13px;margin:18px 0 4px}
main{padding:40px clamp(16px,5vw,64px) 80px;max-width:920px}
h1{font-size:34px;line-height:1.15;font-weight:600;letter-spacing:-.02em;margin:0 0 20px}
h2{font-size:20px;font-weight:600;margin:0 0 8px;letter-spacing:-.01em}
section{margin:0 0 36px}.lead{font-size:18px;color:var(--muted);max-width:62ch;margin:-8px 0 28px}
.note{color:var(--muted);font-size:15px}small{display:block;color:var(--muted);font-size:13.5px;font-weight:400}
.verdict{border-left:6px solid var(--muted);padding:6px 0 6px 20px}.verdict h2{font-size:27px;line-height:1.2;margin:2px 0 6px}
.verdict.ok{border-color:var(--ok)}.verdict.warn{border-color:var(--warn)}.verdict.bad{border-color:var(--bad)}.verdict.busy{border-color:var(--accent)}
.verdict p{margin:0;max-width:70ch}.kicker{color:var(--muted);font-size:14px}
.verdict pre{white-space:pre-wrap;font:inherit;margin:4px 0 0;max-width:72ch}
.flow{display:flex;height:34px;border-radius:5px;overflow:hidden;gap:2px;background:var(--line);margin:14px 0 12px}
.flow span{min-width:3px}
.s-active{background:var(--s-active)}.s-pre{background:var(--s-pre)}.s-leave{background:var(--s-leave)}.s-excl{background:var(--s-excl)}.s-skip{background:var(--s-skip)}
.legend{display:flex;flex-wrap:wrap;gap:8px 28px;margin:0}.legend div{display:flex;gap:8px;align-items:baseline}
.legend dt{color:var(--muted);font-size:14.5px}.legend dd{margin:0;font-weight:600;font-size:18px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}
table{width:100%;border-collapse:collapse;font-size:15px;background:var(--surface);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th{text-align:left;font-weight:600;color:var(--muted);font-size:13.5px;padding:9px 12px;border-bottom:1px solid var(--line)}
td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}tr:last-child td{border-bottom:0}.nowrap{white-space:nowrap}
code{font-size:.92em;background:var(--bg);padding:1px 5px;border-radius:4px}.ids code{display:inline-block;margin:0 4px 6px 0}
form.settings{background:var(--surface);border:1px solid var(--line);border-radius:10px}
.field{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.1fr);gap:16px;padding:16px 20px;border-bottom:1px solid var(--line);align-items:start}
.field .label label{font-weight:600}.control{display:flex;gap:12px;align-items:center}
input:not([type=checkbox]){font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:7px 10px;width:100%}
select{font:inherit;font-weight:400;color:var(--ink);background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:7px 10px;width:100%}
textarea{font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:7px 10px;width:100%;resize:vertical}textarea:disabled{background:var(--bg);color:var(--muted)}
input.num{max-width:9em}input{font-weight:400!important}::placeholder{color:var(--muted);opacity:.7}input:disabled{background:var(--bg);color:var(--muted)}
.badge{display:inline-block;font-size:12.5px;padding:1px 8px;border-radius:999px;margin-left:8px;vertical-align:1px}
.badge.lock{background:var(--bg);color:var(--muted)}.badge.gui{background:var(--accent);color:var(--accent-ink)}
.switch{position:relative;display:inline-block;width:46px;height:26px;flex:none}.switch input{opacity:0;width:0;height:0;position:absolute}
.switch span{position:absolute;inset:0;background:var(--line);border-radius:26px;transition:background .15s}
.switch span::after{content:"";position:absolute;width:20px;height:20px;left:3px;top:3px;background:var(--surface);border-radius:50%;transition:transform .15s;box-shadow:0 1px 2px rgba(0,0,0,.25)}
.switch input:checked+span{background:var(--accent)}.switch input:checked+span::after{transform:translateX(20px)}
.switch input:focus-visible+span{outline:3px solid var(--accent);outline-offset:2px}.switch input:disabled+span{opacity:.5}
.bar{padding:16px 20px;display:flex;justify-content:flex-end}
button,.btn{font:inherit;font-weight:600;border:0;border-radius:6px;padding:9px 18px;background:var(--accent);color:var(--accent-ink);cursor:pointer;text-decoration:none;display:inline-block}
button.quiet{background:transparent;color:var(--accent);border:1px solid var(--line)}button.danger{background:var(--bad);color:#fff}
button:disabled{opacity:.45;cursor:not-allowed}
.action{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.1fr);gap:24px;background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:22px}
.action.danger{border-color:var(--bad)}.action p{color:var(--muted);margin:0}
.action form{display:flex;flex-direction:column;gap:12px;align-items:flex-start}.action label{font-weight:600;width:100%}
.action label.check{display:flex;gap:10px;align-items:flex-start;font-weight:400}.action label.check input{margin-top:5px}
.row{display:flex;flex-wrap:wrap;gap:12px;align-items:center}form.inline{flex-direction:row!important;align-items:center!important}
form.inline label{font-weight:400;display:flex;gap:6px;align-items:center;width:auto}form.inline input{width:5em}
.msg{padding:12px 16px;border-radius:8px;margin:0 0 20px;border:1px solid}.msg.bad{border-color:var(--bad);color:var(--bad)}.msg.ok{border-color:var(--ok);color:var(--ok)}
.reset{margin-top:14px;display:flex;gap:12px;align-items:center}.reset small{display:inline}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:8px 24px;margin:0 0 32px}.facts div{display:contents}.facts dt{color:var(--muted)}.facts dd{margin:0}
.empty{background:var(--surface);border:1px dashed var(--line);border-radius:10px;padding:28px}
@media (max-width:760px){.shell{grid-template-columns:1fr}nav.side{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line);padding:16px}
nav.side ul{display:flex;flex-wrap:wrap;gap:4px}nav.side li a{margin:0}nav.side .group{display:none}.pop{margin-bottom:12px}
.field,.action{grid-template-columns:1fr}h1{font-size:28px}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"#;

fn layout(app: &App, l: &Layers, active: &str, title: &str, body: &str) -> String {
    let pop = l.config.population.name.as_deref().unwrap_or("employees");
    let mut nav = String::new();
    let item = |nav: &mut String, href: &str, key: &str, label: &str| {
        let cur = if key == active {
            " aria-current=page"
        } else {
            ""
        };
        let _ = write!(nav, "<li><a href={href}{cur}>{label}</a></li>");
    };
    nav.push_str("<ul>");
    item(&mut nav, "/", "overview", "Overview");
    item(&mut nav, "/run", "run", "Run");
    nav.push_str("</ul><p class=group>Settings</p><ul>");
    for s in SECTIONS {
        item(&mut nav, &format!("/settings/{}", s.slug), s.slug, s.title);
    }
    nav.push_str("</ul><p class=group>Admin</p><ul>");
    item(&mut nav, "/modules", "modules", "Modules");
    item(&mut nav, "/access", "access", "Access log");
    item(&mut nav, "/exceptions", "exceptions", "Exceptions");
    item(&mut nav, "/audit", "audit", "Audit log");
    item(&mut nav, "/gui", "gui", "GUI");
    nav.push_str("</ul>");
    let ro = if app.opts.read_only {
        "<p class=note>Read only</p>"
    } else {
        ""
    };
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
<title>{t} | AFAS to Entra</title><style>{CSS}</style></head><body><div class=shell>\
<nav class=side aria-label=\"Main menu\"><p class=brand>AFAS to Entra</p><p class=pop>Staff category: {pop}</p>{nav}{ro}</nav>\
<main><h1>{t}</h1>{body}</main></div></body></html>",
        t = esc(title),
        pop = esc(pop),
    )
}

fn layout_bare(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>{t}</title><style>{CSS}</style></head>\
<body><main><h1>{t}</h1>{body}</main></body></html>",
        t = esc(title)
    )
}

// ===================================================================== helpers

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

pub fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    let s = String::from_utf8_lossy(body);
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (url_decode(k), url_decode(v))
        })
        .collect()
}

fn form_get<'a>(f: &'a [(String, String)], k: &str) -> Option<&'a str> {
    f.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn text(status: u16, msg: &str) -> Response {
    Response {
        status,
        content_type: "text/plain; charset=utf-8",
        location: None,
        disposition: None,
        set_cookie: None,
        body: msg.as_bytes().to_vec(),
    }
}

fn html(status: u16, body: &str) -> Response {
    Response {
        status,
        content_type: "text/html; charset=utf-8",
        location: None,
        disposition: None,
        set_cookie: None,
        body: body.as_bytes().to_vec(),
    }
}

fn redirect(to: &str) -> Response {
    Response {
        status: 303,
        content_type: "text/plain; charset=utf-8",
        location: Some(to.to_string()),
        disposition: None,
        set_cookie: None,
        body: Vec::new(),
    }
}

/// Short messages after a redirect, via a fixed code in the URL (no free text).
fn flash(query: &str) -> Option<(&'static str, &'static str)> {
    let code = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("m=").or_else(|| kv.strip_prefix("ok=")))?;
    Some(match code {
        "busy" => (
            "bad",
            "A run is already in progress. Wait until it has finished.",
        ),
        "date" => ("bad", "The date must have the form YYYY-MM-DD."),
        "minutes" => ("bad", "The number of minutes must be between 1 and 10080."),
        "1" => ("ok", "Saved. The change applies from the next run."),
        "none" => ("ok", "Nothing changed."),
        "reset" => ("ok", "Reset to the config file."),
        _ => return None,
    })
}

fn flash_html(query: &str) -> String {
    flash(query).map_or_else(String::new, |(tone, m)| {
        format!("<p class=\"msg {tone}\" role=status>{m}</p>")
    })
}

// ===================================================================== server

/// Removes the login link file when the server stops, so an old link is not left behind.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn serve(app: App) -> Result<(), String> {
    let server =
        tiny_http::Server::http(app.opts.listen).map_err(|e| format!("cannot listen: {e}"))?;
    tracing::info!("GUI listening on http://{}", app.opts.listen);
    let _login = if app.opts.trusted_proxy.is_none() {
        let dir = Config::load(&app.opts.config_path)
            .map_err(|e| e.to_string())?
            .state
            .dir;
        let file = dir.join(LOGIN_FILE);
        let url = format!(
            "http://{}/login?token={}\n",
            app.opts.listen, app.login_token
        );
        write_atomic(&file, url.as_bytes()).map_err(|e| e.to_string())?;
        tracing::info!(
            "login link written to {} (readable by this user only)",
            file.display()
        );
        Some(RemoveOnDrop(file))
    } else {
        None
    };
    loop {
        if app.shutdown.load(Ordering::SeqCst) {
            tracing::warn!("GUI turned off or configuration unreadable: server stopping");
            return Ok(());
        }
        let mut req = match server.recv_timeout(Duration::from_secs(2)) {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => return Err(format!("server error: {e}")),
        };
        let method = req.method().as_str().to_string();
        let path = req.url().to_string();
        let remote = req.remote_addr().map(SocketAddr::ip);
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_ascii_lowercase(),
                    h.value.as_str().to_string(),
                )
            })
            .collect();
        let mut body = Vec::new();
        let read_ok = req
            .as_reader()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut body)
            .is_ok();
        let resp = if read_ok {
            handle(
                &app,
                &Request {
                    method: &method,
                    path: &path,
                    remote,
                    headers: &headers,
                    body: &body,
                },
            )
        } else {
            text(400, "Request not readable.")
        };
        let mut out = tiny_http::Response::from_data(resp.body).with_status_code(resp.status);
        let mut hdrs: Vec<(&str, String)> = vec![
            ("Content-Type", resp.content_type.to_string()),
            ("X-Frame-Options", "DENY".into()),
            ("X-Content-Type-Options", "nosniff".into()),
            ("Referrer-Policy", "no-referrer".into()),
            ("Cache-Control", "no-store".into()),
            ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'".into()),
            ("Cross-Origin-Opener-Policy", "same-origin".into()),
            ("Cross-Origin-Resource-Policy", "same-origin".into()),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()".into()),
        ];
        if let Some(loc) = resp.location {
            hdrs.push(("Location", loc));
        }
        if let Some(d) = resp.disposition {
            hdrs.push(("Content-Disposition", d));
        }
        if let Some(c) = resp.set_cookie {
            hdrs.push(("Set-Cookie", c));
        }
        for (k, v) in hdrs {
            if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                out = out.with_header(h);
            }
        }
        if let Err(e) = req.respond(out) {
            tracing::warn!("sending response failed: {e}");
        }
    }
}
