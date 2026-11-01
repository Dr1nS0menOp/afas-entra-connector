// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! `doctor`: checks the whole chain in one go and says how to fix what is wrong.
//!
//! Read-only: it signs in and reads, but never uploads, changes a group, creates a
//! Temporary Access Pass, sends mail or writes state.

use crate::config::{AuthMode, Config};
use crate::entra::{Credential, TokenProvider};
use crate::error::exit;
use crate::graph::{Graph, GraphError};
use crate::http::build_client;
use crate::modules::settings::ModuleIdentity;
use crate::modules::{Ctx, with_graph};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub area: &'static str,
    pub check: String,
    pub level: Level,
    pub detail: String,
    /// What to do about it (warnings and failures).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

pub struct Options<'a> {
    pub sleep: &'a dyn Fn(Duration),
    pub use_system_proxy: bool,
    pub now: DateTime<Utc>,
    /// Runs `systemctl <args>` and returns its trimmed output, or `None` without systemd.
    pub systemctl: &'a dyn Fn(&[&str]) -> Option<String>,
    /// Skip the TLS handshakes (tests against plain-HTTP mocks).
    pub tls: bool,
}

/// `systemctl` on this host; `None` when systemd is not running.
pub fn real_systemctl(args: &[&str]) -> Option<String> {
    if !Path::new("/run/systemd/system").exists() {
        return None;
    }
    let out = std::process::Command::new("systemctl")
        .args(args)
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

struct Out(Vec<Check>);

impl Out {
    fn add(
        &mut self,
        area: &'static str,
        check: impl Into<String>,
        level: Level,
        detail: impl Into<String>,
        fix: Option<String>,
    ) {
        self.0.push(Check {
            area,
            check: check.into(),
            level,
            detail: detail.into(),
            fix,
        });
    }
    fn ok(&mut self, area: &'static str, check: impl Into<String>, detail: impl Into<String>) {
        self.add(area, check, Level::Ok, detail, None);
    }
}

/// Every check, in the order a person would fix them.
pub fn run(cfg: &Config, config_path: &Path, o: &Options<'_>) -> Vec<Check> {
    let mut out = Out(Vec::new());
    out.ok(
        "Configuration",
        "Config file",
        format!("{} is valid", config_path.display()),
    );
    secrets(cfg, &mut out);
    running_user(cfg, &mut out);
    afas(cfg, o, &mut out);
    provisioning(cfg, o, &mut out);
    modules(cfg, o, &mut out);
    certificates(cfg, o, &mut out);
    if o.tls {
        tls(cfg, &mut out);
    }
    schedule(cfg, o, &mut out);
    out.0
}

/// 0 when everything is fine, 3 with warnings only, `exit::DOCTOR` when something fails.
pub fn exit_code(checks: &[Check]) -> i32 {
    if checks.iter().any(|c| c.level == Level::Fail) {
        exit::DOCTOR
    } else if checks.iter().any(|c| c.level == Level::Warn) {
        exit::COMPLETED_WITH_EXCLUSIONS
    } else {
        exit::OK
    }
}

/// Readable output for a terminal.
pub fn render(checks: &[Check]) -> String {
    let mut s = String::new();
    let mut area = "";
    for c in checks {
        if c.area != area {
            area = c.area;
            let _ = writeln!(s, "\n{area}");
        }
        let mark = match c.level {
            Level::Ok => "  ok  ",
            Level::Info => "  --  ",
            Level::Warn => "  WARN",
            Level::Fail => "  FAIL",
        };
        let _ = writeln!(s, "{mark}  {}: {}", c.check, c.detail);
        if let Some(f) = &c.fix {
            for line in f.lines() {
                let _ = writeln!(s, "          → {line}");
            }
        }
    }
    let fails = checks.iter().filter(|c| c.level == Level::Fail).count();
    let warns = checks.iter().filter(|c| c.level == Level::Warn).count();
    let _ = writeln!(
        s,
        "\n{}",
        match (fails, warns) {
            (0, 0) => "Everything checks out.".to_string(),
            (0, w) => format!("{w} warning(s); nothing is broken."),
            (f, w) => format!("{f} problem(s) to fix, {w} warning(s). Fix them top to bottom."),
        }
    );
    s
}

// ------------------------------------------------------------------ secrets and user

fn secrets(cfg: &Config, out: &mut Out) {
    let a = &cfg.afas;
    match (&a.token_file, &a.token_env) {
        (Some(f), _) => match crate::state::check_private_file(f, "AFAS token file") {
            Ok(()) => out.ok(
                "Configuration",
                "AFAS token",
                format!("{} (0600, right owner)", f.display()),
            ),
            Err(e) => out.add(
                "Configuration",
                "AFAS token",
                Level::Fail,
                e.to_string(),
                Some(format!(
                    "sudo chown afas-sync: {0} && sudo chmod 600 {0}",
                    f.display()
                )),
            ),
        },
        (None, Some(v)) => {
            if std::env::var_os(v).is_some_and(|x| !x.is_empty()) {
                out.ok("Configuration", "AFAS token", format!("from ${v}"));
            } else {
                out.add(
                    "Configuration",
                    "AFAS token",
                    Level::Fail,
                    format!("environment variable {v} is not set"),
                    Some(format!("export {v}=… (or use token_file)")),
                );
            }
        }
        (None, None) => {}
    }
    let mut keys: Vec<(String, std::path::PathBuf)> = Vec::new();
    if cfg.entra.auth == AuthMode::Certificate
        && let Some(k) = &cfg.entra.private_key_pem
    {
        keys.push(("provisioning".into(), k.clone()));
    }
    for (name, id) in module_identities(cfg) {
        keys.push((name.to_string(), id.private_key_pem.clone()));
    }
    for (name, k) in keys {
        match crate::state::check_private_file(&k, "private key") {
            Ok(()) => out.ok(
                "Configuration",
                format!("Private key ({name})"),
                format!("{} (0600)", k.display()),
            ),
            Err(e) => out.add(
                "Configuration",
                format!("Private key ({name})"),
                Level::Fail,
                e.to_string(),
                Some(format!(
                    "sudo chown afas-sync: {0} && sudo chmod 600 {0}",
                    k.display()
                )),
            ),
        }
    }
    if cfg.entra.auth == AuthMode::ClientSecret {
        out.add(
            "Configuration",
            "Entra sign-in",
            Level::Warn,
            "client secret instead of a certificate",
            Some("use a certificate in production (install creates one)".into()),
        );
    }
    if let Some(w) = cfg.webhook.as_ref().filter(|w| w.enabled) {
        match crate::modules::webhook::secret(w) {
            Ok(_) => out.ok(
                "Configuration",
                "Webhook secret",
                "present, at least 16 characters",
            ),
            Err(e) => out.add(
                "Configuration",
                "Webhook secret",
                Level::Fail,
                e,
                Some("create one with: openssl rand -hex 32".into()),
            ),
        }
    }
}

fn module_identities(cfg: &Config) -> Vec<(&'static str, ModuleIdentity)> {
    let mut v = Vec::new();
    if let Some(m) = cfg.roles.as_ref().filter(|m| m.enabled) {
        v.push(("roles", m.identity()));
    }
    if let Some(m) = cfg.joiner.as_ref().filter(|m| m.enabled) {
        v.push(("new hires", m.identity()));
    }
    if let Some(m) = cfg.leaver.as_ref().filter(|m| m.enabled) {
        v.push(("departing employees", m.identity()));
    }
    v
}

fn running_user(cfg: &Config, out: &mut Out) {
    let dir = &cfg.state.dir;
    if !dir.is_dir() {
        out.add(
            "Configuration",
            "State directory",
            Level::Fail,
            format!("{} does not exist", dir.display()),
            Some(
                "sudo afas-entra-sync install (or create it, owned by the service user, mode 0700)"
                    .into(),
            ),
        );
        return;
    }
    let args = vec!["afas-entra-sync".to_string(), "sync".into()];
    match crate::ux::check_running_user(cfg, &args) {
        Ok(()) => out.ok(
            "Configuration",
            "State directory",
            format!("{}", dir.display()),
        ),
        Err(_) => out.add(
            "Configuration",
            "Running user",
            Level::Info,
            "running as root: fine for doctor, but run sync and the GUI as the service user",
            None,
        ),
    }
}

// ------------------------------------------------------------------ AFAS

fn afas(cfg: &Config, o: &Options<'_>, out: &mut Out) {
    const A: &str = "AFAS";
    let client = match build_client(cfg.afas.timeout_secs, o.use_system_proxy, &cfg.tls) {
        Ok(c) => c,
        Err(e) => return out.add(A, "Connection", Level::Fail, e, None),
    };
    let auth = match crate::afas::read_token(&cfg.afas).and_then(|t| crate::afas::auth_header(&t)) {
        Ok(a) => a,
        Err(e) => return out.add(A, "Token", Level::Fail, e.to_string(), None),
    };
    match crate::afas::fetch_sample(&cfg.afas, &auth, &client, o.sleep, 5) {
        Err(e) => {
            let msg = e.to_string();
            let fix = if msg.contains("401") || msg.contains("403") {
                "the token is not accepted: create a new one for the app connector (docs/GUIDE.md step 1b) and store it with: sudo afas-entra-sync install --replace-token"
            } else if msg.contains("404") {
                "the GetConnector name is wrong, or it is not in the app connector: check afas.connector"
            } else {
                "check afas.base_url, the network route to AFAS and any proxy"
            };
            out.add(A, "GetConnector", Level::Fail, msg, Some(fix.into()));
        }
        Ok(rows) if rows.is_empty() => out.add(
            A,
            "GetConnector",
            Level::Warn,
            format!("{} answers, but returns no rows", cfg.afas.connector),
            Some("check the GetConnector's filter in AFAS".into()),
        ),
        Ok(rows) => {
            out.ok(
                A,
                "GetConnector",
                format!("{} answers with data", cfg.afas.connector),
            );
            let fields = afas_fields(&rows, cfg);
            let missing: Vec<&FieldInfo> = fields
                .iter()
                .filter(|f| f.mapped_to.is_some() && !f.present)
                .collect();
            if missing.is_empty() {
                out.ok(
                    A,
                    "Field mapping",
                    "every mapped field is in the GetConnector",
                );
            } else {
                out.add(
                    A,
                    "Field mapping",
                    Level::Fail,
                    format!(
                        "missing in the GetConnector: {}",
                        missing
                            .iter()
                            .map(|f| format!("{} ({})", f.field, f.mapped_to.as_deref().unwrap_or("")))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    Some("add the field to the GetConnector, or correct [afas.fields]; afas-entra-sync afas-fields lists what is there".into()),
                );
            }
            // A sample of rows through the real validation.
            let bad = rows
                .iter()
                .filter(|r| crate::model::parse_row(r, &cfg.afas.fields).is_err())
                .count();
            if bad > 0 && missing.is_empty() {
                out.add(
                    A,
                    "Sample records",
                    Level::Warn,
                    format!("{bad} of the first {} rows have a data error", rows.len()),
                    Some("run a test run (sync) to see which and why".into()),
                );
            }
        }
    }
}

/// Rows taken for `afas-fields`: enough to see each field filled at least once.
pub const FIELD_SAMPLE: usize = 50;

/// `afas-fields`: what the GetConnector offers next to the mapping.
pub fn fields_report(
    cfg: &Config,
    sleep: &dyn Fn(Duration),
    use_system_proxy: bool,
) -> Result<Vec<FieldInfo>, String> {
    let client = build_client(cfg.afas.timeout_secs, use_system_proxy, &cfg.tls)?;
    let auth = crate::afas::read_token(&cfg.afas)
        .and_then(|t| crate::afas::auth_header(&t))
        .map_err(|e| e.to_string())?;
    let rows = crate::afas::fetch_sample(&cfg.afas, &auth, &client, sleep, FIELD_SAMPLE)
        .map_err(|e| e.to_string())?;
    if rows.is_empty() {
        return Err(format!(
            "{} returns no rows; check its filter in AFAS",
            cfg.afas.connector
        ));
    }
    Ok(afas_fields(&rows, cfg))
}

/// Table for a terminal.
pub fn render_fields(fields: &[FieldInfo]) -> String {
    let w = fields
        .iter()
        .map(|f| f.field.chars().count())
        .max()
        .unwrap_or(5)
        .max(5);
    let k = fields
        .iter()
        .map(|f| f.kind.chars().count())
        .max()
        .unwrap_or(4)
        .max(4);
    let mut s = format!("{:<w$}  {:<k$}  Used for\n", "Field", "Data");
    for f in fields.iter().filter(|f| f.present) {
        let _ = writeln!(
            s,
            "{:<w$}  {:<k$}  {}",
            f.field,
            f.kind,
            f.mapped_to.as_deref().unwrap_or("-")
        );
    }
    let missing: Vec<&FieldInfo> = fields.iter().filter(|f| !f.present).collect();
    if !missing.is_empty() {
        s.push_str("\nMissing: these settings point to a field the GetConnector does not return\n");
        for f in missing {
            let _ = writeln!(
                s,
                "  {} = \"{}\"",
                f.mapped_to.as_deref().unwrap_or(""),
                f.field
            );
        }
        s.push_str("Add the field to the GetConnector in AFAS, or correct the setting.\n");
    }
    s
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldInfo {
    /// Field name in the GetConnector.
    pub field: String,
    /// Kind of values seen (text, number, date, empty, ...). Never the values.
    pub kind: String,
    /// The setting it is mapped to, e.g. `afas.fields.upn`.
    pub mapped_to: Option<String>,
    /// Present in the GetConnector's rows.
    pub present: bool,
}

/// GetConnector fields next to the configured mapping. Shows the kind of data, never
/// values, so it is safe to paste in a ticket.
pub fn afas_fields(
    rows: &[serde_json::Map<String, serde_json::Value>],
    cfg: &Config,
) -> Vec<FieldInfo> {
    use serde_json::Value;
    let f = &cfg.afas.fields;
    let mut mapping: Vec<(String, String)> = vec![
        ("employee_id".into(), f.employee_id.clone()),
        ("given_name".into(), f.given_name.clone()),
        ("family_name".into(), f.family_name.clone()),
        ("upn".into(), f.upn.clone()),
        ("start_date".into(), f.start_date.clone()),
        ("end_date".into(), f.end_date.clone()),
    ];
    for (k, v) in [
        ("name_prefix", &f.name_prefix),
        ("display_name", &f.display_name),
        ("email", &f.email),
        ("job_title", &f.job_title),
        ("department", &f.department),
        ("manager_id", &f.manager_id),
        ("cost_center", &f.cost_center),
    ] {
        if let Some(v) = v {
            mapping.push((k.into(), v.clone()));
        }
    }
    for name in crate::config::TOGGLE_NAMES {
        if let Some(Some(t)) = f.extra.toggle(name)
            && t.enabled
        {
            mapping.push((format!("extra.{name}"), t.field.clone()));
        }
    }
    let mut seen: Vec<String> = Vec::new();
    for r in rows {
        for k in r.keys() {
            if !seen.contains(k) {
                seen.push(k.clone());
            }
        }
    }
    let kind = |name: &str| -> String {
        let mut kinds: Vec<&str> = rows
            .iter()
            .filter_map(|r| r.get(name))
            .map(|v| match v {
                Value::Null => "empty",
                Value::Bool(_) => "yes/no",
                Value::Number(_) => "number",
                Value::String(s) if s.is_empty() => "empty",
                Value::String(s) if crate::model::parse_afas_date(s).is_ok() => "date",
                Value::String(s) if s.contains('@') => "text with @",
                Value::String(_) => "text",
                Value::Array(_) => "list",
                Value::Object(_) => "object",
            })
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        kinds.join(" or ")
    };
    let mut out: Vec<FieldInfo> = seen
        .iter()
        .map(|field| FieldInfo {
            field: field.clone(),
            kind: kind(field),
            mapped_to: mapping
                .iter()
                .find(|(_, v)| v == field)
                .map(|(k, _)| format!("afas.fields.{k}")),
            present: true,
        })
        .collect();
    for (k, v) in &mapping {
        if !seen.contains(v) {
            out.push(FieldInfo {
                field: v.clone(),
                kind: String::new(),
                mapped_to: Some(format!("afas.fields.{k}")),
                present: false,
            });
        }
    }
    out
}

// ------------------------------------------------------------------ Entra and Graph

fn entra_fix(msg: &str) -> Option<String> {
    let s = if msg.contains("AADSTS700027") {
        "Entra does not know this certificate: upload the certificate file to the app registration (Certificates & secrets)"
    } else if msg.contains("AADSTS700016") {
        "no such app in this tenant: check client_id and tenant_id"
    } else if msg.contains("AADSTS90002") || msg.contains("AADSTS900023") {
        "tenant not found: check tenant_id"
    } else if msg.contains("AADSTS7000222") || msg.contains("AADSTS7000215") {
        "the client secret is expired or wrong: create a new one, or switch to a certificate"
    } else if msg.contains("AADSTS700024") {
        "the clock of this server is off: enable NTP (timedatectl set-ntp true)"
    } else if msg.contains("AADSTS7000112") {
        "the application is disabled in Entra"
    } else {
        return None;
    };
    Some(s.into())
}

fn graph_problem(e: &GraphError, permission: &str, app: &str) -> (Level, String, Option<String>) {
    match e.status {
        Some(401 | 403) => (
            Level::Fail,
            format!("refused (HTTP {}): {}", e.status.unwrap_or(0), e.message),
            Some(format!(
                "grant the application permission {permission} to the {app} app registration and click 'Grant admin consent'"
            )),
        ),
        None if e.message.starts_with("token:") => {
            (Level::Fail, e.message.clone(), entra_fix(&e.message))
        }
        _ => (Level::Fail, e.to_string(), None),
    }
}

fn provisioning(cfg: &Config, o: &Options<'_>, out: &mut Out) {
    const A: &str = "Entra provisioning";
    let client = match build_client(cfg.entra.timeout_secs, o.use_system_proxy, &cfg.tls) {
        Ok(c) => c,
        Err(e) => return out.add(A, "Connection", Level::Fail, e, None),
    };
    let cred = match Credential::from_config(&cfg.entra) {
        Ok(c) => c,
        Err(e) => return out.add(A, "Sign-in", Level::Fail, e.to_string(), None),
    };
    let tokens = TokenProvider::new(&cfg.entra, &client, cred, o.sleep);
    if let Err(e) = tokens.get(false) {
        let msg = e.to_string();
        return out.add(A, "Sign-in", Level::Fail, msg.clone(), entra_fix(&msg));
    }
    out.ok(
        A,
        "Sign-in",
        format!("app {} signs in", cfg.entra.client_id),
    );
    let g = match Graph::new(&cfg.entra.graph_base, &client, tokens, o.sleep) {
        Ok(g) => g,
        Err(e) => return out.add(A, "Graph", Level::Fail, e, None),
    };
    match g.get("auditLogs/provisioning?$top=1") {
        Ok(_) => out.ok(
            A,
            "Provisioning logs",
            "readable (ProvisioningLog.Read.All)",
        ),
        Err(e) => {
            let (l, d, f) = graph_problem(&e, "ProvisioningLog.Read.All", "provisioning");
            out.add(A, "Provisioning logs", l, d, f);
        }
    }
    out.add(
        A,
        "Upload permission",
        Level::Info,
        "SynchronizationData-User.Upload is only tested by a real upload (sync --apply); a 403 there means it is missing",
        None,
    );
}

fn modules(cfg: &Config, o: &Options<'_>, out: &mut Out) {
    let ctx = Ctx {
        cfg,
        people: &[],
        today: o.now.date_naive(),
        apply: false,
        use_system_proxy: o.use_system_proxy,
        sleep: o.sleep,
        state_dir: &cfg.state.dir,
        actor: "doctor",
    };
    if let Some(r) = cfg.roles.as_ref().filter(|r| r.enabled) {
        const A: &str = "Module: roles and licences";
        let res = with_graph(&ctx, &r.identity(), |g| {
            let mut rows = Vec::new();
            let mut ids: Vec<&str> = r.rules.iter().map(|x| x.group_id.as_str()).collect();
            ids.sort_unstable();
            ids.dedup();
            for id in ids {
                let Ok(seg) = crate::graph::seg(id) else {
                    continue;
                };
                let path = format!(
                    "groups/{seg}?$select=id,displayName,isAssignableToRole,onPremisesSyncEnabled,groupTypes"
                );
                rows.push(match g.get(&path) {
                    Ok(v) => match crate::modules::roles::check_group(&v, &r.group_prefix) {
                        Ok(name) => (
                            format!("Group {name}"),
                            Level::Ok,
                            "can be managed".to_string(),
                            None,
                        ),
                        Err(e) => (
                            format!("Group {id}"),
                            Level::Fail,
                            e,
                            Some(
                                "use a cloud security group whose name starts with the prefix"
                                    .into(),
                            ),
                        ),
                    },
                    Err(e) if e.status == Some(404) => (
                        format!("Group {id}"),
                        Level::Fail,
                        "does not exist".to_string(),
                        Some("check group_id in [[roles.rule]]".into()),
                    ),
                    Err(e) => {
                        let (l, d, f) = graph_problem(&e, "GroupMember.ReadWrite.All", "roles");
                        (format!("Group {id}"), l, d, f)
                    }
                });
            }
            rows
        });
        report_module(out, A, res);
    }
    if let Some(j) = cfg.joiner.as_ref().filter(|j| j.enabled) {
        const A: &str = "Module: new hires";
        let res = with_graph(&ctx, &j.identity(), |g| {
            let mut rows = Vec::new();
            let first = match g.get("users?$top=1&$select=id") {
                Ok(v) => {
                    rows.push((
                        "Read users".into(),
                        Level::Ok,
                        "User.Read.All granted".into(),
                        None,
                    ));
                    v["value"][0]["id"].as_str().map(str::to_string)
                }
                Err(e) => {
                    let (l, d, f) = graph_problem(&e, "User.Read.All", "new hires");
                    rows.push(("Read users".into(), l, d, f));
                    None
                }
            };
            match crate::modules::joiner::mailbox(&j.sender)
                .and_then(|m| g.get(&format!("users/{m}?$select=id")))
            {
                Ok(_) => rows.push(("Sender mailbox".into(), Level::Ok, j.sender.clone(), None)),
                Err(e) if e.status == Some(404) => rows.push((
                    "Sender mailbox".into(),
                    Level::Fail,
                    format!("{} does not exist", j.sender),
                    Some("create the mailbox or correct joiner.sender".into()),
                )),
                Err(e) => {
                    let (l, d, f) = graph_problem(&e, "User.Read.All", "new hires");
                    rows.push(("Sender mailbox".into(), l, d, f));
                }
            }
            if let Some(Ok(uid)) = first.as_deref().map(crate::graph::seg) {
                match g.get(&format!(
                    "users/{uid}/authentication/temporaryAccessPassMethods"
                )) {
                    Ok(_) => rows.push((
                        "Temporary Access Pass".into(),
                        Level::Ok,
                        "UserAuthMethod-TAP.ReadWrite.All granted".into(),
                        None,
                    )),
                    Err(e) => {
                        let (l, d, f) =
                            graph_problem(&e, "UserAuthMethod-TAP.ReadWrite.All", "new hires");
                        rows.push(("Temporary Access Pass".into(), l, d, f));
                    }
                }
            }
            rows.push((
                "Sending mail".into(),
                Level::Info,
                "Mail.Send is only tested by the first real mail; check the Exchange scope with Test-ServicePrincipalAuthorization (docs/MODULES.md)".into(),
                None,
            ));
            rows
        });
        report_module(out, A, res);
    }
    if let Some(l) = cfg.leaver.as_ref().filter(|l| l.enabled) {
        const A: &str = "Module: departing employees";
        let res = with_graph(&ctx, &l.identity(), |g| {
            let mut rows = Vec::new();
            match g.get("users?$top=1&$select=id") {
                Ok(v) => {
                    rows.push((
                        "Read users".into(),
                        Level::Ok,
                        "User.Read.All granted".into(),
                        None,
                    ));
                    if l.auto_reply.is_some()
                        && let Some(Ok(uid)) = v["value"][0]["id"].as_str().map(crate::graph::seg)
                    {
                        match g.get(&format!(
                            "users/{uid}/mailboxSettings/automaticRepliesSetting"
                        )) {
                            Ok(_) => rows.push((
                                "Automatic reply".into(),
                                Level::Ok,
                                "MailboxSettings.ReadWrite granted".into(),
                                None,
                            )),
                            Err(e)
                                if e.status == Some(404)
                                    || e.code.contains("MailboxNotEnabled") =>
                            {
                                rows.push((
                                    "Automatic reply".into(),
                                    Level::Info,
                                    "the sample user has no mailbox; permission not verified"
                                        .into(),
                                    None,
                                ))
                            }
                            Err(e) => {
                                let (lv, d, f) = graph_problem(
                                    &e,
                                    "MailboxSettings.ReadWrite",
                                    "departing employees",
                                );
                                rows.push(("Automatic reply".into(), lv, d, f));
                            }
                        }
                    }
                }
                Err(e) => {
                    let (lv, d, f) = graph_problem(&e, "User.Read.All", "departing employees");
                    rows.push(("Read users".into(), lv, d, f));
                }
            }
            if l.revoke_sessions {
                rows.push((
                    "Sign out everywhere".into(),
                    Level::Info,
                    "User.RevokeSessions.All is only tested by the first real departure".into(),
                    None,
                ));
            }
            rows
        });
        report_module(out, A, res);
    }
}

type Row = (String, Level, String, Option<String>);

fn report_module(out: &mut Out, area: &'static str, res: Result<Vec<Row>, String>) {
    match res {
        Err(e) => out.add(area, "Sign-in", Level::Fail, e.clone(), entra_fix(&e)),
        Ok(rows) => {
            // A failed sign-in shows up on every call: report it once.
            if let Some((_, _, d, f)) = rows.iter().find(|r| r.2.starts_with("token:")) {
                return out.add(area, "Sign-in", Level::Fail, d.clone(), f.clone());
            }
            out.ok(area, "Sign-in", "the module's app registration signs in");
            for (c, l, d, f) in rows {
                out.add(area, c, l, d, f);
            }
        }
    }
}

// ------------------------------------------------------------------ certificates, TLS, schedule

fn certificates(cfg: &Config, o: &Options<'_>, out: &mut Out) {
    const A: &str = "Certificates";
    for c in crate::ux::certificates(cfg, o.now) {
        let name = capitalise(&format!("{} app", c.app));
        let renew = if c.app == "provisioning" {
            "sudo afas-entra-sync install --renew-cert, then upload the new cert.pem to the app registration".to_string()
        } else {
            format!(
                "sudo afas-entra-sync module-setup {} --renew, then upload the new certificate",
                module_key(&c.app)
            )
        };
        match (&c.expires, c.days_left) {
            (Err(e), _) => out.add(
                A,
                name,
                Level::Fail,
                format!("{}: {e}", c.path.display()),
                None,
            ),
            (Ok(d), Some(n)) if n < 0 => {
                out.add(A, name, Level::Fail, format!("expired on {d}"), Some(renew))
            }
            (Ok(d), Some(n)) if n <= crate::ux::CERT_WARN_DAYS => {
                out.add(
                    A,
                    name,
                    Level::Warn,
                    format!("expires on {d}, in {n} days"),
                    Some(renew),
                );
            }
            (Ok(d), Some(n)) => out.ok(A, name, format!("valid until {d} ({n} days)")),
            (Ok(d), None) => out.ok(A, name, format!("valid until {d}")),
        }
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

fn module_key(app: &str) -> &'static str {
    match app {
        "roles" => "roles",
        "new hires" => "joiner",
        _ => "leaver",
    }
}

fn tls(cfg: &Config, out: &mut Out) {
    const A: &str = "TLS";
    let tls_cfg = match crate::tls::client_config(&cfg.tls) {
        Ok(c) => std::sync::Arc::new(c),
        Err(e) => return out.add(A, "Policy", Level::Fail, e, None),
    };
    for (name, url) in [
        ("AFAS", cfg.afas.base_url.as_str()),
        ("Entra login", cfg.entra.authority.as_str()),
        ("Microsoft Graph", cfg.entra.graph_base.as_str()),
    ] {
        let Ok(u) = reqwest::Url::parse(url) else {
            continue;
        };
        if u.scheme() != "https" {
            out.add(
                A,
                name,
                Level::Warn,
                format!("{url} is not HTTPS"),
                Some("use the https:// address".into()),
            );
            continue;
        }
        let (Some(host), Some(port)) = (u.host_str(), u.port_or_known_default()) else {
            continue;
        };
        let p = crate::tls::probe(
            name,
            host,
            port,
            crate::tls::proxy_for(host).as_deref(),
            tls_cfg.clone(),
            Duration::from_secs(20),
        );
        if p.ok {
            let kx = p.key_exchange.clone().unwrap_or_default();
            let detail = format!("{} with {kx}", p.protocol.clone().unwrap_or_default());
            if p.post_quantum {
                out.ok(A, name, detail);
            } else {
                out.add(
                    A,
                    name,
                    Level::Info,
                    format!("{detail} (no post-quantum key exchange)"),
                    None,
                );
            }
        } else {
            out.add(
                A,
                name,
                Level::Fail,
                p.error.unwrap_or_default(),
                Some("a TLS-inspecting proxy or firewall in between? exclude this host, or see SECURITY.md".into()),
            );
        }
    }
}

fn schedule(cfg: &Config, o: &Options<'_>, out: &mut Out) {
    const A: &str = "Schedule and last run";
    match (o.systemctl)(&["is-enabled", "afas-entra-sync.timer"]) {
        None => out.add(
            A,
            "Timer",
            Level::Info,
            "no systemd here; schedule with your own scheduler",
            None,
        ),
        Some(s) if s == "enabled" => out.ok(A, "Timer", "hourly sync is enabled"),
        Some(s) => out.add(
            A,
            "Timer",
            Level::Warn,
            format!("hourly sync is not enabled ({s})"),
            Some("after a good test run: sudo afas-entra-sync install --enable-sync".into()),
        ),
    }
    let path = cfg.state.dir.join(crate::state::REPORT_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return out.add(
            A,
            "Last run",
            Level::Info,
            "no run yet",
            Some("start with a test run: afas-entra-sync sync".into()),
        );
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    let code = v["exit_code"].as_i64().unwrap_or(-1);
    let when = v["started_utc"].as_str().unwrap_or("?");
    let age_h = DateTime::parse_from_rfc3339(when)
        .map(|t| (o.now - t.with_timezone(&Utc)).num_hours())
        .unwrap_or(0);
    let mode = v["mode"].as_str().unwrap_or("?");
    let detail = format!(
        "{mode} {when}, exit {code}: {}",
        v["result"].as_str().unwrap_or("")
    );
    match code {
        0 | 3 => out.ok(A, "Last run", detail),
        20 | 21 => out.add(
            A,
            "Last run",
            Level::Warn,
            detail,
            Some("a safety threshold stopped it: read the report (sync shows it)".into()),
        ),
        _ => out.add(
            A,
            "Last run",
            Level::Fail,
            detail,
            Some("run afas-entra-sync sync to see the cause".into()),
        ),
    }
    if age_h > 3 && mode == "apply" {
        out.add(
            A,
            "Freshness",
            Level::Warn,
            format!("the last applied run was {age_h} hours ago"),
            Some("check the timer: systemctl status afas-entra-sync.timer".into()),
        );
    }
}
