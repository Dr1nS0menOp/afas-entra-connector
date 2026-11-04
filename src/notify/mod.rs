// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Notifications by email (Microsoft Graph), Microsoft Teams, Slack and plain webhooks.
//!
//! After every scheduled sync and `check-logs`, the tool works out what people have to
//! decide or do (see [`findings`]) and sends it to each channel that wants it:
//!
//! - a failure is sent once, then again only when it changes or after `repeat_hours`;
//! - points of attention are sent when there is something new, and repeated while open
//!   after `repeat_hours`;
//! - when things are fine again, "recovered" / "all clear" is sent once.
//!
//! What was sent per channel is kept in `notify-state.json` (hashes only). Test runs only
//! notify with `--notify`, and never change that state.

pub mod findings;
pub mod render;

use crate::config::{AuthMode, Config};
use crate::entra::LogSummary;
use crate::http::{MAX_SMALL_BODY, build_client, read_capped, snippet};
use crate::state::write_atomic;
use findings::{Audience, Finding, Severity};
use render::{Event, Message};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const NOTIFY_STATE_FILE: &str = "notify-state.json";
const NOTIFY_STATE_VERSION: u32 = 1;

fn yes() -> bool {
    true
}
fn default_on() -> Vec<Trigger> {
    vec![Trigger::Failure, Trigger::Attention, Trigger::Recovered]
}
fn default_repeat() -> u32 {
    24
}
fn default_timeout() -> u64 {
    15
}

/// When a channel gets a message.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    /// The run failed or a safety threshold stopped it.
    Failure,
    /// Things people have to decide or do.
    Attention,
    /// Works again / all clear.
    Recovered,
    /// Every successful run (noisy; for a log channel).
    Success,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PersonalData {
    /// Employee numbers only (the default): HR looks the people up in AFAS.
    #[default]
    Numbers,
    /// Also names, sign-in names and email addresses of the employees involved.
    Names,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Email,
    Teams,
    Slack,
    Webhook,
}

impl ChannelKind {
    fn label(self) -> &'static str {
        match self {
            ChannelKind::Email => "email",
            ChannelKind::Teams => "teams",
            ChannelKind::Slack => "slack",
            ChannelKind::Webhook => "webhook",
        }
    }
}

/// `[notify]`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Default triggers for every channel.
    #[serde(default = "default_on")]
    pub on: Vec<Trigger>,
    /// Repeat unchanged open points after this many hours (0 = never).
    #[serde(default = "default_repeat")]
    pub repeat_hours: u32,
    /// Default for every channel.
    #[serde(default)]
    pub personal_data: PersonalData,
    /// Link to the admin GUI in messages.
    #[serde(default)]
    pub gui_url: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// The mailbox and app registration email is sent with.
    #[serde(default)]
    pub email: Option<EmailSender>,
    #[serde(default, rename = "channel")]
    pub channels: Vec<Channel>,
}

/// `[notify.email]`: email goes out through Microsoft Graph (`Mail.Send`, limited to the
/// sender mailbox with Exchange RBAC for Applications).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmailSender {
    pub client_id: String,
    pub certificate_pem: PathBuf,
    pub private_key_pem: PathBuf,
    pub sender: String,
}

impl EmailSender {
    pub fn identity(&self) -> crate::modules::settings::ModuleIdentity {
        crate::modules::settings::ModuleIdentity {
            client_id: self.client_id.clone(),
            certificate_pem: self.certificate_pem.clone(),
            private_key_pem: self.private_key_pem.clone(),
        }
    }
}

/// `[[notify.channel]]`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    pub kind: ChannelKind,
    /// Name in messages and in the state (default: kind and position).
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Email: recipients.
    #[serde(default)]
    pub to: Vec<String>,
    /// Webhook only: the URL in the config. Teams and Slack URLs work as a password, so
    /// they come from `url_env` or `url_file` (mode 0600).
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub url_env: Option<String>,
    #[serde(default)]
    pub url_file: Option<PathBuf>,
    /// Webhook: HMAC-SHA256 secret (at least 16 characters).
    #[serde(default)]
    pub secret_env: Option<String>,
    #[serde(default)]
    pub secret_file: Option<PathBuf>,
    /// Only findings for these groups ("it", "hr"); empty = all. Failures always go.
    #[serde(default)]
    pub audience: Vec<Audience>,
    /// Overrides `[notify] on`.
    #[serde(default)]
    pub on: Option<Vec<Trigger>>,
    /// Overrides `[notify] personal_data`.
    #[serde(default)]
    pub personal_data: Option<PersonalData>,
}

impl Channel {
    /// Stable id: the name, else kind and position.
    pub fn id(&self, index: usize) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{}-{}", self.kind.label(), index + 1))
    }

    fn triggers<'a>(&'a self, cfg: &'a NotifyConfig) -> &'a [Trigger] {
        self.on.as_deref().unwrap_or(&cfg.on)
    }

    fn names(&self, cfg: &NotifyConfig) -> bool {
        self.personal_data.unwrap_or(cfg.personal_data) == PersonalData::Names
    }
}

fn local_url(u: &str) -> bool {
    u.starts_with("http://127.0.0.1:") || u.starts_with("http://localhost:")
}

impl NotifyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.channels.iter().all(|c| !c.enabled) {
            return Err(
                "notify: add at least one [[notify.channel]] (or set notify.enabled = false)"
                    .into(),
            );
        }
        if self.repeat_hours > 720 {
            return Err("notify.repeat_hours can be at most 720 (30 days)".into());
        }
        if !(1..=120).contains(&self.timeout_secs) {
            return Err("notify.timeout_secs must be 1 to 120".into());
        }
        if let Some(u) = &self.gui_url
            && !(u.starts_with("https://") || local_url(u))
        {
            return Err("notify.gui_url must start with https://".into());
        }
        if let Some(e) = &self.email {
            if !crate::config::is_guid(&e.client_id) {
                return Err("notify.email.client_id is not a GUID".into());
            }
            if !crate::modules::settings::is_email(&e.sender)
                || e.sender.contains(['/', '?', '#', '%', '\\'])
            {
                return Err("notify.email.sender must be a mailbox address".into());
            }
        }
        let mut ids = BTreeSet::new();
        for (i, c) in self.channels.iter().enumerate() {
            let id = c.id(i);
            let n = format!("notify channel '{id}'");
            if !ids.insert(id.clone()) {
                return Err(format!("{n}: two channels have the same name"));
            }
            if c.on.as_ref().is_some_and(Vec::is_empty) {
                return Err(format!("{n}: on cannot be empty"));
            }
            let url_sources = [c.url.is_some(), c.url_env.is_some(), c.url_file.is_some()]
                .iter()
                .filter(|x| **x)
                .count();
            match c.kind {
                ChannelKind::Email => {
                    if self.email.is_none() {
                        return Err(format!(
                            "{n}: email needs a [notify.email] section (sender and app registration)"
                        ));
                    }
                    if c.to.is_empty() {
                        return Err(format!("{n}: to needs at least one address"));
                    }
                    if let Some(bad) = c.to.iter().find(|a| !crate::modules::settings::is_email(a))
                    {
                        return Err(format!("{n}: '{bad}' is not an email address"));
                    }
                    if url_sources > 0 || c.secret_env.is_some() || c.secret_file.is_some() {
                        return Err(format!("{n}: email takes no url or secret"));
                    }
                }
                ChannelKind::Teams | ChannelKind::Slack => {
                    if c.url.is_some() {
                        return Err(format!(
                            "{n}: the {} URL works as a password; put it in url_env or url_file (mode 0600), not in the config",
                            c.kind.label()
                        ));
                    }
                    if url_sources != 1 {
                        return Err(format!("{n}: set url_env or url_file"));
                    }
                    if !c.to.is_empty() || c.secret_env.is_some() || c.secret_file.is_some() {
                        return Err(format!("{n}: {} takes no to or secret", c.kind.label()));
                    }
                }
                ChannelKind::Webhook => {
                    if url_sources != 1 {
                        return Err(format!("{n}: set exactly one of url, url_env or url_file"));
                    }
                    if let Some(u) = &c.url {
                        check_url(c.kind, u).map_err(|e| format!("{n}: {e}"))?;
                    }
                    match (&c.secret_env, &c.secret_file) {
                        (Some(_), Some(_)) => {
                            return Err(format!("{n}: use secret_env or secret_file, not both"));
                        }
                        (None, None) => {
                            return Err(format!(
                                "{n}: a secret (secret_env or secret_file) is required to sign the messages"
                            ));
                        }
                        _ => {}
                    }
                    if !c.to.is_empty() {
                        return Err(format!("{n}: webhook takes no to"));
                    }
                }
            }
        }
        Ok(())
    }
}

/// The URL must be HTTPS (Slack: Slack's own webhook host).
pub fn check_url(kind: ChannelKind, u: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(u).map_err(|_| "the URL is not valid".to_string())?;
    if parsed.scheme() != "https" && !local_url(u) {
        return Err("the URL must start with https://".into());
    }
    if kind == ChannelKind::Slack && parsed.host_str() != Some("hooks.slack.com") && !local_url(u) {
        return Err("a Slack incoming webhook URL starts with https://hooks.slack.com/".into());
    }
    Ok(())
}

fn read_secret(env: &Option<String>, file: &Option<PathBuf>, what: &str) -> Result<String, String> {
    let v = if let Some(var) = env {
        std::env::var(var).map_err(|_| format!("environment variable {var} ({what}) is not set"))?
    } else if let Some(f) = file {
        crate::state::check_private_file(f, what).map_err(|e| e.to_string())?;
        std::fs::read_to_string(f).map_err(|e| format!("{what}: {e}"))?
    } else {
        return Err(format!("no {what} configured"));
    };
    let v = v.trim().to_string();
    if v.is_empty() {
        return Err(format!("{what} is empty"));
    }
    Ok(v)
}

/// The URL a Teams, Slack or webhook channel posts to.
pub fn channel_url(c: &Channel) -> Result<String, String> {
    let u = match &c.url {
        Some(u) => u.clone(),
        None => read_secret(&c.url_env, &c.url_file, &format!("{} URL", c.kind.label()))?,
    };
    check_url(c.kind, &u)?;
    Ok(u)
}

// ------------------------------------------------------------------ state

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    #[default]
    Ok,
    Attention,
    Failure,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelState {
    pub last_outcome: Outcome,
    #[serde(default)]
    pub last_sent_utc: Option<String>,
    /// First failed run of the current failure streak.
    #[serde(default)]
    pub failing_since_utc: Option<String>,
    #[serde(default)]
    pub failed_runs: u32,
    /// Hash of the failure last reported.
    #[serde(default)]
    pub failure_key: Option<String>,
    /// Title of the failure last reported (for "recovered").
    #[serde(default)]
    pub failure_title: Option<String>,
    /// Hashes of the open points already reported.
    #[serde(default)]
    pub open: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NotifyState {
    pub version: u32,
    #[serde(default)]
    pub channels: BTreeMap<String, ChannelState>,
}

pub fn load_state(dir: &Path) -> Result<NotifyState, String> {
    let path = dir.join(NOTIFY_STATE_FILE);
    match std::fs::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(NotifyState {
            version: NOTIFY_STATE_VERSION,
            ..Default::default()
        }),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        Ok(t) => serde_json::from_str(&t).map_err(|e| {
            format!(
                "{} is corrupt ({e}); delete it to start over (the next messages then count as new)",
                path.display()
            )
        }),
    }
}

fn save_state(dir: &Path, s: &NotifyState) -> Result<(), String> {
    let j = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    write_atomic(&dir.join(NOTIFY_STATE_FILE), &j).map_err(|e| e.to_string())
}

/// Short hash of a finding key (the state holds no employee numbers).
pub fn hash(key: &str) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(key.as_bytes());
    d.iter().take(10).map(|b| format!("{b:02x}")).collect()
}

/// What to send on one channel, given what was sent before. Pure: decides only.
pub fn decide(
    st: &ChannelState,
    outcome: Outcome,
    findings: &mut [Finding],
    triggers: &[Trigger],
    repeat_hours: u32,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Event> {
    let due = st
        .last_sent_utc
        .as_deref()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .is_none_or(|t| {
            repeat_hours > 0
                && now - t.with_timezone(&chrono::Utc)
                    >= chrono::Duration::hours(i64::from(repeat_hours))
        });
    for f in findings.iter_mut() {
        f.new = !st.open.contains(&hash(&f.key));
    }
    let any_new = findings.iter().any(|f| f.new);
    let has = |t: Trigger| triggers.contains(&t);
    match outcome {
        Outcome::Failure => {
            if !has(Trigger::Failure) {
                return None;
            }
            let key = failure_key(findings);
            let changed = st.last_outcome != Outcome::Failure
                || st.failure_key.as_deref() != Some(key.as_str());
            (changed || (st.last_outcome == Outcome::Failure && due)).then_some(Event::Failure)
        }
        Outcome::Attention => {
            if st.last_outcome == Outcome::Failure && has(Trigger::Recovered) {
                Some(Event::Recovered)
            } else if has(Trigger::Attention)
                && (any_new || st.last_outcome != Outcome::Attention || due)
            {
                Some(Event::Attention)
            } else {
                None
            }
        }
        Outcome::Ok => {
            if st.last_outcome == Outcome::Failure && has(Trigger::Recovered) {
                Some(Event::Recovered)
            } else if st.last_outcome == Outcome::Attention && has(Trigger::Recovered) {
                Some(Event::AllClear)
            } else if has(Trigger::Success) {
                Some(Event::Success)
            } else {
                None
            }
        }
    }
}

fn failure_key(findings: &[Finding]) -> String {
    let mut keys: Vec<&str> = findings
        .iter()
        .filter(|f| f.severity == Severity::Failure)
        .map(|f| f.key.as_str())
        .collect();
    keys.sort_unstable();
    hash(&keys.join("|"))
}

/// The state after a decision (sent or not).
fn next_state(
    st: &ChannelState,
    outcome: Outcome,
    findings: &[Finding],
    sent: bool,
    now: &str,
) -> ChannelState {
    let current: BTreeSet<String> = findings.iter().map(|f| hash(&f.key)).collect();
    let mut n = st.clone();
    if sent {
        n.last_sent_utc = Some(now.to_string());
        n.open = current;
    } else {
        // Forget what was resolved, so it counts as new if it ever comes back.
        n.open = st.open.intersection(&current).cloned().collect();
    }
    match outcome {
        Outcome::Failure => {
            if st.last_outcome != Outcome::Failure {
                n.failing_since_utc = Some(now.to_string());
                n.failed_runs = 0;
            }
            n.failed_runs += 1;
            if sent {
                n.failure_key = Some(failure_key(findings));
                n.failure_title = findings
                    .iter()
                    .find(|f| f.severity == Severity::Failure)
                    .map(|f| f.title.clone());
            }
        }
        _ => {
            n.failing_since_utc = None;
            n.failed_runs = 0;
            n.failure_key = None;
        }
    }
    n.last_outcome = outcome;
    n
}

// ------------------------------------------------------------------ what happened

/// The result of `check-logs`, also written to `last-check-logs.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckLogsReport {
    pub checked_utc: String,
    pub since_utc: String,
    #[serde(default)]
    pub summary: Option<LogSummary>,
    /// Things that look wrong without being failures (e.g. nothing processed).
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// Start of the last sync that uploaded something.
    #[serde(default)]
    pub last_upload_utc: Option<String>,
    pub exit_code: i32,
}

/// One delivery attempt, for the report.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Delivery {
    pub channel: String,
    /// The event sent, or `None` when there was nothing to send.
    pub event: Option<Event>,
    pub ok: bool,
    pub detail: String,
}

/// The context every message shares.
pub struct Context<'a> {
    pub cfg: &'a Config,
    pub source: String,
    pub host: String,
    pub log: Vec<String>,
    pub log_path: Option<String>,
    pub report: Option<Value>,
    pub use_system_proxy: bool,
    pub sleep: &'a dyn Fn(Duration),
    pub now: chrono::DateTime<chrono::Utc>,
}

/// An example message with fictional people, to see what reports look like
/// (`notify-test --render`). `Event::Failure` gives a failed run, anything else a run with
/// points of attention.
pub fn sample(event: Event, names: bool) -> Message {
    let line = |lvl: &tracing::Level, m: &str| crate::logcap::format_line(lvl, m, "");
    let info = tracing::Level::INFO;
    let mut log = vec![
        line(
            &info,
            "sync started by systemd (afas-entra-sync 0.11.0), reference date 2026-11-03",
        ),
        line(
            &info,
            "AFAS GetConnector Entra_Medewerkers: page from row 1 returned 612 rows",
        ),
        line(&info, "AFAS: 612 rows fetched"),
    ];
    let (headline, lead, facts, findings) = if event == Event::Failure {
        log.push(line(
            &tracing::Level::WARN,
            "AFAS request failed, retrying attempt=1 reason=HTTP 503 Service Unavailable: maintenance",
        ));
        log.push(line(
            &tracing::Level::ERROR,
            "AFAS error: AFAS unreachable after 4 attempts: HTTP 503 Service Unavailable: maintenance",
        ));
        let mut f = findings::examples().remove(0);
        f.kind = "run_failed";
        f.severity = Severity::Failure;
        f.audience = vec![Audience::It];
        f.title = "The sync did not run: AFAS could not be read".into();
        f.what = "AFAS error: AFAS unreachable after 4 attempts: HTTP 503 Service Unavailable: maintenance".into();
        f.impact = "Nothing was sent to Microsoft in this run. Until a run succeeds, new hires get no account, changes made in AFAS do not reach AD and Entra, and departing employees keep an enabled account.".into();
        f.why = "The tool already retries within a run (and waits as long as Microsoft or AFAS asks), and every scheduled run starts over. This error was still there after those retries, so it needs a person.".into();
        f.todo = vec![
            "Check whether AFAS Profit is reachable (status.afas.nl) and whether the token still works: `afas-entra-sync doctor`.".into(),
            "If the message names a missing field, a field of the GetConnector was renamed or removed: `afas-entra-sync afas-fields` shows what AFAS returns now.".into(),
            "If the token was revoked, create a new one for the app connector in Profit and replace the token file.".into(),
        ];
        f.table = None;
        f.new = true;
        (
            f.title.clone(),
            format!("{} This is failed run number 3 in a row.", f.impact),
            vec![
                ("Run".to_string(), "Sync, started by systemd".to_string()),
                ("Started".to_string(), "Tue 3 Nov 2026, 10:07".to_string()),
                ("Result".to_string(), "exit 30: AFAS error".to_string()),
                ("Server".to_string(), "sync01".to_string()),
            ],
            vec![f],
        )
    } else {
        log.push(line(&info, "plan: 598 to send (571 active, 6 new hires not started, 21 departed, 0 disabled once more outside the window), 1 skipped (data errors), 13 outside the date window, 0 missing from AFAS while active, 12 API calls"));
        log.push(line(
            &info,
            "upload call 12/12 accepted by Microsoft (48 records)",
        ));
        log.push(line(
            &info,
            "finished: ok, but records need attention (exit 3)",
        ));
        let f = findings::examples_for(names);
        (
            format!("{} points need attention after the sync", f.len()),
            "The sync itself went well (598 employees sent, Tue 3 Nov 2026, 10:07). The points below are things the tool cannot solve on its own; each one says who can.".to_string(),
            vec![
                ("Run".to_string(), "Sync, started by systemd".to_string()),
                ("Started".to_string(), "Tue 3 Nov 2026, 10:07".to_string()),
                ("Reference date".to_string(), "2026-11-03".to_string()),
                ("Result".to_string(), "exit 3: ok, but records need attention".to_string()),
                ("Sent".to_string(), "598 employees in 12 calls".to_string()),
                ("Server".to_string(), "sync01".to_string()),
            ],
            f,
        )
    };
    Message {
        id: uuid::Uuid::new_v4().to_string(),
        event,
        source: "Sync".into(),
        population: None,
        headline,
        lead,
        facts,
        findings,
        log,
        log_path: Some("/var/lib/afas-entra-sync/last-run.log".into()),
        report: None,
        gui_url: Some("https://afas-sync.example.com".into()),
        host: "sync01".into(),
        channel: "example".into(),
        repeat_hours: 24,
        created_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

/// The host name, for "which server sent this".
pub fn host_name() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "this server".into())
}

fn local_time(cfg: &Config, t: chrono::DateTime<chrono::Utc>) -> String {
    t.with_timezone(&cfg.tz())
        .format("%a %-d %b %Y, %H:%M")
        .to_string()
}

/// Headline and lead for a message, from the event and the findings.
fn headline(
    event: Event,
    findings: &[Finding],
    st: &ChannelState,
    ctx: &Context<'_>,
    facts_sent: Option<usize>,
) -> (String, String) {
    let when = local_time(ctx.cfg, ctx.now);
    let failure = findings.iter().find(|f| f.severity == Severity::Failure);
    let open = findings.len();
    match event {
        Event::Failure => match failure {
            Some(f) => {
                let mut lead = f.impact.clone();
                if st.last_outcome == Outcome::Failure && st.failed_runs > 0 {
                    lead.push_str(&format!(
                        " This is failed run number {} in a row.",
                        st.failed_runs + 1
                    ));
                }
                (f.title.clone(), lead)
            }
            None => ("The run failed".into(), String::new()),
        },
        Event::Attention => {
            let title = if open == 1 {
                findings[0].title.clone()
            } else {
                format!("{open} points need attention after the {}", ctx.source.to_lowercase())
            };
            let lead = match facts_sent {
                Some(n) => format!(
                    "The {} itself went well ({n} employees sent, {when}). The points below are things the tool cannot solve on its own; each one says who can.",
                    ctx.source.to_lowercase()
                ),
                None => "The points below are things the tool cannot solve on its own; each one says who can.".into(),
            };
            (title, lead)
        }
        Event::Recovered => {
            let mut lead = format!("The {} of {when} succeeded", ctx.source.to_lowercase());
            if let Some(t) = &st.failure_title {
                lead.push_str(&format!(" after: {t}"));
            }
            if let Some(since) = &st.failing_since_utc {
                lead.push_str(&format!(" (failing since {})", since.replace('T', " ").trim_end_matches('Z')));
            }
            lead.push('.');
            if open > 0 {
                lead.push_str(&format!(" {} still {} attention; see below.", open, if open == 1 { "needs" } else { "need" }));
            }
            ("The sync works again".into(), lead)
        }
        Event::AllClear => (
            "All points of attention are resolved".into(),
            format!("Nothing is open any more after the {} of {when}.", ctx.source.to_lowercase()),
        ),
        Event::Success => (
            format!("{} succeeded", ctx.source),
            match facts_sent {
                Some(n) => format!("{n} employees sent to Microsoft, {when}."),
                None => format!("Finished {when}."),
            },
        ),
        Event::Test => (
            "Test message from afas-entra-sync".into(),
            "If you can read this, this channel works. Below is an example of how a real report looks; the people in it are fictional.".into(),
        ),
    }
}

/// Sends to every channel what it needs after a run. `scope` keeps syncs and log checks
/// apart (an all-clear from one must not close the points of the other). `stateless`:
/// test runs and `notify-test` (send whatever applies, remember nothing).
pub fn dispatch(
    ctx: &Context<'_>,
    scope: &str,
    outcome: Outcome,
    build: &dyn Fn(bool) -> Vec<Finding>,
    facts: &[(String, String)],
    sent: Option<usize>,
    stateless: Option<Event>,
) -> Vec<Delivery> {
    let Some(n) = ctx.cfg.notify.as_ref().filter(|n| n.enabled) else {
        return Vec::new();
    };
    let dir = &ctx.cfg.state.dir;
    let mut state = match load_state(dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("notifications: {e}");
            return vec![Delivery {
                channel: "all".into(),
                event: None,
                ok: false,
                detail: e,
            }];
        }
    };
    let with_names = build(true);
    let numbers_only = findings::without_personal(&build(false));
    let now = ctx.now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut out = Vec::new();
    for (i, c) in n.channels.iter().enumerate().filter(|(_, c)| c.enabled) {
        let id = c.id(i);
        let key = format!("{id}:{scope}");
        let st = state.channels.get(&key).cloned().unwrap_or_default();
        let base = if c.names(n) {
            &with_names
        } else {
            &numbers_only
        };
        let mut fs = findings::for_audience(base, &c.audience);
        // Points for another audience only: nothing for this channel.
        let outcome = if outcome == Outcome::Attention && fs.is_empty() {
            Outcome::Ok
        } else {
            outcome
        };
        let event = match stateless {
            Some(Event::Test) => Some(Event::Test),
            Some(e) => {
                for f in &mut fs {
                    f.new = true;
                }
                (!fs.is_empty()).then_some(e)
            }
            None => decide(
                &st,
                outcome,
                &mut fs,
                c.triggers(n),
                n.repeat_hours,
                ctx.now,
            ),
        };
        let Some(event) = event else {
            if stateless.is_none() {
                state
                    .channels
                    .insert(key.clone(), next_state(&st, outcome, &fs, false, &now));
            }
            out.push(Delivery {
                channel: id,
                event: None,
                ok: true,
                detail: "nothing new to report".into(),
            });
            continue;
        };
        if event == Event::Test {
            fs = findings::examples_for(c.names(n));
        }
        let (headline, lead) = headline(event, &fs, &st, ctx, sent);
        let msg = Message {
            id: uuid::Uuid::new_v4().to_string(),
            event,
            source: ctx.source.clone(),
            population: ctx.cfg.population.name.clone(),
            headline,
            lead,
            facts: facts.to_vec(),
            findings: if matches!(event, Event::AllClear | Event::Success) {
                Vec::new()
            } else {
                fs.clone()
            },
            // Log lines quote data errors (with the value); without names, hide those values.
            log: if c.names(n) {
                ctx.log.clone()
            } else {
                ctx.log.iter().map(|l| findings::redact(l)).collect()
            },
            log_path: ctx.log_path.clone(),
            // The report lists data errors with their values: only where names are allowed.
            report: if c.names(n) { ctx.report.clone() } else { None },
            gui_url: n.gui_url.clone(),
            host: ctx.host.clone(),
            channel: id.clone(),
            repeat_hours: n.repeat_hours,
            created_utc: now.clone(),
        };
        let res = deliver(ctx, n, c, &msg);
        match &res {
            Ok(()) => tracing::info!(channel = %id, event = ?event, "notification sent"),
            Err(e) => tracing::error!(channel = %id, "notification failed: {e}"),
        }
        if stateless.is_none() && res.is_ok() {
            state
                .channels
                .insert(key.clone(), next_state(&st, outcome, &fs, true, &now));
        }
        out.push(Delivery {
            channel: id,
            event: Some(event),
            ok: res.is_ok(),
            detail: match res {
                Ok(()) => format!("sent ({} points)", msg.findings.len()),
                Err(e) => e,
            },
        });
    }
    if stateless.is_none() {
        state.version = NOTIFY_STATE_VERSION;
        if let Err(e) = save_state(dir, &state) {
            tracing::error!("notification state not saved: {e}");
        }
    }
    out
}

// ------------------------------------------------------------------ delivery

fn deliver(ctx: &Context<'_>, n: &NotifyConfig, c: &Channel, m: &Message) -> Result<(), String> {
    match c.kind {
        ChannelKind::Email => send_email(ctx, n, c, m),
        ChannelKind::Teams => post_json(ctx, n, &channel_url(c)?, &render::teams(m), &[]),
        ChannelKind::Slack => post_json(ctx, n, &channel_url(c)?, &render::slack(m), &[]),
        ChannelKind::Webhook => {
            let body = render::webhook(m);
            let secret = read_secret(&c.secret_env, &c.secret_file, "notification webhook secret")?;
            if secret.len() < 16 {
                return Err(
                    "the notification webhook secret must be at least 16 characters".into(),
                );
            }
            let raw = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
            let ts = chrono::Utc::now().timestamp().to_string();
            let mut signed = ts.clone().into_bytes();
            signed.push(b'.');
            signed.extend_from_slice(&raw);
            let sig = format!(
                "sha256={}",
                crate::modules::webhook::hex(&crate::modules::webhook::hmac_sha256(
                    secret.as_bytes(),
                    &signed
                ))
            );
            let ev = serde_json::to_value(m.event)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            post_raw(
                ctx,
                n,
                &channel_url(c)?,
                raw,
                &[
                    ("X-AfasEntraSync-Event", format!("notification.{ev}")),
                    ("X-AfasEntraSync-Delivery", m.id.clone()),
                    ("X-AfasEntraSync-Timestamp", ts),
                    ("X-AfasEntraSync-Signature", sig),
                ],
            )
        }
    }
}

fn post_json(
    ctx: &Context<'_>,
    n: &NotifyConfig,
    url: &str,
    body: &Value,
    headers: &[(&str, String)],
) -> Result<(), String> {
    let raw = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    post_raw(ctx, n, url, raw, headers)
}

/// POST with one retry after a network error, 429 or 5xx (a duplicate message is
/// better than a missing one).
fn post_raw(
    ctx: &Context<'_>,
    n: &NotifyConfig,
    url: &str,
    raw: Vec<u8>,
    headers: &[(&str, String)],
) -> Result<(), String> {
    let client = build_client(n.timeout_secs, ctx.use_system_proxy, &ctx.cfg.tls)?;
    let mut last = String::new();
    for attempt in 1..=2 {
        let mut req = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(raw.clone());
        for (k, v) in headers {
            req = req.header(*k, v.as_str());
        }
        match req.send() {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => {
                let status = r.status();
                let text = read_capped(r, MAX_SMALL_BODY).unwrap_or_default();
                last = format!("HTTP {status}: {}", snippet(&text, 200));
                if !(status.is_server_error() || status.as_u16() == 429) {
                    return Err(last);
                }
            }
            Err(e) => {
                // Webhook URLs are secrets: never in a message or log.
                last = format!("network error: {}", e.without_url());
            }
        }
        if attempt == 1 {
            (ctx.sleep)(Duration::from_secs(5));
        }
    }
    Err(last)
}

/// Attachments larger than this are cut (Graph accepts at most 3 MB inline).
const MAX_ATTACHMENT: usize = 1_000_000;

fn send_email(ctx: &Context<'_>, n: &NotifyConfig, c: &Channel, m: &Message) -> Result<(), String> {
    let sender = n
        .email
        .as_ref()
        .ok_or_else(|| "no [notify.email] section".to_string())?;
    let (subject, html) = render::email(m);
    let b64 = |s: &[u8]| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(s)
    };
    let mut attachments = Vec::new();
    if !m.log.is_empty() {
        let mut log = m.log.join("\n");
        if log.len() > MAX_ATTACHMENT {
            let cut = log.len() - MAX_ATTACHMENT;
            let at = (cut..log.len())
                .find(|i| log.is_char_boundary(*i))
                .unwrap_or(cut);
            log = format!(
                "… (first part cut, see the log on the server)\n{}",
                &log[at..]
            );
        }
        attachments.push(json!({
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": "run.log",
            "contentType": "text/plain; charset=utf-8",
            "contentBytes": b64(log.as_bytes()),
        }));
    }
    if let Some(r) = &m.report {
        let j = serde_json::to_vec_pretty(r).unwrap_or_default();
        if j.len() <= MAX_ATTACHMENT {
            attachments.push(json!({
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": "report.json",
                "contentType": "application/json",
                "contentBytes": b64(&j),
            }));
        }
    }
    let body = json!({
        "message": {
            "subject": subject,
            "importance": if m.event == Event::Failure { "high" } else { "normal" },
            "body": { "contentType": "HTML", "content": html },
            "toRecipients": c.to.iter().map(|a| json!({ "emailAddress": { "address": a } })).collect::<Vec<_>>(),
            "attachments": attachments,
        },
        "saveToSentItems": false,
    });
    let mailbox = crate::modules::joiner::mailbox(&sender.sender).map_err(|e| e.message)?;
    crate::modules::graph_as(
        ctx.cfg,
        &sender.identity(),
        ctx.use_system_proxy,
        ctx.sleep,
        |g| {
            g.call(
                reqwest::Method::POST,
                &format!("users/{mailbox}/sendMail"),
                Some(&body),
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
        },
    )?
}

/// Signs in the email sender (for `doctor`): `Ok` when a token was issued.
pub fn check_email_sign_in(
    cfg: &Config,
    use_system_proxy: bool,
    sleep: &dyn Fn(Duration),
) -> Result<(), String> {
    let Some(e) = cfg.notify.as_ref().and_then(|n| n.email.as_ref()) else {
        return Ok(());
    };
    let mut ec = cfg.entra.clone();
    ec.client_id = e.client_id.clone();
    ec.auth = AuthMode::Certificate;
    ec.certificate_pem = Some(e.certificate_pem.clone());
    ec.private_key_pem = Some(e.private_key_pem.clone());
    ec.client_secret_env = None;
    let cred = crate::entra::Credential::from_config(&ec).map_err(|x| x.to_string())?;
    let client = build_client(ec.timeout_secs, use_system_proxy, &cfg.tls)?;
    crate::entra::TokenProvider::new(&ec, &client, cred, sleep)
        .get(false)
        .map(|_| ())
        .map_err(|x| x.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(key: &str, sev: Severity) -> Finding {
        let mut x = findings::examples().remove(0);
        x.key = key.into();
        x.severity = sev;
        x.title = key.into();
        x
    }

    fn at(h: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-11-03T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
            + chrono::Duration::hours(h)
    }

    const ALL: &[Trigger] = &[Trigger::Failure, Trigger::Attention, Trigger::Recovered];

    /// Runs `decide` + `next_state` like `dispatch` does (delivery always succeeds).
    fn step(st: &mut ChannelState, o: Outcome, fs: &mut [Finding], h: i64) -> Option<Event> {
        let e = decide(st, o, fs, ALL, 24, at(h));
        let now = at(h).to_rfc3339();
        *st = next_state(st, o, fs, e.is_some(), &now);
        e
    }

    #[test]
    fn failures_are_sent_once_then_repeated_daily_and_recovery_is_announced() {
        let mut st = ChannelState::default();
        let mut fail = vec![f("run_failed:30", Severity::Failure)];
        assert_eq!(
            step(&mut st, Outcome::Failure, &mut fail, 0),
            Some(Event::Failure)
        );
        assert_eq!(step(&mut st, Outcome::Failure, &mut fail, 1), None);
        assert_eq!(st.failed_runs, 2);
        // A different failure is news.
        let mut other = vec![f("run_failed:40", Severity::Failure)];
        assert_eq!(
            step(&mut st, Outcome::Failure, &mut other, 2),
            Some(Event::Failure)
        );
        assert_eq!(step(&mut st, Outcome::Failure, &mut other, 25), None);
        assert_eq!(
            step(&mut st, Outcome::Failure, &mut other, 26),
            Some(Event::Failure)
        );
        assert_eq!(
            step(&mut st, Outcome::Ok, &mut [], 27),
            Some(Event::Recovered)
        );
        assert_eq!(st.failing_since_utc, None);
        assert_eq!(step(&mut st, Outcome::Ok, &mut [], 28), None);
    }

    #[test]
    fn attention_only_for_new_points_and_all_clear_at_the_end() {
        let mut st = ChannelState::default();
        let mut a = vec![f("missing:1", Severity::Action)];
        assert_eq!(
            step(&mut st, Outcome::Attention, &mut a, 0),
            Some(Event::Attention)
        );
        assert!(a[0].new);
        assert_eq!(step(&mut st, Outcome::Attention, &mut a, 1), None);
        assert!(!a[0].new);
        let mut ab = vec![
            f("missing:1", Severity::Action),
            f("excluded:2", Severity::Action),
        ];
        assert_eq!(
            step(&mut st, Outcome::Attention, &mut ab, 2),
            Some(Event::Attention)
        );
        assert!(!ab[0].new && ab[1].new);
        assert_eq!(step(&mut st, Outcome::Attention, &mut ab, 3), None);
        // Still open a day later: repeated.
        assert_eq!(
            step(&mut st, Outcome::Attention, &mut ab, 26),
            Some(Event::Attention)
        );
        assert_eq!(
            step(&mut st, Outcome::Ok, &mut [], 27),
            Some(Event::AllClear)
        );
        assert_eq!(step(&mut st, Outcome::Ok, &mut [], 28), None);
        // A point that comes back counts as new.
        assert_eq!(
            step(&mut st, Outcome::Attention, &mut a, 29),
            Some(Event::Attention)
        );
        assert!(a[0].new);
    }

    #[test]
    fn channels_only_get_what_they_asked_for() {
        let st = ChannelState::default();
        let mut a = vec![f("x", Severity::Action)];
        assert_eq!(
            decide(
                &st,
                Outcome::Attention,
                &mut a,
                &[Trigger::Failure],
                24,
                at(0)
            ),
            None
        );
        assert_eq!(
            decide(&st, Outcome::Ok, &mut [], &[Trigger::Success], 24, at(0)),
            Some(Event::Success)
        );
        let failing = ChannelState {
            last_outcome: Outcome::Failure,
            ..Default::default()
        };
        assert_eq!(
            decide(
                &failing,
                Outcome::Ok,
                &mut [],
                &[Trigger::Failure],
                24,
                at(0)
            ),
            None
        );
        // repeat_hours = 0: never repeated.
        let mut st2 = ChannelState::default();
        let e = decide(&st2, Outcome::Attention, &mut a, ALL, 0, at(0));
        st2 = next_state(
            &st2,
            Outcome::Attention,
            &a,
            e.is_some(),
            &at(0).to_rfc3339(),
        );
        assert_eq!(
            decide(&st2, Outcome::Attention, &mut a, ALL, 0, at(500)),
            None
        );
    }

    #[test]
    fn config_rules() {
        let parse = |t: &str| toml::from_str::<NotifyConfig>(t).unwrap().validate();
        assert!(parse("").is_err(), "no channels");
        assert!(
            parse("[[channel]]\nkind = \"teams\"\nurl = \"https://x.logic.azure.com/a\"\n")
                .unwrap_err()
                .contains("password")
        );
        assert!(parse("[[channel]]\nkind = \"teams\"\nurl_env = \"T\"\n").is_ok());
        assert!(
            parse("[[channel]]\nkind = \"email\"\nto = [\"a@b.nl\"]\n")
                .unwrap_err()
                .contains("[notify.email]")
        );
        assert!(parse("[email]\nclient_id = \"00000000-0000-0000-0000-000000000000\"\ncertificate_pem = \"/c\"\nprivate_key_pem = \"/k\"\nsender = \"s@b.nl\"\n[[channel]]\nkind = \"email\"\nto = [\"a@b.nl\"]\n").is_ok());
        assert!(
            parse("[[channel]]\nkind = \"webhook\"\nurl = \"https://x.example/h\"\n")
                .unwrap_err()
                .contains("secret")
        );
        assert!(parse("[[channel]]\nkind = \"webhook\"\nurl = \"http://x.example/h\"\nsecret_env = \"S\"\n").unwrap_err().contains("https"));
        assert!(parse("[[channel]]\nkind = \"slack\"\nurl_env = \"S\"\n[[channel]]\nkind = \"slack\"\nurl_env = \"S\"\nname = \"slack-1\"\n").unwrap_err().contains("same name"));
        assert!(check_url(ChannelKind::Slack, "https://evil.example/services/x").is_err());
        assert!(check_url(ChannelKind::Slack, "https://hooks.slack.com/services/T/B/x").is_ok());
    }
}
