// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Configuration of the optional modules. Every module is off unless its section
//! is present with `enabled = true`, and every module that calls Microsoft Graph
//! signs in with its own app registration, so each one holds only its own rights.

use serde::Deserialize;
use std::path::PathBuf;

fn yes() -> bool {
    true
}

/// App registration a module signs in with (certificate only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleIdentity {
    pub client_id: String,
    pub certificate_pem: PathBuf,
    pub private_key_pem: PathBuf,
}

/// Roles: AFAS attributes decide membership of Entra groups (licences through
/// group-based licensing). Only groups whose name starts with `group_prefix` are touched.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolesConfig {
    #[serde(default)]
    pub enabled: bool,
    /// App registration of this module (certificate auth).
    pub client_id: String,
    pub certificate_pem: PathBuf,
    pub private_key_pem: PathBuf,
    /// Every managed group's display name must start with this, e.g. "AFAS-".
    pub group_prefix: String,
    /// Also give groups to new employees before their start date (licences cost money).
    #[serde(default)]
    pub include_prehires: bool,
    /// Keep leavers in their groups for this many days after the end date
    /// (e.g. so a licensed mailbox stays available while it is converted).
    #[serde(default)]
    pub keep_leavers_days: u32,
    /// Remove members that are not linked to any employee in this upload.
    /// Off by default: admin and service accounts in managed groups are left alone.
    #[serde(default)]
    pub remove_unknown_members: bool,
    #[serde(default = "default_role_changes")]
    pub max_changes_per_run: u32,
    #[serde(default, rename = "rule")]
    pub rules: Vec<RoleRule>,
    #[serde(default)]
    pub sod: Vec<SodRule>,
}

fn default_role_changes() -> u32 {
    50
}

/// One rule: employees matching ALL non-empty criteria get the group.
/// Values within one criterion are alternatives (OR), compared case-insensitively.
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleRule {
    /// Object ID of the Entra group.
    pub group_id: String,
    /// Optional label for reports.
    #[serde(default)]
    pub name: Option<String>,
    /// Match every employee (only allowed without other criteria).
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub department: Vec<String>,
    #[serde(default)]
    pub job_title: Vec<String>,
    #[serde(default)]
    pub job_profile: Vec<String>,
    #[serde(default)]
    pub office: Vec<String>,
    #[serde(default)]
    pub company: Vec<String>,
    #[serde(default)]
    pub employee_type: Vec<String>,
    #[serde(default)]
    pub cost_center: Vec<String>,
    #[serde(default)]
    pub population: Vec<String>,
}

impl RoleRule {
    pub fn criteria(&self) -> [(&'static str, &Vec<String>); 8] {
        [
            ("department", &self.department),
            ("job_title", &self.job_title),
            ("job_profile", &self.job_profile),
            ("office", &self.office),
            ("company", &self.company),
            ("employee_type", &self.employee_type),
            ("cost_center", &self.cost_center),
            ("population", &self.population),
        ]
    }
}

/// Segregation of duties: nobody may be in two or more of these groups.
#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SodRule {
    pub name: String,
    pub groups: Vec<String>,
}

/// Joiners: a Temporary Access Pass for the first day, mailed to the manager or a fixed address.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct JoinerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// App registration of this module (certificate auth).
    pub client_id: String,
    pub certificate_pem: PathBuf,
    pub private_key_pem: PathBuf,
    /// Mailbox the mail is sent from (restrict Mail.Send to it, see SECURITY.md).
    pub sender: String,
    pub deliver_to: DeliverTo,
    /// Required with `deliver_to = "fixed"`; fallback when the manager has no email.
    #[serde(default)]
    pub fixed_address: Option<String>,
    /// Issue the pass this many days before the start date (it only works from the start date).
    #[serde(default = "default_days_before")]
    pub days_before_start: u32,
    /// Hour (local time) on the start date from which the pass works.
    #[serde(default = "default_start_hour")]
    pub start_hour: u32,
    #[serde(default = "default_lifetime")]
    pub lifetime_minutes: u32,
    #[serde(default)]
    pub usable_once: bool,
    #[serde(default = "default_max_taps")]
    pub max_per_run: u32,
    #[serde(default = "default_subject")]
    pub subject: String,
    /// Placeholders: {display_name} {upn} {tap} {valid_from} {valid_until} {start_date}.
    #[serde(default = "default_body")]
    pub body: String,
}

#[derive(Debug, Clone, Copy, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliverTo {
    Manager,
    Fixed,
}

fn default_days_before() -> u32 {
    1
}
fn default_start_hour() -> u32 {
    6
}
fn default_lifetime() -> u32 {
    600
}
fn default_max_taps() -> u32 {
    20
}
fn default_subject() -> String {
    "First sign-in for {display_name}".into()
}
fn default_body() -> String {
    "Hello,\n\n{display_name} starts on {start_date}. Their account is {upn}.\n\nTemporary Access Pass for the first sign-in: {tap}\nValid from {valid_from} until {valid_until}.\n\nHand it over in person or by phone; do not forward this email. The new colleague uses it to sign in and set up MFA.\n".into()
}

/// Leavers: revoke sessions and set an automatic reply, once per end date.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaverConfig {
    #[serde(default)]
    pub enabled: bool,
    /// App registration of this module (certificate auth).
    pub client_id: String,
    pub certificate_pem: PathBuf,
    pub private_key_pem: PathBuf,
    #[serde(default = "yes")]
    pub revoke_sessions: bool,
    /// Automatic reply; placeholders {display_name} {manager_name} {manager_email}.
    #[serde(default)]
    pub auto_reply: Option<String>,
    /// Used instead of `auto_reply` when it names the manager but no manager (with an
    /// email address) is known. Placeholder {display_name}. Without it: no reply then.
    #[serde(default)]
    pub auto_reply_no_manager: Option<String>,
    /// Also reply to external senders.
    #[serde(default)]
    pub auto_reply_external: bool,
    /// Act on leavers whose end date is at most this many days ago.
    #[serde(default = "default_grace")]
    pub grace_days: u32,
    #[serde(default = "default_max_leavers")]
    pub max_per_run: u32,
}

fn default_grace() -> u32 {
    7
}
fn default_max_leavers() -> u32 {
    10
}

/// Webhook: joiner, mover and leaver events as signed JSON, e.g. for an ITSM tool.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    #[serde(default)]
    pub enabled: bool,
    pub url: String,
    /// Environment variable with the HMAC secret (or `secret_file`).
    #[serde(default)]
    pub secret_env: Option<String>,
    #[serde(default)]
    pub secret_file: Option<PathBuf>,
    #[serde(default = "default_events")]
    pub events: Vec<EventKind>,
    #[serde(default = "default_webhook_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_webhook_max")]
    pub max_per_run: u32,
}

#[derive(Debug, Clone, Copy, Deserialize, serde::Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Joiner,
    Mover,
    Leaver,
}

fn default_events() -> Vec<EventKind> {
    vec![EventKind::Joiner, EventKind::Mover, EventKind::Leaver]
}
fn default_webhook_timeout() -> u64 {
    15
}
fn default_webhook_max() -> u32 {
    200
}

macro_rules! identity_of {
    ($t:ty) => {
        impl $t {
            pub fn identity(&self) -> ModuleIdentity {
                ModuleIdentity {
                    client_id: self.client_id.clone(),
                    certificate_pem: self.certificate_pem.clone(),
                    private_key_pem: self.private_key_pem.clone(),
                }
            }
        }
    };
}
identity_of!(RolesConfig);
identity_of!(JoinerConfig);
identity_of!(LeaverConfig);

pub(crate) fn is_email(s: &str) -> bool {
    let mut p = s.split('@');
    matches!((p.next(), p.next(), p.next()), (Some(l), Some(d), None)
        if !l.is_empty() && d.contains('.') && !d.starts_with('.') && !d.ends_with('.'))
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn check_identity(m: &str, id: &ModuleIdentity) -> Result<(), String> {
    if !crate::config::is_guid(&id.client_id) {
        return Err(format!("{m}.client_id is not a GUID"));
    }
    if id.certificate_pem.as_os_str().is_empty() || id.private_key_pem.as_os_str().is_empty() {
        return Err(format!(
            "{m}: certificate_pem and private_key_pem are required"
        ));
    }
    Ok(())
}

pub fn validate(
    roles: Option<&RolesConfig>,
    joiner: Option<&JoinerConfig>,
    leaver: Option<&LeaverConfig>,
    webhook: Option<&WebhookConfig>,
) -> Result<(), String> {
    if let Some(r) = roles {
        check_identity("roles", &r.identity())?;
        let px = r.group_prefix.trim();
        if px.len() < 3 || px.len() > 32 || px != r.group_prefix {
            return Err(
                "roles.group_prefix must be 3 to 32 characters without surrounding spaces".into(),
            );
        }
        if r.max_changes_per_run == 0 {
            return Err("roles.max_changes_per_run must be > 0".into());
        }
        if r.keep_leavers_days > 365 {
            return Err("roles.keep_leavers_days can be at most 365".into());
        }
        if r.enabled && r.rules.is_empty() {
            return Err("roles: at least one [[roles.rule]] is needed".into());
        }
        for (i, rule) in r.rules.iter().enumerate() {
            let n = i + 1;
            if !crate::config::is_guid(&rule.group_id) {
                return Err(format!("roles.rule {n}: group_id is not a GUID"));
            }
            let has = rule.criteria().iter().any(|(_, v)| !v.is_empty());
            if rule.all && has {
                return Err(format!(
                    "roles.rule {n}: `all = true` cannot be combined with criteria"
                ));
            }
            if !rule.all && !has {
                return Err(format!(
                    "roles.rule {n}: no criteria; use `all = true` to give the group to everyone"
                ));
            }
            for (k, v) in rule.criteria() {
                if v.iter().any(|x| x.trim().is_empty()) {
                    return Err(format!("roles.rule {n}: empty value in {k}"));
                }
            }
        }
        for s in &r.sod {
            if s.name.trim().is_empty() || s.groups.len() < 2 {
                return Err("roles.sod: needs a name and at least two groups".into());
            }
            if s.groups.iter().any(|g| !crate::config::is_guid(g)) {
                return Err(format!("roles.sod '{}': group ids must be GUIDs", s.name));
            }
            for g in &s.groups {
                if !r.rules.iter().any(|x| x.group_id.eq_ignore_ascii_case(g)) {
                    return Err(format!(
                        "roles.sod '{}': group {g} is not in any [[roles.rule]]",
                        s.name
                    ));
                }
            }
        }
    }
    if let Some(j) = joiner {
        check_identity("joiner", &j.identity())?;
        if !is_email(&j.sender) || j.sender.contains(['/', '?', '#', '%', '\\']) {
            return Err("joiner.sender must be a mailbox address".into());
        }
        match (&j.deliver_to, &j.fixed_address) {
            (DeliverTo::Fixed, None) => {
                return Err("joiner: deliver_to = \"fixed\" needs fixed_address".into());
            }
            (_, Some(a)) if !is_email(a) => {
                return Err("joiner.fixed_address must be an email address".into());
            }
            _ => {}
        }
        if j.days_before_start > 14 {
            return Err("joiner.days_before_start can be at most 14".into());
        }
        if j.start_hour > 23 {
            return Err("joiner.start_hour must be 0 to 23".into());
        }
        if !(60..=43_200).contains(&j.lifetime_minutes) {
            return Err("joiner.lifetime_minutes must be 60 to 43200".into());
        }
        if j.max_per_run == 0 {
            return Err("joiner.max_per_run must be > 0".into());
        }
        if !j.body.contains("{tap}") {
            return Err("joiner.body must contain {tap}".into());
        }
        if j.subject.contains("{tap}") {
            return Err("joiner.subject must not contain {tap}".into());
        }
    }
    if let Some(l) = leaver {
        check_identity("leaver", &l.identity())?;
        if l.grace_days == 0 || l.grace_days > 90 {
            return Err("leaver.grace_days must be 1 to 90".into());
        }
        if l.max_per_run == 0 {
            return Err("leaver.max_per_run must be > 0".into());
        }
        if let Some(m) = &l.auto_reply
            && (m.trim().is_empty() || m.len() > 4000)
        {
            return Err("leaver.auto_reply must be 1 to 4000 characters".into());
        }
        if let Some(m) = &l.auto_reply_no_manager {
            if m.trim().is_empty() || m.len() > 4000 {
                return Err("leaver.auto_reply_no_manager must be 1 to 4000 characters".into());
            }
            if m.contains("{manager_name}") || m.contains("{manager_email}") {
                return Err(
                    "leaver.auto_reply_no_manager is used when no manager is known: it cannot contain {manager_name} or {manager_email}".into(),
                );
            }
        }
        if l.enabled && !l.revoke_sessions && l.auto_reply.is_none() {
            return Err("leaver: nothing to do (revoke_sessions = false and no auto_reply)".into());
        }
    }
    if let Some(w) = webhook {
        let local =
            w.url.starts_with("http://127.0.0.1:") || w.url.starts_with("http://localhost:");
        if !w.url.starts_with("https://") && !local {
            return Err("webhook.url must start with https://".into());
        }
        if reqwest::Url::parse(&w.url).is_err() {
            return Err("webhook.url is not a valid URL".into());
        }
        match (&w.secret_env, &w.secret_file) {
            (Some(_), Some(_)) => {
                return Err("webhook: use secret_env or secret_file, not both".into());
            }
            (None, None) if w.enabled => {
                return Err(
                    "webhook: a secret (secret_env or secret_file) is required to sign events"
                        .into(),
                );
            }
            _ => {}
        }
        if w.events.is_empty() {
            return Err("webhook.events cannot be empty".into());
        }
        if !(1..=120).contains(&w.timeout_secs) || w.max_per_run == 0 {
            return Err("webhook: timeout_secs 1 to 120 and max_per_run > 0".into());
        }
    }
    Ok(())
}
