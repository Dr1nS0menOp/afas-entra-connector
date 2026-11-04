// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! What a run does, account by account: create, enable, disable, update or nothing,
//! where the account lives (OU in AD, or Entra ID) and which values change.
//!
//! A test run compares the plan with Entra ID as it is now (read-only look-up with the
//! `[preview]` app registration or that of an enabled module), or, without a look-up,
//! with what the last successful sync sent. The result is written next to the report
//! (`last-dry-run-preview.json`, personal data, mode 0600) and shown in the terminal, in
//! the admin GUI and as a standalone HTML page in which the table fills up call by call.

use crate::config::Config;
use crate::graph::{GResult, Graph};
use crate::plan::{Plan, PlannedRecord};
use crate::scim::{attribute, sent_values};
use crate::state::State;
use crate::web::esc;
use chrono::Days;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

pub const PREVIEW_VERSION: u32 = 1;

/// What happens to one account.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// New account, enabled (start date reached).
    Create,
    /// New account, disabled until the start date (new hire), or a departed employee
    /// without an account (Microsoft creates it disabled).
    CreateDisabled,
    Enable,
    Disable,
    Update,
    Unchanged,
    /// Sent before, but the values sent then are unknown (state from before 0.11).
    Resend,
    /// First run without a look-up: linked to the AD account with this employeeID, or created.
    New,
    /// An account with this sign-in name exists without employee number: Microsoft would
    /// create a second one.
    LinkFirst,
    /// The sign-in name belongs to another employee number.
    Conflict,
    /// Not sent: data error.
    Skipped,
    /// Not sent: starts after the pre-hire window.
    Later,
    /// Not sent: left before the lookback window.
    NotSent,
    /// Sent as active before, no longer in AFAS.
    Missing,
}

impl Action {
    pub const ALL: [Action; 14] = [
        Action::Create,
        Action::CreateDisabled,
        Action::Enable,
        Action::Disable,
        Action::Update,
        Action::Unchanged,
        Action::Resend,
        Action::New,
        Action::LinkFirst,
        Action::Conflict,
        Action::Skipped,
        Action::Missing,
        Action::Later,
        Action::NotSent,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Action::Create => "Create",
            Action::CreateDisabled => "Create, disabled",
            Action::Enable => "Enable",
            Action::Disable => "Disable",
            Action::Update => "Update",
            Action::Unchanged => "No change",
            Action::Resend => "Sent before",
            Action::New => "New for this tool",
            Action::LinkFirst => "Link first",
            Action::Conflict => "Conflict",
            Action::Skipped => "Skipped",
            Action::Later => "Later",
            Action::NotSent => "Not sent",
            Action::Missing => "Missing in AFAS",
        }
    }

    /// CSS tone and terminal colour group.
    pub fn tone(self) -> &'static str {
        match self {
            Action::Create => "add",
            Action::CreateDisabled => "pre",
            Action::Enable => "on",
            Action::Disable => "off",
            Action::Update => "upd",
            Action::Unchanged | Action::Resend => "same",
            Action::New => "new",
            Action::LinkFirst | Action::Missing => "warn",
            Action::Conflict | Action::Skipped => "bad",
            Action::Later | Action::NotSent => "skip",
        }
    }

    /// One character for the terminal.
    pub fn symbol(self) -> &'static str {
        match self {
            Action::Create | Action::CreateDisabled | Action::New => "+",
            Action::Enable => "↑",
            Action::Disable => "↓",
            Action::Update => "~",
            Action::Unchanged | Action::Resend => "=",
            Action::LinkFirst | Action::Conflict | Action::Skipped | Action::Missing => "!",
            Action::Later | Action::NotSent => "·",
        }
    }

    /// In the upload (sent to Microsoft).
    pub fn in_upload(self) -> bool {
        !matches!(
            self,
            Action::Skipped | Action::Later | Action::NotSent | Action::Missing
        )
    }

    /// Something happens to the account.
    pub fn is_change(self) -> bool {
        matches!(
            self,
            Action::Create
                | Action::CreateDisabled
                | Action::Enable
                | Action::Disable
                | Action::Update
                | Action::New
        )
    }

    /// Needs a person before (or instead of) the run.
    pub fn is_problem(self) -> bool {
        matches!(
            self,
            Action::LinkFirst | Action::Conflict | Action::Skipped | Action::Missing
        )
    }
}

/// One value that changes. `to = None` with `kept`: empty in AFAS, so not sent, and AD
/// keeps the old value (unless "clear attribute values" is on in the provisioning app).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Change {
    pub key: String,
    pub label: String,
    /// AD attribute of the default mapping.
    pub ad: String,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub kept: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Row {
    pub action: Action,
    pub employee_id: Option<String>,
    pub name: Option<String>,
    pub upn: Option<String>,
    pub department: Option<String>,
    /// Where the account is or will be: `example.com/Staff/Sales`, or `Entra ID`.
    pub location: Option<String>,
    /// Account enabled after this run (for records in the upload).
    pub enabled_after: Option<bool>,
    /// Number of the upload call (1-based) the record is in.
    pub call: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<Change>,
    pub note: Option<String>,
}

/// How the AFAS rows were distributed (the pipeline at the top of the preview).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Flow {
    pub rows_fetched: usize,
    pub valid: usize,
    pub excluded: usize,
    pub merged: usize,
    pub later: usize,
    pub left_earlier: usize,
    pub carried: usize,
    pub sent: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Entra ID as it is now.
    Entra,
    /// What the last successful sync sent.
    LastRun,
    /// Nothing (first run without a look-up).
    Nothing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Preview {
    pub version: u32,
    /// "dry-run" or "apply".
    pub mode: String,
    pub created_utc: String,
    pub today: String,
    pub population: Option<String>,
    /// "Active Directory" or "Entra ID".
    pub target: String,
    pub source: Source,
    /// One sentence: what the plan was compared with.
    pub compared_with: String,
    /// Where new accounts go.
    pub new_accounts: String,
    pub batch_size: usize,
    pub calls: usize,
    pub flow: Flow,
    pub totals: BTreeMap<Action, usize>,
    /// Things to know when reading the preview (e.g. attributes not visible in Entra).
    #[serde(default)]
    pub notes: Vec<String>,
    pub rows: Vec<Row>,
}

/// Small summary for the report (which goes to logs and schedulers, so no names).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Summary {
    pub file: String,
    pub compared_with: Source,
    pub totals: BTreeMap<Action, usize>,
}

impl Preview {
    pub fn summary(&self, file: &str) -> Summary {
        Summary {
            file: file.to_string(),
            compared_with: self.source,
            totals: self.totals.clone(),
        }
    }

    pub fn total(&self, a: Action) -> usize {
        self.totals.get(&a).copied().unwrap_or(0)
    }

    pub fn changes(&self) -> usize {
        Action::ALL
            .iter()
            .filter(|a| a.is_change())
            .map(|a| self.total(*a))
            .sum()
    }

    pub fn problems(&self) -> usize {
        Action::ALL
            .iter()
            .filter(|a| a.is_problem())
            .map(|a| self.total(*a))
            .sum()
    }

    /// The sentence at the top: what the run does.
    pub fn headline(&self) -> String {
        let dry = self.mode != "apply";
        let n = |a: Action| self.total(a);
        let create = n(Action::Create) + n(Action::CreateDisabled);
        let counted: Vec<(usize, &str, &str)> = [
            (create, "create", "to create"),
            (n(Action::Enable), "enable", "to enable"),
            (n(Action::Disable), "disable", "to disable"),
            (n(Action::Update), "update", "to update"),
        ]
        .into_iter()
        .filter(|(c, _, _)| *c > 0)
        .collect();
        let parts: Vec<String> = counted
            .iter()
            .enumerate()
            .map(|(i, (c, verb, to))| {
                if !dry {
                    format!("{c} {to}")
                } else if i == 0 {
                    // "create 2 accounts, enable 1 and update 4"
                    format!(
                        "{verb} {c} {}",
                        if *c == 1 { "account" } else { "accounts" }
                    )
                } else {
                    format!("{verb} {c}")
                }
            })
            .collect();
        let sent = self.flow.sent;
        let mut s = if self.total(Action::New) > 0 && parts.is_empty() {
            let k = n(Action::New);
            if k == 1 {
                "1 employee goes to Microsoft for the first time: linked to the existing account with the same employee number, or given a new one.".to_string()
            } else {
                format!(
                    "{k} employees go to Microsoft for the first time: each is linked to the existing account with the same employee number, or gets a new one."
                )
            }
        } else if parts.is_empty() {
            if dry {
                format!("Nothing would change: all {sent} accounts are up to date.")
            } else {
                format!("Nothing changed: all {sent} accounts were already up to date.")
            }
        } else if dry {
            format!("Microsoft would {}.", join_and(&parts))
        } else {
            format!("Sent to Microsoft: {}.", join_and(&parts))
        };
        let p = self.problems();
        if p > 0 {
            let _ = write!(
                s,
                " {p} {} attention first.",
                if p == 1 { "needs" } else { "need" }
            );
        }
        s
    }
}

fn join_and(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [a] => a.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

// ------------------------------------------------------------------ directory (Entra)

/// One Entra user as the preview needs it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirUser {
    pub upn: String,
    pub employee_id: Option<String>,
    pub enabled: bool,
    /// AD distinguished name (synchronised users only).
    pub dn: Option<String>,
    pub synced: bool,
    /// Our attribute keys (see `scim::ATTRIBUTES`) → current value.
    pub values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directory {
    pub users: Vec<DirUser>,
    pub read_utc: String,
}

/// Graph properties read for the preview.
pub const DIR_SELECT: &str = "id,userPrincipalName,employeeId,displayName,givenName,surname,jobTitle,department,mail,companyName,officeLocation,mobilePhone,businessPhones,employeeType,employeeOrgData,streetAddress,postalCode,city,accountEnabled,onPremisesDistinguishedName,onPremisesSyncEnabled";

impl DirUser {
    pub fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| {
            v[k].as_str()
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
        };
        let upn = s("userPrincipalName")?;
        let mut values = BTreeMap::new();
        let mut put = |key: &str, val: Option<String>| {
            if let Some(x) = val {
                values.insert(key.to_string(), x);
            }
        };
        put("userName", Some(upn.clone()));
        put("displayName", s("displayName"));
        put("givenName", s("givenName"));
        put("familyName", s("surname"));
        put("title", s("jobTitle"));
        put("department", s("department"));
        put("email", s("mail"));
        put("organization", s("companyName"));
        put("officeLocation", s("officeLocation"));
        put("mobilePhone", s("mobilePhone"));
        put(
            "phoneWork",
            v["businessPhones"][0]
                .as_str()
                .filter(|x| !x.trim().is_empty())
                .map(str::to_string),
        );
        put("userType", s("employeeType"));
        put(
            "costCenter",
            v["employeeOrgData"]["costCenter"]
                .as_str()
                .filter(|x| !x.trim().is_empty())
                .map(str::to_string),
        );
        put("streetAddress", s("streetAddress"));
        put("postalCode", s("postalCode"));
        put("locality", s("city"));
        put(
            "manager",
            v["manager"]["employeeId"]
                .as_str()
                .filter(|x| !x.trim().is_empty())
                .map(str::to_string),
        );
        Some(DirUser {
            upn,
            employee_id: s("employeeId"),
            enabled: v["accountEnabled"].as_bool().unwrap_or(false),
            dn: s("onPremisesDistinguishedName"),
            synced: v["onPremisesSyncEnabled"].as_bool() == Some(true),
            values,
        })
    }
}

/// Reads every user (paged), with their manager's employee number.
pub fn read_directory(g: &Graph<'_>) -> GResult<Directory> {
    let users = g
        .get_all(&format!(
            "users?$select={DIR_SELECT}&$expand=manager($select=id,employeeId)&$top=100"
        ))?
        .iter()
        .filter_map(DirUser::from_json)
        .collect();
    Ok(Directory {
        users,
        read_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

/// Signs in with the preview identity and reads the directory. `Ok(None)`: no identity.
pub fn look_up(
    cfg: &Config,
    use_system_proxy: bool,
    sleep: &dyn Fn(std::time::Duration),
) -> Result<Option<Directory>, String> {
    let Some((_, id)) = cfg.preview_identity() else {
        return Ok(None);
    };
    let mut e = cfg.entra.clone();
    e.client_id = id.client_id.clone();
    e.auth = crate::config::AuthMode::Certificate;
    e.certificate_pem = Some(id.certificate_pem.clone());
    e.private_key_pem = Some(id.private_key_pem.clone());
    e.client_secret_env = None;
    let cred = crate::entra::Credential::from_config(&e).map_err(|x| x.to_string())?;
    let client = crate::http::build_client(e.timeout_secs, use_system_proxy, &cfg.tls)?;
    let tokens = crate::entra::TokenProvider::new(&e, &client, cred, sleep);
    let g = Graph::new(&e.graph_base, &client, tokens, sleep)?;
    read_directory(&g).map(Some).map_err(|x| x.to_string())
}

// ------------------------------------------------------------------ locations

/// Splits a distinguished name on the commas that are not escaped.
fn rdns(dn: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut esc_next = false;
    for c in dn.chars() {
        if esc_next {
            cur.push(c);
            esc_next = false;
        } else if c == '\\' {
            esc_next = true;
        } else if c == ',' {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

/// `OU=Sales,OU=Staff,DC=example,DC=com` → `example.com/Staff/Sales` (the canonical name
/// AD admins know from "Active Directory Users and Computers"). `None` without a DC part.
pub fn canonical_name(dn: &str) -> Option<String> {
    let mut dcs = Vec::new();
    let mut path = Vec::new();
    for r in rdns(dn) {
        let (k, v) = r.split_once('=')?;
        let v = v.trim();
        if v.is_empty() {
            return None;
        }
        match k.trim().to_ascii_uppercase().as_str() {
            "DC" => dcs.push(v.to_string()),
            "OU" | "CN" if dcs.is_empty() => path.push(v.to_string()),
            _ => return None,
        }
    }
    if dcs.is_empty() {
        return None;
    }
    path.reverse();
    let domain = dcs.join(".");
    Some(if path.is_empty() {
        domain
    } else {
        format!("{domain}/{}", path.join("/"))
    })
}

/// The container (OU) of an object: its DN without the first part.
pub fn container_of(dn: &str) -> Option<String> {
    let parts = rdns(dn);
    if parts.len() < 2 {
        return None;
    }
    // Rebuild without the object's own name; escape commas again.
    let rest: Vec<String> = parts[1..].iter().map(|p| p.replace(',', "\\,")).collect();
    canonical_name(&rest.join(","))
}

/// "Active Directory" for API-driven provisioning to AD (job id `API2AD…`), else "Entra ID".
pub fn target(cfg: &Config) -> &'static str {
    if cfg.entra.job_id.to_ascii_uppercase().starts_with("API2AAD") {
        "Entra ID"
    } else {
        "Active Directory"
    }
}

fn dir_location(u: &DirUser, target: &str) -> String {
    if target == "Entra ID" {
        return "Entra ID".into();
    }
    match (&u.dn, u.synced) {
        (Some(dn), true) => container_of(dn).unwrap_or_else(|| "Active Directory".into()),
        _ => "Entra ID (cloud only)".into(),
    }
}

// ------------------------------------------------------------------ building

/// Attribute keys this configuration sends at all (others are never compared).
pub fn configured_keys(cfg: &Config) -> BTreeSet<&'static str> {
    let f = &cfg.afas.fields;
    let x = &f.extra;
    let on = crate::config::ExtraFields::active;
    let mut k: BTreeSet<&'static str> = ["userName", "displayName", "givenName", "familyName"]
        .into_iter()
        .collect();
    for (key, mapped) in [
        ("title", f.job_title.is_some()),
        ("department", f.department.is_some()),
        ("manager", f.manager_id.is_some()),
        ("email", f.email.is_some()),
        ("costCenter", f.cost_center.is_some()),
        ("phoneWork", on(&x.phone_work).is_some()),
        ("mobilePhone", on(&x.phone_mobile).is_some()),
        ("officeLocation", on(&x.office).is_some()),
        ("organization", on(&x.company).is_some()),
        (
            "userType",
            on(&x.employee_type).is_some() || cfg.population.employee_type.is_some(),
        ),
        ("jobProfile", on(&x.job_profile).is_some()),
        ("streetAddress", on(&x.street).is_some()),
        ("postalCode", on(&x.postal_code).is_some()),
        ("locality", on(&x.city).is_some()),
        ("country", on(&x.country).is_some()),
        ("hireDate", x.send_hire_date),
        ("leaveDate", x.send_leave_date),
    ] {
        if mapped {
            k.insert(key);
        }
    }
    k
}

/// Keys that can be compared with Entra (others do not reach Entra by default, or are
/// written differently there: country `c` becomes a country name).
const DIR_KEYS: &[&str] = &[
    "userName",
    "displayName",
    "givenName",
    "familyName",
    "title",
    "department",
    "manager",
    "email",
    "phoneWork",
    "mobilePhone",
    "officeLocation",
    "organization",
    "userType",
    "costCenter",
    "streetAddress",
    "postalCode",
    "locality",
];

fn norm(key: &str, v: &str) -> String {
    let collapsed = v.split_whitespace().collect::<Vec<_>>().join(" ");
    match key {
        "userName" | "email" => collapsed.to_ascii_lowercase(),
        "phoneWork" | "mobilePhone" => collapsed.chars().filter(char::is_ascii_digit).collect(),
        "postalCode" => collapsed.replace(' ', "").to_ascii_uppercase(),
        _ => collapsed,
    }
}

fn change(key: &str, from: Option<&String>, to: Option<&String>) -> Option<Change> {
    let same = match (from, to) {
        (Some(a), Some(b)) => norm(key, a) == norm(key, b),
        (None, None) => true,
        _ => false,
    };
    if same {
        return None;
    }
    let a = attribute(key);
    Some(Change {
        key: key.to_string(),
        label: a.map_or(key, |a| a.label).to_string(),
        ad: a.map_or("", |a| a.ad).to_string(),
        from: from.cloned(),
        to: to.cloned(),
        kept: to.is_none(),
    })
}

fn diff(
    keys: &[&str],
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<Change> {
    keys.iter()
        .filter_map(|k| change(k, before.get(*k), after.get(*k)))
        .collect()
}

pub struct Input<'a> {
    pub cfg: &'a Config,
    pub plan: &'a Plan,
    pub previous: Option<&'a State>,
    pub directory: Option<&'a Directory>,
    /// The look-up in Entra was tried and failed.
    pub directory_error: Option<String>,
    pub apply: bool,
    pub created_utc: String,
}

fn local_time(cfg: &Config, rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| {
            t.with_timezone(&cfg.tz())
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| rfc3339.to_string())
}

fn ordered_keys(keys: &BTreeSet<&str>) -> Vec<&'static str> {
    crate::scim::ATTRIBUTES
        .iter()
        .map(|a| a.key)
        .filter(|k| keys.contains(k))
        .collect()
}

pub fn build(i: Input<'_>) -> Preview {
    let cfg = i.cfg;
    let plan = i.plan;
    let target = target(cfg);
    let configured = configured_keys(cfg);
    let all_keys = ordered_keys(&configured);
    let batch = (cfg.upload.batch_size as usize).max(1);
    let mut notes = Vec::new();

    let new_accounts = if target == "Entra ID" {
        "Entra ID".to_string()
    } else {
        cfg.preview
            .new_accounts_ou
            .as_deref()
            .and_then(canonical_name)
            .unwrap_or_else(|| "the target OU of the provisioning app".into())
    };

    // Names for manager values: "Mia Manager (00001)".
    let names: HashMap<&str, &str> = plan
        .records
        .iter()
        .map(|r| {
            (
                r.employee.employee_id.as_str(),
                r.employee.display_name.as_str(),
            )
        })
        .collect();
    let who = |id: &str| match names.get(id) {
        Some(n) => format!("{n} ({id})"),
        None => id.to_string(),
    };
    let show_manager = |c: &mut Change| {
        if c.key == "manager" {
            c.from = c.from.as_deref().map(who);
            c.to = c.to.as_deref().map(who);
        }
    };

    // Directory indexes.
    let mut by_emp: HashMap<&str, &DirUser> = HashMap::new();
    let mut dup_emp: BTreeSet<&str> = BTreeSet::new();
    let mut by_upn: HashMap<String, &DirUser> = HashMap::new();
    let mut dir_keys: Vec<&str> = Vec::new();
    if let Some(d) = i.directory {
        for u in &d.users {
            if let Some(e) = u.employee_id.as_deref()
                && by_emp.insert(e, u).is_some()
            {
                dup_emp.insert(e);
            }
            by_upn.insert(u.upn.to_ascii_lowercase(), u);
        }
        // An attribute that no matched account has in Entra is not synchronised there:
        // comparing it would mark every account as changed.
        let matched: Vec<&DirUser> = plan
            .records
            .iter()
            .filter_map(|r| by_emp.get(r.employee.employee_id.as_str()).copied())
            .collect();
        let mut hidden = Vec::new();
        for k in DIR_KEYS.iter().copied().filter(|k| configured.contains(k)) {
            if matched.is_empty() || matched.iter().any(|u| u.values.contains_key(k)) {
                dir_keys.push(k);
            } else if let Some(a) = attribute(k) {
                hidden.push(a.label);
            }
        }
        let not_in_dir: Vec<&str> = all_keys
            .iter()
            .copied()
            .filter(|k| !DIR_KEYS.contains(k))
            .filter_map(|k| attribute(k).map(|a| a.label))
            .collect();
        hidden.extend(not_in_dir);
        if !hidden.is_empty() && !matched.is_empty() {
            notes.push(format!(
                "Not visible in Entra, so changes to these values cannot be shown: {}. They are still sent.",
                hidden.join(", ")
            ));
        }
    }
    let dir_keys = ordered_keys(&dir_keys.into_iter().collect());

    let (source, compared_with) = match (i.directory, i.previous) {
        (Some(d), _) => (
            Source::Entra,
            format!(
                "Compared with Entra ID as it is now ({} accounts, read at {}). Values reach Entra from AD through Connect Sync, so a change from the last half hour may not show yet.",
                d.users.len(),
                local_time(cfg, &d.read_utc)
            ),
        ),
        (None, Some(p)) => (
            Source::LastRun,
            format!(
                "Compared with what the last successful sync sent ({}).{}",
                local_time(cfg, &p.last_success_utc),
                if i.directory_error.is_none() && cfg.preview_identity().is_none() {
                    " Add a [preview] app registration to compare with Entra itself and to see where each account lives."
                } else {
                    ""
                }
            ),
        ),
        (None, None) => (
            Source::Nothing,
            "Nothing to compare with yet: this is the first run. Add a [preview] app registration to see which accounts already exist and where.".to_string(),
        ),
    };
    if let Some(e) = &i.directory_error {
        notes.insert(
            0,
            format!(
                "The look-up in Entra failed ({e}); compared with the last successful sync instead."
            ),
        );
    }

    let today = plan.today;
    let mut rows = Vec::with_capacity(plan.records.len());
    for (idx, r) in plan.records.iter().enumerate() {
        let mut row = sent_row(r, idx / batch + 1);
        let intended = sent_values(r);
        let id = r.employee.employee_id.as_str();
        let reason = state_reason(r, today, cfg);
        if i.directory.is_some() {
            let by_id = (!dup_emp.contains(id)).then(|| by_emp.get(id)).flatten();
            if dup_emp.contains(id) {
                row.action = Action::Conflict;
                row.note = Some(format!(
                    "Employee number {id} is on more than one account in Entra. Microsoft cannot tell which one is meant: remove the number from the wrong account first."
                ));
            } else if let Some(u) = by_id {
                row.changes = diff(&dir_keys, &u.values, &intended);
                row.location = Some(dir_location(u, target));
                row.action = if r.active && !u.enabled {
                    Action::Enable
                } else if !r.active && u.enabled {
                    Action::Disable
                } else if row.changes.iter().any(|c| !c.kept) {
                    Action::Update
                } else {
                    Action::Unchanged
                };
                row.note = reason.for_action(row.action);
            } else if let Some(u) = by_upn.get(&r.employee.upn.to_ascii_lowercase()) {
                row.location = Some(dir_location(u, target));
                match &u.employee_id {
                    None => {
                        row.action = Action::LinkFirst;
                        row.note = Some(format!(
                            "An account with this sign-in name already exists, without employee number. Microsoft finds accounts only by employee number (employeeID), so it would try to create a second one. Set employeeID {id} on the existing account first (guide, step 5d)."
                        ));
                    }
                    Some(other) => {
                        row.action = Action::Conflict;
                        row.note = Some(format!(
                            "This sign-in name belongs to employee number {other} in Entra. Find out which one is right before the first real run."
                        ));
                    }
                }
            } else {
                created(&mut row, r, &intended, &all_keys, &new_accounts, &reason);
                if !r.active && r.employee.start_date <= today {
                    row.note = Some(
                        "Departed, but no account exists: Microsoft creates a disabled account. Keep policy.leaver_lookback_days short to avoid this."
                            .into(),
                    );
                }
            }
        } else if let Some(p) = i.previous.and_then(|s| s.records.get(id)) {
            row.location = None;
            if p.sent.is_empty() {
                row.action = if p.active != r.active {
                    if r.active {
                        Action::Enable
                    } else {
                        Action::Disable
                    }
                } else {
                    Action::Resend
                };
                row.note = reason.for_action(row.action).or_else(|| {
                    Some("The values sent before are not known yet (state from an older version); from the next run on, changes show here.".into())
                });
            } else {
                row.changes = diff(&all_keys, &p.sent, &intended);
                row.action = if r.active && !p.active {
                    Action::Enable
                } else if !r.active && p.active {
                    Action::Disable
                } else if row.changes.iter().any(|c| !c.kept) {
                    Action::Update
                } else {
                    Action::Unchanged
                };
                row.note = reason.for_action(row.action);
                if p.is_missing() {
                    row.note = Some(format!(
                        "Back in AFAS (missing since {}).",
                        p.missing_since.map(|d| d.to_string()).unwrap_or_default()
                    ));
                }
            }
        } else if i.previous.is_some() {
            created(&mut row, r, &intended, &all_keys, &new_accounts, &reason);
            row.note = Some(format!(
                "{} New since the last run: Microsoft creates the account, unless an AD account already has employeeID {id}; then that one is used.",
                reason.text.clone().unwrap_or_default()
            ).trim().to_string());
        } else {
            row.action = Action::New;
            row.changes = diff(&all_keys, &BTreeMap::new(), &intended);
            row.note = Some(format!(
                "First run: Microsoft uses the AD account whose employeeID is {id}, or creates a new one{}.",
                if r.active { "" } else { " (disabled)" }
            ));
        }
        for c in &mut row.changes {
            show_manager(c);
        }
        rows.push(row);
    }

    // Not in the upload.
    let dir_of = |id: &str| by_emp.get(id).copied();
    for x in &plan.exclusions {
        let id = x.employee_id.as_deref();
        let prev = id.and_then(|i2| i.previous.and_then(|s| s.records.get(i2)));
        let u = id.and_then(dir_of);
        rows.push(Row {
            action: Action::Skipped,
            employee_id: x.employee_id.clone(),
            name: u
                .and_then(|u| u.values.get("displayName").cloned())
                .or_else(|| prev.and_then(|p| p.sent.get("displayName").cloned())),
            upn: u
                .map(|u| u.upn.clone())
                .or_else(|| prev.and_then(|p| p.upn().map(str::to_string))),
            department: None,
            location: u.map(|u| dir_location(u, target)),
            enabled_after: None,
            call: None,
            changes: Vec::new(),
            note: Some(format!(
                "{}. Not sent: the account stays as it is until this is fixed in AFAS.",
                capitalise(&x.reason)
            )),
        });
    }
    for m in &plan.missing {
        let u = dir_of(&m.employee_id);
        rows.push(Row {
            action: Action::Missing,
            employee_id: Some(m.employee_id.clone()),
            name: m
                .display_name
                .clone()
                .or_else(|| u.and_then(|u| u.values.get("displayName").cloned())),
            upn: m.upn.clone().or_else(|| u.map(|u| u.upn.clone())),
            department: None,
            location: u.map(|u| dir_location(u, target)),
            enabled_after: u.map(|u| u.enabled),
            call: None,
            changes: Vec::new(),
            note: Some(match &m.excluded_because {
                Some(why) => format!(
                    "Sent as active before, now skipped because of a data error ({why}). The account is not disabled automatically."
                ),
                None => format!(
                    "Sent as active before, not in AFAS since {}. The account is not disabled automatically: enter an end date in AFAS, or disable it and mark it handled (missing ack).",
                    m.since
                ),
            }),
        });
    }
    for o in &plan.outside_window {
        let e = &o.employee;
        let note = if o.later {
            let from = e
                .start_date
                .checked_sub_days(Days::new(u64::from(cfg.policy.prehire_days)))
                .unwrap_or(e.start_date);
            format!(
                "Starts on {}: the account is created (disabled) from {from}.",
                e.start_date
            )
        } else {
            let last = e.end_date.and_then(|d| {
                d.checked_add_days(Days::new(u64::from(cfg.policy.leaver_lookback_days)))
            });
            format!(
                "Left on {}; no longer sent after {}.",
                e.end_date.map(|d| d.to_string()).unwrap_or_default(),
                last.map(|d| d.to_string()).unwrap_or_default()
            )
        };
        let u = dir_of(&e.employee_id);
        rows.push(Row {
            action: if o.later {
                Action::Later
            } else {
                Action::NotSent
            },
            employee_id: Some(e.employee_id.clone()),
            name: Some(e.display_name.clone()),
            upn: Some(e.upn.clone()),
            department: e.department.clone(),
            location: u.map(|u| dir_location(u, target)),
            enabled_after: None,
            call: None,
            changes: Vec::new(),
            note: Some(note),
        });
    }

    let mut totals: BTreeMap<Action, usize> = BTreeMap::new();
    for r in &rows {
        *totals.entry(r.action).or_default() += 1;
    }
    let c = &plan.counts;
    Preview {
        version: PREVIEW_VERSION,
        mode: if i.apply { "apply" } else { "dry-run" }.into(),
        created_utc: i.created_utc,
        today: today.to_string(),
        population: cfg.population.name.clone(),
        target: target.into(),
        source,
        compared_with,
        new_accounts,
        batch_size: batch,
        calls: c.api_calls_needed,
        flow: Flow {
            rows_fetched: c.rows_fetched,
            valid: c.sent_total + c.skipped_future_start + c.skipped_old_leaver,
            excluded: c.excluded_errors,
            merged: c.identical_duplicates_merged,
            later: c.skipped_future_start,
            left_earlier: c.skipped_old_leaver,
            carried: c.sent_inactive_outside_window,
            sent: c.sent_total,
        },
        totals,
        notes,
        rows,
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn sent_row(r: &PlannedRecord, call: usize) -> Row {
    let e = &r.employee;
    Row {
        action: Action::Unchanged,
        employee_id: Some(e.employee_id.clone()),
        name: Some(e.display_name.clone()),
        upn: Some(e.upn.clone()),
        department: e.department.clone(),
        location: None,
        enabled_after: Some(r.active),
        call: Some(call),
        changes: Vec::new(),
        note: None,
    }
}

fn created(
    row: &mut Row,
    r: &PlannedRecord,
    intended: &BTreeMap<String, String>,
    keys: &[&str],
    location: &str,
    reason: &Reason,
) {
    row.action = if r.active {
        Action::Create
    } else {
        Action::CreateDisabled
    };
    row.location = Some(location.to_string());
    let shown: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|k| !matches!(*k, "userName" | "givenName" | "familyName" | "displayName"))
        .collect();
    row.changes = diff(&shown, &BTreeMap::new(), intended);
    row.note = reason.for_action(row.action);
}

/// Why the account is enabled or disabled, in words.
struct Reason {
    text: Option<String>,
}

impl Reason {
    fn for_action(&self, a: Action) -> Option<String> {
        match a {
            Action::Enable | Action::Disable | Action::Create | Action::CreateDisabled => {
                self.text.clone()
            }
            _ => None,
        }
    }
}

fn state_reason(r: &PlannedRecord, today: chrono::NaiveDate, cfg: &Config) -> Reason {
    let e = &r.employee;
    let text = if r.outside_window {
        Some(match e.end_date {
            Some(end) if end < today => format!(
                "Left on {end}, longer ago than {} days: sent once more as disabled so the account does not stay enabled.",
                cfg.policy.leaver_lookback_days
            ),
            _ => format!("Starts again on {}: disabled until then.", e.start_date),
        })
    } else if r.active {
        (e.start_date == today).then(|| "Start date today.".to_string())
    } else if e.start_date > today {
        Some(format!(
            "New hire: starts on {}, the account is enabled on that day.",
            e.start_date
        ))
    } else {
        e.end_date
            .map(|end| format!("Left on {end}: disabled from the day after."))
    };
    Reason { text }
}

// ------------------------------------------------------------------ demo

/// A realistic example (fictional people) to see the preview without AFAS.
pub fn demo() -> Preview {
    let ch = |key: &str, from: Option<&str>, to: Option<&str>| {
        let a = attribute(key);
        Change {
            key: key.into(),
            label: a.map_or(key, |a| a.label).into(),
            ad: a.map_or("", |a| a.ad).into(),
            from: from.map(str::to_string),
            to: to.map(str::to_string),
            kept: to.is_none(),
        }
    };
    let row = |action: Action,
               id: &str,
               name: &str,
               upn: &str,
               dept: &str,
               loc: Option<&str>,
               on: Option<bool>,
               call: Option<usize>,
               changes: Vec<Change>,
               note: Option<&str>| Row {
        action,
        employee_id: Some(id.into()),
        name: Some(name.into()),
        upn: Some(upn.into()),
        department: Some(dept.into()),
        location: loc.map(str::to_string),
        enabled_after: on,
        call,
        changes,
        note: note.map(str::to_string),
    };
    let sales = Some("example.com/Staff/Sales");
    let fin = Some("example.com/Staff/Finance");
    let ict = Some("example.com/Staff/ICT");
    let new = Some("example.com/Staff/New hires");
    let mut rows = vec![
        row(
            Action::Update,
            "10011",
            "Piet Bakker",
            "p.bakker@example.com",
            "Sales",
            sales,
            Some(true),
            Some(1),
            vec![
                ch("title", Some("Adviseur"), Some("Senior adviseur")),
                ch(
                    "manager",
                    Some("Mia de Groot (10002)"),
                    Some("Kees Visser (10007)"),
                ),
            ],
            None,
        ),
        row(
            Action::Unchanged,
            "10012",
            "Fatima el Amrani",
            "f.elamrani@example.com",
            "Finance",
            fin,
            Some(true),
            Some(1),
            vec![],
            None,
        ),
        row(
            Action::Disable,
            "10019",
            "Bram Hendriks",
            "b.hendriks@example.com",
            "ICT",
            ict,
            Some(false),
            Some(1),
            vec![],
            Some("Left on 2026-11-02: disabled from the day after."),
        ),
        row(
            Action::Update,
            "10023",
            "Sanne Jansen",
            "s.jansen@example.com",
            "Finance",
            fin,
            Some(true),
            Some(1),
            vec![
                ch("department", Some("Sales"), Some("Finance")),
                ch("officeLocation", Some("Utrecht"), Some("Amersfoort")),
            ],
            None,
        ),
        row(
            Action::Unchanged,
            "10031",
            "Lucas de Wit",
            "l.dewit@example.com",
            "ICT",
            ict,
            Some(true),
            Some(1),
            vec![],
            None,
        ),
        row(
            Action::LinkFirst,
            "10044",
            "Noor Bos",
            "n.bos@example.com",
            "Sales",
            sales,
            Some(true),
            Some(1),
            vec![],
            Some(
                "An account with this sign-in name already exists, without employee number. Microsoft finds accounts only by employee number (employeeID), so it would try to create a second one. Set employeeID 10044 on the existing account first (guide, step 5d).",
            ),
        ),
        row(
            Action::Enable,
            "10052",
            "Daan Smit",
            "d.smit@example.com",
            "Sales",
            sales,
            Some(true),
            Some(2),
            vec![],
            Some("Start date today."),
        ),
        row(
            Action::Update,
            "10058",
            "Eva Mulder",
            "e.mulder@example.com",
            "ICT",
            ict,
            Some(true),
            Some(2),
            vec![
                ch(
                    "userName",
                    Some("e.vandijk@example.com"),
                    Some("e.mulder@example.com"),
                ),
                ch("displayName", Some("Eva van Dijk"), Some("Eva Mulder")),
                ch("familyName", Some("van Dijk"), Some("Mulder")),
            ],
            None,
        ),
        row(
            Action::CreateDisabled,
            "10071",
            "Jan de Vries",
            "j.devries@example.com",
            "Sales",
            new,
            Some(false),
            Some(2),
            vec![
                ch("title", None, Some("Accountmanager")),
                ch("department", None, Some("Sales")),
                ch("manager", None, Some("Kees Visser (10007)")),
                ch("email", None, Some("j.devries@example.com")),
            ],
            Some("New hire: starts on 2026-11-16, the account is enabled on that day."),
        ),
        row(
            Action::Create,
            "10072",
            "Yara Peters",
            "y.peters@example.com",
            "Finance",
            new,
            Some(true),
            Some(2),
            vec![
                ch("title", None, Some("Controller")),
                ch("department", None, Some("Finance")),
                ch("manager", None, Some("Mia de Groot (10002)")),
            ],
            Some("Start date today."),
        ),
        row(
            Action::Unchanged,
            "10075",
            "Thomas Kok",
            "t.kok@example.com",
            "Finance",
            fin,
            Some(true),
            Some(2),
            vec![ch("department", Some("Control"), None)],
            None,
        ),
    ];
    for k in 0..36 {
        let n = 10100 + k * 3;
        let (dept, loc) = match k % 3 {
            0 => ("Sales", sales),
            1 => ("Finance", fin),
            _ => ("ICT", ict),
        };
        rows.push(row(
            Action::Unchanged,
            &n.to_string(),
            &format!("Colleague {n}"),
            &format!("colleague{n}@example.com"),
            dept,
            loc,
            Some(true),
            Some(3 + k / 12),
            vec![],
            None,
        ));
    }
    rows.extend([
        row(Action::Skipped, "10090", "Rik van Leeuwen", "rik.vanleeuwen@example", "Sales", sales, None, None, vec![],
            Some("UPN 'rik.vanleeuwen@example': domain 'example' is not in allowed_upn_domains. Not sent: the account stays as it is until this is fixed in AFAS.")),
        row(Action::Missing, "10008", "Anouk Vermeer", "a.vermeer@example.com", "ICT", ict, Some(true), None, vec![],
            Some("Sent as active before, not in AFAS since 2026-10-28. The account is not disabled automatically: enter an end date in AFAS, or disable it and mark it handled (missing ack).")),
        row(Action::Later, "10080", "Milan Dekker", "m.dekker@example.com", "ICT", None, None, None, vec![],
            Some("Starts on 2026-12-01: the account is created (disabled) from 2026-11-17.")),
        row(Action::NotSent, "10003", "Gerard Pauw", "g.pauw@example.com", "Sales", None, None, None, vec![],
            Some("Left on 2026-08-31; no longer sent after 2026-09-30.")),
    ]);
    let mut totals = BTreeMap::new();
    for r in &rows {
        *totals.entry(r.action).or_default() += 1;
    }
    let sent = rows.iter().filter(|r| r.action.in_upload()).count();
    Preview {
        version: PREVIEW_VERSION,
        mode: "dry-run".into(),
        created_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        today: chrono::Utc::now().date_naive().to_string(),
        population: None,
        target: "Active Directory".into(),
        source: Source::Entra,
        compared_with: "Example data (fictional people): compared with Entra ID as it is now. Values reach Entra from AD through Connect Sync, so a change from the last half hour may not show yet.".into(),
        new_accounts: "example.com/Staff/New hires".into(),
        batch_size: 12,
        calls: sent.div_ceil(12),
        flow: Flow {
            rows_fetched: 52,
            valid: 51,
            excluded: 1,
            merged: 0,
            later: 1,
            left_earlier: 1,
            carried: 0,
            sent,
        },
        totals,
        notes: vec!["Not visible in Entra, so changes to these values cannot be shown: Cost center. They are still sent.".into()],
        rows,
    }
}

// ------------------------------------------------------------------ filters

/// Which rows a view shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Show {
    /// Changes and problems (the default).
    Changes,
    Problems,
    /// Everything in the upload.
    Upload,
    NotSent,
    All,
}

impl Show {
    pub fn parse(s: &str) -> Show {
        match s {
            "problems" => Show::Problems,
            "upload" => Show::Upload,
            "notsent" => Show::NotSent,
            "all" => Show::All,
            _ => Show::Changes,
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Show::Changes => "changes",
            Show::Problems => "problems",
            Show::Upload => "upload",
            Show::NotSent => "notsent",
            Show::All => "all",
        }
    }

    /// Like `includes`, but a row "without changes" that keeps a value AFAS emptied also
    /// counts as a change: AD keeps something HR removed.
    pub fn includes_row(self, r: &Row) -> bool {
        self.includes(r.action)
            || (self == Show::Changes && r.action.in_upload() && r.changes.iter().any(|c| c.kept))
    }

    pub fn includes(self, a: Action) -> bool {
        match self {
            Show::Changes => a.is_change() || a.is_problem(),
            Show::Problems => a.is_problem(),
            Show::Upload => a.in_upload(),
            Show::NotSent => !a.in_upload(),
            Show::All => true,
        }
    }
}

// ------------------------------------------------------------------ text (terminal)

fn cut(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        format!("{s:<n$}")
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn paint(color: bool, code: &str, s: &str) -> String {
    if color {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

fn tone_code(tone: &str) -> &'static str {
    match tone {
        "add" => "32",
        "pre" => "36",
        "on" => "1;36",
        "off" => "31",
        "upd" => "33",
        "warn" => "1;33",
        "bad" => "1;31",
        "new" => "34",
        _ => "2",
    }
}

fn change_text(c: &Change) -> String {
    let dash = "—".to_string();
    match (&c.from, &c.to, c.kept) {
        (Some(f), None, true) => format!("{f} stays (empty in AFAS, so not sent)"),
        (None, Some(t), _) => t.clone(),
        (f, t, _) => format!(
            "{} → {}",
            f.as_ref().unwrap_or(&dash),
            t.as_ref().unwrap_or(&dash)
        ),
    }
}

/// The preview as terminal lines: totals, then a table of the rows `show` selects.
pub fn render_text(p: &Preview, show: Show, color: bool, max_rows: usize) -> Vec<String> {
    let mut out = Vec::new();
    let title = if p.mode == "apply" {
        "What this sync sent"
    } else {
        "What the sync would do"
    };
    out.push(paint(color, "1", title));
    out.push(p.headline());
    out.push(paint(color, "2", &p.compared_with));
    for n in &p.notes {
        out.push(paint(color, "2", n));
    }
    out.push(String::new());
    let mut chips = Vec::new();
    for a in Action::ALL {
        let n = p.total(a);
        if n > 0 {
            chips.push(paint(
                color,
                tone_code(a.tone()),
                &format!("{} {} {n}", a.symbol(), a.label()),
            ));
        }
    }
    out.push(format!("  {}", chips.join("   ")));
    out.push(String::new());
    let rows: Vec<&Row> = p.rows.iter().filter(|r| show.includes_row(r)).collect();
    if rows.is_empty() {
        out.push("  Nothing to show here.".into());
        return out;
    }
    let head = format!(
        "  {}  {}  {}  {}  {}",
        cut("Call", 5),
        cut("Action", 18),
        cut("Employee", 30),
        cut("Sign-in name", 30),
        "Where"
    );
    out.push(paint(color, "1", &head));
    out.push(paint(
        color,
        "2",
        &format!(
            "  {}  {}  {}  {}  {}",
            "─".repeat(5),
            "─".repeat(18),
            "─".repeat(30),
            "─".repeat(30),
            "─".repeat(24)
        ),
    ));
    let indent = " ".repeat(2 + 5 + 2 + 18 + 2);
    for r in rows.iter().take(max_rows) {
        let call = r
            .call
            .map(|c| format!("{c}/{}", p.calls))
            .unwrap_or_else(|| "—".into());
        let who = match (&r.name, &r.employee_id) {
            (Some(n), Some(id)) => format!("{n} · {id}"),
            (None, Some(id)) => id.clone(),
            (Some(n), None) => n.clone(),
            (None, None) => "(no employee number)".into(),
        };
        let action = paint(
            color,
            tone_code(r.action.tone()),
            &cut(&format!("{} {}", r.action.symbol(), r.action.label()), 18),
        );
        out.push(format!(
            "  {}  {action}  {}  {}  {}",
            cut(&call, 5),
            cut(&who, 30),
            cut(r.upn.as_deref().unwrap_or("—"), 30),
            r.location.as_deref().unwrap_or("—")
        ));
        for c in &r.changes {
            out.push(format!(
                "{indent}{} {}",
                paint(color, "2", &cut(&c.label, 18)),
                change_text(c)
            ));
        }
        if let Some(n) = &r.note {
            out.push(format!("{indent}{}", paint(color, "2", n)));
        }
    }
    if rows.len() > max_rows {
        out.push(format!(
            "  … and {} more (afas-entra-sync preview --all, or --html for the whole table)",
            rows.len() - max_rows
        ));
    }
    let hidden = p.rows.len() - rows.len();
    if hidden > 0 && show == Show::Changes {
        out.push(String::new());
        out.push(paint(
            color,
            "2",
            &format!(
                "  {} without changes or not sent are not listed: afas-entra-sync preview --all",
                hidden
            ),
        ));
    }
    out
}

// ------------------------------------------------------------------ CSV

fn csv_cell(s: &str) -> String {
    // Leading = + - @ would be run as a formula by spreadsheet programs.
    let s = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r', ';']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn render_csv(p: &Preview) -> String {
    let mut s = String::from(
        "call,action,employee_number,name,sign_in_name,department,where,enabled_after,changes,note\n",
    );
    for r in &p.rows {
        let changes = r
            .changes
            .iter()
            .map(|c| format!("{}: {}", c.label, change_text(c)))
            .collect::<Vec<_>>()
            .join("; ");
        let cells = [
            r.call.map(|c| c.to_string()).unwrap_or_default(),
            r.action.label().to_string(),
            r.employee_id.clone().unwrap_or_default(),
            r.name.clone().unwrap_or_default(),
            r.upn.clone().unwrap_or_default(),
            r.department.clone().unwrap_or_default(),
            r.location.clone().unwrap_or_default(),
            match r.enabled_after {
                Some(true) => "enabled".into(),
                Some(false) => "disabled".into(),
                None => String::new(),
            },
            changes,
            r.note.clone().unwrap_or_default(),
        ];
        s.push_str(
            &cells
                .iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        s.push('\n');
    }
    s
}

// ------------------------------------------------------------------ HTML

/// Extra styling for the preview, on top of the GUI's. No JavaScript: the table fills
/// up with CSS animations only, and not at all for people who prefer reduced motion.
pub const PREVIEW_CSS: &str = r#"
.pv-hero{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:22px 24px;margin:0 0 28px;position:relative;overflow:hidden}
.pv-hero::before{content:"";position:absolute;inset:0 auto 0 0;width:6px;background:var(--accent)}
.pv-hero.warn::before{background:var(--warn)}.pv-hero.bad::before{background:var(--bad)}
.pv-hero h2{font-size:25px;line-height:1.25;margin:4px 0 8px;max-width:40ch}
.pv-hero p{margin:0;color:var(--muted);max-width:78ch}.pv-hero .kicker{margin-bottom:2px}
.pv-notes{margin:10px 0 0;padding:0;list-style:none;color:var(--muted);font-size:14.5px}.pv-notes li::before{content:"i";display:inline-block;width:18px;height:18px;line-height:18px;text-align:center;border-radius:50%;background:var(--bg);font-size:12px;font-weight:700;margin-right:8px;font-style:italic}
.pipe{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));margin:0 0 34px;padding:0;list-style:none}
.pipe li{position:relative;background:var(--surface);border:1px solid var(--line);border-left:0;padding:14px 16px 14px 22px;opacity:0;animation:pv-in .5s ease-out forwards}
.pipe li:first-child{border-left:1px solid var(--line);border-radius:10px 0 0 10px;padding-left:16px}.pipe li:last-child{border-radius:0 10px 10px 0}
.pipe li:not(:last-child)::after{content:"";position:absolute;right:-9px;top:50%;width:16px;height:16px;background:var(--surface);border-top:1px solid var(--line);border-right:1px solid var(--line);transform:translateY(-50%) rotate(45deg);z-index:1}
.pipe li:nth-child(2){animation-delay:.18s}.pipe li:nth-child(3){animation-delay:.36s}.pipe li:nth-child(4){animation-delay:.54s}.pipe li:nth-child(5){animation-delay:.72s}
.pipe .k{display:block;color:var(--muted);font-size:12px;font-weight:600;letter-spacing:.07em;text-transform:uppercase}
.pipe .n{display:block;font-size:26px;font-weight:600;letter-spacing:-.02em;line-height:1.2;margin:2px 0}
.pipe small{font-size:13px}.pipe li.hl{background:color-mix(in srgb,var(--accent) 9%,var(--surface))}.pipe li.hl::after{background:color-mix(in srgb,var(--accent) 9%,var(--surface))}
@keyframes pv-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.where{list-style:none;margin:0;padding:0;border-top:1px solid var(--line)}
.where li{display:grid;grid-template-columns:minmax(0,1.3fr) 4.5em minmax(0,1.5fr);gap:16px;align-items:center;padding:10px 0;border-bottom:1px solid var(--line)}
.where .path{overflow-wrap:anywhere}.where .path span{color:var(--muted)}.where .path b{font-weight:600}.where .cnt{text-align:right;font-weight:600}
.where .new-ou{font-size:12px;font-weight:600;color:var(--accent);margin-left:8px;white-space:nowrap}
.stack{display:flex;height:14px;border-radius:4px;overflow:hidden;background:var(--line);gap:1px;transform-origin:left;animation:pv-grow .9s ease-out both .9s}.stack span{min-width:3px}
@keyframes pv-grow{from{transform:scaleX(0)}to{transform:scaleX(1)}}
.mix{display:flex;flex-wrap:wrap;gap:4px 12px;font-size:13px;color:var(--muted);margin-top:4px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 18px}
.act{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;font-weight:600;padding:2px 10px 2px 8px;border-radius:999px;white-space:nowrap;line-height:1.6}
.act::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;flex:none}
.t-add{background:#dcf1e4;color:#1a5c37}.t-pre{background:#dcecee;color:#0b5a5e}.t-on{background:#0b6b70;color:#fff}.t-off{background:#f7dedb;color:#8f1f18}
.t-upd{background:#f8ead2;color:#7a4600}.t-same{background:transparent;color:var(--muted);box-shadow:inset 0 0 0 1px var(--line)}.t-new{background:#dfe6f6;color:#26407a}
.t-warn{background:#975400;color:#fff}.t-bad{background:#b0261e;color:#fff}.t-skip{background:var(--bg);color:var(--muted)}
.b-add{background:#2f9a5e}.b-pre{background:#6aa8ab}.b-on{background:#0b6b70}.b-off{background:#c4493f}.b-upd{background:#d6962f}.b-same{background:var(--s-skip)}.b-new{background:#5874b8}.b-warn{background:#975400}.b-bad{background:#b0261e}.b-skip{background:var(--line)}
@media (prefers-color-scheme:dark){.t-add{background:#173a27;color:#8fdcae}.t-pre{background:#123537;color:#8fcfd2}.t-on{background:#4fb0b3;color:#06282a}.t-off{background:#43201d;color:#f2a49d}
.t-upd{background:#3d2d12;color:#efc27a}.t-new{background:#1d2a47;color:#a9bdf0}.t-warn{background:#e0a24a;color:#2a1800}.t-bad{background:#ef7b72;color:#2a0805}
.b-add{background:#5cc28a}.b-pre{background:#2f7a7d}.b-on{background:#4fb0b3}.b-off{background:#ef7b72}.b-upd{background:#e0a24a}.b-new{background:#7f9be0}}
.tabs{display:flex;flex-wrap:wrap;gap:2px;border-bottom:1px solid var(--line);margin:0 0 14px}
.tabs a{padding:8px 14px;text-decoration:none;color:var(--muted);border-bottom:3px solid transparent;margin-bottom:-1px;border-radius:6px 6px 0 0}
.tabs a:hover{color:var(--ink);background:var(--surface)}.tabs a[aria-current]{color:var(--ink);border-color:var(--accent);font-weight:600}.tabs a span{font-variant-numeric:tabular-nums;color:var(--muted);font-weight:400;margin-left:4px}
.fillbar{display:flex;align-items:center;gap:14px;margin:0 0 12px;font-size:13.5px;color:var(--muted)}
.fillbar .track{flex:1;height:6px;border-radius:3px;background:var(--line);overflow:hidden}
.fillbar .track span{display:block;height:100%;width:100%;background:var(--accent);transform-origin:left;animation:pv-grow var(--dur) linear both .9s}
.fillbar a{white-space:nowrap}
.tablewrap{overflow-x:auto;border-radius:8px}
table.pv{min-width:760px}table.pv td{font-size:14.5px}table.pv td.c{color:var(--muted);font-size:13px;white-space:nowrap;width:3.5em}
table.pv td.who{min-width:13em;max-width:20em}table.pv td.who b{display:block;font-weight:600}table.pv td.who small{font-size:12.5px;line-height:1.4}
table.pv td.who .upn{overflow-wrap:anywhere}table.pv td.loc{color:var(--muted);font-size:13.5px;min-width:9em;max-width:13em;overflow-wrap:break-word}
table.pv td.what{min-width:16em}table.pv th{white-space:nowrap}
table.pv td.st{white-space:nowrap;font-size:13.5px}.st .on{color:var(--ok)}.st .off{color:var(--muted)}
table.pv tbody tr{animation:pv-row .55s ease-out both;animation-delay:calc(var(--i,0) * 38ms + .9s)}
table.pv tr.callrow td{background:var(--bg);color:var(--muted);font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;padding:6px 12px}
table.pv tr.problem td:first-child{box-shadow:inset 3px 0 0 var(--warn)}
@keyframes pv-row{0%{opacity:0;transform:translateY(5px);background:color-mix(in srgb,var(--accent) 16%,transparent)}45%{opacity:1;transform:none;background:color-mix(in srgb,var(--accent) 16%,transparent)}100%{opacity:1;background:transparent}}
.chg{display:block;line-height:1.45;margin:1px 0}.chg b{font-weight:600;color:var(--muted);font-size:12.5px;margin-right:6px}
.chg del{color:var(--muted);text-decoration-color:color-mix(in srgb,var(--muted) 60%,transparent)}.chg ins{text-decoration:none;font-weight:600}.chg em{color:var(--warn);font-style:normal;font-size:13px}
.why{display:block;color:var(--muted);font-size:13.5px;margin-top:2px;max-width:56ch}
.pv-empty{background:var(--surface);border:1px dashed var(--line);border-radius:10px;padding:22px;color:var(--muted)}
details.more{margin:18px 0}details.more summary{cursor:pointer;font-weight:600;padding:8px 0}
.standalone main{max-width:1180px;margin:0 auto}main:has(.pv-hero){max-width:1200px}
@media (max-width:900px){.pipe{grid-template-columns:1fr 1fr}.pipe li{border-left:1px solid var(--line);border-radius:10px!important;margin:0 8px 8px 0}.pipe li::after{display:none}.where li{grid-template-columns:1fr 3.5em}.where .pv-bar{grid-column:1/-1}}
@media (prefers-reduced-motion:reduce){.pipe li,table.pv tbody tr,.stack,.fillbar .track span{animation:none!important;opacity:1!important;transform:none!important}}
"#;

fn badge(a: Action) -> String {
    format!("<span class=\"act t-{}\">{}</span>", a.tone(), a.label())
}

fn time_label(p: &Preview, tz: Option<chrono_tz::Tz>) -> String {
    chrono::DateTime::parse_from_rfc3339(&p.created_utc)
        .map(|t| match tz {
            Some(z) => t
                .with_timezone(&z)
                .format("%a %-d %b %Y, %H:%M")
                .to_string(),
            None => t.format("%a %-d %b %Y, %H:%M UTC").to_string(),
        })
        .unwrap_or_else(|_| p.created_utc.clone())
}

/// The hero, pipeline and "where" block.
fn render_top(p: &Preview, tz: Option<chrono_tz::Tz>) -> String {
    let mut b = String::new();
    let tone = if p.total(Action::Conflict) + p.total(Action::Skipped) > 0 {
        "bad"
    } else if p.problems() > 0 {
        "warn"
    } else {
        ""
    };
    let kind = if p.mode == "apply" {
        "Sync"
    } else {
        "Test run (dry-run)"
    };
    let _ = write!(
        b,
        "<section class=\"pv-hero {tone}\"><p class=kicker>{kind} of {}, reference date {}{}</p><h2>{}</h2><p>{}</p>",
        esc(&time_label(p, tz)),
        esc(&p.today),
        p.population
            .as_deref()
            .map(|n| format!(", staff category {}", esc(n)))
            .unwrap_or_default(),
        esc(&p.headline()),
        esc(&p.compared_with)
    );
    if !p.notes.is_empty() {
        b.push_str("<ul class=pv-notes>");
        for n in &p.notes {
            let _ = write!(b, "<li>{}</li>", esc(n));
        }
        b.push_str("</ul>");
    }
    b.push_str("</section>");

    // The pipeline: how the rows flow from AFAS to Microsoft.
    let f = &p.flow;
    let changes = p.changes();
    let unchanged = p.total(Action::Unchanged) + p.total(Action::Resend);
    b.push_str("<ol class=pipe aria-label=\"From AFAS to Microsoft, step by step\">");
    let mut stage = |k: &str, n: String, sub: String, hl: bool| {
        let _ = write!(
            b,
            "<li{}><span class=k>{k}</span><span class=n>{n}</span><small>{sub}</small></li>",
            if hl { " class=hl" } else { "" }
        );
    };
    stage(
        "AFAS",
        f.rows_fetched.to_string(),
        "rows fetched".into(),
        false,
    );
    stage(
        "Checked",
        f.valid.to_string(),
        format!(
            "valid{}",
            if f.excluded > 0 {
                format!(" · {} skipped", f.excluded)
            } else {
                String::new()
            }
        ),
        false,
    );
    let mut window = Vec::new();
    if f.later > 0 {
        window.push(format!("{} start later", f.later));
    }
    if f.left_earlier > 0 {
        window.push(format!("{} left earlier", f.left_earlier));
    }
    if f.carried > 0 {
        window.push(format!("{} disabled once more", f.carried));
    }
    stage(
        "Date window",
        f.sent.to_string(),
        if window.is_empty() {
            "to send".into()
        } else {
            format!("to send · {}", window.join(" · "))
        },
        false,
    );
    stage(
        "Upload",
        p.calls.to_string(),
        format!(
            "{} of at most {} records",
            if p.calls == 1 { "call" } else { "calls" },
            p.batch_size
        ),
        false,
    );
    stage(
        if p.target == "Entra ID" {
            "Entra ID"
        } else {
            "AD via Microsoft"
        },
        changes.to_string(),
        format!(
            "{} · {unchanged} without changes",
            if changes == 1 { "change" } else { "changes" }
        ),
        true,
    );
    b.push_str("</ol>");

    // Where: accounts per location, coloured by what happens.
    let mut by_loc: BTreeMap<String, BTreeMap<Action, usize>> = BTreeMap::new();
    for r in p.rows.iter().filter(|r| r.action.in_upload()) {
        let loc = r
            .location
            .clone()
            .unwrap_or_else(|| "Where it is now (not looked up)".into());
        *by_loc.entry(loc).or_default().entry(r.action).or_default() += 1;
    }
    if !by_loc.is_empty() {
        let mut locs: Vec<(String, BTreeMap<Action, usize>)> = by_loc.into_iter().collect();
        locs.sort_by(|a, b| {
            let n = |m: &BTreeMap<Action, usize>| m.values().sum::<usize>();
            n(&b.1).cmp(&n(&a.1)).then(a.0.cmp(&b.0))
        });
        b.push_str("<section><h2>Where the accounts are</h2><ul class=where>");
        let shown = locs.len().min(14);
        for (loc, mix) in locs.iter().take(shown) {
            let total: usize = mix.values().sum();
            let (dom, rest) = match loc.split_once('/') {
                Some((d, r)) => (format!("{d}/"), r.to_string()),
                None => (String::new(), loc.clone()),
            };
            let is_new = *loc == p.new_accounts;
            let _ = write!(
                b,
                "<li><div class=path><span>{}</span><b>{}</b>{}</div><div class=cnt>{total}</div><div class=pv-bar><div class=stack role=img aria-label=\"{}\">",
                esc(&dom),
                esc(&rest),
                if is_new {
                    "<span class=new-ou>new accounts</span>"
                } else {
                    ""
                },
                esc(&mix
                    .iter()
                    .map(|(a, n)| format!("{n} {}", a.label().to_lowercase()))
                    .collect::<Vec<_>>()
                    .join(", "))
            );
            // Changes and problems first, accounts without changes last.
            let mut ordered: Vec<(&Action, &usize)> = mix.iter().collect();
            ordered.sort_by_key(|(a, _)| matches!(a, Action::Unchanged | Action::Resend));
            for (a, n) in ordered {
                let _ = write!(
                    b,
                    "<span class=b-{} style=\"flex-grow:{n}\" title=\"{}: {n}\"></span>",
                    a.tone(),
                    a.label()
                );
            }
            b.push_str("</div><div class=mix>");
            for (a, n) in mix.iter().filter(|(a, _)| **a != Action::Unchanged) {
                let _ = write!(
                    b,
                    "<span>{} {n} {}</span>",
                    a.symbol(),
                    esc(&a.label().to_lowercase())
                );
            }
            b.push_str("</div></div></li>");
        }
        b.push_str("</ul>");
        if locs.len() > shown {
            let _ = write!(
                b,
                "<p class=note>And {} more places with {} accounts.</p>",
                locs.len() - shown,
                locs[shown..]
                    .iter()
                    .map(|(_, m)| m.values().sum::<usize>())
                    .sum::<usize>()
            );
        }
        b.push_str("</section>");
    }
    b
}

/// The table rows (`<tbody>` content) with the fill-up animation.
fn render_rows(p: &Preview, rows: &[&Row]) -> String {
    let mut b = String::new();
    let mut last_call: Option<Option<usize>> = None;
    let mut i = 0usize;
    for r in rows {
        if last_call != Some(r.call) {
            last_call = Some(r.call);
            let label = match r.call {
                Some(c) => format!(
                    "Call {c} of {} to Microsoft · {}",
                    p.calls,
                    rows.iter().filter(|x| x.call == Some(c)).count()
                ),
                None => "Not in the upload".into(),
            };
            let _ = write!(
                b,
                "<tr class=callrow style=\"--i:{}\"><td colspan=6>{}</td></tr>",
                i.min(160),
                esc(&label)
            );
            i += 1;
        }
        // One column for the person: name, then number and sign-in name.
        let name = match (&r.name, &r.employee_id) {
            (Some(n), _) => esc(n),
            (None, Some(id)) => esc(id),
            (None, None) => "—".into(),
        };
        let sub = match (&r.employee_id, &r.upn, r.name.is_some()) {
            (Some(id), Some(u), true) => format!("{} · <span class=upn>{}</span>", esc(id), esc(u)),
            (Some(id), None, true) => esc(id),
            (_, Some(u), _) => format!("<span class=upn>{}</span>", esc(u)),
            (None, None, _) => "no employee number".into(),
            (Some(_), None, false) => String::new(),
        };
        let who = format!("<b>{name}</b><small>{sub}</small>");
        let state = match r.enabled_after {
            Some(true) => "<span class=on>● enabled</span>",
            Some(false) => "<span class=off>○ disabled</span>",
            None => "",
        };
        let mut what = String::new();
        let creating = matches!(
            r.action,
            Action::Create | Action::CreateDisabled | Action::New
        );
        if creating && !r.changes.is_empty() {
            what.push_str("<span class=chg><b>Gets</b>");
            what.push_str(
                &r.changes
                    .iter()
                    .filter_map(|c| {
                        c.to.as_ref().map(|t| {
                            format!("{} <ins>{}</ins>", esc(&c.label.to_lowercase()), esc(t))
                        })
                    })
                    .collect::<Vec<_>>()
                    .join(" · "),
            );
            what.push_str("</span>");
        } else {
            for c in &r.changes {
                let v = match (&c.from, &c.to) {
                    (Some(f), None) if c.kept => {
                        format!("{} <em>stays: empty in AFAS, so not sent</em>", esc(f))
                    }
                    (f, t) => format!(
                        "<del>{}</del> → <ins>{}</ins>",
                        esc(f.as_deref().unwrap_or("—")),
                        esc(t.as_deref().unwrap_or("—"))
                    ),
                };
                let _ = write!(
                    what,
                    "<span class=chg title=\"AD: {}\"><b>{}</b>{v}</span>",
                    esc(&c.ad),
                    esc(&c.label)
                );
            }
        }
        if let Some(n) = &r.note {
            let _ = write!(what, "<span class=why>{}</span>", esc(n));
        }
        let _ = write!(
            b,
            "<tr{} style=\"--i:{}\"><td class=c>{}</td><td>{}</td><td class=who>{who}</td><td class=loc>{}</td><td class=st>{state}</td><td class=what>{what}</td></tr>",
            if r.action.is_problem() {
                " class=problem"
            } else {
                ""
            },
            i.min(160),
            r.call.map(|c| c.to_string()).unwrap_or_else(|| "—".into()),
            badge(r.action),
            // Break long paths only after a slash.
            esc(r.location.as_deref().unwrap_or("—")).replace('/', "/<wbr>"),
        );
        i += 1;
    }
    b
}

fn table(p: &Preview, rows: &[&Row], caption: &str) -> String {
    let n = rows.len().min(160);
    let dur_ms = n * 38 + 400;
    let mut b = String::new();
    let _ = write!(
        b,
        "<div class=fillbar aria-hidden=true><span>Filling the table, call by call</span><span class=track><span style=\"--dur:{dur_ms}ms\"></span></span></div>"
    );
    let _ = write!(
        b,
        "<div class=tablewrap><table class=pv><caption class=note style=\"text-align:left;caption-side:bottom;padding:8px 2px\">{}</caption><thead><tr><th>Call</th><th>Action</th><th>Employee</th><th>Where</th><th>After</th><th>What changes</th></tr></thead><tbody>{}</tbody></table></div>",
        esc(caption),
        render_rows(p, rows)
    );
    b
}

/// The preview for the admin GUI: tabs link to `base` + `show=…`.
pub fn render_html(p: &Preview, show: Show, base: &str, tz: Option<chrono_tz::Tz>) -> String {
    let mut b = render_top(p, tz);
    let counts = |s: Show| p.rows.iter().filter(|r| s.includes_row(r)).count();
    b.push_str(
        "<section><h2>Account by account</h2><nav class=tabs aria-label=\"Which accounts\">",
    );
    for (s, label) in [
        (Show::Changes, "Changes"),
        (Show::Problems, "Needs attention"),
        (Show::Upload, "Everything sent"),
        (Show::NotSent, "Not sent"),
    ] {
        let _ = write!(
            b,
            "<a href=\"{base}show={}\"{}>{label}<span>{}</span></a>",
            s.key(),
            if s == show { " aria-current=page" } else { "" },
            counts(s)
        );
    }
    b.push_str("</nav>");
    let rows: Vec<&Row> = p.rows.iter().filter(|r| show.includes_row(r)).collect();
    if rows.is_empty() {
        b.push_str(match show {
            Show::Problems => "<p class=pv-empty>Nothing needs attention. </p>",
            Show::Changes => "<p class=pv-empty>No account changes: everything is up to date.</p>",
            _ => "<p class=pv-empty>Nothing here.</p>",
        });
    } else {
        b.push_str(&table(
            p,
            &rows,
            "Hover over a changed value to see the AD attribute. Accounts are listed in the order they are sent.",
        ));
    }
    b.push_str("</section>");
    b
}

/// A standalone page (to save or mail): everything on one page, no links back.
pub fn render_page(p: &Preview, tz: Option<chrono_tz::Tz>) -> String {
    let mut b = render_top(p, tz);
    let pick = |s: Show| -> Vec<&Row> { p.rows.iter().filter(|r| s.includes_row(r)).collect() };
    let changes = pick(Show::Changes);
    b.push_str("<section><h2>Changes and points of attention</h2>");
    if changes.is_empty() {
        b.push_str("<p class=pv-empty>No account changes: everything is up to date.</p>");
    } else {
        b.push_str(&table(
            p,
            &changes,
            "Accounts are listed in the order they are sent.",
        ));
    }
    b.push_str("</section>");
    let same: Vec<&Row> = p
        .rows
        .iter()
        .filter(|r| r.action.in_upload() && !Show::Changes.includes_row(r))
        .collect();
    let not_sent: Vec<&Row> = p
        .rows
        .iter()
        .filter(|r| !r.action.in_upload() && !r.action.is_problem())
        .collect();
    for (title, rows) in [("Sent without changes", same), ("Not sent", not_sent)] {
        if rows.is_empty() {
            continue;
        }
        let _ = write!(
            b,
            "<details class=more><summary>{title} ({})</summary><div class=tablewrap><table class=pv><thead><tr><th>Call</th><th>Action</th><th>Employee</th><th>Where</th><th>After</th><th>Note</th></tr></thead><tbody>{}</tbody></table></div></details>",
            rows.len(),
            render_rows(p, &rows).replace("style=\"--i:", "data-i=\"")
        );
    }
    let title = if p.mode == "apply" {
        "What the sync sent"
    } else {
        "What the sync would do"
    };
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><meta name=robots content=noindex><title>{title} | AFAS to Entra</title><style>{}{PREVIEW_CSS}</style></head><body class=standalone><main><p class=kicker>AFAS to Entra · contains personal data, do not forward</p><h1>{title}</h1>{b}<p class=note>Made by afas-entra-sync {} on {}. Reload the page to watch the table fill up again.</p></main></body></html>",
        crate::web::CSS,
        env!("CARGO_PKG_VERSION"),
        esc(&time_label(p, tz))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguished_names_become_paths_admins_know() {
        assert_eq!(
            canonical_name("OU=Sales,OU=Staff,DC=example,DC=com").as_deref(),
            Some("example.com/Staff/Sales")
        );
        assert_eq!(
            container_of("CN=de Vries\\, Jan,OU=New hires,DC=corp,DC=example,DC=nl").as_deref(),
            Some("corp.example.nl/New hires")
        );
        assert_eq!(
            canonical_name("DC=example,DC=com").as_deref(),
            Some("example.com")
        );
        assert_eq!(canonical_name("OU=Staff"), None);
        assert_eq!(canonical_name("not a dn"), None);
        assert_eq!(canonical_name("OU=,DC=x"), None);
        assert_eq!(container_of("DC=com"), None);
    }

    #[test]
    fn headline_says_what_happens_in_plain_words() {
        let mut p = demo();
        assert!(
            p.headline().starts_with(
                "Microsoft would create 2 accounts, enable 1, disable 1 and update 3."
            ),
            "{}",
            p.headline()
        );
        assert!(p.headline().ends_with("3 need attention first."));
        p.mode = "apply".into();
        assert!(
            p.headline().starts_with("Sent to Microsoft: 2 to create"),
            "{}",
            p.headline()
        );
        p.totals.clear();
        p.mode = "dry-run".into();
        assert!(p.headline().starts_with("Nothing would change"));
    }

    #[test]
    fn csv_cells_cannot_start_formulas() {
        assert_eq!(csv_cell("=1+1"), "'=1+1");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("plain"), "plain");
        let csv = render_csv(&demo());
        assert!(
            csv.lines()
                .next()
                .unwrap()
                .starts_with("call,action,employee_number")
        );
        assert!(csv.contains("Job title: Adviseur → Senior adviseur"));
    }

    #[test]
    fn text_view_lists_changes_and_hides_the_rest() {
        let lines = render_text(&demo(), Show::Changes, false, 100);
        let all = lines.join("\n");
        assert!(all.contains("~ Update"), "{all}");
        assert!(
            all.lines()
                .any(|l| l.contains("Job title") && l.ends_with("Adviseur → Senior adviseur")),
            "{all}"
        );
        assert!(!all.contains("Colleague 10100"));
        assert!(all.contains("without changes or not sent are not listed"));
        assert!(!all.contains('\x1b'));
        let colored = render_text(&demo(), Show::All, true, 5).join("\n");
        assert!(colored.contains('\x1b') && colored.contains("… and"));
    }

    #[test]
    fn html_escapes_everything_and_fills_rows_in_order() {
        let mut p = demo();
        p.rows[0].name = Some("<script>x</script>".into());
        let h = render_html(&p, Show::Changes, "/preview?", None);
        assert!(!h.contains("<script>x") && h.contains("&lt;script&gt;"));
        assert!(h.contains("style=\"--i:1\""));
        assert!(h.contains("Call 1 of"));
        assert!(h.contains("aria-current=page>Changes"));
        let page = render_page(&p, None);
        assert!(page.starts_with("<!doctype html>") && page.contains("contains personal data"));
        assert!(!page.contains("<script"));
    }
}
