// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Optional modules that run after the provisioning upload: roles (group
//! membership and licences), joiner (Temporary Access Pass), leaver (sessions,
//! automatic reply) and webhook (joiner/mover/leaver events).
//!
//! Every module plans first (pure functions over data read from Graph), checks its
//! own safety threshold, and only then applies. In a dry-run nothing is written,
//! in Entra or locally.

pub mod joiner;
pub mod leaver;
pub mod records;
pub mod roles;
pub mod settings;
pub mod webhook;

use crate::config::{AuthMode, Config};
use crate::entra::{Credential, TokenProvider};
use crate::graph::{EntraUser, Graph};
use crate::http::build_client;
use crate::plan::PlannedRecord;
use crate::state::write_atomic;
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

pub const MODULE_STATE_FILE: &str = "modules-state.json";
const MODULE_STATE_VERSION: u32 = 1;
const STALE_ATTRS_DAYS: i64 = 7;

/// The attributes the modules look at, per employee, as last seen.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub active: bool,
    pub upn: String,
    pub display_name: String,
    pub email: Option<String>,
    pub department: Option<String>,
    pub job_title: Option<String>,
    pub job_profile: Option<String>,
    pub office: Option<String>,
    pub company: Option<String>,
    pub employee_type: Option<String>,
    pub cost_center: Option<String>,
    pub manager_id: Option<String>,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
}

impl Snapshot {
    pub fn of(r: &PlannedRecord) -> Self {
        let e = &r.employee;
        Snapshot {
            active: r.active,
            upn: e.upn.clone(),
            display_name: e.display_name.clone(),
            email: e.email.clone(),
            department: e.department.clone(),
            job_title: e.job_title.clone(),
            job_profile: e.extra.job_profile.clone(),
            office: e.extra.office.clone(),
            company: e.extra.company.clone(),
            employee_type: e.extra.employee_type.clone(),
            cost_center: e.cost_center.clone(),
            manager_id: r.manager_id.clone(),
            start_date: e.start_date,
            end_date: e.end_date,
        }
    }
}

/// One employee as the modules see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub employee_id: String,
    pub snap: Snapshot,
    pub population: Option<String>,
}

pub fn people(records: &[PlannedRecord], population: Option<&str>) -> Vec<Person> {
    records
        .iter()
        .map(|r| Person {
            employee_id: r.employee.employee_id.clone(),
            snap: Snapshot::of(r),
            population: population.map(str::to_string),
        })
        .collect()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModuleState {
    pub version: u32,
    /// Attributes per employee after the last applied run (mover/joiner detection).
    #[serde(default)]
    pub attrs: BTreeMap<String, Snapshot>,
    /// Employee → start date a Temporary Access Pass was issued for.
    #[serde(default)]
    pub tap_issued: BTreeMap<String, NaiveDate>,
    /// Employee → end date the leaver actions were done for.
    #[serde(default)]
    pub leaver_done: BTreeMap<String, NaiveDate>,
    /// Employee → start date for which "already has a pass" was reported (once).
    #[serde(default)]
    pub tap_existing_noted: BTreeMap<String, NaiveDate>,
    /// Day `attrs` was saved; older than a week = start a new baseline.
    #[serde(default)]
    pub attrs_date: Option<NaiveDate>,
    /// Webhook events not delivered yet.
    #[serde(default)]
    pub outbox: Vec<webhook::Event>,
}

pub fn load_state(dir: &Path) -> Result<ModuleState, String> {
    let path = dir.join(MODULE_STATE_FILE);
    match std::fs::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ModuleState {
            version: MODULE_STATE_VERSION,
            ..Default::default()
        }),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        Ok(t) => {
            let s: ModuleState = serde_json::from_str(&t).map_err(|e| {
                format!(
                    "{} is corrupt ({e}); repair it or delete it deliberately",
                    path.display()
                )
            })?;
            if s.version != MODULE_STATE_VERSION {
                return Err(format!("unknown module state version {}", s.version));
            }
            Ok(s)
        }
    }
}

pub fn save_state(dir: &Path, s: &ModuleState) -> Result<(), String> {
    let j = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    write_atomic(&dir.join(MODULE_STATE_FILE), &j).map_err(|e| e.to_string())
}

/// How an employee was found in Entra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    User(EntraUser),
    /// Not in Entra (yet): normal for new accounts until Connect Sync has run.
    Missing,
    /// A user with this UPN has a different employeeId: never act on it.
    Conflict(String),
}

/// Links employees to Entra users: by employeeId first, then by UPN when the Entra
/// user has no employeeId. A UPN match with another employeeId is a conflict.
pub fn match_users(people: &[Person], users: &[EntraUser]) -> HashMap<String, Found> {
    let mut by_emp: HashMap<&str, &EntraUser> = HashMap::new();
    let mut dup_emp: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for u in users {
        if let Some(e) = u.employee_id.as_deref()
            && by_emp.insert(e, u).is_some()
        {
            dup_emp.insert(e);
        }
    }
    let by_upn: HashMap<String, &EntraUser> = users
        .iter()
        .map(|u| (u.upn.to_ascii_lowercase(), u))
        .collect();
    people
        .iter()
        .map(|p| {
            let id = p.employee_id.as_str();
            let f = if dup_emp.contains(id) {
                Found::Conflict(format!("employeeId {id} is on more than one Entra user"))
            } else if let Some(u) = by_emp.get(id) {
                Found::User((*u).clone())
            } else {
                match by_upn.get(&p.snap.upn.to_ascii_lowercase()) {
                    None => Found::Missing,
                    Some(u) => match &u.employee_id {
                        None => Found::User((*u).clone()),
                        Some(other) => {
                            Found::Conflict(format!("{} has employeeId {other}, not {id}", u.upn))
                        }
                    },
                }
            };
            (p.employee_id.clone(), f)
        })
        .collect()
}

/// One planned or applied change.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Action {
    pub action: String,
    pub employee_id: Option<String>,
    pub upn: Option<String>,
    pub target: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ModuleReport {
    /// Changes planned this run (applied unless dry-run or stopped).
    pub planned: Vec<Action>,
    pub applied: usize,
    /// Changes that failed while applying.
    pub failed: Vec<String>,
    /// Employees skipped and why (not in Entra yet, conflicts, segregation of duties).
    pub notes: Vec<String>,
    /// Waiting, expected to resolve by itself (no attention needed, no exit 3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<String>,
    /// Safety threshold hit: nothing applied by this module.
    pub violations: Vec<String>,
    /// The module could not run (config, sign-in, Graph error).
    pub error: Option<String>,
    pub graph_calls: u32,
}

/// The access log is the audit trail: failing to write it is a failure, reported once.
pub fn note_log_failure(rep: &mut ModuleReport, res: Result<(), String>) {
    if let Err(e) = res {
        let msg = format!("access log not written: {e}");
        if !rep.failed.contains(&msg) {
            rep.failed.push(msg);
        }
    }
}

impl ModuleReport {
    pub fn errored(e: impl Into<String>) -> Self {
        ModuleReport {
            error: Some(e.into()),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ModulesReport {
    /// The modules could not start (e.g. corrupt module state).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<ModuleReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joiner: Option<ModuleReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaver: Option<ModuleReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<ModuleReport>,
}

impl ModulesReport {
    fn all(&self) -> impl Iterator<Item = &ModuleReport> {
        [&self.roles, &self.joiner, &self.leaver, &self.webhook]
            .into_iter()
            .flatten()
    }
    pub fn any_error(&self) -> bool {
        self.error.is_some()
            || self
                .all()
                .any(|m| m.error.is_some() || !m.failed.is_empty())
    }
    pub fn any_violation(&self) -> bool {
        self.all().any(|m| !m.violations.is_empty())
    }
    pub fn any_notes(&self) -> bool {
        self.all().any(|m| !m.notes.is_empty())
    }
}

/// Inputs every module gets.
pub struct Ctx<'a> {
    pub cfg: &'a Config,
    pub people: &'a [Person],
    pub today: NaiveDate,
    pub apply: bool,
    pub use_system_proxy: bool,
    pub sleep: &'a dyn Fn(Duration),
    pub state_dir: &'a Path,
    /// Who triggered the run, for the access log.
    pub actor: &'a str,
    /// The Entra users, read once per run and shared by the modules.
    pub users: std::cell::RefCell<Option<Vec<EntraUser>>>,
}

impl Ctx<'_> {
    /// All Entra users: read on first use (with the calling module's sign-in), then shared.
    pub fn users(&self, g: &Graph<'_>) -> crate::graph::GResult<Vec<EntraUser>> {
        if let Some(u) = self.users.borrow().as_ref() {
            return Ok(u.clone());
        }
        let u = crate::graph::list_users(g)?;
        *self.users.borrow_mut() = Some(u.clone());
        Ok(u)
    }
}

/// Signs in as an app registration (certificate) and hands a Graph client to `f`.
pub fn graph_as<R>(
    cfg: &Config,
    id: &settings::ModuleIdentity,
    use_system_proxy: bool,
    sleep: &dyn Fn(Duration),
    f: impl FnOnce(&Graph<'_>) -> R,
) -> Result<R, String> {
    let mut e = cfg.entra.clone();
    e.client_id = id.client_id.clone();
    e.auth = AuthMode::Certificate;
    e.certificate_pem = Some(id.certificate_pem.clone());
    e.private_key_pem = Some(id.private_key_pem.clone());
    e.client_secret_env = None;
    let cred = Credential::from_config(&e).map_err(|e| e.to_string())?;
    let client = build_client(e.timeout_secs, use_system_proxy, &cfg.tls)?;
    let tokens = TokenProvider::new(&e, &client, cred, sleep);
    let g = Graph::new(&e.graph_base, &client, tokens, sleep)?;
    Ok(f(&g))
}

/// Signs in as a module's own app registration and hands a Graph client to `f`.
pub fn with_graph<R>(
    ctx: &Ctx<'_>,
    id: &settings::ModuleIdentity,
    f: impl FnOnce(&Graph<'_>) -> R,
) -> Result<R, String> {
    graph_as(ctx.cfg, id, ctx.use_system_proxy, ctx.sleep, f)
}

/// Runs every enabled module. `state` is updated in place; the caller saves it
/// after an applied run.
pub fn run_all(ctx: &Ctx<'_>, state: &mut ModuleState) -> ModulesReport {
    let mut rep = ModulesReport::default();
    let cfg = ctx.cfg;
    // Events first: they compare with the attributes of the previous run. Attributes
    // from long ago (modules were off) would turn every change since then into a stale
    // event, so they only count as a new baseline.
    let fresh = state
        .attrs_date
        .is_some_and(|d| d <= ctx.today && (ctx.today - d).num_days() <= STALE_ATTRS_DAYS);
    let events = if fresh {
        webhook::detect(ctx.people, &state.attrs, ctx.today)
    } else {
        Vec::new()
    };
    if let Some(l) = cfg.leaver.as_ref().filter(|l| l.enabled) {
        rep.leaver = Some(leaver::run(ctx, l, state));
    }
    if let Some(j) = cfg.joiner.as_ref().filter(|j| j.enabled) {
        rep.joiner = Some(joiner::run(ctx, j, state));
    }
    if let Some(r) = cfg.roles.as_ref().filter(|r| r.enabled) {
        rep.roles = Some(roles::run(ctx, r));
    }
    if let Some(w) = cfg.webhook.as_ref().filter(|w| w.enabled) {
        let mut r = webhook::run(ctx, w, state, events);
        if !fresh && !state.attrs.is_empty() {
            r.notes.push(format!(
                "the last comparison is older than {STALE_ATTRS_DAYS} days; this run is a new baseline and sends no events for changes before it"
            ));
        }
        rep.webhook = Some(r);
    }
    if ctx.apply {
        state.attrs_date = Some(ctx.today);
        state.attrs = ctx
            .people
            .iter()
            .map(|p| (p.employee_id.clone(), p.snap.clone()))
            .collect();
    }
    rep
}
