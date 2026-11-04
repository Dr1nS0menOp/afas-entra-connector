// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Findings: the things after a run that a person has to decide or do, because the tool
//! cannot (or must not) solve them on its own. Each one says what happened, what it
//! means, why the tool leaves it to people, and who does what.
//!
//! With `names = false` (the default for every channel) no names, sign-in names or
//! email addresses go into the text: only employee numbers, which HR can look up in AFAS.

use super::CheckLogsReport;
use crate::config::Config;
use crate::error::exit;
use crate::plan::{ManagerCause, Plan};
use crate::preview::{Action, Preview};
use crate::state::State;
use crate::sync::Report;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// The run failed or stopped: nothing (or not everything) was sent.
    Failure,
    /// Someone has to act.
    Action,
    /// Good to know.
    Info,
}

/// Who acts on a finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    /// IT / identity management.
    It,
    /// HR (data in AFAS).
    Hr,
}

impl Audience {
    pub fn label(self) -> &'static str {
        match self {
            Audience::It => "IT",
            Audience::Hr => "HR",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Column {
    pub label: String,
    /// Holds names, sign-in names or email addresses: left out with `personal_data = "numbers"`.
    #[serde(skip)]
    pub personal: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Table {
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<String>>,
}

impl Table {
    fn new(cols: &[(&str, bool)]) -> Self {
        Table {
            columns: cols
                .iter()
                .map(|(l, p)| Column {
                    label: (*l).to_string(),
                    personal: *p,
                })
                .collect(),
            rows: Vec::new(),
        }
    }

    fn row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    /// Without the personal columns.
    pub fn without_personal(&self) -> Table {
        let keep: Vec<usize> = (0..self.columns.len())
            .filter(|i| !self.columns[*i].personal)
            .collect();
        Table {
            columns: keep.iter().map(|i| self.columns[*i].clone()).collect(),
            rows: self
                .rows
                .iter()
                .map(|r| {
                    keep.iter()
                        .map(|i| r.get(*i).cloned().unwrap_or_default())
                        .collect()
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    /// Stable identity, for "new since the last message".
    pub key: String,
    pub kind: &'static str,
    pub severity: Severity,
    pub audience: Vec<Audience>,
    pub title: String,
    /// What happened.
    pub what: String,
    /// What it means for accounts and people.
    pub impact: String,
    /// Why the tool leaves this to people.
    pub why: String,
    /// What to do, in order. May contain `code` in backticks.
    pub todo: Vec<String>,
    pub table: Option<Table>,
    /// Not in the previous message on this channel.
    #[serde(default)]
    pub new: bool,
}

impl Finding {
    fn new(kind: &'static str, key: String, severity: Severity, audience: &[Audience]) -> Self {
        Finding {
            key,
            kind,
            severity,
            audience: audience.to_vec(),
            title: String::new(),
            what: String::new(),
            impact: String::new(),
            why: String::new(),
            todo: Vec::new(),
            table: None,
            new: false,
        }
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Everything a finding builder may use.
pub struct SyncInput<'a> {
    pub cfg: &'a Config,
    pub report: &'a Report,
    pub plan: Option<&'a Plan>,
    pub previous: Option<&'a State>,
    pub preview: Option<&'a Preview>,
    /// Put names, sign-in names and email addresses in the text.
    pub names: bool,
    pub host: &'a str,
}

/// People known in this run: employee number → (name, sign-in name, department).
struct People<'a> {
    by_id: HashMap<&'a str, (&'a str, &'a str, Option<&'a str>)>,
    names: bool,
}

impl<'a> People<'a> {
    fn of(plan: Option<&'a Plan>, names: bool) -> Self {
        let mut by_id = HashMap::new();
        if let Some(p) = plan {
            for r in &p.records {
                let e = &r.employee;
                by_id.insert(
                    e.employee_id.as_str(),
                    (
                        e.display_name.as_str(),
                        e.upn.as_str(),
                        e.department.as_deref(),
                    ),
                );
            }
            for o in &p.outside_window {
                let e = &o.employee;
                by_id.entry(e.employee_id.as_str()).or_insert((
                    e.display_name.as_str(),
                    e.upn.as_str(),
                    e.department.as_deref(),
                ));
            }
        }
        People { by_id, names }
    }

    fn name(&self, id: &str) -> String {
        self.by_id
            .get(id)
            .map(|x| x.0.to_string())
            .unwrap_or_default()
    }

    fn department(&self, id: &str) -> String {
        self.by_id
            .get(id)
            .and_then(|x| x.2)
            .unwrap_or("")
            .to_string()
    }

    /// "Jan de Vries (10234)", or just the number without names.
    fn who(&self, id: &str, known_name: Option<&str>) -> String {
        let n = known_name
            .map(str::to_string)
            .or_else(|| self.by_id.get(id).map(|x| x.0.to_string()));
        match n {
            Some(n) if self.names && !n.is_empty() => format!("{n} ({id})"),
            _ => format!("employee {id}"),
        }
    }
}

/// The sentence for a run that sent nothing.
const NOTHING_SENT: &str = "Nothing was sent to Microsoft in this run. Until a run succeeds, new hires get no account, changes made in AFAS do not reach AD and Entra, and departing employees keep an enabled account.";

/// Findings after a sync or test run.
pub fn from_sync(i: &SyncInput<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let r = i.report;
    let people = People::of(i.plan, i.names);
    if let Some(f) = run_failed(i) {
        out.push(f);
    }
    if r.exit_code == exit::GUARD {
        out.extend(safety_stops(i, &people));
    }
    if let Some(plan) = i.plan {
        out.extend(manager_gaps(plan, &people));
        if let Some(f) = missing(plan, &people) {
            out.push(f);
        }
        if let Some(f) = excluded(plan, i.cfg, &people) {
            out.push(f);
        }
        if let Some(f) = own_manager(r, &people) {
            out.push(f);
        }
        if r.upload.is_some() {
            if let Some(f) = upn_changes(plan, &people) {
                out.push(f);
            }
            if let Some(f) = cleared_values(plan, i.previous, &people) {
                out.push(f);
            }
        }
    }
    if let Some(p) = i.preview
        && let Some(f) = duplicate_risk(p, i.names)
    {
        out.push(f);
    }
    out.extend(modules(r));
    if let Some(f) = certificates(r) {
        out.push(f);
    }
    out
}

// ------------------------------------------------------------------ failures

fn run_failed(i: &SyncInput<'_>) -> Option<Finding> {
    let r = i.report;
    let host = i.host;
    let mut f = Finding::new(
        "run_failed",
        format!("run_failed:{}", r.exit_code),
        Severity::Failure,
        &[Audience::It],
    );
    f.what = capitalise(&r.result);
    f.impact = NOTHING_SENT.into();
    f.why = "The tool already retries within a run (and waits as long as Microsoft or AFAS asks), and every scheduled run starts over. This error was still there after those retries, so it needs a person.".into();
    match r.exit_code {
        exit::CONFIG => {
            f.title = "The sync did not run: the configuration is not valid".into();
            f.why = "With a configuration error the tool does not guess: it fetches and sends nothing until the configuration is right.".into();
            f.todo = vec![
                format!("On {host}, run `afas-entra-sync check-config`: it names the exact setting."),
                "Fix the config file, or undo the last change made in the admin GUI (those are in overrides.toml in the state directory).".into(),
                "Then run `afas-entra-sync doctor` to check everything else.".into(),
            ];
        }
        exit::SOURCE => {
            f.title = "The sync did not run: AFAS could not be read".into();
            f.todo = vec![
                "Check whether AFAS Profit is reachable (status.afas.nl) and whether the token still works: `afas-entra-sync doctor`.".into(),
                "If the message names a missing field, a field of the GetConnector was renamed or removed: `afas-entra-sync afas-fields` shows what AFAS returns now.".into(),
                "If the token was revoked, create a new one for the app connector in Profit and replace the token file.".into(),
            ];
        }
        exit::AUTH => {
            f.title = "The sync did not run: signing in to Entra ID failed".into();
            let mut todo = Vec::new();
            if let Some(fix) = crate::doctor::entra_fix(&r.result) {
                todo.push(capitalise(&fix));
            }
            todo.push("If the certificate expired or was removed from the app registration: `sudo afas-entra-sync install --renew-cert`, then upload the new cert.pem in Entra (App registrations → afas-entra-sync → Certificates & secrets).".into());
            todo.push("Run `afas-entra-sync doctor`: it explains the AADSTS code in the message on its own line.".into());
            f.todo = todo;
        }
        exit::UPLOAD => {
            f.title = "The upload to Microsoft stopped before it was complete".into();
            f.impact = "Microsoft received part of the data and is processing it; the rest was not sent. The next run sends everything again, so nothing is lost once a run gets through. Until then, part of today's changes wait.".into();
            f.todo = vec![
                "Check Microsoft 365 Service health for incidents with Microsoft Entra.".into(),
                "HTTP 403: the app registration lacks SynchronizationData-User.Upload, or admin consent was withdrawn.".into(),
                "HTTP 400: Microsoft refused the data itself; the message says which part. A test run with --dump-payload shows exactly what is sent.".into(),
                "If it keeps failing, run `afas-entra-sync check-logs` and see Troubleshooting in the guide.".into(),
            ];
        }
        exit::INTERNAL => {
            f.title = "The sync stopped on an unexpected error".into();
            f.why = "This should not happen: the tool is built to stop safely instead of crashing, and this message is that safe stop.".into();
            f.todo = vec![
                "Keep the attached log and report it to whoever maintains the tool.".into(),
                "The next scheduled run tries again.".into(),
            ];
        }
        _ => return None,
    }
    Some(f)
}

fn safety_stops(i: &SyncInput<'_>, people: &People<'_>) -> Vec<Finding> {
    let r = i.report;
    let c = &r.counts;
    let p = &i.cfg.policy;
    let mut out = Vec::new();
    for v in &r.violations {
        let mut f = Finding::new(
            "safety_stop",
            format!("safety_stop:{}", v.guard),
            Severity::Failure,
            &[Audience::It],
        );
        f.what = format!("{}.", capitalise(&v.message));
        f.impact = "Nothing was uploaded. Every scheduled run stops at the same point until someone decides, so new hires, changes and departures all wait.".into();
        match v.guard {
            "min_records" => {
                f.title = format!(
                    "Safety stop: only {} to send, fewer than the minimum of {}",
                    plural(c.sent_total, "employee", "employees"),
                    p.min_records
                );
                f.why = "A list from AFAS that is much shorter than usual is more likely a mistake (a changed filter, a token that sees less) than a mass departure, so the tool does not send it.".into();
                f.todo = vec![
                    "Check the GetConnector in AFAS: was its filter changed, or did the token's user lose access to part of the employees?".into(),
                    "If the number is right (for example after a reorganisation), lower policy.min_records.".into(),
                ];
                f.audience = vec![Audience::It, Audience::Hr];
            }
            "max_drop_percent" => {
                f.title = "Safety stop: far fewer employees than in the last sync".into();
                f.why = "A sudden drop usually means the GetConnector returns less (a filter, rights, an AFAS problem), not that many people left at once.".into();
                f.todo = vec![
                    "Compare the GetConnector's result in AFAS with the number of employees you expect.".into(),
                    "If the drop is real, run once by hand with `sync --apply` after raising policy.max_drop_percent, then set it back.".into(),
                ];
                f.audience = vec![Audience::It, Audience::Hr];
            }
            "max_invalid_percent" => {
                f.title = format!(
                    "Safety stop: {} of {} records have data errors",
                    c.excluded_errors,
                    c.sent_total + c.excluded_errors
                );
                f.why = "This many errors at once almost always means a field was renamed or changed format in AFAS, not that HR made that many typos. Sending the rest could disable people whose record broke.".into();
                f.todo = vec![
                    "Look at the reasons below: if most are the same, a field mapping is wrong.".into(),
                    "`afas-entra-sync afas-fields` shows what the GetConnector returns per field and which setting uses it.".into(),
                ];
                if let Some(plan) = i.plan {
                    let mut t = Table::new(&[("Employee number", false), ("Problem", false)]);
                    for x in plan.exclusions.iter().take(25) {
                        t.row(vec![
                            x.employee_id.clone().unwrap_or_else(|| "—".into()),
                            capitalise(&x.reason),
                        ]);
                    }
                    f.table = Some(t);
                }
            }
            "max_disables_per_run" => {
                f.title = format!(
                    "Safety stop: {} would be disabled at once (maximum {})",
                    plural(c.new_disables, "account", "accounts"),
                    p.max_disables_per_run
                );
                f.why = "Disabling is the one change that stops people from working, so a burst of them is checked by a person first.".into();
                f.todo = vec![
                    "Run a test run and look at the accounts marked Disable in the preview (afas-entra-sync preview, or Preview in the GUI).".into(),
                    "Real departures, for example the end of a project team? Then run once with `sync --apply --allow-mass-disable`, or tick Proceed under Run in the GUI.".into(),
                    "Not right? Correct the end or start dates in AFAS; the next run continues normally.".into(),
                ];
                if let Some(plan) = i.plan {
                    out.push(with_people_table(f, &plan.new_disable_ids, people, |id| {
                        let rec = plan.records.iter().find(|x| x.employee.employee_id == id);
                        match rec.map(|x| &x.employee) {
                            Some(e) if e.end_date.is_some() => format!(
                                "left on {}",
                                e.end_date.map(|d| d.to_string()).unwrap_or_default()
                            ),
                            Some(e) if e.start_date > plan.today => {
                                format!("start date moved to {}", e.start_date)
                            }
                            _ => String::new(),
                        }
                    }));
                    continue;
                }
            }
            "max_new_per_run" => {
                f.title = format!(
                    "Safety stop: {} were not in the last sync (maximum {})",
                    plural(c.new_records, "employee", "employees"),
                    p.max_new_per_run
                );
                f.why = "When the employee number changes (a different AFAS field, or a staff category prefix added), every employee looks new, and Microsoft would create a second account for each of them next to the existing one.".into();
                f.todo = vec![
                    "Check whether afas.fields.employee_id or population.id_prefix was changed recently.".into(),
                    "A real large intake, for example after an acquisition? Check the test-run preview, then run once with `sync --apply --allow-mass-create`.".into(),
                ];
                if let Some(plan) = i.plan {
                    out.push(with_people_table(
                        f,
                        &plan.new_ids.iter().take(50).cloned().collect::<Vec<_>>(),
                        people,
                        |_| String::new(),
                    ));
                    continue;
                }
            }
            "max_upn_changes_per_run" => {
                f.title = format!(
                    "Safety stop: the sign-in name of {} would change (maximum {})",
                    plural(c.upn_changes, "account", "accounts"),
                    p.max_upn_changes_per_run
                );
                f.why = "A new sign-in name (UPN) changes how people log in, their OneDrive address and their identity in apps with single sign-on. Many at once usually means the UPN rule in AFAS changed.".into();
                f.todo = vec![
                    "Check the UPN field in AFAS and how it is generated.".into(),
                    "Intended, for example a new email domain? Tell the people involved, then run once with `sync --apply --allow-upn-changes`.".into(),
                ];
                if let Some(plan) = i.plan {
                    f.table = Some(upn_table(plan, people));
                }
            }
            "max_calls_per_run" => {
                f.title = format!(
                    "Safety stop: {} API calls needed (maximum {})",
                    c.api_calls_needed, p.max_calls_per_run
                );
                f.why = "Microsoft limits the number of upload calls per day; this check keeps one run from using it up.".into();
                f.todo = vec![
                    "If the number of employees really grew, raise policy.max_calls_per_run (each call holds up to 50 employees).".into(),
                ];
            }
            _ => {
                f.title = "Safety stop: nothing was uploaded".into();
                f.why = "A safety threshold was hit.".into();
            }
        }
        out.push(f);
    }
    out
}

fn with_people_table(
    mut f: Finding,
    ids: &[String],
    people: &People<'_>,
    extra: impl Fn(&str) -> String,
) -> Finding {
    let mut t = Table::new(&[
        ("Employee number", false),
        ("Name", true),
        ("Department", false),
        ("Detail", false),
    ]);
    for id in ids {
        t.row(vec![
            id.clone(),
            people.name(id),
            people.department(id),
            extra(id),
        ]);
    }
    f.table = Some(t);
    f
}

fn upn_table(plan: &Plan, people: &People<'_>) -> Table {
    let mut t = Table::new(&[
        ("Employee number", false),
        ("Name", true),
        ("Old sign-in name", true),
        ("New sign-in name", true),
    ]);
    for u in &plan.upn_changes {
        t.row(vec![
            u.employee_id.clone(),
            people.name(&u.employee_id),
            u.from.clone(),
            u.to.clone(),
        ]);
    }
    t
}

// ------------------------------------------------------------------ data in AFAS

fn manager_gaps(plan: &Plan, people: &People<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for g in &plan.manager_gaps {
        let n = g.reports.len();
        let emps = plural(n, "employee", "employees");
        let m = people.who(&g.manager_id, g.manager_name.as_deref());
        let date = g.date.map(|d| d.to_string()).unwrap_or_default();
        let mut f = Finding::new(
            "manager_gone",
            format!(
                "manager:{}:{:?}:{}",
                g.manager_id,
                g.cause,
                g.reports.join(",")
            ),
            Severity::Action,
            &[Audience::Hr],
        );
        f.why = "Who someone reports to is an HR decision. The tool copies it from AFAS and never guesses a replacement.".into();
        match g.cause {
            ManagerCause::Left => {
                f.title = format!(
                    "{} left on {date}, but {emps} still {} to them",
                    capitalise(&m),
                    if n == 1 { "reports" } else { "report" }
                );
                f.what = format!(
                    "In AFAS, {m} is still the manager of the {emps} below. {} end date was {date}.",
                    if people.names {
                        "Their"
                    } else {
                        "The manager's"
                    }
                );
                f.impact = "In AD and Entra their manager stays an account that is disabled (or is left empty for new hires). Approvals, the org chart and everything that follows the manager, such as the first sign-in code for a new hire, go to someone who is no longer there.".into();
                f.todo = vec![
                    "HR: enter the new manager for these employees in AFAS.".into(),
                    "Nothing else is needed: the next sync updates the manager in AD and Entra."
                        .into(),
                ];
            }
            ManagerCause::NotInAfas => {
                f.title = format!(
                    "{emps} {} to manager {}, who is not in AFAS",
                    if n == 1 { "reports" } else { "report" },
                    g.manager_id
                );
                f.what = format!(
                    "The {emps} below have employee number {} as their manager, but that number is not in the data the GetConnector returns.",
                    g.manager_id
                );
                f.impact = "The tool cannot link someone to a manager it does not know, so in AD these employees keep their previous manager or have none.".into();
                f.todo = vec![
                    "HR: check the manager of these employees in AFAS: a typo, or someone outside this staff category?".into(),
                    "If the manager is in another staff category (for example a contractor), that link is not supported yet; set a manager within the same category.".into(),
                ];
            }
            ManagerCause::Skipped => {
                f.title = format!(
                    "{} is skipped because of a data error, so {emps} have no manager link",
                    capitalise(&m)
                );
                f.what = format!(
                    "The manager's own record has an error: {}.",
                    g.reason.clone().unwrap_or_default()
                );
                f.impact = "Until that record is fixed, these employees are sent without a manager: AD keeps their previous one, new hires get none.".into();
                f.todo = vec![
                    format!(
                        "HR: fix the manager's own record in AFAS ({}).",
                        g.reason.clone().unwrap_or_default()
                    ),
                    "The employees are linked automatically on the next sync.".into(),
                ];
            }
            ManagerCause::NotStarted => {
                f.title = format!(
                    "{} starts on {date}, but {emps} already {} to them",
                    capitalise(&m),
                    if n == 1 { "reports" } else { "report" }
                );
                f.what = format!(
                    "AFAS already lists {m} as the manager of the {emps} below, while the manager only starts on {date}."
                );
                f.impact = "Until then their manager in AD is an account that does not exist or is not enabled yet; approvals and first sign-in codes for new hires may go nowhere.".into();
                f.todo = vec![
                    "HR: decide whether someone should act as manager until the start date, and enter that in AFAS.".into(),
                ];
                f.severity = Severity::Info;
            }
        }
        out.push(with_people_table(f, &g.reports, people, |id| {
            let r = plan.records.iter().find(|x| x.employee.employee_id == id);
            match r {
                Some(x) if x.employee.start_date > plan.today => {
                    format!("new hire, starts {}", x.employee.start_date)
                }
                _ => "active".into(),
            }
        }));
    }
    out
}

fn missing(plan: &Plan, people: &People<'_>) -> Option<Finding> {
    if plan.missing.is_empty() {
        return None;
    }
    let n = plan.missing.len();
    let mut ids: Vec<&str> = plan
        .missing
        .iter()
        .map(|m| m.employee_id.as_str())
        .collect();
    ids.sort_unstable();
    let mut f = Finding::new(
        "missing",
        format!("missing:{}", ids.join(",")),
        Severity::Action,
        &[Audience::Hr, Audience::It],
    );
    f.title = if n == 1 {
        "1 account stays enabled, although the employee is no longer in AFAS".to_string()
    } else {
        format!("{n} accounts stay enabled, although the employees are no longer in AFAS")
    };
    f.what = format!(
        "The {} below {} sent as active before, but {} no longer in the data from AFAS (or {} skipped because of a data error).",
        plural(n, "employee", "employees"),
        if n == 1 { "was" } else { "were" },
        if n == 1 { "is" } else { "are" },
        if n == 1 { "is" } else { "are" }
    );
    f.impact = "Their accounts stay enabled, with access to mail, files and apps, until someone decides. This message comes back until each one is resolved.".into();
    f.why = "Someone who disappears from AFAS is never disabled automatically: a changed filter could make many people disappear at once, and disabling them all would be far worse than waiting for a person to look.".into();
    f.todo = vec![
        "HR: did these people leave? Then enter the end date in AFAS. The next sync disables the account, also when the date is in the past.".into(),
        "Still employed, but filtered out of the GetConnector by mistake? Fix the filter in AFAS.".into(),
        "IT: if an account must be disabled right now, disable it in AD, then mark it as handled so it is no longer reported: `afas-entra-sync missing ack <employee number>`.".into(),
    ];
    let mut t = Table::new(&[
        ("Employee number", false),
        ("Name", true),
        ("Sign-in name", true),
        ("Missing since", false),
        ("Why", false),
    ]);
    for m in &plan.missing {
        t.row(vec![
            m.employee_id.clone(),
            m.display_name
                .clone()
                .unwrap_or_else(|| people.name(&m.employee_id)),
            m.upn.clone().unwrap_or_default(),
            m.since.to_string(),
            match &m.excluded_because {
                Some(r) => format!("in AFAS, but skipped: {r}"),
                None => "not in AFAS".into(),
            },
        ]);
    }
    f.table = Some(t);
    Some(f)
}

/// How HR can fix a data error, from the reason text.
pub fn fix_hint(reason: &str, domains: &[String]) -> String {
    let r = reason.to_ascii_lowercase();
    if r.contains("not in allowed_upn_domains") {
        format!(
            "Use one of the allowed domains in the UPN field: {}",
            domains.join(", ")
        )
    } else if r.contains("also used by another employee") {
        "Give each employee their own UPN".into()
    } else if r.contains("upn") && r.contains("invalid character") {
        "Remove accents, spaces and special characters from the UPN".into()
    } else if r.contains("upn") && (r.contains("@") || r.contains("dot")) {
        "Correct the UPN (one @, no dot at the start or end)".into()
    } else if r.contains("multiple employments") || r.contains("different data") {
        "The GetConnector returns several employments: IT filters it on the current one".into()
    } else if r.contains("also appears in an invalid row") {
        "Fix the other row with this number first".into()
    } else if r.contains("time other than") || r.contains("invalid time") {
        "IT: the date field contains a time; check the GetConnector field".into()
    } else if r.contains("before start date") {
        "Correct the start or end date".into()
    } else if r.contains("start date is missing") {
        "Fill in the start date".into()
    } else if r.contains("date") {
        "Correct the date".into()
    } else if r.contains("email") {
        "Correct the work email address".into()
    } else if r.contains("longer than") {
        "Shorten the value (Active Directory limit)".into()
    } else if r.contains("phone") {
        "Use only digits, spaces and + - ( ) in the phone number".into()
    } else if r.contains("country") {
        "Use a two-letter country code, such as NL".into()
    } else if r.contains("own manager") {
        "Set the right manager".into()
    } else if r.contains("is missing") {
        "Fill in the field".into()
    } else if r.contains("contains spaces") {
        "Remove the spaces".into()
    } else {
        "Correct the record in AFAS".into()
    }
}

fn excluded(plan: &Plan, cfg: &Config, people: &People<'_>) -> Option<Finding> {
    if plan.exclusions.is_empty() {
        return None;
    }
    let n = plan.exclusions.len();
    let mut keys: Vec<String> = plan
        .exclusions
        .iter()
        .map(|x| format!("{}={}", x.employee_id.as_deref().unwrap_or("?"), x.reason))
        .collect();
    keys.sort();
    let mut f = Finding::new(
        "excluded",
        format!("excluded:{}", keys.join("|")),
        Severity::Action,
        &[Audience::Hr],
    );
    f.title = format!(
        "{} skipped because of data errors in AFAS",
        plural(n, "employee is", "employees are")
    );
    f.what = if n == 1 {
        "The record below could not be sent: it has a field that is empty, too long or in the wrong format.".into()
    } else {
        format!(
            "The {n} records below could not be sent: each has a field that is empty, too long or in the wrong format."
        )
    };
    f.impact = if n == 1 {
        "The account stays exactly as it is: a new hire gets no account, and changes (or a departure) in AFAS do not reach AD until the record is fixed.".into()
    } else {
        "Their accounts stay exactly as they are: a new hire gets no account, and changes (or a departure) in AFAS do not reach AD until the record is fixed.".into()
    };
    f.why = "A record with an error is not sent at all, so no account is ever created or changed with half-right data.".into();
    f.todo = vec![
        "HR: correct these records in AFAS (see How to fix).".into(),
        "The next sync picks them up automatically; nothing else is needed.".into(),
    ];
    let mut t = Table::new(&[
        ("Employee number", false),
        ("Name", true),
        ("Problem", false),
        ("How to fix", false),
    ]);
    for x in &plan.exclusions {
        let id = x.employee_id.clone().unwrap_or_else(|| "—".into());
        t.row(vec![
            id.clone(),
            people.name(&id),
            capitalise(&x.reason),
            fix_hint(&x.reason, &cfg.policy.allowed_upn_domains),
        ]);
    }
    f.table = Some(t);
    Some(f)
}

fn own_manager(r: &Report, people: &People<'_>) -> Option<Finding> {
    let ids: Vec<String> = r
        .warnings
        .iter()
        .filter(|w| w.message.contains("their own manager"))
        .map(|w| w.employee_id.clone())
        .collect();
    if ids.is_empty() {
        return None;
    }
    let n = ids.len();
    let mut f = Finding::new(
        "own_manager",
        format!("own_manager:{}", ids.join(",")),
        Severity::Action,
        &[Audience::Hr],
    );
    f.title = format!(
        "{} {} their own manager in AFAS",
        plural(n, "employee", "employees"),
        if n == 1 { "is" } else { "are" }
    );
    f.what = "AFAS lists these employees as their own manager.".into();
    f.impact = "They are sent without a manager, so AD keeps their previous one.".into();
    f.why =
        "A loop like this cannot be right, and the tool does not guess who the manager should be."
            .into();
    f.todo = vec!["HR: set the right manager in AFAS.".into()];
    Some(with_people_table(f, &ids, people, |_| String::new()))
}

fn upn_changes(plan: &Plan, people: &People<'_>) -> Option<Finding> {
    if plan.upn_changes.is_empty() {
        return None;
    }
    let n = plan.upn_changes.len();
    let mut keys: Vec<String> = plan
        .upn_changes
        .iter()
        .map(|u| format!("{}>{}", u.employee_id, u.to))
        .collect();
    keys.sort();
    let mut f = Finding::new(
        "upn_changes",
        format!("upn:{}", keys.join(",")),
        Severity::Action,
        &[Audience::It],
    );
    f.title = format!(
        "The sign-in name of {} changes",
        plural(n, "employee", "employees")
    );
    f.what = "AFAS has a new UPN for the employees below. This sync sent it to Microsoft, which renames their accounts in AD and Entra.".into();
    f.impact = "They sign in with the new name from now on. Their OneDrive address changes, and apps with single sign-on that use the sign-in name as user ID may treat them as a new user.".into();
    f.why = "AFAS is the source of the sign-in name, so the tool follows it. Telling people and checking linked apps is work for people.".into();
    f.todo = vec![
        "Tell the employees their new sign-in name; their password stays the same.".into(),
        "Check apps that identify users by UPN: SAML/SSO apps, scripts, the service desk tool."
            .into(),
    ];
    f.table = Some(upn_table(plan, people));
    Some(f)
}

fn cleared_values(plan: &Plan, previous: Option<&State>, people: &People<'_>) -> Option<Finding> {
    let prev = previous?;
    let mut t = Table::new(&[
        ("Employee number", false),
        ("Name", true),
        ("Field", false),
        ("Value that stays in AD", true),
    ]);
    let mut keys = Vec::new();
    let mut leave_date = false;
    for r in &plan.records {
        let Some(before) = prev.records.get(&r.employee.employee_id) else {
            continue;
        };
        let now = crate::scim::sent_values(r);
        for (k, old) in &before.sent {
            // The manager has its own finding; a cleared leave date matters most.
            if k == "manager" || now.contains_key(k) {
                continue;
            }
            let label = crate::scim::attribute(k).map_or(k.as_str(), |a| a.label);
            if k == "leaveDate" {
                leave_date = true;
            }
            keys.push(format!("{}:{k}:{old}", r.employee.employee_id));
            t.row(vec![
                r.employee.employee_id.clone(),
                people.name(&r.employee.employee_id),
                label.to_string(),
                old.clone(),
            ]);
        }
    }
    if t.rows.is_empty() {
        return None;
    }
    let n = t.rows.len();
    let mut f = Finding::new(
        "cleared_values",
        format!("cleared:{}", keys.join(",")),
        if leave_date {
            Severity::Action
        } else {
            Severity::Info
        },
        &[Audience::It],
    );
    f.title = format!(
        "{} emptied in AFAS but {} in AD",
        plural(n, "value was", "values were"),
        if n == 1 { "stays" } else { "stay" }
    );
    f.what = "These fields had a value in the last sync and are empty in AFAS now.".into();
    f.impact = if leave_date {
        "Empty fields are not sent, so AD keeps the old value (unless clear attribute values is on in the provisioning app). One of them is a leave date: if a Lifecycle Workflow uses it, the leaver workflow can still start for someone who stays.".into()
    } else {
        "Empty fields are not sent, so AD keeps the old value (unless clear attribute values is on in the provisioning app).".into()
    };
    f.why = "Sending empty values would wipe data in AD whenever AFAS returns an incomplete answer, so the tool never does that.".into();
    f.todo = vec![
        "Check whether these fields should really be empty (for example a contract that was extended and lost its end date).".into(),
        "If so, clear the value in AD by hand, or switch on clear attribute values in the provisioning app (it then empties every attribute that AFAS leaves empty).".into(),
    ];
    f.table = Some(t);
    Some(f)
}

fn duplicate_risk(p: &Preview, names: bool) -> Option<Finding> {
    let rows: Vec<_> = p
        .rows
        .iter()
        .filter(|r| matches!(r.action, Action::LinkFirst | Action::Conflict))
        .collect();
    if rows.is_empty() {
        return None;
    }
    let n = rows.len();
    let mut f = Finding::new(
        "duplicate_risk",
        format!(
            "duplicate:{}",
            rows.iter()
                .filter_map(|r| r.employee_id.clone())
                .collect::<Vec<_>>()
                .join(",")
        ),
        Severity::Action,
        &[Audience::It],
    );
    f.title = format!(
        "{} would get a second account",
        plural(n, "employee", "employees")
    );
    f.what = "An account with the same sign-in name already exists in Entra, but without this employee number (or with another one).".into();
    f.impact = "Microsoft finds existing accounts only by employee number (employeeID). Without it, the real sync tries to create a second account, which fails on the duplicate name or leaves two accounts for one person.".into();
    f.why =
        "Which existing account belongs to which employee is something only people can confirm."
            .into();
    f.todo = vec![
        "Link them before the first real sync: set employeeID on the existing AD account (guide, step 5d).".into(),
        "For a conflict (another employee number), find out which one is right first; never guess.".into(),
    ];
    let mut t = Table::new(&[
        ("Employee number", false),
        ("Name", true),
        ("Sign-in name", true),
        ("Problem", false),
    ]);
    for r in rows {
        t.row(vec![
            r.employee_id.clone().unwrap_or_default(),
            if names {
                r.name.clone().unwrap_or_default()
            } else {
                String::new()
            },
            r.upn.clone().unwrap_or_default(),
            r.action.label().into(),
        ]);
    }
    f.table = Some(t);
    Some(f)
}

// ------------------------------------------------------------------ modules, certificates

fn module_name(m: &str) -> &'static str {
    match m {
        "roles" => "roles and licences",
        "joiner" => "new hires (first sign-in code)",
        "leaver" => "departing employees",
        _ => "webhook",
    }
}

fn module_impact(m: &str) -> &'static str {
    match m {
        "roles" => "Group memberships, and with them licences, were not updated in this run.",
        "joiner" => {
            "No first sign-in codes were sent in this run; a new hire who starts soon may not get one in time."
        }
        "leaver" => "Departing employees were not signed out everywhere in this run.",
        _ => "Events were not delivered; they wait in the send queue and go out on a later run.",
    }
}

fn modules(r: &Report) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(m) = &r.modules else {
        return out;
    };
    if let Some(e) = &m.error {
        let mut f = Finding::new(
            "modules_failed",
            "modules:error".into(),
            Severity::Action,
            &[Audience::It],
        );
        f.title = "The optional modules could not start".into();
        f.what = capitalise(e);
        f.impact = "Provisioning itself went fine, but no module ran: groups, first sign-in codes, sign-outs and events all wait.".into();
        f.why = "The modules keep their own state; when it cannot be read, they do nothing rather than repeat what was already done.".into();
        f.todo = vec!["Check modules-state.json in the state directory (see the message).".into()];
        out.push(f);
    }
    for (key, rep) in [
        ("roles", &m.roles),
        ("joiner", &m.joiner),
        ("leaver", &m.leaver),
        ("webhook", &m.webhook),
    ] {
        let Some(x) = rep else { continue };
        let name = module_name(key);
        if let Some(e) = &x.error {
            let mut f = Finding::new(
                "module_failed",
                format!("module:{key}:error"),
                Severity::Action,
                &[Audience::It],
            );
            f.title = format!("The {name} module could not run");
            f.what = capitalise(e);
            f.impact = module_impact(key).into();
            f.why = "Provisioning itself went fine; the module signs in with its own app registration and that part failed.".into();
            f.todo = vec![
                "Run `afas-entra-sync doctor`: the module's sign-in and each permission have their own line.".into(),
            ];
            out.push(f);
        }
        for v in &x.violations {
            let mut f = Finding::new(
                "module_stopped",
                format!("module:{key}:stop"),
                Severity::Action,
                &[Audience::It],
            );
            f.title = format!("The {name} module stopped itself");
            f.what = format!("{}.", capitalise(v));
            f.impact = module_impact(key).into();
            f.why = "Each module has its own maximum per run, so a mistake in the rules cannot change many accounts at once.".into();
            f.todo = vec![
                "Look at the planned actions in a test run (report, or Modules in the GUI).".into(),
                "If they are right, raise the module's maximum for one run (for example roles.max_changes_per_run), then set it back.".into(),
            ];
            out.push(f);
        }
        if !x.failed.is_empty() {
            let mut f = Finding::new(
                "module_actions_failed",
                format!("module:{key}:failed:{}", x.failed.join("|")),
                Severity::Action,
                &[Audience::It],
            );
            f.title = format!(
                "{} of the {name} module failed",
                plural(x.failed.len(), "action", "actions")
            );
            f.what = "Microsoft refused or did not answer the actions below.".into();
            f.impact = module_impact(key).into();
            f.why = "The module tries again on the next run; when the same action keeps failing, the cause is usually a permission or a mailbox that does not exist.".into();
            f.todo = vec![
                "Read the message per action; `afas-entra-sync doctor` checks the permissions."
                    .into(),
            ];
            let mut t = Table::new(&[("What failed", true)]);
            for line in &x.failed {
                t.row(vec![line.clone()]);
            }
            f.table = Some(t);
            out.push(f);
        }
        if !x.notes.is_empty() {
            let mut f = Finding::new(
                "module_notes",
                format!("module:{key}:notes:{}", x.notes.join("|")),
                Severity::Action,
                &[Audience::It],
            );
            f.title = format!(
                "The {name} module has {}",
                plural(x.notes.len(), "point that needs", "points that need")
            ) + " attention";
            f.what =
                "The module skipped these people, or saw something that needs a decision.".into();
            f.impact = "For the people below, the module did nothing this run.".into();
            f.why = "The module only acts when it is sure: an account that cannot be found, or belongs to someone else, is left alone.".into();
            f.todo = vec![
                "Read each line: most say what to do. A new account that is not in Entra yet resolves itself after Connect Sync.".into(),
            ];
            let mut t = Table::new(&[("Note", true)]);
            for line in &x.notes {
                t.row(vec![line.clone()]);
            }
            f.table = Some(t);
            out.push(f);
        }
    }
    out
}

fn certificates(r: &Report) -> Option<Finding> {
    if r.notices.is_empty() {
        return None;
    }
    let mut f = Finding::new(
        "certificate",
        format!("certificate:{}", r.notices.join("|")),
        Severity::Action,
        &[Audience::It],
    );
    f.title = if r.notices.len() == 1 {
        "A certificate expires soon".into()
    } else {
        format!("{} certificates expire soon", r.notices.len())
    };
    f.what = r.notices.join(" ");
    f.impact = "When it expires, signing in to Entra fails and the sync (or the module that uses it) stops.".into();
    f.why = "A new certificate has to be uploaded in Entra by someone with rights there.".into();
    f.todo = vec![
        "Renew it with the command in the message, then upload the new cert.pem to the app registration in Entra.".into(),
        "Remove the old certificate from Entra only after a successful run with the new one.".into(),
    ];
    Some(f)
}

// ------------------------------------------------------------------ provisioning logs

/// The likely cause of a provisioning failure, from Microsoft's reason text.
pub fn provisioning_hint(reason: &str) -> &'static str {
    let r = reason.to_ascii_lowercase();
    if r.contains("unique") || r.contains("already exists") || r.contains("conflict") {
        "Another AD object has this sign-in name or account name (sAMAccountName): rename it, or link it via employeeID"
    } else if r.contains("access") && (r.contains("denied") || r.contains("insufficient")) {
        "The provisioning agent's gMSA lacks rights on the target OU"
    } else if r.contains("no such object") || r.contains("container") || r.contains("parent") {
        "The target OU does not exist or was renamed"
    } else if r.contains("manager") {
        "The manager was not found in AD yet; a later run links them once they exist"
    } else if r.contains("agent") {
        "The provisioning agent is offline: check View on-premises agents in the app"
    } else {
        "See the full entry in the provisioning logs"
    }
}

pub fn from_check_logs(r: &CheckLogsReport, cfg: &Config) -> Vec<Finding> {
    let mut out = Vec::new();
    let app = "the provisioning app";
    if let Some(e) = &r.error {
        let mut f = Finding::new(
            "check_logs_failed",
            "check_logs:error".into(),
            Severity::Action,
            &[Audience::It],
        );
        f.title = "The provisioning logs could not be read".into();
        f.what = capitalise(e);
        f.impact =
            "Whether Microsoft applied the last uploads is unknown until the logs can be read."
                .into();
        f.why = "The tool only knows that Microsoft accepted the data; whether it was applied in AD is only in these logs.".into();
        f.todo = vec![
            "Check that the app registration has ProvisioningLog.Read.All with admin consent: `afas-entra-sync doctor`.".into(),
        ];
        out.push(f);
        return out;
    }
    let Some(s) = &r.summary else { return out };
    if s.failure > 0 {
        let mut keys: Vec<String> = s
            .failures
            .iter()
            .map(|x| format!("{}@{}", x.source_id, x.activity_utc))
            .collect();
        keys.sort();
        let mut f = Finding::new(
            "provisioning_failures",
            format!("prov_fail:{}", keys.join(",")),
            Severity::Action,
            &[Audience::It],
        );
        f.title = format!(
            "Microsoft could not apply {}",
            plural(s.failure, "record", "records")
        );
        f.what = format!(
            "Of {} entries in the provisioning logs since {}, {} failed.",
            s.total,
            local(cfg, &r.since_utc),
            s.failure
        );
        f.impact = "For these employees, the change from AFAS is not in AD: a new hire may have no account, a departure may not be disabled.".into();
        f.why = "The tool hands the data over; Microsoft applies it in AD through the provisioning agent. Errors at that stage happen inside AD (a duplicate name, a missing OU, the agent's rights), where the tool cannot look or act.".into();
        f.todo = vec![
            format!(
                "Open Enterprise applications → {app} → Provisioning logs and filter on Status: Failure for the full details."
            ),
            "Fix the cause in AD (see Likely cause); the next sync sends the records again.".into(),
        ];
        let mut t = Table::new(&[
            ("When", false),
            ("Employee number", false),
            ("Action", false),
            ("Microsoft says", false),
            ("Likely cause", false),
        ]);
        for x in &s.failures {
            t.row(vec![
                local(cfg, &x.activity_utc),
                x.source_id.clone(),
                x.action.clone(),
                x.reason.clone(),
                provisioning_hint(&x.reason).into(),
            ]);
        }
        f.table = Some(t);
        out.push(f);
    }
    for w in &r.warnings {
        let mut f = Finding::new(
            "provisioning_silent",
            format!(
                "prov_silent:{}",
                r.last_upload_utc.clone().unwrap_or_default()
            ),
            Severity::Action,
            &[Audience::It],
        );
        f.title = "Microsoft has not processed the last upload".into();
        f.what = w.clone();
        f.impact = "As long as the provisioning job does not run, nothing from AFAS reaches AD: no new accounts, no changes, no disables.".into();
        f.why = "The tool only learns that Microsoft accepted the data. Whether the job runs is set in Entra.".into();
        f.todo = vec![
            format!("In Entra: Enterprise applications → {app} → Provisioning. Is it running, paused or in quarantine?"),
            "Quarantine is often caused by an empty notification email or a provisioning agent that is offline (View on-premises agents).".into(),
            "Check that entra.job_id and entra.service_principal_id belong to this app (View technical information).".into(),
        ];
        out.push(f);
    }
    out
}

fn local(cfg: &Config, rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| {
            t.with_timezone(&cfg.tz())
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| rfc3339.to_string())
}

// ------------------------------------------------------------------ example

/// The examples as a channel with or without names would get them.
pub fn examples_for(names: bool) -> Vec<Finding> {
    let all = examples();
    if names {
        return all;
    }
    let fix = |s: &str| {
        s.replace("Example: Mia de Groot (10002)", "Example: Employee 10002")
            .replace("Mia de Groot (10002)", "employee 10002")
            .replace("Their end date", "The manager's end date")
    };
    without_personal(
        &all.into_iter()
            .map(|mut f| {
                f.title = fix(&f.title);
                f.what = fix(&f.what);
                f
            })
            .collect::<Vec<_>>(),
    )
}

/// Fictional findings for the test message, so the channel shows what a real report looks like.
pub fn examples() -> Vec<Finding> {
    let mut a = Finding::new(
        "manager_gone",
        "example:manager".into(),
        Severity::Action,
        &[Audience::Hr],
    );
    a.title =
        "Example: Mia de Groot (10002) left on 2026-10-31, but 2 employees still report to them"
            .into();
    a.what = "In AFAS, Mia de Groot (10002) is still the manager of the 2 employees below. Their end date was 2026-10-31.".into();
    a.impact = "In AD and Entra their manager stays an account that is disabled (or is left empty for new hires). Approvals, the org chart and everything that follows the manager, such as the first sign-in code for a new hire, go to someone who is no longer there.".into();
    a.why = "Who someone reports to is an HR decision. The tool copies it from AFAS and never guesses a replacement.".into();
    a.todo = vec![
        "HR: enter the new manager for these employees in AFAS.".into(),
        "Nothing else is needed: the next sync updates the manager in AD and Entra.".into(),
    ];
    let mut t = Table::new(&[
        ("Employee number", false),
        ("Name", true),
        ("Department", false),
        ("Detail", false),
    ]);
    t.row(vec![
        "10011".into(),
        "Piet Bakker".into(),
        "Finance".into(),
        "active".into(),
    ]);
    t.row(vec![
        "10071".into(),
        "Jan de Vries".into(),
        "Finance".into(),
        "new hire, starts 2026-11-16".into(),
    ]);
    a.table = Some(t);
    a.new = true;
    let mut b = Finding::new(
        "excluded",
        "example:excluded".into(),
        Severity::Action,
        &[Audience::Hr],
    );
    b.title = "Example: 1 employee is skipped because of data errors in AFAS".into();
    b.what = "The record below could not be sent: it has a field that is empty, too long or in the wrong format.".into();
    b.impact = "The account stays exactly as it is: a new hire gets no account, and changes (or a departure) in AFAS do not reach AD until the record is fixed.".into();
    b.why = "A record with an error is not sent at all, so no account is ever created or changed with half-right data.".into();
    b.todo = vec![
        "HR: correct these records in AFAS (see How to fix).".into(),
        "The next sync picks them up automatically; nothing else is needed.".into(),
    ];
    let mut t = Table::new(&[
        ("Employee number", false),
        ("Name", true),
        ("Problem", false),
        ("How to fix", false),
    ]);
    t.row(vec![
        "10090".into(),
        "Rik van Leeuwen".into(),
        "UPN 'rik.vanleeuwen@example': domain 'example' is not in allowed_upn_domains".into(),
        "Use one of the allowed domains in the UPN field: example.com".into(),
    ]);
    b.table = Some(t);
    vec![a, b]
}

/// Groups findings by audience for the channel filter.
pub fn for_audience(findings: &[Finding], audience: &[Audience]) -> Vec<Finding> {
    if audience.is_empty() {
        return findings.to_vec();
    }
    findings
        .iter()
        .filter(|f| {
            f.severity == Severity::Failure || f.audience.iter().any(|a| audience.contains(a))
        })
        .cloned()
        .collect()
}

/// Hides values that may name someone in free text: anything between single quotes (data
/// error reasons quote the value, e.g. a UPN) and anything that looks like an address.
pub fn redact(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_quote = false;
    for c in s.chars() {
        if c == '\'' {
            if in_quote {
                out.push_str("…'");
            } else {
                out.push('\'');
            }
            in_quote = !in_quote;
        } else if !in_quote {
            out.push(c);
        }
    }
    if in_quote {
        out.push('…');
    }
    out.split(' ')
        .map(|w| if w.contains('@') { "…@…" } else { w })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Removes personal data from findings: the personal columns, and quoted values or
/// addresses in the texts and remaining cells.
pub fn without_personal(findings: &[Finding]) -> Vec<Finding> {
    findings
        .iter()
        .map(|f| {
            let mut g = f.clone();
            g.what = redact(&f.what);
            g.table = f.table.as_ref().map(|t| {
                let mut t = t.without_personal();
                for row in &mut t.rows {
                    for cell in row.iter_mut() {
                        *cell = redact(cell);
                    }
                }
                t
            });
            g
        })
        .collect()
}

/// Count of findings per severity, for the headline.
pub fn by_severity(findings: &[Finding]) -> BTreeMap<Severity, usize> {
    let mut m = BTreeMap::new();
    for f in findings {
        *m.entry(f.severity).or_default() += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fix_hints_speak_hr_language() {
        let d = vec!["example.com".to_string()];
        assert!(
            fix_hint(
                "UPN 'a@b.c': domain 'b.c' is not in allowed_upn_domains",
                &d
            )
            .contains("example.com")
        );
        assert!(fix_hint("UPN 'x' is also used by another employee", &d).contains("own UPN"));
        assert!(
            fix_hint(
                "employee number appears 2 times with different data (multiple employments?)",
                &d
            )
            .contains("employments")
        );
        assert!(fix_hint("start date is missing", &d).contains("start date"));
        assert!(fix_hint("something odd", &d).contains("Correct the record"));
    }

    #[test]
    fn personal_columns_can_be_left_out() {
        let mut t = Table::new(&[("Employee number", false), ("Name", true)]);
        t.row(vec!["1".into(), "Jan".into()]);
        let s = t.without_personal();
        assert_eq!(s.columns.len(), 1);
        assert_eq!(s.rows, vec![vec!["1".to_string()]]);
    }

    #[test]
    fn redaction_hides_quoted_values_and_addresses() {
        assert_eq!(
            redact("UPN 'jan@x.nl': domain 'x.nl' is not in allowed_upn_domains"),
            "UPN '…': domain '…' is not in allowed_upn_domains"
        );
        assert_eq!(redact("mail jan@x.nl failed"), "mail …@… failed");
        assert_eq!(redact("no quotes"), "no quotes");
        assert_eq!(redact("open 'quote"), "open '…");
    }

    #[test]
    fn provisioning_hints() {
        assert!(provisioning_hint("AttributeValueMustBeUnique").contains("sAMAccountName"));
        assert!(provisioning_hint("Access is denied").contains("gMSA"));
        assert!(provisioning_hint("??").contains("full entry"));
    }
}
