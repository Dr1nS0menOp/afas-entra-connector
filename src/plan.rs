// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! From AFAS rows to an upload plan, including all safety checks.
//! This module does no I/O: the same input always gives the same plan.

use crate::config::{FieldMap, PolicyConfig};
use crate::model::{Employee, RowError, parse_row, validate_upn};
use crate::state::State;
use chrono::{Days, NaiveDate};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// One record to be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRecord {
    pub employee: Employee,
    pub active: bool,
    /// Manager only if they are in this upload too (otherwise Entra cannot link them).
    pub manager_id: Option<String>,
    /// From `[afas.fields.extra]`: send hire / leave date.
    pub send_hire_date: bool,
    pub send_leave_date: bool,
    /// Outside the date window, but sent as active last run: sent once more, as disabled,
    /// so the account does not stay enabled (an end date entered late, or a new employment
    /// that starts after the pre-hire window).
    pub outside_window: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Exclusion {
    pub employee_id: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Warning {
    pub employee_id: String,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Counts {
    pub rows_fetched: usize,
    pub identical_duplicates_merged: usize,
    pub sent_total: usize,
    pub sent_active: usize,
    pub sent_inactive_prehire: usize,
    pub sent_inactive_leaver: usize,
    /// Outside the date window but active last run: sent once more as disabled.
    #[serde(default)]
    pub sent_inactive_outside_window: usize,
    pub skipped_future_start: usize,
    pub skipped_old_leaver: usize,
    pub excluded_errors: usize,
    pub new_disables: usize,
    /// Sent as active last run, no longer in the upload (see `Plan::disappeared`).
    pub disappeared_while_active: usize,
    /// Records this tool has not sent before (only meaningful when there is a previous run).
    #[serde(default)]
    pub new_records: usize,
    /// Records whose sign-in name (UPN) differs from the last run.
    #[serde(default)]
    pub upn_changes: usize,
    pub api_calls_needed: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GuardViolation {
    pub guard: &'static str,
    pub message: String,
}

/// An employee sent as active before who is no longer in the upload.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MissingRecord {
    pub employee_id: String,
    /// First run in which they were missing.
    pub since: NaiveDate,
    /// Still in AFAS but skipped because of this data error; `None` = not in AFAS at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded_because: Option<String>,
    /// From the last values sent (not in the report: it goes to logs and schedulers).
    #[serde(skip)]
    pub upn: Option<String>,
    #[serde(skip)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UpnChange {
    pub employee_id: String,
    pub from: String,
    pub to: String,
}

/// Why the manager link of some employees points nowhere useful.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagerCause {
    /// The manager's end date has passed.
    Left,
    /// The manager's employee number is not in the AFAS data at all.
    NotInAfas,
    /// The manager's own record is skipped because of a data error.
    Skipped,
    /// The manager starts later than the pre-hire window.
    NotStarted,
}

/// A manager who has left (or cannot be linked) while employees still report to them.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ManagerGap {
    pub manager_id: String,
    pub cause: ManagerCause,
    /// End date (left) or start date (not started).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<NaiveDate>,
    /// The data error (skipped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Employee numbers of the people who report to them (active or not started yet).
    pub reports: Vec<String>,
    #[serde(skip)]
    pub manager_name: Option<String>,
}

/// A valid AFAS record that is not sent because of the date window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutsideWindow {
    pub employee: Employee,
    /// `true`: starts after the pre-hire window; `false`: left before the lookback window.
    pub later: bool,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub today: NaiveDate,
    /// Sorted by employee number: deterministic order.
    pub records: Vec<PlannedRecord>,
    pub exclusions: Vec<Exclusion>,
    pub warnings: Vec<Warning>,
    /// Employee numbers sent as ACTIVE last run that are no longer sent.
    /// The provisioning engine does NOT disable them (we do not send them):
    /// review manually. Kept in the state until resolved, see `missing`.
    pub disappeared: Vec<String>,
    /// The same, with since when and why.
    pub missing: Vec<MissingRecord>,
    pub upn_changes: Vec<UpnChange>,
    pub manager_gaps: Vec<ManagerGap>,
    /// Employee numbers counted in `counts.new_disables`.
    pub new_disable_ids: Vec<String>,
    /// Employee numbers counted in `counts.new_records`.
    pub new_ids: Vec<String>,
    /// Valid records outside the date window (not sent), for the preview.
    pub outside_window: Vec<OutsideWindow>,
    pub counts: Counts,
    pub violations: Vec<GuardViolation>,
}

pub struct PlanInput<'a> {
    pub rows: &'a [Map<String, Value>],
    pub fields: &'a FieldMap,
    pub policy: &'a PolicyConfig,
    pub batch_size: usize,
    pub today: NaiveDate,
    pub previous: Option<&'a State>,
    pub allow_mass_disable: bool,
    /// Proceed when more records are new than `max_new_per_run`.
    pub allow_mass_create: bool,
    /// Proceed when more sign-in names change than `max_upn_changes_per_run`.
    pub allow_upn_changes: bool,
}

pub fn build_plan(input: PlanInput<'_>) -> Plan {
    let PlanInput {
        rows,
        fields,
        policy,
        batch_size,
        today,
        previous,
        allow_mass_disable,
        allow_mass_create,
        allow_upn_changes,
    } = input;
    let mut counts = Counts {
        rows_fetched: rows.len(),
        ..Default::default()
    };
    let mut exclusions: Vec<Exclusion> = Vec::new();
    let mut warnings: Vec<Warning> = Vec::new();
    let was_active = |id: &str| {
        previous
            .and_then(|p| p.records.get(id))
            .is_some_and(|r| r.active)
    };

    // 1. Parse rows and validate each row.
    let mut parsed: Vec<Employee> = Vec::with_capacity(rows.len());
    for row in rows {
        match parse_row(row, fields).and_then(|e| {
            validate_upn(&e.upn, &policy.allowed_upn_domains)
                .map(|()| e.clone())
                .map_err(|reason| RowError {
                    employee_id: Some(e.employee_id.clone()),
                    reason,
                })
        }) {
            Ok(e) => parsed.push(e),
            Err(err) => exclusions.push(Exclusion {
                employee_id: err.employee_id,
                reason: err.reason,
            }),
        }
    }

    // If an excluded row has an employee number that also appears in a valid row,
    // it is unclear which row is right: that employee number is excluded entirely.
    let ids_with_bad_rows: BTreeSet<String> = exclusions
        .iter()
        .filter_map(|x| x.employee_id.clone())
        .collect();

    // 2. Duplicate employee numbers: identical = merge, different = exclude.
    let mut by_id: BTreeMap<String, Vec<Employee>> = BTreeMap::new();
    for e in parsed {
        by_id.entry(e.employee_id.clone()).or_default().push(e);
    }
    let mut unique: Vec<Employee> = Vec::with_capacity(by_id.len());
    for (id, mut group) in by_id {
        if ids_with_bad_rows.contains(&id) {
            exclusions.push(Exclusion {
                employee_id: Some(id),
                reason:
                    "employee number also appears in an invalid row; unclear which one is right"
                        .into(),
            });
            continue;
        }
        let first = group.swap_remove(0);
        if group.iter().all(|e| *e == first) {
            counts.identical_duplicates_merged += group.len();
            unique.push(first);
        } else {
            exclusions.push(Exclusion {
                employee_id: Some(id),
                reason: format!(
                    "employee number appears {} times with different data (multiple employments?)",
                    group.len() + 1
                ),
            });
        }
    }
    // Every valid employee, also outside the window: to explain manager links.
    let known: HashMap<String, Employee> = unique
        .iter()
        .map(|e| (e.employee_id.clone(), e.clone()))
        .collect();

    // 3. Apply the window: too far in the future or left too long ago = do not send,
    //    unless the account was active last run: then it is sent once more, disabled.
    let horizon = today
        .checked_add_days(Days::new(u64::from(policy.prehire_days)))
        .unwrap_or(NaiveDate::MAX);
    let cutoff = today
        .checked_sub_days(Days::new(u64::from(policy.leaver_lookback_days)))
        .unwrap_or(NaiveDate::MIN);
    let mut in_window: Vec<Employee> = Vec::with_capacity(unique.len());
    let mut carried: BTreeSet<String> = BTreeSet::new();
    let mut outside_window: Vec<OutsideWindow> = Vec::new();
    for e in unique {
        let later = e.start_date > horizon;
        let gone = !later && e.end_date.is_some_and(|end| end < cutoff);
        if (later || gone) && was_active(&e.employee_id) {
            carried.insert(e.employee_id.clone());
            in_window.push(e);
        } else if later {
            counts.skipped_future_start += 1;
            outside_window.push(OutsideWindow { employee: e, later });
        } else if gone {
            counts.skipped_old_leaver += 1;
            outside_window.push(OutsideWindow { employee: e, later });
        } else {
            in_window.push(e);
        }
    }

    // 4. Duplicate UPNs across different employees: exclude all of them.
    let mut by_upn: HashMap<String, Vec<String>> = HashMap::new();
    for e in &in_window {
        by_upn
            .entry(e.upn.to_ascii_lowercase())
            .or_default()
            .push(e.employee_id.clone());
    }
    let dup_ids: BTreeSet<String> = by_upn
        .values()
        .filter(|ids| ids.len() > 1)
        .flatten()
        .cloned()
        .collect();
    let mut final_set: Vec<Employee> = Vec::with_capacity(in_window.len());
    for e in in_window {
        if dup_ids.contains(&e.employee_id) {
            exclusions.push(Exclusion {
                employee_id: Some(e.employee_id.clone()),
                reason: format!("UPN '{}' is also used by another employee", e.upn),
            });
        } else {
            final_set.push(e);
        }
    }

    // 5. Active status and manager.
    let sent_ids: BTreeSet<&str> = final_set.iter().map(|e| e.employee_id.as_str()).collect();
    let mut records: Vec<PlannedRecord> = Vec::with_capacity(final_set.len());
    for e in &final_set {
        let outside = carried.contains(&e.employee_id);
        let active = !outside && is_active(e, today);
        let manager_id = match &e.manager_id {
            None => None,
            Some(m) if m == &e.employee_id => {
                warnings.push(Warning {
                    employee_id: e.employee_id.clone(),
                    message: "employee is their own manager; manager not sent".into(),
                });
                None
            }
            Some(m) if !sent_ids.contains(m.as_str()) => {
                warnings.push(Warning {
                    employee_id: e.employee_id.clone(),
                    message: format!("manager {m} is not in this upload; manager not sent"),
                });
                None
            }
            Some(m) => Some(m.clone()),
        };
        records.push(PlannedRecord {
            employee: e.clone(),
            active,
            manager_id,
            send_hire_date: fields.extra.send_hire_date,
            send_leave_date: fields.extra.send_leave_date,
            outside_window: outside,
        });
    }
    records.sort_by(|a, b| a.employee.employee_id.cmp(&b.employee.employee_id));
    exclusions.sort_by(|a, b| {
        a.employee_id
            .cmp(&b.employee_id)
            .then(a.reason.cmp(&b.reason))
    });

    // 6. Counts.
    counts.sent_total = records.len();
    for r in &records {
        if r.active {
            counts.sent_active += 1;
        } else if r.outside_window {
            counts.sent_inactive_outside_window += 1;
        } else if r.employee.start_date > today {
            counts.sent_inactive_prehire += 1;
        } else {
            counts.sent_inactive_leaver += 1;
        }
    }
    counts.excluded_errors = exclusions.len();
    let new_disable_ids: Vec<String> = records
        .iter()
        .filter(|r| is_new_disable(r, today, previous))
        .map(|r| r.employee.employee_id.clone())
        .collect();
    counts.new_disables = new_disable_ids.len();
    counts.api_calls_needed = records.len().div_ceil(batch_size.max(1));
    let new_ids: Vec<String> = records
        .iter()
        .filter(|r| previous.is_none_or(|p| !p.records.contains_key(&r.employee.employee_id)))
        .map(|r| r.employee.employee_id.clone())
        .collect();
    counts.new_records = new_ids.len();

    let upn_changes: Vec<UpnChange> = previous
        .map(|prev| {
            records
                .iter()
                .filter_map(|r| {
                    let before = prev.records.get(&r.employee.employee_id)?.upn()?;
                    (!before.eq_ignore_ascii_case(&r.employee.upn)).then(|| UpnChange {
                        employee_id: r.employee.employee_id.clone(),
                        from: before.to_string(),
                        to: r.employee.upn.clone(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    counts.upn_changes = upn_changes.len();

    let sent_now: BTreeSet<&str> = records
        .iter()
        .map(|r| r.employee.employee_id.as_str())
        .collect();
    let excluded_reason: HashMap<&str, &str> = exclusions
        .iter()
        .filter_map(|x| Some((x.employee_id.as_deref()?, x.reason.as_str())))
        .collect();
    let missing: Vec<MissingRecord> = previous
        .map(|prev| {
            prev.records
                .iter()
                .filter(|(id, st)| st.active && !sent_now.contains(id.as_str()))
                .map(|(id, st)| MissingRecord {
                    employee_id: id.clone(),
                    since: st.missing_since.unwrap_or(today),
                    excluded_because: excluded_reason.get(id.as_str()).map(|s| s.to_string()),
                    upn: st.upn().map(str::to_string),
                    display_name: st.sent.get("displayName").cloned(),
                })
                .collect()
        })
        .unwrap_or_default();
    let disappeared: Vec<String> = missing.iter().map(|m| m.employee_id.clone()).collect();
    counts.disappeared_while_active = disappeared.len();

    let manager_gaps = manager_gaps(&records, &known, &exclusions, today, horizon);

    // 7. Safety checks.
    let violations = evaluate_guards(
        &counts,
        policy,
        previous,
        Overrides {
            mass_disable: allow_mass_disable,
            mass_create: allow_mass_create,
            upn_changes: allow_upn_changes,
        },
    );

    Plan {
        today,
        records,
        exclusions,
        warnings,
        disappeared,
        missing,
        upn_changes,
        manager_gaps,
        new_disable_ids,
        new_ids,
        outside_window,
        counts,
        violations,
    }
}

/// Managers who have left or cannot be linked, with the people who still report to them.
/// Only reports who are active or have not started yet count: for someone who has left,
/// their manager no longer matters.
fn manager_gaps(
    records: &[PlannedRecord],
    known: &HashMap<String, Employee>,
    exclusions: &[Exclusion],
    today: NaiveDate,
    horizon: NaiveDate,
) -> Vec<ManagerGap> {
    let sent: HashMap<&str, &PlannedRecord> = records
        .iter()
        .map(|r| (r.employee.employee_id.as_str(), r))
        .collect();
    let mut gaps: BTreeMap<String, ManagerGap> = BTreeMap::new();
    for r in records {
        let e = &r.employee;
        let relevant = r.active || (!r.outside_window && e.start_date > today);
        let Some(m) = e.manager_id.as_deref().filter(|m| *m != e.employee_id) else {
            continue;
        };
        if !relevant {
            continue;
        }
        let manager = sent.get(m).map(|mr| &mr.employee).or_else(|| known.get(m));
        let (cause, date, reason) = match manager {
            Some(me) if me.end_date.is_some_and(|end| end < today) => {
                (ManagerCause::Left, me.end_date, None)
            }
            Some(me) if me.start_date > horizon => {
                (ManagerCause::NotStarted, Some(me.start_date), None)
            }
            Some(_) if sent.contains_key(m) => continue,
            Some(_) | None => match exclusions
                .iter()
                .find(|x| x.employee_id.as_deref() == Some(m))
            {
                Some(x) => (ManagerCause::Skipped, None, Some(x.reason.clone())),
                None if manager.is_some() => continue,
                None => (ManagerCause::NotInAfas, None, None),
            },
        };
        gaps.entry(m.to_string())
            .or_insert_with(|| ManagerGap {
                manager_id: m.to_string(),
                cause,
                date,
                reason,
                reports: Vec::new(),
                manager_name: manager.map(|me| me.display_name.clone()),
            })
            .reports
            .push(e.employee_id.clone());
    }
    gaps.into_values().collect()
}

/// Active from the start date up to and including the end date.
pub fn is_active(e: &Employee, today: NaiveDate) -> bool {
    e.start_date <= today && e.end_date.is_none_or(|end| today <= end)
}

/// A record now sent as disabled while we do not know for sure it was already disabled.
/// Sent as active last run and disabled now always counts, whatever the dates say (a start
/// date moved into the future disables the account too). Without an earlier run, pre-hires
/// do not count (they are new).
fn is_new_disable(r: &PlannedRecord, today: NaiveDate, previous: Option<&State>) -> bool {
    if r.active {
        return false;
    }
    match previous.and_then(|s| s.records.get(&r.employee.employee_id)) {
        Some(p) => p.active,
        None => r.employee.start_date <= today,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Overrides {
    mass_disable: bool,
    mass_create: bool,
    upn_changes: bool,
}

fn evaluate_guards(
    c: &Counts,
    p: &PolicyConfig,
    previous: Option<&State>,
    allow: Overrides,
) -> Vec<GuardViolation> {
    let mut v = Vec::new();

    if c.sent_total < p.min_records as usize {
        v.push(GuardViolation {
            guard: "min_records",
            message: format!(
                "only {} records to send, minimum is {}",
                c.sent_total, p.min_records
            ),
        });
    }

    if let Some(prev) = previous {
        // Drop compared with the last successful run, computed in integers
        // to avoid rounding errors:
        // drop% = (previous - now) * 100 / previous, stop if that is > max.
        let prev_n = prev.sent_total as u128;
        let now_n = c.sent_total as u128;
        if prev_n > 0
            && now_n < prev_n
            && (prev_n - now_n) * 100 > u128::from(p.max_drop_percent) * prev_n
        {
            v.push(GuardViolation {
                guard: "max_drop_percent",
                message: format!(
                    "record count drops from {} to {} (more than {}%)",
                    prev.sent_total, c.sent_total, p.max_drop_percent
                ),
            });
        }
    }

    // Data errors: if a large share is invalid, the mapping is probably wrong.
    let considered = (c.sent_total + c.excluded_errors) as u128;
    if considered > 0
        && (c.excluded_errors as u128) * 100 > u128::from(p.max_invalid_percent) * considered
    {
        v.push(GuardViolation {
            guard: "max_invalid_percent",
            message: format!(
                "{} of {} records invalid (more than {}%)",
                c.excluded_errors, considered, p.max_invalid_percent
            ),
        });
    }

    if c.new_disables > p.max_disables_per_run as usize && !allow.mass_disable {
        v.push(GuardViolation {
            guard: "max_disables_per_run",
            message: format!(
                "{} accounts would be disabled, maximum is {} (to proceed deliberately: --allow-mass-disable)",
                c.new_disables, p.max_disables_per_run
            ),
        });
    }

    // Many records the tool has never sent: a changed employee number (mapping or staff
    // category prefix) makes everybody new, and Microsoft would create a second account
    // for each. Not on the first run: then everything is new by definition.
    if previous.is_some() && c.new_records > p.max_new_per_run as usize && !allow.mass_create {
        v.push(GuardViolation {
            guard: "max_new_per_run",
            message: format!(
                "{} records were not in the last run, maximum is {} (to proceed deliberately: --allow-mass-create)",
                c.new_records, p.max_new_per_run
            ),
        });
    }

    if c.upn_changes > p.max_upn_changes_per_run as usize && !allow.upn_changes {
        v.push(GuardViolation {
            guard: "max_upn_changes_per_run",
            message: format!(
                "the sign-in name (UPN) of {} accounts would change, maximum is {} (to proceed deliberately: --allow-upn-changes)",
                c.upn_changes, p.max_upn_changes_per_run
            ),
        });
    }

    if c.api_calls_needed > p.max_calls_per_run as usize {
        v.push(GuardViolation {
            guard: "max_calls_per_run",
            message: format!(
                "{} API calls needed, maximum is {}",
                c.api_calls_needed, p.max_calls_per_run
            ),
        });
    }
    v
}
