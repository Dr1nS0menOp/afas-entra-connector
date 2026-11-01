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
    pub skipped_future_start: usize,
    pub skipped_old_leaver: usize,
    pub excluded_errors: usize,
    pub new_disables: usize,
    /// Sent as active last run, no longer in the upload (see `Plan::disappeared`).
    pub disappeared_while_active: usize,
    pub api_calls_needed: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GuardViolation {
    pub guard: &'static str,
    pub message: String,
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
    /// review manually.
    pub disappeared: Vec<String>,
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
    } = input;
    let mut counts = Counts {
        rows_fetched: rows.len(),
        ..Default::default()
    };
    let mut exclusions: Vec<Exclusion> = Vec::new();
    let mut warnings: Vec<Warning> = Vec::new();

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

    // 3. Apply the window: too far in the future or left too long ago = do not send.
    let horizon = today
        .checked_add_days(Days::new(u64::from(policy.prehire_days)))
        .unwrap_or(NaiveDate::MAX);
    let cutoff = today
        .checked_sub_days(Days::new(u64::from(policy.leaver_lookback_days)))
        .unwrap_or(NaiveDate::MIN);
    let mut in_window: Vec<Employee> = Vec::with_capacity(unique.len());
    for e in unique {
        if e.start_date > horizon {
            counts.skipped_future_start += 1;
        } else if e.end_date.is_some_and(|end| end < cutoff) {
            counts.skipped_old_leaver += 1;
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
        let active = is_active(e, today);
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
        } else if r.employee.start_date > today {
            counts.sent_inactive_prehire += 1;
        } else {
            counts.sent_inactive_leaver += 1;
        }
    }
    counts.excluded_errors = exclusions.len();
    counts.new_disables = records
        .iter()
        .filter(|r| is_new_disable(r, today, previous))
        .count();
    counts.api_calls_needed = records.len().div_ceil(batch_size.max(1));

    let sent_now: BTreeSet<&str> = records
        .iter()
        .map(|r| r.employee.employee_id.as_str())
        .collect();
    let disappeared: Vec<String> = previous
        .map(|prev| {
            prev.records
                .iter()
                .filter(|(id, st)| st.active && !sent_now.contains(id.as_str()))
                .map(|(id, _)| id.clone())
                .collect()
        })
        .unwrap_or_default();
    counts.disappeared_while_active = disappeared.len();

    // 7. Safety checks.
    let violations = evaluate_guards(&counts, policy, previous, allow_mass_disable);

    Plan {
        today,
        records,
        exclusions,
        warnings,
        disappeared,
        counts,
        violations,
    }
}

/// Active from the start date up to and including the end date.
pub fn is_active(e: &Employee, today: NaiveDate) -> bool {
    e.start_date <= today && e.end_date.is_none_or(|end| today <= end)
}

/// A record now sent as disabled while we do not know for sure it was
/// already disabled. Pre-hires do not count (they are new).
fn is_new_disable(r: &PlannedRecord, today: NaiveDate, previous: Option<&State>) -> bool {
    if r.active || r.employee.start_date > today {
        return false;
    }
    let was_inactive = previous
        .and_then(|s| s.records.get(&r.employee.employee_id))
        .is_some_and(|p| !p.active);
    !was_inactive
}

fn evaluate_guards(
    c: &Counts,
    p: &PolicyConfig,
    previous: Option<&State>,
    allow_mass_disable: bool,
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

    if c.new_disables > p.max_disables_per_run as usize && !allow_mass_disable {
        v.push(GuardViolation {
            guard: "max_disables_per_run",
            message: format!(
                "{} accounts would be disabled, maximum is {} (to proceed deliberately: --allow-mass-disable)",
                c.new_disables, p.max_disables_per_run
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
