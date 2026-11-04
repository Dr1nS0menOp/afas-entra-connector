// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! The safety rules added in 0.11: disables that used to slip past the threshold, leavers
//! entered late, employees missing from AFAS, mass creates, changed sign-in names and
//! managers who left.

mod common;

use afas_entra_sync::config::Config;
use afas_entra_sync::plan::{ManagerCause, Plan, PlanInput, build_plan};
use afas_entra_sync::state::{RecordState, STATE_VERSION, State, StateStore};
use afas_entra_sync::sync::next_state;
use chrono::{Days, NaiveDate};
use common::*;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

const TODAY: &str = "2026-11-03";

fn today() -> NaiveDate {
    d(TODAY)
}
fn plus(n: u64) -> NaiveDate {
    today().checked_add_days(Days::new(n)).unwrap()
}
fn minus(n: u64) -> NaiveDate {
    today().checked_sub_days(Days::new(n)).unwrap()
}

fn cfg_with(o: Opts) -> (Config, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let c = config("http://127.0.0.1:1", "http://127.0.0.1:1", dir.path(), &o);
    (c, dir)
}

fn cfg() -> (Config, tempfile::TempDir) {
    cfg_with(Opts::default())
}

struct Allow {
    disable: bool,
    create: bool,
    upn: bool,
}

const NONE: Allow = Allow {
    disable: false,
    create: false,
    upn: false,
};

fn plan(c: &Config, rows: &[Map<String, Value>], prev: Option<&State>, a: &Allow) -> Plan {
    plan_on(c, rows, prev, a, today())
}

fn plan_on(
    c: &Config,
    rows: &[Map<String, Value>],
    prev: Option<&State>,
    a: &Allow,
    on: NaiveDate,
) -> Plan {
    build_plan(PlanInput {
        rows,
        fields: &c.afas.fields,
        policy: &c.policy,
        batch_size: 50,
        today: on,
        previous: prev,
        allow_mass_disable: a.disable,
        allow_mass_create: a.create,
        allow_upn_changes: a.upn,
    })
}

/// A previous run in which these employees were sent with these active flags.
fn prev(entries: &[(&str, bool)]) -> State {
    let records: BTreeMap<String, RecordState> = entries
        .iter()
        .map(|(id, a)| ((*id).to_string(), RecordState::new(*a)))
        .collect();
    State {
        version: STATE_VERSION,
        last_success_utc: "2026-11-02T10:07:00Z".into(),
        sent_total: records.len(),
        records,
    }
}

fn guards(p: &Plan) -> Vec<&'static str> {
    p.violations.iter().map(|v| v.guard).collect()
}

// ------------------------------------------------------------------ 1a

#[test]
fn an_active_account_disabled_by_a_moved_start_date_counts_as_a_disable() {
    let (c, _t) = cfg_with(Opts {
        max_disables: 0,
        ..Default::default()
    });
    // Active last run; AFAS now says the (new) employment starts in 5 days.
    let rows = vec![row("1", plus(5), None)];
    let p = plan(&c, &rows, Some(&prev(&[("1", true)])), &NONE);
    assert!(!p.records[0].active);
    assert_eq!(
        p.counts.new_disables, 1,
        "used to be 0: the guard never saw it"
    );
    assert_eq!(p.new_disable_ids, vec!["1"]);
    assert!(guards(&p).contains(&"max_disables_per_run"));
    // A real new hire (never sent before) still does not count.
    let p = plan(&c, &rows, Some(&prev(&[("9", true)])), &NONE);
    assert_eq!(p.counts.new_disables, 0);
    // Already disabled last run: not new.
    let p = plan(&c, &rows, Some(&prev(&[("1", false)])), &NONE);
    assert_eq!(p.counts.new_disables, 0);
}

// ------------------------------------------------------------------ 1b

#[test]
fn an_end_date_entered_late_still_disables_the_account_once() {
    let (c, _t) = cfg(); // lookback 30 days
    let rows = vec![
        row("1", minus(400), Some(minus(45))),
        row("2", minus(400), None),
    ];
    let p = plan(&c, &rows, Some(&prev(&[("1", true), ("2", true)])), &NONE);
    let r = p
        .records
        .iter()
        .find(|r| r.employee.employee_id == "1")
        .unwrap();
    assert!(!r.active && r.outside_window, "sent once more, disabled");
    assert_eq!(p.counts.sent_inactive_outside_window, 1);
    assert_eq!(p.counts.skipped_old_leaver, 0);
    assert!(p.disappeared.is_empty(), "not missing: it is sent");
    assert_eq!(p.counts.new_disables, 1);
    // The next run: it was sent as disabled, so now it is simply an old leaver.
    let st = next_state(&p, Some(&prev(&[("1", true), ("2", true)])), today());
    assert!(!st.records["1"].active);
    let p2 = plan(&c, &rows, Some(&st), &NONE);
    assert!(p2.records.iter().all(|r| r.employee.employee_id != "1"));
    assert_eq!(p2.counts.skipped_old_leaver, 1);
    assert!(p2.disappeared.is_empty());
}

#[test]
fn a_new_employment_after_the_window_disables_the_current_account() {
    let (c, _t) = cfg(); // pre-hire window 14 days
    let rows = vec![row("1", plus(60), None)];
    let p = plan(&c, &rows, Some(&prev(&[("1", true)])), &NONE);
    assert!(!p.records[0].active && p.records[0].outside_window);
    assert_eq!(p.counts.skipped_future_start, 0);
    // Without an active account last run it simply waits for the window.
    let p = plan(&c, &rows, Some(&prev(&[("1", false)])), &NONE);
    assert!(p.records.is_empty());
    assert_eq!(p.counts.skipped_future_start, 1);
    assert_eq!(p.outside_window.len(), 1);
    assert!(p.outside_window[0].later);
}

// ------------------------------------------------------------------ 1c

#[test]
fn employees_missing_from_afas_stay_on_the_list_until_handled() {
    let (c, t) = cfg_with(Opts {
        max_drop_percent: 100,
        ..Default::default()
    });
    let both = vec![row("1", minus(400), None), row("2", minus(400), None)];
    let only_1 = vec![row("1", minus(400), None)];
    let p0 = plan(&c, &both, None, &NONE);
    let s0 = next_state(&p0, None, today());

    // Run 1: employee 2 is gone.
    let p1 = plan(&c, &only_1, Some(&s0), &NONE);
    assert_eq!(p1.disappeared, vec!["2"]);
    assert_eq!(p1.missing[0].since, today());
    assert_eq!(p1.missing[0].upn.as_deref(), Some("user2@contoso.nl"));
    let s1 = next_state(&p1, Some(&s0), today());
    assert_eq!(s1.sent_total, 1, "missing ones are not counted as sent");
    assert_eq!(s1.records["2"].missing_since, Some(today()));
    assert!(s1.records["2"].active);

    // Run 2, a day later: still reported, with the original date (it used to vanish here).
    let p2 = plan_on(&c, &only_1, Some(&s1), &NONE, plus(1));
    assert_eq!(p2.disappeared, vec!["2"]);
    assert_eq!(p2.missing[0].since, today());
    let s2 = next_state(&p2, Some(&s1), plus(1));
    assert_eq!(s2.records["2"].missing_since, Some(today()));

    // Saved and read back: consistent.
    let store = StateStore::new(&t.path().join("st")).unwrap();
    store.save(&s2).unwrap();
    assert_eq!(store.load().unwrap().unwrap(), s2);

    // Back in AFAS: no longer missing.
    let p3 = plan_on(&c, &both, Some(&s2), &NONE, plus(2));
    assert!(p3.disappeared.is_empty());
    assert!(
        next_state(&p3, Some(&s2), plus(2)).records["2"]
            .missing_since
            .is_none()
    );

    // Marked as handled: forgotten. A number that is not missing is refused.
    assert!(store.acknowledge_missing(&["1".into()]).is_err());
    assert_eq!(store.acknowledge_missing(&[]).unwrap(), vec!["2"]);
    let after = store.load().unwrap().unwrap();
    assert!(!after.records.contains_key("2"));
    assert!(
        plan_on(&c, &only_1, Some(&after), &NONE, plus(2))
            .disappeared
            .is_empty()
    );
}

#[test]
fn a_missing_employee_still_in_afas_with_a_data_error_says_why() {
    let (c, _t) = cfg_with(Opts {
        max_invalid_percent: 100,
        max_drop_percent: 100,
        ..Default::default()
    });
    let mut bad = row("2", minus(400), None);
    bad.insert("UPN".into(), json!("user2@elsewhere.org"));
    let p = plan(
        &c,
        &[row("1", minus(400), None), bad],
        Some(&prev(&[("1", true), ("2", true)])),
        &NONE,
    );
    assert_eq!(p.missing.len(), 1);
    assert!(
        p.missing[0]
            .excluded_because
            .as_deref()
            .unwrap()
            .contains("allowed_upn_domains")
    );
}

// ------------------------------------------------------------------ 1d

#[test]
fn many_new_employee_numbers_stop_the_run() {
    let (c, _t) = cfg_with(Opts {
        max_drop_percent: 100,
        ..Default::default()
    }); // max_new_per_run default 25
    let rows: Vec<_> = (1..=30)
        .map(|i| row(&format!("N{i:02}"), minus(400), None))
        .collect();
    // The same 30 people were sent last run under other numbers (a prefix was added).
    let old: Vec<(String, bool)> = (1..=30).map(|i| (format!("{i:02}"), true)).collect();
    let old_ref: Vec<(&str, bool)> = old.iter().map(|(a, b)| (a.as_str(), *b)).collect();
    let p = plan(&c, &rows, Some(&prev(&old_ref)), &NONE);
    assert_eq!(p.counts.new_records, 30);
    assert!(
        guards(&p).contains(&"max_new_per_run"),
        "{:?}",
        p.violations
    );
    assert_eq!(p.new_ids.len(), 30);
    // Deliberately: proceed.
    let p = plan(
        &c,
        &rows,
        Some(&prev(&old_ref)),
        &Allow {
            create: true,
            ..NONE
        },
    );
    assert!(!guards(&p).contains(&"max_new_per_run"));
    // The first run is all new by definition: no stop.
    let p = plan(&c, &rows, None, &NONE);
    assert!(!guards(&p).contains(&"max_new_per_run"));
    // Exactly at the maximum: fine.
    let p = plan(&c, &rows[..25], Some(&prev(&old_ref)), &NONE);
    assert!(!guards(&p).contains(&"max_new_per_run"));
}

#[test]
fn changed_sign_in_names_are_listed_and_too_many_stop_the_run() {
    let (c, _t) = cfg(); // max_upn_changes_per_run default 5
    let rows: Vec<_> = (1..=6)
        .map(|i| row(&i.to_string(), minus(400), None))
        .collect();
    let mut st = prev(&[
        ("1", true),
        ("2", true),
        ("3", true),
        ("4", true),
        ("5", true),
        ("6", true),
    ]);
    for (id, r) in st.records.iter_mut() {
        r.sent
            .insert("userName".into(), format!("old{id}@contoso.nl"));
    }
    let p = plan(&c, &rows, Some(&st), &NONE);
    assert_eq!(p.counts.upn_changes, 6);
    assert_eq!(p.upn_changes[0].from, "old1@contoso.nl");
    assert_eq!(p.upn_changes[0].to, "user1@contoso.nl");
    assert!(guards(&p).contains(&"max_upn_changes_per_run"));
    let p = plan(&c, &rows, Some(&st), &Allow { upn: true, ..NONE });
    assert!(p.violations.is_empty(), "{:?}", p.violations);
    // Only a different case: not a change.
    for (id, r) in st.records.iter_mut() {
        r.sent
            .insert("userName".into(), format!("USER{id}@Contoso.nl"));
    }
    assert_eq!(plan(&c, &rows, Some(&st), &NONE).counts.upn_changes, 0);
}

// ------------------------------------------------------------------ managers

fn with_manager(mut r: Map<String, Value>, m: &str) -> Map<String, Value> {
    r.insert("Leidinggevende".into(), json!(m));
    r
}

#[test]
fn managers_who_left_or_cannot_be_linked_are_grouped_with_their_reports() {
    let (c, _t) = cfg_with(Opts {
        max_invalid_percent: 100,
        ..Default::default()
    });
    let mut broken = row("M3", minus(400), None);
    broken.insert("UPN".into(), json!("not-an-upn"));
    let rows = vec![
        row("M1", minus(400), Some(minus(60))), // left long ago (not sent)
        row("M2", minus(400), Some(minus(3))),  // left recently (sent disabled)
        broken,                                 // data error
        row("M5", plus(40), None),              // starts after the window
        row("M6", minus(400), None),            // fine
        with_manager(row("a", minus(10), None), "M1"),
        with_manager(row("b", minus(10), None), "M1"),
        with_manager(row("c", minus(10), None), "M2"),
        with_manager(row("d", minus(10), None), "M3"),
        with_manager(row("e", minus(10), None), "M4"), // not in AFAS
        with_manager(row("f", minus(10), None), "M5"),
        with_manager(row("g", minus(10), None), "M6"),
        with_manager(row("h", plus(5), None), "M1"), // new hire: counts
        with_manager(row("i", minus(400), Some(minus(2))), "M1"), // left: does not count
    ];
    let p = plan(&c, &rows, None, &NONE);
    let by: BTreeMap<&str, _> = p
        .manager_gaps
        .iter()
        .map(|g| (g.manager_id.as_str(), g))
        .collect();
    assert_eq!(by.len(), 5, "{:?}", p.manager_gaps);
    assert_eq!(by["M1"].cause, ManagerCause::Left);
    assert_eq!(by["M1"].date, Some(minus(60)));
    assert_eq!(by["M1"].reports, vec!["a", "b", "h"]);
    assert_eq!(
        by["M1"].manager_name.as_deref(),
        Some("VoornaamM1 AchternaamM1")
    );
    assert_eq!(by["M2"].cause, ManagerCause::Left);
    assert_eq!(by["M3"].cause, ManagerCause::Skipped);
    assert!(by["M3"].reason.as_deref().unwrap().contains("UPN"));
    assert_eq!(by["M4"].cause, ManagerCause::NotInAfas);
    assert_eq!(by["M5"].cause, ManagerCause::NotStarted);
    assert!(!by.contains_key("M6"));
}

// ------------------------------------------------------------------ state

#[test]
fn the_state_remembers_exactly_what_was_sent() {
    let (c, _t) = cfg();
    let p = plan(&c, &[row("1", minus(10), None)], None, &NONE);
    let st = next_state(&p, None, today());
    let s = &st.records["1"].sent;
    assert_eq!(s["userName"], "user1@contoso.nl");
    assert_eq!(s["displayName"], "Voornaam1 Achternaam1");
    assert_eq!(s["title"], "Medewerker");
    assert_eq!(s["department"], "ICT");
    assert_eq!(s["costCenter"], "4130");
    assert!(!s.contains_key("manager"));
    assert_eq!(st.records["1"].upn(), Some("user1@contoso.nl"));
}
