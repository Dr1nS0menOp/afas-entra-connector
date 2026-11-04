// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Property-based tests: thousands of random AFAS datasets, including
//! garbage, duplicates and edge cases. The invariants must always hold.

mod common;

use afas_entra_sync::model::{parse_afas_date, text, validate_upn};
use afas_entra_sync::plan::{PlanInput, build_plan, is_active};
use afas_entra_sync::scim::bulk_requests;
use chrono::{Days, NaiveDate};
use common::*;
use proptest::prelude::*;
use serde_json::{Map, Value, json};
use std::collections::HashSet;

fn arb_text() -> impl Strategy<Value = Value> {
    prop_oneof![
        3 => "[A-Za-z]{1,12}".prop_map(Value::from),
        1 => Just(Value::Null),
        1 => Just(json!("   ")),
        1 => any::<String>().prop_map(Value::from),
        1 => any::<i64>().prop_map(Value::from),
        1 => Just(json!(true)),
    ]
}

fn arb_date() -> impl Strategy<Value = Value> {
    prop_oneof![
        6 => (-400i64..400).prop_map(|off| {
            let base = NaiveDate::from_ymd_opt(2026, 10, 30).unwrap();
            let dt = if off >= 0 { base.checked_add_days(Days::new(off as u64)) } else { base.checked_sub_days(Days::new((-off) as u64)) };
            json!(format!("{}T00:00:00Z", dt.unwrap()))
        }),
        1 => Just(Value::Null),
        1 => any::<String>().prop_map(Value::from),
        1 => Just(json!("2026-01-01T23:00:00Z")),
    ]
}

fn valid_date(off: i64) -> Value {
    let base = NaiveDate::from_ymd_opt(2026, 10, 30).unwrap();
    let dt = if off >= 0 {
        base.checked_add_days(Days::new(off as u64))
    } else {
        base.checked_sub_days(Days::new((-off) as u64))
    };
    json!(format!("{}T00:00:00Z", dt.unwrap()))
}

const FIELDS: [&str; 12] = [
    "Personeelsnummer",
    "Roepnaam",
    "Voorvoegsel",
    "Achternaam",
    "UPN",
    "Email",
    "Functie",
    "Afdeling",
    "Leidinggevende",
    "Kostenplaats",
    "DatumInDienst",
    "DatumUitDienst",
];

/// Usually a valid row; sometimes one field is replaced with garbage.
fn arb_row() -> impl Strategy<Value = Map<String, Value>> {
    (
        0u32..150,                                  // employee number (pool: sometimes duplicate)
        prop_oneof![9 => (0u32..170).prop_map(|i| format!("u{i}@contoso.nl")), 1 => (0u32..170).prop_map(|i| format!("U{i}@CONTOSO.NL"))],
        prop_oneof![2 => Just(None), 3 => (0u32..150).prop_map(Some)],
        -400i64..30,                                // start date relative to today
        prop_oneof![2 => Just(None), 1 => (0i64..400).prop_map(Some)], // days after start
        prop_oneof![3 => Just(Value::Null), 1 => Just(json!("van der"))],
        prop::option::weighted(0.25, (0usize..FIELDS.len(), prop_oneof![arb_text(), arb_date()])),
        "[A-Z][a-z]{1,10}",
        "[A-Z][a-z]{1,10}",
        prop_oneof![Just(Value::Null), Just(json!("ICT")), Just(json!("HR"))],
    )
        .prop_map(|(id, upn, mgr, start, dur, prefix, corrupt, given, family, dept)| {
            let mut m = Map::new();
            m.insert("Personeelsnummer".into(), json!(id.to_string()));
            m.insert("Roepnaam".into(), json!(given));
            m.insert("Voorvoegsel".into(), prefix);
            m.insert("Achternaam".into(), json!(family));
            m.insert("UPN".into(), json!(upn));
            m.insert("Email".into(), Value::Null);
            m.insert("Functie".into(), json!("Medewerker"));
            m.insert("Afdeling".into(), dept);
            m.insert("Leidinggevende".into(), mgr.map_or(Value::Null, |x| json!(x.to_string())));
            m.insert("Kostenplaats".into(), Value::Null);
            m.insert("DatumInDienst".into(), valid_date(start));
            m.insert("DatumUitDienst".into(), dur.map_or(Value::Null, |x| valid_date(start + x)));
            if let Some((i, v)) = corrupt {
                m.insert(FIELDS[i].into(), v);
            }
            m
        })
}

/// Dataset with additional literal copies of existing rows (as AFAS
/// can return them on a join or a page shift).
fn arb_rows(min: usize, max: usize) -> impl Strategy<Value = Vec<Map<String, Value>>> {
    (
        prop::collection::vec(arb_row(), min..max),
        prop::collection::vec(any::<prop::sample::Index>(), 0..8),
    )
        .prop_map(|(mut rows, copies)| {
            if !rows.is_empty() {
                for c in copies {
                    let r = rows[c.index(rows.len())].clone();
                    rows.push(r);
                }
            }
            rows
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(3000),
        ..ProptestConfig::default()
    })]

    #[test]
    fn plan_invariants(rows in arb_rows(0, 120), batch in 1u32..=50) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config("http://127.0.0.1:1", "http://127.0.0.1:1", dir.path(), &Opts { batch_size: batch, ..Default::default() });
        let today = d("2026-10-30");
        let plan = build_plan(PlanInput {
            rows: &rows, fields: &cfg.afas.fields, policy: &cfg.policy, batch_size: batch as usize,
            today, previous: None, allow_mass_disable: false, allow_mass_create: false, allow_upn_changes: false,
        });

        let mut ids = HashSet::new();
        let mut upns = HashSet::new();
        let sent: HashSet<&str> = plan.records.iter().map(|r| r.employee.employee_id.as_str()).collect();
        for w in plan.records.windows(2) {
            prop_assert!(w[0].employee.employee_id < w[1].employee.employee_id, "sorted and unique");
        }
        for r in &plan.records {
            let e = &r.employee;
            prop_assert!(ids.insert(e.employee_id.clone()), "duplicate employee number sent");
            prop_assert!(upns.insert(e.upn.to_ascii_lowercase()), "duplicate UPN sent");
            prop_assert!(validate_upn(&e.upn, &cfg.policy.allowed_upn_domains).is_ok());
            prop_assert_eq!(r.active, is_active(e, today));
            prop_assert!(e.start_date <= today.checked_add_days(Days::new(14)).unwrap());
            prop_assert!(e.end_date.is_none_or(|x| x >= today.checked_sub_days(Days::new(30)).unwrap()));
            prop_assert!(e.end_date.is_none_or(|x| x >= e.start_date));
            if let Some(m) = &r.manager_id {
                prop_assert!(m != &e.employee_id);
                prop_assert!(sent.contains(m.as_str()));
            }
            prop_assert!(!e.given_name.is_empty() && !e.family_name.is_empty() && !e.display_name.is_empty());
            prop_assert!(!e.display_name.chars().any(char::is_control));
        }
        // An excluded employee number is never also sent.
        for x in &plan.exclusions {
            if let Some(id) = &x.employee_id {
                prop_assert!(!sent.contains(id.as_str()), "uitgesloten én verstuurd: {}", id);
            }
        }
        // Counts add up.
        let c = &plan.counts;
        prop_assert_eq!(c.sent_total, plan.records.len());
        prop_assert_eq!(c.sent_active + c.sent_inactive_prehire + c.sent_inactive_leaver + c.sent_inactive_outside_window, c.sent_total);
        prop_assert_eq!(c.api_calls_needed, plan.records.len().div_ceil(batch as usize));
        // Payloads: every record exactly once, never more than batch per call.
        let reqs = bulk_requests(&plan.records, batch as usize);
        prop_assert_eq!(reqs.len(), c.api_calls_needed);
        let mut seen = Vec::new();
        for r in &reqs {
            let ops = r["Operations"].as_array().unwrap();
            prop_assert!(!ops.is_empty() && ops.len() <= batch as usize);
            let mut bulk_ids = HashSet::new();
            for op in ops {
                prop_assert!(bulk_ids.insert(op["bulkId"].as_str().unwrap().to_string()));
                prop_assert_eq!(&op["bulkId"], &op["data"]["externalId"]);
                seen.push(op["data"]["externalId"].as_str().unwrap().to_string());
            }
        }
        let expected: Vec<String> = plan.records.iter().map(|r| r.employee.employee_id.clone()).collect();
        prop_assert_eq!(seen, expected);
    }

    #[test]
    fn date_parser_never_panics(s in any::<String>()) {
        let _ = parse_afas_date(&s);
    }

    #[test]
    fn date_parser_roundtrip(y in 1900i32..2200, m in 1u32..=12, dd in 1u32..=28) {
        let date = NaiveDate::from_ymd_opt(y, m, dd).unwrap();
        prop_assert_eq!(parse_afas_date(&format!("{date}T00:00:00Z")), Ok(date));
        prop_assert_eq!(parse_afas_date(&date.to_string()), Ok(date));
    }

    #[test]
    fn text_never_panics_and_is_clean(s in any::<String>()) {
        let mut m = Map::new();
        m.insert("f".into(), Value::String(s));
        if let Ok(Some(t)) = text(&m, "f") {
            prop_assert!(!t.is_empty());
            prop_assert_eq!(t.trim(), t.as_str());
            prop_assert!(!t.contains("  "));
            prop_assert!(!t.chars().any(char::is_control));
        }
    }
}

/// Check on the generator itself: the datasets must really hit all paths
/// (sent, active, inactive, excluded, duplicate, window).
#[test]
fn generator_covers_all_paths() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        dir.path(),
        &Opts::default(),
    );
    let mut runner = TestRunner::deterministic();
    let strat = arb_rows(60, 120);
    let (mut sent, mut active, mut inactive, mut excl, mut merged, mut skipped, mut mgr) =
        (0, 0, 0, 0, 0, 0, 0);
    for _ in 0..200 {
        let rows = strat.new_tree(&mut runner).unwrap().current();
        let p = build_plan(PlanInput {
            rows: &rows,
            fields: &cfg.afas.fields,
            policy: &cfg.policy,
            batch_size: 50,
            today: d("2026-10-30"),
            previous: None,
            allow_mass_disable: false,
            allow_mass_create: false,
            allow_upn_changes: false,
        });
        sent += p.counts.sent_total;
        active += p.counts.sent_active;
        inactive += p.counts.sent_inactive_leaver + p.counts.sent_inactive_prehire;
        excl += p.counts.excluded_errors;
        merged += p.counts.identical_duplicates_merged;
        skipped += p.counts.skipped_future_start + p.counts.skipped_old_leaver;
        mgr += p.records.iter().filter(|r| r.manager_id.is_some()).count();
    }
    println!(
        "sent={sent} active={active} inactive={inactive} excl={excl} merged={merged} skipped={skipped} mgr={mgr}"
    );
    for (name, n) in [
        ("sent", sent),
        ("active", active),
        ("inactive", inactive),
        ("excl", excl),
        ("merged", merged),
        ("skipped", skipped),
        ("mgr", mgr),
    ] {
        assert!(n > 50, "generator raakt pad '{name}' te weinig ({n})");
    }
}
