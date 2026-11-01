// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
mod common;

use afas_entra_sync::config::Config;
use afas_entra_sync::entra::{Credential, client_assertion};
use afas_entra_sync::http::{backoff, retry_after, snippet};
use afas_entra_sync::model::{parse_afas_date, parse_row, text, validate_upn};
use afas_entra_sync::plan::{Plan, PlanInput, build_plan, is_active};
use afas_entra_sync::scim::{bulk_requests, user_data};
use afas_entra_sync::state::{RecordState, STATE_VERSION, State, StateStore};
use common::*;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::time::Duration;

fn cfg() -> (Config, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    (
        config(
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            dir.path(),
            &Opts::default(),
        ),
        dir,
    )
}

fn plan_with(
    cfg: &Config,
    rows: &[Map<String, Value>],
    today: &str,
    prev: Option<&State>,
    allow: bool,
) -> Plan {
    build_plan(PlanInput {
        rows,
        fields: &cfg.afas.fields,
        policy: &cfg.policy,
        batch_size: cfg.upload.batch_size as usize,
        today: d(today),
        previous: prev,
        allow_mass_disable: allow,
    })
}

fn state_of(entries: &[(&str, bool)]) -> State {
    let records: BTreeMap<String, RecordState> = entries
        .iter()
        .map(|(id, a)| ((*id).to_string(), RecordState { active: *a }))
        .collect();
    State {
        version: STATE_VERSION,
        last_success_utc: "x".into(),
        sent_total: records.len(),
        records,
    }
}

// ---------- dates ----------

#[test]
fn date_formats_accepted() {
    for s in [
        "2024-01-31",
        "2024-01-31T00:00:00",
        "2024-01-31T00:00:00Z",
        "2024-01-31T00:00:00.000Z",
        "2024-01-31T00:00:00+01:00",
        "2024-01-31T00:00:00.0000000-05:00",
        "2024-01-31 00:00:00",
    ] {
        assert_eq!(parse_afas_date(s), Ok(d("2024-01-31")), "{s}");
    }
}

#[test]
fn date_formats_rejected() {
    for s in [
        "",
        "2024-1-31",
        "31-01-2024",
        "2024-02-30",
        "2024-01-31T23:00:00Z",   // time zone conversion: date unreliable
        "2024-01-31T00:00:00.5Z", // not midnight
        "2024-01-31T00:00:00garbage",
        "2024-01-31T00:00",
        "2024-01-31X",
        "2024-01-31T00:00:00+0100",
        "1800-01-01",
        "2024-01-3é",
        "é",
    ] {
        assert!(
            parse_afas_date(s).is_err(),
            "should have been refused: {s:?}"
        );
    }
}

// ---------- text ----------

#[test]
fn text_normalisation() {
    let mut m = Map::new();
    m.insert("a".into(), json!("  Jan   van\tDijk  "));
    m.insert("b".into(), json!("   "));
    m.insert("c".into(), json!(42));
    m.insert("d".into(), json!(1.5));
    m.insert("e".into(), json!(true));
    m.insert("f".into(), json!("a\u{0007}b"));
    m.insert("g".into(), Value::Null);
    assert_eq!(text(&m, "a"), Ok(Some("Jan van Dijk".into())));
    assert_eq!(text(&m, "b"), Ok(None));
    assert_eq!(text(&m, "c"), Ok(Some("42".into())));
    assert!(text(&m, "d").is_err());
    assert!(text(&m, "e").is_err());
    assert!(text(&m, "f").is_err());
    assert_eq!(text(&m, "g"), Ok(None));
    assert_eq!(text(&m, "ontbreekt"), Ok(None));
}

// ---------- UPN ----------

#[test]
fn upn_rules() {
    let dom = vec!["contoso.nl".to_string()];
    for ok in [
        "j.jansen@contoso.nl",
        "J.Jansen@CONTOSO.NL",
        "o'brien@contoso.nl",
        "a-b_c!d#e^f~g@contoso.nl",
    ] {
        assert!(validate_upn(ok, &dom).is_ok(), "{ok}");
    }
    let long_local = format!("{}@contoso.nl", "a".repeat(65));
    for bad in [
        "jansen",
        "j@j@contoso.nl",
        "@contoso.nl",
        ".j@contoso.nl",
        "j.@contoso.nl",
        "j..j@contoso.nl",
        "jé@contoso.nl",
        "j j@contoso.nl",
        "j@fabrikam.nl",
        "j@contoso.nl.evil.com",
        long_local.as_str(),
    ] {
        assert!(validate_upn(bad, &dom).is_err(), "{bad}");
    }
}

// ---------- row parsing ----------

#[test]
fn row_with_prefix_and_display_name() {
    let (c, _t) = cfg();
    let mut r = row("1001", d("2020-01-01"), None);
    r.insert("Voorvoegsel".into(), json!("van der"));
    r.insert("Achternaam".into(), json!("Berg"));
    r.insert("Roepnaam".into(), json!("Piet"));
    let e = parse_row(&r, &c.afas.fields).unwrap();
    assert_eq!(e.family_name, "van der Berg");
    assert_eq!(e.display_name, "Piet van der Berg");
}

#[test]
fn row_errors_are_attributed() {
    let (c, _t) = cfg();
    let mut r = row("1001", d("2020-01-01"), Some(d("2019-01-01")));
    let err = parse_row(&r, &c.afas.fields).unwrap_err();
    assert_eq!(err.employee_id.as_deref(), Some("1001"));
    assert!(err.reason.contains("before start date"));

    r = row("1001", d("2020-01-01"), None);
    r.insert("Functie".into(), json!("x".repeat(129)));
    assert!(
        parse_row(&r, &c.afas.fields)
            .unwrap_err()
            .reason
            .contains("job title")
    );

    r = row("12345678901234567", d("2020-01-01"), None);
    assert!(
        parse_row(&r, &c.afas.fields)
            .unwrap_err()
            .reason
            .contains("longer than 16")
    );

    r = row("1001", d("2020-01-01"), None);
    r.insert("Personeelsnummer".into(), Value::Null);
    assert_eq!(parse_row(&r, &c.afas.fields).unwrap_err().employee_id, None);

    r = row("1001", d("2020-01-01"), None);
    r.insert("DatumInDienst".into(), Value::Null);
    assert!(
        parse_row(&r, &c.afas.fields)
            .unwrap_err()
            .reason
            .contains("start date is missing")
    );

    r = row("1001", d("2020-01-01"), None);
    r.insert("Email".into(), json!("no-mail"));
    assert!(parse_row(&r, &c.afas.fields).is_err());
}

// ---------- active ----------

#[test]
fn active_boundaries() {
    let (c, _t) = cfg();
    let e = parse_row(
        &row("1", d("2026-03-10"), Some(d("2026-06-30"))),
        &c.afas.fields,
    )
    .unwrap();
    assert!(!is_active(&e, d("2026-03-09")));
    assert!(is_active(&e, d("2026-03-10")));
    assert!(is_active(&e, d("2026-06-30")));
    assert!(!is_active(&e, d("2026-07-01")));
}

// ---------- plan ----------

#[test]
fn plan_windows_are_exact() {
    let (c, _t) = cfg(); // prehire 14, lookback 30
    let today = "2026-10-30";
    let rows = vec![
        row("1", d("2026-11-13"), None), // exactly 14 days: yes
        row("2", d("2026-11-14"), None), // 15 days: no
        row("3", d("2020-01-01"), Some(d("2026-09-30"))), // left exactly 30 days ago: yes
        row("4", d("2020-01-01"), Some(d("2026-09-29"))), // 31 days: no
        row("5", d("2020-01-01"), None),
    ];
    let p = plan_with(&c, &rows, today, None, false);
    let ids: Vec<_> = p
        .records
        .iter()
        .map(|r| r.employee.employee_id.as_str())
        .collect();
    assert_eq!(ids, ["1", "3", "5"]);
    assert_eq!(p.counts.skipped_future_start, 1);
    assert_eq!(p.counts.skipped_old_leaver, 1);
    assert_eq!(p.counts.sent_active, 1);
    assert_eq!(p.counts.sent_inactive_prehire, 1);
    assert_eq!(p.counts.sent_inactive_leaver, 1);
}

#[test]
fn plan_duplicates() {
    let (c, _t) = cfg();
    let a = row("1", d("2020-01-01"), None);
    let mut b = row("2", d("2020-01-01"), None);
    let b_same = b.clone();
    let mut b_diff = b.clone();
    b_diff.insert("Afdeling".into(), json!("HR"));
    b.insert("Afdeling".into(), json!("ICT"));
    // identical: merge
    let p = plan_with(
        &c,
        &[a.clone(), b.clone(), b_same],
        "2026-10-30",
        None,
        false,
    );
    assert_eq!(p.records.len(), 2);
    assert_eq!(p.counts.identical_duplicates_merged, 1);
    assert!(p.exclusions.is_empty());
    // different: exclude
    let p = plan_with(&c, &[a.clone(), b, b_diff], "2026-10-30", None, false);
    assert_eq!(p.records.len(), 1);
    assert_eq!(p.exclusions.len(), 1);
    assert_eq!(p.exclusions[0].employee_id.as_deref(), Some("2"));
    // invalid + valid row with the same number: exclude
    let mut bad = row("1", d("2020-01-01"), None);
    bad.insert("UPN".into(), json!("wrong"));
    let p = plan_with(&c, &[a, bad], "2026-10-30", None, false);
    assert!(p.records.is_empty());
}

#[test]
fn plan_duplicate_upn_case_insensitive() {
    let (c, _t) = cfg();
    let a = row("1", d("2020-01-01"), None);
    let mut b = row("2", d("2020-01-01"), None);
    b.insert("UPN".into(), json!("USER1@contoso.nl"));
    let p = plan_with(
        &c,
        &[a, b, row("3", d("2020-01-01"), None)],
        "2026-10-30",
        None,
        false,
    );
    let ids: Vec<_> = p
        .records
        .iter()
        .map(|r| r.employee.employee_id.as_str())
        .collect();
    assert_eq!(ids, ["3"]);
    assert_eq!(p.exclusions.len(), 2);
}

#[test]
fn plan_duplicate_upn_outside_window_is_no_conflict() {
    let (c, _t) = cfg();
    // Former employee (outside window) had the same UPN: not sent, so no conflict.
    let old = row("1", d("2010-01-01"), Some(d("2015-01-01")));
    let mut new = row("2", d("2020-01-01"), None);
    new.insert("UPN".into(), json!("user1@contoso.nl"));
    let p = plan_with(&c, &[old, new], "2026-10-30", None, false);
    assert_eq!(p.records.len(), 1);
    assert!(p.exclusions.is_empty());
}

#[test]
fn plan_manager_rules() {
    let (c, _t) = cfg();
    let boss = row("1", d("2020-01-01"), None);
    let mut emp = row("2", d("2020-01-01"), None);
    emp.insert("Leidinggevende".into(), json!("1"));
    let mut selfm = row("3", d("2020-01-01"), None);
    selfm.insert("Leidinggevende".into(), json!("3"));
    let mut orphan = row("4", d("2020-01-01"), None);
    orphan.insert("Leidinggevende".into(), json!("999"));
    let p = plan_with(&c, &[boss, emp, selfm, orphan], "2026-10-30", None, false);
    let m: Vec<_> = p.records.iter().map(|r| r.manager_id.clone()).collect();
    assert_eq!(m, [None, Some("1".into()), None, None]);
    assert_eq!(p.warnings.len(), 2);
}

#[test]
fn guard_min_records() {
    let (c, _t) = {
        let dir = tempfile::tempdir().unwrap();
        (
            config(
                "http://127.0.0.1:1",
                "http://127.0.0.1:1",
                dir.path(),
                &Opts {
                    min_records: 3,
                    ..Default::default()
                },
            ),
            dir,
        )
    };
    let p = plan_with(
        &c,
        &[
            row("1", d("2020-01-01"), None),
            row("2", d("2020-01-01"), None),
        ],
        "2026-10-30",
        None,
        false,
    );
    assert!(p.violations.iter().any(|v| v.guard == "min_records"));
}

#[test]
fn guard_drop_percent_boundary() {
    let (c, _t) = cfg(); // max 10%
    let rows: Vec<_> = (1..=90)
        .map(|i| row(&i.to_string(), d("2020-01-01"), None))
        .collect();
    let prev100 = state_of(&(1..=100).map(|_| ("x", true)).collect::<Vec<_>>());
    // state_of with duplicate keys gives 1 record; build explicitly:
    let mut prev = prev100;
    prev.records = (1..=100)
        .map(|i| (format!("p{i}"), RecordState { active: true }))
        .collect();
    prev.sent_total = 100;
    // 100 -> 90 = exactly 10%: allowed
    let p = plan_with(&c, &rows, "2026-10-30", Some(&prev), false);
    assert!(
        !p.violations.iter().any(|v| v.guard == "max_drop_percent"),
        "{:?}",
        p.violations
    );
    // 100 -> 89 = 11%: stop
    let p = plan_with(&c, &rows[..89], "2026-10-30", Some(&prev), false);
    assert!(p.violations.iter().any(|v| v.guard == "max_drop_percent"));
}

#[test]
fn guard_invalid_percent() {
    let (c, _t) = cfg(); // max 10%
    let mut rows: Vec<_> = (1..=9)
        .map(|i| row(&i.to_string(), d("2020-01-01"), None))
        .collect();
    let mut bad = row("10", d("2020-01-01"), None);
    bad.insert("UPN".into(), json!("wrong"));
    rows.push(bad.clone());
    // 1 of 10 = 10%: allowed
    assert!(
        plan_with(&c, &rows, "2026-10-30", None, false)
            .violations
            .is_empty()
    );
    let mut bad2 = bad;
    bad2.insert("Personeelsnummer".into(), json!("11"));
    rows.push(bad2);
    // 2 of 11 > 10%: stop
    assert!(
        plan_with(&c, &rows, "2026-10-30", None, false)
            .violations
            .iter()
            .any(|v| v.guard == "max_invalid_percent")
    );
}

#[test]
fn guard_disables() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        dir.path(),
        &Opts {
            max_disables: 2,
            ..Default::default()
        },
    );
    let mut rows: Vec<_> = (1..=10)
        .map(|i| row(&i.to_string(), d("2020-01-01"), None))
        .collect();
    for (i, r) in rows.iter_mut().enumerate().take(3) {
        *r = row(&(i + 1).to_string(), d("2020-01-01"), Some(d("2026-10-29")));
    }
    let all_active: Vec<(String, bool)> = (1..=10).map(|i| (i.to_string(), true)).collect();
    let prev = state_of(
        &all_active
            .iter()
            .map(|(a, b)| (a.as_str(), *b))
            .collect::<Vec<_>>(),
    );
    let p = plan_with(&c, &rows, "2026-10-30", Some(&prev), false);
    assert_eq!(p.counts.new_disables, 3);
    assert!(
        p.violations
            .iter()
            .any(|v| v.guard == "max_disables_per_run")
    );
    // deliberately proceed
    assert!(
        plan_with(&c, &rows, "2026-10-30", Some(&prev), true)
            .violations
            .is_empty()
    );
    // already disabled in the previous run: does not count again
    let mut prev2 = prev.clone();
    for i in 1..=3 {
        prev2
            .records
            .insert(i.to_string(), RecordState { active: false });
    }
    let p = plan_with(&c, &rows, "2026-10-30", Some(&prev2), false);
    assert_eq!(p.counts.new_disables, 0);
    // first run without state: leavers count as possible disables
    assert_eq!(
        plan_with(&c, &rows, "2026-10-30", None, false)
            .counts
            .new_disables,
        3
    );
    // pre-hires never count as disables
    let ph = vec![row("50", d("2026-11-05"), None)];
    assert_eq!(
        plan_with(&c, &ph, "2026-10-30", None, false)
            .counts
            .new_disables,
        0
    );
}

#[test]
fn guard_calls() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        dir.path(),
        &Opts {
            max_calls: 2,
            ..Default::default()
        },
    );
    let rows: Vec<_> = (1..=101)
        .map(|i| row(&i.to_string(), d("2020-01-01"), None))
        .collect();
    let p = plan_with(&c, &rows, "2026-10-30", None, false);
    assert_eq!(p.counts.api_calls_needed, 3);
    assert!(p.violations.iter().any(|v| v.guard == "max_calls_per_run"));
}

#[test]
fn plan_is_deterministic_regardless_of_row_order() {
    let (c, _t) = cfg();
    let mut rows: Vec<_> = (1..=30)
        .map(|i| row(&format!("{i:03}"), d("2020-01-01"), None))
        .collect();
    let p1 = plan_with(&c, &rows, "2026-10-30", None, false);
    rows.reverse();
    let p2 = plan_with(&c, &rows, "2026-10-30", None, false);
    assert_eq!(
        bulk_requests(&p1.records, 50),
        bulk_requests(&p2.records, 50)
    );
}

// ---------- SCIM ----------

#[test]
fn scim_shape_matches_microsoft_example() {
    let (c, _t) = cfg();
    let mut boss = row("701984", d("2020-01-01"), None);
    boss.insert("Roepnaam".into(), json!("Barbara"));
    boss.insert("Achternaam".into(), json!("Jensen"));
    boss.insert("UPN".into(), json!("bjensen@contoso.nl"));
    let mut emp = row("701985", d("2020-01-01"), None);
    emp.insert("Leidinggevende".into(), json!("701984"));
    let p = plan_with(&c, &[boss, emp], "2026-10-30", None, false);
    let reqs = bulk_requests(&p.records, 50);
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert_eq!(
        r["schemas"],
        json!(["urn:ietf:params:scim:api:messages:2.0:BulkRequest"])
    );
    assert_eq!(r["failOnErrors"], Value::Null);
    let op = &r["Operations"][0];
    assert_eq!(op["method"], "POST");
    assert_eq!(op["path"], "/Users");
    assert_eq!(op["bulkId"], "701984");
    let data = &op["data"];
    assert_eq!(
        data["schemas"],
        json!([
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        ])
    );
    assert_eq!(data["externalId"], "701984");
    assert_eq!(data["userName"], "bjensen@contoso.nl");
    assert_eq!(data["name"]["givenName"], "Barbara");
    assert_eq!(data["name"]["familyName"], "Jensen");
    assert_eq!(data["active"], true);
    assert_eq!(data["emails"][0]["type"], "work");
    let ent = &data["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"];
    assert_eq!(ent["employeeNumber"], "701984");
    assert_eq!(ent["department"], "ICT");
    assert_eq!(ent["costCenter"], "4130");
    assert!(ent.get("manager").is_none());
    let ent2 =
        &r["Operations"][1]["data"]["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"];
    assert_eq!(ent2["manager"]["value"], "701984");
}

#[test]
fn scim_omits_empty_optionals() {
    let (c, _t) = cfg();
    let mut r = row("1", d("2020-01-01"), None);
    for k in ["Functie", "Afdeling", "Kostenplaats", "Email"] {
        r.insert(k.into(), Value::Null);
    }
    let p = plan_with(&c, &[r], "2026-10-30", None, false);
    let data = user_data(&p.records[0]);
    assert!(data.get("title").is_none());
    assert!(data.get("emails").is_none());
    let ent = &data["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"];
    assert!(ent.get("department").is_none() && ent.get("costCenter").is_none());
    assert!(!data.to_string().contains("null"));
}

#[test]
fn scim_chunking() {
    let (c, _t) = cfg();
    let rows: Vec<_> = (1..=101)
        .map(|i| row(&i.to_string(), d("2020-01-01"), None))
        .collect();
    let p = plan_with(&c, &rows, "2026-10-30", None, false);
    let reqs = bulk_requests(&p.records, 50);
    let sizes: Vec<_> = reqs
        .iter()
        .map(|r| r["Operations"].as_array().unwrap().len())
        .collect();
    assert_eq!(sizes, [50, 50, 1]);
}

// ---------- config ----------

#[test]
fn config_rejects_mistakes() {
    let dir = tempfile::tempdir().unwrap();
    let tok = dir.path().join("t");
    let base = config_toml(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        dir.path(),
        &tok,
        "certificate",
        &Opts::default(),
    );
    assert!(Config::parse(&base).is_ok());
    let cases: Vec<(&str, String)> = vec![
        (
            "unknown key",
            base.replace("[policy]", "[policy]\nmax_disable_per_run = 5"),
        ),
        (
            "not a guid",
            base.replace(TENANT, "contoso.onmicrosoft.com"),
        ),
        (
            "batch 51",
            base.replace("batch_size = 50", "batch_size = 51"),
        ),
        ("batch 0", base.replace("batch_size = 50", "batch_size = 0")),
        (
            "http afas",
            base.replace(
                "http://127.0.0.1:1/ProfitRestServices",
                "http://afas.example/x",
            ),
        ),
        ("empty domain", base.replace(r#"["contoso.nl"]"#, "[]")),
        (
            "tijdzone",
            base.replace("Europe/Amsterdam", "Europe/Nowhere"),
        ),
        (
            "duplicate field",
            base.replace(r#"department = "Afdeling""#, r#"department = "Functie""#),
        ),
        (
            "two token sources",
            base.replace("[afas]", "[afas]\ntoken_env = \"X\""),
        ),
        (
            "no order for paging",
            base.replace("order_by_field = \"Personeelsnummer\"", ""),
        ),
        (
            "order on two fields",
            base.replace(
                "order_by_field = \"Personeelsnummer\"",
                "order_by_field = \"A,B\"",
            ),
        ),
        (
            "page_size 0",
            base.replace("page_size = 1000", "page_size = 0"),
        ),
        (
            "percentage",
            base.replace("max_drop_percent = 10", "max_drop_percent = 101"),
        ),
        ("min 0", base.replace("min_records = 1", "min_records = 0")),
        (
            "cert + secret",
            base.replace(
                "auth = \"certificate\"",
                "auth = \"certificate\"\nclient_secret_env = \"X\"",
            ),
        ),
    ];
    for (name, toml) in cases {
        assert!(
            Config::parse(&toml).is_err(),
            "should have been refused: {name}"
        );
    }
}

#[test]
fn example_config_in_repo_is_valid() {
    let text = std::fs::read_to_string(format!(
        "{}/afas-entra-sync.example.toml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    Config::parse(&text).expect("example config must be valid");
}

// ---------- state ----------

#[test]
fn state_roundtrip_corruption_and_lock() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::new(dir.path()).unwrap();
    assert!(store.load().unwrap().is_none());
    let s = state_of(&[("1", true), ("2", false)]);
    store.save(&s).unwrap();
    assert_eq!(store.load().unwrap(), Some(s));

    std::fs::write(dir.path().join("state.json"), "{kapot").unwrap();
    assert!(store.load().is_err());
    std::fs::write(
        dir.path().join("state.json"),
        r#"{"version":2,"last_success_utc":"x","sent_total":0,"records":{}}"#,
    )
    .unwrap();
    assert!(store.load().is_err());
    std::fs::write(
        dir.path().join("state.json"),
        r#"{"version":1,"last_success_utc":"x","sent_total":5,"records":{}}"#,
    )
    .unwrap();
    assert!(store.load().is_err());

    let l1 = store.lock().unwrap();
    assert!(matches!(
        store.lock(),
        Err(afas_entra_sync::error::AppError::Locked(_))
    ));
    drop(l1);
    assert!(store.lock().is_ok());
}

// ---------- http ----------

#[test]
fn backoff_and_retry_after() {
    assert_eq!(backoff(1, 1000, 8000), Duration::from_secs(1));
    assert_eq!(backoff(3, 1000, 8000), Duration::from_secs(4));
    assert_eq!(backoff(10, 1000, 8000), Duration::from_secs(8));
    assert_eq!(
        backoff(u32::MAX, u64::MAX, u64::MAX),
        Duration::from_millis(u64::MAX)
    );

    let now = chrono::DateTime::parse_from_rfc3339("2026-10-30T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let mut h = reqwest::header::HeaderMap::new();
    assert_eq!(retry_after(&h, now), None);
    h.insert("retry-after", "7".parse().unwrap());
    assert_eq!(retry_after(&h, now), Some(Duration::from_secs(7)));
    h.insert(
        "retry-after",
        "Fri, 30 Oct 2026 12:00:30 GMT".parse().unwrap(),
    );
    assert_eq!(retry_after(&h, now), Some(Duration::from_secs(30)));
    h.insert(
        "retry-after",
        "Fri, 30 Oct 2026 11:00:00 GMT".parse().unwrap(),
    );
    assert_eq!(retry_after(&h, now), Some(Duration::ZERO));
    h.insert("retry-after", "binnenkort".parse().unwrap());
    assert_eq!(retry_after(&h, now), None);

    assert_eq!(snippet("ééé", 2), "éé…");
    assert_eq!(snippet("a\nb", 10), "a b");
    assert_eq!(snippet("ab", 2), "ab");
    assert_eq!(snippet("abc", 2), "ab…");
}

// ---------- certificate / JWT ----------

fn fingerprint_b64url(file: &str) -> String {
    use base64::Engine;
    let txt = std::fs::read_to_string(fixture(file)).unwrap();
    let hex = txt.trim().split('=').nth(1).unwrap().replace(':', "");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn client_assertion_is_valid_and_thumbprints_match_openssl() {
    let cert = std::fs::read(fixture("test-cert.pem")).unwrap();
    for key in ["test-key.pem", "test-key-pkcs1.pem"] {
        let key_pem = std::fs::read(fixture(key)).unwrap();
        let Credential::Certificate {
            key_pem,
            x5t,
            x5t_s256,
        } = Credential::certificate(&cert, key_pem).unwrap()
        else {
            panic!()
        };
        assert_eq!(x5t, fingerprint_b64url("sha1.txt"));
        assert_eq!(x5t_s256, fingerprint_b64url("sha256.txt"));
        let url = format!("https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token");
        let now = chrono::Utc::now().timestamp();
        let jwt = client_assertion(&url, CLIENT, &key_pem, &x5t, &x5t_s256, now).unwrap();

        let pubkey = jsonwebtoken::DecodingKey::from_rsa_pem(
            &std::fs::read(fixture("test-pub.pem")).unwrap(),
        )
        .unwrap();
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        v.set_audience(&[url.as_str()]);
        v.set_issuer(&[CLIENT]);
        v.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);
        let data = jsonwebtoken::decode::<Value>(&jwt, &pubkey, &v).unwrap();
        assert_eq!(data.claims["sub"], CLIENT);
        assert!(data.claims["jti"].as_str().unwrap().len() == 36);
        assert_eq!(data.header.x5t.as_deref(), Some(x5t.as_str()));
        // Exact time claims (the validator has 60 s leeway, so check separately).
        assert_eq!(data.claims["iat"], now);
        assert_eq!(data.claims["nbf"], now - 60);
        assert_eq!(data.claims["exp"], now + 600);
        assert_eq!(data.claims["aud"], url.as_str());
        assert_eq!(data.claims["iss"], CLIENT);
        assert_eq!(data.header.typ.as_deref(), Some("JWT"));
        assert_eq!(data.header.x5t_s256.as_deref(), Some(x5t_s256.as_str()));
    }
}

#[test]
fn certificate_errors_are_config_errors() {
    let cert = std::fs::read(fixture("test-cert.pem")).unwrap();
    assert!(Credential::certificate(&cert, b"no key".to_vec()).is_err());
    assert!(
        Credential::certificate(b"no cert", std::fs::read(fixture("test-key.pem")).unwrap())
            .is_err()
    );
    let double = [cert.clone(), cert].concat();
    assert!(
        Credential::certificate(&double, std::fs::read(fixture("test-key.pem")).unwrap()).is_err()
    );
}

#[test]
fn disappeared_while_active_is_detected() {
    let (c, _t) = cfg();
    let rows = vec![
        row("1", d("2020-01-01"), None),
        row("3", d("2020-01-01"), Some(d("2026-10-01"))),
    ];
    // 1 = still active, 2 = disappeared while active, 3 = now a leaver (still sent), 4 = was already inactive
    let prev = state_of(&[("1", true), ("2", true), ("3", true), ("4", false)]);
    let p = plan_with(&c, &rows, "2026-10-30", Some(&prev), true);
    assert_eq!(p.disappeared, vec!["2".to_string()]);
    assert_eq!(p.counts.disappeared_while_active, 1);
    assert!(
        plan_with(&c, &rows, "2026-10-30", None, true)
            .disappeared
            .is_empty()
    );
}

#[test]
fn afas_auth_header_variants() {
    use afas_entra_sync::afas::auth_header;
    use base64::Engine;
    let dec = |h: String| {
        let b = h.strip_prefix("AfasToken ").unwrap();
        String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b).unwrap()).unwrap()
    };
    let xml = "<token><version>1</version><data>ABC123</data></token>";
    assert_eq!(dec(auth_header(xml).unwrap()), xml);
    assert_eq!(dec(auth_header(&format!("  {xml}\n")).unwrap()), xml);
    assert_eq!(dec(auth_header("ABC123\n").unwrap()), xml);
    for bad in [
        "",
        "   ",
        "<token><version>1</version><data>ABC123</data>", // no closing tag
        "<token><version>1</version></token>",            // no data
        "ABC 123",
        "ABC<123",
    ] {
        assert!(auth_header(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn all_length_limits_are_exact() {
    let (c, _t) = cfg();
    let base = || row("1001", d("2020-01-01"), None);
    // (field, maximum)
    for (field, max) in [
        ("Roepnaam", 64usize),
        ("Achternaam", 64),
        ("Functie", 128),
        ("Afdeling", 64),
        ("Kostenplaats", 64),
    ] {
        let mut r = base();
        r.insert(field.into(), json!("x".repeat(max)));
        assert!(
            parse_row(&r, &c.afas.fields).is_ok(),
            "{field} with {max} characters must be allowed"
        );
        r.insert(field.into(), json!("x".repeat(max + 1)));
        assert!(
            parse_row(&r, &c.afas.fields).is_err(),
            "{field} with {} characters must fail",
            max + 1
        );
    }
    // employee number: 16
    let r = row(&"1".repeat(16), d("2020-01-01"), None);
    assert!(parse_row(&r, &c.afas.fields).is_ok());
    let r = row(&"1".repeat(17), d("2020-01-01"), None);
    assert!(parse_row(&r, &c.afas.fields).is_err());
    // manager: 16
    let mut r = base();
    r.insert("Leidinggevende".into(), json!("2".repeat(16)));
    assert!(parse_row(&r, &c.afas.fields).is_ok());
    r.insert("Leidinggevende".into(), json!("2".repeat(17)));
    assert!(parse_row(&r, &c.afas.fields).is_err());
    r.insert("Leidinggevende".into(), json!("2 2"));
    assert!(parse_row(&r, &c.afas.fields).is_err());
    // family name incl. prefix: 64 together
    let mut r = base();
    r.insert("Voorvoegsel".into(), json!("van"));
    r.insert("Achternaam".into(), json!("x".repeat(60))); // "van " + 60 = 64
    assert!(parse_row(&r, &c.afas.fields).is_ok());
    r.insert("Achternaam".into(), json!("x".repeat(61)));
    assert!(parse_row(&r, &c.afas.fields).is_err());
    // display name (computed): 256 is the limit; given+family name never reach it, so via the UPN limit:
    // UPN total 113, local part 64
    let dom = vec!["contoso.nl".to_string()];
    let ok_local = format!("{}@contoso.nl", "a".repeat(64));
    assert!(validate_upn(&ok_local, &dom).is_ok());
    let long_dom = vec![format!("{}.nl", "d".repeat(60))];
    let total_113 = format!("{}@{}", "a".repeat(49), long_dom[0]); // 49 + 1 + 63 = 113
    assert_eq!(total_113.len(), 113);
    assert!(validate_upn(&total_113, &long_dom).is_ok());
    let total_114 = format!("{}@{}", "a".repeat(50), long_dom[0]);
    assert!(validate_upn(&total_114, &long_dom).is_err());
}

#[test]
fn one_day_employment_is_valid_and_active_that_day() {
    let (c, _t) = cfg();
    let e = parse_row(
        &row("1", d("2026-10-30"), Some(d("2026-10-30"))),
        &c.afas.fields,
    )
    .unwrap();
    assert!(is_active(&e, d("2026-10-30")));
    assert!(!is_active(&e, d("2026-10-29")) && !is_active(&e, d("2026-10-31")));
}

#[test]
fn date_year_range_is_exact() {
    assert_eq!(parse_afas_date("1900-01-01"), Ok(d("1900-01-01")));
    assert_eq!(parse_afas_date("2200-12-31"), Ok(d("2200-12-31")));
    assert!(parse_afas_date("1899-12-31").is_err());
    assert!(parse_afas_date("2201-01-01").is_err());
    assert!(parse_afas_date("9999-12-31").is_err());
}

#[test]
fn type_errors_name_the_type() {
    let mut m = Map::new();
    for (v, name) in [
        (json!(true), "boolean"),
        (json!([1]), "list"),
        (json!({"a": 1}), "object"),
    ] {
        m.insert("f".into(), v);
        assert!(text(&m, "f").unwrap_err().contains(name), "{name}");
    }
    m.insert("f".into(), json!(5));
    let mut r = Map::new();
    r.insert("d".into(), json!(20240101));
    assert!(
        afas_entra_sync::model::date(&r, "d")
            .unwrap_err()
            .contains("number")
    );
}

#[test]
fn remaining_guard_boundaries_are_exact() {
    let mk = |o: Opts| {
        let dir = tempfile::tempdir().unwrap();
        (
            config("http://127.0.0.1:1", "http://127.0.0.1:1", dir.path(), &o),
            dir,
        )
    };
    let has = |p: &Plan, g: &str| p.violations.iter().any(|v| v.guard == g);
    let active = |n: usize| -> Vec<_> {
        (1..=n)
            .map(|i| row(&i.to_string(), d("2020-01-01"), None))
            .collect()
    };

    // max_disables_per_run = 2: exactly 2 is allowed, 3 is not
    let (c, _t) = mk(Opts {
        max_disables: 2,
        ..Default::default()
    });
    let mut rows = active(10);
    for (i, r) in rows.iter_mut().enumerate().take(2) {
        *r = row(&(i + 1).to_string(), d("2020-01-01"), Some(d("2026-10-29")));
    }
    let p = plan_with(&c, &rows, "2026-10-30", None, false);
    assert_eq!(p.counts.new_disables, 2);
    assert!(!has(&p, "max_disables_per_run"));
    rows[2] = row("3", d("2020-01-01"), Some(d("2026-10-29")));
    assert!(has(
        &plan_with(&c, &rows, "2026-10-30", None, false),
        "max_disables_per_run"
    ));

    // min_records = 3: exactly 3 is allowed, 2 is not
    let (c, _t) = mk(Opts {
        min_records: 3,
        ..Default::default()
    });
    assert!(!has(
        &plan_with(&c, &active(3), "2026-10-30", None, false),
        "min_records"
    ));
    assert!(has(
        &plan_with(&c, &active(2), "2026-10-30", None, false),
        "min_records"
    ));

    // max_calls_per_run = 2 at 50 per call: 100 records allowed, 101 not
    let (c, _t) = mk(Opts {
        max_calls: 2,
        ..Default::default()
    });
    assert!(!has(
        &plan_with(&c, &active(100), "2026-10-30", None, false),
        "max_calls_per_run"
    ));
    assert!(has(
        &plan_with(&c, &active(101), "2026-10-30", None, false),
        "max_calls_per_run"
    ));
}

#[test]
fn unreadable_state_is_an_error_not_a_first_run() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::new(dir.path()).unwrap();
    // state.json exists, but cannot be read as a file
    std::fs::create_dir(dir.path().join("state.json")).unwrap();
    assert!(
        store.load().is_err(),
        "unreadable state must never count as 'first run'"
    );
}

// ---------- security ----------

#[cfg(unix)]
#[test]
fn secret_files_must_be_private() {
    use afas_entra_sync::state::check_private_file;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("secret");
    std::fs::write(&f, "x").unwrap();
    for (mode, ok) in [
        (0o600, true),
        (0o400, true),
        (0o640, false),
        (0o644, false),
        (0o604, false),
        (0o620, false),
    ] {
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        let r = check_private_file(&f, "test secret");
        assert_eq!(r.is_ok(), ok, "mode {mode:o}: {r:?}");
        if !ok {
            assert!(r.unwrap_err().to_string().contains("chmod 600"));
        }
    }
    assert!(check_private_file(dir.path(), "dir").is_err());
    assert!(check_private_file(&dir.path().join("missing"), "x").is_err());
}

#[cfg(unix)]
#[test]
fn readable_token_file_stops_the_run() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        dir.path(),
        &Opts::default(),
    );
    let tok = cfg.afas.token_file.clone().unwrap();
    std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o644)).unwrap();
    let e = afas_entra_sync::afas::read_token(&cfg.afas).unwrap_err();
    assert!(e.to_string().contains("group or others"), "{e}");
}

#[test]
fn response_bodies_are_capped() {
    use afas_entra_sync::http::read_capped;
    assert_eq!(read_capped(&b"abc"[..], 3).unwrap(), "abc");
    assert!(
        read_capped(&b"abcd"[..], 3)
            .unwrap_err()
            .contains("larger than 3")
    );
    assert!(read_capped(&[0xff, 0xfe][..], 10).is_err());
}
