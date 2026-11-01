// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! The decision rules of the modules, tested directly at their boundaries: which groups
//! may be managed, who matches a rule, who is eligible, who counts as a departing
//! employee, who gets a first sign-in code, and which webhook events are detected.

mod common;

use afas_entra_sync::graph::EntraUser;
use afas_entra_sync::modules::records::{Exception, ExceptionKind};
use afas_entra_sync::modules::roles::{GroupInfo, check_group, eligible, plan, rule_matches};
use afas_entra_sync::modules::settings::{EventKind, JoinerConfig, RoleRule, RolesConfig};
use afas_entra_sync::modules::{Found, ModuleState, Person, Snapshot, joiner, leaver, webhook};
use chrono::{Days, NaiveDate};
use common::today_ams;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};

const G1: &str = "a1a1a1a1-0000-0000-0000-000000000001";
const G2: &str = "a1a1a1a1-0000-0000-0000-000000000002";
const G3: &str = "a1a1a1a1-0000-0000-0000-000000000003";

fn today() -> NaiveDate {
    today_ams()
}
fn plus(n: u64) -> NaiveDate {
    today().checked_add_days(Days::new(n)).unwrap()
}
fn minus(n: u64) -> NaiveDate {
    today().checked_sub_days(Days::new(n)).unwrap()
}

fn person(id: &str, f: impl FnOnce(&mut Snapshot)) -> Person {
    let mut snap = Snapshot {
        active: true,
        upn: format!("u{id}@x.nl"),
        display_name: format!("Person {id}"),
        start_date: minus(400),
        ..Default::default()
    };
    f(&mut snap);
    Person {
        employee_id: id.into(),
        snap,
        population: None,
    }
}

fn eu(id: &str, emp: &str) -> EntraUser {
    EntraUser {
        id: id.into(),
        upn: format!("u{emp}@x.nl"),
        employee_id: Some(emp.into()),
        mail: None,
        enabled: true,
    }
}

fn roles_cfg(extra: &str) -> RolesConfig {
    toml::from_str(&format!(
        "enabled = true\nclient_id = \"c0000000-0000-0000-0000-000000000001\"\ncertificate_pem = \"/c\"\nprivate_key_pem = \"/k\"\ngroup_prefix = \"AFAS-\"\n{extra}"
    ))
    .unwrap()
}

fn rule(toml_text: &str) -> RoleRule {
    toml::from_str(&format!("group_id = \"{G1}\"\n{toml_text}")).unwrap()
}

// ------------------------------------------------------------------ roles

#[test]
fn only_safe_groups_with_the_prefix_can_be_managed() {
    let g = |extra: serde_json::Value| {
        let mut v = json!({"id": G1, "displayName": "AFAS-ICT", "isAssignableToRole": false,
                           "onPremisesSyncEnabled": null, "groupTypes": []});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        check_group(&v, "AFAS-")
    };
    assert_eq!(g(json!({})), Ok("AFAS-ICT".into()));
    assert_eq!(g(json!({"groupTypes": ["Unified"]})), Ok("AFAS-ICT".into()));
    assert_eq!(
        g(json!({"onPremisesSyncEnabled": false})),
        Ok("AFAS-ICT".into())
    );
    for (extra, why) in [
        (json!({"displayName": "ICT"}), "group_prefix"),
        (json!({"displayName": "afas-ICT"}), "group_prefix"),
        (json!({"isAssignableToRole": true}), "role-assignable"),
        (json!({"onPremisesSyncEnabled": true}), "on-premises"),
        (json!({"groupTypes": ["DynamicMembership"]}), "dynamic"),
    ] {
        let e = g(extra.clone()).unwrap_err();
        assert!(e.contains(why), "{extra}: {e}");
    }
}

#[test]
fn every_rule_criterion_matches_its_own_attribute() {
    let p = {
        let mut p = person("1", |s| {
            s.department = Some("ICT".into());
            s.job_title = Some("Developer".into());
            s.job_profile = Some("DEV2".into());
            s.office = Some("Utrecht".into());
            s.company = Some("Example BV".into());
            s.employee_type = Some("Employee".into());
            s.cost_center = Some("4130".into());
        });
        p.population = Some("contractors".into());
        p
    };
    for (key, value) in [
        ("department", "ICT"),
        ("job_title", "Developer"),
        ("job_profile", "DEV2"),
        ("office", "Utrecht"),
        ("company", "Example BV"),
        ("employee_type", "Employee"),
        ("cost_center", "4130"),
        ("population", "contractors"),
    ] {
        assert!(
            rule_matches(&rule(&format!("{key} = [\"{value}\"]")), &p),
            "{key}"
        );
        // Case and surrounding spaces do not matter; one of several values is enough.
        let loose = format!("{key} = [\"nope\", \" {} \"]", value.to_uppercase());
        assert!(rule_matches(&rule(&loose), &p), "{key} loose");
        assert!(
            !rule_matches(&rule(&format!("{key} = [\"nope\"]")), &p),
            "{key} other"
        );
    }
    // All criteria must match.
    assert!(rule_matches(
        &rule("department = [\"ICT\"]\noffice = [\"Utrecht\"]"),
        &p
    ));
    assert!(!rule_matches(
        &rule("department = [\"ICT\"]\noffice = [\"Zwolle\"]"),
        &p
    ));
    // A criterion the person has no value for does not match.
    let bare = person("2", |_| {});
    assert!(!rule_matches(&rule("department = [\"ICT\"]"), &bare));
    assert!(rule_matches(&rule("all = true"), &bare));
}

#[test]
fn eligibility_for_groups_at_its_boundaries() {
    let off = roles_cfg("");
    let pre = roles_cfg("include_prehires = true");
    let keep3 = roles_cfg("keep_leavers_days = 3");
    let active = person("1", |_| {});
    let future = person("2", |s| {
        s.active = false;
        s.start_date = plus(5);
    });
    let left = |days: u64| {
        person("3", move |s| {
            s.active = false;
            s.end_date = Some(minus(days));
        })
    };
    assert!(eligible(&off, &active, today()));
    assert!(!eligible(&off, &future, today()));
    assert!(eligible(&pre, &future, today()));
    assert!(!eligible(&off, &left(1), today()));
    assert!(eligible(&keep3, &left(3), today()));
    assert!(!eligible(&keep3, &left(4), today()));
    assert!(
        !eligible(&pre, &left(1), today()),
        "include_prehires is not about leavers"
    );
}

fn found(pairs: &[(&str, Found)]) -> HashMap<String, Found> {
    pairs
        .iter()
        .map(|(k, f)| (k.to_string(), f.clone()))
        .collect()
}

fn exception(emp: &str, group: &str, until: NaiveDate) -> Exception {
    Exception {
        id: "x1".into(),
        employee_id: emp.into(),
        group_id: group.into(),
        kind: ExceptionKind::Include,
        until,
        reason: "test".into(),
        created_by: "t".into(),
        created_utc: "2026-01-01T00:00:00Z".into(),
    }
}

#[test]
fn role_plan_notes() {
    let cfg = roles_cfg(&format!(
        "[[rule]]\ngroup_id = \"{G1}\"\ndepartment = [\"ICT\"]\n\n[[rule]]\ngroup_id = \"{G3}\"\ndepartment = [\"Finance\"]\n\n[[sod]]\nname = \"ICT vs Finance\"\ngroups = [\"{G1}\", \"{G3}\"]\n"
    ));
    let ict = |id: &str| person(id, |s| s.department = Some("ICT".into()));
    let hr = |id: &str| person(id, |s| s.department = Some("HR".into()));
    // 1 is in both conflicting groups by hand, the rules give only one.
    let groups = vec![
        GroupInfo {
            id: G1.into(),
            name: "AFAS-ICT".into(),
            members: vec![eu("u1", "1")],
        },
        GroupInfo {
            id: G3.into(),
            name: "AFAS-Fin".into(),
            members: vec![eu("u1", "1")],
        },
    ];
    let people = [ict("1"), ict("2"), hr("3")];
    let f = found(&[
        ("1", Found::User(eu("u1", "1"))),
        ("2", Found::Missing),
        ("3", Found::Missing),
    ]);
    // Exceptions: one active for a group outside the rules (noted), one expired (silent).
    let x = [
        exception("1", G2, today()),
        exception("1", "a1a1a1a1-0000-0000-0000-0000000000ff", minus(1)),
    ];
    let p = plan(&cfg, &people, &f, &groups, &x, today());
    let has = |s: &str| p.notes.iter().filter(|n| n.contains(s)).count();
    assert_eq!(has("already in 2 of its groups"), 1, "{:?}", p.notes);
    assert_eq!(has("ignored"), 1, "{:?}", p.notes);
    assert!(p.notes.iter().any(|n| n.contains(G2)), "{:?}", p.notes);
    // 2 should get a group but has no account yet: noted. 3 gets no groups: silent.
    assert_eq!(has("2: not in Entra yet"), 1, "{:?}", p.notes);
    assert_eq!(has("3: not in Entra yet"), 0, "{:?}", p.notes);
    // The hand-made membership of the finance group is removed (rules say ICT only).
    assert_eq!(p.removes.len(), 1);
    assert_eq!(p.removes[0].0, G3);
}

// ------------------------------------------------------------------ departing employees

#[test]
fn departing_employee_window_at_its_boundaries() {
    let left = |end: NaiveDate, f: fn(&mut Snapshot)| {
        person("9", move |s| {
            s.active = false;
            s.end_date = Some(end);
            f(s);
        })
    };
    let none: fn(&mut Snapshot) = |_| {};
    let g = 7;
    assert_eq!(
        leaver::is_recent_leaver(&left(minus(1), none), g, today()),
        Some(minus(1))
    );
    assert_eq!(
        leaver::is_recent_leaver(&left(minus(7), none), g, today()),
        Some(minus(7))
    );
    assert_eq!(
        leaver::is_recent_leaver(&left(minus(8), none), g, today()),
        None
    );
    assert_eq!(
        leaver::is_recent_leaver(&left(today(), none), g, today()),
        None
    );
    // Still marked active (e.g. extended): nothing.
    assert_eq!(
        leaver::is_recent_leaver(&left(minus(1), |s| s.active = true), g, today()),
        None
    );
    // Rehired with a future start date: nothing.
    assert_eq!(
        leaver::is_recent_leaver(&left(minus(1), |s| s.start_date = plus(3)), g, today()),
        None
    );
    // No end date: nothing.
    let no_end = person("8", |s| s.active = false);
    assert_eq!(leaver::is_recent_leaver(&no_end, g, today()), None);
}

// ------------------------------------------------------------------ new hires

fn joiner_cfg(deliver: &str) -> JoinerConfig {
    toml::from_str(&format!(
        "enabled = true\nclient_id = \"c0000000-0000-0000-0000-000000000002\"\ncertificate_pem = \"/c\"\nprivate_key_pem = \"/k\"\nsender = \"noreply@x.nl\"\ndeliver_to = \"{deliver}\"\nfixed_address = \"desk@x.nl\"\n"
    ))
    .unwrap()
}

#[test]
fn new_hire_codes_who_and_where_to() {
    let cfg = joiner_cfg("manager");
    let mgr = person("100", |s| s.email = None);
    let hire = |id: &str, start: NaiveDate, end: Option<NaiveDate>| {
        person(id, move |s| {
            s.start_date = start;
            s.end_date = end;
            s.manager_id = Some("100".into());
        })
    };
    let people = [
        mgr.clone(),
        hire("1", minus(2), Some(today())), // last day today: still gets one
        hire("2", minus(2), Some(minus(1))), // already left: none
        hire("3", plus(1), None),           // account conflict: none, noted
        hire("4", plus(1), None),           // not in Entra yet: none, noted
    ];
    let mut mgr_user = eu("m", "100");
    mgr_user.mail = Some("boss@x.nl".into());
    let mut f = found(&[
        ("100", Found::User(mgr_user.clone())),
        ("1", Found::User(eu("u1", "1"))),
        ("2", Found::User(eu("u2", "2"))),
        (
            "3",
            Found::Conflict("employeeId 3 is on more than one Entra user".into()),
        ),
        ("4", Found::Missing),
    ]);
    let state = ModuleState::default();
    let (items, notes) = joiner::plan(&cfg, &people, &f, &state, today());
    let ids: Vec<&str> = items.iter().map(|i| i.employee_id.as_str()).collect();
    assert_eq!(ids, ["1"], "{notes:?}");
    // The manager has no email in AFAS: the address of their enabled Entra account.
    assert_eq!(items[0].to, "boss@x.nl");
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("3:") && n.contains("more than one")),
        "{notes:?}"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("4:") && n.contains("not in Entra yet")),
        "{notes:?}"
    );

    // A disabled manager account is no address: the fixed address is used.
    mgr_user.enabled = false;
    f.insert("100".into(), Found::User(mgr_user));
    let (items, _) = joiner::plan(&cfg, &people, &f, &state, today());
    assert_eq!(items[0].to, "desk@x.nl");
}

#[test]
fn sender_mailbox_is_a_safe_path_segment() {
    assert!(joiner::mailbox("noreply@x.nl").is_ok());
    for bad in [
        "a/b@x.nl",
        "a?b@x.nl",
        "a#b@x.nl",
        "a%2f@x.nl",
        "a\\b@x.nl",
        "no-at-sign",
    ] {
        assert!(joiner::mailbox(bad).is_err(), "{bad}");
    }
}

// ------------------------------------------------------------------ webhook

#[test]
fn webhook_events_for_every_kind_of_change() {
    let act = |id: &str| person(id, |_| {});
    let gone = |id: &str| {
        person(id, |s| {
            s.active = false;
            s.end_date = Some(minus(1));
        })
    };
    let prev: BTreeMap<String, Snapshot> = [
        ("c", act("c")),
        ("d", gone("d")),
        ("e", act("e")),
        ("f", act("f")),
        ("g", gone("g")),
    ]
    .into_iter()
    .map(|(k, p)| (k.to_string(), p.snap))
    .collect();
    let mut e_now = act("e");
    e_now.snap.department = Some("Sales".into());
    let mut g_now = gone("g");
    g_now.snap.department = Some("Sales".into());
    let now = [
        act("a"),  // new, active: new hire
        gone("b"), // new, already left: nothing
        gone("c"), // was active, now left: departing employee
        act("d"),  // was left, now active: returning employee
        e_now,     // department changed: job change
        act("f"),  // unchanged: nothing
        g_now,     // left and changed: nothing
    ];
    let ev = webhook::detect(&now, &prev, today());
    let got: Vec<(&str, EventKind, bool)> = ev
        .iter()
        .map(|e| (e.employee_id.as_str(), e.event, e.rehire))
        .collect();
    assert_eq!(
        got,
        [
            ("a", EventKind::Joiner, false),
            ("c", EventKind::Leaver, false),
            ("d", EventKind::Joiner, true),
            ("e", EventKind::Mover, false),
        ]
    );
    assert_eq!(
        ev[3].changes.get("department"),
        Some(&[None, Some("Sales".to_string())])
    );
    assert_eq!(ev[3].changes.len(), 1);
    // No previous run: a baseline, no events.
    assert!(webhook::detect(&now, &BTreeMap::new(), today()).is_empty());
}

#[test]
fn hmac_with_a_key_of_exactly_one_block() {
    // Reference values from Python's hmac module. 64 bytes is used as is, 65 is hashed.
    let k64: Vec<u8> = (0u8..64).collect();
    let k65: Vec<u8> = (0u8..65).collect();
    assert_eq!(
        webhook::hex(&webhook::hmac_sha256(&k64, b"afas-entra-sync")),
        "415c253dae87495dc726e0ca6a03378aec2868187edc648df4377e08efb996e0"
    );
    assert_eq!(
        webhook::hex(&webhook::hmac_sha256(&k65, b"afas-entra-sync")),
        "c74b9ee99772632d84757325472014f17e3adec6f760ac1297e3ec4d0453b3f1"
    );
}

// ------------------------------------------------------------------ state

#[test]
fn unreadable_module_state_is_an_error_not_a_fresh_start() {
    let dir = tempfile::tempdir().unwrap();
    // A fresh directory: a fresh state.
    assert!(afas_entra_sync::modules::load_state(dir.path()).is_ok());
    // Present but unreadable (here: a directory): never treated as "no state", or every
    // code already sent would be forgotten.
    std::fs::create_dir(dir.path().join("modules-state.json")).unwrap();
    assert!(afas_entra_sync::modules::load_state(dir.path()).is_err());
}

#[test]
fn departing_employee_with_an_account_conflict_is_skipped_with_the_reason() {
    let cfg: afas_entra_sync::modules::settings::LeaverConfig = toml::from_str(
        "enabled = true\nclient_id = \"c0000000-0000-0000-0000-000000000003\"\ncertificate_pem = \"/c\"\nprivate_key_pem = \"/k\"\n",
    )
    .unwrap();
    let p = person("7", |s| {
        s.active = false;
        s.end_date = Some(minus(1));
    });
    let f = found(&[(
        "7",
        Found::Conflict("employeeId 7 is on more than one Entra user".into()),
    )]);
    let (items, notes) = leaver::plan(&cfg, &[p], &f, &ModuleState::default(), today());
    assert!(items.is_empty());
    assert!(
        notes
            .iter()
            .any(|n| n.starts_with("7:") && n.contains("more than one")),
        "{notes:?}"
    );
}
