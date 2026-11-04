// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! The test-run preview: per account what happens and where, compared with Entra or with
//! the last sync, and the files a test run writes.

mod common;

use afas_entra_sync::config::Config;
use afas_entra_sync::plan::{PlanInput, build_plan};
use afas_entra_sync::preview::{self, Action, DirUser, Directory, Preview, Show};
use afas_entra_sync::state::{RecordState, STATE_VERSION, State};
use afas_entra_sync::sync::{RunOptions, next_state, run};
use chrono::{Days, NaiveDate};
use common::*;
use mockito::{Matcher, Server};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

fn today() -> NaiveDate {
    d("2026-11-03")
}
fn plus(n: u64) -> NaiveDate {
    today().checked_add_days(Days::new(n)).unwrap()
}
fn minus(n: u64) -> NaiveDate {
    today().checked_sub_days(Days::new(n)).unwrap()
}

fn cfg(extra: &str) -> (Config, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("afas.token");
    write_secret(&token, b"ABCDEF0123456789");
    let text = config_toml(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        &dir.path().join("state"),
        &token,
        "certificate",
        &Opts {
            max_invalid_percent: 100,
            max_drop_percent: 100,
            batch_size: 2,
            ..Default::default()
        },
    ) + extra;
    (Config::parse(&text).unwrap(), dir)
}

fn build(
    c: &Config,
    rows: &[Map<String, Value>],
    prev: Option<&State>,
    dir: Option<&Directory>,
) -> Preview {
    let plan = build_plan(PlanInput {
        rows,
        fields: &c.afas.fields,
        policy: &c.policy,
        batch_size: 2,
        today: today(),
        previous: prev,
        allow_mass_disable: true,
        allow_mass_create: true,
        allow_upn_changes: true,
    });
    preview::build(preview::Input {
        cfg: c,
        plan: &plan,
        previous: prev,
        directory: dir,
        directory_error: None,
        apply: false,
        created_utc: "2026-11-03T09:42:00Z".into(),
    })
}

fn dir_user(
    emp: Option<&str>,
    upn: &str,
    enabled: bool,
    ou: &str,
    values: &[(&str, &str)],
) -> DirUser {
    let mut v: BTreeMap<String, String> = values
        .iter()
        .map(|(k, x)| ((*k).to_string(), (*x).to_string()))
        .collect();
    v.insert("userName".into(), upn.into());
    DirUser {
        upn: upn.into(),
        employee_id: emp.map(str::to_string),
        enabled,
        dn: Some(format!("CN=x,{ou},DC=contoso,DC=nl")),
        synced: true,
        values: v,
    }
}

fn row_of<'a>(p: &'a Preview, id: &str) -> &'a preview::Row {
    p.rows
        .iter()
        .find(|r| r.employee_id.as_deref() == Some(id))
        .unwrap_or_else(|| panic!("no row {id}"))
}

/// What a matched user looks like when nothing changes.
fn same(id: &str) -> Vec<(&'static str, String)> {
    vec![
        ("displayName", format!("Voornaam{id} Achternaam{id}")),
        ("givenName", format!("Voornaam{id}")),
        ("familyName", format!("Achternaam{id}")),
        ("title", "Medewerker".into()),
        ("department", "ICT".into()),
        ("email", format!("user{id}@contoso.nl")),
    ]
}

fn matched(id: &str, enabled: bool, ou: &str, changes: &[(&'static str, &str)]) -> DirUser {
    let mut vals = same(id);
    for (k, v) in changes {
        vals.retain(|(x, _)| x != k);
        vals.push((k, v.to_string()));
    }
    let refs: Vec<(&str, &str)> = vals.iter().map(|(k, v)| (*k, v.as_str())).collect();
    dir_user(
        Some(id),
        &format!("user{id}@contoso.nl"),
        enabled,
        ou,
        &refs,
    )
}

#[test]
fn against_entra_every_account_gets_an_action_and_a_place() {
    let (c, _t) =
        cfg("\n[preview]\nnew_accounts_ou = \"OU=New hires,OU=Staff,DC=contoso,DC=nl\"\n");
    let rows = vec![
        row("1", minus(400), None),           // unchanged
        row("2", minus(400), None),           // job title changes
        row("3", minus(400), Some(minus(1))), // left: disable
        row("4", today(), None),              // starts today: enable
        row("5", plus(7), None),              // new hire, no account: create disabled
        row("6", minus(1), None),             // started, no account: create
        row("7", minus(400), None),           // UPN exists without employee number
        row("8", minus(400), None),           // UPN belongs to someone else
    ];
    let mut two = row("2", minus(400), None);
    two.insert("Functie".into(), json!("Senior medewerker"));
    let rows: Vec<_> = rows
        .into_iter()
        .map(|r| {
            if r["Personeelsnummer"] == "2" {
                two.clone()
            } else {
                r
            }
        })
        .collect();
    let d = Directory {
        users: vec![
            matched("1", true, "OU=ICT,OU=Staff", &[]),
            matched("2", true, "OU=ICT,OU=Staff", &[]),
            matched("3", true, "OU=ICT,OU=Staff", &[]),
            matched("4", false, "OU=New hires,OU=Staff", &[]),
            dir_user(None, "user7@contoso.nl", true, "OU=Old,OU=Staff", &[]),
            dir_user(Some("99"), "user8@contoso.nl", true, "OU=ICT,OU=Staff", &[]),
        ],
        read_utc: "2026-11-03T09:41:00Z".into(),
    };
    let p = build(&c, &rows, None, Some(&d));
    assert_eq!(p.source, preview::Source::Entra);
    assert_eq!(p.target, "Active Directory");
    assert_eq!(p.new_accounts, "contoso.nl/Staff/New hires");

    let r1 = row_of(&p, "1");
    assert_eq!(r1.action, Action::Unchanged, "{:?}", r1.changes);
    assert_eq!(r1.location.as_deref(), Some("contoso.nl/Staff/ICT"));
    assert_eq!(r1.call, Some(1));

    let r2 = row_of(&p, "2");
    assert_eq!(r2.action, Action::Update);
    assert_eq!(r2.changes.len(), 1);
    assert_eq!(r2.changes[0].label, "Job title");
    assert_eq!(r2.changes[0].ad, "title");
    assert_eq!(r2.changes[0].from.as_deref(), Some("Medewerker"));
    assert_eq!(r2.changes[0].to.as_deref(), Some("Senior medewerker"));

    assert_eq!(row_of(&p, "3").action, Action::Disable);
    assert!(row_of(&p, "3").note.as_deref().unwrap().contains("Left on"));
    assert_eq!(row_of(&p, "4").action, Action::Enable);
    assert_eq!(row_of(&p, "4").call, Some(2));

    let r5 = row_of(&p, "5");
    assert_eq!(r5.action, Action::CreateDisabled);
    assert_eq!(r5.location.as_deref(), Some("contoso.nl/Staff/New hires"));
    assert_eq!(r5.enabled_after, Some(false));
    assert!(r5.note.as_deref().unwrap().contains("New hire"));
    assert!(
        r5.changes
            .iter()
            .any(|c| c.label == "Department" && c.to.as_deref() == Some("ICT"))
    );
    assert_eq!(row_of(&p, "6").action, Action::Create);

    let r7 = row_of(&p, "7");
    assert_eq!(r7.action, Action::LinkFirst);
    assert_eq!(r7.location.as_deref(), Some("contoso.nl/Staff/Old"));
    assert!(r7.note.as_deref().unwrap().contains("employeeID 7"));
    assert_eq!(row_of(&p, "8").action, Action::Conflict);

    assert_eq!(p.problems(), 2);
    assert!(
        p.headline()
            .starts_with("Microsoft would create 2 accounts, enable 1, disable 1 and update 1."),
        "{}",
        p.headline()
    );
    // Cost center is configured but not in Entra: not compared, and said so.
    assert!(
        p.notes.iter().any(|n| n.contains("Cost center")),
        "{:?}",
        p.notes
    );
}

#[test]
fn against_the_last_sync_changes_and_emptied_values_show() {
    let (c, _t) = cfg("");
    let rows = vec![
        row("1", minus(400), None),
        row("2", minus(400), None),
        row("3", plus(3), None),
    ];
    let first = build_plan(PlanInput {
        rows: &rows,
        fields: &c.afas.fields,
        policy: &c.policy,
        batch_size: 50,
        today: today(),
        previous: None,
        allow_mass_disable: true,
        allow_mass_create: true,
        allow_upn_changes: true,
    });
    let st = next_state(&first, None, today());
    let mut changed = rows.clone();
    changed[0].insert("Afdeling".into(), json!("Finance"));
    changed[1].insert("Kostenplaats".into(), Value::Null);
    let p = build(&c, &changed, Some(&st), None);
    assert_eq!(p.source, preview::Source::LastRun);
    let r1 = row_of(&p, "1");
    assert_eq!(r1.action, Action::Update);
    assert_eq!(r1.changes[0].from.as_deref(), Some("ICT"));
    assert_eq!(r1.changes[0].to.as_deref(), Some("Finance"));
    // An emptied value is not sent, so it stays: shown, but not an update.
    let r2 = row_of(&p, "2");
    assert_eq!(r2.action, Action::Unchanged);
    assert!(r2.changes[0].kept && r2.changes[0].to.is_none());
    assert_eq!(
        row_of(&p, "3").action,
        Action::Unchanged,
        "pre-hire, still disabled"
    );
    // State from before 0.11 (no values): honest about it.
    let mut old = st.clone();
    for r in old.records.values_mut() {
        r.sent.clear();
    }
    let p = build(&c, &changed, Some(&old), None);
    assert_eq!(row_of(&p, "1").action, Action::Resend);
}

#[test]
fn first_run_without_look_up_and_records_that_are_not_sent() {
    let (c, _t) = cfg("");
    let mut bad = row("9", minus(400), None);
    bad.insert("UPN".into(), json!("x@elsewhere.org"));
    let rows = vec![
        row("1", minus(400), None),
        row("2", plus(60), None),              // later
        row("3", minus(400), Some(minus(90))), // left long ago
        bad,
    ];
    let p = build(&c, &rows, None, None);
    assert_eq!(p.source, preview::Source::Nothing);
    assert_eq!(row_of(&p, "1").action, Action::New);
    assert!(
        row_of(&p, "1")
            .note
            .as_deref()
            .unwrap()
            .contains("employeeID is 1")
    );
    let r2 = row_of(&p, "2");
    assert_eq!(r2.action, Action::Later);
    assert!(
        r2.note.as_deref().unwrap().contains("from 2026-12-19"),
        "{:?}",
        r2.note
    );
    assert_eq!(row_of(&p, "3").action, Action::NotSent);
    let r9 = row_of(&p, "9");
    assert_eq!(r9.action, Action::Skipped);
    assert!(r9.note.as_deref().unwrap().contains("allowed_upn_domains"));
    assert!(
        p.headline().contains("for the first time"),
        "{}",
        p.headline()
    );
    // Views.
    let changes: Vec<_> = p
        .rows
        .iter()
        .filter(|r| Show::Changes.includes(r.action))
        .collect();
    assert_eq!(changes.len(), 2, "new + skipped");
    assert!(
        p.rows
            .iter()
            .filter(|r| Show::NotSent.includes(r.action))
            .count()
            == 3
    );
}

#[test]
fn a_missing_employee_is_in_the_preview_with_what_to_do() {
    let (c, _t) = cfg("");
    let mut st = State {
        version: STATE_VERSION,
        last_success_utc: "2026-11-02T10:00:00Z".into(),
        sent_total: 1,
        records: BTreeMap::new(),
    };
    st.records.insert("1".into(), RecordState::new(true));
    let mut gone = RecordState::new(true);
    gone.sent
        .insert("displayName".into(), "Anouk Vermeer".into());
    gone.sent
        .insert("userName".into(), "a.vermeer@contoso.nl".into());
    gone.missing_since = Some(minus(5));
    st.records.insert("2".into(), gone);
    let p = build(&c, &[row("1", minus(400), None)], Some(&st), None);
    let r = row_of(&p, "2");
    assert_eq!(r.action, Action::Missing);
    assert_eq!(r.name.as_deref(), Some("Anouk Vermeer"));
    assert!(r.note.as_deref().unwrap().contains(&minus(5).to_string()));
    assert!(r.note.as_deref().unwrap().contains("missing ack"));
}

#[test]
fn a_test_run_looks_up_entra_and_writes_the_preview_and_the_page() {
    let mut afas = Server::new();
    let mut ms = Server::new();
    let rows = vec![row("1", minus(400), None), row("2", plus(3), None)];
    afas.mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
        .match_query(Matcher::Any)
        .with_body(afas_body(&rows))
        .create();
    let token = ms
        .mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
        .match_body(Matcher::Regex(
            "client_id=c0000000-0000-0000-0000-000000000009".into(),
        ))
        .with_body(r#"{"access_token":"tok","expires_in":3600}"#)
        .expect(1)
        .create();
    let users = ms
        .mock("GET", "/v1.0/users")
        .match_query(Matcher::AllOf(vec![
            Matcher::Regex("expand=manager".into()),
            Matcher::Regex("onPremisesDistinguishedName".into()),
        ]))
        .with_body(
            json!({ "value": [ {
                "id": "u1", "userPrincipalName": "user1@contoso.nl", "employeeId": "1",
                "displayName": "Voornaam1 Achternaam1", "givenName": "Voornaam1", "surname": "Achternaam1",
                "jobTitle": "Adviseur", "department": "ICT", "mail": "user1@contoso.nl",
                "accountEnabled": true, "onPremisesSyncEnabled": true,
                "onPremisesDistinguishedName": "CN=Voornaam1 Achternaam1,OU=ICT,DC=contoso,DC=nl",
                "manager": null
            } ] })
            .to_string(),
        )
        .expect(1)
        .create();
    let dir = tempfile::tempdir().unwrap();
    let tok = dir.path().join("afas.token");
    write_secret(&tok, b"ABCDEF0123456789");
    let text = config_toml(
        &afas.url(),
        &ms.url(),
        &dir.path().join("state"),
        &tok,
        "certificate",
        &Opts::default(),
    ) + &format!(
        "\n[preview]\nclient_id = \"c0000000-0000-0000-0000-000000000009\"\ncertificate_pem = \"{}\"\nprivate_key_pem = \"{}\"\n",
        fixture("test-cert.pem"),
        dir.path().join("test-key.pem").display()
    );
    let cfg = Config::parse(&text).unwrap();
    let page = dir.path().join("preview.html");
    let r = run(
        &cfg,
        &RunOptions {
            preview_html: Some(page.clone()),
            actor: "test".into(),
            ..Default::default()
        },
        &|_| {},
    )
    .map_err(|(e, _)| e)
    .unwrap();
    token.assert();
    users.assert();
    let p = r.preview.unwrap();
    assert_eq!(p.source, preview::Source::Entra);
    assert_eq!(row_of(&p, "1").action, Action::Update);
    assert_eq!(row_of(&p, "1").location.as_deref(), Some("contoso.nl/ICT"));
    assert_eq!(row_of(&p, "2").action, Action::CreateDisabled);
    // Written next to the test-run report, never over the sync's report.
    let state = dir.path().join("state");
    let saved: Preview =
        serde_json::from_slice(&std::fs::read(state.join("last-dry-run-preview.json")).unwrap())
            .unwrap();
    assert_eq!(saved, p);
    assert!(state.join("last-dry-run-report.json").exists());
    assert!(!state.join("last-report.json").exists());
    let rep: Value =
        serde_json::from_slice(&std::fs::read(state.join("last-dry-run-report.json")).unwrap())
            .unwrap();
    assert_eq!(rep["preview"]["compared_with"], "entra");
    assert_eq!(rep["preview"]["totals"]["update"], 1);
    // The report goes to logs and schedulers: no names in it.
    assert!(!rep.to_string().contains("Voornaam1"));
    let html = std::fs::read_to_string(&page).unwrap();
    assert!(
        html.contains("Adviseur") && html.contains("Medewerker"),
        "the change is on the page"
    );
    assert!(html.contains("contoso.nl/<wbr>ICT"), "where the account is");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&page).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "personal data: owner only");
    }
}

#[test]
fn a_failed_look_up_falls_back_and_says_so() {
    let mut afas = Server::new();
    let mut ms = Server::new();
    afas.mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
        .match_query(Matcher::Any)
        .with_body(afas_body(&[row("1", minus(400), None)]))
        .create();
    ms.mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
        .with_body(r#"{"access_token":"tok","expires_in":3600}"#)
        .create();
    ms.mock("GET", "/v1.0/users")
        .match_query(Matcher::Any)
        .with_status(403)
        .with_body(r#"{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}"#)
        .create();
    let dir = tempfile::tempdir().unwrap();
    let tok = dir.path().join("afas.token");
    write_secret(&tok, b"ABCDEF0123456789");
    let text = config_toml(
        &afas.url(),
        &ms.url(),
        &dir.path().join("state"),
        &tok,
        "certificate",
        &Opts::default(),
    ) + &format!(
        "\n[preview]\nclient_id = \"c0000000-0000-0000-0000-000000000009\"\ncertificate_pem = \"{}\"\nprivate_key_pem = \"{}\"\n",
        fixture("test-cert.pem"),
        dir.path().join("test-key.pem").display()
    );
    let cfg = Config::parse(&text).unwrap();
    let r = run(
        &cfg,
        &RunOptions {
            actor: "t".into(),
            ..Default::default()
        },
        &|_| {},
    )
    .map_err(|(e, _)| e)
    .unwrap();
    let p = r.preview.unwrap();
    assert_eq!(p.source, preview::Source::Nothing);
    assert!(
        p.notes[0].contains("look-up in Entra failed") && p.notes[0].contains("403"),
        "{:?}",
        p.notes
    );
    assert_eq!(r.report.exit_code, 0, "the preview never fails a run");
}

#[test]
fn preview_config_is_checked() {
    let err = |extra: &str| {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("afas.token");
        write_secret(&token, b"ABCDEF0123456789");
        Config::parse(
            &(config_toml(
                "http://127.0.0.1:1",
                "http://127.0.0.1:1",
                &dir.path().join("s"),
                &token,
                "certificate",
                &Opts::default(),
            ) + extra),
        )
        .err()
        .map(|e| e.to_string())
    };
    assert!(
        err("\n[preview]\nnew_accounts_ou = \"Staff\"\n")
            .unwrap()
            .contains("distinguished name")
    );
    assert!(
        err("\n[preview]\nclient_id = \"c0000000-0000-0000-0000-000000000009\"\n")
            .unwrap()
            .contains("go together")
    );
    assert!(
        err("\n[preview]\nnew_accounts_ou = \"OU=New,DC=x,DC=nl\"\nentra_lookup = false\n")
            .is_none()
    );
}
