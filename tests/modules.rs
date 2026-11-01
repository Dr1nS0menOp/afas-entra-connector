// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Modules: roles, joiner, leaver, webhook, exceptions and access log, end-to-end
//! through `sync::run` against mocked AFAS, Entra login, Microsoft Graph and a webhook.

mod common;

use afas_entra_sync::config::Config;
use afas_entra_sync::error::exit;
use afas_entra_sync::graph::EntraUser;
use afas_entra_sync::modules::records::{
    AccessEntry, ExceptionKind, access_csv, add_exception, read_access,
};
use afas_entra_sync::modules::webhook::{hex, hmac_sha256};
use afas_entra_sync::modules::{Found, Person, Snapshot, load_state, match_users};
use afas_entra_sync::sync::{RunOptions, RunResult, run};
use chrono::{Days, NaiveDate};
use common::*;
use mockito::{Matcher, Mock, Server, ServerGuard};
use serde_json::{Map, Value, json};

const G_ICT: &str = "a1a1a1a1-0000-0000-0000-000000000001";
const G_ALL: &str = "a1a1a1a1-0000-0000-0000-000000000002";
const G_FIN: &str = "a1a1a1a1-0000-0000-0000-000000000003";
const U1: &str = "b0000000-0000-0000-0000-000000000001";
const U2: &str = "b0000000-0000-0000-0000-000000000002";
const U3: &str = "b0000000-0000-0000-0000-000000000003";
const U4: &str = "b0000000-0000-0000-0000-000000000004";
const UADM: &str = "b0000000-0000-0000-0000-0000000000ad";
const M_ROLES: &str = "c0000000-0000-0000-0000-000000000001";
const M_JOIN: &str = "c0000000-0000-0000-0000-000000000002";
const M_LEAVE: &str = "c0000000-0000-0000-0000-000000000003";

fn today() -> NaiveDate {
    today_ams()
}
fn plus(n: u64) -> NaiveDate {
    today().checked_add_days(Days::new(n)).unwrap()
}
fn minus(n: u64) -> NaiveDate {
    today().checked_sub_days(Days::new(n)).unwrap()
}

fn rows() -> Vec<Map<String, Value>> {
    let mut r1 = row("00001", minus(400), None);
    r1.insert("Roepnaam".into(), json!("Mia"));
    r1.insert("Achternaam".into(), json!("Manager"));
    let mut r2 = row("00002", minus(400), None);
    r2.insert("Afdeling".into(), json!("HR"));
    let mut r3 = row("00003", minus(400), Some(minus(2)));
    r3.insert("Leidinggevende".into(), json!("00001"));
    let mut r4 = row("00004", plus(1), None);
    r4.insert("Leidinggevende".into(), json!("00001"));
    vec![r1, r2, r3, r4]
}

fn user(id: &str, emp: Option<&str>, upn: &str) -> Value {
    json!({ "id": id, "userPrincipalName": upn, "employeeId": emp, "mail": upn, "accountEnabled": true })
}

fn users_json() -> String {
    json!({ "value": [
        user(U1, Some("00001"), "user00001@contoso.nl"),
        user(U2, Some("00002"), "user00002@contoso.nl"),
        user(U3, Some("00003"), "user00003@contoso.nl"),
        user(U4, Some("00004"), "user00004@contoso.nl"),
        user(UADM, None, "admin@contoso.nl"),
    ]})
    .to_string()
}

struct Env {
    afas: ServerGuard,
    ms: ServerGuard,
    hook: ServerGuard,
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let mut e = Env {
            afas: Server::new(),
            ms: Server::new(),
            hook: Server::new(),
            dir: tempfile::tempdir().unwrap(),
        };
        e.afas
            .mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
            .match_query(Matcher::Any)
            .with_body(afas_body(&rows()))
            .create();
        e.ms.mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
            .with_body(r#"{"access_token":"tok","expires_in":3600}"#)
            .create();
        e.ms.mock(
            "POST",
            format!("/v1.0/servicePrincipals/{SP}/synchronization/jobs/{JOB}/bulkUpload").as_str(),
        )
        .with_status(202)
        .create();
        e.ms.mock("GET", "/v1.0/users")
            .match_query(Matcher::Any)
            .with_body(users_json())
            .create();
        e
    }

    /// GET of the user's existing Temporary Access Pass methods.
    fn passes(&mut self, uid: &str, ids: &[&str]) -> Mock {
        let v: Vec<Value> = ids.iter().map(|i| json!({ "id": i })).collect();
        self.ms
            .mock(
                "GET",
                format!("/v1.0/users/{uid}/authentication/temporaryAccessPassMethods").as_str(),
            )
            .match_query(Matcher::Any)
            .with_body(json!({ "value": v }).to_string())
            .create()
    }

    /// Replace the AFAS data (before building the config).
    fn set_rows(&mut self, rows: &[Map<String, Value>]) {
        self.afas = Server::new();
        self.afas
            .mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
            .match_query(Matcher::Any)
            .with_body(afas_body(rows))
            .create();
    }

    fn key(&self) -> String {
        self.dir.path().join("test-key.pem").display().to_string()
    }

    fn cfg(&self, modules: &str) -> Config {
        let tok = self.dir.path().join("afas.token");
        write_secret(&tok, b"ABCDEF0123456789");
        let text = config_toml(
            &self.afas.url(),
            &self.ms.url(),
            &self.dir.path().join("state"),
            &tok,
            "certificate",
            &Opts {
                min_records: 1,
                ..Opts::default()
            },
        ) + modules;
        Config::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"))
    }

    fn roles(&self, extra: &str) -> String {
        format!(
            "\n[roles]\nenabled = true\nclient_id = \"{M_ROLES}\"\ncertificate_pem = \"{}\"\nprivate_key_pem = \"{}\"\ngroup_prefix = \"AFAS-\"\n{extra}\n[[roles.rule]]\ngroup_id = \"{G_ICT}\"\ndepartment = [\"ict\"]\n\n[[roles.rule]]\ngroup_id = \"{G_ALL}\"\nall = true\n",
            fixture("test-cert.pem"),
            self.key()
        )
    }

    fn group(&mut self, id: &str, name: &str, members: &[Value]) {
        self.ms
            .mock("GET", format!("/v1.0/groups/{id}").as_str())
            .match_query(Matcher::Any)
            .with_body(json!({"id": id, "displayName": name, "isAssignableToRole": false, "onPremisesSyncEnabled": null, "groupTypes": []}).to_string())
            .create();
        self.ms
            .mock(
                "GET",
                format!("/v1.0/groups/{id}/members/microsoft.graph.user").as_str(),
            )
            .match_query(Matcher::Any)
            .with_body(json!({ "value": members }).to_string())
            .create();
    }

    fn add(&mut self, group: &str, user: &str, n: usize) -> Mock {
        self.ms
            .mock(
                "POST",
                format!("/v1.0/groups/{group}/members/$ref").as_str(),
            )
            .match_body(Matcher::PartialJson(
                json!({ "@odata.id": format!("{}/v1.0/directoryObjects/{user}", self.ms.url()) }),
            ))
            .with_status(204)
            .expect(n)
            .create()
    }

    fn remove(&mut self, group: &str, user: &str, n: usize) -> Mock {
        self.ms
            .mock(
                "DELETE",
                format!("/v1.0/groups/{group}/members/{user}/$ref").as_str(),
            )
            .with_status(204)
            .expect(n)
            .create()
    }

    fn state(&self) -> std::path::PathBuf {
        self.dir.path().join("state")
    }
}

fn go(cfg: &Config, apply: bool) -> RunResult {
    let o = RunOptions {
        apply,
        as_of: None,
        allow_mass_disable: true,
        dump_payload: None,
        use_system_proxy: false,
        actor: "test".into(),
    };
    run(cfg, &o, &|_| {}).map_err(|(e, _)| e).unwrap()
}

// ------------------------------------------------------------------ roles

#[test]
fn roles_add_and_remove_follow_rules_and_leave_unknown_members_alone() {
    let mut env = Env::new();
    env.group(
        G_ICT,
        "AFAS-ICT",
        &[
            user(U3, Some("00003"), "user00003@contoso.nl"),
            user(UADM, None, "admin@contoso.nl"),
        ],
    );
    env.group(
        G_ALL,
        "AFAS-All",
        &[user(U1, Some("00001"), "user00001@contoso.nl")],
    );
    let add_u1 = env.add(G_ICT, U1, 1);
    let rm_u3 = env.remove(G_ICT, U3, 1);
    let rm_adm = env.remove(G_ICT, UADM, 0);
    let add_u2 = env.add(G_ALL, U2, 1);
    let add_u4 = env.add(G_ICT, U4, 0); // pre-hire: not without include_prehires
    let cfg = env.cfg(&env.roles(""));
    let r = go(&cfg, true);
    for m in [&add_u1, &rm_u3, &rm_adm, &add_u2, &add_u4] {
        m.assert();
    }
    let roles = r.report.modules.as_ref().unwrap().roles.clone().unwrap();
    assert_eq!(roles.applied, 3, "{roles:?}");
    assert!(roles.error.is_none() && roles.failed.is_empty());
    assert_eq!(r.report.exit_code, exit::OK, "{:?}", r.report);
    let log = read_access(&env.state(), None, None).unwrap();
    assert_eq!(log.len(), 3);
    assert!(
        log.iter()
            .all(|e| e.ok && e.module == "roles" && e.actor == "test")
    );
    assert!(
        log.iter()
            .any(|e| e.action == "remove_from_group" && e.employee_id.as_deref() == Some("00003"))
    );
}

#[test]
fn roles_dry_run_plans_but_writes_nothing() {
    let mut env = Env::new();
    env.group(G_ICT, "AFAS-ICT", &[]);
    env.group(G_ALL, "AFAS-All", &[]);
    let none = env
        .ms
        .mock(
            "POST",
            Matcher::Regex(r"^/v1\.0/groups/.*/members/\$ref$".into()),
        )
        .expect(0)
        .create();
    let cfg = env.cfg(&env.roles(""));
    let r = go(&cfg, false);
    none.assert();
    let roles = r.report.modules.unwrap().roles.unwrap();
    // u1 ICT+All, u2 All
    assert_eq!(roles.planned.len(), 3, "{roles:?}");
    assert_eq!(roles.applied, 0);
    assert!(!env.state().join("modules-state.json").exists());
    assert!(!env.state().join("access.log").exists());
}

#[test]
fn roles_threshold_stops_all_changes() {
    let mut env = Env::new();
    env.group(G_ICT, "AFAS-ICT", &[]);
    env.group(G_ALL, "AFAS-All", &[]);
    let none = env
        .ms
        .mock(
            "POST",
            Matcher::Regex(r"^/v1\.0/groups/.*/members/\$ref$".into()),
        )
        .expect(0)
        .create();
    let cfg = env.cfg(&env.roles("max_changes_per_run = 2"));
    let r = go(&cfg, true);
    none.assert();
    assert_eq!(r.report.exit_code, exit::MODULE_GUARD);
    let roles = r.report.modules.unwrap().roles.unwrap();
    assert_eq!(roles.violations.len(), 1);
    assert_eq!(roles.applied, 0);
}

#[test]
fn roles_refuse_unsafe_groups() {
    for (name, extra, why) in [
        ("Finance", json!({}), "group_prefix"),
        (
            "AFAS-Admins",
            json!({"isAssignableToRole": true}),
            "role-assignable",
        ),
        (
            "AFAS-OnPrem",
            json!({"onPremisesSyncEnabled": true}),
            "on-premises",
        ),
        (
            "AFAS-Dyn",
            json!({"groupTypes": ["Unified", "DynamicMembership"]}),
            "dynamic",
        ),
    ] {
        let mut env = Env::new();
        let mut g = json!({"id": G_ICT, "displayName": name, "isAssignableToRole": false, "groupTypes": []});
        for (k, v) in extra.as_object().unwrap() {
            g[k] = v.clone();
        }
        env.ms
            .mock("GET", format!("/v1.0/groups/{G_ICT}").as_str())
            .match_query(Matcher::Any)
            .with_body(g.to_string())
            .create();
        // Members are readable: the refusal must come from the group check itself.
        env.ms
            .mock(
                "GET",
                format!("/v1.0/groups/{G_ICT}/members/microsoft.graph.user").as_str(),
            )
            .match_query(Matcher::Any)
            .with_body(json!({ "value": [] }).to_string())
            .create();
        env.group(G_ALL, "AFAS-All", &[]);
        let none = env
            .ms
            .mock(
                "POST",
                Matcher::Regex(r"^/v1\.0/groups/.*/members/\$ref$".into()),
            )
            .expect(0)
            .create();
        let cfg = env.cfg(&env.roles(""));
        let r = go(&cfg, true);
        none.assert();
        assert_eq!(r.report.exit_code, exit::MODULE_FAILED, "{name}");
        let e = r.report.modules.unwrap().roles.unwrap().error.unwrap();
        assert!(e.contains(why), "{name}: {e}");
    }
}

#[test]
fn roles_exceptions_and_segregation_of_duties() {
    let mut env = Env::new();
    env.group(G_ICT, "AFAS-ICT", &[]);
    env.group(
        G_ALL,
        "AFAS-All",
        &[user(U1, Some("00001"), "a"), user(U2, Some("00002"), "b")],
    );
    env.group(G_FIN, "AFAS-Finance", &[]);
    // Exception: 00001 stays out of ICT; 00002 gets Finance.
    add_exception(
        &env.state_mk(),
        "00001",
        G_ICT,
        ExceptionKind::Exclude,
        plus(10),
        "test",
        "t",
        today(),
    )
    .unwrap();
    add_exception(
        &env.state_mk(),
        "00002",
        G_FIN,
        ExceptionKind::Include,
        plus(10),
        "test",
        "t",
        today(),
    )
    .unwrap();
    // Expired exception is ignored.
    let mut x = afas_entra_sync::modules::records::load_exceptions(&env.state()).unwrap();
    x.items.push(afas_entra_sync::modules::records::Exception {
        id: "old".into(),
        employee_id: "00002".into(),
        group_id: G_ICT.into(),
        kind: ExceptionKind::Include,
        until: minus(1),
        reason: "expired".into(),
        created_by: "t".into(),
        created_utc: "x".into(),
    });
    afas_entra_sync::modules::records::save_exceptions(&env.state(), &x).unwrap();
    let add_fin = env.add(G_FIN, U2, 1);
    let add_ict = env.add(G_ICT, U1, 0);
    let add_ict2 = env.add(G_ICT, U2, 0);
    let cfg = env.cfg(&format!(
        "{}\n[[roles.rule]]\ngroup_id = \"{G_FIN}\"\ndepartment = [\"Finance\"]\n",
        env.roles("")
    ));
    go(&cfg, true);
    add_fin.assert();
    add_ict.assert();
    add_ict2.assert();

    // SoD: ICT and Finance together are not allowed. 00001 is ICT and gets Finance by exception.
    let mut env = Env::new();
    env.group(G_ICT, "AFAS-ICT", &[]);
    env.group(
        G_ALL,
        "AFAS-All",
        &[user(U1, Some("00001"), "a"), user(U2, Some("00002"), "b")],
    );
    env.group(G_FIN, "AFAS-Finance", &[]);
    add_exception(
        &env.state_mk(),
        "00001",
        G_FIN,
        ExceptionKind::Include,
        plus(10),
        "test",
        "t",
        today(),
    )
    .unwrap();
    let add_ict = env.add(G_ICT, U1, 0);
    let add_fin = env.add(G_FIN, U1, 0);
    let cfg = env.cfg(&format!(
        "{}\n[[roles.rule]]\ngroup_id = \"{G_FIN}\"\ndepartment = [\"Finance\"]\n\n[[roles.sod]]\nname = \"IT vs Finance\"\ngroups = [\"{G_ICT}\", \"{G_FIN}\"]\n",
        env.roles("")
    ));
    let r = go(&cfg, true);
    add_ict.assert();
    add_fin.assert();
    assert_eq!(r.report.exit_code, exit::COMPLETED_WITH_EXCLUSIONS);
    let notes = r.report.modules.unwrap().roles.unwrap().notes;
    assert!(
        notes
            .iter()
            .any(|n| n.contains("(segregation of duties) 'IT vs Finance'")),
        "{notes:?}"
    );
}

impl Env {
    fn state_mk(&self) -> std::path::PathBuf {
        std::fs::create_dir_all(self.state()).unwrap();
        self.state()
    }
}

// ------------------------------------------------------------------ joiner

fn joiner_cfg(env: &Env, deliver: &str) -> String {
    format!(
        "\n[joiner]\nenabled = true\nclient_id = \"{M_JOIN}\"\ncertificate_pem = \"{}\"\nprivate_key_pem = \"{}\"\nsender = \"noreply@contoso.nl\"\ndeliver_to = \"{deliver}\"\nfixed_address = \"servicedesk@contoso.nl\"\n",
        fixture("test-cert.pem"),
        env.key()
    )
}

#[test]
fn joiner_issues_one_pass_mails_the_manager_and_never_logs_it() {
    let mut env = Env::new();
    env.passes(U4, &[]);
    let tap = env
        .ms
        .mock(
            "POST",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .match_body(Matcher::PartialJson(
            json!({"isUsableOnce": false, "lifetimeInMinutes": 600}),
        ))
        .with_status(201)
        .with_body(
            r#"{"id":"d0000000-0000-0000-0000-000000000001","temporaryAccessPass":"Secret#Tap42"}"#,
        )
        .expect(1)
        .create();
    let mail = env
        .ms
        .mock("POST", "/v1.0/users/noreply@contoso.nl/sendMail")
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("Secret#Tap42".into()),
            Matcher::Regex("user00001@contoso.nl".into()),
        ]))
        .with_status(202)
        .expect(1)
        .create();
    let cfg = env.cfg(&joiner_cfg(&env, "manager"));
    let r = go(&cfg, true);
    tap.assert();
    mail.assert();
    let j = r.report.modules.as_ref().unwrap().joiner.clone().unwrap();
    assert_eq!(j.applied, 1, "{j:?}");
    assert_eq!(r.report.exit_code, exit::OK);
    // The pass is in no file the tool writes.
    for f in ["access.log", "modules-state.json", "last-report.json"] {
        let t = std::fs::read_to_string(env.state().join(f)).unwrap();
        assert!(!t.contains("Secret#Tap42"), "{f}");
    }
    assert_eq!(
        load_state(&env.state()).unwrap().tap_issued.get("00004"),
        Some(&plus(1))
    );
    // Next run: nothing new.
    let r = go(&cfg, true);
    tap.assert();
    assert_eq!(r.report.modules.unwrap().joiner.unwrap().planned.len(), 0);
}

#[test]
fn joiner_removes_the_pass_when_the_mail_fails_and_retries() {
    let mut env = Env::new();
    env.passes(U4, &[]);
    env.ms
        .mock(
            "POST",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .with_status(201)
        .with_body(
            r#"{"id":"d0000000-0000-0000-0000-000000000001","temporaryAccessPass":"Secret#Tap42"}"#,
        )
        .create();
    env.ms
        .mock("POST", "/v1.0/users/noreply@contoso.nl/sendMail")
        .with_status(403)
        .with_body(r#"{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}"#)
        .create();
    let del = env
        .ms
        .mock(
            "DELETE",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods/d0000000-0000-0000-0000-000000000001").as_str(),
        )
        .with_status(204)
        .expect(1)
        .create();
    let cfg = env.cfg(&joiner_cfg(&env, "fixed"));
    let r = go(&cfg, true);
    del.assert();
    assert_eq!(r.report.exit_code, exit::MODULE_FAILED);
    assert!(load_state(&env.state()).unwrap().tap_issued.is_empty());
    let log = std::fs::read_to_string(env.state().join("access.log")).unwrap();
    assert!(log.contains("Temporary Access Pass) removed again") && !log.contains("Secret#Tap42"));
}

#[test]
fn joiner_never_replaces_an_existing_pass() {
    let mut env = Env::new();
    env.passes(U4, &["d0000000-0000-0000-0000-0000000000ee"]);
    let post = env
        .ms
        .mock(
            "POST",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .expect(0)
        .create();
    let mail = env
        .ms
        .mock("POST", "/v1.0/users/noreply@contoso.nl/sendMail")
        .expect(0)
        .create();
    let cfg = env.cfg(&joiner_cfg(&env, "manager"));
    let r = go(&cfg, true);
    post.assert();
    mail.assert();
    let j = r.report.modules.unwrap().joiner.unwrap();
    assert!(j.failed.is_empty(), "{j:?}");
    assert!(
        j.notes
            .iter()
            .any(|n| n.contains("already has a Temporary Access Pass")),
        "{j:?}"
    );
    assert_eq!(r.report.exit_code, exit::COMPLETED_WITH_EXCLUSIONS);
    // Not marked as done: once the existing pass is deleted, a new one is sent.
    assert!(load_state(&env.state()).unwrap().tap_issued.is_empty());
}

/// A 5xx on the POST may mean Graph created the pass anyway: the POST is not repeated
/// (that would be a second pass or fail), and any pass that appeared is removed.
#[test]
fn joiner_does_not_repeat_the_post_and_cleans_up_when_the_outcome_is_unknown() {
    let mut env = Env::new();
    let tid = "d0000000-0000-0000-0000-000000000077";
    // First GET (before): none. Later GETs (cleanup): the one Graph made anyway.
    let gets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let g2 = gets.clone();
    env.ms
        .mock(
            "GET",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .match_query(Matcher::Any)
        .with_body_from_request(move |_| {
            let n = g2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let v = if n == 0 {
                json!([])
            } else {
                json!([{ "id": tid }])
            };
            json!({ "value": v }).to_string().into_bytes()
        })
        .create();
    let post = env
        .ms
        .mock(
            "POST",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .with_status(503)
        .expect(1)
        .create();
    let del = env
        .ms
        .mock(
            "DELETE",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods/{tid}").as_str(),
        )
        .with_status(204)
        .expect(1)
        .create();
    let mail = env
        .ms
        .mock("POST", "/v1.0/users/noreply@contoso.nl/sendMail")
        .expect(0)
        .create();
    let cfg = env.cfg(&joiner_cfg(&env, "manager"));
    let r = go(&cfg, true);
    post.assert();
    del.assert();
    mail.assert();
    assert_eq!(gets.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(r.report.exit_code, exit::MODULE_FAILED);
    assert!(load_state(&env.state()).unwrap().tap_issued.is_empty());
}

#[test]
fn joiner_never_mails_a_manager_who_has_left() {
    let mut env = Env::new();
    // 00003 has left (end date two days ago); make them 00004's manager.
    let mut r = rows();
    r[3].insert("Leidinggevende".into(), json!("00003"));
    env.afas = Server::new();
    env.afas
        .mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
        .match_query(Matcher::Any)
        .with_body(afas_body(&r))
        .create();
    env.passes(U4, &[]);
    env.ms
        .mock(
            "POST",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .with_status(201)
        .with_body(r#"{"id":"d0000000-0000-0000-0000-000000000001","temporaryAccessPass":"X"}"#)
        .create();
    let to_desk = env
        .ms
        .mock("POST", "/v1.0/users/noreply@contoso.nl/sendMail")
        .match_body(Matcher::Regex("servicedesk@contoso.nl".into()))
        .with_status(202)
        .expect(1)
        .create();
    let cfg = env.cfg(&joiner_cfg(&env, "manager"));
    let r = go(&cfg, true);
    to_desk.assert();
    assert_eq!(r.report.modules.unwrap().joiner.unwrap().applied, 1);
}

#[test]
fn pass_start_time_survives_daylight_saving_changes() {
    use afas_entra_sync::modules::joiner::valid_from_utc;
    let ams: chrono_tz::Tz = "Europe/Amsterdam".parse().unwrap();
    let d = |s: &str| NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
    let utc = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    // Ordinary winter and summer days.
    assert_eq!(
        valid_from_utc(ams, d("2027-01-11"), 6),
        Some(utc("2027-01-11T05:00:00Z"))
    );
    assert_eq!(
        valid_from_utc(ams, d("2027-06-14"), 6),
        Some(utc("2027-06-14T04:00:00Z"))
    );
    // 02:00 does not exist on 28 March 2027: the next existing hour, never "now".
    assert_eq!(
        valid_from_utc(ams, d("2027-03-28"), 2),
        Some(utc("2027-03-28T01:00:00Z"))
    );
    // 02:00 exists twice on 31 October 2027: the first.
    assert_eq!(
        valid_from_utc(ams, d("2027-10-31"), 2),
        Some(utc("2027-10-31T00:00:00Z"))
    );
}

#[test]
fn access_log_write_failure_is_a_failure() {
    let mut env = Env::new();
    env.group(G_ICT, "AFAS-ICT", &[]);
    env.group(G_ALL, "AFAS-All", &[]);
    env.ms
        .mock(
            "POST",
            Matcher::Regex(r"^/v1\.0/groups/.*/members/\$ref$".into()),
        )
        .with_status(204)
        .create();
    // The access log path is a directory: appending fails.
    std::fs::create_dir_all(env.state().join("access.log")).unwrap();
    let cfg = env.cfg(&env.roles(""));
    let r = go(&cfg, true);
    let roles = r.report.modules.unwrap().roles.unwrap();
    assert!(roles.applied > 0, "{roles:?}");
    assert_eq!(
        roles
            .failed
            .iter()
            .filter(|f| f.starts_with("access log not written"))
            .count(),
        1,
        "{roles:?}"
    );
    assert_eq!(r.report.exit_code, exit::MODULE_FAILED);
}

#[test]
fn modules_that_act_after_the_end_date_need_the_lookback_window() {
    let env = Env::new();
    let base = config_toml(
        "https://afas.example",
        "https://login.example",
        &env.dir.path().join("state"),
        &env.dir.path().join("afas.token"),
        "certificate",
        &Opts {
            min_records: 1,
            ..Opts::default()
        },
    );
    let look: u32 = Config::parse(&base).unwrap().policy.leaver_lookback_days;
    let roles = |keep: u32| base.clone() + &env.roles(&format!("keep_leavers_days = {keep}"));
    assert!(Config::parse(&roles(look - 1)).is_ok());
    let e = Config::parse(&roles(look)).unwrap_err().to_string();
    assert!(
        e.contains("keep_leavers_days") && e.contains("leaver_lookback_days"),
        "{e}"
    );
}

#[test]
fn automatic_reply_is_escaped_and_keeps_line_breaks() {
    use afas_entra_sync::modules::leaver::reply_html;
    assert_eq!(
        reply_html("Jan <b>& \"Co\"</b>\r\nNext line"),
        "Jan &lt;b&gt;&amp; &quot;Co&quot;&lt;/b&gt;<br>Next line"
    );
}

// ------------------------------------------------------------------ leaver

#[test]
fn leaver_revokes_sessions_and_sets_reply_once() {
    let mut env = Env::new();
    let revoke = env
        .ms
        .mock(
            "POST",
            format!("/v1.0/users/{U3}/revokeSignInSessions").as_str(),
        )
        .with_body(r#"{"value":true}"#)
        .expect(1)
        .create();
    let reply = env
        .ms
        .mock("PATCH", format!("/v1.0/users/{U3}/mailboxSettings").as_str())
        .match_body(Matcher::PartialJson(json!({"automaticRepliesSetting": {"status": "alwaysEnabled", "externalAudience": "none", "internalReplyMessage": "Gone. Ask Mia Manager (user00001@contoso.nl)."}})))
        .with_body("{}")
        .expect(1)
        .create();
    let cfg = env.cfg(&format!(
        "\n[leaver]\nenabled = true\nclient_id = \"{M_LEAVE}\"\ncertificate_pem = \"{}\"\nprivate_key_pem = \"{}\"\nauto_reply = \"Gone. Ask {{manager_name}} ({{manager_email}}).\"\n",
        fixture("test-cert.pem"),
        env.key()
    ));
    let r = go(&cfg, true);
    revoke.assert();
    reply.assert();
    assert_eq!(r.report.modules.unwrap().leaver.unwrap().applied, 1);
    go(&cfg, true);
    revoke.assert();
    reply.assert();
}

// ------------------------------------------------------------------ webhook

fn webhook_cfg(env: &Env) -> String {
    format!(
        "\n[webhook]\nenabled = true\nurl = \"{}/hook\"\nsecret_env = \"TEST_HOOK_SECRET\"\n",
        env.hook.url()
    )
}

#[test]
fn webhook_baseline_then_signed_events_with_retry() {
    // SAFETY of the test: the variable is only read by this process.
    unsafe { std::env::set_var("TEST_HOOK_SECRET", "0123456789abcdef-secret") };
    let mut env = Env::new();
    let cfg = env.cfg(&webhook_cfg(&env));
    let none = env.hook.mock("POST", "/hook").expect(0).create();
    go(&cfg, true); // baseline
    none.assert();
    none.remove();

    // Change: 00002 moves from HR to Sales. Receiver is down once.
    let mut rs = rows();
    rs[1].insert("Afdeling".into(), json!("Sales"));
    env.afas.reset();
    env.afas
        .mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
        .match_query(Matcher::Any)
        .with_body(afas_body(&rs))
        .create();
    let down = env
        .hook
        .mock("POST", "/hook")
        .with_status(503)
        .expect(1)
        .create();
    let r = go(&cfg, true);
    down.assert();
    down.remove();
    assert_eq!(r.report.exit_code, exit::MODULE_FAILED);
    assert_eq!(load_state(&env.state()).unwrap().outbox.len(), 1);

    let got = std::sync::Arc::new(std::sync::Mutex::new(None::<(String, String, Vec<u8>)>));
    let g2 = got.clone();
    let up = env
        .hook
        .mock("POST", "/hook")
        .match_header("x-afasentrasync-event", "mover")
        .with_status(200)
        .with_body_from_request(move |req| {
            let h = |n: &str| {
                req.header(n)
                    .first()
                    .map(|v| v.to_str().unwrap().to_string())
                    .unwrap_or_default()
            };
            *g2.lock().unwrap() = Some((
                h("x-afasentrasync-timestamp"),
                h("x-afasentrasync-signature"),
                req.body().unwrap().clone(),
            ));
            b"ok".to_vec()
        })
        .expect(1)
        .create();
    let r = go(&cfg, true);
    up.assert();
    assert_eq!(r.report.exit_code, exit::OK);
    assert!(load_state(&env.state()).unwrap().outbox.is_empty());
    let (ts, sig, body) = got.lock().unwrap().clone().unwrap();
    let mut signed = ts.into_bytes();
    signed.push(b'.');
    signed.extend_from_slice(&body);
    assert_eq!(
        sig,
        format!(
            "sha256={}",
            hex(&hmac_sha256(b"0123456789abcdef-secret", &signed))
        )
    );
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["event"], "mover");
    assert_eq!(v["employee_id"], "00002");
    assert_eq!(v["changes"]["department"], json!(["HR", "Sales"]));
    assert!(v.get("attempts").is_none());
}

#[test]
fn hmac_matches_rfc4231() {
    assert_eq!(
        hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    let long_key = [0xaau8; 131];
    assert_eq!(
        hex(&hmac_sha256(
            &long_key,
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

// ------------------------------------------------------------------ units

fn person(id: &str, upn: &str) -> Person {
    Person {
        employee_id: id.into(),
        snap: Snapshot {
            upn: upn.into(),
            start_date: minus(10),
            active: true,
            ..Default::default()
        },
        population: None,
    }
}

fn eu(id: &str, emp: Option<&str>, upn: &str) -> EntraUser {
    EntraUser {
        id: id.into(),
        upn: upn.into(),
        employee_id: emp.map(str::to_string),
        mail: None,
        enabled: true,
    }
}

#[test]
fn users_are_matched_safely() {
    let people = [
        person("1", "a@x.nl"),
        person("2", "b@x.nl"),
        person("3", "c@x.nl"),
        person("4", "d@x.nl"),
        person("5", "e@x.nl"),
    ];
    let users = [
        eu("u1", Some("1"), "renamed@x.nl"), // by employeeId, UPN changing
        eu("u2", None, "B@x.nl"),            // by UPN, no employeeId yet
        eu("u3", Some("99"), "c@x.nl"),      // UPN taken by someone else
        eu("u5a", Some("5"), "e1@x.nl"),     // employeeId twice
        eu("u5b", Some("5"), "e2@x.nl"),
    ];
    let m = match_users(&people, &users);
    assert!(matches!(&m["1"], Found::User(u) if u.id == "u1"));
    assert!(matches!(&m["2"], Found::User(u) if u.id == "u2"));
    assert!(matches!(&m["3"], Found::Conflict(_)));
    assert!(matches!(&m["4"], Found::Missing));
    assert!(matches!(&m["5"], Found::Conflict(_)));
}

#[test]
fn csv_export_quotes_and_defuses_formulas() {
    let e = AccessEntry {
        utc: "2026-11-01T00:00:00Z".into(),
        module: "roles".into(),
        action: "add_to_group".into(),
        employee_id: Some("1".into()),
        upn: Some("=HYPERLINK(\"x\")".into()),
        target: Some("AFAS-ICT, \"main\"".into()),
        ok: true,
        detail: None,
        actor: "cli".into(),
    };
    let csv = access_csv(&[e]);
    assert!(csv.contains("\"'=HYPERLINK(\"\"x\"\")\""), "{csv}");
    assert!(csv.contains("\"AFAS-ICT, \"\"main\"\"\""));
}

#[test]
fn exceptions_are_validated() {
    let dir = tempfile::tempdir().unwrap();
    let t = today();
    let ok = |emp: &str, g: &str, until: NaiveDate, reason: &str| {
        add_exception(
            dir.path(),
            emp,
            g,
            ExceptionKind::Include,
            until,
            reason,
            "t",
            t,
        )
    };
    assert!(ok("00001", G_ICT, plus(5), "project").is_ok());
    assert!(ok("00001", "not-a-guid", plus(5), "x").is_err());
    assert!(ok("00001", G_ICT, minus(1), "x").is_err());
    assert!(ok("00001", G_ICT, plus(400), "x").is_err());
    assert!(ok("", G_ICT, plus(5), "x").is_err());
    assert!(ok("00001", G_ICT, plus(5), "").is_err());
    assert!(ok("00001", G_ICT, plus(5), "a\u{7}b").is_err());
}

#[test]
fn module_settings_are_validated() {
    let env = Env::new();
    let base = |m: &str| {
        let tok = env.dir.path().join("afas.token");
        write_secret(&tok, b"ABCDEF0123456789");
        config_toml(
            &env.afas.url(),
            &env.ms.url(),
            &env.state(),
            &tok,
            "certificate",
            &Opts::default(),
        ) + m
    };
    let cert = fixture("test-cert.pem");
    let key = env.key();
    let id = |c: &str| {
        format!("client_id = \"{c}\"\ncertificate_pem = \"{cert}\"\nprivate_key_pem = \"{key}\"\n")
    };
    let bad = [
        (
            "rule without criteria",
            format!(
                "[roles]\nenabled = true\n{}group_prefix = \"AFAS-\"\n[[roles.rule]]\ngroup_id = \"{G_ICT}\"\n",
                id(M_ROLES)
            ),
        ),
        (
            "all plus criteria",
            format!(
                "[roles]\nenabled = true\n{}group_prefix = \"AFAS-\"\n[[roles.rule]]\ngroup_id = \"{G_ICT}\"\nall = true\ndepartment = [\"x\"]\n",
                id(M_ROLES)
            ),
        ),
        (
            "short prefix",
            format!(
                "[roles]\nenabled = true\n{}group_prefix = \"A\"\n[[roles.rule]]\ngroup_id = \"{G_ICT}\"\nall = true\n",
                id(M_ROLES)
            ),
        ),
        (
            "sod group not in rules",
            format!(
                "[roles]\nenabled = true\n{}group_prefix = \"AFAS-\"\n[[roles.rule]]\ngroup_id = \"{G_ICT}\"\nall = true\n[[roles.sod]]\nname = \"x\"\ngroups = [\"{G_ICT}\", \"{G_FIN}\"]\n",
                id(M_ROLES)
            ),
        ),
        (
            "unknown key",
            format!(
                "[roles]\nenabled = true\n{}group_prefix = \"AFAS-\"\ntypo = 1\n[[roles.rule]]\ngroup_id = \"{G_ICT}\"\nall = true\n",
                id(M_ROLES)
            ),
        ),
        (
            "tap in subject",
            format!(
                "[joiner]\nenabled = true\n{}sender = \"a@b.nl\"\ndeliver_to = \"manager\"\nsubject = \"{{tap}}\"\n",
                id(M_JOIN)
            ),
        ),
        (
            "body without tap",
            format!(
                "[joiner]\nenabled = true\n{}sender = \"a@b.nl\"\ndeliver_to = \"manager\"\nbody = \"hello\"\n",
                id(M_JOIN)
            ),
        ),
        (
            "fixed without address",
            format!(
                "[joiner]\nenabled = true\n{}sender = \"a@b.nl\"\ndeliver_to = \"fixed\"\n",
                id(M_JOIN)
            ),
        ),
        (
            "leaver with nothing to do",
            format!(
                "[leaver]\nenabled = true\n{}revoke_sessions = false\n",
                id(M_LEAVE)
            ),
        ),
        (
            "webhook over http",
            "[webhook]\nenabled = true\nurl = \"http://example.com/x\"\nsecret_env = \"S\"\n"
                .to_string(),
        ),
        (
            "webhook without secret",
            "[webhook]\nenabled = true\nurl = \"https://example.com/x\"\n".to_string(),
        ),
    ];
    for (name, m) in bad {
        assert!(
            Config::parse(&base(&format!("\n{m}"))).is_err(),
            "{name} should be refused"
        );
    }
    let good = format!(
        "\n[roles]\nenabled = true\n{}group_prefix = \"AFAS-\"\n[[roles.rule]]\ngroup_id = \"{G_ICT}\"\nall = true\n",
        id(M_ROLES)
    );
    assert!(Config::parse(&base(&good)).is_ok());
    // GUI layer cannot redirect the modules.
    for k in [
        "roles.group_prefix",
        "roles.client_id",
        "joiner.sender",
        "joiner.fixed_address",
        "webhook.url",
        "leaver.private_key_pem",
    ] {
        assert!(afas_entra_sync::config::is_locked(k), "{k}");
    }
}

#[test]
fn webhook_treats_an_old_comparison_as_a_new_baseline() {
    unsafe { std::env::set_var("TEST_HOOK_SECRET", "0123456789abcdef-secret") };
    let mut env = Env::new();
    let cfg = env.cfg(&webhook_cfg(&env));
    let none = env.hook.mock("POST", "/hook").expect(0).create();
    go(&cfg, true); // baseline
    // Pretend the last comparison is from three weeks ago (modules were off since).
    let mut st = load_state(&env.state()).unwrap();
    st.attrs_date = Some(minus(21));
    afas_entra_sync::modules::save_state(&env.state(), &st).unwrap();
    let mut rs = rows();
    rs[1].insert("Afdeling".into(), json!("Sales"));
    env.afas.reset();
    env.afas
        .mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
        .match_query(Matcher::Any)
        .with_body(afas_body(&rs))
        .create();
    let r = go(&cfg, true);
    none.assert();
    let w = r.report.modules.unwrap().webhook.unwrap();
    assert!(w.notes.iter().any(|n| n.contains("new baseline")), "{w:?}");
    assert!(load_state(&env.state()).unwrap().outbox.is_empty());
    assert_eq!(load_state(&env.state()).unwrap().attrs_date, Some(today()));
}

#[test]
fn joiner_removes_an_expired_pass_first() {
    let mut env = Env::new();
    let old = "d0000000-0000-0000-0000-0000000000aa";
    env.ms
        .mock(
            "GET",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .match_query(Matcher::Any)
        .with_body(
            json!({"value":[{"id": old, "isUsable": false, "methodUsabilityReason": "Expired"}]})
                .to_string(),
        )
        .create();
    let del = env
        .ms
        .mock(
            "DELETE",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods/{old}").as_str(),
        )
        .with_status(204)
        .expect(1)
        .create();
    let post = env
        .ms
        .mock(
            "POST",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .with_status(201)
        .with_body(r#"{"id":"d0000000-0000-0000-0000-000000000001","temporaryAccessPass":"X"}"#)
        .expect(1)
        .create();
    env.ms
        .mock("POST", "/v1.0/users/noreply@contoso.nl/sendMail")
        .with_status(202)
        .create();
    let cfg = env.cfg(&joiner_cfg(&env, "manager"));
    let r = go(&cfg, true);
    del.assert();
    post.assert();
    assert_eq!(r.report.modules.unwrap().joiner.unwrap().applied, 1);
}

// ------------------------------------------------------------------ graph client

mod graph_client {
    use super::*;
    use afas_entra_sync::entra::{Credential, TokenProvider};
    use afas_entra_sync::graph::{Graph, seg};
    use afas_entra_sync::http::build_client;
    use reqwest::Method;
    use std::cell::RefCell;
    use std::time::Duration;

    /// Runs `f` with a Graph client against the mock server; returns the sleeps.
    fn with<R>(env: &Env, f: impl FnOnce(&Graph<'_>) -> R) -> (R, Vec<Duration>) {
        let cfg = env.cfg(&env.roles(""));
        let client = build_client(5, false, &Default::default()).unwrap();
        let mut e = cfg.entra.clone();
        e.client_id = M_ROLES.into();
        let cred = Credential::from_config(&e).unwrap();
        let slept = RefCell::new(Vec::new());
        let sleep = |d: Duration| slept.borrow_mut().push(d);
        let tokens = TokenProvider::new(&e, &client, cred, &sleep);
        let g = Graph::new(&e.graph_base, &client, tokens, &sleep).unwrap();
        let r = f(&g);
        drop(g);
        (r, slept.into_inner())
    }

    fn first_then(
        env: &mut Env,
        method: &str,
        path: &str,
        first: usize,
        then: usize,
    ) -> (Mock, Mock) {
        let a = env
            .ms
            .mock(method, path)
            .with_status(first)
            .with_header("retry-after", "7")
            .expect_at_most(1)
            .create();
        let b = env
            .ms
            .mock(method, path)
            .with_status(then)
            .with_body("{\"ok\":true}")
            .create();
        (a, b)
    }

    #[test]
    fn get_is_retried_after_503_honouring_retry_after() {
        let mut env = Env::new();
        let (a, b) = first_then(&mut env, "GET", "/v1.0/things", 503, 200);
        let (r, slept) = with(&env, |g| g.get("things"));
        a.assert();
        b.assert();
        assert_eq!(r.unwrap()["ok"], true);
        assert_eq!(slept, vec![Duration::from_secs(7)]);
    }

    #[test]
    fn post_is_not_repeated_after_a_5xx_but_is_after_429() {
        let mut env = Env::new();
        let five = env
            .ms
            .mock("POST", "/v1.0/a")
            .with_status(500)
            .expect(1)
            .create();
        let (r, _) = with(&env, |g| g.call(Method::POST, "a", None));
        five.assert();
        assert!(r.unwrap_err().outcome_unknown());

        let (t, ok) = first_then(&mut env, "POST", "/v1.0/b", 429, 201);
        let (r, slept) = with(&env, |g| g.call(Method::POST, "b", None));
        t.assert();
        ok.assert();
        assert_eq!(r.unwrap().0, 201);
        assert_eq!(slept, vec![Duration::from_secs(7)]);
    }

    #[test]
    fn gives_up_after_five_attempts() {
        let mut env = Env::new();
        let m = env
            .ms
            .mock("GET", "/v1.0/down")
            .with_status(502)
            .expect(5)
            .create();
        let (r, slept) = with(&env, |g| g.get("down"));
        m.assert();
        assert_eq!(r.unwrap_err().status, Some(502));
        assert_eq!(slept.len(), 4);
    }

    #[test]
    fn retry_after_is_capped_at_two_minutes() {
        let mut env = Env::new();
        env.ms
            .mock("GET", "/v1.0/slow")
            .with_status(429)
            .with_header("retry-after", "86400")
            .expect_at_most(1)
            .create();
        env.ms.mock("GET", "/v1.0/slow").with_body("{}").create();
        let (_, slept) = with(&env, |g| g.get("slow"));
        assert_eq!(slept, vec![Duration::from_secs(120)]);
    }

    #[test]
    fn one_token_refresh_on_401_then_give_up() {
        let mut env = Env::new();
        let (a, b) = first_then(&mut env, "GET", "/v1.0/me", 401, 200);
        let (r, _) = with(&env, |g| g.get("me"));
        a.assert();
        b.assert();
        assert!(r.is_ok());
        let always = env
            .ms
            .mock("GET", "/v1.0/no")
            .with_status(401)
            .expect(2)
            .create();
        let (r, _) = with(&env, |g| g.get("no"));
        always.assert();
        assert_eq!(r.unwrap_err().status, Some(401));
    }

    #[test]
    fn client_errors_are_not_retried_and_the_graph_error_is_parsed() {
        let mut env = Env::new();
        let m = env
            .ms
            .mock("GET", "/v1.0/bad")
            .with_status(403)
            .with_body(r#"{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}"#)
            .expect(1)
            .create();
        let (r, slept) = with(&env, |g| g.get("bad"));
        m.assert();
        let e = r.unwrap_err();
        assert_eq!(
            (e.status, e.code.as_str(), e.message.as_str()),
            (
                Some(403),
                "Authorization_RequestDenied",
                "Insufficient privileges"
            )
        );
        assert!(!e.outcome_unknown() && slept.is_empty());
    }

    #[test]
    fn paging_follows_same_host_only_and_needs_a_value_list() {
        let mut env = Env::new();
        let base = env.ms.url();
        env.ms
            .mock("GET", "/v1.0/list")
            .match_query(Matcher::Missing)
            .with_body(
                json!({"value":[1,2],"@odata.nextLink": format!("{base}/v1.0/list?page=2")})
                    .to_string(),
            )
            .create();
        env.ms
            .mock("GET", "/v1.0/list")
            .match_query(Matcher::UrlEncoded("page".into(), "2".into()))
            .with_body(json!({"value":[3]}).to_string())
            .create();
        let (r, _) = with(&env, |g| g.get_all("list"));
        assert_eq!(r.unwrap(), vec![json!(1), json!(2), json!(3)]);

        env.ms
            .mock("GET", "/v1.0/evil")
            .with_body(json!({"value":[],"@odata.nextLink":"https://evil.example/x"}).to_string())
            .create();
        let (r, _) = with(&env, |g| g.get_all("evil"));
        assert!(r.unwrap_err().message.contains("different host"));

        env.ms.mock("GET", "/v1.0/odd").with_body("{}").create();
        let (r, _) = with(&env, |g| g.get_all("odd"));
        assert!(r.unwrap_err().message.contains("no 'value' list"));
        let (r, _) = with(&env, |g| g.get("https://evil.example/v1.0/users"));
        assert!(r.unwrap_err().message.contains("different host"));
    }

    #[test]
    fn network_errors_retry_a_get_but_never_a_post() {
        let env = Env::new();
        let cfg = env.cfg(&env.roles(""));
        let client = build_client(5, false, &Default::default()).unwrap();
        let mut e = cfg.entra.clone();
        e.client_id = M_ROLES.into();
        let cred = Credential::from_config(&e).unwrap();
        let slept = RefCell::new(Vec::new());
        let sleep = |d: Duration| slept.borrow_mut().push(d);
        let tokens = TokenProvider::new(&e, &client, cred, &sleep);
        // Nothing listens on port 1.
        let g = Graph::new("http://127.0.0.1:1/v1.0", &client, tokens, &sleep).unwrap();
        let err = g.get("users").unwrap_err();
        assert!(err.outcome_unknown());
        assert_eq!(g.calls.get(), 5);
        assert_eq!(slept.borrow().len(), 4);
        let err = g.call(Method::POST, "users", None).unwrap_err();
        assert!(err.outcome_unknown());
        assert_eq!(g.calls.get(), 6, "a POST is tried once");
        assert_eq!(slept.borrow().len(), 4);
    }

    #[test]
    fn calls_are_counted() {
        let mut env = Env::new();
        env.ms.mock("GET", "/v1.0/one").with_body("{}").create();
        let (n, _) = with(&env, |g| {
            g.get("one").unwrap();
            g.get("one").unwrap();
            g.calls.get()
        });
        assert_eq!(n, 2);
    }

    #[test]
    fn object_ids_in_paths_are_guid_characters_only() {
        assert!(seg("b0000000-0000-0000-0000-000000000001").is_ok());
        for bad in ["", "../users", "a/b", "id?x=1", "x y", &"a".repeat(65)] {
            assert!(seg(bad).is_err(), "{bad}");
        }
        assert!(seg(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn entra_user_ignores_empty_employee_id_and_mail() {
        let u = EntraUser::from_json(&json!({"id":"x","userPrincipalName":"a@b.c","employeeId":"","mail":"","accountEnabled":true})).unwrap();
        assert_eq!((u.employee_id, u.mail, u.enabled), (None, None, true));
        assert!(EntraUser::from_json(&json!({"userPrincipalName":"a@b.c"})).is_none());
        let u = EntraUser::from_json(&json!({"id":"x"})).unwrap();
        assert!(!u.enabled);
    }
}

// ------------------------------------------------------------------ boundaries end-to-end

fn tap_ok(env: &mut Env, uid: &str) -> Mock {
    env.passes(uid, &[]);
    env.ms
        .mock(
            "POST",
            format!("/v1.0/users/{uid}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .with_status(201)
        .with_body(r#"{"id":"d0000000-0000-0000-0000-000000000001","temporaryAccessPass":"X"}"#)
        .create()
}

#[test]
fn new_hire_code_is_valid_from_the_start_date_only() {
    use afas_entra_sync::modules::joiner::valid_from_utc;
    let ams: chrono_tz::Tz = "Europe/Amsterdam".parse().unwrap();
    let from = valid_from_utc(ams, plus(1), 6).unwrap();
    let until = from + chrono::Duration::minutes(600);
    let local = |d: chrono::DateTime<chrono::Utc>| {
        d.with_timezone(&ams).format("%Y-%m-%d %H:%M").to_string()
    };
    let mut env = Env::new();
    env.passes(U4, &[]);
    let tap = env
        .ms
        .mock(
            "POST",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .match_body(Matcher::PartialJson(json!({
            "startDateTime": from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "lifetimeInMinutes": 600
        })))
        .with_status(201)
        .with_body(r#"{"id":"d0000000-0000-0000-0000-000000000001","temporaryAccessPass":"X"}"#)
        .expect(1)
        .create();
    let mail = env
        .ms
        .mock("POST", "/v1.0/users/noreply@contoso.nl/sendMail")
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex(regex_lite_escape(&local(from))),
            Matcher::Regex(regex_lite_escape(&local(until))),
        ]))
        .with_status(202)
        .expect(1)
        .create();
    let cfg = env.cfg(&joiner_cfg(&env, "manager"));
    go(&cfg, true);
    tap.assert();
    mail.assert();
}

fn regex_lite_escape(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == ' ' {
                c.to_string()
            } else {
                format!("\\{c}")
            }
        })
        .collect()
}

#[test]
fn new_hire_after_the_start_date_gets_a_code_valid_now() {
    let mut env = Env::new();
    let mut rs = rows();
    rs[3] = row("00004", minus(1), None);
    rs[3].insert("Leidinggevende".into(), json!("00001"));
    env.set_rows(&rs);
    env.passes(U4, &[]);
    let tap = env
        .ms
        .mock(
            "POST",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .match_request(|r| {
            let v: Value = serde_json::from_slice(r.body().unwrap()).unwrap();
            v.get("startDateTime").is_none()
        })
        .with_status(201)
        .with_body(r#"{"id":"d0000000-0000-0000-0000-000000000001","temporaryAccessPass":"X"}"#)
        .expect(1)
        .create();
    env.ms
        .mock("POST", "/v1.0/users/noreply@contoso.nl/sendMail")
        .with_status(202)
        .create();
    let cfg = env.cfg(&joiner_cfg(&env, "manager"));
    go(&cfg, true);
    tap.assert();
}

#[test]
fn new_hires_test_run_and_maximum_per_run() {
    // Two new hires (00002 and 00004).
    let mut rs = rows();
    rs[1] = row("00002", plus(1), None);
    rs[1].insert("Leidinggevende".into(), json!("00001"));
    // And one whose account is not in Entra yet: a note in the report, not planned.
    rs.push(row("00009", plus(1), None));
    let make = |max: u32| {
        let mut env = Env::new();
        env.set_rows(&rs);
        let cfg = env.cfg(&(joiner_cfg(&env, "manager") + &format!("max_per_run = {max}\n")));
        (env, cfg)
    };
    // Test run: planned, nothing sent.
    let (mut env, cfg) = make(5);
    let none = env
        .ms
        .mock("POST", Matcher::Regex("temporaryAccessPassMethods".into()))
        .expect(0)
        .create();
    let r = go(&cfg, false);
    none.assert();
    let j = r.report.modules.unwrap().joiner.unwrap();
    assert_eq!((j.planned.len(), j.applied), (2, 0), "{j:?}");
    assert!(
        j.notes
            .iter()
            .any(|n| n.starts_with("00009") && n.contains("not in Entra yet")),
        "{j:?}"
    );
    // One over the maximum: nothing at all.
    let (mut env, cfg) = make(1);
    let none = env
        .ms
        .mock("POST", Matcher::Regex("temporaryAccessPassMethods".into()))
        .expect(0)
        .create();
    let r = go(&cfg, true);
    none.assert();
    assert_eq!(r.report.exit_code, exit::MODULE_GUARD);
    assert_eq!(
        r.report.modules.unwrap().joiner.unwrap().violations.len(),
        1
    );
    // Exactly the maximum: both.
    let (mut env, cfg) = make(2);
    let t2 = tap_ok(&mut env, U2);
    let t4 = tap_ok(&mut env, U4);
    env.ms
        .mock("POST", "/v1.0/users/noreply@contoso.nl/sendMail")
        .with_status(202)
        .expect(2)
        .create();
    let r = go(&cfg, true);
    t2.assert();
    t4.assert();
    assert_eq!(r.report.modules.unwrap().joiner.unwrap().applied, 2);
}

fn leaver_cfg(env: &Env, extra: &str) -> String {
    format!(
        "\n[leaver]\nenabled = true\nclient_id = \"{M_LEAVE}\"\ncertificate_pem = \"{}\"\nprivate_key_pem = \"{}\"\nauto_reply = \"Gone.\"\n{extra}",
        fixture("test-cert.pem"),
        env.key()
    )
}

#[test]
fn departing_employees_test_run_maximum_and_missing_account() {
    // Two departing employees (00002, 00003) and one without an Entra account (00009).
    let mut rs = rows();
    rs[1] = row("00002", minus(400), Some(minus(1)));
    rs.push(row("00009", minus(400), Some(minus(1))));
    let make = |max: u32| {
        let mut env = Env::new();
        env.set_rows(&rs);
        let cfg = env.cfg(&leaver_cfg(&env, &format!("max_per_run = {max}\n")));
        (env, cfg)
    };
    let (mut env, cfg) = make(5);
    let none = env
        .ms
        .mock("POST", Matcher::Regex("revokeSignInSessions".into()))
        .expect(0)
        .create();
    let r = go(&cfg, false);
    none.assert();
    let l = r.report.modules.unwrap().leaver.unwrap();
    assert_eq!(l.planned.len(), 2, "{l:?}");
    assert!(
        l.notes
            .iter()
            .any(|n| n.starts_with("00009") && n.contains("no account")),
        "{l:?}"
    );

    let (mut env, cfg) = make(1);
    let none = env
        .ms
        .mock("POST", Matcher::Regex("revokeSignInSessions".into()))
        .expect(0)
        .create();
    let r = go(&cfg, true);
    none.assert();
    assert_eq!(r.report.exit_code, exit::MODULE_GUARD);

    let (mut env, cfg) = make(2);
    let rev = env
        .ms
        .mock("POST", Matcher::Regex("revokeSignInSessions".into()))
        .with_body("{}")
        .expect(2)
        .create();
    env.ms
        .mock("PATCH", Matcher::Regex("mailboxSettings".into()))
        .with_body("{}")
        .create();
    let r = go(&cfg, true);
    rev.assert();
    assert_eq!(r.report.modules.unwrap().leaver.unwrap().applied, 2);
}

#[test]
fn automatic_reply_errors_other_than_no_mailbox_are_failures() {
    for (status, body, ok) in [
        (
            404,
            r#"{"error":{"code":"ResourceNotFound","message":"x"}}"#,
            true,
        ),
        (
            400,
            r#"{"error":{"code":"MailboxNotEnabledForRESTAPI","message":"x"}}"#,
            true,
        ),
        (
            403,
            r#"{"error":{"code":"ErrorAccessDenied","message":"x"}}"#,
            false,
        ),
        (
            400,
            r#"{"error":{"code":"ErrorInvalidRequest","message":"x"}}"#,
            false,
        ),
    ] {
        let mut env = Env::new();
        env.ms
            .mock(
                "POST",
                format!("/v1.0/users/{U3}/revokeSignInSessions").as_str(),
            )
            .with_body("{}")
            .create();
        env.ms
            .mock(
                "PATCH",
                format!("/v1.0/users/{U3}/mailboxSettings").as_str(),
            )
            .with_status(status)
            .with_body(body)
            .create();
        let cfg = env.cfg(&leaver_cfg(&env, ""));
        let r = go(&cfg, true);
        let l = r.report.modules.unwrap().leaver.unwrap();
        assert_eq!(l.failed.is_empty(), ok, "{status} {body}: {l:?}");
        assert_eq!(l.applied, usize::from(ok), "{status}");
        let done = load_state(&env.state()).unwrap().leaver_done;
        assert_eq!(done.contains_key("00003"), ok, "{status}");
    }
}

#[test]
fn group_changes_that_fail_are_failures() {
    // add: (status, body, counts as done)
    for (status, body, ok) in [
        (
            400,
            r#"{"error":{"code":"Request_BadRequest","message":"One or more added object references already exist for the following modified properties: 'members'."}}"#,
            true,
        ),
        (
            400,
            r#"{"error":{"code":"Request_BadRequest","message":"Invalid object identifier"}}"#,
            false,
        ),
        (
            403,
            r#"{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}"#,
            false,
        ),
    ] {
        let mut env = Env::new();
        env.group(
            G_ICT,
            "AFAS-ICT",
            &[
                user(U1, Some("00001"), "user00001@contoso.nl"),
                user(U2, Some("00002"), "user00002@contoso.nl"),
                user(U3, Some("00003"), "user00003@contoso.nl"),
            ],
        );
        env.group(
            G_ALL,
            "AFAS-All",
            &[
                user(U2, Some("00002"), "user00002@contoso.nl"),
                user(U3, Some("00003"), "user00003@contoso.nl"),
            ],
        );
        // Only U1 is missing from AFAS-All: one add.
        env.ms
            .mock(
                "POST",
                Matcher::Regex(r"^/v1\.0/groups/.*/members/\$ref$".into()),
            )
            .with_status(status)
            .with_body(body)
            .expect(1)
            .create();
        // U2 (HR) leaves AFAS-ICT, U3 (left 2 days ago) leaves both: removals succeed.
        env.ms
            .mock(
                "DELETE",
                Matcher::Regex(r"^/v1\.0/groups/.*/members/.*/\$ref$".into()),
            )
            .with_status(204)
            .create();
        let cfg = env.cfg(&env.roles(""));
        let r = go(&cfg, true);
        let roles = r.report.modules.unwrap().roles.unwrap();
        assert_eq!(roles.failed.is_empty(), ok, "{body}: {roles:?}");
        assert_eq!(r.report.exit_code == exit::MODULE_FAILED, !ok);
    }
    // remove: 404 = already gone (fine), 403 = failure
    for (status, ok) in [(404, true), (403, false)] {
        let mut env = Env::new();
        env.group(
            G_ICT,
            "AFAS-ICT",
            &[
                user(U1, Some("00001"), "user00001@contoso.nl"),
                user(U2, Some("00002"), "user00002@contoso.nl"),
            ],
        );
        env.group(
            G_ALL,
            "AFAS-All",
            &[
                user(U1, Some("00001"), "user00001@contoso.nl"),
                user(U2, Some("00002"), "user00002@contoso.nl"),
            ],
        );
        env.ms
            .mock(
                "POST",
                Matcher::Regex(r"^/v1\.0/groups/.*/members/\$ref$".into()),
            )
            .with_status(204)
            .create();
        let del = env
            .ms
            .mock(
                "DELETE",
                format!("/v1.0/groups/{G_ICT}/members/{U2}/$ref").as_str(),
            )
            .with_status(status)
            .with_body(r#"{"error":{"code":"x","message":"y"}}"#)
            .expect(1)
            .create();
        let cfg = env.cfg(&env.roles(""));
        let r = go(&cfg, true);
        del.assert();
        let roles = r.report.modules.unwrap().roles.unwrap();
        assert_eq!(roles.failed.is_empty(), ok, "{status}: {roles:?}");
    }
}

#[test]
fn group_change_maximum_is_inclusive() {
    let planned = {
        let mut env = Env::new();
        env.group(G_ICT, "AFAS-ICT", &[]);
        env.group(G_ALL, "AFAS-All", &[]);
        let cfg = env.cfg(&env.roles(""));
        go(&cfg, false)
            .report
            .modules
            .unwrap()
            .roles
            .unwrap()
            .planned
            .len()
    };
    assert!(planned >= 2);
    for (max, guard) in [(planned, false), (planned - 1, true)] {
        let mut env = Env::new();
        env.group(G_ICT, "AFAS-ICT", &[]);
        env.group(G_ALL, "AFAS-All", &[]);
        env.ms
            .mock(
                "POST",
                Matcher::Regex(r"^/v1\.0/groups/.*/members/\$ref$".into()),
            )
            .with_status(204)
            .expect(if guard { 0 } else { planned })
            .create();
        let cfg = env.cfg(&env.roles(&format!("max_changes_per_run = {max}")));
        let r = go(&cfg, true);
        assert_eq!(r.report.exit_code == exit::MODULE_GUARD, guard, "max {max}");
    }
}

// ------------------------------------------------------------------ webhook limits

fn queued(n: usize) -> afas_entra_sync::modules::ModuleState {
    use afas_entra_sync::modules::settings::EventKind;
    use afas_entra_sync::modules::webhook::Event;
    let mut s = load_state(std::path::Path::new("/nonexistent-dir-for-default")).unwrap();
    s.outbox = (0..n)
        .map(|i| Event {
            id: format!("e{i}"),
            event: EventKind::Mover,
            created_utc: "2026-11-01T00:00:00Z".into(),
            employee_id: format!("{i:05}"),
            rehire: false,
            employee: Snapshot::default(),
            changes: [(
                "department".to_string(),
                [Some("HR".to_string()), Some("ICT".to_string())],
            )]
            .into_iter()
            .collect(),
            attempts: 0,
        })
        .collect();
    s
}

fn hook_cfg(url: &str, secret_var: &str, extra: &str) -> String {
    format!("\n[webhook]\nenabled = true\nurl = \"{url}\"\nsecret_env = \"{secret_var}\"\n{extra}")
}

#[test]
fn webhook_secret_needs_sixteen_characters() {
    for (var, secret, ok) in [
        ("TEST_HOOK_S15", "123456789012345", false),
        ("TEST_HOOK_S16", "1234567890123456", true),
    ] {
        unsafe { std::env::set_var(var, secret) };
        let mut env = Env::new();
        afas_entra_sync::modules::save_state(&env.state_mk(), &queued(1)).unwrap();
        let hook = env
            .hook
            .mock("POST", "/hook")
            .with_status(200)
            .expect(usize::from(ok))
            .create();
        let cfg = env.cfg(&hook_cfg(&format!("{}/hook", env.hook.url()), var, ""));
        let r = go(&cfg, true);
        hook.assert();
        let w = r.report.modules.unwrap().webhook.unwrap();
        assert_eq!(w.error.is_none(), ok, "{secret}: {w:?}");
        if ok {
            assert_eq!(w.applied, 1);
        }
    }
}

#[test]
fn webhook_sends_in_order_within_its_maximum() {
    unsafe { std::env::set_var("TEST_HOOK_ORDER", "0123456789abcdef-secret") };
    // Maximum 1 of 2: one sent, one waits.
    let mut env = Env::new();
    afas_entra_sync::modules::save_state(&env.state_mk(), &queued(2)).unwrap();
    // Any POST counts: exactly one may be sent, and it is the oldest.
    let first = env
        .hook
        .mock("POST", "/hook")
        .with_status(200)
        .expect(1)
        .create();
    let cfg = env.cfg(&hook_cfg(
        &format!("{}/hook", env.hook.url()),
        "TEST_HOOK_ORDER",
        "max_per_run = 1",
    ));
    let r = go(&cfg, true);
    first.assert();
    let w = r.report.modules.unwrap().webhook.unwrap();
    assert_eq!(w.applied, 1);
    let left = load_state(&env.state()).unwrap().outbox;
    assert_eq!(
        left.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        ["e1"]
    );

    // The first fails: the second is not tried this run; attempts counted.
    let mut env = Env::new();
    afas_entra_sync::modules::save_state(&env.state_mk(), &queued(2)).unwrap();
    let down = env
        .hook
        .mock("POST", "/hook")
        .with_status(500)
        .expect(1)
        .create();
    let cfg = env.cfg(&hook_cfg(
        &format!("{}/hook", env.hook.url()),
        "TEST_HOOK_ORDER",
        "",
    ));
    go(&cfg, true);
    down.assert();
    let left = load_state(&env.state()).unwrap().outbox;
    assert_eq!(
        left.iter()
            .map(|e| (e.id.as_str(), e.attempts))
            .collect::<Vec<_>>(),
        [("e0", 1), ("e1", 0)]
    );

    // Receiver unreachable: the same, through the network-error path.
    let env = Env::new();
    afas_entra_sync::modules::save_state(&env.state_mk(), &queued(1)).unwrap();
    let cfg = env.cfg(&hook_cfg("http://127.0.0.1:1/hook", "TEST_HOOK_ORDER", ""));
    let r = go(&cfg, true);
    assert_eq!(r.report.exit_code, exit::MODULE_FAILED);
    assert_eq!(load_state(&env.state()).unwrap().outbox[0].attempts, 1);

    // A test run lists the queue with the changed fields.
    let mut env = Env::new();
    afas_entra_sync::modules::save_state(&env.state_mk(), &queued(1)).unwrap();
    let none = env.hook.mock("POST", "/hook").expect(0).create();
    let cfg = env.cfg(&hook_cfg(
        &format!("{}/hook", env.hook.url()),
        "TEST_HOOK_ORDER",
        "",
    ));
    let r = go(&cfg, false);
    none.assert();
    let w = r.report.modules.unwrap().webhook.unwrap();
    assert_eq!(w.planned[0].detail.as_deref(), Some("department"));
}

#[test]
fn webhook_send_queue_is_capped_at_ten_thousand() {
    unsafe { std::env::set_var("TEST_HOOK_CAP", "0123456789abcdef-secret") };
    for (n, dropped) in [(10_000, 0), (10_001, 1), (10_002, 2)] {
        let mut env = Env::new();
        afas_entra_sync::modules::save_state(&env.state_mk(), &queued(n)).unwrap();
        env.hook.mock("POST", "/hook").with_status(503).create();
        let cfg = env.cfg(&hook_cfg(
            &format!("{}/hook", env.hook.url()),
            "TEST_HOOK_CAP",
            "",
        ));
        let r = go(&cfg, true);
        let w = r.report.modules.unwrap().webhook.unwrap();
        let left = load_state(&env.state()).unwrap().outbox;
        assert_eq!(left.len(), 10_000);
        assert_eq!(
            w.notes.iter().any(|x| x.contains("oldest events dropped")),
            dropped > 0,
            "{n}"
        );
        // The oldest go first.
        assert_eq!(left[0].id, format!("e{dropped}"));
    }
}

#[test]
fn a_pass_that_is_not_valid_yet_is_never_deleted() {
    let mut env = Env::new();
    let future = "d0000000-0000-0000-0000-0000000000bb";
    env.ms
        .mock(
            "GET",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .match_query(Matcher::Any)
        .with_body(
            json!({"value":[{"id": future, "isUsable": false, "methodUsabilityReason": "NotYetValid"}]})
                .to_string(),
        )
        .create();
    let del = env
        .ms
        .mock(
            "DELETE",
            Matcher::Regex("temporaryAccessPassMethods".into()),
        )
        .expect(0)
        .create();
    let post = env
        .ms
        .mock(
            "POST",
            format!("/v1.0/users/{U4}/authentication/temporaryAccessPassMethods").as_str(),
        )
        .expect(0)
        .create();
    let cfg = env.cfg(&joiner_cfg(&env, "manager"));
    let r = go(&cfg, true);
    del.assert();
    post.assert();
    let j = r.report.modules.unwrap().joiner.unwrap();
    assert!(
        j.notes
            .iter()
            .any(|n| n.contains("already has a Temporary Access Pass")),
        "{j:?}"
    );
}
