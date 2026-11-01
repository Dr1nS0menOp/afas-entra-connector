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
    for (name, extra) in [
        ("Finance", json!({})),
        ("AFAS-Admins", json!({"isAssignableToRole": true})),
        ("AFAS-OnPrem", json!({"onPremisesSyncEnabled": true})),
        ("AFAS-Dyn", json!({"groupTypes": ["DynamicMembership"]})),
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
        assert!(
            r.report.modules.unwrap().roles.unwrap().error.is_some(),
            "{name}"
        );
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
            .any(|n| n.contains("segregation of duties 'IT vs Finance'")),
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
    assert!(log.contains("pass removed again") && !log.contains("Secret#Tap42"));
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
