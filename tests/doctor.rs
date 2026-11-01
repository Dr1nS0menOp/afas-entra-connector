// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! `doctor` and `afas-fields` against mocked AFAS, Entra login and Microsoft Graph.

mod common;

use afas_entra_sync::config::Config;
use afas_entra_sync::doctor::{self, Check, Level, Options};
use afas_entra_sync::error::exit;
use common::*;
use mockito::{Matcher, Server, ServerGuard};
use serde_json::json;
use std::path::Path;

struct Env {
    afas: ServerGuard,
    ms: ServerGuard,
    dir: tempfile::TempDir,
}

fn env(afas_status: usize, rows: Option<Vec<serde_json::Map<String, serde_json::Value>>>) -> Env {
    let mut e = Env {
        afas: Server::new(),
        ms: Server::new(),
        dir: tempfile::tempdir().unwrap(),
    };
    let rows = rows.unwrap_or_else(|| vec![row("00001", d("2020-01-01"), None)]);
    e.afas
        .mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
        .match_query(Matcher::Any)
        .with_status(afas_status)
        .with_body(afas_body(&rows))
        .create();
    std::fs::create_dir_all(e.dir.path().join("state")).unwrap();
    e
}

impl Env {
    fn token_ok(&mut self) {
        self.ms
            .mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
            .with_body(r#"{"access_token":"tok","expires_in":3600}"#)
            .create();
    }
    fn logs(&mut self, status: usize) {
        self.ms
            .mock("GET", "/v1.0/auditLogs/provisioning")
            .match_query(Matcher::Any)
            .with_status(status)
            .with_body(if status == 200 {
                r#"{"value":[]}"#.to_string()
            } else {
                json!({"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}).to_string()
            })
            .create();
    }
    fn cfg(&self, extra: &str) -> Config {
        let base = config(
            &self.afas.url(),
            &self.ms.url(),
            self.dir.path(),
            &Opts::default(),
        );
        if extra.is_empty() {
            return base;
        }
        let tok = self.dir.path().join("afas.token");
        let text = config_toml(
            &self.afas.url(),
            &self.ms.url(),
            &self.dir.path().join("state"),
            &tok,
            "certificate",
            &Opts::default(),
        ) + extra;
        Config::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"))
    }
}

fn no_systemd(_: &[&str]) -> Option<String> {
    None
}

fn run(cfg: &Config) -> Vec<Check> {
    let o = Options {
        sleep: &|_| {},
        use_system_proxy: false,
        now: chrono::Utc::now(),
        systemctl: &no_systemd,
        tls: false,
    };
    doctor::run(cfg, Path::new("/etc/afas-entra-sync/config.toml"), &o)
}

fn find<'a>(checks: &'a [Check], check: &str) -> &'a Check {
    checks
        .iter()
        .find(|c| c.check == check)
        .unwrap_or_else(|| panic!("no check {check:?} in {checks:#?}"))
}

#[test]
fn everything_fine_gives_exit_0_and_says_so() {
    let mut e = env(200, None);
    e.token_ok();
    e.logs(200);
    let cfg = e.cfg("");
    let checks = run(&cfg);
    let bad: Vec<_> = checks
        .iter()
        .filter(|c| matches!(c.level, Level::Fail | Level::Warn))
        .collect();
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(doctor::exit_code(&checks), exit::OK);
    assert_eq!(find(&checks, "Sign-in").level, Level::Ok);
    assert_eq!(find(&checks, "Field mapping").level, Level::Ok);
    assert_eq!(find(&checks, "Provisioning logs").level, Level::Ok);
    assert!(doctor::render(&checks).contains("Everything checks out."));
}

#[test]
fn missing_afas_field_is_named_with_its_setting() {
    let mut r = row("00001", d("2020-01-01"), None);
    r.remove("Afdeling");
    let mut e = env(200, Some(vec![r]));
    e.token_ok();
    e.logs(200);
    let checks = run(&e.cfg(""));
    let c = find(&checks, "Field mapping");
    assert_eq!(c.level, Level::Fail);
    assert!(
        c.detail.contains("Afdeling (afas.fields.department)"),
        "{c:?}"
    );
    assert!(c.fix.as_deref().unwrap().contains("afas-fields"));
    assert_eq!(doctor::exit_code(&checks), exit::DOCTOR);
}

#[test]
fn rejected_afas_token_says_how_to_replace_it() {
    let mut e = env(401, None);
    e.token_ok();
    e.logs(200);
    let checks = run(&e.cfg(""));
    let c = find(&checks, "GetConnector");
    assert_eq!(c.level, Level::Fail);
    assert!(
        c.fix.as_deref().unwrap().contains("--replace-token"),
        "{c:?}"
    );
}

#[test]
fn unknown_certificate_gets_the_aadsts_explanation() {
    let mut e = env(200, None);
    e.ms.mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
        .with_status(401)
        .with_body(json!({"error":"invalid_client","error_description":"AADSTS700027: Client assertion contains an invalid signature."}).to_string())
        .create();
    let checks = run(&e.cfg(""));
    let c = find(&checks, "Sign-in");
    assert_eq!(c.level, Level::Fail, "{c:?}");
    assert!(
        c.fix
            .as_deref()
            .unwrap_or("")
            .contains("upload the certificate"),
        "{c:?}"
    );
    assert_eq!(doctor::exit_code(&checks), exit::DOCTOR);
    // No Graph checks after a failed sign-in.
    assert!(!checks.iter().any(|c| c.check == "Provisioning logs"));
}

#[test]
fn missing_permission_names_it() {
    let mut e = env(200, None);
    e.token_ok();
    e.logs(403);
    let checks = run(&e.cfg(""));
    let c = find(&checks, "Provisioning logs");
    assert_eq!(c.level, Level::Fail);
    assert!(
        c.fix
            .as_deref()
            .unwrap()
            .contains("ProvisioningLog.Read.All"),
        "{c:?}"
    );
}

#[test]
fn loose_secret_file_is_failed_with_the_chmod_line() {
    let mut e = env(200, None);
    e.token_ok();
    e.logs(200);
    let cfg = e.cfg("");
    use std::os::unix::fs::PermissionsExt;
    let tok = e.dir.path().join("afas.token");
    std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o644)).unwrap();
    let checks = run(&cfg);
    let c = find(&checks, "AFAS token");
    assert_eq!(c.level, Level::Fail);
    assert!(c.fix.as_deref().unwrap().contains("chmod 600"));
}

#[test]
fn roles_module_groups_are_checked_and_a_missing_one_named() {
    const G1: &str = "a1a1a1a1-0000-0000-0000-000000000001";
    const G2: &str = "a1a1a1a1-0000-0000-0000-000000000002";
    let mut e = env(200, None);
    e.token_ok();
    e.logs(200);
    e.ms.mock("GET", format!("/v1.0/groups/{G1}").as_str())
        .match_query(Matcher::Any)
        .with_body(json!({"id": G1, "displayName": "AFAS-ICT", "isAssignableToRole": false, "onPremisesSyncEnabled": null, "groupTypes": []}).to_string())
        .create();
    e.ms.mock("GET", format!("/v1.0/groups/{G2}").as_str())
        .match_query(Matcher::Any)
        .with_status(404)
        .with_body(r#"{"error":{"code":"Request_ResourceNotFound","message":"not found"}}"#)
        .create();
    let key = e.dir.path().join("test-key.pem");
    let roles = format!(
        "\n[roles]\nenabled = true\nclient_id = \"c0000000-0000-0000-0000-000000000001\"\ncertificate_pem = \"{}\"\nprivate_key_pem = \"{}\"\ngroup_prefix = \"AFAS-\"\n\n[[roles.rule]]\ngroup_id = \"{G1}\"\nall = true\n\n[[roles.rule]]\ngroup_id = \"{G2}\"\nall = true\n",
        fixture("test-cert.pem"),
        key.display()
    );
    let checks = run(&e.cfg(&roles));
    let ok = find(&checks, "Group AFAS-ICT");
    assert_eq!(ok.level, Level::Ok);
    let missing = find(&checks, &format!("Group {G2}"));
    assert_eq!(missing.level, Level::Fail);
    assert_eq!(missing.detail, "does not exist");
    assert_eq!(find(&checks, "Private key (roles)").level, Level::Ok);
}

#[test]
fn schedule_and_last_run_are_reported() {
    let mut e = env(200, None);
    e.token_ok();
    e.logs(200);
    let cfg = e.cfg("");
    let disabled = |_: &[&str]| Some("disabled".to_string());
    let o = Options {
        sleep: &|_| {},
        use_system_proxy: false,
        now: chrono::Utc::now(),
        systemctl: &disabled,
        tls: false,
    };
    let checks = doctor::run(&cfg, Path::new("c.toml"), &o);
    let t = find(&checks, "Timer");
    assert_eq!(t.level, Level::Warn);
    assert!(t.fix.as_deref().unwrap().contains("--enable-sync"));
    assert_eq!(find(&checks, "Last run").level, Level::Info);
    assert_eq!(doctor::exit_code(&checks), exit::COMPLETED_WITH_EXCLUSIONS);

    // A failed last run.
    let report = json!({"started_utc": chrono::Utc::now().to_rfc3339(), "mode": "apply", "exit_code": 30, "result": "upload refused"});
    std::fs::write(
        cfg.state.dir.join(afas_entra_sync::state::REPORT_FILE),
        report.to_string(),
    )
    .unwrap();
    let checks = doctor::run(&cfg, Path::new("c.toml"), &o);
    let l = find(&checks, "Last run");
    assert_eq!(l.level, Level::Fail);
    assert!(l.detail.contains("upload refused"));

    // A good sync, but too long ago: the timer is probably not running.
    let report = json!({"started_utc": (chrono::Utc::now() - chrono::Duration::hours(5)).to_rfc3339(), "mode": "apply", "exit_code": 0, "result": "ok"});
    std::fs::write(
        cfg.state.dir.join(afas_entra_sync::state::REPORT_FILE),
        report.to_string(),
    )
    .unwrap();
    let checks = doctor::run(&cfg, Path::new("c.toml"), &o);
    let l = find(&checks, "Last run");
    assert_eq!(l.level, Level::Ok);
    assert!(
        l.detail.starts_with("sync at ") && l.detail.ends_with(" UTC, exit 0: ok"),
        "{l:?}"
    );
    assert_eq!(find(&checks, "Freshness").level, Level::Warn);
}

#[test]
fn afas_fields_shows_kinds_and_mapping_but_never_values() {
    let mut r = row("00001", d("2020-01-01"), None);
    r.insert("Extra".into(), json!("geheim-waarde"));
    r.remove("Functie");
    let e = env(200, Some(vec![r]));
    let cfg = e.cfg("");
    let f = doctor::fields_report(&cfg, &|_| {}, false).unwrap();
    let get = |n: &str| f.iter().find(|x| x.field == n).unwrap();
    assert_eq!(get("DatumInDienst").kind, "date");
    assert_eq!(get("UPN").kind, "text with @");
    assert_eq!(get("UPN").mapped_to.as_deref(), Some("afas.fields.upn"));
    assert_eq!(get("Voorvoegsel").kind, "empty");
    assert_eq!(get("Extra").mapped_to, None);
    let missing = get("Functie");
    assert!(!missing.present);
    assert_eq!(missing.mapped_to.as_deref(), Some("afas.fields.job_title"));
    let table = doctor::render_fields(&f);
    assert!(table.contains("Missing"));
    assert!(table.contains("afas.fields.job_title = \"Functie\""));
    let all = format!("{table}{}", serde_json::to_string(&f).unwrap());
    for secret in ["geheim-waarde", "user00001@contoso.nl", "Voornaam00001"] {
        assert!(!all.contains(secret), "{secret} leaked");
    }
}
